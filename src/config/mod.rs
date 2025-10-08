pub mod manage;

use anyhow::{Context, Result};
use chrono::Utc;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;

pub const CURRENT_CONFIG_VERSION: u16 = 2;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_config_version")]
    pub version: u16,
    pub api_keys: HashMap<String, String>,
    #[serde(default)]
    pub secure_keys: HashSet<String>,
    pub settings: Settings,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub timeout: u64,
    pub max_threads: usize,
    pub user_agent: String,
    pub user_agent_preset: UserAgentPreset,
    pub proxy: Option<String>,
    pub proxy_auth: Option<ProxyAuth>,
    pub retry_count: usize,
    pub rate_limit_delay: u64,
    pub auto_update: bool,
    #[serde(default)]
    pub http_cache_ttl_seconds: Option<u64>,
    #[serde(default = "default_hedge_delay")]
    pub hedge_delay_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum UserAgentPreset {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Mobile,
    Osint,
    Custom(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

impl UserAgentPreset {
    pub fn to_string(&self) -> String {
        match self {
            UserAgentPreset::Chrome => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
            }
            UserAgentPreset::Firefox => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0".to_string()
            }
            UserAgentPreset::Safari => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15".to_string()
            }
            UserAgentPreset::Edge => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0".to_string()
            }
            UserAgentPreset::Mobile => {
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1".to_string()
            }
            UserAgentPreset::Osint => {
                "BUIT Osint/1.0 (Open source osint toolkit)".to_string()
            }
            UserAgentPreset::Custom(ua) => ua.clone(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: CURRENT_CONFIG_VERSION,
            api_keys: HashMap::new(),
            secure_keys: HashSet::new(),
            settings: Settings::default(),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            timeout: 30,
            max_threads: 10,
            user_agent: UserAgentPreset::Chrome.to_string(),
            user_agent_preset: UserAgentPreset::Chrome,
            proxy: None,
            proxy_auth: None,
            retry_count: 3,
            rate_limit_delay: 100,
            auto_update: true,
            http_cache_ttl_seconds: None,
            hedge_delay_ms: default_hedge_delay(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if !config_path.exists() {
            let config = Config::default();
            config.save()?;
            return Ok(config);
        }

        let content = fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read configuration from {:?}", config_path))?;

        match serde_json::from_str::<Config>(&content) {
            Ok(mut config) => {
                if config.version == 0 || config.version != CURRENT_CONFIG_VERSION {
                    config = Self::migrate(config)?;
                }
                Ok(config)
            }
            Err(error) => {
                let backup_path = Self::write_backup(&config_path, &content)?;
                Err(anyhow::anyhow!(
                    "Failed to parse configuration (backup saved to {:?}): {}",
                    backup_path,
                    error
                ))
            }
        }
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        let content = serde_json::to_string_pretty(self)?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(config_path, content)?;
        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let mut path =
            dirs::config_dir().ok_or_else(|| anyhow::anyhow!("Could not find config directory"))?;
        path.push("buit");
        path.push("config.json");
        Ok(path)
    }

    #[allow(dead_code)]
    pub fn get_api_key(&self, service: &str) -> Option<String> {
        if let Some(value) = self.api_keys.get(service) {
            return Some(value.clone());
        }
        if self.secure_keys.contains(service) {
            return read_secure_key(service)
                .map_err(|err| {
                    warn!("Failed to read secure key for {}: {}", service, err);
                    err
                })
                .ok();
        }
        None
    }

    pub fn set_api_key(&mut self, service: String, key: String, secure: bool) -> Result<()> {
        if secure {
            store_secure_key(&service, &key)?;
            self.secure_keys.insert(service.clone());
            self.api_keys.remove(&service);
        } else {
            if self.secure_keys.remove(&service) {
                if let Err(err) = delete_secure_key(&service) {
                    warn!("Failed to remove secure key for {}: {}", service, err);
                }
            }
            self.api_keys.insert(service.clone(), key);
        }
        self.save()
    }

    pub fn set_auto_update(&mut self, enabled: bool) -> Result<()> {
        self.settings.auto_update = enabled;
        self.save()
    }

    fn migrate(mut config: Config) -> Result<Config> {
        if config.version > CURRENT_CONFIG_VERSION && config.version != 0 {
            return Err(anyhow::anyhow!(
                "Configuration version {} is newer than supported {}",
                config.version,
                CURRENT_CONFIG_VERSION
            ));
        }

        if config.version == 0 {
            config.version = CURRENT_CONFIG_VERSION;
            return Ok(config);
        }

        match config.version {
            v if v < CURRENT_CONFIG_VERSION => {
                // Future migration steps can be handled here.
                config.version = CURRENT_CONFIG_VERSION;
                Ok(config)
            }
            _ => Ok(config),
        }
    }

    fn write_backup(path: &Path, content: &str) -> Result<PathBuf> {
        let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
        let backup_path = if let Some(parent) = path.parent() {
            let filename = format!("config.bak-{}.json", timestamp);
            parent.join(filename)
        } else {
            PathBuf::from(format!("config.bak-{}.json", timestamp))
        };

        fs::write(&backup_path, content).with_context(|| {
            format!("Failed to write configuration backup at {:?}", backup_path)
        })?;

        Ok(backup_path)
    }
}

fn default_config_version() -> u16 {
    0
}

fn default_hedge_delay() -> u64 {
    600
}

fn keyring_entry(service: &str) -> Result<Entry> {
    Entry::new("buit", service).map_err(|err| anyhow::anyhow!(err))
}

fn store_secure_key(service: &str, value: &str) -> Result<()> {
    let entry = keyring_entry(service)?;
    entry
        .set_password(value)
        .map_err(|err| anyhow::anyhow!(err))
}

fn read_secure_key(service: &str) -> Result<String, keyring::Error> {
    Entry::new("buit", service)?.get_password()
}

fn delete_secure_key(service: &str) -> Result<(), keyring::Error> {
    Entry::new("buit", service)?.delete_password()
}
