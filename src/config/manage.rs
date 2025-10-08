use super::{Config, ProxyAuth, UserAgentPreset};
use crate::cli::{ConfigAction, ConfigArgs};
use anyhow::Result;
use console::style;

pub fn run(args: ConfigArgs) -> Result<()> {
    let mut config = Config::load()?;

    match args.action {
        ConfigAction::SetKey {
            service,
            key,
            secure,
        } => {
            config.set_api_key(service.clone(), key, secure)?;
            if secure {
                println!(
                    "{} API key for {} stored securely in system keychain",
                    style("✓").green(),
                    style(service).cyan()
                );
            } else {
                println!(
                    "{} API key for {} has been saved",
                    style("✓").green(),
                    style(service).cyan()
                );
            }
        }

        ConfigAction::SetProxy {
            url,
            username,
            password,
        } => {
            config.settings.proxy = Some(url.clone());
            if let (Some(user), Some(pass)) = (username, password) {
                config.settings.proxy_auth = Some(ProxyAuth {
                    username: user,
                    password: pass,
                });
            }
            config.save()?;
            println!(
                "{} Proxy configuration saved: {}",
                style("✓").green(),
                style(url).cyan()
            );
        }

        ConfigAction::SetUserAgent { agent } => {
            let preset = match agent.to_lowercase().as_str() {
                "chrome" => UserAgentPreset::Chrome,
                "firefox" => UserAgentPreset::Firefox,
                "safari" => UserAgentPreset::Safari,
                "edge" => UserAgentPreset::Edge,
                "mobile" => UserAgentPreset::Mobile,
                "osint" => UserAgentPreset::Osint,
                _ => UserAgentPreset::Custom(agent.clone()),
            };
            config.settings.user_agent_preset = preset.clone();
            config.settings.user_agent = preset.to_string();
            config.save()?;
            println!("{} User agent updated", style("✓").green());
        }

        ConfigAction::SetThreads { count } => {
            config.settings.max_threads = count;
            config.save()?;
            println!(
                "{} Thread count set to {}",
                style("✓").green(),
                style(count.to_string()).cyan()
            );
        }

        ConfigAction::List => {
            println!("{}", style("Configured Services:").bold());
            println!("{}", style("═══════════════════").cyan());

            if config.api_keys.is_empty() && config.secure_keys.is_empty() {
                println!("{}", style("No API keys configured").yellow());
            } else {
                for service in config.api_keys.keys() {
                    println!("  • {}", style(service).cyan());
                }
                for service in &config.secure_keys {
                    println!(
                        "  • {} {}",
                        style(service).cyan(),
                        style("[secure]").green()
                    );
                }
            }

            println!("\n{}", style("Settings:").bold());
            println!("{}", style("═════════").cyan());
            println!("  Timeout: {} seconds", config.settings.timeout);
            println!("  Max Threads: {}", config.settings.max_threads);
            println!(
                "  User Agent Preset: {:?}",
                config.settings.user_agent_preset
            );
            println!(
                "  User Agent: {}",
                &config.settings.user_agent[..50.min(config.settings.user_agent.len())]
            );
            if let Some(proxy) = &config.settings.proxy {
                println!("  Proxy: {}", proxy);
                if config.settings.proxy_auth.is_some() {
                    println!("  Proxy Auth: Configured");
                }
            }
            println!("  Retry Count: {}", config.settings.retry_count);
            println!("  Rate Limit Delay: {}ms", config.settings.rate_limit_delay);
            println!(
                "  Auto Update: {}",
                if config.settings.auto_update {
                    style("✓ Enabled").green()
                } else {
                    style("✗ Disabled").red()
                }
            );
        }

        ConfigAction::Test { service } => {
            if let Some(service_name) = service {
                if config.get_api_key(&service_name).is_some() {
                    println!(
                        "{} API key for {} is configured",
                        style("✓").green(),
                        style(&service_name).cyan()
                    );
                } else {
                    println!(
                        "{} No API key found for {}",
                        style("✗").red(),
                        style(&service_name).cyan()
                    );
                }
            } else {
                println!("{}", style("Testing all configured API keys...").yellow());
                for service_name in config.api_keys.keys().chain(config.secure_keys.iter()) {
                    println!("  {} {}", style("✓").green(), style(service_name).cyan());
                }
            }
        }

        ConfigAction::SetAutoUpdate { enabled } => {
            let enabled_bool = match enabled.to_lowercase().as_str() {
                "on" | "true" | "yes" | "1" => true,
                "off" | "false" | "no" | "0" => false,
                _ => {
                    println!("{} Invalid value. Use 'on' or 'off'", style("✗").red());
                    return Ok(());
                }
            };
            config.set_auto_update(enabled_bool)?;
            if enabled_bool {
                println!(
                    "{} Auto-update enabled - BUIT will check for updates at startup",
                    style("✓").green()
                );
            } else {
                println!(
                    "{} Auto-update disabled - Use 'buit update' to check manually",
                    style("✓").green()
                );
            }
        }
    }

    Ok(())
}
