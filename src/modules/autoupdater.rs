use crate::cli::UpdateArgs;
use crate::config::Config;
use crate::utils::http::HttpClient;
use anyhow::{anyhow, Result};
use console::style;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

#[derive(Debug, Serialize, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    name: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug)]
struct PlatformInfo {
    os: String,
    arch: String,
    extension: String,
}

pub async fn run(args: UpdateArgs) -> Result<()> {
    println!("{} Checking for updates...", style("🔄").cyan());

    let current_version = env!("CARGO_PKG_VERSION");
    println!(
        "{} Current version: {}",
        style("📍").green(),
        style(current_version).yellow()
    );

    let platform = detect_platform();
    println!(
        "{} Platform: {} {}",
        style("🖥").blue(),
        platform.os,
        platform.arch
    );

    let latest_release = get_latest_release().await?;
    let latest_version = latest_release.tag_name.trim_start_matches('v');

    println!(
        "{} Latest version: {}",
        style("🆕").green(),
        style(latest_version).yellow()
    );

    if current_version == latest_version {
        println!(
            "{} You're already running the latest version!",
            style("✅").green()
        );
        return Ok(());
    }

    if args.check_only {
        println!(
            "{} Update available: {} -> {}",
            style("🔔").yellow(),
            style(current_version).red(),
            style(latest_version).green()
        );
        return Ok(());
    }

    let asset = find_platform_asset(&latest_release.assets, &platform)?;
    println!(
        "{} Found asset: {}",
        style("📦").cyan(),
        style(&asset.name).blue()
    );

    if args.auto_confirm || confirm_update(current_version, latest_version)? {
        download_and_install(&asset, &platform).await?;
        println!(
            "{} Successfully updated to version {}!",
            style("🎉").green(),
            style(latest_version).yellow()
        );
        println!(
            "{} Restart your terminal or run 'buit --version' to verify!",
            style("💡").cyan()
        );
    } else {
        println!("{} Update cancelled by user", style("❌").red());
    }

    Ok(())
}

fn detect_platform() -> PlatformInfo {
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        "x64"
    };

    let extension = if cfg!(target_os = "windows") {
        "zip"
    } else {
        "tar.gz"
    };

    PlatformInfo {
        os: os.to_string(),
        arch: arch.to_string(),
        extension: extension.to_string(),
    }
}

async fn get_latest_release() -> Result<GitHubRelease> {
    let client = HttpClient::new()?;
    let url = "https://api.github.com/repos/BuuDevOff/BUIT/releases/latest";

    println!("{} Fetching release information...", style("🌐").cyan());
    let response = client.get(url).await?;

    let release: GitHubRelease = serde_json::from_str(&response)
        .map_err(|e| anyhow!("Failed to parse GitHub API response: {}", e))?;

    Ok(release)
}

fn find_platform_asset<'a>(
    assets: &'a [GitHubAsset],
    platform: &PlatformInfo,
) -> Result<&'a GitHubAsset> {
    let pattern = format!("{}-{}.{}", platform.os, platform.arch, platform.extension);

    assets
        .iter()
        .find(|asset| asset.name.contains(&pattern))
        .ok_or_else(|| anyhow!("No asset found for platform: {}", pattern))
}

async fn download_and_install(asset: &GitHubAsset, platform: &PlatformInfo) -> Result<()> {
    let client = HttpClient::new()?;

    println!(
        "{} Downloading {}...",
        style("⬇").cyan(),
        style(&asset.name).blue()
    );

    let temp_dir = tempdir()?;
    let archive_path = temp_dir.path().join(&asset.name);

    let response = client.get(&asset.browser_download_url).await?;
    fs::write(&archive_path, response.as_bytes())?;

    println!("{} Download completed, extracting...", style("📦").green());

    let extracted_path = extract_archive(&archive_path, &temp_dir.path(), platform)?;

    replace_binary(&extracted_path)?;

    Ok(())
}

fn extract_archive(
    archive_path: &Path,
    extract_to: &Path,
    platform: &PlatformInfo,
) -> Result<std::path::PathBuf> {
    if platform.extension == "zip" {
        let file = fs::File::open(archive_path)?;
        let mut archive = zip::ZipArchive::new(file)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = extract_to.join(file.name());

            if file.name().ends_with('/') {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        fs::create_dir_all(p)?;
                    }
                }
                let mut outfile = fs::File::create(&outpath)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
        }

        find_binary_in_dir(extract_to)
    } else {
        // Extract TAR.GZ (Unix)
        let tar_gz = fs::File::open(archive_path)?;
        let tar = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(tar);
        archive.unpack(extract_to)?;

        find_binary_in_dir(extract_to)
    }
}

fn find_binary_in_dir(dir: &Path) -> Result<std::path::PathBuf> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with("buit") && (name.ends_with(".exe") || !name.contains('.')) {
                return Ok(path);
            }
        }
    }

    Err(anyhow!("Binary not found in extracted archive"))
}

fn replace_binary(new_binary_path: &Path) -> Result<()> {
    let current_exe = env::current_exe()?;

    println!("{} Installing update...", style("🔧").cyan());

    if cfg!(target_os = "windows") {
        let backup_path = current_exe.with_extension("exe.bak");

        if backup_path.exists() {
            fs::remove_file(&backup_path)?;
        }
        fs::copy(&current_exe, &backup_path)?;

        match fs::copy(new_binary_path, &current_exe) {
            Ok(_) => {
                let _ = fs::remove_file(&backup_path);
            }
            Err(_) => {
                fs::copy(&backup_path, &current_exe)?;
                fs::remove_file(&backup_path)?;

                println!(
                    "{} Automatic update failed (file in use).",
                    style("⚠").yellow()
                );
                println!(
                    "{} Please close BUIT and run the update command again.",
                    style("💡").cyan()
                );
                return Err(anyhow!("Cannot replace binary while it's running"));
            }
        }
    } else {
        fs::copy(new_binary_path, &current_exe)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&current_exe)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&current_exe, perms)?;
        }
    }

    Ok(())
}

fn confirm_update(current: &str, latest: &str) -> Result<bool> {
    println!();
    println!("{} Update available:", style("🔔").yellow());
    println!("  {} Current: {}", style("📍").blue(), style(current).red());
    println!(
        "  {} Latest:  {}",
        style("🆕").blue(),
        style(latest).green()
    );
    println!();

    use dialoguer::Confirm;

    let confirmed = Confirm::new()
        .with_prompt("Do you want to update now?")
        .default(true)
        .interact()?;

    Ok(confirmed)
}

pub async fn check_for_updates_at_startup() -> Result<()> {
    let config = Config::load()?;

    if !config.settings.auto_update {
        return Ok(());
    }

    let current_version = env!("CARGO_PKG_VERSION");

    match get_latest_release().await {
        Ok(latest_release) => {
            let latest_version = latest_release.tag_name.trim_start_matches('v');

            if current_version == latest_version {
                println!(
                    "{} You're running the latest version ({})",
                    style("✅").green(),
                    style(current_version).yellow()
                );
                return Ok(());
            }

            println!(
                "{} Update available: {} -> {}",
                style("🔔").yellow(),
                style(current_version).red(),
                style(latest_version).green()
            );

            use dialoguer::Confirm;

            let should_update = Confirm::new()
                .with_prompt("Do you want to install the update now?")
                .default(false)
                .interact()?;

            if should_update {
                let platform = detect_platform();
                let asset = find_platform_asset(&latest_release.assets, &platform)?;
                download_and_install(&asset, &platform).await?;
                println!(
                    "{} Successfully updated to version {}!",
                    style("🎉").green(),
                    style(latest_version).yellow()
                );
                println!(
                    "{} Please restart BUIT to use the new version!",
                    style("💡").cyan()
                );
                std::process::exit(0);
            } else {
                let should_disable = Confirm::new()
                    .with_prompt("Do you want to disable automatic update checks?")
                    .default(false)
                    .interact()?;

                if should_disable {
                    let mut config = config;
                    config.set_auto_update(false)?;
                    println!(
                        "{} Auto-update disabled. Use 'buit update' to check manually.",
                        style("ℹ").blue()
                    );
                }
            }
        }
        Err(_) => {
            // Silently fail on network errors during startup
        }
    }

    Ok(())
}
