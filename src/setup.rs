use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Select};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
pub async fn force_setup() -> Result<()> {
    println!("\n{}", style("🔧 BUIT Installation Setup").cyan().bold());
    println!("{}", style("══════════════════════════").cyan());
    offer_auto_setup()?;
    Ok(())
}
pub fn check_and_setup() -> Result<()> {
    if env::var("BUIT_NO_AUTOSETUP").is_ok() {
        return Ok(());
    }
    if is_in_path() {
        return Ok(());
    }
    let current_exe = env::current_exe()?;
    if should_offer_setup(&current_exe) {
        offer_auto_setup()?;
    }
    Ok(())
}
fn is_in_path() -> bool {
    let binary_name = if cfg!(target_os = "windows") {
        "buit.exe"
    } else {
        "buit"
    };
    let which_cmd = if cfg!(target_os = "windows") {
        "where"
    } else {
        "which"
    };
    if let Ok(output) = Command::new(which_cmd).arg(binary_name).output() {
        if output.status.success() && !output.stdout.is_empty() {
            return true;
        }
    }
    false
}
fn should_offer_setup(current_exe: &PathBuf) -> bool {
    let exe_str = current_exe.to_string_lossy().to_lowercase();
    let common_paths = if cfg!(target_os = "windows") {
        vec![
            "program files",
            "windows",
            "system32",
            "c:\\tools",
            "appdata",
        ]
    } else {
        vec!["/usr/local/bin", "/usr/bin", "/bin", "/opt", "/.local/bin"]
    };
    if common_paths.iter().any(|path| exe_str.contains(path)) {
        return false;
    }
    let temp_paths = if cfg!(target_os = "windows") {
        vec!["downloads", "desktop", "temp", "tmp"]
    } else {
        vec!["downloads", "desktop", "tmp", "/tmp", "documents"]
    };
    temp_paths.iter().any(|path| exe_str.contains(path))
        || !common_paths.iter().any(|path| exe_str.contains(path))
}
fn offer_auto_setup() -> Result<()> {
    println!("\n{}", style("🚀 BUIT First-Time Setup").cyan().bold());
    println!("{}", style("══════════════════════════").cyan());
    println!(
        "\n{} BUIT is not installed in your system PATH.",
        style("ℹ️").blue()
    );
    println!("Would you like to install it automatically for easier access?");
    if !Confirm::new()
        .with_prompt("Install BUIT to system PATH?")
        .default(true)
        .interact()?
    {
        println!(
            "\n{} Setup skipped. You can run BUIT from its current location.",
            style("⏭️").yellow()
        );
        return Ok(());
    }
    let install_options = get_install_options();
    let selection = Select::new()
        .with_prompt("Choose installation location")
        .items(&install_options)
        .default(0)
        .interact()?;
    install_to_location(selection)?;
    Ok(())
}
#[cfg(target_os = "windows")]
fn get_install_options() -> Vec<String> {
    vec![
        "C:\\tools\\buit\\ (Recommended)".to_string(),
        "User AppData\\Local\\Programs\\buit\\".to_string(),
        "Custom location...".to_string(),
    ]
}
#[cfg(not(target_os = "windows"))]
fn get_install_options() -> Vec<String> {
    vec![
        "/usr/local/bin (Recommended - requires sudo)".to_string(),
        "~/.local/bin (User installation)".to_string(),
        "Custom location...".to_string(),
    ]
}
#[cfg(target_os = "windows")]
fn install_to_location(selection: usize) -> Result<()> {
    let current_exe = env::current_exe()?;
    let target_dir = match selection {
        0 => PathBuf::from("C:\\tools\\buit"),
        1 => {
            let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("C:\\"));
            path.push("Programs");
            path.push("buit");
            path
        }
        _ => {
            println!("Enter custom installation path:");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            PathBuf::from(input.trim())
        }
    };
    fs::create_dir_all(&target_dir)?;
    let binary_name = if cfg!(target_os = "windows") {
        "buit.exe"
    } else {
        "buit"
    };
    let target_exe = target_dir.join(binary_name);
    fs::copy(&current_exe, &target_exe)?;
    println!(
        "\n✅ {} installed to: {}",
        style("BUIT").green().bold(),
        target_dir.display()
    );
    add_to_windows_path(&target_dir)?;
    println!(
        "\n{} {} {}",
        style("🎉").green(),
        style("Installation complete!").green().bold(),
        "Restart your terminal to use 'buit' from anywhere."
    );
    Ok(())
}
#[cfg(not(target_os = "windows"))]
fn install_to_location(selection: usize) -> Result<()> {
    let current_exe = env::current_exe()?;
    let target_path = match selection {
        0 => PathBuf::from("/usr/local/bin/buit"),
        1 => {
            let home = env::var("HOME")?;
            let mut path = PathBuf::from(home);
            path.push(".local/bin");
            fs::create_dir_all(&path)?;
            path.push("buit");
            path
        }
        _ => {
            println!("Enter custom installation path:");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            PathBuf::from(input.trim())
        }
    };
    if selection == 0 {
        let status = Command::new("sudo")
            .arg("cp")
            .arg(&current_exe)
            .arg(&target_path)
            .status()?;
        if !status.success() {
            println!(
                "❌ {} Installation failed. Try running with sudo.",
                style("Error:").red()
            );
            return Ok(());
        }
        Command::new("sudo")
            .arg("chmod")
            .arg("+x")
            .arg(&target_path)
            .status()?;
    } else {
        fs::copy(&current_exe, &target_path)?;
        Command::new("chmod").arg("+x").arg(&target_path).status()?;
        add_to_user_path()?;
    }
    println!(
        "\n✅ {} installed to: {}",
        style("BUIT").green().bold(),
        target_path.display()
    );
    println!(
        "\n{} {} {}",
        style("🎉").green(),
        style("Installation complete!").green().bold(),
        "You can now run 'buit' from anywhere!"
    );
    Ok(())
}
#[cfg(target_os = "windows")]
fn add_to_windows_path(dir: &PathBuf) -> Result<()> {
    use std::process::Command;
    let dir_str = dir.to_string_lossy();
    let ps_script = format!(
        r#"
        $currentPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
        if ($currentPath -notlike '*{}*') {{
            $newPath = $currentPath + ';{}'
            [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
            Write-Output 'Added to PATH'
        }} else {{
            Write-Output 'Already in PATH'
        }}
        "#,
        dir_str, dir_str
    );
    let output = Command::new("powershell")
        .arg("-Command")
        .arg(&ps_script)
        .output();
    match output {
        Ok(_) => println!("📝 Added to Windows PATH"),
        Err(_) => println!(
            "⚠️  Please add {} to your PATH manually",
            style(dir_str).yellow()
        ),
    }
    Ok(())
}
#[cfg(not(target_os = "windows"))]
fn add_to_user_path() -> Result<()> {
    let home = env::var("HOME")?;
    let local_bin = format!("{}/.local/bin", home);
    let shell = env::var("SHELL").unwrap_or_default();
    let mut shell_configs = vec![];
    if shell.contains("zsh") {
        shell_configs.extend(vec![
            format!("{}/.zshrc", home),
            format!("{}/.zprofile", home),
            format!("{}/.profile", home),
        ]);
    } else if shell.contains("bash") {
        shell_configs.extend(vec![
            format!("{}/.bashrc", home),
            format!("{}/.bash_profile", home),
            format!("{}/.profile", home),
        ]);
    } else {
        shell_configs.extend(vec![
            format!("{}/.profile", home),
            format!("{}/.bashrc", home),
            format!("{}/.zshrc", home),
        ]);
    }
    let custom_zsh = format!("{}/.oh-my-zsh/custom/buit.zsh", home);
    let mut path_added = false;
    for config_file in shell_configs {
        if PathBuf::from(&config_file).exists() {
            let content = fs::read_to_string(&config_file).unwrap_or_default();
            if !content.contains(&local_bin) {
                let path_line = format!(
                    "\n# Added by BUIT installer\nexport PATH=\"$PATH:{}\"\n",
                    local_bin
                );
                if let Ok(_) = fs::write(&config_file, format!("{}{}", content, path_line)) {
                    println!("📝 Added ~/.local/bin to PATH in {}", config_file);
                    path_added = true;
                    break;
                }
            } else {
                println!("✅ ~/.local/bin already in PATH in {}", config_file);
                path_added = true;
                break;
            }
        }
    }
    if !path_added && PathBuf::from(format!("{}/.oh-my-zsh", home)).exists() {
        let custom_content = format!(
            "# BUIT PATH configuration\nexport PATH=\"$PATH:{}\"\n",
            local_bin
        );
        if let Ok(_) = fs::write(&custom_zsh, custom_content) {
            println!("📝 Created oh-my-zsh custom config: {}", custom_zsh);
            path_added = true;
        }
    }
    if !path_added {
        println!(
            "⚠️  Please add {} to your PATH manually",
            style(local_bin.clone()).yellow()
        );
        println!("   Add this line to your shell config:");
        println!("   export PATH=\"$PATH:{}\"", style(local_bin).cyan());
    } else {
        println!(
            "🔄 Please restart your terminal or run: source ~/.{}rc",
            if shell.contains("zsh") { "zsh" } else { "bash" }
        );
    }
    Ok(())
}
