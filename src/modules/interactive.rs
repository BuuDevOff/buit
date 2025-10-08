use anyhow::Result;
use console::style;
use std::io::{self, Write};
pub async fn run() -> Result<()> {
    println!(
        "{} {} {}",
        style("🎮").cyan(),
        style("Interactive OSINT Mode").green().bold(),
        style("- Guided Workflows").yellow()
    );
    println!();
    loop {
        display_main_menu();
        let choice = get_user_input("Select an option")?;
        match choice.trim() {
            "1" => target_investigation().await?,
            "2" => domain_reconnaissance().await?,
            "3" => social_investigation().await?,
            "4" => network_analysis().await?,
            "5" => security_assessment().await?,
            "6" => show_configuration().await?,
            "7" => show_help(),
            "0" | "exit" | "quit" => {
                println!("{} Goodbye! Happy hunting! 🕵️", style("👋").yellow());
                break;
            }
            _ => {
                println!("{} Invalid choice. Please try again.", style("❌").red());
            }
        }
        println!();
    }
    Ok(())
}
fn display_main_menu() {
    println!(
        "{}",
        style("╔══════════════════════════════════════╗").cyan()
    );
    println!(
        "{}",
        style("║           BUIT Main Menu             ║").cyan()
    );
    println!(
        "{}",
        style("╚══════════════════════════════════════╝").cyan()
    );
    println!();
    println!(
        "{} {} Target Investigation",
        style("1.").yellow(),
        style("👤").cyan()
    );
    println!("   Username, email, phone number research");
    println!();
    println!(
        "{} {} Domain Reconnaissance",
        style("2.").yellow(),
        style("🌐").cyan()
    );
    println!("   Domain analysis, subdomains, WHOIS");
    println!();
    println!(
        "{} {} Social Media Investigation",
        style("3.").yellow(),
        style("📱").cyan()
    );
    println!("   Social profiles, GitHub analysis");
    println!();
    println!(
        "{} {} Network Analysis",
        style("4.").yellow(),
        style("🖥️").cyan()
    );
    println!("   IP analysis, port scanning, geolocation");
    println!();
    println!(
        "{} {} Security Assessment",
        style("5.").yellow(),
        style("🛡️").cyan()
    );
    println!("   URL scanning, hash analysis, leaks");
    println!();
    println!(
        "{} {} Configuration",
        style("6.").yellow(),
        style("⚙️").cyan()
    );
    println!("   View/modify BUIT settings");
    println!();
    println!(
        "{} {} Help & Documentation",
        style("7.").yellow(),
        style("❓").cyan()
    );
    println!("   Learn about BUIT modules");
    println!();
    println!("{} {} Exit", style("0.").yellow(), style("🚪").cyan());
    println!();
}
async fn target_investigation() -> Result<()> {
    println!(
        "{}",
        style("🎯 Target Investigation Workflow").green().bold()
    );
    println!();
    let target = get_user_input("Enter target (username, email, or phone)")?;
    println!("{}", style("Select investigation type:").yellow());
    println!("1. Username search across platforms");
    println!("2. Email investigation & breach checking");
    println!("3. Phone number analysis");
    println!("4. Comprehensive investigation (all)");
    let choice = get_user_input("Choice")?;
    match choice.trim() {
        "1" => {
            println!(
                "{} Searching username: {}",
                style("🔍").cyan(),
                style(&target).cyan()
            );
            run_module("username", &target).await?;
        }
        "2" => {
            println!(
                "{} Investigating email: {}",
                style("📧").cyan(),
                style(&target).cyan()
            );
            run_module("email", &format!("{} --breaches --social", target)).await?;
        }
        "3" => {
            println!(
                "{} Analyzing phone: {}",
                style("📱").cyan(),
                style(&target).cyan()
            );
            run_module("phone", &format!("{} --carrier", target)).await?;
        }
        "4" => {
            println!(
                "{} Running comprehensive investigation...",
                style("🔄").cyan()
            );
            run_module("username", &target).await?;
            run_module("email", &format!("{} --breaches", target)).await?;
            run_module("phone", &format!("{} --carrier", target)).await?;
        }
        _ => println!("{} Invalid choice", style("❌").red()),
    }
    Ok(())
}
async fn domain_reconnaissance() -> Result<()> {
    println!(
        "{}",
        style("🌐 Domain Reconnaissance Workflow").green().bold()
    );
    println!();
    let domain = get_user_input("Enter domain (e.g., example.com)")?;
    println!("{}", style("Select reconnaissance type:").yellow());
    println!("1. Basic domain info (WHOIS)");
    println!("2. Subdomain enumeration");
    println!("3. Comprehensive domain analysis");
    println!("4. URL technology scan");
    let choice = get_user_input("Choice")?;
    match choice.trim() {
        "1" => {
            println!(
                "{} Getting WHOIS for: {}",
                style("🔍").cyan(),
                style(&domain).cyan()
            );
            run_module("whois", &format!("{} --parse", domain)).await?;
        }
        "2" => {
            println!(
                "{} Enumerating subdomains for: {}",
                style("🔍").cyan(),
                style(&domain).cyan()
            );
            let fast = get_yes_no("Use fast mode (skip alive check)?");
            if fast {
                run_module("subdomain", &format!("{} --skip-alive-check", domain)).await?;
            } else {
                run_module("subdomain", &domain).await?;
            }
        }
        "3" => {
            println!(
                "{} Running comprehensive domain analysis...",
                style("🔄").cyan()
            );
            run_module("whois", &format!("{} --parse", domain)).await?;
            run_module("subdomain", &domain).await?;
            run_module("domain", &format!("{} --dns --ssl", domain)).await?;
        }
        "4" => {
            println!(
                "{} Scanning URL: https://{}",
                style("🔍").cyan(),
                style(&domain).cyan()
            );
            run_module("urlscan", &format!("https://{}", domain)).await?;
        }
        _ => println!("{} Invalid choice", style("❌").red()),
    }
    Ok(())
}
async fn social_investigation() -> Result<()> {
    println!("{}", style("📱 Social Media Investigation").green().bold());
    println!();
    let target = get_user_input("Enter username or profile")?;
    println!("{}", style("Select investigation type:").yellow());
    println!("1. Social media profiles");
    println!("2. GitHub analysis");
    println!("3. Comprehensive social investigation");
    let choice = get_user_input("Choice")?;
    match choice.trim() {
        "1" => {
            println!(
                "{} Searching social profiles: {}",
                style("🔍").cyan(),
                style(&target).cyan()
            );
            run_module("social", &format!("{} --analyze", target)).await?;
        }
        "2" => {
            println!(
                "{} Analyzing GitHub profile: {}",
                style("🔍").cyan(),
                style(&target).cyan()
            );
            run_module("github", &format!("{} --repos --secrets", target)).await?;
        }
        "3" => {
            println!(
                "{} Running comprehensive social investigation...",
                style("🔄").cyan()
            );
            run_module("social", &format!("{} --analyze", target)).await?;
            run_module("github", &format!("{} --repos", target)).await?;
        }
        _ => println!("{} Invalid choice", style("❌").red()),
    }
    Ok(())
}
async fn network_analysis() -> Result<()> {
    println!("{}", style("🖥️ Network Analysis Workflow").green().bold());
    println!();
    let target = get_user_input("Enter IP address or hostname")?;
    println!("{}", style("Select analysis type:").yellow());
    println!("1. IP geolocation");
    println!("2. Port scanning");
    println!("3. Comprehensive network analysis");
    let choice = get_user_input("Choice")?;
    match choice.trim() {
        "1" => {
            println!(
                "{} Geolocating IP: {}",
                style("🔍").cyan(),
                style(&target).cyan()
            );
            run_module("geoip", &format!("{} --isp", target)).await?;
            run_module("ip", &format!("{} --geo --asn", target)).await?;
        }
        "2" => {
            println!(
                "{} Scanning ports: {}",
                style("🔍").cyan(),
                style(&target).cyan()
            );
            run_module("portscan", &target).await?;
        }
        "3" => {
            println!(
                "{} Running comprehensive network analysis...",
                style("🔄").cyan()
            );
            run_module("ip", &format!("{} --geo --asn --reverse", target)).await?;
            run_module("portscan", &target).await?;
            run_module("whois", &target).await?;
        }
        _ => println!("{} Invalid choice", style("❌").red()),
    }
    Ok(())
}
async fn security_assessment() -> Result<()> {
    println!("{}", style("🛡️ Security Assessment Tools").green().bold());
    println!();
    println!("{}", style("Select assessment type:").yellow());
    println!("1. Hash analysis");
    println!("2. Data breach checking");
    println!("3. URL security scan");
    println!("4. Shodan search");
    let choice = get_user_input("Choice")?;
    match choice.trim() {
        "1" => {
            let hash = get_user_input("Enter hash to analyze")?;
            println!(
                "{} Analyzing hash: {}",
                style("🔍").cyan(),
                style(&hash).cyan()
            );
            run_module("hash", &format!("{} --identify --crack", hash)).await?;
        }
        "2" => {
            let email = get_user_input("Enter email to check for breaches")?;
            println!(
                "{} Checking breaches for: {}",
                style("🔍").cyan(),
                style(&email).cyan()
            );
            run_module("leaks", &format!("{} --hibp --passwords", email)).await?;
        }
        "3" => {
            let url = get_user_input("Enter URL to scan")?;
            println!(
                "{} Scanning URL: {}",
                style("🔍").cyan(),
                style(&url).cyan()
            );
            run_module("urlscan", &url).await?;
        }
        "4" => {
            let query = get_user_input("Enter Shodan search query")?;
            println!(
                "{} Searching Shodan: {}",
                style("🔍").cyan(),
                style(&query).cyan()
            );
            run_module("shodan", &format!("{} --vulns", query)).await?;
        }
        _ => println!("{} Invalid choice", style("❌").red()),
    }
    Ok(())
}
async fn show_configuration() -> Result<()> {
    println!("{}", style("⚙️ BUIT Configuration").green().bold());
    println!();
    run_module("config", "list").await?;
    println!();
    println!("{}", style("Configuration options:").yellow());
    println!("1. Set thread count");
    println!("2. Set proxy");
    println!("3. Set user agent");
    println!("4. Add API key");
    println!("0. Back to main menu");
    let choice = get_user_input("Choice")?;
    match choice.trim() {
        "1" => {
            let threads = get_user_input("Enter thread count (1-50)")?;
            run_module("config", &format!("set-threads {}", threads)).await?;
        }
        "2" => {
            let proxy = get_user_input("Enter proxy URL (e.g., http://127.0.0.1:8080)")?;
            run_module("config", &format!("set-proxy {}", proxy)).await?;
        }
        "3" => {
            println!("Available user agents: chrome, firefox, safari, edge, mobile, bot");
            let agent = get_user_input("Enter user agent")?;
            run_module("config", &format!("set-user-agent {}", agent)).await?;
        }
        "4" => {
            let service = get_user_input("Enter service name (shodan, hibp, etc.)")?;
            let key = get_user_input("Enter API key")?;
            run_module("config", &format!("set-key {} {}", service, key)).await?;
        }
        "0" => return Ok(()),
        _ => println!("{} Invalid choice", style("❌").red()),
    }
    Ok(())
}
fn show_help() {
    println!("{}", style("❓ BUIT Help & Documentation").green().bold());
    println!();
    println!("{} Available modules:", style("📚").cyan());
    let modules = [
        ("username", "Search usernames across social platforms"),
        ("email", "Email investigation and breach checking"),
        ("phone", "Phone number analysis and carrier lookup"),
        ("subdomain", "Subdomain enumeration via CT logs and DNS"),
        ("whois", "WHOIS lookup for domains and IPs"),
        ("ip", "IP address analysis with geolocation"),
        ("urlscan", "URL analysis and technology detection"),
        ("hash", "Hash identification and basic cracking"),
        ("github", "GitHub profile and repository analysis"),
        ("geoip", "Detailed IP geolocation"),
        ("portscan", "Network port scanning"),
        ("wayback", "Wayback Machine historical analysis"),
        ("leaks", "Data breach and leak checking"),
        ("shodan", "Shodan device and service search"),
        ("social", "Social media reconnaissance"),
        ("domain", "Comprehensive domain analysis"),
    ];
    for (module, description) in modules.iter() {
        println!("  {} {}", style(module).yellow().bold(), description);
    }
    println!();
    println!("{} For detailed help on any module:", style("💡").yellow());
    println!("  buit <module> --help");
    println!();
    println!("{} Examples:", style("🎯").cyan());
    println!("  buit username john_doe");
    println!("  buit subdomain example.com --skip-alive-check");
    println!("  buit whois example.com --parse");
    println!("  buit ip 8.8.8.8 --geo");
}
async fn run_module(module: &str, args: &str) -> Result<()> {
    println!(
        "{} Running: buit {} {}",
        style("▶️").green(),
        style(module).yellow(),
        style(args).cyan()
    );
    println!("{}", style("─".repeat(50)).dim());
    use tokio::process::Command;
    let output = Command::new("./target/release/buit")
        .arg(module)
        .args(args.split_whitespace())
        .output()
        .await;
    match output {
        Ok(result) => {
            if !result.stdout.is_empty() {
                println!("{}", String::from_utf8_lossy(&result.stdout));
            }
            if !result.stderr.is_empty() {
                println!("{}", String::from_utf8_lossy(&result.stderr));
            }
        }
        Err(e) => {
            println!("{} Error running module: {}", style("❌").red(), e);
        }
    }
    println!("{}", style("─".repeat(50)).dim());
    println!("{} Module execution completed", style("✅").green());
    Ok(())
}
fn get_user_input(prompt: &str) -> Result<String> {
    print!("{} {}: ", style("➤").blue(), style(prompt).yellow());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
fn get_yes_no(prompt: &str) -> bool {
    loop {
        print!("{} {} (y/n): ", style("➤").blue(), style(prompt).yellow());
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("{} Please enter 'y' or 'n'", style("❌").red()),
        }
    }
}
