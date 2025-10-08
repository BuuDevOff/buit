use crate::cli::LeaksArgs;
use crate::config::Config;
use crate::utils::http::{HttpClient, HttpError};
use anyhow::Result;
use console::style;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct LeaksResult {
    pub target: String,
    pub breaches: Vec<Breach>,
    pub password_dumps: Vec<PasswordDump>,
    pub total_breaches: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Breach {
    pub name: String,
    pub date: String,
    pub compromised_accounts: u64,
    pub compromised_data: Vec<String>,
    pub description: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordDump {
    pub source: String,
    pub password: String,
    pub hash_type: String,
}
pub async fn run(args: LeaksArgs) -> Result<()> {
    println!(
        "{} Checking leaks for: {}",
        style("💧").cyan(),
        style(&args.target).yellow().bold()
    );
    let config = Config::load()?;
    let client = HttpClient::new()?;
    let mut result = LeaksResult {
        target: args.target.clone(),
        breaches: vec![],
        password_dumps: vec![],
        total_breaches: 0,
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    if args.hibp {
        println!("\n{} Checking HaveIBeenPwned...", style("🔍").cyan());
        if config.get_api_key("hibp").is_none() {
            result.warnings.push("API key hibp missing".to_string());
        }
        let (breaches, mut warnings, mut errors) =
            check_hibp(&client, &config, &args.target).await?;
        result.breaches = breaches;
        result.total_breaches = result.breaches.len();
        result.warnings.append(&mut warnings);
        result.errors.append(&mut errors);
    }
    if args.passwords {
        println!("\n{} Checking password dumps...", style("🔒").cyan());
        let (password_dumps, mut warnings, mut errors) =
            check_password_dumps(&client, &args.target).await?;
        result.password_dumps = password_dumps;
        result.warnings.append(&mut warnings);
        result.errors.append(&mut errors);
    }
    display_results(&result);
    Ok(())
}
async fn check_hibp(
    client: &HttpClient,
    config: &Config,
    target: &str,
) -> Result<(Vec<Breach>, Vec<String>, Vec<String>)> {
    let mut breaches = Vec::new();
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    let Some(api_key) = config.get_api_key("hibp") else {
        return Ok((breaches, warnings, errors));
    };

    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}",
        target
    );

    match client
        .get_with_headers(
            &url,
            &[
                ("User-Agent", "BUIT-OSINT-Tool"),
                ("hibp-api-key", api_key.as_str()),
            ],
        )
        .await
    {
        Ok(response) => {
            if let Ok(hibp_breaches) = serde_json::from_str::<Vec<serde_json::Value>>(&response) {
                for breach_data in hibp_breaches {
                    if let (Some(name), Some(breach_date), Some(pwn_count)) = (
                        breach_data.get("Name").and_then(|v| v.as_str()),
                        breach_data.get("BreachDate").and_then(|v| v.as_str()),
                        breach_data.get("PwnCount").and_then(|v| v.as_u64()),
                    ) {
                        let data_classes = breach_data
                            .get("DataClasses")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect::<Vec<String>>()
                            })
                            .unwrap_or_default();

                        let description = breach_data
                            .get("Description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("No description available")
                            .to_string();

                        breaches.push(Breach {
                            name: name.to_string(),
                            date: breach_date.to_string(),
                            compromised_accounts: pwn_count,
                            compromised_data: data_classes,
                            description,
                        });
                    }
                }
            } else {
                errors.push("Failed to parse HIBP response".to_string());
            }
        }
        Err(HttpError::BadStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
            warnings.push("No HIBP records found".to_string());
        }
        Err(err) => {
            errors.push(format!("HIBP request failed: {}", err));
        }
    }

    Ok((breaches, warnings, errors))
}
async fn check_password_dumps(
    _client: &HttpClient,
    target: &str,
) -> Result<(Vec<PasswordDump>, Vec<String>, Vec<String>)> {
    let mut warnings = Vec::new();
    if target.is_empty() {
        warnings.push("No target provided for password dump lookup".to_string());
    } else {
        warnings.push(
            "Password dump lookup not implemented; use dedicated breach datasets".to_string(),
        );
    }
    Ok((Vec::new(), warnings, Vec::new()))
}
fn display_results(result: &LeaksResult) {
    println!("\n{}", style("Data Breach Results:").green().bold());
    println!("{}", style("═══════════════════").cyan());
    println!(
        "  {} {}",
        style("Target:").yellow(),
        style(&result.target).cyan()
    );
    println!(
        "  {} {}",
        style("Breaches Found:").yellow(),
        style(result.total_breaches.to_string()).red()
    );
    if !result.breaches.is_empty() {
        println!("\n{}", style("Breached Services:").red().bold());
        for breach in &result.breaches {
            println!(
                "  {} {} ({})",
                style("•").red(),
                style(&breach.name).red().bold(),
                style(&breach.date).yellow()
            );
            println!(
                "    Accounts: {}",
                style(breach.compromised_accounts.to_string()).red()
            );
            println!("    Data: {}", breach.compromised_data.join(", "));
            println!("    Description: {}", style(&breach.description).dim());
        }
    }
    if !result.password_dumps.is_empty() {
        println!("\n{}", style("⚠ Password Dumps Found:").red().bold());
        for dump in &result.password_dumps {
            println!(
                "  {} {}",
                style("Source:").yellow(),
                style(&dump.source).red()
            );
            println!("    Password/Hash: {}", style(&dump.password).red());
            println!("    Type: {}", style(&dump.hash_type).cyan());
        }
        println!("\n{}", style("⚠ SECURITY ALERT:").red().bold());
        println!("  This email/username has been found in password dumps!");
        println!("  Consider changing passwords on all accounts.");
    } else if result.breaches.is_empty() {
        println!("\n{} No breaches found for this target", style("✓").green());
    }
    if !result.warnings.is_empty() {
        println!("\n{}", style("Warnings:").yellow());
        for warning in &result.warnings {
            println!("  {} {}", style("⚠").yellow(), warning);
        }
    }
    if !result.errors.is_empty() {
        println!("\n{}", style("Errors:").red());
        for error in &result.errors {
            println!("  {} {}", style("✗").red(), error);
        }
    }
}
