use crate::cli::BreachCheckArgs;
use crate::config::Config;
use crate::utils::http::{HttpClient, HttpError};
use anyhow::Result;
use console::style;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BreachInfo {
    pub name: String,
    pub domain: String,
    pub breach_date: String,
    pub added_date: String,
    pub pwn_count: u64,
    pub description: String,
    pub data_classes: Vec<String>,
    pub is_verified: bool,
    pub is_fabricated: bool,
    pub is_sensitive: bool,
    pub is_retired: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BreachCheckResult {
    pub target: String,
    pub target_type: String,
    pub breaches: Vec<BreachInfo>,
    pub total_accounts_breached: u64,
    pub sources_checked: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

pub async fn run(args: BreachCheckArgs) -> Result<()> {
    println!(
        "{} Breach check: {}",
        style("🔓").cyan(),
        style(&args.target).yellow().bold()
    );

    let config = Config::load()?;
    let client = HttpClient::new()?;
    let mut result = BreachCheckResult {
        target: args.target.clone(),
        target_type: determine_target_type(&args.target),
        breaches: Vec::new(),
        total_accounts_breached: 0,
        sources_checked: Vec::new(),
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    // Check HaveIBeenPwned
    if args.hibp || args.all {
        result.sources_checked.push("HaveIBeenPwned".to_string());
        match config.get_api_key("hibp") {
            Some(api_key) => match check_hibp_api(&client, &args.target, &api_key).await {
                Ok((breaches, mut src_warnings, mut src_errors)) => {
                    result.total_accounts_breached +=
                        breaches.iter().map(|b| b.pwn_count).sum::<u64>();
                    result.breaches.extend(breaches);
                    warnings.append(&mut src_warnings);
                    errors.append(&mut src_errors);
                }
                Err(e) => errors.push(format!("HIBP request failed: {}", e)),
            },
            None => warnings.push("API key hibp missing".to_string()),
        }
    }

    // Check DeHashed (if configured)
    if args.dehashed || args.all {
        result.sources_checked.push("DeHashed".to_string());
        match config.get_api_key("dehashed") {
            Some(api_key) => match check_dehashed_api(&client, &args.target, &api_key).await {
                Ok((breaches, mut src_warnings, mut src_errors)) => {
                    result.breaches.extend(breaches);
                    warnings.append(&mut src_warnings);
                    errors.append(&mut src_errors);
                }
                Err(e) => errors.push(format!("DeHashed request failed: {}", e)),
            },
            None => warnings.push("API key dehashed missing".to_string()),
        }
    }

    // Check IntelX (if configured)
    if args.intelx || args.all {
        result.sources_checked.push("IntelX".to_string());
        match config.get_api_key("intelx") {
            Some(api_key) => match check_intelx_api(&client, &args.target, &api_key).await {
                Ok((breaches, mut src_warnings, mut src_errors)) => {
                    result.breaches.extend(breaches);
                    warnings.append(&mut src_warnings);
                    errors.append(&mut src_errors);
                }
                Err(e) => errors.push(format!("IntelX request failed: {}", e)),
            },
            None => warnings.push("API key intelx missing".to_string()),
        }
    }

    // Remove duplicates
    result
        .breaches
        .dedup_by(|a, b| a.name == b.name && a.breach_date == b.breach_date);
    result
        .breaches
        .sort_by(|a, b| b.breach_date.cmp(&a.breach_date));

    result.warnings = warnings;
    result.errors = errors;

    display_results(&result);
    Ok(())
}

fn determine_target_type(target: &str) -> String {
    if target.contains('@') {
        "email".to_string()
    } else if target
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        "username".to_string()
    } else {
        "unknown".to_string()
    }
}

async fn check_hibp_api(
    client: &HttpClient,
    target: &str,
    api_key: &str,
) -> Result<(Vec<BreachInfo>, Vec<String>, Vec<String>)> {
    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}",
        target
    );

    let headers = vec![("hibp-api-key", api_key), ("User-Agent", "BUIT-OSINT-Tool")];

    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    let response = match client.get_with_headers(&url, &headers).await {
        Ok(body) => body,
        Err(HttpError::BadStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
            warnings.push("No HIBP records found".to_string());
            return Ok((Vec::new(), warnings, errors));
        }
        Err(HttpError::BadStatus { status, .. }) if status == StatusCode::UNAUTHORIZED => {
            errors.push("HIBP rejected credentials".to_string());
            return Ok((Vec::new(), warnings, errors));
        }
        Err(err) => return Err(err.into()),
    };

    let hibp_breaches: Vec<serde_json::Value> = serde_json::from_str(&response)?;

    let mut breaches = Vec::new();
    for breach_data in hibp_breaches {
        breaches.push(BreachInfo {
            name: breach_data["Name"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string(),
            domain: breach_data["Domain"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string(),
            breach_date: breach_data["BreachDate"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string(),
            added_date: breach_data["AddedDate"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string(),
            pwn_count: breach_data["PwnCount"].as_u64().unwrap_or(0),
            description: breach_data["Description"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            data_classes: breach_data["DataClasses"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            is_verified: breach_data["IsVerified"].as_bool().unwrap_or(false),
            is_fabricated: breach_data["IsFabricated"].as_bool().unwrap_or(false),
            is_sensitive: breach_data["IsSensitive"].as_bool().unwrap_or(false),
            is_retired: breach_data["IsRetired"].as_bool().unwrap_or(false),
        });
    }

    Ok((breaches, warnings, errors))
}

async fn check_dehashed_api(
    _client: &HttpClient,
    _target: &str,
    _api_key: &str,
) -> Result<(Vec<BreachInfo>, Vec<String>, Vec<String>)> {
    let warnings = vec!["DeHashed integration not implemented".to_string()];
    Ok((Vec::new(), warnings, Vec::new()))
}

async fn check_intelx_api(
    _client: &HttpClient,
    _target: &str,
    _api_key: &str,
) -> Result<(Vec<BreachInfo>, Vec<String>, Vec<String>)> {
    let warnings = vec!["IntelX integration not implemented".to_string()];
    Ok((Vec::new(), warnings, Vec::new()))
}

fn display_results(result: &BreachCheckResult) {
    println!("\n{}", style("Breach Check Results:").green().bold());
    println!("{}", style("═══════════════════").cyan());
    println!(
        "  {} {}",
        style("Target:").yellow(),
        style(&result.target).cyan()
    );
    println!(
        "  {} {}",
        style("Type:").yellow(),
        style(&result.target_type).cyan()
    );
    println!(
        "  {} {}",
        style("Sources Checked:").yellow(),
        result.sources_checked.join(", ")
    );
    println!(
        "  {} {}",
        style("Breaches Found:").yellow(),
        if result.breaches.is_empty() {
            style("0").green().to_string()
        } else {
            style(&result.breaches.len().to_string())
                .red()
                .bold()
                .to_string()
        }
    );

    if !result.breaches.is_empty() {
        println!(
            "  {} {}",
            style("Total Accounts:").yellow(),
            style(result.total_accounts_breached.to_string())
                .red()
                .bold()
        );

        println!("\n{}", style("Breach Details:").red().bold());
        for breach in &result.breaches {
            println!(
                "\n  {} {} ({})",
                style("🔓").red(),
                style(&breach.name).red().bold(),
                style(&breach.breach_date).yellow()
            );

            if !breach.domain.is_empty() && breach.domain != "Unknown" {
                println!("    {} {}", style("Domain:").dim(), breach.domain);
            }

            if breach.pwn_count > 0 {
                println!(
                    "    {} {}",
                    style("Accounts:").dim(),
                    style(breach.pwn_count.to_string()).red()
                );
            }

            if !breach.data_classes.is_empty() {
                println!(
                    "    {} {}",
                    style("Data Types:").dim(),
                    breach.data_classes.join(", ")
                );
            }

            // Security indicators
            let mut indicators = Vec::new();
            if breach.is_verified {
                indicators.push(style("Verified").green());
            }
            if breach.is_sensitive {
                indicators.push(style("Sensitive").red());
            }
            if breach.is_fabricated {
                indicators.push(style("Fabricated").yellow());
            }
            if breach.is_retired {
                indicators.push(style("Retired").dim());
            }

            if !indicators.is_empty() {
                println!(
                    "    {} {}",
                    style("Status:").dim(),
                    indicators
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            if !breach.description.is_empty() {
                let desc = if breach.description.len() > 100 {
                    format!("{}...", &breach.description[..100])
                } else {
                    breach.description.clone()
                };
                println!("    {} {}", style("Description:").dim(), style(desc).dim());
            }
        }

        println!("\n{}", style("⚠ SECURITY RECOMMENDATIONS:").red().bold());
        println!("  • Change passwords on all affected accounts immediately");
        println!("  • Enable two-factor authentication where possible");
        println!("  • Monitor accounts for suspicious activity");
        println!("  • Consider using a password manager");
        println!("  • Check if sensitive data was compromised");
    } else {
        println!("\n{} No breaches found for this target", style("✓").green());
        println!(
            "{} This doesn't guarantee safety - continue monitoring",
            style("ℹ").cyan()
        );
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
