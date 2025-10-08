use crate::cli::EmailArgs;
use crate::config::Config;
use crate::utils::http::{HttpClient, HttpError};
use crate::utils::json;
use anyhow::Result;
use console::style;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailResult {
    pub email: String,
    pub valid_format: bool,
    pub services: Vec<ServiceCheck>,
    pub breaches: Vec<BreachInfo>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceCheck {
    pub service: String,
    pub registered: bool,
    pub profile_url: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct BreachInfo {
    pub name: String,
    pub date: String,
    pub compromised_data: Vec<String>,
}
pub async fn run(args: EmailArgs) -> Result<()> {
    println!(
        "{} Checking email: {}",
        style("📧").cyan(),
        style(&args.email).yellow().bold()
    );
    if !validate_email(&args.email) {
        println!("{} Invalid email format", style("✗").red());
        return Ok(());
    }
    let client = HttpClient::new()?;
    let config = Config::load()?;
    let mut results = EmailResult {
        email: args.email.clone(),
        valid_format: true,
        services: vec![],
        breaches: vec![],
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    if args.social {
        println!("\n{} Checking social media accounts...", style("🔍").cyan());
        let social_outcome = check_social_accounts(&client, &args.email).await?;
        results.services = social_outcome.0;
        results.warnings.extend(social_outcome.1);
        results.errors.extend(social_outcome.2);
    }
    if args.breaches {
        println!("\n{} Checking for data breaches...", style("🔍").cyan());
        let breach_outcome = check_breaches(&client, &config, &args.email).await?;
        results.breaches = breach_outcome.0;
        results.warnings.extend(breach_outcome.1);
        results.errors.extend(breach_outcome.2);
    }
    display_results(&results, &args.format);
    Ok(())
}
fn validate_email(email: &str) -> bool {
    match regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") {
        Ok(re) => re.is_match(email),
        Err(e) => {
            eprintln!("Email validation regex error: {}", e);
            false
        }
    }
}
async fn check_social_accounts(
    client: &HttpClient,
    email: &str,
) -> Result<(Vec<ServiceCheck>, Vec<String>, Vec<String>)> {
    let mut services = Vec::new();
    #[allow(unused_mut)]
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    match check_github(client, email).await {
        Ok(registered) => {
            services.push(ServiceCheck {
                service: "GitHub".to_string(),
                registered,
                profile_url: None,
            });
        }
        Err(err) => {
            errors.push(format!("GitHub lookup failed: {}", err));
        }
    }

    match check_gravatar(client, email).await {
        Ok(registered) => {
            services.push(ServiceCheck {
                service: "Gravatar".to_string(),
                registered,
                profile_url: Some(format!("https://gravatar.com/{}", hash_email(email))),
            });
        }
        Err(err) => {
            errors.push(format!("Gravatar lookup failed: {}", err));
        }
    }

    Ok((services, warnings, errors))
}

async fn check_github(client: &HttpClient, email: &str) -> Result<bool> {
    let url = format!("https://api.github.com/search/users?q={}", email);
    match client.get(&url).await {
        Ok(response) => {
            Ok(response.contains("total_count") && !response.contains("\"total_count\":0"))
        }
        Err(err) => Err(anyhow::anyhow!("GitHub API error: {}", err)),
    }
}

async fn check_gravatar(client: &HttpClient, email: &str) -> Result<bool> {
    let hash = hash_email(email);
    let url = format!("https://www.gravatar.com/avatar/{}?d=404", hash);
    match client.check_url(&url).await {
        Ok(true) => Ok(true),
        Ok(false) => Ok(false),
        Err(err) => Err(anyhow::anyhow!(err)),
    }
}
fn hash_email(email: &str) -> String {
    // Note: Using SHA-256 for hashing before Gravatar request
    let mut hasher = Sha256::new();
    hasher.update(email.trim().to_lowercase().as_bytes());
    format!("{:x}", hasher.finalize())
}
async fn check_breaches(
    client: &HttpClient,
    config: &Config,
    email: &str,
) -> Result<(Vec<BreachInfo>, Vec<String>, Vec<String>)> {
    let mut breaches = Vec::new();
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if let Some(api_key) = config.get_api_key("hibp") {
        let hibp_url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{}",
            email
        );
        match client
            .get_with_headers(
                &hibp_url,
                &[
                    ("User-Agent", "BUIT-OSINT-Tool"),
                    ("hibp-api-key", api_key.as_str()),
                ],
            )
            .await
        {
            Ok(response) => {
                if let Ok(hibp_breaches) = json::from_str::<Vec<serde_json::Value>>(&response) {
                    for breach_data in hibp_breaches {
                        if let (Some(name), Some(breach_date)) = (
                            breach_data.get("Name").and_then(|v| v.as_str()),
                            breach_data.get("BreachDate").and_then(|v| v.as_str()),
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

                            breaches.push(BreachInfo {
                                name: name.to_string(),
                                date: breach_date.to_string(),
                                compromised_data: data_classes,
                            });
                        }
                    }
                }
            }
            Err(HttpError::BadStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                warnings.push("No HIBP records found".to_string());
            }
            Err(err) => {
                errors.push(format!("HIBP request failed: {}", err));
            }
        }
    } else {
        warnings.push("API key hibp missing".to_string());
    }

    match config.get_api_key("snusbase") {
        Some(api_key) => {
            let snusbase_url = format!("https://snusbase.com/api/search?term={}&type=email", email);
            match client
                .get_with_headers(
                    &snusbase_url,
                    &[
                        ("Auth", api_key.as_str()),
                        ("Content-Type", "application/json"),
                    ],
                )
                .await
            {
                Ok(response) => {
                    if let Ok(data) = json::from_str::<serde_json::Value>(&response) {
                        if let Some(results) = data.get("results").and_then(|v| v.as_object()) {
                            for (db_name, _entries) in results {
                                breaches.push(BreachInfo {
                                    name: db_name.clone(),
                                    date: "Unknown".to_string(),
                                    compromised_data: vec!["Email addresses".to_string()],
                                });
                            }
                        }
                    }
                }
                Err(err) => {
                    errors.push(format!("Snusbase request failed: {}", err));
                }
            }
        }
        None => warnings.push("API key snusbase missing".to_string()),
    }

    warnings.push("PwnDB lookup skipped (requires Tor connectivity)".to_string());

    Ok((breaches, warnings, errors))
}
fn display_results(results: &EmailResult, format: &str) {
    match format {
        "json" => {
            println!("{}", json::to_string_pretty(results).unwrap());
        }
        _ => {
            println!("\n{}", style("Results:").green().bold());
            println!("{}", style("════════").cyan());
            if !results.services.is_empty() {
                println!("\n{}", style("Social Media Accounts:").yellow());
                for service in &results.services {
                    let status = if service.registered {
                        style("✓").green()
                    } else {
                        style("✗").red()
                    };
                    println!("  {} {}", status, service.service);
                    if let Some(url) = &service.profile_url {
                        println!("      {}", style(url).blue().underlined());
                    }
                }
            }
            if !results.breaches.is_empty() {
                println!("\n{}", style("Data Breaches:").red());
                for breach in &results.breaches {
                    println!(
                        "  {} {} ({})",
                        style("⚠").yellow(),
                        breach.name,
                        breach.date
                    );
                    println!("    Compromised: {}", breach.compromised_data.join(", "));
                }
            }
            if !results.warnings.is_empty() {
                println!("\n{}", style("Warnings:").yellow());
                for warning in &results.warnings {
                    println!("  {} {}", style("⚠").yellow(), warning);
                }
            }
            if !results.errors.is_empty() {
                println!("\n{}", style("Errors:").red());
                for error in &results.errors {
                    println!("  {} {}", style("✗").red(), error);
                }
            }
        }
    }
}
