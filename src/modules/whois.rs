use crate::cli::WhoisArgs;
use crate::utils::http::HttpClient;
use anyhow::Result;
use console::style;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
#[derive(Debug, Serialize, Deserialize)]
pub struct WhoisResult {
    pub target: String,
    pub target_type: String,
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub name_servers: Vec<String>,
    pub organization: Option<String>,
    pub country: Option<String>,
    pub emails: Vec<String>,
    pub raw_data: String,
    pub parsed: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
pub async fn run(args: WhoisArgs) -> Result<()> {
    println!(
        "{} WHOIS lookup: {}",
        style("🔍").cyan(),
        style(&args.target).yellow().bold()
    );
    let client = HttpClient::new()?;
    let target_type = if args.target.parse::<IpAddr>().is_ok() {
        "IP"
    } else {
        "Domain"
    };
    let mut result = WhoisResult {
        target: args.target.clone(),
        target_type: target_type.to_string(),
        registrar: None,
        creation_date: None,
        expiration_date: None,
        name_servers: vec![],
        organization: None,
        country: None,
        emails: vec![],
        raw_data: String::new(),
        parsed: false,
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    let mut success = false;
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    println!("  {} Trying local WHOIS command...", style("🔍").cyan());
    if let Ok(output) = std::process::Command::new("whois")
        .arg(&args.target)
        .output()
    {
        if !output.stdout.is_empty() {
            result.raw_data = String::from_utf8_lossy(&output.stdout).to_string();
            success = true;
            if args.parse {
                let data = result.raw_data.clone();
                parse_whois_text(&mut result, &data);
            }
            println!("  {} Local WHOIS command successful", style("✓").green());
        } else if !output.stderr.is_empty() {
            let error = String::from_utf8_lossy(&output.stderr);
            println!(
                "  {} Local WHOIS command failed: {}",
                style("⚠").yellow(),
                error.trim()
            );
            warnings.push(format!("Local WHOIS command failed: {}", error.trim()));
        }
    } else {
        println!(
            "  {} Local WHOIS command not available",
            style("⚠").yellow()
        );
        warnings.push("Local WHOIS command not available".to_string());
    }
    if !success {
        println!("  {} Trying web services...", style("🔍").cyan());
        let whois_services = if target_type == "IP" {
            vec![format!("https://ipapi.co/{}/json", args.target)]
        } else {
            vec![format!("http://whois.domaintools.com/{}", args.target)]
        };
        for (index, url) in whois_services.iter().enumerate() {
            println!(
                "  {} Trying web service {}...",
                style("🔍").cyan(),
                index + 1
            );
            match client.get(url).await {
                Ok(response) => {
                    if !response.is_empty()
                        && !response.contains("error")
                        && !response.contains("API Key")
                        && !response.contains("captcha")
                        && !response.contains("Security Check")
                    {
                        result.raw_data = response.clone();
                        success = true;
                        if args.parse {
                            if target_type == "IP" && url.contains("ipapi.co") {
                                parse_ipapi_data(&mut result, &response);
                            } else {
                                parse_whois_text(&mut result, &response);
                            }
                        }
                        println!("  {} Web service successful", style("✓").green());
                        break;
                    } else {
                        warnings.push(format!("Web service response from {} was unusable", url));
                    }
                }
                Err(err) => {
                    println!("  {} Web service {} failed", style("⚠").yellow(), index + 1);
                    warnings.push(format!("Web service {} failed: {}", url, err));
                    continue;
                }
            }
        }
    }
    if !success {
        println!("  {} All lookup methods failed", style("✗").red());
        errors.push(format!(
            "WHOIS lookup failed for {} via local command and web services",
            args.target
        ));
    }
    result.warnings = warnings;
    result.errors = errors;
    display_results(&result, args.parse);
    Ok(())
}
fn parse_ipapi_data(result: &mut WhoisResult, data: &str) {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
        result.organization = json
            .get("org")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        result.country = json
            .get("country_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Ok(formatted) = serde_json::to_string_pretty(&json) {
            result.raw_data = formatted;
        }
        result.parsed = true;
    }
}
fn parse_whois_text(result: &mut WhoisResult, data: &str) {
    let lines: Vec<&str> = data.lines().collect();
    for line in lines {
        let line = line.trim();
        if line.to_lowercase().contains("registrar:") {
            if let Some(value) = extract_value_after_colon(line) {
                result.registrar = Some(value);
            }
        }
        if line.to_lowercase().contains("creation date:")
            || line.to_lowercase().contains("created:")
            || line.to_lowercase().contains("registered:")
        {
            if let Some(value) = extract_value_after_colon(line) {
                result.creation_date = Some(value);
            }
        }
        if line.to_lowercase().contains("expiry date:")
            || line.to_lowercase().contains("expiration date:")
            || line.to_lowercase().contains("expires:")
        {
            if let Some(value) = extract_value_after_colon(line) {
                result.expiration_date = Some(value);
            }
        }
        if line.to_lowercase().contains("name server:")
            || line.to_lowercase().contains("nameserver:")
        {
            if let Some(value) = extract_value_after_colon(line) {
                result.name_servers.push(value);
            }
        }
        if line.to_lowercase().contains("organization:")
            || line.to_lowercase().contains("org:")
            || line.to_lowercase().contains("orgname:")
        {
            if let Some(value) = extract_value_after_colon(line) {
                result.organization = Some(value);
            }
        }
        if line.to_lowercase().contains("country:") {
            if let Some(value) = extract_value_after_colon(line) {
                result.country = Some(value);
            }
        }
        if line.contains("@")
            && (line.to_lowercase().contains("email:")
                || line.to_lowercase().contains("abuse")
                || line.to_lowercase().contains("contact"))
        {
            if let Some(email) = extract_email_from_line(line) {
                if !result.emails.contains(&email) {
                    result.emails.push(email);
                }
            }
        }
    }
    result.parsed = true;
}
fn extract_value_after_colon(line: &str) -> Option<String> {
    if let Some(pos) = line.find(':') {
        let value = line[pos + 1..].trim();
        if !value.is_empty() && value != "REDACTED FOR PRIVACY" {
            return Some(value.to_string());
        }
    }
    None
}
fn extract_email_from_line(line: &str) -> Option<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    for word in words {
        if word.contains("@") && word.contains(".") {
            let email = word.trim_end_matches(&[',', '.', ')', ']'][..]);
            if email.matches('@').count() == 1 {
                return Some(email.to_string());
            }
        }
    }
    None
}
fn display_results(result: &WhoisResult, parse: bool) {
    println!("\n{}", style("WHOIS Results:").green().bold());
    println!("{}", style("══════════════").cyan());
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
    if parse && result.parsed {
        if let Some(registrar) = &result.registrar {
            println!(
                "  {} {}",
                style("Registrar:").yellow(),
                style(registrar).cyan()
            );
        }
        if let Some(creation) = &result.creation_date {
            println!(
                "  {} {}",
                style("Created:").yellow(),
                style(creation).cyan()
            );
        }
        if let Some(expiration) = &result.expiration_date {
            println!(
                "  {} {}",
                style("Expires:").yellow(),
                style(expiration).cyan()
            );
        }
        if let Some(org) = &result.organization {
            println!(
                "  {} {}",
                style("Organization:").yellow(),
                style(org).cyan()
            );
        }
        if let Some(country) = &result.country {
            println!("  {} {}", style("Country:").yellow(), style(country).cyan());
        }
        if !result.name_servers.is_empty() {
            println!("\n{}", style("Name Servers:").yellow());
            for ns in &result.name_servers {
                println!("  • {}", style(ns).cyan());
            }
        }
        if !result.emails.is_empty() {
            println!("\n{}", style("Contact Emails:").yellow());
            for email in &result.emails {
                println!("  • {}", style(email).cyan());
            }
        }
    } else if !result.raw_data.is_empty() {
        println!("\n{}", style("Raw WHOIS Data:").yellow());
        println!("{}", style("═══════════════").cyan());
        println!("{}", result.raw_data);
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
