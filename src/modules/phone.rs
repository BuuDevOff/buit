use crate::cli::PhoneArgs;
use crate::config::Config;
use crate::utils::http::{HttpClient, HttpError};
use anyhow::Result;
use console::style;
use regex::Regex;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct PhoneResult {
    pub number: String,
    pub formatted: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub carrier: Option<String>,
    pub line_type: Option<String>,
    pub valid: bool,
    pub possible_formats: Vec<String>,
    pub social_media: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
pub async fn run(args: PhoneArgs) -> Result<()> {
    println!(
        "{} Phone number lookup: {}",
        style("📞").cyan(),
        style(&args.number).yellow().bold()
    );
    let cleaned_number = clean_phone_number(&args.number);
    let client = HttpClient::new()?;
    let config = Config::load()?;
    let mut result = PhoneResult {
        number: args.number.clone(),
        formatted: format_phone_number(&cleaned_number),
        country: None,
        country_code: None,
        carrier: None,
        line_type: None,
        valid: validate_phone_number(&cleaned_number),
        possible_formats: generate_formats(&cleaned_number),
        social_media: vec![],
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    if result.valid {
        result.country = identify_country(&cleaned_number);
        result.country_code = extract_country_code(&cleaned_number);
        if args.carrier {
            println!("\n{} Checking carrier information...", style("📡").cyan());
            let (carrier_info, mut warnings, mut errors) =
                lookup_carrier(&client, &config, &cleaned_number).await?;
            result.carrier = carrier_info.carrier;
            result.line_type = carrier_info.line_type;
            result.warnings.append(&mut warnings);
            result.errors.append(&mut errors);
        }
        let (social, mut warnings, mut errors) =
            check_social_media(&client, &config, &cleaned_number).await?;
        result.social_media = social;
        result.warnings.append(&mut warnings);
        result.errors.append(&mut errors);
    } else {
        result
            .warnings
            .push("Phone number failed E.164 validation".to_string());
    }
    display_results(&result, args.format.as_deref());
    Ok(())
}
fn clean_phone_number(number: &str) -> String {
    number.chars().filter(|c| c.is_ascii_digit()).collect()
}
fn format_phone_number(number: &str) -> String {
    if number.len() == 10 && number.starts_with("1") {
        format!(
            "+1 ({}) {}-{}",
            &number[0..3],
            &number[3..6],
            &number[6..10]
        )
    } else if number.len() == 11 && number.starts_with("1") {
        format!(
            "+1 ({}) {}-{}",
            &number[1..4],
            &number[4..7],
            &number[7..11]
        )
    } else if number.len() == 10 {
        format!("({}) {}-{}", &number[0..3], &number[3..6], &number[6..10])
    } else {
        number.to_string()
    }
}
fn validate_phone_number(number: &str) -> bool {
    match Regex::new(r"^\+?[1-9]\d{1,14}$") {
        Ok(re) => re.is_match(number),
        Err(_) => false, // If regex fails, consider invalid
    }
}
fn identify_country(number: &str) -> Option<String> {
    if number.starts_with("1") && number.len() >= 10 {
        Some("United States/Canada".to_string())
    } else if number.starts_with("44") {
        Some("United Kingdom".to_string())
    } else if number.starts_with("33") {
        Some("France".to_string())
    } else if number.starts_with("49") {
        Some("Germany".to_string())
    } else if number.starts_with("86") {
        Some("China".to_string())
    } else if number.starts_with("91") {
        Some("India".to_string())
    } else if number.starts_with("81") {
        Some("Japan".to_string())
    } else if number.starts_with("7") {
        Some("Russia".to_string())
    } else {
        None
    }
}
fn extract_country_code(number: &str) -> Option<String> {
    if number.starts_with("1") && number.len() >= 10 {
        Some("+1".to_string())
    } else if number.len() > 2 {
        let code = &number[0..2];
        Some(format!("+{}", code))
    } else {
        None
    }
}
fn generate_formats(number: &str) -> Vec<String> {
    let mut formats = vec![];
    formats.push(number.to_string());
    formats.push(format!("+{}", number));
    if number.len() == 10 {
        formats.push(format!(
            "({}) {}-{}",
            &number[0..3],
            &number[3..6],
            &number[6..10]
        ));
        formats.push(format!(
            "{}-{}-{}",
            &number[0..3],
            &number[3..6],
            &number[6..10]
        ));
        formats.push(format!(
            "{}.{}.{}",
            &number[0..3],
            &number[3..6],
            &number[6..10]
        ));
    }
    formats
}
struct CarrierInfo {
    carrier: Option<String>,
    line_type: Option<String>,
}

async fn lookup_carrier(
    client: &HttpClient,
    config: &Config,
    number: &str,
) -> Result<(CarrierInfo, Vec<String>, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    let mut carrier_info = CarrierInfo {
        carrier: None,
        line_type: None,
    };

    if let Some(api_key) = config.get_api_key("abstractapi_phone") {
        let url = format!(
            "https://phonevalidation.abstractapi.com/v1/?api_key={}&phone={}",
            api_key, number
        );
        match client.get(&url).await {
            Ok(response) => match serde_json::from_str::<serde_json::Value>(&response) {
                Ok(data) => {
                    carrier_info.carrier = data
                        .get("carrier")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    carrier_info.line_type =
                        data.get("type").and_then(|v| v.as_str()).map(str::to_owned);
                    if carrier_info.carrier.is_none() && carrier_info.line_type.is_none() {
                        warnings.push("AbstractAPI returned no carrier details".to_string());
                    }
                    return Ok((carrier_info, warnings, errors));
                }
                Err(err) => {
                    errors.push(format!("Failed to parse AbstractAPI response: {}", err));
                }
            },
            Err(HttpError::BadStatus { status, .. }) if status == StatusCode::UNAUTHORIZED => {
                errors.push("AbstractAPI rejected credentials".to_string());
            }
            Err(err) => errors.push(format!("AbstractAPI request failed: {}", err)),
        }
    } else {
        warnings.push("API key abstractapi_phone missing".to_string());
    }

    if let Some(api_key) = config.get_api_key("numverify") {
        let fallback_url = format!(
            "http://apilayer.net/api/validate?access_key={}&number={}&country_code=&format=1",
            api_key, number
        );
        match client.get(&fallback_url).await {
            Ok(response) => match serde_json::from_str::<serde_json::Value>(&response) {
                Ok(data) => {
                    carrier_info.carrier = data
                        .get("carrier")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    carrier_info.line_type = data
                        .get("line_type")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    if carrier_info.carrier.is_none() && carrier_info.line_type.is_none() {
                        warnings.push("NumVerify returned no carrier details".to_string());
                    }
                    return Ok((carrier_info, warnings, errors));
                }
                Err(err) => errors.push(format!("Failed to parse NumVerify response: {}", err)),
            },
            Err(HttpError::BadStatus { status, .. }) if status == StatusCode::UNAUTHORIZED => {
                errors.push("NumVerify rejected credentials".to_string());
            }
            Err(err) => errors.push(format!("NumVerify request failed: {}", err)),
        }
    } else {
        warnings.push("API key numverify missing".to_string());
    }

    warnings.push("Carrier lookup failed due to upstream errors".to_string());
    Ok((carrier_info, warnings, errors))
}

async fn check_social_media(
    _client: &HttpClient,
    _config: &Config,
    _number: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let warnings = vec!["Social media probing is not implemented".to_string()];
    Ok((Vec::new(), warnings, Vec::new()))
}
fn display_results(result: &PhoneResult, format: Option<&str>) {
    match format {
        Some("json") => match serde_json::to_string_pretty(result) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("Error serializing phone result to JSON: {}", e),
        },
        _ => {
            println!("\n{}", style("Phone Number Analysis:").green().bold());
            println!("{}", style("═════════════════════").cyan());
            println!("  {} {}", style("Number:").yellow(), result.number);
            println!("  {} {}", style("Formatted:").yellow(), result.formatted);
            println!(
                "  {} {}",
                style("Valid:").yellow(),
                if result.valid {
                    style("✓").green()
                } else {
                    style("✗").red()
                }
            );
            if let Some(country) = &result.country {
                println!("  {} {}", style("Country:").yellow(), style(country).cyan());
            }
            if let Some(code) = &result.country_code {
                println!(
                    "  {} {}",
                    style("Country Code:").yellow(),
                    style(code).cyan()
                );
            }
            if let Some(carrier) = &result.carrier {
                println!("  {} {}", style("Carrier:").yellow(), style(carrier).cyan());
            }
            if let Some(line_type) = &result.line_type {
                println!(
                    "  {} {}",
                    style("Line Type:").yellow(),
                    style(line_type).cyan()
                );
            }
            if !result.possible_formats.is_empty() {
                println!("\n{}", style("Possible Formats:").yellow());
                for format in &result.possible_formats {
                    println!("  • {}", style(format).cyan());
                }
            }
            if !result.social_media.is_empty() {
                println!("\n{}", style("Social Media:").yellow());
                for platform in &result.social_media {
                    println!("  • {}", style(platform).cyan());
                }
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
    }
}
