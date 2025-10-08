use crate::{
    cli::IpArgs,
    utils::{context::AppContext, http::HttpClient, output},
};
use anyhow::Result;
use console::style;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use trust_dns_resolver::{config::*, TokioAsyncResolver};
use utoipa::ToSchema;
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct IpResult {
    pub ip: String,
    pub valid: bool,
    pub version: String,
    pub reverse_dns: Option<String>,
    pub asn: Option<AsnInfo>,
    pub geolocation: Option<GeoInfo>,
    pub ports: Vec<u16>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct AsnInfo {
    pub number: String,
    pub organization: String,
    pub country: String,
}
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct GeoInfo {
    pub country: String,
    pub city: Option<String>,
    pub region: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}
pub async fn run(args: IpArgs) -> Result<IpResult> {
    if output::is_console() {
        println!(
            "{} IP Analysis: {}",
            style("🔍").cyan(),
            style(&args.ip).yellow().bold()
        );
    }
    let ip_addr: IpAddr = args.ip.parse()?;
    let ctx = AppContext::current().execution();
    let client = HttpClient::from_shared(ctx.http.clone());
    let mut result = IpResult {
        ip: args.ip.clone(),
        valid: true,
        version: if ip_addr.is_ipv4() { "IPv4" } else { "IPv6" }.to_string(),
        reverse_dns: None,
        asn: None,
        geolocation: None,
        ports: vec![],
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    if !args.no_reverse && output::is_console() {
        println!("{} Performing reverse DNS lookup...", style("🔍").cyan());
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        if let Ok(response) = resolver.reverse_lookup(ip_addr).await {
            result.reverse_dns = response.iter().next().map(|name| name.to_string());
        }
    }
    if !args.no_asn && output::is_console() {
        println!("{} Fetching ASN information...", style("📋").cyan());
        result.asn =
            fetch_asn_info(&client, &args.ip, &mut result.errors, &mut result.warnings).await?;
    }
    if !args.no_geo && output::is_console() {
        println!("{} Getting geolocation data...", style("🌍").cyan());
        result.geolocation =
            fetch_geo_info(&client, &args.ip, &mut result.errors, &mut result.warnings).await?;
    }
    if output::is_console() {
        display_results(&result);
    }
    Ok(result)
}
async fn fetch_asn_info(
    client: &HttpClient,
    ip: &str,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<Option<AsnInfo>> {
    let hackertarget_url = format!("https://api.hackertarget.com/aslookup/?q={}", ip);
    match client.get(&hackertarget_url).await {
        Ok(response) => {
            if let Some(line) = response.lines().next() {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 7 {
                    let asn = parts[1].trim_matches('"');
                    let country = parts[3].trim_matches('"');
                    let org_name = parts[6].trim_matches('"');

                    if asn.is_empty() || org_name.is_empty() {
                        warnings.push("Hackertarget response missing ASN details".to_string());
                    }

                    return Ok(Some(AsnInfo {
                        number: asn.to_string(),
                        organization: org_name.to_string(),
                        country: country.to_string(),
                    }));
                } else {
                    errors.push("Hackertarget ASN payload malformed".to_string());
                }
            } else {
                errors.push("Hackertarget ASN response empty".to_string());
            }
        }
        Err(err) => {
            errors.push(format!("Hackertarget ASN lookup failed: {}", err));
        }
    }

    let ipinfo_url = format!("https://ipinfo.io/{}/json", ip);
    match client.get(&ipinfo_url).await {
        Ok(response) => {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&response) {
                if let Some(org) = data.get("org").and_then(|v| v.as_str()) {
                    let mut parts = org.splitn(2, ' ');
                    if let (Some(asn), Some(name)) = (parts.next(), parts.next()) {
                        return Ok(Some(AsnInfo {
                            number: asn.to_string(),
                            organization: name.to_string(),
                            country: data
                                .get("country")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown")
                                .to_string(),
                        }));
                    } else {
                        errors.push("ipinfo.io ASN format unexpected".to_string());
                    }
                } else {
                    errors.push("ipinfo.io response missing 'org' field".to_string());
                }
            } else {
                errors.push("ipinfo.io ASN payload not valid JSON".to_string());
            }
        }
        Err(err) => {
            errors.push(format!("ipinfo.io ASN request failed: {}", err));
        }
    }

    let ipapi_url = format!("https://ipapi.co/{}/json", ip);
    match client.get(&ipapi_url).await {
        Ok(response) => {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&response) {
                let asn = data.get("asn").and_then(|v| v.as_str());
                let org = data.get("org").and_then(|v| v.as_str());

                if let (Some(asn), Some(org)) = (asn, org) {
                    return Ok(Some(AsnInfo {
                        number: asn.to_string(),
                        organization: org.to_string(),
                        country: data
                            .get("country_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                    }));
                } else {
                    errors.push("ipapi.co response missing ASN information".to_string());
                }
            } else {
                errors.push("ipapi.co ASN payload not valid JSON".to_string());
            }
        }
        Err(err) => errors.push(format!("ipapi.co ASN request failed: {}", err)),
    }

    Ok(None)
}

async fn fetch_geo_info(
    client: &HttpClient,
    ip: &str,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<Option<GeoInfo>> {
    let ip_api_url = format!("http://ip-api.com/json/{}", ip);
    match client.get(&ip_api_url).await {
        Ok(response) => {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&response) {
                if data.get("status").and_then(|v| v.as_str()) == Some("success") {
                    return Ok(Some(GeoInfo {
                        country: data
                            .get("country")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                        city: data
                            .get("city")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        region: data
                            .get("regionName")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        latitude: data.get("lat").and_then(|v| v.as_f64()),
                        longitude: data.get("lon").and_then(|v| v.as_f64()),
                        timezone: data
                            .get("timezone")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    }));
                } else if let Some(message) = data.get("message").and_then(|v| v.as_str()) {
                    errors.push(format!("ip-api.com returned error: {}", message));
                } else {
                    errors.push("ip-api.com returned unsuccessful status".to_string());
                }
            } else {
                errors.push("ip-api.com geolocation payload not valid JSON".to_string());
            }
        }
        Err(err) => errors.push(format!("ip-api.com request failed: {}", err)),
    }

    let ipinfo_url = format!("https://ipinfo.io/{}/json", ip);
    match client.get(&ipinfo_url).await {
        Ok(response) => {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&response) {
                if let Some(loc) = data.get("loc").and_then(|v| v.as_str()) {
                    let coords: Vec<&str> = loc.split(',').collect();
                    let latitude = coords.get(0).and_then(|s| s.parse().ok());
                    let longitude = coords.get(1).and_then(|s| s.parse().ok());

                    if latitude.is_none() || longitude.is_none() {
                        warnings.push("ipinfo.io location coordinates incomplete".to_string());
                    }

                    return Ok(Some(GeoInfo {
                        country: data
                            .get("country")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                        city: data
                            .get("city")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        region: data
                            .get("region")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        latitude,
                        longitude,
                        timezone: data
                            .get("timezone")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    }));
                } else {
                    errors.push("ipinfo.io response missing 'loc' field".to_string());
                }
            } else {
                errors.push("ipinfo.io geolocation payload not valid JSON".to_string());
            }
        }
        Err(err) => errors.push(format!("ipinfo.io geolocation request failed: {}", err)),
    }

    let freegeo_url = format!("https://freegeoip.app/json/{}", ip);
    match client.get(&freegeo_url).await {
        Ok(response) => {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&response) {
                return Ok(Some(GeoInfo {
                    country: data
                        .get("country_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                    city: data
                        .get("city")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    region: data
                        .get("region_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    latitude: data.get("latitude").and_then(|v| v.as_f64()),
                    longitude: data.get("longitude").and_then(|v| v.as_f64()),
                    timezone: data
                        .get("time_zone")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                }));
            } else {
                errors.push("freegeoip.app payload not valid JSON".to_string());
            }
        }
        Err(err) => errors.push(format!("freegeoip.app request failed: {}", err)),
    }

    Ok(None)
}
fn display_results(result: &IpResult) {
    println!("\n{}", style("IP Analysis Results:").green().bold());
    println!("{}", style("═══════════════════").cyan());
    println!("  {} {}", style("IP Address:").yellow(), result.ip);
    println!("  {} {}", style("Version:").yellow(), result.version);
    if let Some(rdns) = &result.reverse_dns {
        println!(
            "  {} {}",
            style("Reverse DNS:").yellow(),
            style(rdns).cyan()
        );
    }
    if let Some(asn) = &result.asn {
        println!("\n{}", style("ASN Information:").yellow());
        println!("  Number: {}", style(&asn.number).cyan());
        println!("  Organization: {}", style(&asn.organization).cyan());
        println!("  Country: {}", style(&asn.country).cyan());
    }
    if let Some(geo) = &result.geolocation {
        println!("\n{}", style("Geolocation:").yellow());
        println!("  Country: {}", style(&geo.country).cyan());
        if let Some(city) = &geo.city {
            println!("  City: {}", style(city).cyan());
        }
        if let Some(region) = &geo.region {
            println!("  Region: {}", style(region).cyan());
        }
        if let (Some(lat), Some(lon)) = (geo.latitude, geo.longitude) {
            println!("  Coordinates: {}, {}", lat, lon);
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
