use crate::cli::GeoipArgs;
use crate::utils::json;
use crate::utils::{context::AppContext, http::HttpClient};
use anyhow::Result;
use console::style;
use maxminddb::geoip2;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
#[derive(Debug, Serialize, Deserialize)]
pub struct GeoIpResult {
    pub ip: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
    pub organization: Option<String>,
    pub asn: Option<String>,
    pub threat_level: Option<String>,
    pub source: String,
}
#[derive(Debug, Deserialize)]
struct IpApiResponse {
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    #[serde(rename = "regionName")]
    region: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    asn: Option<String>,
    status: Option<String>,
}
pub async fn run(args: GeoipArgs) -> Result<()> {
    println!(
        "{} GeoIP lookup: {}",
        style("📍").cyan(),
        style(&args.ip).yellow().bold()
    );

    let mut result = GeoIpResult {
        ip: args.ip.clone(),
        country: None,
        country_code: None,
        region: None,
        city: None,
        latitude: None,
        longitude: None,
        timezone: None,
        isp: None,
        organization: None,
        asn: None,
        threat_level: None,
        source: "Unknown".to_string(),
    };

    // Try offline MaxMind database first
    if let Ok(maxmind_result) = lookup_maxmind(&args.ip) {
        result = maxmind_result;
        result.source = "MaxMind GeoLite2".to_string();
    } else {
        // Fallback to online API
        let ctx = AppContext::current().execution();
        let client = HttpClient::from_shared(ctx.http.clone());
        if let Ok(api_result) = lookup_online(&client, &args.ip, args.isp).await {
            result = api_result;
            result.source = "ip-api.com".to_string();
        }
    }
    result.threat_level = assess_threat_level(&args.ip);
    display_results(&result);
    Ok(())
}

fn lookup_maxmind(ip: &str) -> Result<GeoIpResult> {
    // Common paths for MaxMind databases
    let db_paths = [
        "GeoLite2-City.mmdb",
        "/usr/share/GeoIP/GeoLite2-City.mmdb",
        "/var/lib/GeoIP/GeoLite2-City.mmdb",
        "./data/GeoLite2-City.mmdb",
    ];

    for path in &db_paths {
        if Path::new(path).exists() {
            match maxminddb::Reader::open_readfile(path) {
                Ok(reader) => {
                    let ip_addr: IpAddr = ip.parse()?;
                    match reader.lookup::<geoip2::City>(ip_addr) {
                        Ok(city) => {
                            return Ok(GeoIpResult {
                                ip: ip.to_string(),
                                country: city
                                    .country
                                    .as_ref()
                                    .and_then(|c| c.names.as_ref())
                                    .and_then(|n| n.get("en"))
                                    .map(|s| s.to_string()),
                                country_code: city
                                    .country
                                    .as_ref()
                                    .and_then(|c| c.iso_code)
                                    .map(|s| s.to_string()),
                                region: city
                                    .subdivisions
                                    .as_ref()
                                    .and_then(|s| s.get(0))
                                    .and_then(|r| r.names.as_ref())
                                    .and_then(|n| n.get("en"))
                                    .map(|s| s.to_string()),
                                city: city
                                    .city
                                    .as_ref()
                                    .and_then(|c| c.names.as_ref())
                                    .and_then(|n| n.get("en"))
                                    .map(|s| s.to_string()),
                                latitude: city.location.as_ref().and_then(|l| l.latitude),
                                longitude: city.location.as_ref().and_then(|l| l.longitude),
                                timezone: city
                                    .location
                                    .as_ref()
                                    .and_then(|l| l.time_zone.as_ref())
                                    .map(|s| s.to_string()),
                                isp: None,
                                organization: None,
                                asn: None,
                                threat_level: None,
                                source: "MaxMind".to_string(),
                            });
                        }
                        Err(_) => continue,
                    }
                }
                Err(_) => continue,
            }
        }
    }

    Err(anyhow::anyhow!("No MaxMind database found"))
}

async fn lookup_online(client: &HttpClient, ip: &str, include_isp: bool) -> Result<GeoIpResult> {
    let url = format!("http://ip-api.com/json/{}", ip);
    let response = client.get(&url).await?;
    let api_result: IpApiResponse = json::from_str(&response)?;

    if api_result.status.as_deref() == Some("success") {
        Ok(GeoIpResult {
            ip: ip.to_string(),
            country: api_result.country,
            country_code: api_result.country_code,
            region: api_result.region,
            city: api_result.city,
            latitude: api_result.lat,
            longitude: api_result.lon,
            timezone: api_result.timezone,
            isp: if include_isp { api_result.isp } else { None },
            organization: if include_isp { api_result.org } else { None },
            asn: if include_isp { api_result.asn } else { None },
            threat_level: None,
            source: "ip-api.com".to_string(),
        })
    } else {
        Err(anyhow::anyhow!("API request failed"))
    }
}

fn assess_threat_level(ip: &str) -> Option<String> {
    let suspicious_ranges = ["10.", "192.168.", "172.16.", "127.", "0.", "255."];
    for range in &suspicious_ranges {
        if ip.starts_with(range) {
            return Some("Private/Invalid".to_string());
        }
    }
    Some("Unknown".to_string())
}
fn display_results(result: &GeoIpResult) {
    println!("\n{}", style("GeoIP Results:").green().bold());
    println!("{}", style("══════════════").cyan());
    println!(
        "  {} {}",
        style("IP Address:").yellow(),
        style(&result.ip).cyan()
    );
    println!(
        "  {} {}",
        style("Data Source:").yellow(),
        style(&result.source).cyan()
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
    if let Some(region) = &result.region {
        println!("  {} {}", style("Region:").yellow(), style(region).cyan());
    }
    if let Some(city) = &result.city {
        println!("  {} {}", style("City:").yellow(), style(city).cyan());
    }
    if let (Some(lat), Some(lon)) = (result.latitude, result.longitude) {
        println!("  {} {}, {}", style("Coordinates:").yellow(), lat, lon);
        println!(
            "  {} https://maps.google.com/?q={},{}",
            style("Map:").yellow(),
            lat,
            lon
        );
    }
    if let Some(timezone) = &result.timezone {
        println!(
            "  {} {}",
            style("Timezone:").yellow(),
            style(timezone).cyan()
        );
    }
    if let Some(isp) = &result.isp {
        println!("\n{}", style("ISP Information:").yellow());
        println!("  ISP: {}", style(isp).cyan());
    }
    if let Some(org) = &result.organization {
        println!("  Organization: {}", style(org).cyan());
    }
    if let Some(asn) = &result.asn {
        println!("  ASN: {}", style(asn).cyan());
    }
    if let Some(threat) = &result.threat_level {
        println!("\n{}", style("Security Assessment:").yellow());
        let color = match threat.as_str() {
            "Private/Invalid" => "yellow",
            "High" => "red",
            "Medium" => "yellow",
            _ => "green",
        };
        println!(
            "  Threat Level: {}",
            match color {
                "red" => style(threat).red(),
                "yellow" => style(threat).yellow(),
                _ => style(threat).green(),
            }
        );
    }
}
