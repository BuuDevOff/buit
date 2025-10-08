use crate::cli::ShodanArgs;
use crate::config::Config;
use crate::utils::http::HttpClient;
use anyhow::Result;
use console::style;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct ShodanResult {
    pub query: String,
    pub results: Vec<ShodanHost>,
    pub total_found: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShodanHost {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub banner: String,
    pub location: String,
    pub org: String,
    pub vulns: Vec<String>,
}

pub async fn run(args: ShodanArgs) -> Result<()> {
    println!(
        "{} Shodan search: {}",
        style("🔍").cyan(),
        style(&args.query).yellow().bold()
    );

    let config = Config::load().unwrap_or_default();
    let api_key = match config.get_api_key("shodan") {
        Some(key) => key,
        None => {
            println!("{} No Shodan API key configured.", style("⚠").yellow());
            println!(
                "{} Get a free API key at: https://account.shodan.io/register",
                style("💡").cyan()
            );
            println!(
                "{} Then configure it with: buit config set-key shodan YOUR_API_KEY",
                style("💡").cyan()
            );
            return Ok(());
        }
    };

    let client = HttpClient::new()?;
    let results = search_shodan(
        &client,
        &api_key,
        &args.query,
        args.limit.unwrap_or(10),
        args.vulns,
    )
    .await?;
    display_results(&results);
    Ok(())
}

async fn search_shodan(
    client: &HttpClient,
    api_key: &str,
    query: &str,
    limit: usize,
    include_vulns: bool,
) -> Result<ShodanResult> {
    let url = format!(
        "https://api.shodan.io/shodan/host/search?key={}&query={}&limit={}",
        api_key,
        urlencoding::encode(query),
        limit
    );

    println!("{} Querying Shodan API...", style("🌐").cyan());

    let response = match client.get(&url).await {
        Ok(resp) => resp,
        Err(e) => {
            println!("{} Failed to query Shodan API: {}", style("❌").red(), e);
            println!(
                "{} Check your API key and internet connection",
                style("💡").cyan()
            );
            return Ok(ShodanResult {
                query: query.to_string(),
                results: Vec::new(),
                total_found: 0,
            });
        }
    };

    let data: Value = match serde_json::from_str(&response) {
        Ok(json) => json,
        Err(e) => {
            println!(
                "{} Failed to parse Shodan response: {}",
                style("❌").red(),
                e
            );
            if response.contains("Invalid API key") {
                println!("{} Your API key appears to be invalid", style("⚠").yellow());
            } else if response.contains("No information available") {
                println!(
                    "{} No results found for query: {}",
                    style("ℹ").cyan(),
                    query
                );
            }
            return Ok(ShodanResult {
                query: query.to_string(),
                results: Vec::new(),
                total_found: 0,
            });
        }
    };

    // Check for API errors
    if let Some(error) = data.get("error") {
        println!(
            "{} Shodan API error: {}",
            style("❌").red(),
            error.as_str().unwrap_or("Unknown error")
        );
        return Ok(ShodanResult {
            query: query.to_string(),
            results: Vec::new(),
            total_found: 0,
        });
    }

    let mut hosts = Vec::new();

    if let Some(matches) = data.get("matches").and_then(|v| v.as_array()) {
        for match_data in matches.iter().take(limit) {
            let ip = match_data
                .get("ip_str")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();

            let port = match_data
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(80) as u16;

            let service = match_data
                .get("product")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    match_data
                        .get("_shodan")
                        .and_then(|s| s.get("module"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| format!("Port {}", port));

            let banner = match_data
                .get("data")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join("\\n");

            let location = if let Some(loc) = match_data.get("location") {
                format!(
                    "{}, {}",
                    loc.get("city")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown"),
                    loc.get("country_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                )
            } else {
                "Unknown".to_string()
            };

            let org = match_data
                .get("org")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();

            let mut vulns = Vec::new();
            if include_vulns {
                if let Some(vulns_data) = match_data.get("vulns").and_then(|v| v.as_object()) {
                    vulns = vulns_data.keys().cloned().collect();
                }
            }

            hosts.push(ShodanHost {
                ip,
                port,
                service,
                banner,
                location,
                org,
                vulns,
            });
        }
    }

    let total = data.get("total").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    Ok(ShodanResult {
        query: query.to_string(),
        total_found: total,
        results: hosts,
    })
}

fn display_results(result: &ShodanResult) {
    println!("\n{}", style("Shodan Search Results:").green().bold());
    println!("{}", style("═════════════════════").cyan());
    println!(
        "  {} {}",
        style("Query:").yellow(),
        style(&result.query).cyan()
    );
    println!(
        "  {} {}",
        style("Total Found:").yellow(),
        style(result.total_found.to_string()).green()
    );
    println!(
        "  {} {}",
        style("Showing:").yellow(),
        style(result.results.len().to_string()).green()
    );

    if result.results.is_empty() {
        println!("\n{} No results found", style("✗").red());
        println!("{} Try different search terms like:", style("💡").cyan());
        println!("  • apache");
        println!("  • nginx");
        println!("  • ssh");
        println!("  • country:US apache");
        return;
    }

    for (i, host) in result.results.iter().enumerate() {
        println!(
            "\n{}. {} {}",
            style((i + 1).to_string()).cyan(),
            style("Host:").yellow(),
            style(&host.ip).cyan().bold()
        );
        println!(
            "   {} {}",
            style("Port:").yellow(),
            style(host.port.to_string()).green()
        );
        println!(
            "   {} {}",
            style("Service:").yellow(),
            style(&host.service).cyan()
        );
        println!(
            "   {} {}",
            style("Location:").yellow(),
            style(&host.location).cyan()
        );
        println!(
            "   {} {}",
            style("Organization:").yellow(),
            style(&host.org).cyan()
        );

        if !host.vulns.is_empty() {
            println!(
                "   {} {}",
                style("Vulnerabilities:").red().bold(),
                style(format!("{} found", host.vulns.len())).red()
            );
            for vuln in &host.vulns {
                println!("     • {}", style(vuln).red());
            }
        }

        if !host.banner.is_empty() {
            println!(
                "   {} {}",
                style("Banner:").yellow(),
                style(&host.banner.replace("\\n", " | ")).dim()
            );
        }
    }

    println!("\n{}", style("Usage Examples:").yellow().bold());
    println!("• buit shodan \"apache\"           - Find Apache servers");
    println!("• buit shodan \"country:US ssh\"   - SSH in US");
    println!("• buit shodan \"port:22\"          - All SSH services");
    println!("• buit shodan \"nginx country:FR\" - Nginx in France");
    println!("• buit shodan \"webcam\"           - Find webcams");

    println!("\n{}", style("Security Notes:").yellow().bold());
    println!("• This data is publicly available via Shodan");
    println!("• Use responsibly for security research only");
    println!("• Respect rate limits (free tier: 100 queries/month)");
}
