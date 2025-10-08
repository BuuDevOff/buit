use crate::cli::ReverseDnsArgs;
use crate::utils::dns::DnsClient;
use anyhow::Result;
use console::style;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReverseDnsResult {
    pub ip: String,
    pub hostnames: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReverseDnsReport {
    pub target: String,
    pub results: Vec<ReverseDnsResult>,
    pub total_ips: usize,
    pub resolved_count: usize,
}

pub async fn run(args: ReverseDnsArgs) -> Result<()> {
    println!(
        "{} Reverse DNS lookup: {}",
        style("🔍").cyan(),
        style(&args.target).yellow().bold()
    );

    let dns_client = DnsClient::new()?;
    let mut results = Vec::new();
    let mut resolved_count = 0;

    // Parse input as IP, CIDR, or range
    let ips = parse_target(&args.target)?;
    let total_ips = ips.len();

    if total_ips > 1000 && !args.force {
        return Err(anyhow::anyhow!(
            "Large IP range detected ({} IPs). Use --force to proceed or specify a smaller range.",
            total_ips
        ));
    }

    println!(
        "{} Scanning {} IP addresses...",
        style("📡").cyan(),
        total_ips
    );

    // Process IPs with concurrency limit
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(args.threads));
    let mut tasks = Vec::new();

    for ip in ips {
        let dns_client = dns_client.clone();
        let permit = semaphore.clone().acquire_owned().await?;

        let task = tokio::spawn(async move {
            let _permit = permit;
            let result = match dns_client.reverse_dns(ip).await {
                Ok(hostnames) if !hostnames.is_empty() => ReverseDnsResult {
                    ip: ip.to_string(),
                    hostnames,
                    error: None,
                },
                Ok(_) => ReverseDnsResult {
                    ip: ip.to_string(),
                    hostnames: vec![],
                    error: Some("No PTR record found".to_string()),
                },
                Err(e) => ReverseDnsResult {
                    ip: ip.to_string(),
                    hostnames: vec![],
                    error: Some(e.to_string()),
                },
            };
            result
        });

        tasks.push(task);
    }

    for task in tasks {
        let result = task.await?;
        if !result.hostnames.is_empty() {
            resolved_count += 1;
        }
        results.push(result);
    }

    let report = ReverseDnsReport {
        target: args.target.clone(),
        results,
        total_ips,
        resolved_count,
    };

    display_results(&report);
    Ok(())
}

fn parse_target(target: &str) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();

    // Try parsing as single IP
    if let Ok(ip) = target.parse::<IpAddr>() {
        ips.push(ip);
        return Ok(ips);
    }

    // Try parsing as CIDR
    if let Ok(network) = target.parse::<IpNetwork>() {
        match network {
            IpNetwork::V4(net) => {
                for ip in net.iter() {
                    ips.push(IpAddr::V4(ip));
                }
            }
            IpNetwork::V6(net) => {
                for ip in net.iter() {
                    ips.push(IpAddr::V6(ip));
                }
            }
        }
        return Ok(ips);
    }

    // Try parsing as range (e.g., 192.168.1.1-192.168.1.10)
    if target.contains('-') {
        let parts: Vec<&str> = target.split('-').collect();
        if parts.len() == 2 {
            let start: IpAddr = parts[0].parse()?;
            let end: IpAddr = parts[1].parse()?;

            match (start, end) {
                (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
                    let start_u32 = u32::from(start_v4);
                    let end_u32 = u32::from(end_v4);

                    if start_u32 <= end_u32 {
                        for ip_u32 in start_u32..=end_u32 {
                            ips.push(IpAddr::V4(ip_u32.into()));
                        }
                    }
                }
                _ => return Err(anyhow::anyhow!("IPv6 ranges not supported yet")),
            }
            return Ok(ips);
        }
    }

    Err(anyhow::anyhow!(
        "Invalid target format. Use IP, CIDR (192.168.1.0/24), or range (192.168.1.1-192.168.1.10)"
    ))
}

fn display_results(report: &ReverseDnsReport) {
    println!("\n{}", style("Reverse DNS Results:").green().bold());
    println!("{}", style("═══════════════════").cyan());
    println!(
        "  {} {}",
        style("Target:").yellow(),
        style(&report.target).cyan()
    );
    println!("  {} {}", style("Total IPs:").yellow(), report.total_ips);
    println!(
        "  {} {} ({:.1}%)",
        style("Resolved:").yellow(),
        style(report.resolved_count.to_string()).green(),
        if report.total_ips > 0 {
            (report.resolved_count as f64 / report.total_ips as f64) * 100.0
        } else {
            0.0
        }
    );

    if !report.results.is_empty() {
        println!("\n{}", style("Resolved Hostnames:").yellow());

        for result in &report.results {
            if !result.hostnames.is_empty() {
                println!("  {} {}", style(&result.ip).cyan().bold(), style("→").dim());
                for hostname in &result.hostnames {
                    println!("    {}", style(hostname).green());
                }
            }
        }

        // Show failed lookups if requested
        let failed: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.hostnames.is_empty())
            .collect();

        if !failed.is_empty() && failed.len() < 50 {
            println!(
                "\n{} ({} IPs)",
                style("Failed Lookups:").yellow(),
                failed.len()
            );
            for result in failed.iter().take(10) {
                println!(
                    "  {} {}",
                    style(&result.ip).dim(),
                    style(result.error.as_deref().unwrap_or("No PTR record")).dim()
                );
            }
            if failed.len() > 10 {
                println!("  {} {} more...", style("...").dim(), failed.len() - 10);
            }
        }
    }
}
