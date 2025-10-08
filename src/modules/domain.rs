use crate::cli::DomainArgs;
use anyhow::Result;
use console::style;
use reqwest::Client;
use std::collections::HashMap;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use whois::WhoIs;

pub async fn run(args: DomainArgs) -> Result<()> {
    println!(
        "{} Domain Analysis: {}",
        style("🌐").cyan(),
        style(&args.domain).yellow().bold()
    );
    println!(
        "DNS: {}, SSL: {}, WHOIS: {}",
        style(args.dns.to_string()).cyan(),
        style(args.ssl.to_string()).cyan(),
        style(args.whois.to_string()).cyan()
    );

    if args.dns {
        perform_dns_analysis(&args.domain).await?;
    }

    if args.ssl {
        perform_ssl_analysis(&args.domain).await?;
    }

    if args.whois {
        perform_whois_analysis(&args.domain).await?;
    }

    // Basic domain info
    perform_basic_analysis(&args.domain).await?;

    Ok(())
}

async fn perform_dns_analysis(domain: &str) -> Result<()> {
    println!("\n{} DNS Analysis", style("🔍").cyan());
    println!("{}", "=".repeat(40));

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // A Records
    match resolver.lookup_ip(domain).await {
        Ok(response) => {
            println!("{} A Records:", style("📋").green());
            for ip in response.iter() {
                println!("   {}", style(ip.to_string()).yellow());
            }
        }
        Err(_) => println!("{} No A records found", style("⚠️").yellow()),
    }

    // MX Records
    match resolver.mx_lookup(domain).await {
        Ok(response) => {
            println!("{} MX Records:", style("📋").green());
            for mx in response.iter() {
                println!(
                    "   {} (priority: {})",
                    style(mx.exchange().to_string().trim_end_matches('.')).yellow(),
                    style(mx.preference().to_string()).cyan()
                );
            }
        }
        Err(_) => println!("{} No MX records found", style("⚠️").yellow()),
    }

    // NS Records
    match resolver.ns_lookup(domain).await {
        Ok(response) => {
            println!("{} NS Records:", style("📋").green());
            for ns in response.iter() {
                println!(
                    "   {}",
                    style(ns.to_string().trim_end_matches('.')).yellow()
                );
            }
        }
        Err(_) => println!("{} No NS records found", style("⚠️").yellow()),
    }

    // TXT Records
    match resolver.txt_lookup(domain).await {
        Ok(response) => {
            println!("{} TXT Records:", style("📋").green());
            for txt in response.iter() {
                let txt_data = txt.to_string();
                if txt_data.len() > 100 {
                    println!(
                        "   {}...",
                        style(txt_data.chars().take(100).collect::<String>()).yellow()
                    );
                } else {
                    println!("   {}", style(txt_data).yellow());
                }
            }
        }
        Err(_) => println!("{} No TXT records found", style("⚠️").yellow()),
    }

    Ok(())
}

async fn perform_ssl_analysis(domain: &str) -> Result<()> {
    println!("\n{} SSL Certificate Analysis", style("🔐").cyan());
    println!("{}", "=".repeat(40));

    let client = Client::new();
    let url = format!("https://{}", domain);

    match client.head(&url).send().await {
        Ok(response) => {
            println!(
                "{} SSL Certificate Status: {}",
                style("🔒").cyan(),
                style("Valid").green()
            );

            if let Some(server) = response.headers().get("server") {
                if let Ok(server_str) = server.to_str() {
                    println!("🖥️  Server: {}", style(server_str).yellow());
                }
            }

            // Try to get more certificate details via OpenSSL-like API call
            match get_ssl_details(domain).await {
                Ok(details) => {
                    println!("📋 Certificate Details:");
                    for (key, value) in details {
                        println!("   {}: {}", style(key).cyan(), style(value).yellow());
                    }
                }
                Err(_) => println!(
                    "{} Could not retrieve detailed certificate info",
                    style("⚠️").yellow()
                ),
            }
        }
        Err(e) => {
            println!("{} SSL Certificate Error: {}", style("❌").red(), e);
        }
    }

    Ok(())
}

async fn get_ssl_details(domain: &str) -> Result<HashMap<String, String>> {
    let mut details = HashMap::new();

    // This is a simplified SSL check - in a real implementation,
    // you'd use a proper SSL/TLS library to get certificate details
    let client = Client::new();
    let url = format!("https://{}", domain);

    match client.get(&url).send().await {
        Ok(response) => {
            details.insert("Status".to_string(), "Connected".to_string());

            if let Some(content_type) = response.headers().get("content-type") {
                if let Ok(ct_str) = content_type.to_str() {
                    details.insert("Content-Type".to_string(), ct_str.to_string());
                }
            }

            // Add more certificate parsing here with a proper TLS library
        }
        Err(_) => {
            details.insert("Status".to_string(), "Connection Failed".to_string());
        }
    }

    Ok(details)
}

async fn perform_whois_analysis(_domain: &str) -> Result<()> {
    println!("\n{} WHOIS Information", style("📄").cyan());
    println!("{}", "=".repeat(40));

    let mut whois = WhoIs::new("/usr/bin/whois".to_string());

    match whois.lookup() {
        Ok(result) => {
            let whois_data = &result;

            // Parse important WHOIS fields
            parse_whois_data(&whois_data);
        }
        Err(e) => {
            println!("{} WHOIS lookup failed: {}", style("❌").red(), e);
        }
    }

    Ok(())
}

fn parse_whois_data(whois_data: &str) {
    let lines: Vec<&str> = whois_data.lines().collect();
    let mut found_info = false;

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.to_lowercase().contains("domain name:") || line.to_lowercase().contains("domain:") {
            println!("🌐 {}", style(line).yellow());
            found_info = true;
        } else if line.to_lowercase().contains("registrar:") {
            println!("🏢 {}", style(line).yellow());
            found_info = true;
        } else if line.to_lowercase().contains("creation date:")
            || line.to_lowercase().contains("created:")
        {
            println!("📅 {}", style(line).yellow());
            found_info = true;
        } else if line.to_lowercase().contains("expir") {
            println!("⏰ {}", style(line).yellow());
            found_info = true;
        } else if line.to_lowercase().contains("name server:")
            || line.to_lowercase().contains("nserver:")
        {
            println!("🌐 {}", style(line).yellow());
            found_info = true;
        } else if line.to_lowercase().contains("status:") {
            println!("🔒 {}", style(line).yellow());
            found_info = true;
        }
    }

    if !found_info {
        println!(
            "{} Could not parse WHOIS data or domain not found",
            style("⚠️").yellow()
        );
        // Show raw data if parsing failed
        if whois_data.len() > 500 {
            println!("Raw WHOIS (truncated):");
            println!("{}", whois_data.chars().take(500).collect::<String>());
            println!("...");
        } else {
            println!("Raw WHOIS:");
            println!("{}", whois_data);
        }
    }
}

async fn perform_basic_analysis(domain: &str) -> Result<()> {
    println!("\n{} Basic Domain Information", style("ℹ️").cyan());
    println!("{}", "=".repeat(40));

    // Domain length and structure
    println!(
        "📏 Domain Length: {} characters",
        style(domain.len().to_string()).yellow()
    );

    let parts: Vec<&str> = domain.split('.').collect();
    println!(
        "🏗️  Domain Structure: {} levels",
        style(parts.len().to_string()).yellow()
    );

    if parts.len() >= 2 {
        if let (Some(tld), Some(sld)) = (parts.last(), parts.get(parts.len() - 2)) {
            println!("🌐 TLD: {}", style(tld).yellow());
            println!("🏷️  SLD: {}", style(sld).yellow());
        } else {
            eprintln!("Warning: Could not parse domain structure");
        }

        // Check if it's a subdomain
        if parts.len() > 2 {
            println!(
                "📁 Subdomain detected: {}",
                style(parts[0..parts.len() - 2].join(".")).yellow()
            );
        }
    }

    // Check if domain is reachable via HTTP/HTTPS
    let client = Client::new();

    println!("\n{} Connectivity Check:", style("🔗").cyan());

    // HTTP Check
    let http_url = format!("http://{}", domain);
    match client
        .head(&http_url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(response) => {
            println!(
                "🌐 HTTP: {} (Status: {})",
                style("Reachable").green(),
                style(response.status().as_str()).yellow()
            );
        }
        Err(_) => {
            println!("🌐 HTTP: {}", style("Not reachable").red());
        }
    }

    // HTTPS Check
    let https_url = format!("https://{}", domain);
    match client
        .head(&https_url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(response) => {
            println!(
                "🔒 HTTPS: {} (Status: {})",
                style("Reachable").green(),
                style(response.status().as_str()).yellow()
            );
        }
        Err(_) => {
            println!("🔒 HTTPS: {}", style("Not reachable").red());
        }
    }

    Ok(())
}
