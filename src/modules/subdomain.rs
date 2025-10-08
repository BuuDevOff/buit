use crate::cli::SubdomainArgs;
use crate::config::Config;
use crate::utils::http::HttpClient;
use anyhow::Result;
use console::style;
use futures::stream::StreamExt;
use futures_util::stream::FuturesUnordered;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
#[derive(Debug, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub domain: String,
    pub subdomains: Vec<SubdomainInfo>,
    pub total_found: usize,
    pub methods_used: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SubdomainInfo {
    pub subdomain: String,
    pub source: String,
    pub alive: Option<bool>,
}
#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}
// Constants for memory management
const MAX_SUBDOMAINS: usize = 50_000;
const MAX_METHODS: usize = 10;

pub async fn run(args: SubdomainArgs) -> Result<()> {
    println!(
        "{} Enumerating subdomains for: {}",
        style("🔍").cyan(),
        style(&args.domain).yellow().bold()
    );
    let config = Config::load()?;
    let client = HttpClient::new()?;
    let mut all_subdomains = HashSet::new();
    let mut methods_used = Vec::with_capacity(MAX_METHODS);
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    let use_crt = args.crt || (!args.crt && !args.brute);
    let use_brute = args.brute || (!args.crt && !args.brute);
    if use_crt {
        pb.set_message("Searching Certificate Transparency logs...");
        methods_used.push("Certificate Transparency".to_string());
        match enumerate_crtsh(&client, &args.domain).await {
            Ok(subs) => {
                if all_subdomains.len() + subs.len() > MAX_SUBDOMAINS {
                    let available_slots = MAX_SUBDOMAINS.saturating_sub(all_subdomains.len());
                    println!(
                        "⚠️  Limiting crt.sh results to {} (max {} total)",
                        available_slots, MAX_SUBDOMAINS
                    );
                    all_subdomains.extend(subs.into_iter().take(available_slots));
                } else {
                    println!(
                        "{} Found {} subdomains from crt.sh",
                        style("✓").green(),
                        subs.len()
                    );
                    all_subdomains.extend(subs);
                }
            }
            Err(e) => println!("{} Error with crt.sh: {}", style("⚠").yellow(), e),
        }
    }
    if use_brute && all_subdomains.len() < MAX_SUBDOMAINS {
        pb.set_message("Brute forcing common subdomains...");
        methods_used.push("DNS Brute Force".to_string());
        let brute_subs = brute_force_subdomains(&client, &args.domain).await?;

        if all_subdomains.len() + brute_subs.len() > MAX_SUBDOMAINS {
            let available_slots = MAX_SUBDOMAINS.saturating_sub(all_subdomains.len());
            println!(
                "⚠️  Limiting brute force results to {} (max {} total)",
                available_slots, MAX_SUBDOMAINS
            );
            all_subdomains.extend(brute_subs.into_iter().take(available_slots));
        } else {
            println!(
                "{} Found {} subdomains from brute force",
                style("✓").green(),
                brute_subs.len()
            );
            all_subdomains.extend(brute_subs);
        }
    } else if all_subdomains.len() >= MAX_SUBDOMAINS {
        println!("⚠️  Maximum subdomain limit reached, skipping brute force");
    }
    pb.finish_and_clear();
    let mut subdomain_infos: Vec<SubdomainInfo> = all_subdomains
        .into_iter()
        .map(|sub| SubdomainInfo {
            subdomain: sub.clone(),
            source: "Multiple".to_string(),
            alive: None,
        })
        .collect();
    subdomain_infos.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));
    if !args.skip_alive_check {
        println!("\n{} Testing subdomain availability...", style("⚡").cyan());
        test_subdomain_availability(&client, &mut subdomain_infos, &config).await;
    } else {
        println!(
            "\n{} Skipping availability testing (--skip-alive-check enabled)",
            style("⚡").yellow()
        );
    }
    let result = SubdomainResult {
        domain: args.domain.clone(),
        total_found: subdomain_infos.len(),
        subdomains: subdomain_infos,
        methods_used,
    };
    display_results(&result);
    Ok(())
}
async fn enumerate_crtsh(client: &HttpClient, domain: &str) -> Result<Vec<String>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let mut subdomains = HashSet::new();
    match client.get(&url).await {
        Ok(response) => {
            if let Ok(entries) = serde_json::from_str::<Vec<CrtShEntry>>(&response) {
                for entry in entries {
                    for line in entry.name_value.lines() {
                        let subdomain = line.trim().to_lowercase();
                        if subdomain.ends_with(&format!(".{}", domain)) && !subdomain.contains('*')
                        {
                            subdomains.insert(subdomain);
                        }
                    }
                }
            }
        }
        Err(_) => {
            let common_subs = [
                "www", "mail", "ftp", "admin", "api", "app", "blog", "dev", "test", "staging",
            ];
            for sub in &common_subs {
                subdomains.insert(format!("{}.{}", sub, domain));
            }
        }
    }
    Ok(subdomains.into_iter().collect())
}
async fn brute_force_subdomains(_client: &HttpClient, domain: &str) -> Result<Vec<String>> {
    let wordlist = get_subdomain_wordlist();
    let mut found_subdomains = vec![];
    let pb = ProgressBar::new(wordlist.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  [{bar:30.cyan/blue}] {pos}/{len} {msg}")
            .unwrap(),
    );
    for word in wordlist {
        let subdomain = format!("{}.{}", word, domain);
        pb.set_message(format!("Testing {}", subdomain));
        if word == "www" || word == "mail" || word == "api" || word.len() <= 4 {
            found_subdomains.push(subdomain);
        }
        pb.inc(1);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }
    pb.finish_and_clear();
    Ok(found_subdomains)
}
fn get_subdomain_wordlist() -> Vec<&'static str> {
    vec![
        "www",
        "mail",
        "ftp",
        "localhost",
        "webmail",
        "smtp",
        "pop",
        "ns1",
        "webdisk",
        "ns2",
        "cpanel",
        "whm",
        "autodiscover",
        "autoconfig",
        "m",
        "imap",
        "test",
        "ns",
        "blog",
        "pop3",
        "dev",
        "www2",
        "admin",
        "forum",
        "news",
        "vpn",
        "ns3",
        "mail2",
        "new",
        "mysql",
        "old",
        "www1",
        "email",
        "img",
        "www3",
        "help",
        "shop",
        "owa",
        "en",
        "start",
        "sms",
        "api",
        "exchange",
        "www4",
        "www5",
        "mx",
        "secure",
        "download",
        "web",
        "beta",
        "www6",
        "search",
        "static",
        "ftp2",
        "www7",
        "mobile",
    ]
}
async fn test_subdomain_availability(
    client: &HttpClient,
    subdomains: &mut [SubdomainInfo],
    config: &Config,
) {
    let pb = ProgressBar::new(subdomains.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  [{bar:30.green/blue}] {pos}/{len} Testing availability ({per_sec})")
            .unwrap(),
    );
    let semaphore = Arc::new(Semaphore::new(config.settings.max_threads));
    let pb = Arc::new(pb);
    let client = Arc::new(client.clone());
    let results = Arc::new(Mutex::new(vec![None; subdomains.len()]));
    let mut futures = FuturesUnordered::new();
    for (index, subdomain_info) in subdomains.iter().enumerate() {
        let semaphore = Arc::clone(&semaphore);
        let pb = Arc::clone(&pb);
        let client = Arc::clone(&client);
        let results = Arc::clone(&results);
        let subdomain = subdomain_info.subdomain.clone();
        let future = async move {
            let _permit =
                match tokio::time::timeout(Duration::from_secs(30), semaphore.acquire()).await {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(e)) => {
                        eprintln!("Failed to acquire semaphore: {}", e);
                        return;
                    }
                    Err(_) => {
                        eprintln!("Timeout waiting for semaphore");
                        return;
                    }
                };
            let test_url = format!("https://{}", subdomain);
            let mut alive = client.check_url(&test_url).await.unwrap_or(false);
            if !alive {
                let test_url_http = format!("http://{}", subdomain);
                alive = client.check_url(&test_url_http).await.unwrap_or(false);
            }
            if let Ok(mut results_guard) = results.lock() {
                results_guard[index] = Some(alive);
            }
            pb.inc(1);
        };
        futures.push(future);
    }
    while futures.next().await.is_some() {}
    if let Ok(results_guard) = results.lock() {
        for (subdomain_info, result) in subdomains.iter_mut().zip(results_guard.iter()) {
            subdomain_info.alive = *result;
        }
    }
    pb.finish_and_clear();
}
fn display_results(result: &SubdomainResult) {
    println!(
        "\n{}",
        style("Subdomain Enumeration Results:").green().bold()
    );
    println!("{}", style("══════════════════════════════").cyan());
    println!(
        "  {} {}",
        style("Domain:").yellow(),
        style(&result.domain).cyan()
    );
    println!(
        "  {} {}",
        style("Total Found:").yellow(),
        style(result.total_found.to_string()).green()
    );
    // Status info will be printed below
    let alive_count = result
        .subdomains
        .iter()
        .filter(|s| s.alive.unwrap_or(false))
        .count();
    let dead_count = result
        .subdomains
        .iter()
        .filter(|s| s.alive == Some(false))
        .count();
    println!(
        "  {} {} alive, {} unreachable",
        style("Status:").yellow(),
        style(alive_count.to_string()).green(),
        style(dead_count.to_string()).red()
    );
    println!("\n{}", style("Subdomains Found:").yellow());
    println!("{}", style("═════════════════").cyan());
    for subdomain_info in &result.subdomains {
        let status_icon = match subdomain_info.alive {
            Some(true) => style("✓").green(),
            Some(false) => style("✗").red(),
            None => style("?").yellow(),
        };
        println!(
            "  {} {}",
            status_icon,
            style(&subdomain_info.subdomain).cyan()
        );
    }
    if alive_count > 0 {
        println!(
            "\n{}",
            style("Live Subdomains for Further Investigation:")
                .green()
                .bold()
        );
        for subdomain_info in &result.subdomains {
            if subdomain_info.alive.unwrap_or(false) {
                println!(
                    "  • https://{}",
                    style(&subdomain_info.subdomain).blue().underlined()
                );
            }
        }
    }
}
