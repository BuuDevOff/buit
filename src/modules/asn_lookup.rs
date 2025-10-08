use crate::cli::AsnLookupArgs;
use crate::utils::asn::{lookup_asn, AsnInfo};
use crate::utils::dns::resolve_hostname;
use anyhow::Result;
use console::style;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct AsnLookupResult {
    pub target: String,
    pub ip: String,
    pub asn_info: Option<AsnInfo>,
    pub error: Option<String>,
}

pub async fn run(args: AsnLookupArgs) -> Result<()> {
    println!(
        "{} ASN lookup: {}",
        style("🌐").cyan(),
        style(&args.target).yellow().bold()
    );

    // Resolve hostname to IP if necessary
    let ip = resolve_hostname(&args.target).await?;
    println!(
        "  {} Resolved to: {}",
        style("→").dim(),
        style(ip.to_string()).cyan()
    );

    // Lookup ASN information
    match lookup_asn(ip).await {
        Ok(Some(asn_info)) => {
            let result = AsnLookupResult {
                target: args.target.clone(),
                ip: ip.to_string(),
                asn_info: Some(asn_info),
                error: None,
            };
            display_results(&result);
        }
        Ok(None) => {
            let result = AsnLookupResult {
                target: args.target.clone(),
                ip: ip.to_string(),
                asn_info: None,
                error: Some("No ASN data returned by provider".to_string()),
            };
            display_results(&result);
        }
        Err(e) => {
            let result = AsnLookupResult {
                target: args.target.clone(),
                ip: ip.to_string(),
                asn_info: None,
                error: Some(e.to_string()),
            };
            display_results(&result);
        }
    }

    Ok(())
}

fn display_results(result: &AsnLookupResult) {
    println!("\n{}", style("ASN Information:").green().bold());
    println!("{}", style("════════════════").cyan());
    println!(
        "  {} {}",
        style("Target:").yellow(),
        style(&result.target).cyan()
    );
    println!(
        "  {} {}",
        style("IP Address:").yellow(),
        style(&result.ip).cyan()
    );

    if let Some(asn_info) = &result.asn_info {
        if let Some(asn_value) = asn_info.asn {
            println!(
                "  {} AS{}",
                style("ASN:").yellow(),
                style(asn_value.to_string()).green().bold()
            );
        } else {
            println!("  {} {}", style("ASN:").yellow(), style("Unknown").yellow());
        }

        if let Some(org) = &asn_info.org {
            println!(
                "  {} {}",
                style("Organization:").yellow(),
                style(org).green()
            );
        }

        if let Some(country) = &asn_info.country {
            println!("  {} {}", style("Country:").yellow(), style(country).cyan());
        }

        if let Some(registry) = &asn_info.registry {
            println!(
                "  {} {}",
                style("Registry:").yellow(),
                style(registry).cyan()
            );
        }

        if let Some(allocated) = &asn_info.allocated {
            println!(
                "  {} {}",
                style("Allocated:").yellow(),
                style(allocated).cyan()
            );
        }

        if let Some(prefix) = &asn_info.prefix {
            println!("  {} {}", style("Network:").yellow(), style(prefix).cyan());
        }
    } else if let Some(error) = &result.error {
        println!("  {} {}", style("Error:").red(), style(error).red());
    }

    // Additional context about ASN
    if let Some(asn_info) = &result.asn_info {
        println!("\n{}", style("ASN Context:").yellow());

        if let Some(asn_value) = asn_info.asn {
            let asn_type = match asn_value {
                1..=23455 => "Public ASN (16-bit range)",
                23456 => "Reserved for AS_TRANS",
                23457..=64495 => "Public ASN (16-bit range)",
                64496..=64511 => "Reserved for use in documentation and sample code",
                64512..=65534 => "Private ASN (16-bit range)",
                65535 => "Reserved",
                65536..=4199999999 => "Public ASN (32-bit range)",
                4200000000..=4294967294 => "Private ASN (32-bit range)",
                4294967295 => "Reserved",
                _ => "Unknown range",
            };

            println!(
                "  {} {}",
                style("ASN Type:").yellow(),
                style(asn_type).dim()
            );

            // Common well-known ASNs
            let well_known = get_well_known_asns();
            if let Some(description) = well_known.get(&asn_value) {
                println!(
                    "  {} {}",
                    style("Known As:").yellow(),
                    style(description).green()
                );
            }
        }
    }
}

fn get_well_known_asns() -> HashMap<u32, &'static str> {
    let mut map = HashMap::new();

    // Major cloud providers
    map.insert(16509, "Amazon Web Services (AWS)");
    map.insert(14061, "DigitalOcean");
    map.insert(15169, "Google LLC");
    map.insert(8075, "Microsoft Corporation");
    map.insert(20940, "Akamai Technologies");

    // Major ISPs
    map.insert(7922, "Comcast Cable Communications");
    map.insert(7018, "AT&T Services");
    map.insert(22394, "Verizon Wireless");
    map.insert(701, "Verizon Business");
    map.insert(3356, "Level 3 Communications");

    // CDNs
    map.insert(13335, "Cloudflare, Inc.");
    map.insert(16625, "Fastly, Inc.");
    map.insert(54113, "Fastly, Inc.");

    // Social Media / Tech
    map.insert(32934, "Facebook, Inc.");
    map.insert(13414, "Twitter, Inc.");
    map.insert(36459, "GitHub, Inc.");

    map
}
