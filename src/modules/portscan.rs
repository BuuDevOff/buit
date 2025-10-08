use crate::cli::PortscanArgs;
use crate::config::Config;
use anyhow::Result;
use console::style;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn run(args: PortscanArgs) -> Result<()> {
    println!(
        "{} Port scanning: {}",
        style("🔍").cyan(),
        style(&args.target).yellow().bold()
    );

    let config = Config::load()?;
    let thread_count = config.settings.max_threads;

    let ports = parse_port_range(&args.ports.unwrap_or_else(|| "1-1000".to_string()))?;
    let scan_type = args.scan_type.as_deref().unwrap_or("tcp");

    println!(
        "{} Scanning {} ports with {} threads",
        style("⚡").yellow(),
        ports.len(),
        thread_count
    );

    let target_ip = resolve_target(&args.target).await?;
    let open_ports = match scan_type {
        "tcp" => tcp_scan(&target_ip, &ports, thread_count).await?,
        "udp" => {
            println!("{} UDP scanning not implemented yet", style("⚠️").yellow());
            Vec::new()
        }
        _ => {
            println!("{} Unknown scan type: {}", style("❌").red(), scan_type);
            return Ok(());
        }
    };

    display_results(&args.target, &open_ports);
    Ok(())
}

fn parse_port_range(port_str: &str) -> Result<Vec<u16>> {
    const MAX_PORTS: usize = 65_535;
    let mut ports = Vec::new();

    for part in port_str.split(',') {
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                let start: u16 = range[0].parse()?;
                let end: u16 = range[1].parse()?;

                if start > end {
                    return Err(anyhow::anyhow!("Invalid port range: {} > {}", start, end));
                }

                let range_size = (end - start + 1) as usize;
                if range_size > 10_000 {
                    return Err(anyhow::anyhow!(
                        "Port range too large: {} ports (max 10,000)",
                        range_size
                    ));
                }

                if ports.len() + range_size > MAX_PORTS {
                    return Err(anyhow::anyhow!("Total ports exceed maximum: {}", MAX_PORTS));
                }

                for port in start..=end {
                    ports.push(port);
                }
            }
        } else {
            if ports.len() >= MAX_PORTS {
                return Err(anyhow::anyhow!(
                    "Too many ports specified (max {})",
                    MAX_PORTS
                ));
            }
            ports.push(part.parse()?);
        }
    }

    Ok(ports)
}

async fn resolve_target(target: &str) -> Result<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    let addrs: Vec<SocketAddr> = format!("{}:80", target).to_socket_addrs()?.collect();
    if let Some(addr) = addrs.first() {
        Ok(addr.ip())
    } else {
        Err(anyhow::anyhow!("Could not resolve target: {}", target))
    }
}

async fn tcp_scan(target_ip: &IpAddr, ports: &[u16], max_concurrent: usize) -> Result<Vec<u16>> {
    use futures::stream::{iter, StreamExt};

    // Use async stream instead of rayon block_on to avoid deadlocks
    let open_ports: Vec<u16> = iter(ports.iter().cloned())
        .map(|port| async move {
            let addr = SocketAddr::new(*target_ip, port);
            match timeout(Duration::from_millis(1000), TcpStream::connect(addr)).await {
                Ok(Ok(_)) => {
                    print!(".");
                    Some(port)
                }
                _ => None,
            }
        })
        .buffer_unordered(max_concurrent)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    println!();
    Ok(open_ports)
}

fn display_results(target: &str, open_ports: &[u16]) {
    println!(
        "\n{} Scan Results for {}",
        style("📊").cyan(),
        style(target).yellow().bold()
    );
    println!("{}", "=".repeat(50));

    if open_ports.is_empty() {
        println!("{} No open ports found", style("❌").red());
        return;
    }

    println!(
        "{} Found {} open ports:",
        style("✅").green(),
        open_ports.len()
    );

    for &port in open_ports {
        let service = get_common_service(port);
        println!("  {} {}/tcp  {}", style("✓").green(), port, service);
    }
}

fn get_common_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        993 => "imaps",
        995 => "pop3s",
        3389 => "rdp",
        5432 => "postgresql",
        3306 => "mysql",
        1433 => "mssql",
        6379 => "redis",
        27017 => "mongodb",
        _ => "unknown",
    }
}
