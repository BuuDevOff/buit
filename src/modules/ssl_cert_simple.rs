use crate::cli::SslCertArgs;
use anyhow::Result;
use console::style;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SslCertInfo {
    pub domain: String,
    pub port: u16,
    pub connection_status: String,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub certificate_info: Option<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

pub async fn run(args: SslCertArgs) -> Result<()> {
    println!(
        "{} SSL Certificate Analysis: {}:{}",
        style("🔐").cyan(),
        style(&args.domain).yellow().bold(),
        style(args.port.to_string()).yellow()
    );

    match check_ssl_connection(&args.domain, args.port).await {
        Ok(cert_info) => display_results(&cert_info),
        Err(e) => {
            println!(
                "{} Failed to analyze SSL certificate: {}",
                style("❌").red(),
                e
            );
            let cert_info = SslCertInfo {
                domain: args.domain.clone(),
                port: args.port,
                connection_status: "Connection failed".to_string(),
                tls_version: None,
                cipher_suite: None,
                certificate_info: None,
                warnings: Vec::new(),
                errors: vec![format!("TCP connection failed: {}", e)],
            };
            display_results(&cert_info);
        }
    }

    Ok(())
}

async fn check_ssl_connection(domain: &str, port: u16) -> Result<SslCertInfo> {
    use std::time::Duration;
    use tokio::net::TcpStream;

    // Try to establish a basic TCP connection first
    let addr = format!("{}:{}", domain, port);
    let _stream =
        tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await??;

    // For now, return basic connection info
    Ok(SslCertInfo {
        domain: domain.to_string(),
        port,
        connection_status: "Connected (TCP handshake only)".to_string(),
        tls_version: None,
        cipher_suite: None,
        certificate_info: None,
        warnings: vec![
            "TLS handshake not performed; run `openssl s_client -connect host:port` for details"
                .to_string(),
        ],
        errors: Vec::new(),
    })
}

fn display_results(cert_info: &SslCertInfo) {
    println!(
        "\n{}",
        style("SSL Certificate Analysis Results:").green().bold()
    );
    println!("{}", style("═══════════════════════════════════").cyan());

    println!(
        "  {} {}:{}",
        style("Target:").yellow(),
        cert_info.domain,
        cert_info.port
    );
    println!(
        "  {} {}",
        style("Status:").yellow(),
        if cert_info.connection_status.contains("Connected") {
            style(&cert_info.connection_status).green()
        } else {
            style(&cert_info.connection_status).yellow()
        }
    );

    if let Some(tls_version) = &cert_info.tls_version {
        println!(
            "  {} {}",
            style("TLS Version:").yellow(),
            style(tls_version).cyan()
        );
    }

    if let Some(cipher) = &cert_info.cipher_suite {
        println!(
            "  {} {}",
            style("Cipher Suite:").yellow(),
            style(cipher).cyan()
        );
    }

    if let Some(cert_info_str) = &cert_info.certificate_info {
        println!(
            "  {} {}",
            style("Certificate:").yellow(),
            style(cert_info_str).green()
        );
    }

    println!("\n{}", style("Recommendations:").yellow());
    println!(
        "  • Use 'openssl s_client -connect {}:{}' for detailed certificate analysis",
        cert_info.domain, cert_info.port
    );
    println!("  • Check SSL Labs (ssllabs.com/ssltest) for comprehensive security analysis");
    println!("  • Verify certificate chain and expiration dates");
    println!("  • Ensure strong cipher suites are enabled");

    if !cert_info.warnings.is_empty() {
        println!("\n{}", style("Warnings:").yellow());
        for warning in &cert_info.warnings {
            println!("  {} {}", style("⚠").yellow(), warning);
        }
    }

    if !cert_info.errors.is_empty() {
        println!("\n{}", style("Errors:").red());
        for error in &cert_info.errors {
            println!("  {} {}", style("✗").red(), error);
        }
    }
}
