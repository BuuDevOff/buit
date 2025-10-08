use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use tokio::net::lookup_host;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug, Clone)]
pub struct DnsClient {
    resolver: TokioAsyncResolver,
}

impl DnsClient {
    pub fn new() -> Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self { resolver })
    }

    pub async fn reverse_dns(&self, ip: IpAddr) -> Result<Vec<String>> {
        let response = self.resolver.reverse_lookup(ip).await?;
        Ok(response.into_iter().map(|name| name.to_string()).collect())
    }

    #[allow(dead_code)]
    pub async fn resolve_a(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let response = self.resolver.lookup_ip(domain).await?;
        Ok(response.into_iter().collect())
    }

    #[allow(dead_code)]
    pub async fn resolve_mx(&self, domain: &str) -> Result<Vec<String>> {
        use trust_dns_resolver::proto::rr::RecordType;

        let response = self.resolver.lookup(domain, RecordType::MX).await?;
        let mut mx_records = Vec::new();

        for record in response.iter() {
            if let Some(mx_data) = record.as_mx() {
                mx_records.push(format!("{} {}", mx_data.preference(), mx_data.exchange()));
            }
        }

        Ok(mx_records)
    }

    #[allow(dead_code)]
    pub async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>> {
        use trust_dns_resolver::proto::rr::RecordType;

        let response = self.resolver.lookup(domain, RecordType::TXT).await?;
        let mut txt_records = Vec::new();

        for record in response.iter() {
            if let Some(txt_data) = record.as_txt() {
                for data in txt_data.iter() {
                    txt_records.push(String::from_utf8_lossy(data).to_string());
                }
            }
        }

        Ok(txt_records)
    }
}

pub async fn resolve_hostname(host: &str) -> Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    let addrs: Vec<SocketAddr> = lookup_host(format!("{}:80", host)).await?.collect();
    if let Some(addr) = addrs.first() {
        Ok(addr.ip())
    } else {
        Err(anyhow::anyhow!("Could not resolve hostname: {}", host))
    }
}
