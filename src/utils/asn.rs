use crate::utils::http::HttpClient;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize)]
pub struct AsnInfo {
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub country: Option<String>,
    pub registry: Option<String>,
    pub allocated: Option<String>,
    pub prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpApiAsnResponse {
    #[serde(rename = "as")]
    asn: Option<String>,
    #[serde(rename = "org")]
    organization: Option<String>,
    country: Option<String>,
}

pub async fn lookup_asn(ip: IpAddr) -> Result<Option<AsnInfo>> {
    let client = HttpClient::new()?;
    lookup_asn_ipapi(&client, ip).await
}

async fn lookup_asn_ipapi(client: &HttpClient, ip: IpAddr) -> Result<Option<AsnInfo>> {
    let url = format!("http://ip-api.com/json/{}?fields=as,org,country", ip);
    let response = client.get(&url).await?;
    let api_response: IpApiAsnResponse = serde_json::from_str(&response)?;

    if let Some(as_field) = api_response.asn.clone() {
        if let Some((asn, org)) = extract_asn_fields(&as_field, api_response.organization.clone()) {
            return Ok(Some(AsnInfo {
                asn: Some(asn),
                org: if org.is_empty() { None } else { Some(org) },
                country: api_response.country,
                registry: None,
                allocated: None,
                prefix: None,
            }));
        }
    }

    if let Some(org) = api_response.organization {
        return Ok(Some(AsnInfo {
            asn: None,
            org: if org.is_empty() { None } else { Some(org) },
            country: api_response.country,
            registry: None,
            allocated: None,
            prefix: None,
        }));
    }

    Ok(None)
}

fn extract_asn_fields(as_field: &str, fallback_org: Option<String>) -> Option<(u32, String)> {
    let trimmed = as_field.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(space_pos) = trimmed.find(' ') {
        let (asn_part, org_part) = trimmed.split_at(space_pos);
        let asn_number = asn_part.trim_start_matches("AS").parse::<u32>().ok()?;
        let org = org_part.trim().to_string();
        if org.is_empty() {
            let fallback = fallback_org.unwrap_or_default();
            return Some((asn_number, fallback));
        }
        Some((asn_number, org))
    } else {
        let asn_number = trimmed.trim_start_matches("AS").parse::<u32>().ok()?;
        let org = fallback_org.unwrap_or_default();
        Some((asn_number, org))
    }
}
