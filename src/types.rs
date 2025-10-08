use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Shared schema version for API responses.
pub const API_SCHEMA_VERSION: &str = "2024-01-01";

/// Metadata that accompanies every API envelope.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ResponseMeta {
    pub timestamp: String,
    pub version: String,
}

impl ResponseMeta {
    pub fn current() -> Self {
        ResponseMeta {
            timestamp: Utc::now().to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Standard envelope returned by the API and structured CLI outputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiEnvelope<T>
where
    T: Serialize,
{
    pub schema_version: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    pub meta: ResponseMeta,
}

impl<T> ApiEnvelope<T>
where
    T: Serialize,
{
    pub fn new(data: Option<T>, warnings: Vec<String>, errors: Vec<String>) -> Self {
        ApiEnvelope {
            schema_version: API_SCHEMA_VERSION.to_string(),
            success: errors.is_empty(),
            data,
            warnings,
            errors,
            meta: ResponseMeta::current(),
        }
    }

    pub fn success(data: T) -> Self {
        Self::new(Some(data), Vec::new(), Vec::new())
    }

    #[allow(dead_code)]
    pub fn failure(errors: Vec<String>, warnings: Vec<String>) -> Self {
        Self::new(None, warnings, errors)
    }
}
