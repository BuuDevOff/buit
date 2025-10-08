use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

use anyhow::Result;
use backoff::{backoff::Backoff, ExponentialBackoff};
use governor::{DefaultDirectRateLimiter, Quota};
use moka::future::Cache;
use reqwest::{Client, Method, Proxy, StatusCode, Url};
use serde::Serialize;
use thiserror::Error;
use tokio::{sync::Mutex, time::sleep};

use crate::config::Config;
use crate::utils::context::AppContext;

const MAX_BODY_BYTES: usize = 10_000_000; // 10MB limit for textual responses
#[allow(dead_code)]
const MAX_JSON_BYTES: usize = 5_000_000; // 5MB limit for JSON deserialisation
const DEFAULT_PER_HOST_LIMIT: u32 = 5; // 5 requests per second by default
const MIN_BACKOFF_MS: u64 = 250;

pub type SharedHttpCache = Arc<Cache<String, Arc<Vec<u8>>>>;
type RateLimiterHandle = DefaultDirectRateLimiter;
type ClientWithMiddleware = Client;

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("Invalid URL {url}: {source}")]
    InvalidUrl {
        url: String,
        #[source]
        source: url::ParseError,
    },
    #[error("Timeout while requesting {url}")]
    Timeout { url: String },
    #[error("Rate limit reached for host {host}")]
    RateLimited {
        host: String,
        retry_after: Option<Duration>,
    },
    #[error("HTTP {status} returned from {url}")]
    BadStatus {
        url: String,
        status: StatusCode,
        body_snippet: Option<String>,
    },
    #[error("Response from {url} too large: {size} bytes (limit {limit})")]
    BodyTooLarge {
        url: String,
        size: usize,
        limit: usize,
    },
    #[error("Failed to parse response from {url}: {message}")]
    Parse { url: String, message: String },
    #[error("Request error for {url}: {source}")]
    Transport {
        url: String,
        #[source]
        source: reqwest::Error,
    },
}

impl HttpError {
    fn is_retryable(&self) -> bool {
        match self {
            HttpError::Timeout { .. } => true,
            HttpError::RateLimited { .. } => true,
            HttpError::BadStatus { status, .. } => status.is_server_error(),
            HttpError::Transport { source, .. } => {
                source.is_timeout() || source.is_connect() || source.is_request()
            }
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct HttpCtx {
    client: ClientWithMiddleware,
    retry_attempts: usize,
    rate_limiters: Arc<Mutex<HashMap<String, Arc<RateLimiterHandle>>>>,
    per_host_quota: Quota,
    cache: Option<SharedHttpCache>,
}

impl HttpCtx {
    pub fn new(config: &Config, cache: Option<SharedHttpCache>) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.settings.timeout))
            .user_agent(&config.settings.user_agent)
            .use_rustls_tls()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(30))
            .tcp_keepalive(Duration::from_secs(600));

        if let Some(proxy_url) = &config.settings.proxy {
            let mut proxy = Proxy::all(proxy_url)?;

            if let Some(auth) = &config.settings.proxy_auth {
                proxy = proxy.basic_auth(&auth.username, &auth.password);
            }

            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;

        let retry_attempts = config.settings.retry_count.max(1);
        let per_second = compute_per_host_limit(config.settings.rate_limit_delay);
        let per_host_quota = Quota::per_second(per_second);

        Ok(HttpCtx {
            client,
            retry_attempts,
            rate_limiters: Arc::new(Mutex::new(HashMap::new())),
            per_host_quota,
            cache,
        })
    }

    #[allow(dead_code)]
    pub fn cache(&self) -> Option<SharedHttpCache> {
        self.cache.clone()
    }

    pub async fn await_permit(&self, host: &str) -> Result<(), HttpError> {
        let limiter = {
            let mut guard = self.rate_limiters.lock().await;
            guard
                .entry(host.to_string())
                .or_insert_with(|| Arc::new(RateLimiterHandle::direct(self.per_host_quota)))
                .clone()
        };

        limiter.until_ready().await;
        Ok(())
    }

    pub async fn get_text(&self, url: &str) -> Result<String, HttpError> {
        let bytes = self.execute(Method::GET, url, None, None).await?;
        String::from_utf8(bytes.to_vec()).map_err(|err| HttpError::Parse {
            url: url.to_string(),
            message: err.utf8_error().to_string(),
        })
    }

    pub async fn get_json<T>(&self, url: &str) -> Result<T, HttpError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let bytes = self.execute(Method::GET, url, None, None).await?;
        if bytes.len() > MAX_JSON_BYTES {
            return Err(HttpError::BodyTooLarge {
                url: url.to_string(),
                size: bytes.len(),
                limit: MAX_JSON_BYTES,
            });
        }

        serde_json::from_slice(&bytes).map_err(|err| HttpError::Parse {
            url: url.to_string(),
            message: err.to_string(),
        })
    }

    #[allow(dead_code)]
    pub async fn post_json<T, B>(&self, url: &str, body: &B) -> Result<T, HttpError>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: Serialize,
    {
        let payload = serde_json::to_vec(body).map_err(|err| HttpError::Parse {
            url: url.to_string(),
            message: err.to_string(),
        })?;
        let bytes = self.execute(Method::POST, url, None, Some(payload)).await?;
        if bytes.len() > MAX_JSON_BYTES {
            return Err(HttpError::BodyTooLarge {
                url: url.to_string(),
                size: bytes.len(),
                limit: MAX_JSON_BYTES,
            });
        }
        serde_json::from_slice(&bytes).map_err(|err| HttpError::Parse {
            url: url.to_string(),
            message: err.to_string(),
        })
    }

    async fn execute(
        &self,
        method: Method,
        url: &str,
        headers: Option<&[(&str, &str)]>,
        body: Option<Vec<u8>>,
    ) -> Result<Arc<Vec<u8>>, HttpError> {
        let parsed = Url::parse(url).map_err(|source| HttpError::InvalidUrl {
            url: url.to_string(),
            source,
        })?;

        if let Some(host) = parsed.host_str() {
            self.await_permit(host).await?;
        }

        let cache_lookup_key =
            cache_key(&method, url, headers.unwrap_or_default(), body.as_deref());

        if let Some(cache) = &self.cache {
            if let Some(bytes) = cache.get(&cache_lookup_key).await {
                return Ok(bytes);
            }
        }

        let bytes = self
            .perform_with_retries(method, parsed.clone(), headers, body)
            .await?;

        if let Some(cache) = &self.cache {
            cache.insert(cache_lookup_key, bytes.clone()).await;
        }

        Ok(bytes)
    }

    async fn perform_with_retries(
        &self,
        method: Method,
        url: Url,
        headers: Option<&[(&str, &str)]>,
        body: Option<Vec<u8>>,
    ) -> Result<Arc<Vec<u8>>, HttpError> {
        let mut attempt = 0;
        let mut backoff = default_backoff();

        loop {
            attempt += 1;
            match self
                .perform_once(method.clone(), url.clone(), headers, body.clone())
                .await
            {
                Ok(bytes) => return Ok(bytes),
                Err(err) => {
                    if attempt >= self.retry_attempts || !err.is_retryable() {
                        return Err(err);
                    }

                    if let Some(delay) = backoff.next_backoff() {
                        sleep(delay).await;
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }

    async fn perform_once(
        &self,
        method: Method,
        url: Url,
        headers: Option<&[(&str, &str)]>,
        body: Option<Vec<u8>>,
    ) -> Result<Arc<Vec<u8>>, HttpError> {
        let mut request = self.client.request(method, url.clone());

        if let Some(headers) = headers {
            for (key, value) in headers {
                request = request.header(*key, *value);
            }
        }

        if let Some(body) = body {
            request = request.body(body);
        }

        let host = url.host_str().map(|h| h.to_string());

        let response = request.send().await.map_err(|source| {
            if source.is_timeout() {
                HttpError::Timeout {
                    url: url.to_string(),
                }
            } else {
                HttpError::Transport {
                    url: url.to_string(),
                    source,
                }
            }
        })?;

        let status = response.status();

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = parse_retry_after(response.headers().get("retry-after"));
            return Err(HttpError::RateLimited {
                host: host.unwrap_or_default(),
                retry_after,
            });
        }

        if !status.is_success() {
            let snippet = response.text().await.ok().map(truncate);
            return Err(HttpError::BadStatus {
                url: url.to_string(),
                status,
                body_snippet: snippet,
            });
        }

        let bytes = response.bytes().await.map_err(|source| {
            if source.is_timeout() {
                HttpError::Timeout {
                    url: url.to_string(),
                }
            } else {
                HttpError::Transport {
                    url: url.to_string(),
                    source,
                }
            }
        })?;

        if bytes.len() > MAX_BODY_BYTES {
            return Err(HttpError::BodyTooLarge {
                url: url.to_string(),
                size: bytes.len(),
                limit: MAX_BODY_BYTES,
            });
        }

        Ok(Arc::new(bytes.to_vec()))
    }
}

#[derive(Clone)]
pub struct HttpClient {
    inner: Arc<HttpCtx>,
}

impl HttpClient {
    pub fn new() -> Result<Self> {
        let ctx = AppContext::current().http();
        Ok(Self::from_shared(ctx))
    }

    pub fn from_shared(inner: Arc<HttpCtx>) -> Self {
        HttpClient { inner }
    }

    pub async fn check_url(&self, url: &str) -> Result<bool, HttpError> {
        match self.inner.execute(Method::GET, url, None, None).await {
            Ok(_) => Ok(true),
            Err(HttpError::BadStatus { status, .. }) if status == StatusCode::NOT_FOUND => {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    #[allow(dead_code)]
    pub async fn await_permit(&self, host: &str) -> Result<(), HttpError> {
        self.inner.await_permit(host).await
    }

    pub async fn get(&self, url: &str) -> Result<String, HttpError> {
        self.inner.get_text(url).await
    }

    #[allow(dead_code)]
    pub async fn get_text(&self, url: &str) -> Result<String, HttpError> {
        self.inner.get_text(url).await
    }

    #[allow(dead_code)]
    pub async fn get_json<T>(&self, url: &str) -> Result<T, HttpError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        self.inner.get_json(url).await
    }

    pub async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<String, HttpError> {
        let bytes = self
            .inner
            .execute(Method::GET, url, Some(headers), None)
            .await?;
        String::from_utf8(bytes.to_vec()).map_err(|err| HttpError::Parse {
            url: url.to_string(),
            message: err.utf8_error().to_string(),
        })
    }

    #[allow(dead_code)]
    pub async fn post_json<T, B>(&self, url: &str, body: &B) -> Result<T, HttpError>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: Serialize,
    {
        self.inner.post_json(url, body).await
    }
}

fn compute_per_host_limit(rate_limit_delay_ms: u64) -> NonZeroU32 {
    if rate_limit_delay_ms == 0 {
        return NonZeroU32::new(DEFAULT_PER_HOST_LIMIT).unwrap();
    }

    let per_second = (1_000 / rate_limit_delay_ms.max(1)).max(1);
    NonZeroU32::new(per_second as u32)
        .unwrap_or_else(|| NonZeroU32::new(DEFAULT_PER_HOST_LIMIT).unwrap())
}

fn cache_key(method: &Method, url: &str, headers: &[(&str, &str)], body: Option<&[u8]>) -> String {
    let mut key = format!("{}:{}", method, url);
    if !headers.is_empty() {
        let mut parts: Vec<String> = headers
            .iter()
            .map(|(k, v)| format!("{}={}", k.trim().to_lowercase(), v.trim()))
            .collect();
        parts.sort();
        key.push('|');
        key.push_str(&parts.join("&"));
    }

    if let Some(body) = body {
        let body_hash = blake3::hash(body);
        key.push('|');
        key.push_str(&body_hash.to_string());
    }

    key
}

fn parse_retry_after(value: Option<&reqwest::header::HeaderValue>) -> Option<Duration> {
    use chrono::{DateTime, Utc};

    let header = value?.to_str().ok()?;
    if let Ok(seconds) = header.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    DateTime::parse_from_rfc2822(header)
        .or_else(|_| DateTime::parse_from_rfc3339(header))
        .ok()
        .map(|dt| {
            let retry_at = dt.with_timezone(&Utc);
            let now = Utc::now();
            if retry_at > now {
                (retry_at - now)
                    .to_std()
                    .unwrap_or_else(|_| Duration::from_secs(0))
            } else {
                Duration::from_secs(0)
            }
        })
}

fn truncate(body: String) -> String {
    const MAX_LEN: usize = 256;
    if body.len() <= MAX_LEN {
        body
    } else {
        format!("{}…", &body[..MAX_LEN])
    }
}

fn default_backoff() -> ExponentialBackoff {
    let mut backoff = ExponentialBackoff::default();
    backoff.initial_interval = Duration::from_millis(MIN_BACKOFF_MS);
    backoff.randomization_factor = 0.3;
    backoff.multiplier = 1.8;
    backoff.max_interval = Duration::from_secs(10);
    backoff.max_elapsed_time = Some(Duration::from_secs(60));
    backoff
}
