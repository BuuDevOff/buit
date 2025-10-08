use std::{env, sync::Arc};

use anyhow::Result;
use axum::{
    extract::{Path, Query},
    http::{header, Request, StatusCode},
    middleware::{self, Next},
    response::Json,
    routing::get,
    Router,
};
use axum_prometheus::PrometheusMetricLayer;
use console::style;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    cli::*,
    modules::{
        email, geoip, github, hash, ip, leaks, phone, search, social, subdomain,
        username::{self, UsernameRunSummary},
        whois,
    },
    types::{ApiEnvelope, ResponseMeta},
};

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct HealthEnvelope {
    pub schema_version: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<HealthResponse>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    pub meta: ResponseMeta,
}

impl From<ApiEnvelope<HealthResponse>> for HealthEnvelope {
    fn from(value: ApiEnvelope<HealthResponse>) -> Self {
        Self {
            schema_version: value.schema_version,
            success: value.success,
            data: value.data,
            warnings: value.warnings,
            errors: value.errors,
            meta: value.meta,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct IpEnvelope {
    pub schema_version: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ip::IpResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    pub meta: ResponseMeta,
}

impl From<ApiEnvelope<ip::IpResult>> for IpEnvelope {
    fn from(value: ApiEnvelope<ip::IpResult>) -> Self {
        Self {
            schema_version: value.schema_version,
            success: value.success,
            data: value.data,
            warnings: value.warnings,
            errors: value.errors,
            meta: value.meta,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct UsernameResponse {
    username: String,
    results: Vec<username::UsernameResult>,
    found: usize,
    checked: usize,
    not_found: usize,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct UsernameEnvelope {
    pub schema_version: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<UsernameResponse>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    pub meta: ResponseMeta,
}

impl From<ApiEnvelope<UsernameResponse>> for UsernameEnvelope {
    fn from(value: ApiEnvelope<UsernameResponse>) -> Self {
        Self {
            schema_version: value.schema_version,
            success: value.success,
            data: value.data,
            warnings: value.warnings,
            errors: value.errors,
            meta: value.meta,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApiQuery {
    pub format: Option<String>,
    pub limit: Option<usize>,
    pub platforms: Option<String>,
    #[allow(dead_code)]
    pub verbose: Option<bool>,
    pub ports: Option<String>,
    pub scan_type: Option<String>,
    pub dns: Option<bool>,
    pub ssl: Option<bool>,
    pub whois: Option<bool>,
    pub output: Option<String>,
    pub engines: Option<String>,
}

#[derive(OpenApi)]
#[openapi(
    paths(health_handler, ip_handler, username_handler),
    components(
        schemas(
            ResponseMeta,
            HealthResponse,
            HealthEnvelope,
            ip::IpResult,
            ip::AsnInfo,
            ip::GeoInfo,
            IpEnvelope,
            UsernameResponse,
            username::UsernameResult,
            username::UsernameRunSummary,
            UsernameEnvelope
        )
    ),
    tags(
        (name = "system", description = "System endpoints"),
        (name = "ip", description = "IP analysis"),
        (name = "username", description = "Username search")
    )
)]
struct ApiDoc;

#[derive(Clone)]
pub struct ApiServerOptions {
    pub host: String,
    pub port: u16,
    pub cors_permissive: bool,
    pub token: Option<String>,
}

pub async fn start_api_server(opts: ApiServerOptions) -> Result<()> {
    println!(
        "{} Starting BUIT API Server on {}:{}",
        style("🚀").green(),
        opts.host,
        opts.port
    );

    let addr = format!("{}:{}", opts.host, opts.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    let (prom_layer, prom_handle) = PrometheusMetricLayer::pair();
    let metrics_handle = prom_handle.clone();

    let mut app = base_router()
        .route("/openapi.json", get(openapi_json))
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
        .route(
            "/metrics",
            get(move || async move { metrics_handle.render() }),
        )
        .layer(build_cors_layer(opts.cors_permissive));

    app = app.layer(TraceLayer::new_for_http());
    app = app.layer(prom_layer);

    if let Some(token) = opts.token {
        let token = Arc::new(token);
        app = app.layer(middleware::from_fn(
            move |req: Request<axum::body::Body>, next: Next| {
                let token = token.clone();
                async move {
                    let authorized = req
                        .headers()
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|header_value| {
                            header_value
                                .strip_prefix("Bearer ")
                                .or_else(|| header_value.strip_prefix("bearer "))
                                .map(str::trim)
                                .map(|candidate| candidate == token.as_str())
                        })
                        .unwrap_or(false);

                    if authorized {
                        Ok(next.run(req).await)
                    } else {
                        Err(StatusCode::UNAUTHORIZED)
                    }
                }
            },
        ));
    }

    println!(
        "{} OpenAPI spec: {}",
        style("📚").yellow(),
        style(format!("http://{}/openapi.json", addr))
            .blue()
            .underlined()
    );
    println!(
        "{} Swagger UI: {}",
        style("📖").yellow(),
        style(format!("http://{}/docs", addr)).blue().underlined()
    );
    println!(
        "{} Metrics: {}",
        style("📈").yellow(),
        style(format!("http://{}/metrics", addr))
            .blue()
            .underlined()
    );

    axum::serve(listener, app).await?;
    Ok(())
}

fn base_router() -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/username/:handle", get(username_handler))
        .route("/email/:address", get(email_handler))
        .route("/subdomain/:domain", get(subdomain_handler))
        .route("/ip/:address", get(ip_handler))
        .route("/whois/:domain", get(whois_handler))
        .route("/hash/:value", get(hash_handler))
        .route("/geoip/:ip", get(geoip_handler))
        .route("/phone/:number", get(phone_handler))
        .route("/github/:user", get(github_handler))
        .route("/search/:query", get(search_handler))
        .route("/social/:target", get(social_handler))
        .route("/leaks/:target", get(leaks_handler))
        .route("/portscan/:target", get(portscan_handler))
        .route("/domain/:domain", get(domain_handler))
        .route("/metadata/:file", get(metadata_handler))
        .route("/report/:title", get(report_handler))
        .route("/reverse-image/:url", get(reverse_image_handler))
}

fn build_cors_layer(permissive: bool) -> CorsLayer {
    if permissive
        || env::var("BUIT_API_ALLOW_CORS")
            .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
    {
        CorsLayer::permissive()
    } else {
        CorsLayer::new()
    }
}

async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "system",
    responses(
        (status = 200, description = "BUIT API health status", body = HealthEnvelope)
    )
)]
async fn health_handler() -> Json<HealthEnvelope> {
    let health = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    Json(ApiEnvelope::success(health).into())
}

#[utoipa::path(
    get,
    path = "/ip/{address}",
    tag = "ip",
    params(("address" = String, Path, description = "IP address to analyse")),
    responses(
        (status = 200, description = "IP analysis result", body = IpEnvelope),
        (status = 500, description = "IP analysis failed")
    )
)]
async fn ip_handler(
    Path(address): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<IpEnvelope>, StatusCode> {
    let args = IpArgs {
        ip: address.clone(),
        no_reverse: false,
        no_asn: false,
        no_geo: false,
    };

    match ip::run(args).await {
        Ok(result) => {
            let warnings = result.warnings.clone();
            let errors = result.errors.clone();
            let mut envelope = ApiEnvelope::success(result);
            envelope.warnings = warnings;
            envelope.errors = errors;
            Ok(Json(envelope.into()))
        }
        Err(e) => {
            tracing::error!("ip_handler error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[utoipa::path(
    get,
    path = "/username/{handle}",
    tag = "username",
    params(
        ("handle" = String, Path, description = "Username to search"),
        ("format" = Option<String>, Query, description = "Existing format flag")
    ),
    responses(
        (status = 200, description = "Username search result", body = UsernameEnvelope),
        (status = 500, description = "Username search failed")
    )
)]
async fn username_handler(
    Path(handle): Path<String>,
    Query(params): Query<ApiQuery>,
) -> Result<Json<UsernameEnvelope>, StatusCode> {
    let args = UsernameArgs {
        username: handle.clone(),
        format: params.format.unwrap_or_else(|| "json".to_string()),
        output: None,
        platforms: params.platforms.clone(),
    };

    match username::run_with_summary(args).await {
        Ok(summary) => {
            let UsernameRunSummary {
                results,
                warnings,
                errors,
                checked,
                not_found,
            } = summary;

            let data = UsernameResponse {
                username: handle,
                found: results.len(),
                checked,
                not_found,
                results,
            };

            let mut envelope = ApiEnvelope::success(data);
            envelope.warnings = warnings;
            envelope.errors = errors;
            Ok(Json(envelope.into()))
        }
        Err(e) => {
            tracing::error!("username_handler error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn email_handler(
    Path(address): Path<String>,
    Query(params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let args = EmailArgs {
        email: address.clone(),
        breaches: true,
        social: true,
        format: params.format.unwrap_or_else(|| "json".to_string()),
    };

    match email::run(args.clone()).await {
        Ok(_) => {
            let data = json!({
                "email": address,
                "message": "Email analysis completed successfully",
                "note": "Detailed results available via CLI"
            });
            Ok(Json(ApiEnvelope::success(data)))
        }
        Err(e) => {
            tracing::error!("Email analysis error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn subdomain_handler(
    Path(domain): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let args = SubdomainArgs {
        domain: domain.clone(),
        crt: true,
        brute: false,
        skip_alive_check: false,
    };

    match subdomain::run(args.clone()).await {
        Ok(_) => {
            let data = json!({
                "domain": domain,
                "message": "Subdomain enumeration completed successfully",
                "note": "Detailed results available via CLI"
            });
            Ok(Json(ApiEnvelope::success(data)))
        }
        Err(e) => {
            tracing::error!("Subdomain enumeration error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn whois_handler(
    Path(domain): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let args = WhoisArgs {
        target: domain.clone(),
        parse: true,
    };

    match whois::run(args.clone()).await {
        Ok(_) => {
            let data = json!({
                "domain": domain,
                "message": "WHOIS lookup completed successfully",
                "cli_command": format!("buit whois {}", domain)
            });
            Ok(Json(ApiEnvelope::success(data)))
        }
        Err(e) => {
            tracing::error!("WHOIS lookup error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn hash_handler(
    Path(value): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let args = HashArgs {
        hash: value.clone(),
        identify: true,
        crack: false,
    };

    match hash::run(args.clone()).await {
        Ok(_) => {
            let data = json!({
                "hash": value,
                "message": "Hash analysis completed successfully",
                "cli_command": format!("buit hash {}", value)
            });
            Ok(Json(ApiEnvelope::success(data)))
        }
        Err(e) => {
            tracing::error!("Hash analysis error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn geoip_handler(
    Path(ip_addr): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let args = GeoipArgs {
        ip: ip_addr.clone(),
        isp: true,
    };

    match geoip::run(args.clone()).await {
        Ok(_) => {
            let data = json!({
                "ip": ip_addr,
                "message": "GeoIP lookup completed successfully",
                "cli_command": format!("buit geoip {}", ip_addr)
            });
            Ok(Json(ApiEnvelope::success(data)))
        }
        Err(e) => {
            tracing::error!("GeoIP lookup error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn phone_handler(
    Path(number): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let args = PhoneArgs {
        number: number.clone(),
        carrier: true,
        format: Some("json".to_string()),
    };

    match phone::run(args.clone()).await {
        Ok(_) => {
            let data = json!({
                "number": number,
                "message": "Phone analysis completed successfully",
                "cli_command": format!("buit phone {}", args.number)
            });
            Ok(Json(ApiEnvelope::success(data)))
        }
        Err(e) => {
            tracing::error!("Phone analysis error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn github_handler(
    Path(user): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let args = GithubArgs {
        target: user.clone(),
        repos: true,
        secrets: false,
    };

    match github::run(args.clone()).await {
        Ok(_) => {
            let data = json!({
                "user": user,
                "message": "GitHub analysis completed successfully",
                "cli_command": format!("buit github {}", args.target)
            });
            Ok(Json(ApiEnvelope::success(data)))
        }
        Err(e) => {
            tracing::error!("GitHub analysis error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn search_handler(
    Path(query): Path<String>,
    Query(params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let args = SearchArgs {
        query: query.clone(),
        engine: params
            .engines
            .clone()
            .unwrap_or_else(|| "duckduckgo".to_string()),
        limit: params.limit.unwrap_or(20),
        deep: false,
    };

    match search::run(args.clone()).await {
        Ok(_) => {
            let data = json!({
                "query": query,
                "message": "Search completed successfully",
                "cli_command": format!("buit search {}", args.query)
            });
            Ok(Json(ApiEnvelope::success(data)))
        }
        Err(e) => {
            tracing::error!("Search error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn social_handler(
    Path(target): Path<String>,
    Query(params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let args = SocialArgs {
        target: target.clone(),
        id_type: params
            .format
            .clone()
            .unwrap_or_else(|| "username".to_string()),
        platforms: params.platforms.clone(),
        analyze: false,
    };

    match social::run(args.clone()).await {
        Ok(_) => {
            let data = json!({
                "target": target,
                "message": "Social media reconnaissance completed successfully",
                "cli_command": "buit social ..."
            });
            Ok(Json(ApiEnvelope::success(data)))
        }
        Err(e) => {
            tracing::error!("Social module error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn leaks_handler(
    Path(target): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let args = LeaksArgs {
        target: target.clone(),
        hibp: true,
        passwords: false,
    };

    match leaks::run(args.clone()).await {
        Ok(_) => {
            let data = json!({
                "target": target,
                "message": "Leak analysis completed successfully",
                "note": "Use CLI for detailed breach information"
            });
            Ok(Json(ApiEnvelope::success(data)))
        }
        Err(e) => {
            tracing::error!("Leaks module error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn portscan_handler(
    Path(target): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let data = json!({
        "target": target,
        "message": "Run 'buit portscan <target>' for detailed results"
    });
    Ok(Json(ApiEnvelope::success(data)))
}

async fn domain_handler(
    Path(domain): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let data = json!({
        "domain": domain,
        "message": "Domain analysis available via CLI",
        "cli_command": "buit domain <domain>"
    });
    Ok(Json(ApiEnvelope::success(data)))
}

async fn metadata_handler(
    Path(file): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let data = json!({
        "file": file,
        "message": "Run 'buit metadata <file>' to extract metadata"
    });
    Ok(Json(ApiEnvelope::success(data)))
}

async fn report_handler(
    Path(title): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let data = json!({
        "title": title,
        "message": "Use 'buit report' from the CLI to generate reports"
    });
    Ok(Json(ApiEnvelope::success(data)))
}

async fn reverse_image_handler(
    Path(url): Path<String>,
    Query(_params): Query<ApiQuery>,
) -> Result<Json<ApiEnvelope<Value>>, StatusCode> {
    let data = json!({
        "image": url,
        "message": "Reverse image search requires manual steps",
        "note": "Run 'buit reverse-image <url|path>'"
    });
    Ok(Json(ApiEnvelope::success(data)))
}
