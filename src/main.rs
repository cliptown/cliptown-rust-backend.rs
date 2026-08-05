pub mod account_security;
pub mod app_vault;
pub mod encrypted_objects;
pub mod entity;
mod memebank_auth;
mod memebank_routes;
pub mod memebank_transfer;

#[cfg(test)]
#[path = "memebank_routes/headless_tests.rs"]
mod memebank_headless_tests;

use std::{
    env,
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration as StdDuration,
};

use axum::{
    extract::State,
    http::{header, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
#[cfg(test)]
use chrono::{Duration, Utc};
use memebank_auth::MemebankAuthenticator;
#[cfg(test)]
use memebank_routes::routes;
use memebank_routes::AppState;
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseBackend, Statement};
use serde::Serialize;
use shared_auth_client::SharedAuthClient;
use tower_http::set_header::SetResponseHeaderLayer;
use url::Url;

#[derive(Debug, Serialize)]
struct ServiceInfo {
    service: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct HealthStatus {
    status: &'static str,
}

#[derive(Debug)]
struct StartupError(&'static str);

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for StartupError {}

struct RuntimeConfig {
    bind_address: SocketAddr,
    database_url: String,
    database_max_connections: u32,
    shared_auth_base_url: String,
    shared_auth_issuer: String,
    shared_auth_introspect_secret: String,
}

impl RuntimeConfig {
    fn from_env() -> Result<Self, StartupError> {
        let bind_address = env::var("CLIPTOWN_BIND_ADDRESS")
            .unwrap_or_else(|_| "0.0.0.0:3000".to_owned())
            .parse()
            .map_err(|_| StartupError("CLIPTOWN_BIND_ADDRESS is invalid"))?;
        let database_url = required_env("DATABASE_URL")?;
        let database_max_connections = env::var("CLIPTOWN_DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "16".to_owned())
            .parse::<u32>()
            .ok()
            .filter(|value| (1..=128).contains(value))
            .ok_or(StartupError(
                "CLIPTOWN_DATABASE_MAX_CONNECTIONS must be from 1 through 128",
            ))?;
        let shared_auth_base_url = required_env("SHARED_AUTH_BASE_URL")?;
        if !valid_shared_auth_base_url(&shared_auth_base_url) {
            return Err(StartupError(
                "SHARED_AUTH_BASE_URL must use HTTPS outside loopback",
            ));
        }
        let shared_auth_issuer = required_env("SHARED_AUTH_ISSUER")?;
        if !valid_https_issuer(&shared_auth_issuer) {
            return Err(StartupError("SHARED_AUTH_ISSUER must be an HTTPS URL"));
        }
        let shared_auth_introspect_secret = required_env("SHARED_AUTH_INTROSPECT_SECRET")?;
        if !valid_service_credential(&shared_auth_introspect_secret) {
            return Err(StartupError(
                "SHARED_AUTH_INTROSPECT_SECRET does not satisfy the service credential policy",
            ));
        }

        Ok(Self {
            bind_address,
            database_url,
            database_max_connections,
            shared_auth_base_url,
            shared_auth_issuer,
            shared_auth_introspect_secret,
        })
    }
}

fn public_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(service_info))
        .route("/healthz", get(healthz))
}

fn app(state: AppState) -> Router {
    public_routes::<AppState>()
        .route("/readyz", get(readyz))
        .merge(memebank_routes::routes())
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
        ))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("cliptown-api: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), StartupError> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .try_init()
        .map_err(|_| StartupError("logging initialization failed"))?;
    dotenvy::dotenv().ok();
    let RuntimeConfig {
        bind_address,
        database_url,
        database_max_connections,
        shared_auth_base_url,
        shared_auth_issuer,
        shared_auth_introspect_secret,
    } = RuntimeConfig::from_env()?;

    let mut database_options = ConnectOptions::new(database_url);
    database_options
        .max_connections(database_max_connections)
        .min_connections(1)
        .connect_timeout(StdDuration::from_secs(5))
        .acquire_timeout(StdDuration::from_secs(5))
        .sqlx_logging(false);
    let database = Database::connect(database_options)
        .await
        .map_err(|_| StartupError("database initialization failed"))?;

    let shared_auth = SharedAuthClient::new(shared_auth_base_url)
        .with_service_credential(shared_auth_introspect_secret);
    let authenticator = MemebankAuthenticator::new(shared_auth, shared_auth_issuer)
        .map_err(|_| StartupError("shared-auth initialization failed"))?;
    let state = AppState::new(database, authenticator);

    let listener = tokio::net::TcpListener::bind(bind_address)
        .await
        .map_err(|_| StartupError("listener initialization failed"))?;
    tracing::info!(address = %bind_address, "ClipTown API listening");
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|_| StartupError("HTTP server failed"))?;
    Ok(())
}

async fn service_info() -> Json<ServiceInfo> {
    Json(ServiceInfo {
        service: "cliptown-api",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn healthz() -> Json<HealthStatus> {
    Json(HealthStatus { status: "ok" })
}

async fn readyz(State(state): State<AppState>) -> Response {
    let statement = Statement::from_string(
        DatabaseBackend::Postgres,
        "SELECT to_regclass('cliptown.memebank_transfers') IS NOT NULL \
         AND to_regclass('cliptown.memebank_transfer_idempotency') IS NOT NULL AS ready"
            .to_owned(),
    );
    let ready = match state.database.query_one(statement).await {
        Ok(Some(row)) => {
            let ready: Result<bool, _> = row.try_get("", "ready");
            ready.unwrap_or(false)
        }
        _ => false,
    };
    if ready {
        (StatusCode::OK, Json(HealthStatus { status: "ready" })).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthStatus {
                status: "not_ready",
            }),
        )
            .into_response()
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn required_env(name: &'static str) -> Result<String, StartupError> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(StartupError(match name {
            "DATABASE_URL" => "DATABASE_URL is required",
            "SHARED_AUTH_BASE_URL" => "SHARED_AUTH_BASE_URL is required",
            "SHARED_AUTH_ISSUER" => "SHARED_AUTH_ISSUER is required",
            "SHARED_AUTH_INTROSPECT_SECRET" => "SHARED_AUTH_INTROSPECT_SECRET is required",
            _ => "required configuration is missing",
        }))
}

fn valid_shared_auth_base_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    if url.scheme() == "https" {
        return true;
    }
    url.scheme() == "http" && is_loopback_url(&url)
}

fn valid_https_issuer(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn is_loopback_url(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn valid_service_credential(value: &str) -> bool {
    (32..=16 * 1024).contains(&value.len())
        && value.trim() == value
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request},
        response::Response,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn request(method: Method, path: &str) -> Response {
        public_routes::<()>()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("valid request"),
            )
            .await
            .expect("router response")
    }

    async fn json_body(response: Response) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collection")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("JSON response")
    }

    #[tokio::test]
    async fn root_reports_service_and_version() {
        let response = request(Method::GET, "/").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");

        let body = json_body(response).await;
        assert_eq!(body["service"], "cliptown-api");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn liveness_is_credential_and_database_independent() {
        let health = json_body(request(Method::GET, "/healthz").await).await;
        assert_eq!(health["status"], "ok");
    }

    #[tokio::test]
    async fn rejects_unknown_routes_and_unsupported_methods() {
        assert_eq!(
            request(Method::GET, "/missing").await.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            request(Method::POST, "/healthz").await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[test]
    fn auth_endpoints_fail_closed_on_remote_plaintext_or_weak_credentials() {
        assert!(!valid_shared_auth_base_url("http://auth.example.test"));
        assert!(valid_shared_auth_base_url("http://127.0.0.1:8120"));
        assert!(valid_shared_auth_base_url(
            "https://auth.example.test/shared-auth"
        ));
        assert!(!valid_https_issuer("http://auth.example.test"));
        assert!(valid_https_issuer("https://auth.example.test"));
        assert!(!valid_service_credential("too-short"));
        assert!(!valid_service_credential(
            "0123456789abcdef0123456789abcdef\n"
        ));
        assert!(valid_service_credential("0123456789abcdef0123456789abcdef"));
    }
}
