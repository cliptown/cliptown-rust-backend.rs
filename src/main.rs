pub mod account_security;
pub mod app_vault;
pub mod encrypted_objects;
pub mod entity;
pub mod memebank_integration;

use std::{env, error::Error};

use axum::{
    http::{header, HeaderValue},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use tower_http::set_header::SetResponseHeaderLayer;

#[derive(Debug, Serialize)]
struct ServiceInfo {
    service: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct HealthStatus {
    status: &'static str,
}

fn app() -> Router {
    Router::new()
        .route("/", get(service_info))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("cliptown-api: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();

    let bind_address =
        env::var("CLIPTOWN_BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:3000".to_owned());
    if bind_address.trim().is_empty() {
        return Err("CLIPTOWN_BIND_ADDRESS must not be empty".into());
    }

    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    axum::serve(listener, app()).await?;
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

async fn readyz() -> Json<HealthStatus> {
    Json(HealthStatus { status: "ready" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
        response::Response,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn request(method: Method, path: &str) -> Response {
        app()
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
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );

        let body = json_body(response).await;
        assert_eq!(body["service"], "cliptown-api");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn health_and_readiness_are_distinct_contracts() {
        let health = json_body(request(Method::GET, "/healthz").await).await;
        let readiness = json_body(request(Method::GET, "/readyz").await).await;
        assert_eq!(health["status"], "ok");
        assert_eq!(readiness["status"], "ready");
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
}
