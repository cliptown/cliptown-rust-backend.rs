use std::{env, time::{SystemTime, UNIX_EPOCH}};

use axum::{
    body::Body,
    http::{header::AUTHORIZATION, HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use http_body_util::BodyExt;
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};
use serde_json::{json, Value};
use shared_auth_client::SharedAuthClient;
use tower::ServiceExt;

use super::*;
use crate::memebank_auth::MemebankAuthenticator;

const SERVICE_SECRET: &str = "independent-cliptown-introspection-secret-0001";
const ISSUER: &str = "https://auth.example.test";
const SUBJECT_ONE: &str = "00000000-0000-4000-8000-000000000001";
const SUBJECT_TWO: &str = "00000000-0000-4000-8000-000000000002";
const TRANSFER_PATH: &str = "/v1/integrations/memebank/transfers";

#[tokio::test]
async fn headless_memebank_flow_enforces_auth_ownership_idempotency_and_state() {
    let Ok(database_url) = env::var("CLIPTOWN_TEST_DATABASE_URL") else {
        eprintln!("CLIPTOWN_TEST_DATABASE_URL is unset; skipping Postgres headless E2E");
        return;
    };

    let database = Database::connect(database_url)
        .await
        .expect("connect to test PostgreSQL");
    database
        .execute_unprepared(include_str!("../../schema/schema.sql"))
        .await
        .expect("apply reviewed test schema");
    cleanup(&database).await;

    let (auth_base, auth_task) = spawn_shared_auth().await;
    let authenticator = MemebankAuthenticator::new(
        SharedAuthClient::new(auth_base).with_service_credential(SERVICE_SECRET),
        ISSUER.to_owned(),
    )
    .expect("valid shared-auth adapter");
    let app = routes().with_state(AppState::new(database.clone(), authenticator));

    let create_body = create_request("source-item-00000001");
    let created = call_json(
        &app,
        Method::POST,
        TRANSFER_PATH,
        "write-token",
        Some("create-operation-000001"),
        Some(create_body.clone()),
        None,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{created:?}");
    let transfer_id = created.body["transfer_id"]
        .as_str()
        .expect("created transfer id")
        .to_owned();
    assert_eq!(created.body["state"], "pending");
    assert!(!created.raw.contains(SERVICE_SECRET));
    assert!(!created.raw.contains("write-token"));

    let replay = call_json(
        &app,
        Method::POST,
        TRANSFER_PATH,
        "write-token",
        Some("create-operation-000001"),
        Some(create_body.clone()),
        None,
    )
    .await;
    assert_eq!(replay.status, StatusCode::CREATED);
    assert_eq!(replay.body["transfer_id"], transfer_id);

    let mut mismatch_body = create_body.clone();
    mismatch_body["source_item_id"] = json!("source-item-00000002");
    let mismatch = call_json(
        &app,
        Method::POST,
        TRANSFER_PATH,
        "write-token",
        Some("create-operation-000001"),
        Some(mismatch_body),
        None,
    )
    .await;
    assert_eq!(mismatch.status, StatusCode::CONFLICT);

    let listed = call_json(
        &app,
        Method::GET,
        &format!("{TRANSFER_PATH}?limit=25&direction=memebank_to_cliptown"),
        "read-token",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{listed:?}");
    assert_eq!(listed.body["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed.body["items"][0]["transfer_id"], transfer_id);

    let fetched = call_json(
        &app,
        Method::GET,
        &format!("{TRANSFER_PATH}/{transfer_id}"),
        "read-token",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.body["transfer_id"], transfer_id);

    let cross_subject = call_json(
        &app,
        Method::GET,
        &format!("{TRANSFER_PATH}/{transfer_id}"),
        "read-other-subject-token",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(cross_subject.status, StatusCode::NOT_FOUND);
    assert_eq!(cross_subject.body["error"], "not_found");

    let acknowledgement = json!({
        "contract_version": 1,
        "disposition": "acknowledged",
        "client_receipt_id": "receipt-operation-000001"
    });
    let acknowledged = call_json(
        &app,
        Method::POST,
        &format!("{TRANSFER_PATH}/{transfer_id}/ack"),
        "write-token",
        Some("acknowledge-operation-000001"),
        Some(acknowledgement.clone()),
        None,
    )
    .await;
    assert_eq!(acknowledged.status, StatusCode::OK, "{acknowledged:?}");
    assert_eq!(acknowledged.body["state"], "acknowledged");

    let acknowledged_replay = call_json(
        &app,
        Method::POST,
        &format!("{TRANSFER_PATH}/{transfer_id}/ack"),
        "write-token",
        Some("acknowledge-operation-000001"),
        Some(acknowledgement),
        None,
    )
    .await;
    assert_eq!(acknowledged_replay.status, StatusCode::OK);
    assert_eq!(acknowledged_replay.body["state"], "acknowledged");

    let second = call_json(
        &app,
        Method::POST,
        TRANSFER_PATH,
        "write-token",
        Some("create-operation-000002"),
        Some(create_request("source-item-00000003")),
        None,
    )
    .await;
    assert_eq!(second.status, StatusCode::CREATED);
    let second_id = second.body["transfer_id"]
        .as_str()
        .expect("second transfer id");
    let cancelled = call_json(
        &app,
        Method::DELETE,
        &format!("{TRANSFER_PATH}/{second_id}"),
        "delete-token",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(cancelled.status, StatusCode::NO_CONTENT);
    let cancelled_state = call_json(
        &app,
        Method::GET,
        &format!("{TRANSFER_PATH}/{second_id}"),
        "read-token",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(cancelled_state.body["state"], "cancelled");

    let wrong_scope = call_json(
        &app,
        Method::POST,
        TRANSFER_PATH,
        "read-token",
        Some("create-operation-000003"),
        Some(create_request("source-item-00000004")),
        None,
    )
    .await;
    assert_eq!(wrong_scope.status, StatusCode::FORBIDDEN);

    let stale_assurance = call_json(
        &app,
        Method::POST,
        TRANSFER_PATH,
        "stale-write-token",
        Some("create-operation-000004"),
        Some(create_request("source-item-00000005")),
        None,
    )
    .await;
    assert_eq!(stale_assurance.status, StatusCode::FORBIDDEN);

    let wrong_audience = call_json(
        &app,
        Method::GET,
        TRANSFER_PATH,
        "wrong-audience-token",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(wrong_audience.status, StatusCode::UNAUTHORIZED);

    let revoked = call_json(
        &app,
        Method::GET,
        TRANSFER_PATH,
        "revoked-token",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);

    let prohibited_header = call_json(
        &app,
        Method::GET,
        TRANSFER_PATH,
        "read-token",
        None,
        None,
        Some(("x-3fa-step-up", "must-not-be-accepted")),
    )
    .await;
    assert_eq!(prohibited_header.status, StatusCode::BAD_REQUEST);

    let outage = call_json(
        &app,
        Method::GET,
        TRANSFER_PATH,
        "outage-token",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(outage.status, StatusCode::SERVICE_UNAVAILABLE);
    for response in [
        mismatch,
        cross_subject,
        wrong_scope,
        stale_assurance,
        wrong_audience,
        revoked,
        prohibited_header,
        outage,
    ] {
        assert!(!response.raw.contains("token"));
        assert!(!response.raw.contains("ciphertext"));
        assert!(!response.raw.contains(SERVICE_SECRET));
    }

    cleanup(&database).await;
    auth_task.abort();
}

#[derive(Debug)]
struct TestResponse {
    status: StatusCode,
    body: Value,
    raw: String,
}

async fn call_json(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    idempotency_key: Option<&str>,
    body: Option<Value>,
    extra_header: Option<(&str, &str)>,
) -> TestResponse {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header("accept", "application/json");
    if let Some(key) = idempotency_key {
        builder = builder.header("idempotency-key", key);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some((name, value)) = extra_header {
        builder = builder.header(name, value);
    }
    let request = builder
        .body(Body::from(body.map(|value| value.to_string()).unwrap_or_default()))
        .expect("test request");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("router response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect response")
        .to_bytes();
    let raw = String::from_utf8(bytes.to_vec()).expect("UTF-8 response");
    let body = if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&raw).expect("JSON response")
    };
    TestResponse { status, body, raw }
}

fn create_request(source_item_id: &str) -> Value {
    let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();
    json!({
        "contract_version": 1,
        "direction": "memebank_to_cliptown",
        "source_item_id": source_item_id,
        "media_type": "image/png",
        "content_sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "content_length": 16,
        "payload": {
            "algorithm": "xchacha20poly1305-v1",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAA",
            "ciphertext": "AQIDBAUGBwgJCgsMDQ4PEA==",
            "associated_data_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_id": "device-key-00000001"
        },
        "expires_at": expires_at
    })
}

async fn spawn_shared_auth() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind shared-auth mock");
    let address = listener.local_addr().expect("shared-auth mock address");
    let app = Router::new().route("/auth/introspect", post(mock_introspect));
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("shared-auth mock server");
    });
    (format!("http://{address}"), task)
}

async fn mock_introspect(headers: HeaderMap, Json(request): Json<Value>) -> Response {
    if headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(&format!("Bearer {SERVICE_SECRET}"))
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if request["audience"] != "cliptown-api" {
        return Json(json!({"active": false})).into_response();
    }
    let token = request["token"].as_str().unwrap_or_default();
    if token == "outage-token" {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if token == "revoked-token" || token.is_empty() {
        return Json(json!({"active": false})).into_response();
    }

    let now = now_seconds();
    let (subject, scope, audience, aal, acr, auth_time) = match token {
        "read-token" => (
            SUBJECT_ONE,
            "cliptown:memebank:read",
            "cliptown-api",
            1,
            "urn:oresoftware:loa:1",
            now - 3600,
        ),
        "read-other-subject-token" => (
            SUBJECT_TWO,
            "cliptown:memebank:read",
            "cliptown-api",
            1,
            "urn:oresoftware:loa:1",
            now - 3600,
        ),
        "write-token" => (
            SUBJECT_ONE,
            "cliptown:memebank:write",
            "cliptown-api",
            2,
            "urn:oresoftware:loa:2",
            now - 30,
        ),
        "stale-write-token" => (
            SUBJECT_ONE,
            "cliptown:memebank:write",
            "cliptown-api",
            2,
            "urn:oresoftware:loa:2",
            now - 1200,
        ),
        "delete-token" => (
            SUBJECT_ONE,
            "cliptown:memebank:delete",
            "cliptown-api",
            2,
            "urn:oresoftware:loa:2",
            now - 30,
        ),
        "wrong-audience-token" => (
            SUBJECT_ONE,
            "cliptown:memebank:read",
            "other-api",
            1,
            "urn:oresoftware:loa:1",
            now - 30,
        ),
        _ => return Json(json!({"active": false})).into_response(),
    };

    Json(json!({
        "active": true,
        "sub": subject,
        "iss": ISSUER,
        "aud": audience,
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 290,
        "jti": format!("delegated-{token}"),
        "sid": "session-active-0001",
        "auth_time": auth_time,
        "roles": ["user"],
        "aal": aal,
        "amr": [if aal >= 2 { "passkey" } else { "password" }],
        "acr": acr,
        "scope": scope,
        "azp": "memebank-api",
        "parent_jti": "parent-token-0001"
    }))
    .into_response()
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}

async fn cleanup(database: &sea_orm::DatabaseConnection) {
    database
        .execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "DELETE FROM cliptown.accounts WHERE user_id IN ($1::uuid, $2::uuid)",
            [SUBJECT_ONE.into(), SUBJECT_TWO.into()],
        ))
        .await
        .expect("clean test subjects");
}
