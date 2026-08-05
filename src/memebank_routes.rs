//! Production Axum and SeaORM adapter for the MemeBank transfer API.
//!
//! The routes are API-only and subject-owned. They never inspect phone
//! installation state, accept a 3FA-specific artifact, invoke a deep link or
//! local bridge, share a database credential with MemeBank, or fall back to the
//! clipboard. Authentication is reduced by `memebank_auth` before this module
//! receives an authorized subject.

use axum::{
    extract::{
        rejection::{JsonRejection, QueryRejection},
        DefaultBodyLimit, Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, FixedOffset, SecondsFormat, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    DatabaseTransaction, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, QuerySelect, Set,
    Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    entity::{
        memebank_transfer as transfer_entity, memebank_transfer_idempotency as idempotency_entity,
    },
    memebank_auth::{AuthFailure, MemebankAuthenticator},
    memebank_transfer::{
        acknowledge_state, cancel_state, evaluate_idempotency, validate_opaque_cursor,
        AcknowledgeTransferRequest, AcknowledgementDisposition, CipherAlgorithm, CipherEnvelope,
        CreateTransferRequest, IdempotencyBinding, IdempotencyDecision, IdempotentOperation,
        Operation, PolicyError, TransferDirection, TransferState,
    },
};

const TRANSFERS_PATH: &str = "/v1/integrations/memebank/transfers";
const MAX_REQUEST_BODY_BYTES: usize = 48 * 1024 * 1024;
const DEFAULT_PAGE_LIMIT: u64 = 50;
const MAX_PAGE_LIMIT: u64 = 100;
const IDEMPOTENCY_TTL_HOURS: i64 = 24;

#[derive(Clone)]
pub struct AppState {
    pub database: DatabaseConnection,
    pub authenticator: MemebankAuthenticator,
}

impl AppState {
    pub fn new(database: DatabaseConnection, authenticator: MemebankAuthenticator) -> Self {
        Self {
            database,
            authenticator,
        }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(TRANSFERS_PATH, post(create_transfer).get(list_transfers))
        .route(
            "/v1/integrations/memebank/transfers/:transfer_id",
            get(get_transfer).delete(cancel_transfer),
        )
        .route(
            "/v1/integrations/memebank/transfers/:transfer_id/ack",
            post(acknowledge_transfer),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTransferWire {
    contract_version: u16,
    direction: TransferDirection,
    source_item_id: String,
    media_type: String,
    content_sha256: String,
    content_length: u64,
    payload: CipherEnvelope,
    #[serde(default)]
    encrypted_metadata: Option<CipherEnvelope>,
    expires_at: String,
}

impl CreateTransferWire {
    fn normalize(&self) -> Result<(CreateTransferRequest, DateTime<FixedOffset>), ApiError> {
        let expires_at =
            DateTime::parse_from_rfc3339(&self.expires_at).map_err(|_| ApiError::BadRequest)?;
        Ok((
            CreateTransferRequest {
                contract_version: self.contract_version,
                direction: self.direction,
                source_item_id: self.source_item_id.clone(),
                media_type: self.media_type.clone(),
                content_sha256: self.content_sha256.clone(),
                content_length: self.content_length,
                payload: self.payload.clone(),
                encrypted_metadata: self.encrypted_metadata.clone(),
                expires_at_unix_seconds: expires_at.timestamp(),
            },
            expires_at,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcknowledgeTransferWire {
    contract_version: u16,
    disposition: AcknowledgementDisposition,
    client_receipt_id: String,
}

impl AcknowledgeTransferWire {
    fn policy_request(&self) -> AcknowledgeTransferRequest {
        AcknowledgeTransferRequest {
            contract_version: self.contract_version,
            disposition: self.disposition,
            client_receipt_id: self.client_receipt_id.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListTransfersQuery {
    cursor: Option<String>,
    limit: Option<u64>,
    direction: Option<TransferDirection>,
    state: Option<TransferState>,
}

#[derive(Debug, Serialize)]
struct TransferResponse {
    contract_version: u16,
    direction: TransferDirection,
    source_item_id: String,
    media_type: String,
    content_sha256: String,
    content_length: u64,
    payload: CipherEnvelope,
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_metadata: Option<CipherEnvelope>,
    expires_at: String,
    transfer_id: Uuid,
    state: TransferState,
    created_at: String,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    acknowledged_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct TransferPage {
    items: Vec<TransferResponse>,
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum ApiError {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    PayloadTooLarge,
    IncompatibleContract,
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::IncompatibleContract => {
                (StatusCode::UNPROCESSABLE_ENTITY, "incompatible_contract")
            }
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
        };
        (status, Json(ErrorResponse { error: code })).into_response()
    }
}

async fn create_transfer(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateTransferWire>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let authorized = state
        .authenticator
        .authorize(&headers, Operation::Write)
        .await
        .map_err(map_auth_failure)?;
    let subject_id = subject_uuid(&authorized.subject)?;
    let idempotency_key = idempotency_key(&headers)?;
    let Json(wire) = payload.map_err(map_json_rejection)?;
    let now = Utc::now().fixed_offset();
    let digest = request_digest(&wire)?;
    let (request, expires_at) = wire.normalize()?;
    request
        .validate(now.timestamp())
        .map_err(map_policy_error)?;
    evaluate_idempotency(
        now.timestamp(),
        None,
        &authorized.subject,
        idempotency_key,
        IdempotentOperation::Create,
        TRANSFERS_PATH,
        &digest,
    )
    .map_err(map_policy_error)?;

    let transaction = begin_subject_transaction(&state.database, subject_id).await?;
    ensure_account(&transaction, subject_id).await?;
    lock_idempotency(&transaction, subject_id, idempotency_key).await?;

    let existing =
        active_idempotency(&transaction, subject_id, idempotency_key, now.timestamp()).await?;
    if let Some(existing) = existing {
        let binding = binding_from_model(&existing, &authorized.subject)?;
        match evaluate_idempotency(
            now.timestamp(),
            Some(binding),
            &authorized.subject,
            idempotency_key,
            IdempotentOperation::Create,
            TRANSFERS_PATH,
            &digest,
        )
        .map_err(map_policy_error)?
        {
            IdempotencyDecision::Replay => {
                let transfer_id = existing.transfer_id.ok_or(ApiError::Unavailable)?;
                let model = find_owned_transfer(&transaction, subject_id, transfer_id)
                    .await?
                    .ok_or(ApiError::Unavailable)?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| ApiError::Unavailable)?;
                let response = transfer_response(&model, now.timestamp())?;
                return Ok((StatusCode::CREATED, Json(response)));
            }
            IdempotencyDecision::New => return Err(ApiError::Unavailable),
        }
    }

    let transfer_id = Uuid::new_v4();
    let model = transfer_active_model(transfer_id, subject_id, &wire, expires_at, now)
        .insert(&transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;

    insert_idempotency(
        &transaction,
        subject_id,
        idempotency_key,
        IdempotentOperation::Create,
        TRANSFERS_PATH,
        &digest,
        transfer_id,
        TransferState::Pending,
        now,
        expires_at,
    )
    .await?;

    transaction
        .commit()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let response = transfer_response(&model, now.timestamp())?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn list_transfers(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<ListTransfersQuery>, QueryRejection>,
) -> Result<Json<TransferPage>, ApiError> {
    let authorized = state
        .authenticator
        .authorize(&headers, Operation::Read)
        .await
        .map_err(map_auth_failure)?;
    let subject_id = subject_uuid(&authorized.subject)?;
    let Query(query) = query.map_err(|_| ApiError::BadRequest)?;
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        return Err(ApiError::BadRequest);
    }
    let now = Utc::now().fixed_offset();
    let transaction = begin_subject_transaction(&state.database, subject_id).await?;

    let mut select = transfer_entity::Entity::find()
        .filter(transfer_entity::Column::SubjectId.eq(subject_id))
        .order_by_desc(transfer_entity::Column::CreatedAt)
        .order_by_desc(transfer_entity::Column::Id)
        .limit(limit + 1);

    if let Some(direction) = query.direction {
        select = select.filter(transfer_entity::Column::Direction.eq(direction_value(direction)));
    }
    if let Some(state_filter) = query.state {
        select = select.filter(state_condition(state_filter, now));
    }
    if let Some(cursor) = query.cursor.as_deref() {
        let cursor = decode_cursor(cursor)?;
        select = select.filter(
            Condition::any()
                .add(transfer_entity::Column::CreatedAt.lt(cursor.created_at))
                .add(
                    Condition::all()
                        .add(transfer_entity::Column::CreatedAt.eq(cursor.created_at))
                        .add(transfer_entity::Column::Id.lt(cursor.id)),
                ),
        );
    }

    let mut models = select
        .all(&transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let has_more = models.len() > limit as usize;
    models.truncate(limit as usize);
    let next_cursor = if has_more {
        models.last().map(encode_cursor).transpose()?
    } else {
        None
    };
    let items = models
        .iter()
        .map(|model| transfer_response(model, now.timestamp()))
        .collect::<Result<Vec<_>, _>>()?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(Json(TransferPage { items, next_cursor }))
}

async fn get_transfer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(transfer_id): Path<String>,
) -> Result<Json<TransferResponse>, ApiError> {
    let authorized = state
        .authenticator
        .authorize(&headers, Operation::Read)
        .await
        .map_err(map_auth_failure)?;
    let subject_id = subject_uuid(&authorized.subject)?;
    let transfer_id = parse_transfer_id(&transfer_id)?;
    let now = Utc::now().fixed_offset();
    let transaction = begin_subject_transaction(&state.database, subject_id).await?;
    let model = find_owned_transfer(&transaction, subject_id, transfer_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(Json(transfer_response(&model, now.timestamp())?))
}

async fn acknowledge_transfer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(transfer_id): Path<String>,
    payload: Result<Json<AcknowledgeTransferWire>, JsonRejection>,
) -> Result<Json<TransferResponse>, ApiError> {
    let authorized = state
        .authenticator
        .authorize(&headers, Operation::Write)
        .await
        .map_err(map_auth_failure)?;
    let subject_id = subject_uuid(&authorized.subject)?;
    let transfer_id = parse_transfer_id(&transfer_id)?;
    let idempotency_key = idempotency_key(&headers)?;
    let Json(wire) = payload.map_err(map_json_rejection)?;
    let request = wire.policy_request();
    request.validate().map_err(map_policy_error)?;
    let digest = request_digest(&wire)?;
    let route = format!("{TRANSFERS_PATH}/{transfer_id}/ack");
    let now = Utc::now().fixed_offset();
    evaluate_idempotency(
        now.timestamp(),
        None,
        &authorized.subject,
        idempotency_key,
        IdempotentOperation::Acknowledge,
        &route,
        &digest,
    )
    .map_err(map_policy_error)?;

    let transaction = begin_subject_transaction(&state.database, subject_id).await?;
    lock_idempotency(&transaction, subject_id, idempotency_key).await?;
    let existing =
        active_idempotency(&transaction, subject_id, idempotency_key, now.timestamp()).await?;
    if let Some(existing) = existing {
        let binding = binding_from_model(&existing, &authorized.subject)?;
        match evaluate_idempotency(
            now.timestamp(),
            Some(binding),
            &authorized.subject,
            idempotency_key,
            IdempotentOperation::Acknowledge,
            &route,
            &digest,
        )
        .map_err(map_policy_error)?
        {
            IdempotencyDecision::Replay => {
                let replay_id = existing.transfer_id.ok_or(ApiError::Unavailable)?;
                let model = find_owned_transfer(&transaction, subject_id, replay_id)
                    .await?
                    .ok_or(ApiError::Unavailable)?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| ApiError::Unavailable)?;
                return Ok(Json(transfer_response(&model, now.timestamp())?));
            }
            IdempotencyDecision::New => return Err(ApiError::Unavailable),
        }
    }

    let model = find_owned_transfer(&transaction, subject_id, transfer_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let current = state_from_value(&model.state)?;
    let target = acknowledge_state(
        now.timestamp(),
        model.expires_at.timestamp(),
        current,
        wire.disposition,
    )
    .map_err(map_policy_error)?;
    let model = if target == current {
        model
    } else {
        let mut active = model.into_active_model();
        active.state = Set(state_value(target).to_owned());
        active.updated_at = Set(now);
        active.acknowledged_at = Set(Some(now));
        active.cancelled_at = Set(None);
        active
            .update(&transaction)
            .await
            .map_err(|_| ApiError::Unavailable)?
    };

    insert_idempotency(
        &transaction,
        subject_id,
        idempotency_key,
        IdempotentOperation::Acknowledge,
        &route,
        &digest,
        transfer_id,
        target,
        now,
        model.expires_at,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(Json(transfer_response(&model, now.timestamp())?))
}

async fn cancel_transfer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(transfer_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let authorized = state
        .authenticator
        .authorize(&headers, Operation::Delete)
        .await
        .map_err(map_auth_failure)?;
    let subject_id = subject_uuid(&authorized.subject)?;
    let transfer_id = parse_transfer_id(&transfer_id)?;
    let now = Utc::now().fixed_offset();
    let transaction = begin_subject_transaction(&state.database, subject_id).await?;
    let model = find_owned_transfer(&transaction, subject_id, transfer_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let current = state_from_value(&model.state)?;
    let target = cancel_state(now.timestamp(), model.expires_at.timestamp(), current);
    if target != current {
        let mut active = model.into_active_model();
        active.state = Set(state_value(target).to_owned());
        active.updated_at = Set(now);
        active.acknowledged_at = Set(None);
        active.cancelled_at = Set((target == TransferState::Cancelled).then_some(now));
        active
            .update(&transaction)
            .await
            .map_err(|_| ApiError::Unavailable)?;
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn begin_subject_transaction(
    database: &DatabaseConnection,
    subject_id: Uuid,
) -> Result<DatabaseTransaction, ApiError> {
    let transaction = database.begin().await.map_err(|_| ApiError::Unavailable)?;
    transaction
        .execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT set_config('request.jwt.claim.sub', $1, true)",
            [subject_id.to_string().into()],
        ))
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(transaction)
}

async fn ensure_account(
    transaction: &DatabaseTransaction,
    subject_id: Uuid,
) -> Result<(), ApiError> {
    transaction
        .execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "INSERT INTO cliptown.accounts (user_id) VALUES ($1::uuid) ON CONFLICT (user_id) DO NOTHING",
            [subject_id.to_string().into()],
        ))
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(())
}

async fn lock_idempotency(
    transaction: &DatabaseTransaction,
    subject_id: Uuid,
    key: &str,
) -> Result<(), ApiError> {
    let lock_key = format!("{subject_id}:{key}");
    transaction
        .execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            [lock_key.into()],
        ))
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(())
}

async fn active_idempotency(
    transaction: &DatabaseTransaction,
    subject_id: Uuid,
    key: &str,
    now_unix_seconds: i64,
) -> Result<Option<idempotency_entity::Model>, ApiError> {
    let existing = idempotency_entity::Entity::find()
        .filter(idempotency_entity::Column::SubjectId.eq(subject_id))
        .filter(idempotency_entity::Column::IdempotencyKey.eq(key))
        .one(transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.expires_at.timestamp() > now_unix_seconds {
        return Ok(Some(existing));
    }
    idempotency_entity::Entity::delete_by_id(existing.id)
        .exec(transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(None)
}

fn binding_from_model<'a>(
    model: &'a idempotency_entity::Model,
    subject: &'a str,
) -> Result<IdempotencyBinding<'a>, ApiError> {
    let operation = match model.operation.as_str() {
        "create" => IdempotentOperation::Create,
        "acknowledge" => IdempotentOperation::Acknowledge,
        _ => return Err(ApiError::Unavailable),
    };
    Ok(IdempotencyBinding {
        subject,
        key: &model.idempotency_key,
        operation,
        normalized_route: &model.normalized_route,
        request_digest: &model.request_digest_base64url,
        expires_at_unix_seconds: model.expires_at.timestamp(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn insert_idempotency(
    transaction: &DatabaseTransaction,
    subject_id: Uuid,
    key: &str,
    operation: IdempotentOperation,
    route: &str,
    digest: &str,
    transfer_id: Uuid,
    response_state: TransferState,
    now: DateTime<FixedOffset>,
    transfer_expires_at: DateTime<FixedOffset>,
) -> Result<(), ApiError> {
    let policy_expiry = now + Duration::hours(IDEMPOTENCY_TTL_HOURS);
    let expires_at = transfer_expires_at.min(policy_expiry);
    idempotency_entity::ActiveModel {
        id: Set(Uuid::new_v4()),
        subject_id: Set(subject_id),
        idempotency_key: Set(key.to_owned()),
        operation: Set(match operation {
            IdempotentOperation::Create => "create",
            IdempotentOperation::Acknowledge => "acknowledge",
        }
        .to_owned()),
        normalized_route: Set(route.to_owned()),
        request_digest_base64url: Set(digest.to_owned()),
        transfer_id: Set(Some(transfer_id)),
        response_state: Set(Some(state_value(response_state).to_owned())),
        created_at: Set(now),
        expires_at: Set(expires_at),
    }
    .insert(transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    Ok(())
}

async fn find_owned_transfer<C>(
    connection: &C,
    subject_id: Uuid,
    transfer_id: Uuid,
) -> Result<Option<transfer_entity::Model>, ApiError>
where
    C: ConnectionTrait,
{
    transfer_entity::Entity::find_by_id(transfer_id)
        .filter(transfer_entity::Column::SubjectId.eq(subject_id))
        .one(connection)
        .await
        .map_err(|_| ApiError::Unavailable)
}

fn transfer_active_model(
    transfer_id: Uuid,
    subject_id: Uuid,
    wire: &CreateTransferWire,
    expires_at: DateTime<FixedOffset>,
    now: DateTime<FixedOffset>,
) -> transfer_entity::ActiveModel {
    let metadata = wire.encrypted_metadata.as_ref();
    transfer_entity::ActiveModel {
        id: Set(transfer_id),
        subject_id: Set(subject_id),
        contract_version: Set(i16::try_from(wire.contract_version).unwrap_or(1)),
        direction: Set(direction_value(wire.direction).to_owned()),
        state: Set(state_value(TransferState::Pending).to_owned()),
        source_item_id: Set(wire.source_item_id.clone()),
        media_type: Set(wire.media_type.clone()),
        content_sha256_base64url: Set(wire.content_sha256.clone()),
        content_length: Set(i64::try_from(wire.content_length).unwrap_or(i64::MAX)),
        payload_algorithm: Set(algorithm_value(wire.payload.algorithm).to_owned()),
        payload_nonce_base64: Set(wire.payload.nonce.clone()),
        payload_ciphertext_base64: Set(wire.payload.ciphertext.clone()),
        payload_associated_data_hash_base64: Set(wire.payload.associated_data_hash.clone()),
        payload_key_id: Set(wire.payload.key_id.clone()),
        metadata_algorithm: Set(metadata.map(|value| algorithm_value(value.algorithm).to_owned())),
        metadata_nonce_base64: Set(metadata.map(|value| value.nonce.clone())),
        metadata_ciphertext_base64: Set(metadata.map(|value| value.ciphertext.clone())),
        metadata_associated_data_hash_base64: Set(
            metadata.and_then(|value| value.associated_data_hash.clone())
        ),
        metadata_key_id: Set(metadata.map(|value| value.key_id.clone())),
        expires_at: Set(expires_at),
        created_at: Set(now),
        updated_at: Set(now),
        acknowledged_at: Set(None),
        cancelled_at: Set(None),
    }
}

fn transfer_response(
    model: &transfer_entity::Model,
    now_unix_seconds: i64,
) -> Result<TransferResponse, ApiError> {
    let direction = direction_from_value(&model.direction)?;
    let stored_state = state_from_value(&model.state)?;
    let state = if stored_state == TransferState::Pending
        && model.expires_at.timestamp() <= now_unix_seconds
    {
        TransferState::Expired
    } else {
        stored_state
    };
    let payload = CipherEnvelope {
        algorithm: algorithm_from_value(&model.payload_algorithm)?,
        nonce: model.payload_nonce_base64.clone(),
        ciphertext: model.payload_ciphertext_base64.clone(),
        associated_data_hash: model.payload_associated_data_hash_base64.clone(),
        key_id: model.payload_key_id.clone(),
    };
    let encrypted_metadata = match (
        model.metadata_algorithm.as_deref(),
        model.metadata_nonce_base64.as_ref(),
        model.metadata_ciphertext_base64.as_ref(),
        model.metadata_associated_data_hash_base64.as_ref(),
        model.metadata_key_id.as_ref(),
    ) {
        (None, None, None, None, None) => None,
        (Some(algorithm), Some(nonce), Some(ciphertext), hash, Some(key_id)) => {
            Some(CipherEnvelope {
                algorithm: algorithm_from_value(algorithm)?,
                nonce: nonce.clone(),
                ciphertext: ciphertext.clone(),
                associated_data_hash: hash.cloned(),
                key_id: key_id.clone(),
            })
        }
        _ => return Err(ApiError::Unavailable),
    };

    Ok(TransferResponse {
        contract_version: u16::try_from(model.contract_version)
            .map_err(|_| ApiError::Unavailable)?,
        direction,
        source_item_id: model.source_item_id.clone(),
        media_type: model.media_type.clone(),
        content_sha256: model.content_sha256_base64url.clone(),
        content_length: u64::try_from(model.content_length).map_err(|_| ApiError::Unavailable)?,
        payload,
        encrypted_metadata,
        expires_at: timestamp(&model.expires_at),
        transfer_id: model.id,
        state,
        created_at: timestamp(&model.created_at),
        updated_at: timestamp(&model.updated_at),
        acknowledged_at: model.acknowledged_at.as_ref().map(timestamp),
    })
}

fn state_condition(state: TransferState, now: DateTime<FixedOffset>) -> Condition {
    match state {
        TransferState::Pending => Condition::all()
            .add(transfer_entity::Column::State.eq("pending"))
            .add(transfer_entity::Column::ExpiresAt.gt(now)),
        TransferState::Expired => Condition::any()
            .add(transfer_entity::Column::State.eq("expired"))
            .add(
                Condition::all()
                    .add(transfer_entity::Column::State.eq("pending"))
                    .add(transfer_entity::Column::ExpiresAt.lte(now)),
            ),
        other => Condition::all().add(transfer_entity::Column::State.eq(state_value(other))),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    created_at_micros: i64,
    id: Uuid,
}

struct DecodedCursor {
    created_at: DateTime<FixedOffset>,
    id: Uuid,
}

fn encode_cursor(model: &transfer_entity::Model) -> Result<String, ApiError> {
    let payload = CursorPayload {
        created_at_micros: model.created_at.timestamp_micros(),
        id: model.id,
    };
    serde_json::to_vec(&payload)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| ApiError::Unavailable)
}

fn decode_cursor(value: &str) -> Result<DecodedCursor, ApiError> {
    validate_opaque_cursor(value).map_err(map_policy_error)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::BadRequest)?;
    if bytes.len() > 256 {
        return Err(ApiError::BadRequest);
    }
    let payload: CursorPayload =
        serde_json::from_slice(&bytes).map_err(|_| ApiError::BadRequest)?;
    let created_at = DateTime::<Utc>::from_timestamp_micros(payload.created_at_micros)
        .ok_or(ApiError::BadRequest)?
        .fixed_offset();
    Ok(DecodedCursor {
        created_at,
        id: payload.id,
    })
}

fn request_digest<T: Serialize>(value: &T) -> Result<String, ApiError> {
    let encoded = serde_json::to_vec(value).map_err(|_| ApiError::BadRequest)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(encoded)))
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let value = values.next().ok_or(ApiError::BadRequest)?;
    if values.next().is_some() {
        return Err(ApiError::BadRequest);
    }
    value.to_str().map_err(|_| ApiError::BadRequest)
}

fn subject_uuid(subject: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(subject).map_err(|_| ApiError::Unauthorized)
}

fn parse_transfer_id(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| ApiError::BadRequest)
}

fn map_json_rejection(error: JsonRejection) -> ApiError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::PayloadTooLarge
    } else {
        ApiError::BadRequest
    }
}

fn map_auth_failure(error: AuthFailure) -> ApiError {
    match error {
        AuthFailure::BadRequest => ApiError::BadRequest,
        AuthFailure::Unauthorized => ApiError::Unauthorized,
        AuthFailure::Forbidden => ApiError::Forbidden,
        AuthFailure::Unavailable => ApiError::Unavailable,
    }
}

fn map_policy_error(error: PolicyError) -> ApiError {
    match error {
        PolicyError::IncompatibleContract => ApiError::IncompatibleContract,
        PolicyError::InvalidTransfer
        | PolicyError::InvalidCipherEnvelope
        | PolicyError::InvalidRetention
        | PolicyError::InvalidAcknowledgement
        | PolicyError::InvalidIdempotency
        | PolicyError::InvalidCursor => ApiError::BadRequest,
        PolicyError::InvalidTransition
        | PolicyError::TransferExpired
        | PolicyError::IdempotencyConflict => ApiError::Conflict,
        PolicyError::NotFound => ApiError::NotFound,
        PolicyError::WrongScope | PolicyError::AssuranceRequired => ApiError::Forbidden,
        PolicyError::InvalidPolicy
        | PolicyError::WrongIssuer
        | PolicyError::WrongAudience
        | PolicyError::WrongAuthorizedParty
        | PolicyError::InvalidDelegation
        | PolicyError::TokenNotYetValid
        | PolicyError::TokenExpired
        | PolicyError::TokenLifetimeExceeded => ApiError::Unauthorized,
    }
}

fn direction_value(value: TransferDirection) -> &'static str {
    match value {
        TransferDirection::MemebankToCliptown => "memebank_to_cliptown",
        TransferDirection::CliptownToMemebank => "cliptown_to_memebank",
    }
}

fn direction_from_value(value: &str) -> Result<TransferDirection, ApiError> {
    match value {
        "memebank_to_cliptown" => Ok(TransferDirection::MemebankToCliptown),
        "cliptown_to_memebank" => Ok(TransferDirection::CliptownToMemebank),
        _ => Err(ApiError::Unavailable),
    }
}

fn state_value(value: TransferState) -> &'static str {
    match value {
        TransferState::Pending => "pending",
        TransferState::Acknowledged => "acknowledged",
        TransferState::Ignored => "ignored",
        TransferState::Rejected => "rejected",
        TransferState::Expired => "expired",
        TransferState::Cancelled => "cancelled",
    }
}

fn state_from_value(value: &str) -> Result<TransferState, ApiError> {
    match value {
        "pending" => Ok(TransferState::Pending),
        "acknowledged" => Ok(TransferState::Acknowledged),
        "ignored" => Ok(TransferState::Ignored),
        "rejected" => Ok(TransferState::Rejected),
        "expired" => Ok(TransferState::Expired),
        "cancelled" => Ok(TransferState::Cancelled),
        _ => Err(ApiError::Unavailable),
    }
}

fn algorithm_value(value: CipherAlgorithm) -> &'static str {
    match value {
        CipherAlgorithm::Xchacha20poly1305V1 => "xchacha20poly1305-v1",
        CipherAlgorithm::Aes256GcmV1 => "aes-256-gcm-v1",
    }
}

fn algorithm_from_value(value: &str) -> Result<CipherAlgorithm, ApiError> {
    match value {
        "xchacha20poly1305-v1" => Ok(CipherAlgorithm::Xchacha20poly1305V1),
        "aes-256-gcm-v1" => Ok(CipherAlgorithm::Aes256GcmV1),
        _ => Err(ApiError::Unavailable),
    }
}

fn timestamp(value: &DateTime<FixedOffset>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_is_opaque_bounded_and_round_trips() {
        let now = Utc::now().fixed_offset();
        let model = transfer_entity::Model {
            id: Uuid::new_v4(),
            subject_id: Uuid::new_v4(),
            contract_version: 1,
            direction: "memebank_to_cliptown".into(),
            state: "pending".into(),
            source_item_id: "source-0000000001".into(),
            media_type: "image/png".into(),
            content_sha256_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            content_length: 1,
            payload_algorithm: "xchacha20poly1305-v1".into(),
            payload_nonce_base64: "AAAAAAAAAAAAAAAA".into(),
            payload_ciphertext_base64: "AQ==".into(),
            payload_associated_data_hash_base64: None,
            payload_key_id: "key-000000000001".into(),
            metadata_algorithm: None,
            metadata_nonce_base64: None,
            metadata_ciphertext_base64: None,
            metadata_associated_data_hash_base64: None,
            metadata_key_id: None,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            acknowledged_at: None,
            cancelled_at: None,
        };
        let encoded = encode_cursor(&model).unwrap();
        assert!(!encoded.contains(model.id.to_string().as_str()));
        let decoded = decode_cursor(&encoded).unwrap();
        assert_eq!(decoded.id, model.id);
        assert_eq!(
            decoded.created_at.timestamp_micros(),
            now.timestamp_micros()
        );
    }

    #[test]
    fn canonical_request_digest_is_stable_and_sensitive_to_mutation() {
        let request = AcknowledgeTransferWire {
            contract_version: 1,
            disposition: AcknowledgementDisposition::Acknowledged,
            client_receipt_id: "receipt-0000000001".into(),
        };
        let digest = request_digest(&request).unwrap();
        assert_eq!(digest.len(), 43);
        assert_eq!(digest, request_digest(&request).unwrap());

        let mut changed = request.clone();
        changed.disposition = AcknowledgementDisposition::Rejected;
        assert_ne!(digest, request_digest(&changed).unwrap());
    }

    #[test]
    fn transfer_response_never_contains_cancel_timestamp_or_internal_subject() {
        let now = Utc::now().fixed_offset();
        let model = transfer_entity::Model {
            id: Uuid::new_v4(),
            subject_id: Uuid::new_v4(),
            contract_version: 1,
            direction: "memebank_to_cliptown".into(),
            state: "cancelled".into(),
            source_item_id: "source-0000000001".into(),
            media_type: "image/png".into(),
            content_sha256_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            content_length: 1,
            payload_algorithm: "xchacha20poly1305-v1".into(),
            payload_nonce_base64: "AAAAAAAAAAAAAAAA".into(),
            payload_ciphertext_base64: "AQ==".into(),
            payload_associated_data_hash_base64: None,
            payload_key_id: "key-000000000001".into(),
            metadata_algorithm: None,
            metadata_nonce_base64: None,
            metadata_ciphertext_base64: None,
            metadata_associated_data_hash_base64: None,
            metadata_key_id: None,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            acknowledged_at: None,
            cancelled_at: Some(now),
        };
        let encoded =
            serde_json::to_string(&transfer_response(&model, now.timestamp()).unwrap()).unwrap();
        assert!(!encoded.contains("subject"));
        assert!(!encoded.contains("cancelled_at"));
    }
}
