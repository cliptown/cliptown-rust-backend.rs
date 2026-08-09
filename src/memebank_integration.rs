use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

pub const MEMEBANK_CLIENT_ID: &str = "memebank-api";
pub const CLIPTOWN_AUDIENCE: &str = "cliptown-api";
pub const READ_SCOPE: &str = "cliptown:memebank:read";
pub const WRITE_SCOPE: &str = "cliptown:memebank:write";
pub const DELETE_SCOPE: &str = "cliptown:memebank:delete";
pub const LOA2_ACR: &str = "urn:oresoftware:loa:2";

pub const MAX_CONTENT_LENGTH: u64 = 16 * 1024 * 1024;
pub const MAX_CIPHERTEXT_BASE64_LENGTH: usize = 22_369_624;
pub const MAX_CURSOR_LENGTH: usize = 512;
pub const MAX_IDEMPOTENCY_KEY_LENGTH: usize = 128;
pub const MIN_IDEMPOTENCY_KEY_LENGTH: usize = 16;
pub const DEFAULT_MAX_TRANSFER_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const DEFAULT_MAX_SENSITIVE_AUTH_AGE_SECONDS: i64 = 10 * 60;
pub const MAX_DELEGATED_TOKEN_LIFETIME_SECONDS: i64 = 5 * 60;
pub const DEFAULT_MAX_CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    MemebankToCliptown,
    CliptownToMemebank,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Pending,
    Acknowledged,
    Ignored,
    Rejected,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementDisposition {
    Acknowledged,
    Ignored,
    Rejected,
}

impl From<AcknowledgementDisposition> for TransferState {
    fn from(value: AcknowledgementDisposition) -> Self {
        match value {
            AcknowledgementDisposition::Acknowledged => Self::Acknowledged,
            AcknowledgementDisposition::Ignored => Self::Ignored,
            AcknowledgementDisposition::Rejected => Self::Rejected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherEnvelope {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
    pub associated_data_hash: Option<String>,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTransferCommand {
    pub contract_version: u16,
    pub direction: TransferDirection,
    pub source_item_id: String,
    pub media_type: String,
    pub content_sha256: String,
    pub content_length: u64,
    pub payload: CipherEnvelope,
    pub encrypted_metadata: Option<CipherEnvelope>,
    /// Parsed by the HTTP adapter from the contract's RFC3339 `expires_at`.
    pub expires_at_unix_seconds: i64,
    /// SHA-256 of the exact accepted request body, used for idempotency binding.
    pub request_sha256_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcknowledgeTransferCommand {
    pub contract_version: u16,
    pub disposition: AcknowledgementDisposition,
    pub client_receipt_id: String,
    pub request_sha256_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRecord {
    pub transfer_id: String,
    pub owner_subject: String,
    pub state: TransferState,
    pub expires_at_unix_seconds: i64,
    pub created_at_unix_seconds: i64,
    pub updated_at_unix_seconds: i64,
    pub acknowledged_at_unix_seconds: Option<i64>,
    pub client_receipt_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    List,
    Get,
    Create,
    Acknowledge,
    Cancel,
}

impl Operation {
    pub fn required_scope(self) -> &'static str {
        match self {
            Self::List | Self::Get => READ_SCOPE,
            Self::Create | Self::Acknowledge => WRITE_SCOPE,
            Self::Cancel => DELETE_SCOPE,
        }
    }

    pub fn requires_recent_loa2(self) -> bool {
        matches!(self, Self::Create | Self::Acknowledge | Self::Cancel)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegatedAuthContext<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub audience: &'a str,
    pub authorized_party: &'a str,
    pub session_id: &'a str,
    pub token_id: &'a str,
    pub parent_token_id: &'a str,
    pub scopes: &'a [&'a str],
    pub aal: u8,
    pub acr: Option<&'a str>,
    pub amr: &'a [&'a str],
    pub auth_time_unix_seconds: Option<i64>,
    pub issued_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
    pub session_active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationPolicy<'a> {
    pub expected_issuer: &'a str,
    pub max_sensitive_auth_age_seconds: i64,
    pub max_clock_skew_seconds: i64,
}

impl<'a> DelegationPolicy<'a> {
    pub fn new(expected_issuer: &'a str) -> Self {
        Self {
            expected_issuer,
            max_sensitive_auth_age_seconds: DEFAULT_MAX_SENSITIVE_AUTH_AGE_SECONDS,
            max_clock_skew_seconds: DEFAULT_MAX_CLOCK_SKEW_SECONDS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferPolicy {
    pub max_transfer_lifetime_seconds: i64,
    pub max_content_length: u64,
    pub max_ciphertext_base64_length: usize,
}

impl Default for TransferPolicy {
    fn default() -> Self {
        Self {
            max_transfer_lifetime_seconds: DEFAULT_MAX_TRANSFER_LIFETIME_SECONDS,
            max_content_length: MAX_CONTENT_LENGTH,
            max_ciphertext_base64_length: MAX_CIPHERTEXT_BASE64_LENGTH,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedSubject<'a> {
    pub subject: &'a str,
    pub session_id: &'a str,
    pub token_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyOperation {
    Create,
    Acknowledge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdempotencyRecord<'a> {
    pub subject: &'a str,
    pub operation: IdempotencyOperation,
    pub key: &'a str,
    pub request_sha256_base64: &'a str,
    pub transfer_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyDecision<'a> {
    Insert,
    Replay { transfer_id: &'a str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    InvalidConfiguration,
    InvalidClock,
    InvalidIssuer,
    InvalidDelegation,
    InvalidTokenLifetime,
    WrongAudience,
    WrongAuthorizedParty,
    MissingSession,
    InactiveSession,
    ExpiredToken,
    WrongScope,
    InvalidAssurance,
    StaleAssurance,
    UnsupportedContractVersion,
    InvalidTransfer,
    PayloadTooLarge,
    InvalidRetention,
    InvalidIdempotencyKey,
    IdempotencyConflict,
    NotFound,
    InvalidStateTransition,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "MemeBank transfer policy is invalid",
            Self::InvalidClock => "server clock is invalid",
            Self::InvalidIssuer => "delegated token issuer is invalid",
            Self::InvalidDelegation => "delegation lineage is invalid",
            Self::InvalidTokenLifetime => "delegated token lifetime is invalid",
            Self::WrongAudience => "delegated token audience is invalid",
            Self::WrongAuthorizedParty => "delegated token client is invalid",
            Self::MissingSession => "delegated token is not session-bound",
            Self::InactiveSession => "delegated token session is inactive",
            Self::ExpiredToken => "delegated token is expired",
            Self::WrongScope => "delegated token scope is invalid",
            Self::InvalidAssurance => "authentication assurance is insufficient",
            Self::StaleAssurance => "authentication assurance is stale",
            Self::UnsupportedContractVersion => "MemeBank contract version is unsupported",
            Self::InvalidTransfer => "MemeBank transfer is invalid",
            Self::PayloadTooLarge => "MemeBank transfer payload exceeds policy",
            Self::InvalidRetention => "MemeBank transfer retention exceeds policy",
            Self::InvalidIdempotencyKey => "idempotency input is invalid",
            Self::IdempotencyConflict => "idempotency key is bound to another request",
            Self::NotFound => "transfer was not found",
            Self::InvalidStateTransition => "transfer state transition is invalid",
        };
        formatter.write_str(message)
    }
}

impl Error for PolicyError {}

pub fn authorize_operation<'a>(
    now_unix_seconds: i64,
    context: DelegatedAuthContext<'a>,
    operation: Operation,
    policy: DelegationPolicy<'_>,
) -> Result<AuthorizedSubject<'a>, PolicyError> {
    validate_delegation_policy(now_unix_seconds, policy)?;
    if context.issuer != policy.expected_issuer {
        return Err(PolicyError::InvalidIssuer);
    }
    if !is_canonical_uuid(context.subject)
        || !is_portable_identifier(context.token_id, 1, 128)
        || !is_portable_identifier(context.parent_token_id, 1, 128)
        || context.token_id == context.parent_token_id
    {
        return Err(PolicyError::InvalidDelegation);
    }
    if context.audience != CLIPTOWN_AUDIIENCE {
        return Err(PolicyError::WrongAudience);
    }
    if context.authorized_party != MEMEBANK_CLIENT_ID {
        return Err(PolicyError::WrongAuthorizedParty);
    }
    if !is_portable_identifier(context.session_id, 1, 128) {
        return Err(PolicyError::MissingSession);
    }
    if !context.session_active {
        return Err(PolicyError::InactiveSession);
    }
    let latest_allowed_issue_time = now_unix_seconds
        .checked_add(policy.max_clock_skew_seconds)
        .ok_or(PolicyError::InvalidClock)?;
    let token_lifetime = context
        .expires_at_unix_seconds
        .checked_sub(context.issued_at_unix_seconds)
        .ok_or(PolicyError::InvalidClock)?;
    if context.issued_at_unix_seconds > latest_allowed_issue_time
        || !(1..=MAX_DELEGATED_TOKEN_LIFETIME_SECONDS).contains(&token_lifetime)
    {
        return Err(PolicyError::InvalidTokenLifetime);
    }
    if context.expires_at_unix_seconds <= now_unix_seconds {
        return Err(PolicyError::ExpiredToken);
    }
    if context.scopes.len() != 1 || context.scopes[0] != operation.required_scope() {
        return Err(PolicyError::WrongScope);
    }
    if context.amr.is_empty()
        || context.amr.len() > 16
        || context
            .amr
            .iter()
            .any(|method| !is_portable_identifier(method, 1, 64))
    {
        return Err(PolicyError::InvalidAssurance);
    }

    if operation.requires_recent_loa2() {
        if context.aal < 2 || context.acr != Some(LOA2_ACR) {
            return Err(PolicyError::InvalidAssurance);
        }
        let auth_time = context
            .auth_time_unix_seconds
            .ok_or(PolicyError::InvalidAssurance)?;
        let latest_allowed_auth_time = now_unix_seconds
            .checked_add(policy.max_clock_skew_seconds)
            .ok_or(PolicyError::InvalidClock)?;
        if auth_time > latest_allowed_auth_time {
            return Err(PolicyError::InvalidAssurance);
        }
        let age = now_unix_seconds
            .checked_sub(auth_time)
            .ok_or(PolicyError::InvalidClock)?;
        if age > policy.max_sensitive_auth_age_seconds {
            return Err(PolicyError::StaleAssurance);
        }
    }

    Ok(AuthorizedSubject {
        subject: context.subject,
        session_id: context.session_id,
        token_id: context.token_id,
    })
}

pub fn authorize_owned_transfer(
    authorized: AuthorizedSubject<'_>,
    transfer: &TransferRecord,
) -> Result<(), PolicyError> {
    if transfer.owner_subject != authorized.subject {
        return Err(PolicyError::NotFound);
    }
    Ok(())
}

pub fn validate_create_transfer(
    now_unix_seconds: i64,
    command: &CreateTransferCommand,
    idempotency_key: &str,
    policy: TransferPolicy,
) -> Result<(), PolicyError> {
    validate_transfer_policy(now_unix_seconds, policy)?;
    validate_idempotency_key(idempotency_key)?;
    if command.contract_version != 1 {
        return Err(PolicyError::UnsupportedContractVersion);
    }
    if !is_portable_identifier(&command.source_item_id, 1, 128)
        || !is_media_type(&command.media_type)
        || !is_sha256_base64url(&command.content_sha256)
        || !is_sha256_base64url(&command.request_sha256_base64)
    {
        return Err(PolicyError::InvalidTransfer);
    }
    if command.content_length > policy.max_content_length {
        return Err(PolicyError::PayloadTooLarge);
    }
    validate_cipher_envelope(&command.payload, policy.max_ciphertext_base64_length)?;
    if let Some(metadata) = &command.encrypted_metadata {
        validate_cipher_envelope(metadata, policy.max_ciphertext_base64_length)?;
    }

    let lifetime = command
        .expires_at_unix_seconds
        .checked_sub(now_unix_seconds)
        .ok_or(PolicyError::InvalidClock)?;
    if lifetime <= 0 || lifetime > policy.max_transfer_lifetime_seconds {
        return Err(PolicyError::InvalidRetention);
    }
    Ok(())
}

pub fn validate_acknowledgement(
    command: &AcknowledgeTransferCommand,
    idempotency_key: &str,
) -> Result<(), PolicyError> {
    validate_idempotency_key(idempotency_key)?;
    if command.contract_version != 1 {
        return Err(PolicyError::UnsupportedContractVersion);
    }
    if !is_portable_identifier(&command.client_receipt_id, 16, 128)
        || !is_sha256_base64url(&command.request_sha256_base64)
    {
        return Err(PolicyError::InvalidTransfer);
    }
    Ok(())
}

pub fn evaluate_idempotency<'a>(
    subject: &str,
    operation: IdempotencyOperation,
    key: &str,
    request_sha256_base64: &str,
    existing: Option<IdempotencyRecord<'a>>,
) -> Result<IdempotencyDecision<'a>, PolicyError> {
    if !is_canonical_uuid(subject)
        || validate_idempotency_key(key).is_err()
        || !is_sha256_base64url(request_sha256_base64)
    {
        return Err(PolicyError::InvalidIdempotencyKey);
    }
    let Some(record) = existing else {
        return Ok(IdempotencyDecision::Insert);
    };
    if record.subject != subject || record.operation != operation || record.key != key {
        return Err(PolicyError::IdempotencyConflict);
    }
    if record.request_sha256_base64 != request_sha256_base64 {
        return Err(PolicyError::IdempotencyConflict);
    }
    if !is_canonical_uuid(record.transfer_id) {
        return Err(PolicyError::IdempotencyConflict);
    }
    Ok(IdempotencyDecision::Replay {
        transfer_id: record.transfer_id,
    })
}

pub fn apply_acknowledgement(
    now_unix_seconds: i64,
    transfer: &mut TransferRecord,
    command: &AcknowledgeTransferCommand,
) -> Result<(), PolicyError> {
    if now_unix_seconds < 0 || transfer.updated_at_unix_seconds > now_unix_seconds {
        return Err(PolicyError::InvalidClock);
    }
    expire_if_needed(now_unix_seconds, transfer)?;
    let desired_state = TransferState::from(command.disposition);
    match transfer.state {
        TransferState::Pending => {
            transfer.state = desired_state;
            transfer.updated_at_unix_seconds = now_unix_seconds;
            transfer.acknowledged_at_unix_seconds = Some(now_unix_seconds);
            transfer.client_receipt_id = Some(command.client_receipt_id.clone());
            Ok(())
        }
        state if state == desired_state
            && transfer.client_receipt_id.as_deref() == Some(command.client_receipt_id.as_str()) =>
        {
            Ok(())
        }
        _ => Err(PolicyError::InvalidStateTransition),
    }
}

pub fn apply_cancel(
    now_unix_seconds: i64,
    transfer: &mut TransferRecord,
) -> Result<(), PolicyError> {
    if now_unix_seconds < 0 || transfer.updated_at_unix_seconds > now_unix_seconds {
        return Err(PolicyError::InvalidClock);
    }
    expire_if_needed(now_unix_seconds, transfer)?;
    if transfer.state == TransferState::Pending {
        transfer.state = TransferState::Cancelled;
        transfer.updated_at_unix_seconds = now_unix_seconds;
    }
    Ok(())
}

pub fn expire_if_needed(
    now_unix_seconds: i64,
    transfer: &mut TransferRecord,
) -> Result<(), PolicyError> {
    if now_unix_seconds < 0 {
        return Err(PolicyError::InvalidClock);
    }
    if transfer.state == TransferState::Pending
        && transfer.expires_at_unix_seconds <= now_unix_seconds
    {
        transfer.state = TransferState::Expired;
        transfer.updated_at_unix_seconds = now_unix_seconds;
    }
    Ok(())
}

pub fn validate_cursor(cursor: Option<&str>) -> Result<(), PolicyError> {
    if let Some(value) = cursor {
        if value.is_empty()
            || value.len() > MAX_CURSOR_LENGTH
            || value != value.trim()
            || value.chars().any(char::is_control)
        {
            return Err(PolicyError::InvalidTransfer);
        }
    }
    Ok(())
}

fn validate_delegation_policy(
    now_unix_seconds: i64,
    policy: DelegationPolicy<'_>,
) -> Result<(), PolicyError> {
    if now_unix_seconds < 0 {
        return Err(PolicyError::InvalidClock);
    }
    if policy.expected_issuer.is_empty()
        || policy.expected_issuer != policy.expected_issuer.trim()
        || !(1..=DEFAULT_MAX_SENSITIVE_AUTH_AGE_SECONDS)
            .contains(&policy.max_sensitive_auth_age_seconds)
        || !(0..=DEFAULT_MAX_CLOCK_SKEW_SECONDS).contains(&policy.max_clock_skew_seconds)
    {
        return Err(PolicyError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_transfer_policy(
    now_unix_seconds: i64,
    policy: TransferPolicy,
) -> Result<(), PolicyError> {
    if now_unix_seconds < 0 {
        return Err(PolicyError::InvalidClock);
    }
    if policy.max_transfer_lifetime_seconds <= 0
        || policy.max_transfer_lifetime_seconds > 30 * 24 * 60 * 60
        || policy.max_content_length == 0
        || policy.max_content_length > MAX_CONTENT_LENGTH
        || policy.max_ciphertext_base64_length == 0
        || policy.max_ciphertext_base64_length > MAX_CIPHERTEXT_BASE64_LENGTH
    {
        return Err(PolicyError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_cipher_envelope(
    envelope: &CipherEnvelope,
    max_ciphertext_base64_length: usize,
) -> Result<(), PolicyError> {
    if !matches!(
        envelope.algorithm.as_str(),
        "xchacha20poly1305-v1" | "aes-256-gcm-v1"
    ) || !(16..=128).contains(&envelope.nonce.len())
        || !is_base64(&envelope.nonce)
        || envelope.ciphertext.is_empty()
        || envelope.ciphertext.len() > max_ciphertext_base64_length
        || !is_base64(&envelope.ciphertext)
        || !is_portable_identifier(&envelope.key_id, 1, 128)
        || envelope
            .associated_data_hash
            .as_deref()
            .is_some_and(|value| !is_bounded_base64(value, 1, 128))
    {
        return Err(PolicyError::InvalidTransfer);
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), PolicyError> {
    if !is_portable_identifier(
        value,
        MIN_IDEMPOTENCY_KEY_LENGTH,
        MAX_IDEMPOTENCY_KEY_LENGTH,
    ) {
        return Err(PolicyError::InvalidIdempotencyKey);
    }
    Ok(())
}

fn is_media_type(value: &str) -> bool {
    if !(3..=128).contains(&value.len()) || value.matches('/').count() != 1 {
        return false;
    }
    value.split('/').all(|part| {
        !part.is_empty()
            && part.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-')
            })
    })
}

fn is_sha256_base64url(value: &str) -> bool {
    if !(43..=44).contains(&value.len()) {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'_' | b'-')
            || (byte == b'=' && index + 1 == value.len())
    })
}

fn is_bounded_base64(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len()) && is_base64(value)
}

fn is_base64(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'+' | b'/' | b'_' | b'-')
                || (byte == b'=' && index + 2 >= value.len())
        })
}

fn is_portable_identifier(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn is_canonical_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => byte == b'-',
        _ => byte.is_ascii_hexdigit(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 2_000_000_000;
    const ISSUER: &str = "https://auth.example.test";
    const SUBJECT: &str = "0198c4e8-5f4b-7d26-8c21-c4b44277b128";
    const OTHER_SUBJECT: &str = "0198c4e8-5f4b-7d26-8c21-c4b44277b129";
    const TRANSFER_ID: &str = "0198c4e8-5f4b-7d26-8c21-c4b44277b130";
    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn context<'a>(scope: &'a str) -> DelegatedAuthContext<'a> {
        DelegatedAuthContext {
            issuer: ISSUER,
            subject: SUBJECT,
            audience: CLIPTOWN_AUDIENCE,
            authorized_party: MEMEBANK_CLIENT_ID,
            session_id: "session-0001",
            token_id: "delegated-token-0001",
            parent_token_id: "subject-token-0001",
            scopes: Box::leak(Box::new([scope])),
            aal: 2,
            acr: Some(LOA2_ACR),
            amr: &["pwd", "totp"],
            auth_time_unix_seconds: Some(NOW - 30),
            issued_at_unix_seconds: NOW,
            expires_at_unix_seconds: NOW + 300,
            session_active: true,
        }
    }

    fn envelope() -> CipherEnvelope {
        CipherEnvelope {
            algorithm: "xchacha20poly1305-v1".into(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAA".into(),
            ciphertext: "opaque-ciphertext".into(),
            associated_data_hash: Some(DIGEST.into()),
            key_id: "content-key-0001".into(),
        }
    }

    fn create_command() -> CreateTransferCommand {
        CreateTransferCommand {
            contract_version: 1,
            direction: TransferDirection::MemebankToCliptown,
            source_item_id: "source-item-0001".into(),
            media_type: "image/png".into(),
            content_sha256: DIGEST.into(),
            content_length: 42,
            payload: envelope(),
            encrypted_metadata: Some(envelope()),
            expires_at_unix_seconds: NOW + 3600,
            request_sha256_base64: DIGEST.into(),
        }
    }

    fn acknowledgement() -> AcknowledgeTransferCommand {
        AcknowledgeTransferCommand {
            contract_version: 1,
            disposition: AcknowledgementDisposition::Acknowledged,
            client_receipt_id: "receipt-transfer-0001".into(),
            request_sha256_base64: DIGEST.into(),
        }
    }

    fn transfer(owner: &str) -> TransferRecord {
        TransferRecord {
            transfer_id: TRANSFER_ID.into(),
            owner_subject: owner.into(),
            state: TransferState::Pending,
            expires_at_unix_seconds: NOW + 3600,
            created_at_unix_seconds: NOW - 10,
            updated_at_unix_seconds: NOW - 10,
            acknowledged_at_unix_seconds: None,
            client_receipt_id: None,
        }
    }

    #[test]
    fn exact_delegation_tuple_and_subject_ownership_are_required() {
        let authorized = authorize_operation(
            NOW,
            context(READ_SCOPE),
            Operation::Get,
            DelegationPolicy::new(ISSUER),
        )
        .expect("valid read delegation");
        authorize_owned_transfer(authorized, &transfer(SUBJECT)).expect("owner access");
        assert_eq!(
            authorize_owned_transfer(authorized, &transfer(OTHER_SUBJECT)),
            Err(PolicyError::NotFound)
        );

        let mut wrong = context(READ_SCOPE);
        wrong.audience = "memebank-api";
        assert_eq!(
            authorize_operation(
                NOW,
                wrong,
                Operation::Get,
                DelegationPolicy::new(ISSUER)
            ),
            Err(PolicyError::WrongAudience)
        );

        let mut wrong = context(READ_SCOPE);
        wrong.authorized_party = "other-client";
        assert_eq!(
            authorize_operation(
                NOW,
                wrong,
                Operation::Get,
                DelegationPolicy::new(ISSUER)
            ),
            Err(PolicyError::WrongAuthorizedParty)
        );

        let mut wrong = context(READ_SCOPE);
        wrong.scopes = &[READ_SCOPE, WRITE_SCOPE];
        assert_eq!(
            authorize_operation(
                NOW,
                wrong,
                Operation::Get,
                DelegationPolicy::new(ISSUER)
            ),
            Err(PolicyError::WrongScope)
        );

        let mut recursive = context(READ_SCOPE);
        recursive.parent_token_id = recursive.token_id;
        assert_eq!(
            authorize_operation(
                NOW,
                recursive,
                Operation::Get,
                DelegationPolicy::new(ISSUER)
            ),
            Err(PolicyError::InvalidDelegation)
        );

        let mut overlong = context(READ_SCOPE);
        overlong.expires_at_unix_seconds = NOW + 301;
        assert_eq!(
            authorize_operation(
                NOW,
                overlong,
                Operation::Get,
                DelegationPolicy::new(ISSUER)
            ),
            Err(PolicyError::InvalidTokenLifetime)
        );

        let mut future_issued = context(READ_SCOPE);
        future_issued.issued_at_unix_seconds = NOW + 61;
        assert_eq!(
            authorize_operation(
                NOW,
                future_issued,
                Operation::Get,
                DelegationPolicy::new(ISSUER)
            ),
            Err(PolicyError::InvalidTokenLifetime)
        );

        let relaxed_policy = DelegationPolicy {
            expected_issuer: ISSUER,
            max_sensitive_auth_age_seconds:
                DEFAULT_MAX_SENSITIVE_AUTH_AGE_SECONDS + 1,
            max_clock_skew_seconds: DEFAULT_MAX_CLOCK_SKEW_SECONDS,
        };
        assert_eq!(
            authorize_operation(NOW, context(READ_SCOPE), Operation::Get, relaxed_policy),
            Err(PolicyError::InvalidConfiguration)
        );
    }

    #[test]
    fn sensitive_operations_require_recent_normalized_loa2() {
        for method in ["totp", "passkey", "email_otp", "sms_otp", "otp"] {
            let mut valid = context(WRITE_SCOPE);
            valid.amr = Box::leak(Box::new(["pwd", method]));
            authorize_operation(
                NOW,
                valid,
                Operation::Create,
                DelegationPolicy::new(ISSUER),
            )
            .expect("normalized shared-auth method is accepted");
        }

        let mut missing = context(WRITE_SCOPE);
        missing.aal = 1;
        missing.acr = Some("urn:oresoftware:loa:1");
        assert_eq!(
            authorize_operation(
                NOW,
                missing,
                Operation::Create,
                DelegationPolicy::new(ISSUER)
            ),
            Err(PolicyError::InvalidAssurance)
        );

        let mut stale = context(DELETE_SCOPE);
        stale.auth_time_unix_seconds = Some(NOW - 601);
        assert_eq!(
            authorize_operation(
                NOW,
                stale,
                Operation::Cancel,
                DelegationPolicy::new(ISSUER)
            ),
            Err(PolicyError::StaleAssurance)
        );

        let mut revoked = context(READ_SCOPE);
        revoked.session_active = false;
        assert_eq!(
            authorize_operation(
                NOW,
                revoked,
                Operation::List,
                DelegationPolicy::new(ISSUER)
            ),
            Err(PolicyError::InactiveSession)
        );
    }

    #[test]
    fn ciphertext_and_retention_are_bounded_before_storage() {
        validate_create_transfer(
            NOW,
            &create_command(),
            "create-transfer-0001",
            TransferPolicy::default(),
        )
        .expect("valid ciphertext transfer");

        let mut oversized = create_command();
        oversized.content_length = MAX_CONTENT_LENGTH + 1;
        assert_eq!(
            validate_create_transfer(
                NOW,
                &oversized,
                "create-transfer-0001",
                TransferPolicy::default()
            ),
            Err(PolicyError::PayloadTooLarge)
        );

        let mut retained = create_command();
        retained.expires_at_unix_seconds = NOW + DEFAULT_MAX_TRANSFER_LIFETIME_SECONDS + 1;
        assert_eq!(
            validate_create_transfer(
                NOW,
                &retained,
                "create-transfer-0001",
                TransferPolicy::default()
            ),
            Err(PolicyError::InvalidRetention)
        );

        let mut malformed = create_command();
        malformed.payload.algorithm = "plaintext-v1".into();
        assert_eq!(
            validate_create_transfer(
                NOW,
                &malformed,
                "create-transfer-0001",
                TransferPolicy::default()
            ),
            Err(PolicyError::InvalidTransfer)
        );
    }

    #[test]
    fn idempotency_is_subject_operation_and_digest_bound() {
        assert_eq!(
            evaluate_idempotency(
                SUBJECT,
                IdempotencyOperation::Create,
                "create-transfer-0001",
                DIGEST,
                None
            ),
            Ok(IdempotencyDecision::Insert)
        );
        let existing = IdempotencyRecord {
            subject: SUBJECT,
            operation: IdempotencyOperation::Create,
            key: "create-transfer-0001",
            request_sha256_base64: DIGEST,
            transfer_id: TRANSFER_ID,
        };
        assert_eq!(
            evaluate_idempotency(
                SUBJECT,
                IdempotencyOperation::Create,
                "create-transfer-0001",
                DIGEST,
                Some(existing)
            ),
            Ok(IdempotencyDecision::Replay {
                transfer_id: TRANSFER_ID
            })
        );
        assert_eq!(
            evaluate_idempotency(
                SUBJECT,
                IdempotencyOperation::Create,
                "create-transfer-0001",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                Some(existing)
            ),
            Err(PolicyError::IdempotencyConflict)
        );
        assert_eq!(
            evaluate_idempotency(
                OTHER_SUBJECT,
                IdempotencyOperation::Create,
                "create-transfer-0001",
                DIGEST,
                Some(existing)
            ),
            Err(PolicyError::IdempotencyConflict)
        );
    }

    #[test]
    fn acknowledgement_cancel_and_expiry_are_fail_closed_and_idempotent() {
        let command = acknowledgement();
        validate_acknowledgement(&command, "ack-transfer-000001")
            .expect("valid acknowledgement");
        let mut record = transfer(SUBJECT);
        apply_acknowledgement(NOW, &mut record, &command).expect("first acknowledgement");
        assert_eq!(record.state, TransferState::Acknowledged);
        apply_acknowledgement(NOW, &mut record, &command).expect("same acknowledgement replay");

        let mut conflicting = acknowledgement();
        conflicting.disposition = AcknowledgementDisposition::Rejected;
        assert_eq!(
            apply_acknowledgement(NOW, &mut record, &conflicting),
            Err(PolicyError::InvalidStateTransition)
        );

        apply_cancel(NOW, &mut record).expect("terminal cancel is a no-op");
        assert_eq!(record.state, TransferState::Acknowledged);

        let mut expiring = transfer(SUBJECT);
        expiring.expires_at_unix_seconds = NOW;
        apply_cancel(NOW, &mut expiring).expect("expiry is evaluated using server time");
        assert_eq!(expiring.state, TransferState::Expired);
    }

    #[test]
    fn cursor_and_identifier_inputs_are_bounded() {
        validate_cursor(None).expect("absent cursor");
        validate_cursor(Some("opaque.cursor-0001")).expect("opaque cursor");
        assert_eq!(validate_cursor(Some(" bad")), Err(PolicyError::InvalidTransfer));
        assert_eq!(
            validate_acknowledgement(&acknowledgement(), "short"),
            Err(PolicyError::InvalidIdempotencyKey)
        );
    }
}
