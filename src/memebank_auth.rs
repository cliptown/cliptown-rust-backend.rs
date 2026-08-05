//! Protected shared-auth adapter for the MemeBank transfer API.
//!
//! This module is the only place where the ClipTown backend accepts an incoming
//! delegated bearer. It reduces the bearer to the existing fail-closed
//! `DelegatedAuthorization` model through the official shared-auth Rust SDK.
//! There is deliberately no 3FA-specific proof, mobile-app discovery, deep-link,
//! clipboard, local-IPC, or loopback-bridge input.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{header::AUTHORIZATION, HeaderMap};
use shared_auth_client::{ClientError, Introspection, SharedAuthClient};

use crate::memebank_transfer::{
    authorize_delegated_operation, AuthorizedSubject, DelegatedAuthorization, DelegatedTokenPolicy,
    Operation, CLIPTOWN_API_AUDIENCE,
};

const MAX_BEARER_BYTES: usize = 16 * 1024;
const PROHIBITED_INTEGRATION_HEADERS: [&str; 7] = [
    "x-3fa-step-up",
    "x-3fa-proof",
    "x-3fa-token",
    "x-app-installed",
    "x-cliptown-app-present",
    "x-memebank-app-present",
    "x-local-bridge",
];

#[derive(Clone)]
pub struct MemebankAuthenticator {
    client: SharedAuthClient,
    issuer: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    BadRequest,
    Unauthorized,
    Forbidden,
    Unavailable,
}

impl MemebankAuthenticator {
    pub fn new(client: SharedAuthClient, issuer: String) -> Result<Self, AuthFailure> {
        if !valid_issuer(&issuer) {
            return Err(AuthFailure::Unavailable);
        }
        Ok(Self { client, issuer })
    }

    pub async fn authorize(
        &self,
        headers: &HeaderMap,
        operation: Operation,
    ) -> Result<AuthorizedSubject, AuthFailure> {
        validate_integration_headers(headers)?;
        let bearer = delegated_bearer(headers)?;
        let introspection = self
            .client
            .introspect_for_audience(bearer, CLIPTOWN_API_AUDIENCE)
            .await
            .map_err(map_client_error)?;
        let claims = introspection_to_authorization(introspection)?;
        authorize_delegated_operation(
            now_unix_seconds()?,
            &claims,
            operation,
            DelegatedTokenPolicy::new(&self.issuer),
        )
        .map_err(|error| match error {
            crate::memebank_transfer::PolicyError::WrongScope
            | crate::memebank_transfer::PolicyError::AssuranceRequired => AuthFailure::Forbidden,
            _ => AuthFailure::Unauthorized,
        })
    }
}

fn validate_integration_headers(headers: &HeaderMap) -> Result<(), AuthFailure> {
    if PROHIBITED_INTEGRATION_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        return Err(AuthFailure::BadRequest);
    }
    Ok(())
}

fn delegated_bearer(headers: &HeaderMap) -> Result<&str, AuthFailure> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(AuthFailure::Unauthorized)?;
    if values.next().is_some() {
        return Err(AuthFailure::Unauthorized);
    }
    let value = value.to_str().map_err(|_| AuthFailure::Unauthorized)?;
    let (scheme, token) = value.split_once(' ').ok_or(AuthFailure::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > MAX_BEARER_BYTES
        || token.trim() != token
        || token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(AuthFailure::Unauthorized);
    }
    Ok(token)
}

fn introspection_to_authorization(
    introspection: Introspection,
) -> Result<DelegatedAuthorization, AuthFailure> {
    if !introspection.active || !introspection.has_delegation_lineage() {
        return Err(AuthFailure::Unauthorized);
    }

    let issuer = required(introspection.iss)?;
    let audience = required(introspection.aud)?;
    let authorized_party = required(introspection.azp)?;
    let subject = required(introspection.sub)?;
    let session_id = required(introspection.sid)?;
    let token_id = required(introspection.jti)?;
    let parent_token_id = required(introspection.parent_jti)?;
    let not_before_unix_seconds = required_time(introspection.nbf)?;
    let expires_at_unix_seconds = required_time(introspection.exp)?;
    let authenticated_at_unix_seconds = introspection
        .auth_time
        .map(i64::try_from)
        .transpose()
        .map_err(|_| AuthFailure::Unauthorized)?;
    let scopes = introspection
        .scope
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    Ok(DelegatedAuthorization {
        issuer,
        audiences: vec![audience],
        authorized_party,
        subject,
        session_id,
        token_id,
        parent_token_id,
        scopes,
        assurance_level: introspection.aal.unwrap_or(0),
        assurance_context: introspection.acr.unwrap_or_default(),
        authentication_methods: introspection.amr,
        authenticated_at_unix_seconds,
        not_before_unix_seconds,
        expires_at_unix_seconds,
        session_active: true,
        delegated: true,
    })
}

fn required(value: Option<String>) -> Result<String, AuthFailure> {
    value
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(AuthFailure::Unauthorized)
}

fn required_time(value: Option<u64>) -> Result<i64, AuthFailure> {
    i64::try_from(value.ok_or(AuthFailure::Unauthorized)?).map_err(|_| AuthFailure::Unauthorized)
}

fn map_client_error(error: ClientError) -> AuthFailure {
    match error {
        ClientError::Unauthorized | ClientError::InvalidInput(_) => AuthFailure::Unauthorized,
        ClientError::MissingServiceCredential
        | ClientError::InvalidBaseUrl
        | ClientError::RequestTooLarge { .. }
        | ClientError::ResponseTooLarge { .. }
        | ClientError::Encode { .. }
        | ClientError::Decode { .. }
        | ClientError::Transport(_)
        | ClientError::Status(_) => AuthFailure::Unavailable,
    }
}

fn valid_issuer(value: &str) -> bool {
    value.starts_with("https://")
        && value.len() <= 512
        && value.trim() == value
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

fn now_unix_seconds() -> Result<i64, AuthFailure> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthFailure::Unavailable)?;
    i64::try_from(duration.as_secs()).map_err(|_| AuthFailure::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memebank_transfer::{MEMEBANK_READ_SCOPE, MEMEBANK_WRITE_SCOPE};

    const NOW: u64 = 1_800_000_000;

    fn introspection(scope: &str) -> Introspection {
        Introspection {
            active: true,
            sub: Some("00000000-0000-4000-8000-000000000001".into()),
            iss: Some("https://auth.example.test".into()),
            aud: Some(CLIPTOWN_API_AUDIENCE.into()),
            iat: Some(NOW - 10),
            nbf: Some(NOW - 10),
            exp: Some(NOW + 290),
            jti: Some("delegated-token-0001".into()),
            sid: Some("session-active-0001".into()),
            auth_time: Some(NOW - 30),
            project: None,
            provider: None,
            provider_tenant: None,
            provider_subject: None,
            email: None,
            email_verified: None,
            roles: vec!["user".into()],
            aal: Some(2),
            amr: vec!["passkey".into()],
            acr: Some("urn:oresoftware:loa:2".into()),
            scope: Some(scope.into()),
            azp: Some("memebank-api".into()),
            parent_jti: Some("parent-token-0001".into()),
            rest: Default::default(),
        }
    }

    #[test]
    fn exact_delegation_lineage_is_reduced_without_factor_app_state() {
        let claims = introspection_to_authorization(introspection(MEMEBANK_WRITE_SCOPE))
            .expect("valid delegated introspection");
        assert_eq!(claims.token_id, "delegated-token-0001");
        assert_eq!(claims.parent_token_id, "parent-token-0001");
        assert_eq!(claims.scopes, vec![MEMEBANK_WRITE_SCOPE]);
        assert_eq!(claims.authentication_methods, vec!["passkey"]);
    }

    #[test]
    fn inactive_or_incomplete_lineage_fails_closed() {
        let mut value = introspection(MEMEBANK_READ_SCOPE);
        value.active = false;
        assert_eq!(
            introspection_to_authorization(value),
            Err(AuthFailure::Unauthorized)
        );

        let mut value = introspection(MEMEBANK_READ_SCOPE);
        value.jti = None;
        assert_eq!(
            introspection_to_authorization(value),
            Err(AuthFailure::Unauthorized)
        );

        let mut value = introspection(MEMEBANK_READ_SCOPE);
        value.parent_jti = value.jti.clone();
        assert_eq!(
            introspection_to_authorization(value),
            Err(AuthFailure::Unauthorized)
        );
    }

    #[test]
    fn direct_factor_and_app_presence_headers_are_rejected() {
        for name in PROHIBITED_INTEGRATION_HEADERS {
            let mut headers = HeaderMap::new();
            headers.insert(name, "present".parse().unwrap());
            assert_eq!(
                validate_integration_headers(&headers),
                Err(AuthFailure::BadRequest)
            );
        }
    }

    #[test]
    fn bearer_must_be_single_compact_and_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer delegated.jwt.value".parse().unwrap());
        assert_eq!(delegated_bearer(&headers).unwrap(), "delegated.jwt.value");

        headers.append(AUTHORIZATION, "Bearer second.token".parse().unwrap());
        assert_eq!(delegated_bearer(&headers), Err(AuthFailure::Unauthorized));

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer token with spaces".parse().unwrap());
        assert_eq!(delegated_bearer(&headers), Err(AuthFailure::Unauthorized));
    }
}
