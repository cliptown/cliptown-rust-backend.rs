//! Vendored transport subset of the official shared-auth Rust SDK.
//!
//! Upstream: `shared-auth/shared-auth-clients` at
//! `cebdacc461fef31444cba7545a444373f6b26d3d`.
//!
//! This copy contains only the protected exact-audience introspection surface
//! consumed by ClipTown. It retains upstream validation, bounded bodies,
//! redirect refusal, loopback-only plaintext HTTP, and credential isolation.

use std::{net::IpAddr, sync::Arc, time::Duration};

use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    redirect::Policy,
    Method, RequestBuilder, Response,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

const DEFAULT_MAX_REQUEST_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("introspection service credential is required")]
    MissingServiceCredential,
    #[error("invalid shared-auth base URL")]
    InvalidBaseUrl,
    #[error("invalid {0}")]
    InvalidInput(&'static str),
    #[error("request body exceeds {limit} bytes")]
    RequestTooLarge { limit: usize },
    #[error("response body exceeds {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("request JSON encoding failed")]
    Encode {
        #[source]
        source: serde_json::Error,
    },
    #[error("response JSON decoding failed")]
    Decode {
        #[source]
        source: serde_json::Error,
    },
    #[error("transport failed")]
    Transport(#[from] reqwest::Error),
    #[error("unexpected status {0}")]
    Status(u16),
}

#[derive(Clone, Debug, Deserialize)]
pub struct Introspection {
    pub active: bool,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub iat: Option<u64>,
    #[serde(default)]
    pub nbf: Option<u64>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub jti: Option<String>,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub auth_time: Option<u64>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub provider_tenant: Option<String>,
    #[serde(default)]
    pub provider_subject: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub aal: Option<u8>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub parent_jti: Option<String>,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

impl Introspection {
    pub fn has_scope(&self, required: &str) -> bool {
        self.active
            && self.scope.as_deref().is_some_and(|scope| {
                scope
                    .split_ascii_whitespace()
                    .any(|value| value == required)
            })
    }

    pub fn has_delegation_lineage(&self) -> bool {
        self.active
            && self.jti.as_deref().is_some_and(|value| !value.is_empty())
            && self
                .parent_jti
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            && self.jti != self.parent_jti
    }
}

#[derive(Clone, Debug, Serialize)]
struct IntrospectRequest<'a> {
    token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<&'a str>,
}

#[derive(Clone)]
enum BaseUrl {
    Valid(Url),
    Invalid,
}

#[derive(Clone)]
pub struct SharedAuthClient {
    base: BaseUrl,
    http: reqwest::Client,
    service_credential: Option<Arc<str>>,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl SharedAuthClient {
    pub fn new(base: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .user_agent("shared-auth-client-rust/0.1")
            .build()
            .expect("static shared-auth HTTP client configuration is valid");
        Self::with_http(base, http)
    }

    pub fn with_http(base: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            base: match normalize_base(&base.into()) {
                Ok(base) => BaseUrl::Valid(base),
                Err(()) => BaseUrl::Invalid,
            },
            http,
            service_credential: None,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    pub fn with_service_credential(mut self, credential: impl Into<String>) -> Self {
        self.service_credential = Some(Arc::<str>::from(credential.into()));
        self
    }

    pub fn with_max_request_bytes(mut self, limit: usize) -> Self {
        self.max_request_bytes = limit;
        self
    }

    pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
        self.max_response_bytes = limit;
        self
    }

    pub async fn introspect_for_audience(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<Introspection, ClientError> {
        let audience = required_identifier(audience, "audience")?;
        let credential = self
            .service_credential
            .as_deref()
            .ok_or(ClientError::MissingServiceCredential)?;
        let credential = required_credential(credential, "service credential")?;
        let token = required_credential(token, "token")?;
        let request = self.request(Method::POST, &["auth", "introspect"])?;
        let request = self.with_json(
            request,
            &IntrospectRequest {
                token,
                audience: Some(audience),
            },
        )?;
        let request = with_bearer(request, credential, "service credential")?;
        self.send_json(request).await
    }

    fn request(&self, method: Method, segments: &[&str]) -> Result<RequestBuilder, ClientError> {
        Ok(self
            .http
            .request(method, self.endpoint(segments)?)
            .header(ACCEPT, "application/json"))
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, ClientError> {
        let mut url = match &self.base {
            BaseUrl::Valid(url) => url.clone(),
            BaseUrl::Invalid => return Err(ClientError::InvalidBaseUrl),
        };
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| ClientError::InvalidBaseUrl)?;
            path.pop_if_empty();
            for segment in segments {
                validate_path_segment(segment)?;
                path.push(segment);
            }
        }
        Ok(url)
    }

    fn with_json<B: Serialize + ?Sized>(
        &self,
        request: RequestBuilder,
        body: &B,
    ) -> Result<RequestBuilder, ClientError> {
        let encoded = serde_json::to_vec(body).map_err(|source| ClientError::Encode { source })?;
        if encoded.len() > self.max_request_bytes {
            return Err(ClientError::RequestTooLarge {
                limit: self.max_request_bytes,
            });
        }
        Ok(request
            .header(CONTENT_TYPE, "application/json")
            .body(encoded))
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> Result<T, ClientError> {
        decode_json(request.send().await?, self.max_response_bytes).await
    }
}

fn normalize_base(base: &str) -> Result<Url, ()> {
    let mut url = Url::parse(base.trim()).map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.cannot_be_a_base()
    {
        return Err(());
    }
    if url.scheme() == "http" && !is_loopback(&url) {
        return Err(());
    }

    let normalized_path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if normalized_path.is_empty() {
        "/"
    } else {
        &normalized_path
    });
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let normalized = host.trim_end_matches('.');
    normalized.eq_ignore_ascii_case("localhost")
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn with_bearer(
    request: RequestBuilder,
    credential: &str,
    field: &'static str,
) -> Result<RequestBuilder, ClientError> {
    Ok(request.bearer_auth(required_credential(credential, field)?))
}

fn required_credential<'a>(value: &'a str, field: &'static str) -> Result<&'a str, ClientError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
        || value.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(ClientError::InvalidInput(field));
    }
    Ok(value)
}

fn required_identifier<'a>(value: &'a str, field: &'static str) -> Result<&'a str, ClientError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(ClientError::InvalidInput(field));
    }
    Ok(value)
}

fn validate_path_segment(segment: &str) -> Result<(), ClientError> {
    if segment.is_empty() || segment.chars().any(char::is_control) || matches!(segment, "." | "..")
    {
        return Err(ClientError::InvalidInput("path segment"));
    }
    Ok(())
}

async fn decode_json<T: DeserializeOwned>(
    mut response: Response,
    max_response_bytes: usize,
) -> Result<T, ClientError> {
    match response.status().as_u16() {
        200..=299 => {}
        401 => return Err(ClientError::Unauthorized),
        code => return Err(ClientError::Status(code)),
    }

    let max_response_bytes_u64 = u64::try_from(max_response_bytes).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes_u64)
    {
        return Err(ClientError::ResponseTooLarge {
            limit: max_response_bytes,
        });
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let next_len =
            body.len()
                .checked_add(chunk.len())
                .ok_or(ClientError::ResponseTooLarge {
                    limit: max_response_bytes,
                })?;
        if next_len > max_response_bytes {
            return Err(ClientError::ResponseTooLarge {
                limit: max_response_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body).map_err(|source| ClientError::Decode { source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_plaintext_and_malformed_credentials_fail_closed() {
        assert!(matches!(
            SharedAuthClient::new("http://auth.example.test").base,
            BaseUrl::Invalid
        ));
        assert!(matches!(
            required_credential(" token ", "token"),
            Err(ClientError::InvalidInput("token"))
        ));
        assert!(matches!(
            required_identifier(" audience ", "audience"),
            Err(ClientError::InvalidInput("audience"))
        ));
    }

    #[test]
    fn delegation_lineage_requires_distinct_current_and_parent_ids() {
        let mut value = Introspection {
            active: true,
            sub: None,
            iss: None,
            aud: None,
            iat: None,
            nbf: None,
            exp: None,
            jti: Some("current".into()),
            sid: None,
            auth_time: None,
            project: None,
            provider: None,
            provider_tenant: None,
            provider_subject: None,
            email: None,
            email_verified: None,
            roles: Vec::new(),
            aal: None,
            amr: Vec::new(),
            acr: None,
            scope: None,
            azp: None,
            parent_jti: Some("parent".into()),
            rest: Default::default(),
        };
        assert!(value.has_delegation_lineage());
        value.parent_jti = value.jti.clone();
        assert!(!value.has_delegation_lineage());
    }
}
