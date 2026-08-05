# MemeBank production activation

Status: implementation under review in `cliptown/cliptown-rust-backend.rs#8`.
Tracking: GitHub issue `cliptown/cliptown-rust-backend.rs#7`; Linear `DEN-2259`.

## Boundary

MemeBank and ClipTown are independently deployable products. Their canonical
integration is the versioned ClipTown HTTPS API consumed through official SDKs.
It must work from a web app, desktop app, CLI, worker, or server when neither
mobile application is installed.

The backend does not:

- call 3FA or accept a 3FA bearer, proof, challenge response, or custom header;
- probe for MemeBank, ClipTown, or 3FA installation state;
- invoke a deep link, platform intent, app extension, loopback bridge, or local IPC;
- read a sibling product database or share cloud credentials;
- monitor the clipboard or fall back to clipboard transport when the API fails.

Native **Copy** remains a separate explicit foreground feature. It is not an
authentication mechanism, availability probe, or product-integration transport.

## API surface

The mounted routes follow the merged OpenAPI contract in
`cliptown/cliptown-interfaces`:

| Method | Path | Delegated scope | Assurance |
|---|---|---|---|
| `POST` | `/v1/integrations/memebank/transfers` | `cliptown:memebank:write` | recent LOA2 |
| `GET` | `/v1/integrations/memebank/transfers` | `cliptown:memebank:read` | base assurance |
| `GET` | `/v1/integrations/memebank/transfers/{id}` | `cliptown:memebank:read` | base assurance |
| `POST` | `/v1/integrations/memebank/transfers/{id}/ack` | `cliptown:memebank:write` | recent LOA2 |
| `DELETE` | `/v1/integrations/memebank/transfers/{id}` | `cliptown:memebank:delete` | recent LOA2 |

Create and acknowledgement require one `Idempotency-Key`. List cursors are opaque
and bounded. Payloads contain ciphertext and bounded routing/integrity metadata;
no bearer token, refresh token, introspection credential, OTP material,
cryptographic key, provider credential, durable private URL, signed object URL,
plaintext OCR, caption, tag, or image content is accepted as integration metadata.

## Shared-auth contract

MemeBank obtains an operation-scoped delegated token from shared-auth. ClipTown
uses protected exact-audience introspection through the official Rust transport
client and requires all of the following:

- active token;
- configured issuer;
- sole audience `cliptown-api`;
- authorized party `memebank-api`;
- active revocation-aware session identifier;
- non-empty current `jti` and distinct `parent_jti`;
- exactly one operation-appropriate `cliptown:memebank:*` scope;
- bounded not-before, expiry, and delegated lifetime;
- normalized shared-auth assurance;
- recent LOA2 for write and delete operations.

A completed factor ceremony may have used a passkey, TOTP, email OTP, SMS OTP, or
a compatible 3FA-imported factor. ClipTown consumes only normalized shared-auth
claims such as `aal`, `acr`, `amr`, and `auth_time`; it never contacts or identifies
the factor application.

The independent introspection service credential is attached only to protected
`/auth/introspect`. It is never returned to MemeBank, stored with a transfer,
forwarded to ClipTown SDK methods, or included in logs and errors.

## Official SDK provenance

`vendor/shared-auth-client` is a build-local snapshot of the official
`shared-auth/shared-auth-clients` Rust package at the immutable commit recorded in
`vendor/shared-auth-client/UPSTREAM.md`. The snapshot exists so ordinary builds
do not require a reusable cross-organization Git credential.

It is not a fork of shared-auth authorization policy. It contains only the
reviewed protected introspection transport needed by this service. Updates must:

1. name a new immutable upstream commit;
2. review the diff against the official package;
3. regenerate `Cargo.lock`;
4. rerun formatting, Clippy, all-target tests, release build, and the headless
   PostgreSQL flow;
5. preserve redirect refusal, bounded bodies, HTTPS outside loopback, and service
   credential isolation.

A reviewed registry or zed-pkg release may replace the vendored source later.

## Database lifecycle

The service **never executes `schema/schema.sql` at startup**. Database desired
state remains deployment-controlled and reviewable. The migration must create at
least:

- `cliptown.memebank_transfers`;
- `cliptown.memebank_transfer_idempotency`;
- their ownership/index/check constraints;
- subject-scoped row-level-security policies;
- public-role revocations.

`/healthz` remains independent of the database and authentication service.
`/readyz` returns unavailable until the database is reachable and both required
MemeBank tables exist.

Every transfer transaction sets the transaction-local
`request.jwt.claim.sub`. Queries additionally include an explicit `subject_id`
predicate. This double boundary means a cross-subject identifier is returned as
not found rather than revealing resource existence.

## Idempotency and concurrency

Create and acknowledgement bind the idempotency key to:

- delegated subject;
- normalized route;
- operation;
- canonical request digest;
- bounded expiry.

A PostgreSQL transaction advisory lock serializes concurrent use of one
`(subject, key)` pair. An identical replay returns the stored transfer result; a
key reused with a different request returns conflict. Expired bindings can be
replaced. Terminal transfer states cannot be reopened.

## Runtime configuration

Required:

```text
DATABASE_URL
SHARED_AUTH_BASE_URL
SHARED_AUTH_ISSUER
SHARED_AUTH_INTROSPECT_SECRET
```

Optional:

```text
CLIPTOWN_BIND_ADDRESS=0.0.0.0:3000
CLIPTOWN_DATABASE_MAX_CONNECTIONS=16
```

`SHARED_AUTH_BASE_URL` must use HTTPS outside loopback.
`SHARED_AUTH_ISSUER` must be an HTTPS URL.
`SHARED_AUTH_INTROSPECT_SECRET` must be delivered through the deployment secret
controller, never a command-line flag, image layer, repository file, ConfigMap,
log line, trace, or client bundle.

Use separate database and shared-auth credentials per environment. The API role
needs only the reviewed ClipTown schema operations; it must not receive a
MemeBank database credential or broad object-store authority.

## Validation

Source CI must run:

```sh
cargo metadata --locked --format-version 1 --no-deps
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
CLIPTOWN_TEST_DATABASE_URL=postgres://... cargo test --locked --all-targets -- --nocapture
cargo build --locked --release
```

The headless test launches a loopback protected-introspection authority and a
real PostgreSQL database. It exercises create, replay, mismatch conflict, list,
get, cross-subject not-found behavior, acknowledge, acknowledgement replay,
cancel, wrong scope, wrong audience, inactive/revoked session, stale LOA2,
prohibited 3FA/app-presence headers, and shared-auth outage. No phone, emulator,
deep-link handler, clipboard permission, or installed sibling application is
present.

## Rollout

1. Merge and release the coordinated shared-auth server and client changes.
2. Apply the reviewed database desired state in a non-production environment.
3. Provision the independent introspection credential and exact delegation policy.
4. Deploy one ClipTown API replica with the routes enabled by the reviewed build.
5. Confirm `/healthz`, `/readyz`, database constraints/RLS, and the headless API
   flow using non-production subjects.
6. Observe authorization outcome counts, request latency, idempotency conflicts,
   database errors, and shared-auth availability. Metrics must not contain
   subjects, tokens, ciphertext, source identifiers, or credentials.
7. Expand replicas gradually. Do not enable a mobile-only fallback during an API
   or authentication outage.

## Rollback

Rollback is an application deployment change, not a schema-destructive action.
Revert to the previous ClipTown API image while retaining transfer rows and
idempotency records. Remove or disable the MemeBank delegation policy if calls
must be stopped immediately. Do not drop tables, weaken RLS, widen scopes, bypass
protected introspection, accept direct 3FA artifacts, or redirect users through a
local app bridge as a rollback shortcut.

After rollback, preserve evidence needed to diagnose the failure while keeping
bearers, introspection credentials, ciphertext, and user-derived metadata out of
logs and incident documents.
