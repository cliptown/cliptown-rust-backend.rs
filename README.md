# ClipTown Rust backend

Rust API service for encrypted ClipTown synchronization. The service exposes service information, liveness, database-aware readiness, and the authenticated subject-owned MemeBank transfer API. DEN-42/DEN-44/DEN-45/DEN-47/DEN-51 add reviewed account-security, Signal Protocol relay, isolated application-vault, PostgreSQL/Supabase, and encrypted Cloudflare R2 foundations without enabling unauthenticated placeholder routes.

## Security model

- Flutter encrypts clipboard text, metadata, images, and files before upload.
- PostgreSQL/Supabase and R2 store opaque ciphertext plus bounded routing/integrity metadata.
- Signal Protocol sessions enroll devices and deliver small wrapped account/clip/object/application-vault keys; large objects use chunked AEAD with random content keys.
- 3FA authenticator records use a separate opaque application-vault trust domain and never become clipboard history, search, RAG, preview, paste, pin, notification, export, or ordinary retention data.
- Application-vault logical clocks must fit PostgreSQL `BIGINT`, and backend policy may require a shorter proof lifetime than the five-minute wire-contract maximum.
- Application-vault record heads are database-bound to every identity and ordering field of their referenced mutation; copying only a server sequence cannot redirect a head to another opaque record.
- A 3FA step-up proof is single-use and bound to one subject, initiating device, challenge, action, method, route, target, body hash, issuer key, and expiration. Consumption uses database transaction time, never a caller-supplied clock. It is not a primary login or reusable bearer token.
- Backup email and phone OTP are recovery/step-up channels only.
- Biometrics remain in platform authenticators; a six-digit PIN is local-only and never an encryption key or server credential.
- See [`docs/security-storage.md`](docs/security-storage.md) and [`docs/app-vault-step-up.md`](docs/app-vault-step-up.md).

## MemeBank delegated transfer boundary

DEN-1578 defines the backend enforcement and PostgreSQL/RLS desired state for the versioned MemeBank transfer API. DEN-2259 connects that reviewed policy to authenticated Axum routes, protected shared-auth introspection, SeaORM/PostgreSQL persistence, and a headless database-backed flow.

The API accepts only normalized output from protected shared-auth verification and pins the issuer, sole `cliptown-api` audience, `memebank-api` authorized party, active session, distinct current/parent delegation lineage, and exactly one `cliptown:memebank:*` operation scope. Write and delete require recent LOA2. A factor ceremony reaches ClipTown only as normalized shared-auth assurance; the routes reject direct 3FA artifacts and app-presence signals.

The transfer queue stores ciphertext plus bounded routing and integrity metadata. Create and acknowledgement idempotency are subject, route, operation, and digest bound; concurrent use of one key is serialized with a PostgreSQL transaction advisory lock; cross-subject access is indistinguishable from absence; terminal records cannot be reopened. The schema enables RLS for both transfer tables and revokes public access.

MemeBank and ClipTown interoperate through the versioned HTTPS API and official SDKs. The route tree has no dependency on mutually installed phone apps, deep links, local IPC, a loopback bridge, shared databases, shared cloud credentials, or clipboard monitoring. Native **Copy** remains a separate explicit foreground feature and is not a fallback transport.

See [`docs/memebank-production-activation.md`](docs/memebank-production-activation.md) for routes, configuration, shared-auth and SDK provenance, migration ownership, validation, rollout, and rollback.

## Run

The service fails closed unless its database and protected shared-auth settings are configured:

```sh
DATABASE_URL=postgres://... \
SHARED_AUTH_BASE_URL=https://gateway.example/shared-auth \
SHARED_AUTH_ISSUER=https://auth.example \
SHARED_AUTH_INTROSPECT_SECRET='from-secret-controller' \
CLIPTOWN_BIND_ADDRESS=127.0.0.1:3000 \
cargo run --locked
```

`CLIPTOWN_DATABASE_MAX_CONNECTIONS` defaults to `16` and must be from 1 through 128.

The service does not run database migrations at startup. PostgreSQL desired state belongs in [`schema/schema.sql`](schema/schema.sql) and must be reviewed through the declarative migration workflow before deployment. `/healthz` is process-local; `/readyz` verifies database access and the required MemeBank transfer tables.

## Validate

```sh
cargo metadata --locked --format-version 1 --no-deps
cargo tree --locked -e normal,build -i rsa
python3 scripts/check-security-schema.py
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
CLIPTOWN_TEST_DATABASE_URL=postgres://... cargo test --locked --all-targets -- --nocapture
cargo build --locked --release
nix develop -c agent-check audit
```

GitHub Actions runs the Rust checks against Rust 1.88 and stable. Both native and Nix CI resolve `cliptown-interfaces` at commit `ef3d5f55719e56b1a6f11d2d6464c0976aa1863d`, avoiding a moving sibling dependency while consuming the merged application-vault, external step-up, and MemeBank transfer contracts. The repository toolchain is pinned to the declared Rust 1.88 minimum required by the locked SeaORM/ICU/time dependency graph.

The build-local `vendor/shared-auth-client` directory records an immutable official SDK source commit and preserves the reviewed exact-audience introspection transport without requiring a reusable cross-organization Git credential. It is not a factor client or alternate authorization policy. See [`vendor/shared-auth-client/UPSTREAM.md`](vendor/shared-auth-client/UPSTREAM.md).

SeaORM default features remain disabled because this service uses PostgreSQL only. The explicitly enabled JSON mapping is required for the reviewed application namespace policy, and its resolved dependency graph is committed in `Cargo.lock` so every `--locked` native and Nix build sees the same model. Cargo may retain optional SQLx MySQL/SQLite package metadata in the lockfile, but CI fails if `rsa`, `sqlx-mysql`, or `sqlx-sqlite` becomes reachable in the active normal/build dependency graph. RustSec advisory `RUSTSEC-2023-0071` is ignored only after that reachability proof; every other advisory remains fail-closed.
