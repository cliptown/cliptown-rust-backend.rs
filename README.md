# ClipTown Rust backend

Rust API service for encrypted ClipTown synchronization. The current foundation exposes service information, liveness, and readiness contracts. DEN-42/DEN-44/DEN-45/DEN-47/DEN-51 add reviewed account-security, Signal Protocol relay, isolated application-vault, PostgreSQL/Supabase, and encrypted Cloudflare R2 foundations without enabling unauthenticated placeholder routes. DEN-1578 adds the server-side policy and persistence foundation for the API-first MemeBank transfer contract; those routes remain unmounted until protected shared-auth verification and the reviewed storage adapter are wired.

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

### MemeBank interoperability boundary

MemeBank interoperability is independent from ClipTown's isolated application-vault and external-proof features. ClipTown accepts MemeBank authority only after shared-auth has verified and protectedly introspected a short-lived delegated token with:

- `aud=cliptown-api`;
- `azp=memebank-api`;
- exactly one operation scope: `cliptown:memebank:read`, `cliptown:memebank:write`, or `cliptown:memebank:delete`;
- a stable UUID subject, active revocation-aware session, token/delegation lineage, and unexpired token;
- recent `aal=2` plus `acr=urn:oresoftware:loa:2` for create, acknowledge, and cancel.

The backend consumes normalized shared-auth assurance and does not accept a MemeBank-specific 3FA proof, factor header, app-install state, deep link, local IPC message, shared clipboard event, or broad service credential. Resource access is always bound to the delegated subject; cross-subject and absent records have the same not-found result.

`src/memebank_integration.rs` owns the pure authorization/domain policy. It validates the exact client/audience/scope tuple, recent assurance, ciphertext envelopes, 16 MiB content limit, seven-day transfer retention, subject/operation/body-digest-bound idempotency, opaque cursors, ownership, expiry, and terminal state transitions. It deliberately contains no HTTP endpoint and no direct token-verification shortcut.

`schema/memebank-integration.sql` is an additive reviewed desired-state fragment applied after `schema/schema.sql`. It creates ciphertext-only transfer and idempotency tables, subject-owned RLS policies, `FORCE ROW LEVEL SECURITY`, bounded constraints/indexes, and explicit `PUBLIC` revocations. It contains no access/refresh token, OTP, private-key, plaintext OCR/caption, provider credential, durable/signed URL, app-path, or installation-state columns. `scripts/check-security-schema.py` fails CI when those invariants drift.

The canonical HTTP contract remains `cliptown-interfaces/openapi/memebank-integration.openapi.yaml`, and callers use the official `cliptown-clients` SDK. An explicit native Copy action may exist for ordinary user paste behavior, but it is not the integration transport and neither phone application must be installed.

## Run

```sh
CLIPTOWN_BIND_ADDRESS=127.0.0.1:3000 cargo run --locked
```

The service does not run database migrations at startup. PostgreSQL desired state belongs in [`schema/schema.sql`](schema/schema.sql) plus reviewed additive fragments such as [`schema/memebank-integration.sql`](schema/memebank-integration.sql). Apply them in that order through the declarative migration workflow before deployment.

## Validate

```sh
cargo metadata --locked --format-version 1 --no-deps
cargo tree --locked -e normal,build -i rsa
python3 scripts/check-security-schema.py
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
nix develop -c agent-check audit
```

GitHub Actions runs the Rust checks against Rust 1.88 and stable. Both native and Nix CI resolve `cliptown-interfaces` at commit `ef3d5f55719e56b1a6f11d2d6464c0976aa1863d`, avoiding a moving sibling dependency while consuming the merged application-vault and external step-up contracts. The repository toolchain is pinned to the declared Rust 1.88 minimum required by the locked SeaORM/ICU/time dependency graph. Before the MemeBank handlers are mounted, CI must pin a released `cliptown-interfaces` revision containing the versioned MemeBank contract rather than consuming a moving PR branch.

SeaORM default features remain disabled because this service uses PostgreSQL only. The explicitly enabled JSON mapping is required for the reviewed application namespace policy, and its resolved dependency graph is committed in `Cargo.lock` so every `--locked` native and Nix build sees the same model. Cargo may retain optional SQLx MySQL/SQLite package metadata in the lockfile, but CI fails if `rsa`, `sqlx-mysql`, or `sqlx-sqlite` becomes reachable in the active normal/build dependency graph. RustSec advisory `RUSTSEC-2023-0071` is ignored only after that reachability proof; every other advisory remains fail-closed.
