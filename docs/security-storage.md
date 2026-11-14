# ClipTown backend account security and encrypted storage

Tracking: DEN-42, DEN-45, DEN-47, and DEN-51.

## Boundaries

The Rust service, PostgreSQL/Supabase, CockroachDB, and Cloudflare R2 are not trusted with clipboard plaintext, plaintext embeddings, local file paths, or private key material. Flutter and Rust desktop devices encrypt text, metadata, images, files, and opted-in embedding backup envelopes before upload. The backend stores public Signal Protocol prekeys, opaque recipient mailboxes, ciphertext manifests, KMS-encrypted recovery destinations, keyed OTP digests, and bounded routing metadata.

Each desktop app owns an independent encrypted SQLite database and local search index. Text embeddings are fixed-width vectors stored and searched locally in SQLite; the cloud receives only an explicitly opted-in encrypted vector envelope and bounded dimensions. PostgreSQL/Supabase is the primary application desired state. The separate `cliptown_backup` schema from `ORESoftware/k8s-libs-and-shared-defs` is the portable PostgreSQL/CockroachDB backup desired state; both are converged by `declarative-migrations`, never by application-startup DDL.

The shared-definitions repository remains authoritative. Because untrusted pull-request jobs cannot read that cross-organization private repository with `GITHUB_TOKEN`, this repository carries a byte-for-byte, SHA-256-pinned snapshot at `schema/portable-backup.sql`. Its provenance records an exact upstream revision, and CI rejects drift before running the pinned DPM revision against PostgreSQL 17 and CockroachDB 25. Updating the snapshot requires a reviewed upstream revision and fresh convergence evidence on both engines; it is not an independent schema fork.

## Device management

Users can list, name, add, approve, suspend, and revoke devices. New devices remain pending until trusted-device QR/safety-number approval or an explicitly approved recovery flow. Revocation is terminal and must atomically block auth, prekey/mailbox operations, sync mutation acceptance, new R2 grants, and future wrapped-key fan-out.

## Recovery and local unlock

Backup email and phone are recovery/step-up channels. Destinations are envelope-encrypted with a service/KMS key and deduplicated through a keyed blind digest. OTP challenges expire, have bounded attempts and issuance cooldowns, store only keyed digests, and are consumed or invalidated once.

Biometrics and passkeys remain in platform authenticators. A six-digit PIN remains local and protects a random device-wrapping key through a bounded Argon2id/scrypt policy and device throttling. No PIN, PIN verifier, biometric template, or recovery key is stored by this service.

## Signal Protocol

The backend is an authenticated but cryptographically untrusted public-prekey directory and opaque mailbox. One-time prekeys are claimed transactionally with `FOR UPDATE SKIP LOCKED`. Envelope IDs are idempotency/replay keys. Signal sessions deliver small wrapped account/clip/object keys and device-control messages; large object ciphertext is not directly ratchet-encrypted.

## Cloudflare R2

Every image or file object uses a fresh content key and chunked AEAD. Chunks have contiguous indices, independent nonces, ciphertext digests, and randomized storage keys. Presigned upload/download grants are short-lived, scoped to one user/object/chunk, and never expose a plaintext hash or local path as the storage key. The manifest commits to the aggregate ciphertext digest, encrypted metadata, chunk order/sizes, and one wrapped content key per active recipient device. Parent manifests, child chunks, wrapped keys, and upload sessions have explicit subject-owned PostgreSQL row-level policies.

The reviewed manifest, grant, relational, and cross-engine convergence contracts are implemented. That does not establish live R2 delivery: promotion still requires authenticated ownership middleware, an R2 signer/provider adapter, a disposable-bucket upload/download/delete canary, ciphertext/redaction inspection, retry/idempotency coverage, and lifecycle cleanup evidence.

## Rollout gates

Routes remain disabled until authentication and ownership middleware, KMS rotation, provider delivery, SeaORM repositories, declarative migration verification, RLS tests, R2 grant tests, redaction snapshots, both desktop clients' secure-storage/provider/UI flows, mobile share/clipboard flows, and multi-device E2E tests all pass.
