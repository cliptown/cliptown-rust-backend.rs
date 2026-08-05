# Vendored shared-auth Rust client

This directory is a build-local snapshot of the official Rust client from:

- repository: `shared-auth/shared-auth-clients`
- package path: `clients/rust`
- upstream commit: `cebdacc461fef31444cba7545a444373f6b26d3d`
- coordinated pull request: `shared-auth/shared-auth-clients#34`

Only the protected exact-audience introspection transport surface consumed by the
ClipTown backend is retained here. Its security behavior remains aligned with the
upstream package:

- remote plaintext HTTP is refused;
- redirects are disabled;
- request and response bodies are bounded;
- malformed tokens, audiences, base URLs, and service credentials fail before
  transport;
- the independent introspection credential is attached only to
  `/auth/introspect` and never enters the JSON body;
- active delegated responses expose and distinguish `jti` and `parent_jti`.

The vendored package exists so ClipTown builds do not require a reusable
cross-organization Git credential. It is not an independent API implementation,
a factor client, or a forked authorization policy. Product authorization remains
in `src/memebank_transfer.rs`, and the network contract remains owned by
shared-auth.

A future registry or reviewed zed-pkg release may replace this snapshot. Any
update must record a new immutable upstream commit, review the diff against the
official package, regenerate `Cargo.lock`, and rerun the headless PostgreSQL flow.
