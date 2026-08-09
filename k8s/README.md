# ClipTown API Kubernetes release contract

This directory is the application-owned Kubernetes base for `cliptown-api`. It is intentionally environment-neutral: database/shared-auth endpoints, credentials, ingress, network policy, autoscaling, and observability destinations belong to the GitOps environment.

## Image invariant

`deployment.yaml` contains a non-deployable release-contract placeholder. A live Argo CD application **must** replace it through `spec.source.kustomize.images` with exactly:

```text
ghcr.io/cliptown/cliptown-rust-backend.rs@sha256:<64 lowercase hex>
```

Do not deploy `latest`, a branch name, a mutable semantic tag, or the source-SHA tag. The `Publish OCI image` workflow publishes the source-SHA tag only so GHCR can expose an immutable digest; GitOps consumes the digest.

## Required external objects

The target namespace must provide these before sync:

- Secret `cliptown-api-runtime`
  - `database-url`
  - `shared-auth-introspect-secret`
- ConfigMap `cliptown-api-runtime`
  - `shared-auth-base-url` — HTTPS outside loopback
  - `shared-auth-issuer` — HTTPS issuer URL

The application does not apply `schema/schema.sql` at startup. Deployment automation must apply the reviewed schema before expecting `/readyz` to return 200.

## Non-production canary

1. Record the source SHA, GHCR digest, schema SHA, config revision, and current production digest.
2. Apply `schema/schema.sql` to the canary database with the normal declarative migration controller.
3. Create/update the external Secret and ConfigMap; never commit their values here.
4. Deploy one replica with the exact image digest.
5. Require `/healthz` = 200 and `/readyz` = 200 before sending test traffic.
6. Exercise the headless MemeBank create/list/get/ack/cancel flow with both phone applications absent.
7. Verify wrong audience/client/scope, revoked session, stale LOA2, replay mismatch, prohibited factor/app headers, and shared-auth outage remain fail-closed.
8. Confirm logs, traces, and metrics contain no bearer, introspection credential, ciphertext body, database URL, or private MemeBank metadata.
9. Hold the canary long enough to observe readiness stability, restart count, request errors, database saturation, and shared-auth verification failures.

## Minimum dashboard/alert signals

Environment monitoring should cover:

- pod available/ready replicas and restart rate;
- HTTP 5xx and latency for the MemeBank route prefix;
- readiness failures;
- PostgreSQL pool exhaustion/connect failures;
- shared-auth introspection unavailable/denied rates;
- idempotency conflicts and transfer-state conflicts as bounded counters;
- CPU and memory saturation.

Alerts must not include credentials, bearer values, ciphertext, request bodies, or private identifiers.

## Rollback

Rollback is a GitOps digest change, not a rebuild:

1. Restore the previously recorded `ghcr.io/...@sha256:<digest>` in the Argo CD image override.
2. Sync and wait for `/healthz` and `/readyz` on the restored ReplicaSet.
3. Re-run a read-only headless transfer check.
4. Record old digest, failed/new digest, timestamps, reason, and observed recovery.

Database rollback is independent. Do not reverse a schema change unless its reviewed migration procedure explicitly supports reversal. The application schema is additive for the DEN-2259 transfer route and startup never mutates it automatically.
