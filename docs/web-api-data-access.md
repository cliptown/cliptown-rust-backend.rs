# Web/API data-access decision

ClipTown adopts the
[portfolio four-path ADR](https://github.com/ORESoftware/k8s-cluster/blob/main/docs/architecture/web-api-data-access.md)
for [ORESoftware/k8s-cluster#1399](https://github.com/ORESoftware/k8s-cluster/issues/1399)
and [DEN-3960](https://linear.app/denman/issue/DEN-3960/document-4-web-server-to-api-server-data-access-patterns-across-10).
Paths are selected per operation and do not confer authority on one another.

## Current boundary

This repository is the API and product-data owner; it is not a trusted web tier.
Browser, Flutter, GPUI, and MemeBank integrations use the versioned HTTPS API
and official SDKs. The API alone holds the ClipTown database credential and
performs product-domain writes after protected shared-auth introspection.

| Operation | Path | Decision |
| --- | --- | --- |
| Create, list, get, acknowledge, or cancel a MemeBank transfer | P2: stateless HTTP | The versioned API is authoritative; mutating calls require stable, operation-bound idempotency. |
| API access to ClipTown persistence | Local API authority | This is not P1. API handlers use subject-owned transactions and RLS. |
| Browser/mobile direct database access | Prohibited | Clients receive no database credential and do not fall back to a shared database. |
| Stateful web-to-API connection | Not deployed | P3 requires a separately reviewed streaming need. |
| NATS/MQ command path | Not deployed | The database transfer rows are pull-oriented API state, not a P4 message bus. |

## Path 1: constrained direct reads

P1 is not enabled. A future separately deployed web server may receive direct
read access only with a distinct read-only role that has no DML, DDL, ownership,
membership, or `BYPASSRLS` capability. It must be limited to reviewed stable
views, derive the subject from verified identity, force tenant/owner isolation,
and pass negative cross-subject tests. The pool and query timeout must be
bounded, cancellation must follow request cancellation, and a replica read must
be treated as potentially stale. Reads that require authoritative command state
use P2. Native and browser clients never qualify for P1.

## Path 2: stateless HTTP

P2 is the deployed and default client-to-API path. The API pins issuer,
`cliptown-api` audience, `memebank-api` authorized party, delegation lineage,
operation scope, active session, and required assurance. Cross-subject access is
indistinguishable from absence. Ciphertext and bounded routing/integrity metadata
cross the API; credentials, keys, plaintext, clipboard contents, and private
paths do not appear in URLs or logs.

Mutations require a stable idempotency key bound to subject, route, operation,
and request digest. Retries reuse that key, honor a total deadline and
`Retry-After`, and use capped jitter; authentication and validation failures are
not retried. Clients set connect and total timeouts, bound request/response
bodies, and stop on cancellation. The service bounds its database pool and HTTP
body size and returns explicit overload/unavailable responses instead of
creating an unbounded queue.

Propagate W3C trace context and a request ID through SDKs and shared-auth calls.
Record route templates, status class, latency, timeout, retry count, database
pool pressure, and idempotent replay/conflict outcomes. Never record bearer
tokens, the introspection credential, ciphertext payloads, or subject identifiers
as unbounded metric labels.

## Path 3: bounded stateful API connection

No P3 web-to-API transport exists. Add one only when a measured streaming use
case cannot be served by P2 polling. A proposal must cap connections per pod,
authenticate the handshake, set connect/idle/lifetime deadlines, use heartbeat
and bounded buffers, reconnect with jitter, and drain on shutdown. Overflow or
disconnect forces a P2 resync; it must not bypass authorization or switch to P1.

## Path 4: asynchronous NATS or message queue

No P4 broker path exists. The MemeBank “transfer queue” is API-owned database
state fetched through P2, not an asynchronous broker. A future P4 command needs
a versioned envelope, tenant/subject and actor identity, trace context, stable
message/idempotency ID, bounded payload, durable consumer, commit-before-ack,
retry budget, dead-letter policy, graceful drain, and queue age/redelivery/DLQ
metrics. Acceptance by the broker is not completion; clients query the
authoritative API result. P4 never carries secrets or plaintext clipboard data.

## Consistency and failure behavior

- The API owns every ClipTown product write. A client never writes the database
  directly or substitutes clipboard, deep links, local IPC, or shared storage.
- P2 returns the API's committed or accepted result. P1 would return only the
  snapshot read; P3 messages would be hints; P4 publication would be acceptance.
- Database, shared-auth, or API outages fail closed with bounded unavailable
  responses. They never weaken tenant scope, assurance, or transport choice.
- Shutdown stops admission, drains bounded in-flight requests, and closes any
  future stateful or consumer connection without acknowledging unfinished work.

## Schema and migrations

`schema/schema.sql` is the ClipTown declarative desired state;
`schema/memebank-integration.sql` is its reviewed additive MemeBank fragment.
The versioned HTTP contract lives in `cliptown-interfaces`, and callers use the
official generated clients. Deployment applies schema changes through the
reviewed declarative workflow. The API never runs migrations at startup and
never receives a migration/owner credential.
