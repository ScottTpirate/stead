# ADR-0008: NATS stream, subject, retention, replay, ordering, and dead-letter contract

- **Status:** Proposed
- **Date:** 2026-09-02
- **Decision owners:** WS-07, with WS-01 architecture, WS-02 outbox/core, WS-06 security, WS-08 projection, and WS-12 operations review
- **Project-owner approval required:** no; this selects the JetStream mechanics deliberately left open by `ADR-CAND-006` without changing the locked NATS, transactional-outbox, authorization, classification, or deployment-domain decisions
- **Requirement IDs:** `EVT-001`, `EVT-002`, `EVT-003`, `EVT-004`, `ACT-001`, `NOTIF-001`, `AUD-001`, `AUD-002`, `CLS-006`, `TEST-005`, `PERF-002`, `PERF-003`, `PERF-004`
- **Affected contracts/modules/directories:** `/specs/asyncapi/`, `/packages/event-schemas/`, `/apps/worker/`, `/modules/audit/`, `/modules/notification/`, consumer-owned projections, NATS deployment configuration, and event/replay/security/performance tests
- **Resolves on acceptance:** `ADR-CAND-006`
- **Supersedes / superseded by:** supersedes no accepted decision; a different broker, subject grammar, cross-domain transfer, or NATS-authoritative business state requires a superseding ADR

## Context

The Master Build Directive already fixes NATS JetStream, CloudEvents 1.0, AsyncAPI 3.1.x, transactional outbox publication, at-least-once delivery, idempotent consumers, replay and dead-letter handling, protected-content minimization, and no synchronous NATS wait in request handling. PostgreSQL remains authoritative. The unresolved implementation choice is how Phase 1 partitions accounts and streams and how it makes retries, ordering, replay, recovery, and credentials deterministic without turning Organization lifecycle into broker administration.

The original proposal created one NATS account, signing hierarchy, resolver lifecycle, and four-stream set for every Organization. That is disproportionate for ordinary Phase 1 deployments and makes local startup and Organization creation depend on broker provisioning. Phase 1 needs a smaller secure baseline that preserves a future stronger topology without adopting it prematurely.

## Decision

### Deployment-domain topology

Phase 1 has one internal Stead NATS application account for each deployment security domain. Most standard and local deployments have one deployment security domain and therefore one Stead application account. Organization creation never creates a NATS account, user, signing key, resolver entry, stream, or other broker resource.

The account has service-role credentials for the outbox publisher, each registered consumer class, replay, and narrowly scoped maintenance. Permissions allow only the subjects and JetStream operations needed by that role. Browser sessions, end users, external Agent runtimes, provider credentials, and ordinary API credentials receive no NATS credentials. A service credential is infrastructure identity and never grants product authorization or content access.

Organization, container, resource, effective-label reference, activation revision, authorization revision, and correlation metadata remain schema-validated application data. Consumers validate their configured deployment domain, reject scope mismatch, refetch authoritative data when content or current visibility is needed, and perform the current central authorization and fence checks before creating a protected projection, notification, or external effect. No consumer may use account membership, subject access, or an event as an authorization grant.

Subjects remain the provider-neutral AsyncAPI addresses `stead.<domain>.<action>.v<major>`. They do not contain Organization, provider, classification, or deployment identifiers. Accounts have no imports or exports for protected Stead subjects in Phase 1. A future per-Organization account topology is optional and requires a superseding decision backed by scale, connection/account-count, operational-failure, backup/restore, and application-partitioning evidence.

### Streams, retention, and publication

Each deployment-domain account has a small fixed stream set, not a stream set per Organization:

- `STEAD_EVENTS_V1` contains registered canonical Stead event subjects.
- `STEAD_DLQ_V1` contains only registered minimized dead-letter notification subjects.

The versioned deployment manifest owns exact subjects, storage type, replicas, maximum message size, maximum age, byte/message limits, duplicate window, consumer limits, and supported server/client versions. Phase 1 uses file-backed limit retention, explicit acknowledgements, and `DiscardNew` so capacity pressure leaves authoritative outbox rows pending instead of silently evicting retained events. Mirrors, sources, transforms, republish, rollup, direct reads, and unregistered subjects are disabled unless a later reviewed contract explicitly enables them.

The authoritative module writes its state, one outbox record, and the logical audit intent in one PostgreSQL transaction through module-owned interfaces. The relay publishes after commit and marks the outbox record delivered only after a matching JetStream publish acknowledgement. API responses never wait for publication, a consumer, replay, or NATS availability. Relay and consumers use bounded batches and backpressure; a full or unavailable stream degrades asynchronous freshness but does not roll back acknowledged authoritative state.

### Delivery, ordering, idempotency, and dead letters

Delivery is at least once. CloudEvent `id` and the registered restore-stable logical producer `source` identify one representation; a separate schema-defined semantic idempotency key identifies the same logical change across compatible representations. Consumer-owned PostgreSQL state records processed identity, payload digest, resource version, outcome, and checkpoint in the same transaction as its projection or effect intent. Identity reuse with a different digest or semantic key is quarantined.

Events carry a resource-local version or sequence. Consumers converge under duplicate, delayed, reversed, concurrent, restart, and replay delivery and make no global-order assumption. A gap or stale fence causes refetch, defer, or rebuild; it does not authorize accepting an older protected view.

Durable consumers use explicit acknowledgements. Broker delivery remains eligible until the handler has atomically recorded either success or a minimized terminal outcome in PostgreSQL. Application-owned retry state applies a finite, configured attempt/deadline budget; a terminal transaction records a closed failure code, creates the minimized dead-letter outbox notification and logical audit intent, and only then acknowledges the source. Raw payloads, exception text, credentials, provider locators, titles, comments, document bodies, prompts, or stack traces never enter DLQ messages, broker metadata, logs, metrics, or support evidence.

### Replay and recovery

Replay is requested through a centrally authorized Stead operation that binds the deployment domain, consumer, event identity or bounded range, purpose, expiry, and current authorization/activation revisions. Replay workers have no product authority of their own. They use the ordinary schema validation, idempotency, authorization, fence, audit, and effect path; changed authorization denies or suppresses the result. Direct broker replay by a browser, end user, or ordinary operator credential is unsupported.

JetStream is reconstructible transport, not backup authority. Recovery starts from PostgreSQL authoritative state, pending outbox rows, owner snapshots, consumer checkpoints, and minimized terminal state. A compatible authenticated JetStream snapshot may accelerate same-domain restore, but loss of all streams must still permit outbox drain and projection rebuild. Restore never weakens the target deployment domain or treats retained broker bytes as current authorization.

### Credentials and supported development mode

Production NATS client and cluster links use authenticated encrypted transport with peer verification and no plaintext fallback. Credentials are generated or supplied through deployment secret references, scoped by service role and deployment domain, rotated without changing canonical event identity, and excluded from PostgreSQL business data, events, logs, metrics, and backups.

The supported development stack automatically generates local-only account and service credentials plus validated NATS configuration. It requires no operator-key ceremony, account JWT signing hierarchy, or external resolver. Production deployments may use documented NATS operator mode, but that is an interchangeable deployment mechanism for the same deployment-domain account contract and never participates in Organization lifecycle.

## Rejected alternatives

- **One account and stream set per Organization:** rejected for the Phase 1 baseline because it couples product creation to broker provisioning and imposes unproven connection, key, resolver, restore, and operational costs. It remains a possible later high-isolation topology after evidence.
- **One global account spanning deployment security domains:** rejected because a credential or configuration error could cross the deployment-domain boundary.
- **Organization tokens in subjects:** rejected because it changes the locked subject grammar and exposes routing identifiers; Organization scoping remains validated event metadata and application authorization.
- **Consumer-side filtering as authorization:** rejected because receipt or filtering is not the central authorization decision.
- **Finite broker delivery as the terminal authority:** rejected because a crash can exhaust broker delivery before the owner records a terminal outcome.
- **Full failed payloads in a DLQ:** rejected because they duplicate protected content and turn broker access into a disclosure path.
- **Synchronous publish or consumer completion in requests:** rejected because NATS availability must not control authoritative request completion.

## Consequences

- Local and ordinary installations have one generated Stead application account and two fixed streams per deployment security domain, regardless of Organization count.
- Service-role ACLs and deployment-domain accounts contain broker compromise while application metadata and fresh central decisions enforce Organization/container authorization.
- Capacity, duplicates, poison events, replay, and total stream loss are explicit tested states; PostgreSQL outbox and projections remain the correctness boundary.
- Stronger per-Organization broker isolation is not forbidden, but Phase 1 does not pay its operational cost or claim its security benefit without evidence.
- Detailed stream values, schemas, fixtures, failure-code registry, and version-specific read-back rules live in machine-readable deployment and AsyncAPI contracts rather than this ADR.

## Compatibility and migration

There is no accepted production predecessor to migrate. Any experimental per-Organization topology must stop publication, drain or preserve pending outbox rows, create the deployment-domain account and fixed streams, start compatible consumers from explicit checkpoints, rebuild projections, and retire old credentials only after reconciliation. Event subjects, CloudEvent source identities, semantic idempotency keys, and canonical resource identities remain stable across that topology change.

Stream and event evolution uses expand/coexist/contract. Producers do not emit a new major until compatible consumers are deployed; rollback preserves readable old representations and all PostgreSQL outbox, processed, checkpoint, terminal, and audit state. Unknown schema majors or unsafe server/client configuration fail closed.

## Tests

- `T-ADR-0008-SUBJECT-PARTITION`: two Organizations in one domain share the domain account without broker provisioning; another domain has a distinct account; cross-domain credentials and subjects deny, and no browser/end-user credential exists.
- `T-ADR-0008-SUBSCRIBER-ISOLATION`: enumerate publisher, consumer, replay, and maintenance permissions and deny wildcard expansion, cross-domain access, unregistered subjects, and management operations outside each role.
- `T-ADR-0008-RETENTION`: verify the versioned two-stream-per-domain manifest, explicit ack, bounded limits, `DiscardNew`, capacity backpressure, and rejection of unsafe or unknown configuration.
- `T-ADR-0008-RESOURCE-ORDERING`: inject duplicates, gaps, reversal, concurrency, restart, and replay and prove resource-local convergence without global ordering.
- `T-ADR-0008-IDEMPOTENCY`: lose publish/consumer acknowledgements, restart and restore producers/consumers, and prove one projection/effect per semantic event with collision quarantine.
- `T-ADR-0008-DLQ`: crash at retry and terminal boundaries; prove no source is stranded, terminal state precedes acknowledgement, and DLQ/audit evidence is minimized.
- `T-ADR-0008-AUTHORIZED-REPLAY`: deny direct, expired, foreign, or stale replay and prove an authorized bounded replay uses the ordinary handler and audit path.
- `T-ADR-0008-SCHEMA-COMPATIBILITY`: validate registered channels/types/sources, additive evolution, major-version coexistence, and unsupported-major quarantine.
- `T-ADR-0008-PAYLOAD-MINIMIZATION`: canary protected values through events, retries, DLQ, telemetry, doctor, and backup/restore evidence and prove absence outside authorized stores.
- `T-ADR-0008-ASYNC-PERFORMANCE`: prove zero request-path NATS calls/waits, bounded batches, stable SQL/OpenFGA/provider counts, and record event-to-visible p50/p95/p99 against the current baseline and release ceiling.
- `T-ADR-0008-PROJECTION-REBUILD`: destroy streams and rebuild from authoritative snapshots, outbox/checkpoints, and retained compatible events without exposing stale or unauthorized state.

`STEAD-P1-007` owns relay, stream/consumer manifests, idempotent delivery, DLQ, replay, and activity/inbox/audit projections. Consumer owners own their local processed/checkpoint state. `STEAD-P1-011` owns development/production configuration, credentials, health, capacity, backup/restore, and recovery. `STEAD-P1-012` independently reruns the complete suites. Shared test IDs do not transfer directory ownership.

## Rollback

Rollback stops publishers and consumers, restores the last compatible declarative account/stream/consumer configuration and binaries, and resumes from preserved PostgreSQL outbox and checkpoints. It never deletes an acknowledged authoritative mutation, re-enables plaintext transport, restores retired credentials, weakens a deployment-domain boundary, or relies on NATS as the only recovery source. If the prior version cannot read current retained data or schemas, publication remains stopped and recovery moves forward.

## Reviews and approvals

| Role | Identity | Decision revision | Disposition | Evidence |
|---|---|---|---|---|
| Decision author (WS-07) | `/root/adr_cand_006` | `pending exact immutable revision` | PROPOSED | Authored decision candidate; author cannot approve |
| Architecture and standards (WS-01) | `pending non-author reviewer` | `pending exact immutable revision` | PENDING | Topology, portability, compatibility, and supersession review required |
| Core/outbox integration (WS-02) | `pending non-author reviewer` | `pending exact immutable revision` | PENDING | Atomic outbox and failure-boundary review required |
| Authorization/classification/security (WS-06) | `pending non-author reviewer` | `pending exact immutable revision` | PENDING | Domain isolation, credential, replay, and nondisclosure review required |
| Events/worker consumer (WS-07, non-author) | `pending non-author reviewer` | `pending exact immutable revision` | PENDING | Delivery, retry, replay, DLQ, and audit review required |
| Projection consumer (WS-08) | `pending non-author reviewer` | `pending exact immutable revision` | PENDING | Ordering, rebuild, lag, and visibility review required |
| Deployment operations (WS-12) | `pending non-author reviewer` | `pending exact immutable revision` | PENDING | Local startup, production transport, capacity, recovery, and rollback review required |
| Independent QA (WS-13) | `pending non-author reviewer` | `pending exact immutable revision` | PENDING | Traceability, compatibility, performance, and recovery review required |
| Independent security (WS-13) | `pending non-author reviewer` | `pending exact immutable revision` | PENDING | Fail-closed credential, payload, replay, and DLQ review required |
| Project owner | `not required for this conforming selection` | `pending exact immutable revision` | NOT_REQUIRED | Required only if review changes a locked or owner-controlled decision |

Until all required non-author dispositions accept one exact immutable revision and the acceptance-only descendant is recorded, this ADR remains proposed and `STEAD-P1-007` remains blocked.
