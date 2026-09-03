# ADR-0008: NATS stream, subject, retention, replay, ordering, and dead-letter contract

- **Status:** Proposed
- **Date:** 2026-09-02
- **Decision owners:** WS-07, with WS-01 architecture, WS-02 outbox/core, WS-06 security, WS-08 projection, and WS-12 operations review
- **Project-owner approval required:** no; this selects the JetStream mechanics deliberately left open by `ADR-CAND-006` without changing the locked NATS, transactional-outbox, authorization, classification, or deployment-domain decisions
- **Requirement IDs:** `EVT-001`, `EVT-002`, `EVT-003`, `EVT-004`, `ACT-001`, `NOTIF-001`, `AUD-001`, `AUD-002`, `CLS-006`, `TEST-005`, `PERF-002`, `PERF-003`, `PERF-004`
- **Affected contracts/modules/directories:** `/specs/asyncapi/`, `/packages/event-schemas/`, `/apps/worker/`, `/modules/audit/`, `/modules/notification/`, consumer-owned projections, NATS deployment configuration, and event/replay/security/performance tests
- **Resolves on acceptance:** `ADR-CAND-006`
- **Supersedes / superseded by:** supersedes no accepted decision; a different broker, subject grammar, cross-domain transfer, or NATS-authoritative business state requires a superseding ADR

## Context and decision scope

The Master Build Directive already fixes NATS JetStream, CloudEvents 1.0, AsyncAPI 3.1.x, transactional outbox publication, at-least-once delivery, idempotent consumers, replay and dead-letter handling, protected-content minimization, and no synchronous NATS wait in request handling. PostgreSQL remains authoritative. The unresolved implementation choice is how Phase 1 partitions accounts and streams and how it makes retries, ordering, replay, recovery, and credentials deterministic without turning Organization lifecycle into broker administration.

The original proposal created one NATS account, signing hierarchy, resolver lifecycle, and four-stream set for every Organization. That is disproportionate for ordinary Phase 1 deployments and makes local startup and Organization creation depend on broker provisioning. Phase 1 needs a smaller secure baseline that preserves a future stronger topology without adopting it prematurely.

## Decision drivers

- Keep Organization creation and the supported development stack independent from broker-account provisioning and operator-key ceremonies.
- Isolate deployment security domains while retaining application-level Organization/container authorization.
- Preserve provider-neutral events, bounded operations, replay, recovery, and future topology compatibility.
- Make request latency independent from NATS and keep PostgreSQL as the correctness and recovery boundary.

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

The manifest also carries a closed, versioned registry of the required durable consumer classes for each subject and schema major, including owner, filter, initial checkpoint, bounded outcome deadline, and projection-rebuild or effect-reconciliation behavior. The active registry revision is frozen into each outbox record in the authoritative transaction. Adding or removing a required consumer is an expand/coexist/contract migration; a new consumer does not silently claim historical events without an explicit authorized replay start.

The authoritative module writes its state, one outbox record, and the logical audit intent in one PostgreSQL transaction through module-owned interfaces. The relay publishes after commit. A matching JetStream publish acknowledgement records transport publication only; it never makes the canonical outbox payload eligible for retirement. The WS-02-owned delivery repository retains the exact canonical event bytes and identity as a recovery source until typed consumer-owner completion reads prove that every required consumer in the event's frozen registry has durably recorded success or a minimized terminal outcome with its dead-letter and logical audit intents. Consumer owners write only their own processed/checkpoint state, and relay/recovery coordination uses their typed ports rather than foreign SQL.

API responses never wait for publication, a consumer, replay, or NATS availability. Relay and consumers use bounded batches and backpressure; a full or unavailable stream degrades asynchronous freshness but does not roll back acknowledged authoritative state. Broker age or retention expiry is a transport event, not a delivery terminal: while any required outcome remains open, the recovery coordinator republishes the retained canonical event under the same CloudEvent source, id, semantic idempotency key, and payload digest. Republish attempts and deadlines are bounded and observable, but the retained PostgreSQL recovery source is not retired merely because a broker copy expired.

### Delivery, ordering, idempotency, and dead letters

Delivery is at least once. CloudEvent `id` and the registered restore-stable logical producer `source` identify one representation; a separate schema-defined semantic idempotency key identifies the same logical change across compatible representations. Consumer-owned PostgreSQL state records processed identity, payload digest, resource version, outcome, and checkpoint in the same transaction as its projection or effect intent. Identity reuse with a different digest or semantic key is quarantined.

Events carry a resource-local version or sequence. Consumers converge under duplicate, delayed, reversed, concurrent, restart, and replay delivery and make no global-order assumption. A gap or stale fence causes refetch, defer, or rebuild; it does not authorize accepting an older protected view.

Durable consumers use explicit acknowledgements and unlimited broker redelivery while a broker copy remains retained. Application-owned retry state applies a finite, configured attempt/deadline budget. Before that budget closes, broker expiry or loss causes bounded recovery from the retained PostgreSQL source rather than silent completion. At the deadline the registered consumer owner atomically records a closed failure code, minimized terminal outcome, dead-letter outbox notification, and logical audit intent before acknowledging any remaining broker copy or reporting completion through its typed port. Only durable success or that complete terminal transaction satisfies the frozen consumer registry and permits recovery-source retirement. Raw payloads, exception text, credentials, provider locators, titles, comments, document bodies, prompts, or stack traces never enter DLQ messages, broker metadata, logs, metrics, or support evidence.

### Replay and recovery

Replay is requested through a centrally authorized Stead operation that binds the deployment domain, consumer, event identity or bounded range, purpose, expiry, and current authorization/activation revisions. Replay workers have no product authority of their own. They use the ordinary schema validation, idempotency, authorization, fence, audit, and effect path; changed authorization denies or suppresses the result. Direct broker replay by a browser, end user, or ordinary operator credential is unsupported.

JetStream is reconstructible transport, not backup authority. Recovery starts from PostgreSQL authoritative state, every unretired outbox recovery source whether or not it was already published, the frozen required-consumer registry, owner snapshots, consumer checkpoints, and minimized terminal state. A compatible authenticated JetStream snapshot may accelerate same-domain restore, but expiry or loss of all streams must still permit incomplete events to be republished, terminal outcomes and their DLQ/audit intents to complete, and projections to rebuild. Restore never weakens the target deployment domain or treats retained broker bytes as current authorization.

### Credentials and supported development mode

Production NATS client and cluster links use authenticated encrypted transport with peer verification and no plaintext fallback. JetStream file storage uses deployment-managed authenticated encryption at rest through a secret reference; exported snapshots remain inside the authenticated backup boundary. Credentials are generated or supplied through deployment secret references, scoped by service role and deployment domain, rotated without changing canonical event identity, and excluded from PostgreSQL business data, events, logs, metrics, and backups.

The supported development stack automatically generates local-only account and service credentials plus validated NATS configuration. It requires no operator-key ceremony, account JWT signing hierarchy, or external resolver. Production deployments may use documented NATS operator mode, but that is an interchangeable deployment mechanism for the same deployment-domain account contract and never participates in Organization lifecycle.

## Considered options

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
- Bounded broker history can expire independently of a consumer, so PostgreSQL retains each canonical distribution source until the frozen required-consumer set reaches durable success or minimized terminal state. This adds bounded completion/checkpoint coordination but prevents broker retention from becoming silent delivery authority.
- Stronger per-Organization broker isolation is not forbidden, but Phase 1 does not pay its operational cost or claim its security benefit without evidence.
- Detailed stream values, schemas, fixtures, failure-code registry, and version-specific read-back rules live in machine-readable deployment and AsyncAPI contracts rather than this ADR.

## Rollout and supersession

There is no accepted production predecessor to migrate. Any experimental per-Organization topology must stop publication, drain or preserve pending outbox rows, create the deployment-domain account and fixed streams, start compatible consumers from explicit checkpoints, rebuild projections, and retire old credentials only after reconciliation. Event subjects, CloudEvent source identities, semantic idempotency keys, and canonical resource identities remain stable across that topology change.

Stream and event evolution uses expand/coexist/contract. Producers do not emit a new major until compatible consumers are deployed; consumer-registry changes preserve explicit start checkpoints and coexistence behavior. Rollback preserves readable old representations, frozen consumer registries, unretired recovery sources, and all PostgreSQL processed, checkpoint, terminal, DLQ, and audit state. Unknown schema majors or unsafe server/client configuration fail closed.

## Verification

- `T-ADR-0008-SUBJECT-PARTITION`: two Organizations in one domain share the domain account without broker provisioning; another domain has a distinct account; cross-domain credentials and subjects deny, and no browser/end-user credential exists.
- `T-ADR-0008-SUBSCRIBER-ISOLATION`: enumerate publisher, consumer, replay, and maintenance permissions and deny wildcard expansion, cross-domain access, unregistered subjects, and management operations outside each role.
- `T-ADR-0008-RETENTION`: verify the versioned two-stream-per-domain manifest and consumer registry, explicit ack, bounded limits, `DiscardNew`, capacity backpressure, and rejection of unsafe or unknown configuration; hold a required consumer offline past broker `MaxAge` and prove the broker copy may expire while the PostgreSQL recovery source cannot retire.
- `T-ADR-0008-RESOURCE-ORDERING`: inject duplicates, gaps, reversal, concurrency, restart, and replay and prove resource-local convergence without global ordering.
- `T-ADR-0008-IDEMPOTENCY`: lose publish/consumer acknowledgements, expire the broker copy, restart and restore producers/consumers, republish the retained canonical identity, and prove one projection/effect per semantic event with collision quarantine.
- `T-ADR-0008-DLQ`: crash at retry and terminal boundaries and keep a consumer unavailable through broker retention and its application deadline; prove no source retires before durable success or a minimized terminal/DLQ/audit transaction, terminal state precedes acknowledgement, and evidence is minimized.
- `T-ADR-0008-AUTHORIZED-REPLAY`: deny direct, expired, foreign, or stale replay and prove an authorized bounded replay uses the ordinary handler and audit path.
- `T-ADR-0008-SCHEMA-COMPATIBILITY`: validate registered channels/types/sources, additive evolution, major-version coexistence, and unsupported-major quarantine.
- `T-ADR-0008-PAYLOAD-MINIMIZATION`: canary protected values through events, retries, DLQ, telemetry, doctor, and backup/restore evidence and prove absence outside authorized stores.
- `T-ADR-0008-ASYNC-PERFORMANCE`: prove zero request-path NATS calls/waits, bounded batches, stable SQL/OpenFGA/provider counts, and record event-to-visible p50/p95/p99 against the current baseline and release ceiling.
- `T-ADR-0008-PROJECTION-REBUILD`: destroy or age out streams, republish every incomplete frozen-registry event from retained outbox sources, and rebuild from authoritative snapshots, outbox/checkpoints, and retained compatible events without exposing stale or unauthorized state.

`STEAD-P1-007` owns relay, stream/consumer manifests, idempotent delivery, DLQ, replay, and activity/inbox/audit projections. Consumer owners own their local processed/checkpoint state. `STEAD-P1-011` owns development/production configuration, credentials, health, capacity, backup/restore, and recovery. `STEAD-P1-012` independently reruns the complete suites. Shared test IDs do not transfer directory ownership.

## Rollback

Rollback stops publishers and consumers, restores the last compatible declarative account/stream/consumer configuration and binaries, and resumes from preserved PostgreSQL outbox recovery sources, frozen consumer registries, and checkpoints. A prior binary that treats broker publication as permission to discard an incomplete recovery source is incompatible and must not start; recovery moves forward instead. Rollback never deletes an acknowledged authoritative mutation, re-enables plaintext transport, restores retired credentials, weakens a deployment-domain boundary, or relies on NATS as the only recovery source.

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
