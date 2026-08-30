# ADR-0008: NATS stream, subject, retention, replay, ordering, and dead-letter contract

- **Status:** Proposed
- **Date:** 2026-08-30
- **Decision owners:** WS-07, with WS-01 architecture, WS-02 outbox/core, WS-06 security, WS-08 projection, and WS-12 operations review
- **Project-owner approval required:** no; this selects the JetStream mechanics deliberately left open by `ADR-CAND-006` without changing the locked event naming, transactional-outbox, authorization, classification, or deployment-domain decisions
- **Requirement IDs:** `EVT-001`, `EVT-002`, `EVT-003`, `EVT-004`, `ACT-001`, `NOTIF-001`, `AUD-001`, `AUD-002`, `CLS-006`, `TEST-005`, `PERF-003`, `PERF-004`
- **Affected contracts/modules/directories:** `/specs/asyncapi/`, `/packages/event-schemas/`, `/apps/worker/`, `/modules/audit/`, `/modules/notification/`, consumer-owned projection state, NATS deployment configuration, event/replay/security/performance tests, and operator backup/restore/upgrade evidence
- **Resolves on acceptance:** `ADR-CAND-006`
- **Supersedes / superseded by:** supersedes no accepted decision; a transport-subject prefix, cross-domain account export, different broker, global-order contract, or NATS-authoritative business state requires a superseding ADR

## Context and decision scope

The directive already fixes NATS JetStream, CloudEvents 1.0, AsyncAPI 3.1.x, the subject and event-type form `stead.<domain>.<action>.v<major>`, transactional outbox publication, at-least-once delivery, idempotent consumers, protected-content minimization, controlled replay, and the prohibition on global-order assumptions. PostgreSQL remains authoritative. [ADR-0005](./0005-authorization-and-policy-decision-topology.md) requires fresh authorization for protected delivery and durable-effect controls where an effect outlives an ordinary finite request. The PostgreSQL isolation decision for `ADR-CAND-002` owns the outbox and processed-event transaction seams.

This record selects only the Phase 1 broker partition, fixed stream classes, consumer behavior, resource ordering key, retention and capacity response, dead-letter representation, replay authorization, schema evolution, projection rebuild, and recovery mechanics. It does not define a domain event body, add an ontology concept, implement NATS, make events authorize an action, or make a consumer completion part of a request.

The design relies only on documented JetStream accounts, limit-retention streams, explicit-ack durable consumers, publish deduplication, and bounded redelivery. Accounts are isolated subject namespaces; streams retain messages under explicit limits; durable consumers are stateful at-least-once views. The implementation must pin and support-test an exact NATS server/client version before distribution. See the official NATS documentation for [accounts](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/accounts), [streams](https://docs.nats.io/nats-concepts/jetstream/streams), and [consumers](https://docs.nats.io/nats-concepts/jetstream/consumers).

## Decision drivers

- Preserve the locked NATS subject form without exposing organization or security-domain identifiers in subjects.
- Prevent a credential or subject-ACL error in one Organization or security domain from becoming a cross-tenant subscription.
- Keep authoritative requests independent from NATS availability while retaining every unacknowledged outbox intent.
- Make duplicates, out-of-order delivery, restart, poison messages, and replay normal tested states rather than exceptional assumptions.
- Keep projection rebuild possible after the JetStream retention window from authoritative owner snapshots plus retained incremental events.
- Bound storage, message size, retry, concurrency, and operator actions without silently discarding acknowledged authoritative mutations.
- Preserve payload minimization and existence nondisclosure in events, broker administration, telemetry, dead-letter records, and replay.

## Considered options

1. **One isolated NATS account for each `(security_domain_id, organization_id)` pair; the locked subjects inside it; four non-overlapping limit-retention stream classes; durable pull consumers; PostgreSQL idempotency and controlled exact-message replay.** This preserves the subject contract, provides an enforceable organization/domain broker boundary, and keeps one simple event model. It adds account lifecycle and per-partition connection management. Accepted.
2. **Status quo: leave account, stream, retention, ordering, and replay mechanics deferred.** This leaves `STEAD-P1-007` unable to implement subject authorization, deterministic recovery, or `TEST-005`. Rejected.
3. **One shared account and subjects prefixed with security-domain and Organization tokens.** This partitions efficiently but changes the locked `stead.<domain>.<action>.v<major>` NATS address and exposes tenant-routing tokens to every credential that can observe the namespace. Rejected for Phase 1.
4. **One account per deployment security domain and payload-only Organization routing.** NATS permissions and stream filters cannot enforce a value inside a JSON payload. A subscriber allowed on a subject could receive other Organizations in that domain. Rejected.
5. **One global stream or a stream per domain with consumer-side filtering.** This makes stream credentials and mistakes cross-domain/cross-Organization disclosure paths and couples unrelated retention and recovery. Rejected.
6. **Work-queue or interest retention for canonical events.** Acknowledgment or consumer deletion could remove the only retained transport copy before another projection or replay needs it. Rejected; independent durable consumers use limit retention.
7. **Treat stream order, publish deduplication, or exactly-once acknowledgments as sufficient correctness.** Publisher retries can outlive the duplicate window and consumer acknowledgments can be lost. Rejected; consumer-owned state is idempotent and out-of-order safe.
8. **Copy full failed payloads and stack traces into a dead-letter stream, then let operators republish them.** This duplicates protected data, turns broker possession into apparent authority, and can repeat effects across consumers. Rejected.

## Decision

### Organization and security-domain partition

Every active Organization has exactly one event partition for its current deployment security domain. A partition is one NATS account identified by an opaque account public key and an authorized PostgreSQL mapping to `(organization_id, security_domain_id, partition_generation)`. Account, stream, durable-consumer, credential, and metric names contain only bounded opaque identifiers; the canonical Organization and security-domain identifiers remain in the schema-validated CloudEvent data and access-controlled Stead state.

Subjects inside every partition remain exactly the AsyncAPI addresses shaped as `stead.<domain>.<action>.v<major>`. No Organization, Team, Project, label profile, classification value, security domain, deployment profile, or provider token is added to a subject. CloudEvent `type` uses the same required form, and CloudEvent `subject` must equal the canonical resource URI in `data.resource.uri`.

Phase 1 creates no account imports or exports for protected event subjects. A worker credential is scoped to one partition and one registered role: outbox publisher, named consumer, dead-letter recorder, replay executor, or bounded observer. It receives only the exact publish, consumer, and JetStream API permissions that role needs. Ordinary API credentials, browser sessions, provider credentials, and human operator sessions receive no NATS credential. Broker provisioning credentials are separate from ordinary relay/consumer credentials and are not mounted in those runtimes.

Partition provisioning is asynchronous and idempotent. Authoritative Organization creation commits PostgreSQL state plus an outbox intent; it never waits for NATS. The provisioning controller creates or verifies the declared account and stream manifest outside that transaction. Until the partition is ready, relay attempts remain pending and health reports the safe degraded state. A mismatched account mapping, reused account key, security-domain change, or nonconforming stream fails closed. Moving an Organization between security domains is not an in-product event-account migration and cannot create a cross-domain transfer path.

Organization deletion tombstones the mapping and stops new publication, but does not immediately remove streams, dead-letter evidence, or recovery state. Authorized retention completion and backup evidence precede an audited purge. Local, external, Kubernetes, and air-gapped profiles use the same logical partition contract.

### Fixed stream classes

Each partition contains these non-overlapping file-backed JetStream streams. Names carry the opaque partition generation and class, never canonical tenant data.

| Stream class | Subject families | `MaxAge` | `MaxBytes` | `MaxMsgs` | `MaxConsumers` | Purpose |
|---|---|---:|---:|---:|---:|---|
| `domain_v1` | organization, project, workitem, comment, document, scm, ci, artifact, attachment, storage | 30 days | 1 GiB | 5,000,000 | 64 | authoritative-change transport and ordinary projection replay |
| `control_v1` | identity, authorization, classification, audit, migration, operations | 90 days | 512 MiB | 2,000,000 | 32 | security/control and operator lifecycle transport |
| `projection_v1` | search_graph, notification | 14 days | 256 MiB | 1,000,000 | 32 | rebuildable projection lifecycle and notification-state transport |
| `dead_letter_v1` | dead_letter | 90 days | 256 MiB | 250,000 | 16 | minimized controlled-failure and replay lifecycle records |

Every stream uses `LimitsPolicy`, `FileStorage`, `DiscardNew`, the table limits, a 64 KiB maximum including headers, and a 24-hour duplicate window. The account file-storage limit must be at least the sum of its stream byte limits plus 25 percent recovery headroom, and the server limit must admit every declared account without overcommit. Runtime identities cannot delete or purge streams. Local mode uses one replica; a declared clustered availability profile uses three. Availability profile selection never depends on a security-label profile ID.

`DiscardNew` is deliberate: capacity pressure rejects the JetStream publish rather than evicting an unexpired event. The relay keeps the PostgreSQL outbox record pending, backs off, and alerts. Max-age expiry remains expected transport retention, not deletion of authoritative state. A deployment policy may require longer ages or larger capacities; it may not silently reduce these Phase 1 release minima. Retention changes are manifest-versioned and preflighted against current consumer lag and rollback windows.

The relay publishes only a schema-validated event to the one stream class registered for its AsyncAPI channel, sets `Nats-Msg-Id` to the immutable CloudEvent `id`, requires a JetStream publish acknowledgment for the expected stream, and records the acknowledged account, stream, and sequence before marking the outbox delivery complete. A lost acknowledgment may cause a duplicate. No correctness claim depends on the 24-hour server duplicate window.

### Consumers, idempotency, and resource ordering

Production handlers bind durable pull consumers with `AckExplicit`, one fetch loop per durable, at most 128 messages or 1 MiB per fetch, a 250 ms fetch expiry, `MaxAckPending` no greater than 256, and a finite redelivery schedule. The Phase 1 default maximum is eight deliveries with backoff `1s, 5s, 30s, 2m, 10m, 30m, 2h, 12h`; a deterministic schema, authorization, partition, or payload-integrity failure may enter dead-letter handling immediately. Replay is instant but backpressured by the same batch, acknowledgment, database, and authorization limits.

The resource ordering key is the validated pair `(CloudEvent source, CloudEvent subject)`, where subject is the canonical resource URI. Dispatchers may serialize or consistently lane this key for efficiency, but correctness must survive duplicates and any delivery order. No consumer assumes global order, cross-stream order, wall-clock order, or an order between two resources. A consumer of an authoritative change treats the event as an invalidation/reference, not an unversioned authoritative delta: it obtains current owner state or applies an owner-supplied version/fence before a conditional projection update. Deletes use tombstones. Reverse-order and concurrent-delivery tests must converge on current authoritative state.

Each durable consumer contract has an owner-controlled PostgreSQL processed-event table. Its unique identity is `(consumer_contract_id, partition_generation, source_stream, cloud_event_id)`, with the payload digest, schema identity, source sequence, processing result, and checkpoint. In one owner transaction, the handler performs its conditional projection/state change, records the processed event, and appends any required audit/outbox intent. It acknowledges NATS only after commit. A repeated ID with the same digest is skipped and acknowledged; the same ID with a different digest is quarantined as an integrity failure.

External notification, provider, credential, export, or other durable effects reauthorize current resource/container/domain/label state and use the ADR-0005 durable effect-permit and downstream idempotency contract. Event possession, prior authorization metadata, a broker credential, a replay approval, or a processed-event row never grants authority. Denied or stale events produce no existence-leaking notification, count, activity, delivery, or diagnostic.

### Schema and payload enforcement

The relay and every consumer validate the CloudEvents envelope, registered type/channel relationship, exact allowed `dataschema` identity/digest, shared event data, account mapping, Organization, security domain, canonical subject/resource equality, and maximum size before use. The account tuple and payload tuple must agree. Unknown fields rejected by the registered schema, an unknown schema, unsupported major, invalid event-type/channel pair, malformed actor context, missing idempotency key, or payload above 64 KiB cannot reach a domain handler.

Events contain only canonical identifiers/references, effective label metadata required for routing and later recheck, safe actor/correlation/causation context, changed-field names, and bounded lifecycle metadata. They contain no protected body, comment/document text, prompt, memory, credential, token, signature material, provider locator, source code, attachment bytes, arbitrary exception text, or stack trace. Error classes and change fields come from closed registries.

Within one subject major, schema evolution is additive and backward compatible: an existing field cannot be removed, narrowed, reinterpreted, or made newly required for an already admitted producer. Consumers declare an exact supported schema set and digest. A breaking change creates a new subject/type/schema major and an explicit coexistence plan; it is never accepted by best-effort parsing. AsyncAPI plus referenced JSON Schemas is the sole channel/type/schema registry, and compatibility fixtures validate every producer and consumer before activation.

### Dead-letter and poison-message handling

Dead-letter records use `stead.dead_letter.recorded.v1` in the failing event's same account. They contain only the source account/stream/sequence, event ID/type/subject digest, payload digest, schema identity, consumer contract ID, bounded attempt count/timestamps, a closed failure-code and retryability value, correlation/causation references, and the authorized replay-request identity when applicable. They never embed the original payload, parser input, exception message, stack trace, credential, or protected body.

Before terminating or acknowledging a permanently failed delivery, the consumer atomically records its owner failure state and a dead-letter/audit intent in PostgreSQL. A crash before that commit leaves the source message eligible for redelivery; a crash after it is harmless through idempotency. Max-delivery advisories are observability signals, not the sole reliable DLQ trigger. Failure while processing a dead-letter lifecycle event records a bounded local operational error and alert; it does not recursively dead-letter the dead-letter event.

The original event remains in its source limit-retention stream until ordinary expiry. A dead-letter record is not authority and is not a copy of recoverable data. If its source event expires, the only recovery is an owner-authorized authoritative snapshot/projection rebuild or a new domain operation; the platform never fabricates the missing event.

### Authorized replay and projection rebuild

Replay is requested only through a Stead API/operator operation protected by central authentication, OpenFGA, deterministic policy, profile-qualified ceiling, current provider/path and revision/fence checks, and audit. The request binds one partition generation, consumer contract, source stream and sequence/event ID, expected payload/schema digests, bounded range or exact ID set, purpose, expiry, requester/actor, and maximum work. It cannot cross an account, Organization, security domain, consumer contract, or schema allowlist.

The replay worker rechecks the approval and current security state, retrieves the exact retained source message, verifies every binding, and invokes the same schema validation, authorization, idempotency, transaction, and effect-permit path as ordinary delivery. It does not republish the event to all consumers and cannot override a completed processed-event row without a separately authorized repair operation. Replay success/failure and resulting checkpoint are audited without payload content.

A projection rebuild uses a consumer-owner build generation: establish an authorized owner snapshot/checkpoint, load current canonical state through typed owner ports in bounded batches, validate and atomically switch the rebuilt generation, then consume retained events after the checkpoint. Events remain incremental transport, not the snapshot system of record. Unknown lag, a gap before the retained start, mismatched account generation, invalid schema, or stale authorization suppresses the projection until a safe rebuild completes. Search/activity/inbox counts never reveal suppressed rows.

### Observability, backup, and performance

Safe metrics cover outbox commit-to-publish acknowledgment, publish-to-consumer start, handler transaction, event-to-visible p50/p95/p99, bounded batch sizes, pending and age lag, redelivery, duplicate/collision, schema rejection, capacity rejection, dead-letter, replay, rebuild, and checkpoint age. Normal metric labels are low-cardinality stream class, consumer contract, result class, and deployment mode. Per-partition diagnostics require authorized drill-down and use opaque partition IDs. Logs/traces never record event payloads, canonical resource titles, labels, credentials, or raw errors.

Authoritative requests perform zero NATS operations and wait for zero relay/consumer acknowledgments. Relay and consumer work is bounded and batched; handlers use set-oriented authorization and database operations rather than per-row waterfalls. The standard fixture must demonstrate event-to-visible p95 at or below one second and the five-second release ceiling, plus stable SQL/write/OpenFGA/provider counts as batch cardinality grows.

Backup/restore treats JetStream as reconstructible transport. The required backup contains PostgreSQL authoritative state, pending outbox, processed-event/checkpoint state, declarative opaque account/stream/consumer manifests, and secret-reference metadata; account credential seeds are reprovisioned through the configured secret mechanism. A compatible JetStream snapshot may accelerate restore but never replaces those sources. Restore recreates accounts and streams, verifies ACLs/manifests, drains the outbox, and performs snapshot-plus-incremental projection rebuild tests before readiness. Air-gapped operation uses the same declarative state with no external broker control plane.

## Consequences

- Organization and security-domain isolation is enforceable without changing or leaking through the locked subject form.
- Phase 1 pays a bounded account-lifecycle and credential-management cost per Organization/domain pair; later scale evidence may justify a superseding partition ADR.
- Limit retention and `DiscardNew` favor visible backpressure and recoverable outbox lag over silent eviction.
- JetStream publish deduplication reduces common duplicates but PostgreSQL processed-event state remains the correctness boundary.
- Replays are consumer-specific, authorized, digest-bound, and idempotent; broker operators cannot turn message possession into product authority.
- Projection rebuild remains possible after stream expiry because authoritative owner snapshots, not indefinite broker history, define current state.
- No NATS backup or stream sequence is described as authoritative business data.

## Verification

Acceptance creates these future executable obligations; decision approval is not implementation evidence:

- `T-ADR-0008-SUBJECT-PARTITION`: provision two Organizations in one domain and one in another; prove opaque distinct accounts, exact locked subjects, tuple mismatch rejection, no imports/exports, and no cross-partition publication.
- `T-ADR-0008-SUBSCRIBER-ISOLATION`: enumerate effective NATS permissions and attempt cross-account, foreign-stream, wildcard, management, replay, and browser/provider subscriptions; all deny without existence leakage.
- `T-ADR-0008-RESOURCE-ORDERING`: inject duplicate, reverse, concurrent, delayed, restart, and cross-resource deliveries; current projection and activity semantics converge without a global-order assumption.
- `T-ADR-0008-RETENTION`: verify the four exact stream classes, subject disjointness, limits, `DiscardNew`, capacity backpressure, expiry, lag warnings, tombstone retention, and no silent outbox completion.
- `T-ADR-0008-IDEMPOTENCY`: lose publish and consumer acknowledgments inside/outside the duplicate window; prove one durable effect, atomic processed state, digest-collision quarantine, and safe restart.
- `T-ADR-0008-DLQ`: inject transient, permanent, malformed, oversized, unsupported, and recursive failures; prove bounded redelivery, durable minimized record before termination, original-source retention, and zero protected/error body.
- `T-ADR-0008-AUTHORIZED-REPLAY`: deny direct broker replay, expired/foreign/mismatched approvals and changed authorization; prove an exact authorized replay uses the ordinary handler/idempotency/effect path and is audited.
- `T-ADR-0008-SCHEMA-COMPATIBILITY`: validate every registered type/channel/schema digest, compatible additive evolution, unsupported-major quarantine, dual-major migration, consumer rollback, and forbidden tolerant parsing.
- `T-ADR-0008-PAYLOAD-MINIMIZATION`: canary protected bodies, titles, comments, document text, prompts, memory, credentials, provider locators, raw exceptions, and labels through event/DLQ/log/trace/metric paths; every forbidden value is absent.
- `T-ADR-0008-PROJECTION-REBUILD`: rebuild from owner snapshot plus checkpoint and retained events under duplicates, gaps, stale labels, NATS loss, restore, and rollback; invalid generations never become visible.

`STEAD-P1-007` owns the partition/relay/consumer/dead-letter/replay implementation cases. `STEAD-P1-008` consumes the ordering, idempotency, schema, minimization, and rebuild contracts for search/graph. `STEAD-P1-012` independently reruns every complete test. Performance evidence records response NATS waits, publish/visible latency distributions, SQL writes/queries, authorization/provider calls, batch cardinality, lag, payload size, and regression versus the accepted baseline.

## Rollout and supersession

1. Accept this decision at one immutable revision with every named non-author review; keep dependent implementation blocked until then.
2. Land the WS-07-owned AsyncAPI/header/data/config contracts and compatibility/negative fixtures before NATS implementation.
3. Provision declared accounts and four streams, then start schema-validating consumers from an explicit checkpoint before enabling outbox relay.
4. Enable relay with publish acknowledgments and compare outbox, stream, consumer, and processed-event checkpoints; no request path changes.
5. Exercise capacity failure, restart, poison, replay, NATS-total-loss, snapshot rebuild, backup/restore, and version rollback before promotion.
6. For a new event major, create new subjects/streams and deploy dual-readable consumers first; dual-publish only when the reviewed migration explicitly requires it. Remove the old major only after all consumers, replays, rollback windows, and retained outbox records prove safe.

Rollback restores the last accepted declarative manifest and compatible consumers while preserving PostgreSQL outbox, processed-event, dead-letter, and audit state. It never deletes an acknowledged authoritative mutation. If the old consumer cannot understand retained data, stop consumption and recover forward. A superseding decision must include account/subject migration, cross-domain non-transfer proof, replay and backup compatibility, performance evidence, and project-owner approval if it changes a locked subject, broker, or security-domain decision.

## Reviews and approvals

Required decision-time dispositions against the exact immutable decision revision:

- WS-07 event/worker owner: pending.
- WS-01 architecture/standards: pending.
- WS-02 core/outbox integration: pending.
- WS-06 authorization/classification/security: pending.
- WS-08 search/projection consumer: pending.
- WS-12 operations/backup/restore: pending.
- distinct WS-13 independent QA reviewer: pending.
- distinct WS-13 independent security reviewer: pending.
- Project owner: not required unless review changes a locked or project-owner-controlled decision; this proposal does not.

Until all required non-author dispositions accept one immutable revision and the acceptance-only descendant is recorded, this ADR remains proposed and `STEAD-P1-007` remains blocked.
