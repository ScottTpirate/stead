# Events, activity, notifications, and audit contract

Status: **Phase 0 approval candidate**
Requirements: `EVT-001`–`EVT-004`, `ACT-001`, `NOTIF-001`–`NOTIF-002`, `AUD-001`–`AUD-002`, `AGENT-004`

The normative event skeleton is [AsyncAPI](../../specs/asyncapi/stead.yaml), with shared [actor context](../../packages/event-schemas/common/actor-context/actor-context-v0.1.schema.json) and [data schema](../../packages/event-schemas/stead/stead-event-v0.1.schema.json).

Concrete event types and NATS subjects use `stead.<domain>.<action>.v<major>`; for example, `stead.workitem.updated.v1`. The earlier placeholder namespace had no production consumers, so this is a pre-compatibility normalization: no dual-publish period, consumer migration, or compatibility alias is required.

AsyncAPI enumerates the complete Phase 0 event-family catalog: organization/team, identity/agent, authorization, classification, project/initiative/cycle, Work Item, comment, knowledge, SCM, CI, artifact/package/release, attachment, storage, search/graph lifecycle, notification, audit lifecycle, migration, operations, and controlled dead letter/replay. Its 74 declared event types are schema-bound to exactly one of 19 channel families; every family defines send and receive operations. Each declared type uses the shared versioned JSON data schema unless a later compatible specialization is added.

Domain changes and outbox inserts are one transaction. The worker publishes CloudEvents to versioned NATS subjects with at-least-once delivery. Durable consumers use idempotency/processed-event state, assume only per-resource order, tolerate replay/out-of-order delivery, and route permanent failures to an authorized DLQ. NATS, Activity, Inbox, Search, and Audit views are not business systems of record.

Events carry minimal canonical resource/container/label metadata, actor and principal type, different requester when present, delegation/task context, correlation, causation, and a required idempotency key. Capability context is optional, authorization-filtered, and omitted when irrelevant or not visible. Protected bodies, prompts, memories, credentials, and secrets are prohibited.

Activity and notifications are generated only after authorization/classification checks and are rechecked at read/delivery time. Unauthorized entries, counts, reasons, thread membership, and external-channel payloads are suppressed or safely redacted. Audit is append-only, records decisions and controlled deltas/hashes, and supports authorized export and future tamper-evident checkpoints.

Schema evolution is backward compatible within v1. Breaking changes require a new subject/schema major, explicit dual-publish/dual-read window, replay validation, consumer migration, and rollback without losing acknowledged domain changes.
