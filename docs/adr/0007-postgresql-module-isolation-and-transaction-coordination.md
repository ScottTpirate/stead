# ADR-0007: PostgreSQL module isolation and transaction coordination

- **Status:** Proposed
- **Date:** 2026-08-30
- **Decision owners:** WS-01, with WS-02 transaction/core-outbox integration, WS-06 security-state ownership, WS-07 audit/event integration, and WS-12 migration/operations ownership
- **Project-owner approval required:** no; this selects physical mechanics within the approved modular-monolith, PostgreSQL-authority, namespace-ownership, transactional-outbox, and authorization contracts without changing a locked decision or project-owner-controlled contract
- **Requirement IDs:** `PRIN-005`, `ARCH-003`, `ARCH-004`, `EVT-002`, `AUD-001`, `AUD-002`, `DEP-005`, `OPS-003`, `OPS-004`, `PERF-003`, `PERF-004`, `TEST-005`, `TEST-007`
- **Affected contracts/modules/directories:** PostgreSQL access beneath `/apps/core/` and `/apps/worker/`; module-owned repositories and migrations; `/apps/core/internal/outbox/`; `/apps/steadctl/`; deployment, migration, upgrade, backup/restore, integration, security, event, and performance tests
- **Resolves on acceptance:** `ADR-CAND-002`
- **Supersedes / superseded by:** supersedes no accepted decision; a database-per-module topology, changed namespace owner, direct cross-module table access, or general distributed-transaction mechanism requires a superseding ADR

## Context and decision scope

The [Master Build Directive](../architecture/MASTER_BUILD_DIRECTIVE.md) already fixes PostgreSQL as authoritative Stead storage, a Go modular monolith plus workers, module-owned tables and migrations, stock Gitea and OpenFGA datastore boundaries, and an atomic domain-change-plus-outbox write. The [contract ownership matrix](../architecture/contract-ownership-matrix.md) fixes every logical namespace and write owner. This record chooses only the physical PostgreSQL namespace, role, migration, read, and transaction mechanics left open by `ADR-CAND-002`.

[ADR-0005](./0005-authorization-and-policy-decision-topology.md) requires one typed final authorization/audit operation, owner-only domain writes, a transaction-scoped `core_outbox` port, durable `AuthorizationEffectPermit` persistence for stronger effects, and typed but not yet fully implemented `commit_boundary` coordination seams. [ADR-0006](./0006-signed-policy-bundle-distribution-and-activation.md) requires an atomic PostgreSQL activation-pointer/audit-intent commit without pretending that PostgreSQL, OpenFGA, or the external monotonic anchor share a transaction. This decision supplies those local mechanics and does not reinterpret either ADR.

The decision does not select domain tables, event subjects or retention, provider reconciliation, a migration library, a database driver, a user-facing authorization rule, or a new product concept. It does not make PostgreSQL roles or row-level security a substitute for OpenFGA plus the deterministic policy-decision layer. It does not persist `BoundedReadGuard`, serving-lease, replica-quiescence, `DisclosureEgressFence`, transport-buffer, or terminal-proof state in Phase 1 merely to reserve the strict seam.

## Decision drivers

- Preserve the fixed table/migration owner for every module and make accidental foreign DDL or DML fail at the database boundary.
- Keep the modular monolith simple to install, back up, restore, and operate in local, external-PostgreSQL, and Kubernetes profiles.
- Permit one real PostgreSQL transaction for an owning module's mutation, authorization-fence work through its owner, and the WS-02-owned outbox insertion without exposing another module's tables.
- Keep cross-module reads set-oriented and fast while preventing base tables from becoming an informal API.
- Keep PostgreSQL transactions short and exclude NATS, Gitea, OpenFGA, BlobStore, and other network effects from them.
- Support expand/migrate/contract upgrades, compatible rollback, deterministic recovery, and whole-database backup evidence.
- Preserve the Phase 1 `request_boundary` performance path and durable-effect storage without prebuilding later high-assurance coordination.

## Considered options

1. **One Stead PostgreSQL database, one schema and role set per fixed logical namespace, owner-scoped migrations, typed transaction participants, and explicit read projections.** This preserves local transactions and joins, materially constrains foreign writes, minimizes deployment components, and keeps one backup/restore unit. Its application composition root remains trusted to select the correct role and port. Accepted.
2. **A separate database or service per module.** This creates stronger physical isolation from an in-process fault, but requires distributed consistency, more credentials/pools/backups, cross-database read infrastructure, and materially more operational work before evidence shows a need. It works against `PRIN-005` and prevents the simple atomic outbox path. Rejected for Phase 1.
3. **One `public` schema with table-name prefixes.** This is initially easy but makes ownership grant patterns fragile, increases name collision and search-path risk, and does not provide an enforceable migration boundary. Rejected.
4. **One shared owner/runtime role and unrestricted cross-schema SQL.** This uses the fewest roles but makes every module, migration, support command, and injection defect capable of changing every table. Static conventions alone do not satisfy the fixed database ownership contract. Rejected.
5. **Cross-module foreign keys, triggers, direct base-table joins, or writable shared views as the integration mechanism.** These can be fast locally but let one module's migration or runtime path control another module's state and create hidden ordering/cascade behavior. Rejected. Reviewed read-only contracts and consumer-owned projections retain local efficiency.
6. **A general XA/two-phase-commit, saga, command-bus, or distributed-transaction framework.** PostgreSQL cannot make Gitea, OpenFGA, NATS, the monotonic anchor, or BlobStore one atomic resource, and the slice does not justify a general framework. Rejected. Required external effects use explicit pending/fence, idempotency, outbox, and reconciliation contracts owned by their issues.
7. **Persist strict serving, guard, quiescence, and egress state now.** This would pre-design the later `commit_boundary` runtime and add write amplification to the standard path. Rejected for Phase 1; only the accepted typed ports remain.

## Decision

### One database and exact schema namespaces

Every Phase 1 deployment has one PostgreSQL database for Stead platform state, conventionally named `stead`. It contains one non-public schema for each fixed logical namespace:

| PostgreSQL schema | Fixed write/migration owner |
|---|---|
| `organization`, `project`, `work`, `core_outbox` | WS-02 |
| `identity`, `authorization`, `classification` | WS-06 |
| `knowledge` | WS-04 |
| `scm` | WS-03 |
| `ci`, `artifact` | WS-09 |
| `search` | WS-08 |
| `notification`, `audit` | WS-07 |
| `migration` | WS-11 |

Consumer processed-event tables live in the destination owner's existing schema. No additional shared application-data schema is created. `public` has `CREATE` revoked from application and runtime roles and contains no Stead table, view, function, sequence, or mutable type. Application SQL schema-qualifies every object and runs with a search path that does not select a writable application schema.

The `stead` database may run on a bundled or external PostgreSQL deployment without changing this contract. Gitea and OpenFGA retain their separately owned database/schema boundaries and credentials; no Stead role receives privileges on their internal objects. A label-profile ID, deployment profile name, or administrator choice does not silently select a different module topology. Evidence that a supported assurance profile needs database-per-module isolation requires a superseding ADR with migration, performance, backup, and rollback proof.

Tables, indexes, sequences, constraints, views, and functions use lower-case `snake_case` names inside their owner schema and are never distinguished only by a module prefix in `public`. Cross-schema foreign keys, cascades, triggers, writable views, event triggers, `dblink`, foreign-data-wrapper access, and direct DML are prohibited. Cross-module references use canonical IDs and owner ports; consumer projections preserve source IDs and revision/fence metadata. A source owner may supply a read contract as described below, but never grants ownership or write privilege to the consumer.

### Database roles and connection discipline

Each schema has these non-login roles:

- `stead_owner_<schema>` owns the schema and every object in it. Only the controlled migration path may assume it.
- `stead_rw_<schema>` receives only the table, sequence, and function privileges required by that schema's owner-authored repositories. It cannot create, alter, drop, truncate, reassign, or grant objects.
- A narrowly named `stead_ro_<source>_<consumer>_<purpose>` role may receive `SELECT` on an explicitly approved, versioned read view. It receives no base-table privilege.

Long-running login roles such as `stead_api` and `stead_worker` are `NOINHERIT`, have no direct table privileges, and may assume only the execution roles required by their registered modules. They are not superusers and have no `BYPASSRLS`, `CREATEDB`, `CREATEROLE`, replication, database ownership, schema ownership, or upstream-database privilege. The operator-only migration login is separate, is not mounted into a running API or worker, and may assume an owner role only while the signed release migration plan is executing. Default privileges are owner-authored and revoke access from `PUBLIC` before granting the exact runtime or read role.

The composition root owns a bounded pool per deployable login, not an unbounded pool per schema. Every repository operation runs inside an explicit PostgreSQL transaction. The transaction coordinator selects a fixed `SET LOCAL ROLE`, local statement/lock/idle-transaction timeouts bounded by the request or operation deadline, and a non-writable search path before giving a module implementation a scoped query executor. Transaction end automatically clears the role and settings before the connection returns to the pool. Module public contracts never expose a driver connection, `database/sql` transaction, driver-specific transaction, role-changing primitive, or arbitrary cross-schema executor. SQL is parameterized; application-controlled SQL fragments, multi-statement user input, and session-level role changes are prohibited.

These roles constrain repositories and migrations; they are not a claim of hostile-process isolation inside one modular-monolith process. The composition/database adapter is part of the trusted computing base. Forbidden-import, SQL-scope, catalog-privilege, and runtime negative tests prove that ordinary module code cannot obtain its pool or execute under a foreign role.

### Module-owned migrations and ordering

Each owner stores immutable, monotonically numbered PostgreSQL migration files with its module or owned core component. Each schema contains its own owner-controlled `_schema_migrations` ledger recording migration ID, source checksum, release/build identity, phase, applied time, and clean/dirty result. A released migration is never edited in place; a correction is a new migration. There is no writable global migration table owned by all modules.

The release carries one machine-readable migration plan assembled from owner registrations. For every migration it declares the schema owner, checksum, dependencies, `expand`, resumable `backfill/verify`, or `contract` phase, whether it is transactional, binary compatibility range, and whether a tested reverse operation exists. `steadctl upgrade` invokes the server-owned migration runner, obtains one database-scoped advisory lock, verifies the current per-schema vector and checksums, topologically sorts the declared acyclic dependencies, and assumes exactly one owner role at a time. A dirty, unknown, checksum-mismatched, cyclic, or incompatible state blocks readiness and upgrade.

DDL and DML stay in the migration's owned schema. A cross-module data change is split into owner-authored migrations coordinated by dependency declarations and typed export/read or command ports; no migration edits a foreign schema. Backfills are bounded, checkpointed, resumable, idempotent, and complete before contract. Migrations run transactionally unless PostgreSQL forbids the required online operation. A non-transactional migration must be explicitly declared, have pre/postconditions and a resumable failure path, and may not be grouped with an authoritative state transition that claims atomicity.

Expand/migrate/contract is mandatory for a rolling or rollback-compatible change: expand creates additive state; compatible writers/readers coexist; backfill and verification complete; only after the supported rollback window may contract remove the old representation. Cross-module read views and typed contracts version and coexist by the same rule. Database triggers are not used to hide dual writes across owners or to append the outbox.

### Transaction ownership and coordination

The normal unit of work has one authoritative write owner. WS-02 supplies a typed `WithinTransaction` coordinator that owns `BEGIN`, role selection, participant ordering, commit, and rollback. Before the transaction starts, the caller declares a closed participant plan. Each participant is a module-owner implementation invoked through its typed port; it executes only owner-authored statements under that owner's runtime role. Participants run serially on the connection in the registered acyclic order, no participant is added after the first write, and `core_outbox` is the final write participant before commit. Any participant error, cancellation, timeout, stale version, authorization-fence mismatch, or outbox failure rolls back the whole transaction.

Ordinary domain mutations use PostgreSQL `READ COMMITTED`, explicit optimistic versions/ETags, conditional updates, and targeted row locks for the invariant being changed. Stronger isolation is opt-in per reviewed operation, not a platform-wide default. No transparent transaction retry is allowed after a decision boundary, outbox/audit intent, permit consumption, provider call, external effect, or disclosure. A deadlock or serialization failure normally returns a retryable, non-disclosing error so the complete idempotent operation can obtain a fresh authorization decision. A narrowly proven pre-effect callback may be retried only within its original deadline and idempotency contract.

A cross-module atomic write is exceptional and must be named by its implementation issue. It may use the same local PostgreSQL transaction only through registered owner participants; the coordinator contains no domain SQL and an owner never writes another owner's table. The Phase 1 authorization/audit operation, domain-change-plus-outbox operation, durable-permit-plus-outbox operation, and ADR-0006 activation-pointer-plus-outbox operation are the intended initial cases. There is no generic public unit-of-work API, arbitrary participant discovery, nested independent commit, or module-controlled transaction commit.

No PostgreSQL transaction remains open while calling NATS, Gitea, OpenFGA, a policy artifact transport, BlobStore, an identity provider, or another network service. Required cross-store sequences first persist owner-controlled pending/fence/idempotency state where their accepted contract requires it, perform the external operation outside the local transaction, verify or reconcile the result, then commit the next owner-controlled state transition and outbox intent. PostgreSQL and an external system are never described as atomically committed together.

### Core outbox and audit handoff

`core_outbox` remains solely WS-02-owned. Domain and security modules receive only a typed transaction-scoped append port. Its implementation temporarily runs the WS-02 repository participant under `stead_rw_core_outbox` on the caller's existing transaction; callers receive neither that role nor raw table access. The append validates the versioned, immutable WS-07-owned audit/event intent and records it in the same commit as the authoritative local mutation. A failed append fails the transaction.

WS-07 receives a separate reviewed delivery-repository port implemented under WS-02 ownership. It exposes bounded claim, success, release/retry, and diagnostic operations needed by the relay, but not arbitrary SQL or delete/truncate authority. Claiming uses bounded batches and safe concurrent ownership; the exact NATS subject, stream, retention, ordering, retry, and DLQ rules remain controlled by `ADR-CAND-006`. NATS availability and consumer completion are never part of a request transaction or response barrier.

For one finite composed `request_boundary` read, the coordinator may use one final logical PostgreSQL operation to perform the ADR-0005 revision/time checks and append at most one safe aggregate audit intent through the outbox port. It does not create a transaction, audit row, or permit per returned row, panel, relationship, or internal query. The protected response begins only after that operation commits. WS-07 later materializes the append-only `audit` record idempotently from the durable intent; the undelivered intent remains recoverable evidence while NATS is unavailable.

### Cross-module reads and local read models

The default cross-module read is a typed owner port. Direct `SELECT` on another module's base table is prohibited even when two modules share a workstream. When a measured composed-read path needs one local set-oriented join, the source owner may publish a versioned, read-only view containing only the reviewed columns and fence/version fields. The source owner owns its migration and grants `SELECT` only to one named purpose role; the consuming repository owns the query and receives no base-table, function-execution, or write privilege. The view is a data contract, not an authorization decision, and cannot expose protected rows before the ADR-0005 set-oriented authorization and final fence.

For asynchronous or fan-in use, the consumer instead owns a local rebuildable projection in its own schema, populated through versioned events and carrying source revision/fence state. Search, activity, and analytics projections never become authoritative. Lagging, unknown, or authorization-relevant stale projections suppress protected results until caught up. Joins are permitted across a module's own tables and approved read views or consumer-owned projections; unrestricted cross-schema base-table joins are not.

Every approved read path declares source owner, consumer, purpose, columns, consistency/staleness behavior, authorization scope, migration/coexistence version, query-count budget, and removal plan. This permits efficient PostgreSQL joins and read models without turning physical colocation into shared ownership.

### Durable effects and the strict-mode seam

ADR-0005 `AuthorizationEffectPermit` rows live in the WS-06-owned `authorization` schema and change only through the WS-06 port. Issuance and each authority-changing transition use the transaction coordinator when an immutable audit/outbox intent must commit with the state change. Provider calls and credential materialization occur only after the applicable permit/audit transaction commits and outside that transaction. Ambiguous results remain durable and idempotently reconciling; they are not converted to success by a database retry or process restart.

Phase 1 creates no PostgreSQL table for ephemeral `BoundedReadGuard` or response sessions and does not infer schemas for serving leases, replica quiescence, `DisclosureEgressFence`, buffer ownership, epochs, or terminal proof. The typed ports selected by ADR-0005 remain compile-time seams; `commit_boundary` activation denies until its later implementation and separately reviewed persistence/evidence are complete. This record therefore enables durable effects without making strict-mode storage a prerequisite for the standard path.

## Consequences

### Security, authorization, classification, and bypass paths

Schema roles make foreign DDL/DML and base-table reads fail by default, limit migration/runtime blast radius, and keep Gitea/OpenFGA internals unreachable. They do not authorize a person, Agent, service account, resource, label, or operation. Every protected API, BFF, worker, migration, backup, restore, repair, projection, and provider path retains the central OpenFGA plus deterministic policy-decision, profile-qualified ceiling, provider/path, revision-fence, non-disclosure, and audit requirements. Runtime roles are never chosen from a security-label profile or user-controlled value.

No support utility, importer, analytics job, MCP server, test harness, `steadctl` command, or database administrator convenience path receives ordinary foreign-table write access. Repairs are owner-authored migrations or typed owner operations and are audited. PostgreSQL row-level security may be added only as defense in depth under an owner-reviewed design; it cannot replace, cache, weaken, or independently reinterpret the central decision.

### Data model, migration, and backward compatibility

Logical namespace owners do not change. The one-to-one schema mapping makes the Phase 0 ownership map executable and leaves public API, canonical resource, JSON Schema, OpenFGA, policy, event, and provider contracts unchanged. Module migration vectors and read-contract versions are internal compatibility inputs, not new product resources.

Old and new binaries may coexist only while every touched schema and read contract declares both compatible. An unknown migration or contract version fails readiness. No cross-schema cascade or trigger can silently change another module during coexistence. Projection tables remain disposable and rebuildable; authoritative tables, `core_outbox`, durable permits, activation state, migration ledgers, and append-only audit records are retained according to their owning contracts.

### Upgrade, rollback, backup, restore, and recovery

Upgrade performs compatibility/capacity preflight, verifies a recoverable backup, acquires the migration lock, applies expand and bounded backfill/verification in dependency order, upgrades services in safe order, runs contract and smoke tests, and schedules contract only after the rollback window. Each step records safe schema/migration/checksum/outcome evidence through the audit/outbox path without copying SQL parameters or protected row contents.

Binary rollback is allowed while the prior binary accepts the current migration vector and no contract phase removed its representation. A tested reverse migration may run only when it is declared non-destructive and restores all invariants. Otherwise the system remains on the expanded schema and uses forward recovery; `steadctl` must not improvise a down migration. Authorization, activation sequence, policy-time, revocation, label, explicit-deny, or external-anchor state is never lowered by database rollback.

The supported backup unit for Stead PostgreSQL is the whole `stead` database at one consistent snapshot/WAL point, including every authoritative module schema, per-schema migration ledger, `core_outbox`, durable permits, activation/fence state, and audit data. Selective authoritative-schema restore is unsupported unless a later owner-approved recovery plan proves all references and fences. WS-12 coordinates this snapshot with Gitea, OpenFGA, Git, BlobStore, configuration/policy, and other required stores using their owned maintenance/checkpoint interfaces; it does not claim a cross-store transaction or rely on NATS history. Temporary backup maintenance/quiescence is an operations mechanism and does not implement the ADR-0005 `commit_boundary` egress guarantee.

Restore runs with protected writes disabled, restores the whole database and ownership/ACL state, verifies every schema checksum/vector and the separately retained ADR-0006 monotonic anchor, then replays undelivered outbox work and rebuilds/reconciles projections. It preserves IDs, relationships, permissions, labels, Work/Docs/provider mappings, audit evidence, and canonical URLs. Missing or older authority/fence/anchor evidence keeps protected services unready and requires forward recovery; an old backup cannot resurrect a revoked authority or discarded explicit deny.

### APIs, schemas, events, providers, and standards mappings

No public API or serialized canonical schema changes. Cross-module Go ports retain stable semantic names; read-view and migration formats are explicitly versioned compatibility boundaries. Event payload and NATS semantics remain WS-07-owned and are not encoded in database grants. Provider adapters continue to use supported APIs/protocols and receive no Stead, Gitea, or OpenFGA database shortcut.

### Observability, audit, privacy, and evidence

Safe metrics and traces report transaction p50/p95/p99, stable statement/query count and time, PostgreSQL write count, rollback/error/deadlock/serialization count, lock and pool wait, participant count, role-scope failure, outbox append/claim/relay lag, permit row transitions, migration duration/state, backup/restore duration, and schema-vector health. Module/schema and stable statement IDs may be bounded labels; Organization, principal, resource, URI, label/compartment, SQL parameter, response digest, provider credential, and migration row contents may not be metric labels or telemetry bodies.

Audit covers migration/role/grant changes, transaction failure after an audit precondition, foreign-access attempts, activation/policy transactions, permit transitions, backup/restore, rollback/forward recovery, outbox relay/replay, and repair operations. It records safe migration IDs/checksums, actor/requester context, outcome, correlation/causation, applicable revisions, and reason-safe failure codes without secrets, protected bodies, raw policy input, tuples, or SQL parameter values.

Every performance-sensitive implementation reports the endpoint or browser scenario, p50/p95/p99, SQL query count, PostgreSQL write count, OpenFGA calls, provider calls, response size, frontend chunk impact, and comparison with the current baseline. Database work must remain set-oriented with constant query/authorization/write counts as returned rows grow. Ordinary reads wait for zero NATS consumers and make zero synchronous provider business calls. This ADR itself adds no frontend bytes.

### Dependencies, licenses, supply chain, and portability

The decision requires only supported PostgreSQL roles, schemas, transactions, advisory locks, views, and catalog inspection. It does not select or add a migration framework, proxy, connection pooler, FDW, distributed-transaction library, cloud service, or proprietary database feature. The eventual Go driver and migration implementation require normal pinned dependency, license, vulnerability, provenance, and SBOM approval. The same logical design works with bundled and external PostgreSQL and with network access disabled after installation artifacts are present.

### Documentation and accessibility

Contributor documentation must describe schema/role ownership, the scoped transaction executor, registered participants, SQL and migration rules, read-contract registration, outbox access, and prohibited cross-schema paths. Operator documentation must describe effective role grants, migration vectors/checksums, preflight, dirty-state recovery, backup/restore, compatible rollback versus forward recovery, and `steadctl doctor` output. CLI and reports use copyable identifiers, explicit status text rather than color alone, and no protected content.

## Verification

Decision acceptance approves these mechanics and future evidence obligations; it does not claim that implementation tests already exist or pass. Dependent issues must add the named tests and traceability links:

- `T-ADR-0007-NAMESPACE-ROLES`: catalog tests create the exact schemas and owner/runtime roles; prove `public` is locked down; prove runtime logins have no direct inherited privilege; and prove Stead roles cannot query or mutate Gitea/OpenFGA objects.
- `T-ADR-0007-FOREIGN-WRITE-DENIAL`: for every module and worker role, attempts to insert, update, delete, truncate, alter, drop, grant, copy into, trigger, or call a foreign write function fail; only the owner migration path and registered owner participant succeed. Repair, importer, test, analytics, and CLI identities receive no bypass.
- `T-ADR-0007-TRANSACTION-PORTS`: compile-time and integration tests prove raw driver connections/transactions and role-changing primitives do not cross module public contracts; declared participants run under the right role/order on one transaction; cancellation, timeout, stale version, or participant failure rolls back all local writes.
- `T-ADR-0007-OUTBOX-ATOMICITY`: crash and error injection before/after domain, authorization, activation-pointer, durable-permit, and `core_outbox` statements proves each accepted local mutation and its immutable intent commit together or neither commits. NATS outage does not delay the response or lose the intent, and WS-07 can claim/mark only through the reviewed WS-02 port.
- `T-ADR-0007-CROSS-MODULE-READS`: foreign base-table `SELECT` fails; typed ports, explicitly granted versioned views, and consumer-owned projections return only declared fields/fences; set-oriented join query counts remain constant as rows grow; stale protected projections suppress rather than leak.
- `T-ADR-0007-DURABLE-EFFECTS`: WS-06-owned permit issuance/transitions and required outbox intents are atomic, provider effects occur only after commit, ambiguous outcomes survive restart for reconciliation, ordinary composed reads create no permit rows, and Phase 1 creates no strict guard/quiescence/egress persistence.
- `T-ADR-0007-MIGRATION-ORDERING`: per-schema checksum ledgers, one advisory lock, dependency topological order, exact owner role, transactional rollback, non-transactional resume, bounded backfill, dirty-state denial, and cycle/unknown/checksum mismatch rejection pass without foreign DDL/DML.
- `T-ADR-0007-UPGRADE-ROLLBACK`: expand/coexist/backfill/verify/contract tests run across supported binaries; compatible pre-contract rollback succeeds; an incompatible or destructive target blocks rollback and produces an audited forward-recovery plan.
- `T-ADR-0007-BACKUP-RESTORE`: a representative whole-database backup/restore preserves all authoritative schemas, ACLs, migration vectors, IDs, relationships, permissions, labels, outbox/permit/activation/audit state, and canonical mappings; the restored system revalidates the external anchor, replays undelivered intents, rebuilds projections, and remains denied on stale or missing authority evidence.
- `T-ADR-0007-FAILURE-INJECTION`: database loss, disk full/read only, pool exhaustion, lock/deadlock/serialization failure, process crash at every transaction/migration/restore boundary, and partial external-operation sequences yield rollback, durable pending/reconciliation state, or fail-closed unready behavior without acknowledged-write or mandatory-audit loss.
- `T-ADR-0007-OBSERVABILITY-PERFORMANCE`: the standard `request_boundary` benchmark publishes p50/p95/p99, stable SQL/query/write/participant/pool/lock counts, OpenFGA/provider calls, response size, outbox/projection lag, and baseline delta; it proves one composed request, at most one logical authorization/audit transaction, no per-row work, no NATS wait, and no frontend bundle impact.

These tests complement, rather than replace, `T-ADR-0005-SEQUENCE`, `T-ADR-0005-FENCE`, `T-ADR-0005-REQUEST-BOUNDARY`, `T-ADR-0005-COMMIT-BOUNDARY-SEAM`, `T-ADR-0005-MIGRATION-ROLLBACK`, `T-ADR-0006-ATOMIC-ACTIVATION`, `T-ADR-0006-FAILURE-INJECTION`, `T-ADR-0006-BACKUP-RESTORE`, `T-EVT-002-ACCEPTANCE`, `T-TEST-005-ACCEPTANCE`, and `T-TEST-007-ACCEPTANCE`.

## Rollout and supersession

1. Implement role/schema bootstrap, catalog privilege tests, the scoped PostgreSQL transaction adapter, and owner migration registration behind deny-only health checks.
2. Implement `core_outbox` migrations and WS-02 append/delivery repository ports; prove the domain/authorization/activation/permit atomicity fixtures before a producer activates.
3. Add module schemas and migrations only when their dependency-ready issues activate. Add typed read ports first; approve a read view or consumer projection only from measured query evidence.
4. Run expand/coexistence, crash recovery, NATS-outage, backup/restore, supported upgrade/rollback, and `steadctl doctor` tests on the same candidate before Phase 1 release.
5. Keep `commit_boundary` persistence and activation disabled until the separately gated strict implementation supplies its complete typed-port, egress, lease, epoch, buffer, recovery, and performance evidence.

Abort rollout on a foreign privilege, unowned migration, mutable released checksum, cross-schema DML/trigger/cascade, raw outbox access, partial domain/audit commit, open transaction around a network call, unknown migration vector, failed restore, N+1 regression, protected telemetry, or strict-mode fallback. Pre-production rollback removes only unreleased bootstrap/migration work. After persisted data exists, rollback follows the compatible coexistence rule above or uses forward recovery.

This proposed record targets `main` only after acceptance at one immutable revision and all required non-author reviews below. A future superseding ADR may choose physical database separation, additional defense-in-depth controls, or strict coordination persistence only with measured security/correctness benefit, a portable migration path, cross-store failure semantics, performance evidence, backup/restore, coexistence, and rollback. Changing a fixed namespace owner, upstream boundary, authoritative store, or another locked/project-owner-controlled contract also requires explicit project-owner approval.

## Reviews and approvals

Review accepts this decision at one exact immutable revision; it does not approve dependent migrations, implementation, release evidence, or another ADR. The author cannot self-approve. Independent QA and independent security must be distinct non-author identities.

| Role | Identity | Disposition | Evidence/date |
|---|---|---|---|
| Decision author (WS-01) | `/root/adr_cand_002` | PROPOSED | 2026-08-30; focused `ADR-CAND-002` draft for live issue 18 |
| Architecture and standards (WS-01, non-author) | pending non-author reviewer | PENDING | Topology, boundary, compatibility, and supersession review required |
| Core transaction/outbox owner (WS-02) | pending non-author reviewer | PENDING | Transaction role/participant, one-operation, and `core_outbox` review required |
| Identity/authorization/classification owner (WS-06) | pending non-author reviewer | PENDING | Fence, permit, role, classification, and non-disclosure review required |
| Events/audit owner (WS-07) | pending non-author reviewer | PENDING | Intent ownership, relay-port, idempotency, replay, and audit review required |
| Deployment/operations owner (WS-12) | pending non-author reviewer | PENDING | Migration, upgrade, backup/restore, external-PostgreSQL, and recovery review required |
| Independent QA (distinct WS-13 identity) | pending non-author reviewer | PENDING | Exact test obligations, traceability, failure injection, and performance review required |
| Independent security (distinct WS-13 identity) | pending non-author reviewer | PENDING | Database privilege, bypass, backup, restore, and protected-telemetry review required |
| Project owner | not required for this conforming selection | N/A | Required only if review changes a locked or project-owner-controlled contract |
