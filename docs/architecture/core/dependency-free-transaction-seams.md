# Dependency-free core transaction seams

Status: bounded `P1-015-CORE-PORTS` implementation contribution. This is not complete `STEAD-P1-015`, ADR-0005, or ADR-0007 evidence.

## Scope and ownership

The Go packages under `apps/core/internal/transaction` and `apps/core/internal/outbox` are the WS-02 composition boundary. Go's `internal` rule prevents domain, security, provider, worker, CLI, and test-harness packages outside `apps/core` from importing them. The whole `apps/core` subtree remains trusted WS-02 integration code; this boundary does not claim hostile-process isolation inside the modular monolith.

This slice uses only the Go standard library and local packages. It opens no database or network connection and imports no database driver, OpenFGA, NATS, provider, module implementation, browser, or frontend code.

Internal handoff versions are exact:

- `stead.core.transaction-coordinator/v1`
- `stead.core.validated-intent-handoff/v1`
- `stead.core.bound-revision-handoff/v1`
- `stead.core.durable-effect-handoff/v1`

Missing, empty, forged, stale, expired, reused, cross-registry, or incompatible values deny.

## Closed transaction plan

Startup registration supplies a complete participant total order and its backward-only dependencies. Registration is deep-copied and frozen before use. Coordinator construction adds the final-read and durable-effect singleton plans as reserved templates in a coordinator-owned registry snapshot; a caller cannot see, replace, or collide with them. Those handoffs bind only request-local opaque result storage and a resulting intent source, then execute through the same registry-minted single-use plan. They never construct, replace, or add a runtime participant. An operation invocation otherwise selects one registered key and zero or one immutable intent; it cannot supply participants, discover them, add one after execution begins, choose a PostgreSQL role, or obtain a lifecycle handle.

The coordinator alone calls the trusted WS-02 lifecycle adapter to begin, commit, or roll back. That adapter contract is under Go's `apps/core/internal` import wall, and no coordinator method returns its session or exposes a generic caller-facing unit of work. Owner callbacks receive a per-registry, per-plan, per-participant capability that is valid only during that callback. It exposes no SQL, query executor, driver, connection, role, commit, rollback, retry, or widening operation. Participants run one at a time in declared order. The predeclared outbox slot runs last, and an append failure rolls back the operation. Cancellation, timeout, owner error, panic, stale-fence error, commit failure, or outbox failure produces no accepted partial fake-journal result and never causes an automatic retry.

The lifecycle adapter in this slice is only a typed interface exercised by a transactional fake journal. A real PostgreSQL adapter must remain inside the WS-02 boundary and separately prove `BEGIN`, exact role selection, SQL scoping, atomic commit/rollback, ambiguous-commit recovery, and live failure injection.

## WS-07 intent handoff

The outbox package snapshots canonical bytes only after the composition root's WS-07 validation adapter asserts that its separately owned validation succeeded. Core checks handoff integrity and immutability but does not parse or define event/audit fields, payload meaning, subject, publication, retention, replay, ordering, DLQ, Inbox, activity, or materialization semantics.

Only `Append(context.Context, TransactionScope, ValidatedIntent)` crosses the insertion seam. The transaction scope expires before transaction end. There is no raw table, claim, delete, truncate, publish, or NATS surface. Payload copies are available only to the WS-02-owned storage adapter and must not enter logs, traces, metrics, or another module.

## Final request boundary

`FinalizeRead` invokes one registered logical authorization/audit port exactly once for a finite composed read. It can return only one opaque bound revision and zero or one aggregate validated intent; there is no per-row intent list. The outbox slot runs after the final operation, and the bound revision is returned to the response adapter only after commit succeeds.

The request-boundary adapter owns this exact sequence:

1. atomically claim the single-use bound revision;
2. call the WS-06 recheck port once against the exact opaque revision;
3. accept only a receipt sealed for that call and revision;
4. immediately invoke the buffered response's atomic header/first-protected-byte release.

Changed, pending, missing, malformed, stale, unverifiable, wrong-version, canceled, panic, typed-nil, or mismatched results suppress the buffer and collapse to `boundary_denied`. There is no `Allowed()` value, per-byte recheck, or retry. The buffered-response implementation must make `Release` the atomic first-disclosure handoff and return an error only before that handoff occurs.

## Strict and durable-effect seams

The same package preserves typed ports for mode readiness, serving lease, quiescence, `BoundedReadGuard`, `DisclosureEgressFence`, suppression, and terminal proof. The `commit_boundary` adapter is deliberately deny-only, does not call an incomplete port bundle, and never falls back to `request_boundary`. The ordinary request-boundary adapter contains and invokes none of these ports. No guard, lease, fence, response, buffer, epoch, or terminal-proof state is persisted here.

The durable-effect method invokes one registered WS-06 preparation port, requires one validated outbox intent, commits both through the same coordinator, and returns an opaque owner receipt only after commit. It defines no permit states, storage, expiry, transition, effect-class registry, credential, provider call, stream, or external effect. There is no caller-supplied mode or effect class.

## Evidence and counters

The fake harness exposes stable low-cardinality counts for begin, serial participant calls, declared write participants, the one final outbox slot, append, commit, rollback, final logical audit, durable handoff, and retries. It also reports explicit zero values for SQL queries, PostgreSQL writes, OpenFGA calls, provider calls, NATS waits, browser requests, and frontend bytes. These counters do not grow with 0, 1, 1,000, or 1,000,000 represented result rows.

Initial interface-only benchmark baseline, measured on 2026-08-30 on an Intel i9-12900H with Go's benchmark harness (`-benchtime=300ms -count=10`; nearest-rank percentiles over the ten aggregate `ns/op` samples):

| Scenario | p50 | p95 | p99 | Allocation result |
|---|---:|---:|---:|---:|
| two owner participants plus validated outbox slot | 550.8 ns/op | 643.8 ns/op | 643.8 ns/op | 616 B/op, 11 allocs/op |
| final logical authorization/audit handoff, no intent | 582.3 ns/op | 842.5 ns/op | 842.5 ns/op | 417 B/op, 12 allocs/op |
| bound-revision response recheck and release | 310.6 ns/op | 322.0 ns/op | 322.0 ns/op | 146 B/op, 5 allocs/op |

This is the first seam baseline, so no prior delta exists. It is not a product endpoint/browser measurement and makes no claim against PERF-002 latency. Its endpoint/browser scenario is `not enabled`; response size is `0`; SQL queries/writes, OpenFGA/provider calls, NATS waits, browser requests, eager/lazy frontend bytes, and frontend chunk delta are all `0`.

Run the focused evidence with:

```sh
go test ./apps/core/internal/outbox ./apps/core/internal/transaction
go test -race ./apps/core/internal/outbox ./apps/core/internal/transaction
go test -cover ./apps/core/internal/outbox ./apps/core/internal/transaction
go test ./apps/core/internal/transaction -run '^$' -bench 'Benchmark(ExecuteClosedPlan|FinalizeReadNoIntent|RequestBoundaryRecheck)$' -benchmem -benchtime=300ms -count=10
```

The suites exercise these child-issue cases:

- `T-P1-015-CORE-PORTS-ORDERING`
- `T-P1-015-CORE-PORTS-ROLLBACK`
- `T-P1-015-OUTBOX-LAST`
- `T-P1-015-REQUEST-BOUNDARY-RECHECK`
- `T-P1-015-COMMIT-BOUNDARY-DENY`
- `T-P1-015-OPAQUE-CAPABILITIES`

They are partial compile-time/fake-harness contributions to `T-ADR-0005-SEQUENCE`, `T-ADR-0005-REQUEST-BOUNDARY`, `T-ADR-0005-COMMIT-BOUNDARY-SEAM`, `T-ADR-0007-TRANSACTION-PORTS`, `T-ADR-0007-OUTBOX-ATOMICITY`, and `T-ADR-0007-DURABLE-EFFECTS`; they do not complete those cumulative suites.

## Upgrade, rollback, and remaining evidence

This slice adds no database state, migration, dependency, service, endpoint, workflow, public API, event schema, or frontend artifact. A binary that does not support one of the exact internal handoff versions denies rather than translating it. Pre-production rollback removes unused implementation wiring while retaining the last accepted interface/fixture version.

Still required separately: approved driver/image activation; live PostgreSQL role and transaction adapter; `core_outbox` migrations/repository; owner-scoped SQL and real atomicity; crash/ambiguous-commit injection; WS-07 delivery/materialization; NATS outage/replay; provider and OpenFGA integration; WS-06 permit storage/semantics; full strict-mode runtime; endpoint p50/p95/p99 and query/write/call/response-size evidence; upgrade, backup/restore, and release-gate validation.
