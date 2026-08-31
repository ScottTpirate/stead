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

Startup first wraps the trusted lifecycle adapter in one opaque `BackendContract`. The trusted WS-02 storage integration uses that authority to create a `BackendOperation[T]` whose backend, owner, typed repository executor, and operation seal are fixed. An owner-authored adapter is paired with it as an opaque `RegisteredOperation[T]`; `TypedParticipant[T]` therefore has no owner field or raw callback that request code can replace. `NewPlanContract[T]` freezes the complete participant total order and backward-only dependencies and returns an opaque `PlanTemplate` plus its opaque `PlanContract[T]`. Every template in one registry must carry the same exact backend seal. Coordinator construction adds the final-read and durable-effect singleton contracts as reserved templates in a coordinator-owned registry snapshot; a caller cannot see, replace, or collide with them.

`PlanContract[T].Bind` accepts only the exact registry containing that sealed template, a non-nil request-local value of the compile-time type `T`, and zero or one immutable intent. It accepts no template key, owner, participant, callback, dependency, repository executor, or order. The resulting `Plan` is single-use and has no mutation surface. Wrong invocation types do not compile; a zero, same-key/different-seal, typed-nil, foreign-backend, or foreign-registry binding fails before `Begin`.

The coordinator alone calls the trusted WS-02 lifecycle adapter to begin, commit, or roll back. Every successful `Begin` creates one unique coordinator-owned state containing the exact returned `Session`, backend seal, registry, and running plan. Immediately around each registered owner call, the coordinator mints an `OperationPort[T]` bound to that exact state, the fixed backend operation/owner, the already-bound invocation, and a private call-context marker. The port exposes only `Execute(context.Context) error`; the caller supplies no session, transaction, owner, operation, or invocation. `Execute` atomically consumes the port and invokes only the registered repository executor on the exact `Begin` session. It has no validity boolean, session/token accessor, SQL, query executor, driver, connection, role, commit, rollback, retry, or widening method. The coordinator closes every copy when the owner callback returns and accepts the participant only when that exact port completed successfully. If an owner returns while its backend executor is still running, the port is marked closing, the coordinator waits for that executor to finish before rollback, and the late `Execute` completion fails; lifecycle and repository operations therefore cannot race on the session.

The external `testowneradapter` package names only the typed port and command. The separate trusted `testbackendadapter` package owns per-session transactional staging and the only Session-bearing executor. Tests prove a write triggered by the external owner commits with its Begin session, an owner error after repository execution rolls the staged write back, and two blocked requests remain independently staged while one later commits and the other rolls back. Same-owner/cross-session and different-owner live ports deliberately cross-swapped with the other call context fail before either repository executor runs. Zero, wrong-backend, copied, concurrent, reused, retained, and goroutine-after-return ports cannot produce another repository operation. Participants still run one at a time in registered order inside each session. The predeclared outbox slot runs last, and an append failure rolls back the operation. Cancellation, timeout, owner error, panic, stale-fence error, commit failure, or outbox failure produces no accepted partial fake-journal result and never causes an automatic retry.

The lifecycle adapter in this slice is only a typed interface exercised by the per-session fake journal. A real PostgreSQL adapter must remain inside the WS-02 boundary and separately prove `BEGIN`, exact role selection, SQL scoping, atomic commit/rollback, ambiguous-commit recovery, and live failure injection.

## WS-07 intent handoff

The outbox package snapshots canonical bytes only after the composition root's WS-07 validation adapter asserts that its separately owned validation succeeded. Core checks handoff integrity and immutability but does not parse or define event/audit fields, payload meaning, subject, publication, retention, replay, ordering, DLQ, Inbox, activity, or materialization semantics.

Only the generic typed `AppendPort[SessionBinding, BindingReceipt]` crosses the insertion seam. The coordinator wraps the exact outbox-owner binding for this `Begin` in a one-use `TransactionScope`; the appender must synchronously consume that scope and binding, then return both opaque receipts. The coordinator verifies both receipts belong to the exact instances it supplied before commit and invalidates all copies. Two simultaneous scopes with the same Go type cannot be cross-swapped: each coordinator observes a foreign receipt and rolls back. The scope exposes no binding accessor, raw table, SQL, claim, delete, truncate, publish, or NATS surface. Payload copies are available only to the WS-02-owned storage adapter and must not enter logs, traces, metrics, or another module.

## Final request boundary

`FinalizeRead` invokes one registered logical authorization/audit port exactly once for a finite composed read. That owner also receives only its reserved, exact-session `OperationPort`; coordinator construction rejects a missing, foreign-backend, or wrong-owner backend operation when the owner port is configured. It can return only one opaque bound revision and zero or one aggregate validated intent; there is no per-row intent list. The outbox slot runs after the final operation, and the bound revision is returned to the response adapter only after commit succeeds.

The request-boundary adapter owns this exact sequence:

1. atomically claim the single-use bound revision;
2. call the WS-06 recheck port once against the exact opaque revision;
3. accept only a receipt sealed for that call and revision;
4. immediately invoke the buffered response's atomic header/first-protected-byte release.

Changed, pending, missing, malformed, stale, unverifiable, wrong-version, canceled, panic, typed-nil, or mismatched results suppress the buffer and collapse to `boundary_denied`. There is no `Allowed()` value, per-byte recheck, or retry. The buffered-response implementation must make `Release` the atomic first-disclosure handoff and return an error only before that handoff occurs.

## Strict and durable-effect seams

The same package preserves typed ports for mode readiness, serving lease, quiescence, `BoundedReadGuard`, `DisclosureEgressFence`, suppression, and terminal proof. The `commit_boundary` adapter is deliberately deny-only, does not call an incomplete port bundle, and never falls back to `request_boundary`. The ordinary request-boundary adapter contains and invokes none of these ports. No guard, lease, fence, response, buffer, epoch, or terminal-proof state is persisted here.

The durable-effect method invokes one registered WS-06 preparation port through its reserved exact-session `OperationPort`, requires one validated outbox intent, commits both through the same coordinator, and returns an opaque owner receipt only after commit. It defines no permit states, storage, expiry, transition, effect-class registry, credential, provider call, stream, or external effect. There is no caller-supplied mode or effect class.

## Evidence and counters

The fake harness exposes stable low-cardinality counts for begin, serial participant calls, declared write participants, the one final outbox slot, append, commit, rollback, final logical audit, durable handoff, and retries. It also reports explicit zero values for SQL queries, PostgreSQL writes, OpenFGA calls, provider calls, NATS waits, browser requests, and frontend bytes. These counters do not grow with 0, 1, 1,000, or 1,000,000 represented result rows.

The focused suites report 93.3% statement coverage for `internal/outbox` and 90.7% for `internal/transaction`. Compile-fail evidence contains 15 independently executed cases, including wrong invocation type, runtime-participant injection, separable validity checks, direct Session access, raw SQL/role/lifecycle access, and forged opaque values.

Exact-session typed-port measurements were collected on 2026-08-30 on an Intel i9-12900H with Go's benchmark harness (`-benchtime=300ms -count=10`; nearest-rank percentiles over the ten aggregate `ns/op` samples). The delta compares the completion-handshake correction with parent `f11bbbdfa9c9daa85a5cfd2ab8b04ca353bd1e91`:

| Scenario | p50 | p95 | p99 | Allocation result | p50 delta |
|---|---:|---:|---:|---:|---:|
| two typed owner participants plus exact-receipt outbox slot | 791.9 ns/op | 820.2 ns/op | 820.2 ns/op | 1,136 B/op, 21 allocs/op | +96.4 ns (+13.9%) |
| final logical authorization/audit handoff, no intent | 625.9 ns/op | 640.2 ns/op | 640.2 ns/op | 688 B/op, 16 allocs/op | +52.0 ns (+9.1%) |
| bound-revision response recheck and release | 290.2 ns/op | 301.4 ns/op | 301.4 ns/op | 146 B/op, 5 allocs/op | -3.6 ns (-1.2%) |

Against the exact parent, the closed-plan handshake adds 256 bytes and two allocations for two protected owner operations; finalization adds 112 bytes and one allocation. This is the measured cost of preventing rollback from racing an escaped running backend operation. These are not product endpoint/browser measurements and make no claim against PERF-002 latency. The endpoint/browser scenario is `not enabled`; response size is `0`; SQL queries/writes, OpenFGA/provider calls, NATS waits, browser requests, eager/lazy frontend bytes, and frontend chunk delta are all `0`.

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
