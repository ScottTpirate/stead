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

`PlanContract[T].Bind` accepts only the exact registry containing that sealed template, a non-nil request-local value of the compile-time type `T`, and zero or one immutable intent. It accepts no template key, owner, participant, callback, dependency, repository executor, order, caller-provided copier, or codec. Reference-free invocation types are copied by value. Reference-bearing types pass a closed default-codec snapshot profile capped at 1 MiB, depth 64, and 262,144 visited values; custom codecs, interfaces, hidden/tagged state, unsupported reference kinds, cycles, shared pointer/map identity, overlapping pointer/slice storage, malformed round trips, and limit violations fail before `Begin`. The snapshot is digest-bound. Each public participant receives separately decoded owner and backend views, and each later participant plus any transaction-owned deferred intent receives another fresh view, so caller or owner mutation before repository execution cannot split authorization, domain-write, and outbox inputs. Reserved final-read and durable-effect result carriers use a separate private coordinator-owned binding because the participant must return its result to the coordinator; those carrier instances are created by the coordinator, intentionally share their private result object across owner/backend/deferred-intent steps, are never accepted through public `Bind`, and remain unexposed until execution finishes. The resulting `Plan` is single-use and has no mutation surface. Wrong invocation types do not compile; a zero, same-key/different-seal, typed-nil, foreign-backend, foreign-registry, unsupported, aliased, or unsnapshotable binding fails before `Begin`.

The coordinator alone calls the trusted WS-02 lifecycle adapter to begin, commit, or roll back. Every successful `Begin` creates one unique coordinator-owned state containing the exact returned lifecycle `Session`, a distinct opaque `ExecutorBinding`, backend seal, registry, and running plan. `ExecutorBinding` is only a package-sealed comparable identity paired internally with that exact `Session` for coordinator validation. Its constructor accepts no payload, closure, wrapper, query handle, or second argument, and there is no public resolver. The trusted backend adapter stores its own private identity-to-session journal and removes both directions when commit or rollback closes the session; an unknown, foreign, copied-late, or expired identity therefore cannot reach storage. A missing or cross-session identity fails before any registered operation and the returned lifecycle session is rolled back. Immediately around each registered public owner call, the coordinator mints an `OperationPort[T]` bound to that exact state, the fixed backend operation/owner, an independently decoded backend invocation that the owner never receives, and the exact coordinator-created call context; the owner callback receives its own independent view. The port exposes only `Execute(context.Context) error`; it accepts only that exact context identity and always executes with the stored coordinator context. A derived context—including `context.WithoutCancel` or an added-value context—cannot retain the private marker while removing cancellation, widening a deadline, or replacing trusted values. The caller supplies no session, transaction, owner, operation, or invocation. `Execute` atomically consumes the port and invokes only the registered repository executor with the identity returned beside `Session`; the identity has no validity boolean, payload, resolver, session/token accessor, SQL, query executor, driver, connection, role, commit, rollback, retry, or widening method. The coordinator closes every port copy when the owner callback returns and accepts the participant only when that exact port completed successfully. If an owner returns while its backend executor is still running, the port is marked closing, the coordinator waits for that executor to finish before rollback, and the late `Execute` completion fails; lifecycle and repository operations therefore cannot race on the session.

The external `testowneradapter` package names only the typed port and command. The separate `testbackendadapter` package owns per-session transactional staging, the lifecycle session, and a private identity journal. Compile-negative and static tests prove that a registered executor cannot call lifecycle methods, construct a payload-bearing binding, or resolve a binding as `Session`; runtime tests prove unknown, foreign, cross-session, and copied-late identities are rejected, identity mappings expire after both commit and rollback, and an independent live transaction remains usable. Tests also prove a write triggered by the external owner commits with its Begin-created transaction, an owner error after repository execution rolls the staged write back, and two blocked requests remain independently staged while one later commits and the other rolls back. Same-owner/cross-session and different-owner live ports deliberately cross-swapped with the other call context fail before either repository executor runs. Zero, wrong-backend, copied, concurrent, reused, retained, and goroutine-after-return ports cannot produce another repository operation. Participants still run one at a time in registered order inside each session. The predeclared outbox slot runs last, and an append failure rolls back the operation. Cancellation, timeout, owner error, panic, stale-fence error, commit failure, or outbox failure produces no accepted partial fake-journal result and never causes an automatic retry.

This is an API and integration boundary, not sandboxing of a malicious backend implementation. The WS-02 backend necessarily creates and owns its lifecycle sessions and could call its own methods internally; its code, dependency intake, and registration remain trusted and independently reviewed. The enforced invariant is that neither an owner nor a registered executor can obtain lifecycle authority from `ExecutorBinding`, and accidental backend storage use through a retained identity fails after the journal expires.

The lifecycle adapter in this slice is only a typed interface exercised by the per-session fake journal. A real PostgreSQL adapter must remain inside the WS-02 boundary and separately prove `BEGIN`, exact role selection, SQL scoping, atomic commit/rollback, ambiguous-commit recovery, and live failure injection.

## WS-07 intent handoff

The outbox package snapshots canonical bytes only after the composition root's WS-07 validation adapter asserts that its separately owned validation succeeded. Core checks handoff integrity and immutability but does not parse or define event/audit fields, payload meaning, subject, publication, retention, replay, ordering, DLQ, Inbox, activity, or materialization semantics.

Only the generic typed `AppendPort[SessionBinding, BindingReceipt]` crosses the insertion seam. The coordinator wraps the exact outbox-owner binding for this `Begin` in a one-use `TransactionScope`; the appender must synchronously consume that scope and binding, then return both opaque receipts. If either callback escapes, close atomically changes `running` to `closing`, rejects new use/resolve attempts, waits for the active callback's done signal, changes to `closed`, suppresses its late result/receipt, and only then permits rollback. The coordinator verifies both receipts belong to the exact instances it supplied before commit and invalidates all copies. Two simultaneous scopes with the same Go type cannot be cross-swapped: each coordinator observes a foreign receipt and rolls back. The scope exposes no binding accessor, raw table, SQL, claim, delete, truncate, publish, or NATS surface. Payload copies are available only to the WS-02-owned storage adapter and must not enter logs, traces, metrics, or another module.

## Final request boundary

`FinalizeRead` invokes one registered logical authorization/audit port exactly once for a finite composed read. That owner also receives only its reserved, exact-transaction `OperationPort`; coordinator construction rejects a missing, foreign-backend, or wrong-owner backend operation when the owner port is configured. Its issuer can mint exactly one opaque bound revision and zero or one aggregate validated intent; retained issuer copies close under a defer and cannot mint another value. Every revision copy shares one lifecycle state: provisional during the owner call, pending only after the coordinator accepts the exact issued material, active exactly once only after `Execute` returns committed success, and permanently invalid after any error, panic, outbox failure, or failed/ambiguous commit result. A provisional or pending revision fails before recheck and cannot consume its later single-use response boundary. There is no per-row intent list. The outbox slot runs after the final operation, and the bound revision is returned to the response adapter only after commit succeeds.

The request-boundary adapter owns this exact sequence:

1. atomically claim the single-use bound revision;
2. call the WS-06 recheck port once against the exact opaque revision;
3. accept only a receipt sealed for that call and revision;
4. immediately invoke the buffered response's atomic header/first-protected-byte release.

Changed, pending, missing, malformed, stale, unverifiable, wrong-version, canceled, panic, typed-nil, or mismatched results suppress the buffer and collapse to `boundary_denied`. There is no `Allowed()` value, per-byte recheck, or retry. The buffered-response implementation must make `Release` the atomic first-disclosure handoff and return an error only before that handoff occurs.

## Strict and durable-effect seams

The same package preserves typed ports for mode readiness, serving lease, quiescence, `BoundedReadGuard`, `DisclosureEgressFence`, suppression, and terminal proof. The `commit_boundary` adapter is deliberately deny-only, does not call an incomplete port bundle, and never falls back to `request_boundary`. The ordinary request-boundary adapter contains and invokes none of these ports. No guard, lease, fence, response, buffer, epoch, or terminal-proof state is persisted here.

The durable-effect method invokes one registered WS-06 preparation port through its reserved exact-transaction `OperationPort`, requires one validated outbox intent, commits both through the same coordinator, and returns an opaque owner receipt only after commit. Its issuer and every receipt copy use the same single-issuance provisional/pending/active/invalid lifecycle as the bound revision: no copy is usable before committed success, every unsuccessful or ambiguous path invalidates it, and activation can happen only once. It defines no permit states, storage, expiry, transition, effect-class registry, credential, provider call, stream, or external effect. There is no caller-supplied mode or effect class.

## Evidence and counters

The fake harness exposes stable low-cardinality counts for begin, serial participant calls, declared write participants, the one final outbox slot, append, commit, rollback, final logical audit, durable handoff, and retries. It also reports explicit zero values for SQL queries, PostgreSQL writes, OpenFGA calls, provider calls, NATS waits, browser requests, and frontend bytes. These counters do not grow with 0, 1, 1,000, or 1,000,000 represented result rows.

A fresh `-count=1` coverage run on 2026-09-03 reported 90.3% statement coverage for `internal/outbox` and 74.5% for the direct `testbackendadapter` package suite. Repeated transaction runs observed a schedule-dependent 90.8–91.0% range; all ten final-candidate runs reported 90.8%, so only that conservative reproducible floor is claimed. Compile-fail evidence contains 20 independently executed cases, including caller-supplied snapshotters, wrong invocation type, runtime-participant injection, separable validity checks, direct Session access, executor commit/rollback attempts, removed resolver use, payload-bearing constructor use, raw SQL/role/lifecycle access, and forged opaque values. Runtime tests mutate pointer, slice, and map owner views before `Execute`, preserve the backend/later-participant/deferred-intent bound value, reject shared or overlapping alias topology, reject derived contexts, and prove outer-scope and inner-binding escape, cancellation, deadline, panic, missing-receipt, unknown/foreign/cross-session identity, and copied-late identity paths fail or wait before exactly one lifecycle close. Proof-lifecycle tests add concurrent multi-mint contention, retained issuers, owner error/panic, invalid/outbox error and panic, failed/ambiguous commit error and panic, concurrent precommit use attempts, shared-copy invalidation, and exactly one postcommit activation for both revision and durable-effect receipts.

Exact-session typed-port measurements were collected on 2026-08-30 on an Intel i9-12900H with Go's benchmark harness (`-benchtime=300ms -count=10`; nearest-rank percentiles over the ten aggregate `ns/op` samples). The delta compares the completion-handshake correction with parent `f11bbbdfa9c9daa85a5cfd2ab8b04ca353bd1e91`:

| Scenario | p50 | p95 | p99 | Allocation result | p50 delta |
|---|---:|---:|---:|---:|---:|
| two typed owner participants plus exact-receipt outbox slot | 791.9 ns/op | 820.2 ns/op | 820.2 ns/op | 1,136 B/op, 21 allocs/op | +96.4 ns (+13.9%) |
| final logical authorization/audit handoff, no intent | 625.9 ns/op | 640.2 ns/op | 640.2 ns/op | 688 B/op, 16 allocs/op | +52.0 ns (+9.1%) |
| bound-revision response recheck and release | 290.2 ns/op | 301.4 ns/op | 301.4 ns/op | 146 B/op, 5 allocs/op | -3.6 ns (-1.2%) |

Against the exact parent, the closed-plan handshake adds 256 bytes and two allocations for two protected owner operations; finalization adds 112 bytes and one allocation. This is the measured cost of preventing rollback from racing an escaped running backend operation. These are not product endpoint/browser measurements and make no claim against PERF-002 latency. The endpoint/browser scenario is `not enabled`; response size is `0`; SQL queries/writes, OpenFGA/provider calls, NATS waits, browser requests, eager/lazy frontend bytes, and frontend chunk delta are all `0`.

The immutable-invocation and coordinator-context correction was measured on 2026-09-02 with the same host and harness against exact review base `a77dbd044916802d145b3de12263b9b741ecdf32`. Reference-free operations retain the fast path; the reference-bearing scenario measures bind-time validation/encoding and round-trip decode plus one fresh decode for each of two participants. A deferred intent on the immutable binding path receives another fresh view.

| Scenario | p50 | p95 | p99 | Allocation result | p50 delta from `a77dbd0` |
|---|---:|---:|---:|---:|---:|
| reference-free two-participant plan plus outbox | 904.4 ns/op | 933.3 ns/op | 933.3 ns/op | 1,280 B/op, 22 allocs/op | +114.3 ns (+14.5%) |
| reference-bearing two-participant plan plus outbox | 6,812 ns/op | 7,165 ns/op | 7,165 ns/op | 3,428 B/op, 65 allocs/op | new bounded path |
| final logical authorization/audit handoff, no intent | 664.6 ns/op | 679.7 ns/op | 679.7 ns/op | 728 B/op, 17 allocs/op | +44.1 ns (+7.1%) |
| bound-revision response recheck and release | 292.4 ns/op | 312.5 ns/op | 312.5 ns/op | 146 B/op, 5 allocs/op | +1.5 ns (+0.5%) |

For the unchanged reference-free paths, the exact-base allocation results were 1,136 B/op with 21 allocations, 688 B/op with 16 allocations, and 146 B/op with 5 allocations respectively. The added cost binds the participant port to an exact stored context and carries an error-capable immutable invocation view. The reference-bearing path has no unsafe baseline because `a77dbd0` aliases its input. These microbenchmarks remain below a product endpoint and therefore do not claim endpoint latency compliance.

The final immutable-view and outbox close/wait correction was measured on 2026-09-02 against exact review base `b2dbab4d12b7364c883181d75e552bef52e79cd0`. Completion channels are allocated lazily only when close overlaps a running scope, so the ordinary closed-plan path keeps its prior allocation count. The required second decode for each public backend view is visible only on the bounded reference-bearing path.

| Scenario | p50 | p95 | p99 | Allocation result | p50 delta from `b2dbab4` |
|---|---:|---:|---:|---:|---:|
| reference-free two-participant plan plus outbox | 954.9 ns/op | 979.6 ns/op | 979.6 ns/op | 1,400 B/op, 22 allocs/op | +50.5 ns (+5.6%) |
| reference-bearing two-participant plan plus outbox | 9,329 ns/op | 9,659 ns/op | 9,659 ns/op | 4,761 B/op, 88 allocs/op | +2,517 ns (+36.9%) |
| final logical authorization/audit handoff, no intent | 676.3 ns/op | 702.0 ns/op | 702.0 ns/op | 776 B/op, 17 allocs/op | +11.7 ns (+1.8%) |
| bound-revision response recheck and release | 292.9 ns/op | 303.1 ns/op | 303.1 ns/op | 146 B/op, 5 allocs/op | +0.5 ns (+0.2%) |

The reference-bearing increase is the measured cost of giving two public owner/backend pairs four independent decoded views rather than two shared views; bind-time alias scanning remains bounded at 1 MiB, depth 64, and 262,144 visited values and sorts memory regions in `O(n log n)`. Endpoint/browser scenario, response size, SQL/PostgreSQL writes, OpenFGA/provider calls, NATS waits, browser requests, and frontend chunk deltas remain zero for this dependency-free seam.

The provisional-proof and identity-only executor correction was measured on 2026-09-03 against rejected exact candidate `30e82f07d792a3354d43fad13e1df3ed0ffbc7a3` with the same host, harness, sample count, and nearest-rank calculation. The baseline was freshly sampled immediately before the correction and the successor immediately after it. Finalization and boundary measurements include the shared atomic proof lifecycle state.

| Scenario | p50 | p95 | p99 | Allocation result | p50 delta from `30e82f0` |
|---|---:|---:|---:|---:|---:|
| reference-free two-participant plan plus outbox | 1,029 ns/op | 1,064 ns/op | 1,064 ns/op | 1,440 B/op, 23 allocs/op | -20 ns (-1.9%) |
| reference-bearing two-participant plan plus outbox | 9,329 ns/op | 9,659 ns/op | 9,659 ns/op | 4,801 B/op, 89 allocs/op | +8 ns (+0.1%) |
| final logical authorization/audit handoff, no intent | 848.6 ns/op | 862.3 ns/op | 862.3 ns/op | 848 B/op, 18 allocs/op | -4.8 ns (-0.6%) |
| bound-revision response recheck and release | 463.8 ns/op | 477.3 ns/op | 477.3 ns/op | 194 B/op, 6 allocs/op | -1.0 ns (-0.2%) |

The reference-bearing and boundary timing changes are within microbenchmark sample noise. Against `30e82f0`, identity-only binding removes eight bytes without adding an allocation on both plan paths and finalization; the response-boundary allocation result is unchanged. These remain internal seam measurements, not endpoint latency claims. Endpoint/browser scenario, response size, SQL/PostgreSQL writes, OpenFGA/provider calls, NATS waits, browser requests, and frontend chunk deltas remain zero for this dependency-free seam.

Run the focused evidence with:

```sh
go test ./apps/core/internal/outbox ./apps/core/internal/transaction/...
go test -race ./apps/core/internal/outbox ./apps/core/internal/transaction/...
go test -cover ./apps/core/internal/outbox ./apps/core/internal/transaction/testbackendadapter
for run in $(seq 1 10); do go test -count=1 -cover ./apps/core/internal/transaction; done
go test -count=100 ./apps/core/internal/transaction ./apps/core/internal/transaction/testbackendadapter -run 'Test(ExecutorBinding|CoordinatorRejectsCrossSession|BackendBindingJournal|RegisteredExecutorLeakedBinding|BindingJournalRejects)'
go test ./apps/core/internal/transaction -run '^$' -bench 'Benchmark(ExecuteClosedPlan|ExecuteReferenceSnapshotPlan|FinalizeReadNoIntent|RequestBoundaryRecheck)$' -benchmem -benchtime=300ms -count=10
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
