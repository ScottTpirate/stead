# Performance evidence

WS-13 owns the independent harness and evidence contract. Feature owners supply instrumented fixtures and benchmarks; they do not approve their own result. Performance tests exercise the user-facing golden path, not isolated throughput at the expense of interaction latency.

## Benchmark labels

- `standard/request_boundary`: colocated standard deployment and the required Phase 1 path.
- `high-assurance/commit_boundary`: separately published strict-mode topology and budget. It may not be reported as the standard benchmark.

Every result records source revision, deployment topology, disclosure mode, device, browser/runtime, network shape, corpus and dataset version, concurrency/load, cold or warm state, and sample count. It reports p50/p95/p99 latency, database query count/time and write count, OpenFGA call count/time, provider call count/time, response bytes, eager frontend JavaScript gzip bytes, Core Web Vitals or equivalent interaction metrics, and event/projection lag.

## Required suites

- `T-PERF-001-ACCEPTANCE`: prove the useful golden path is the optimization target and synchronous work is not retained when it can be safely projected, batched, prefetched, deferred, or asynchronous.
- `T-PERF-002-ACCEPTANCE`: measure every Master Directive engineering target and existing release ceiling under the standard fixture; separately label strict-mode results.
- `T-PERF-003-ACCEPTANCE`: after shell load, assert normally one primary composed BFF request, zero ordinary-read provider calls, zero NATS waits, and local rebuildable PostgreSQL provider projections.
- `T-PERF-004-ACCEPTANCE`: vary result-set size and fail sequential per-row SQL, OpenFGA, policy, provider, audit, or write growth; assert at most one logical synchronous authorization/audit operation for a composed request.
- `T-PERF-005-ACCEPTANCE`: measure input acknowledgement, cached/prefetched Peek, command-palette latency, route usefulness, cold interactive time, layout stability, capability chunking, and the 250 KiB gzip eager universal-shell budget.
- `T-PERF-006-ACCEPTANCE`: run Go microbenchmarks for hot components, browser and end-to-end golden latency, bundle checks, projection-lag measurement, and regression comparison. An unexplained regression over ten percent in a critical baselined metric fails independent review; release ceilings always fail when exceeded.

The initial executable bundle check is `npm run validate:web-bundle`, run after the production frontend build by `make foundation-check`. Query-, provider-, authorization-call-, browser-, and end-to-end harnesses land with their owning Phase 1 implementation issues before those paths are accepted.

## Phase 1 evidence foundation

The first machine-readable evidence contract lives in
`tests/performance/harness/performance-evidence-v1.schema.json`. The companion
semantic validator enforces the relationships JSON Schema cannot express:
percentile order, exact disclosure-mode labeling, one composed request, zero
direct browser/provider/NATS bypasses, zero authorization-decision cache hits,
one logical composed-read audit operation, set-oriented count budgets, every
PERF-002 engineering target and OPS-005 release ceiling, the eager bundle
ceiling, and independently reviewed regressions.

Run the owned harness tests with:

```bash
ruby tests/performance/harness/performance_foundation_test.rb
ruby tests/performance/harness/verify_evidence.rb \
  packages/test-fixtures/harness/performance/standard-request-boundary-valid.json
scripts/run_pinned_node.sh node \
  tests/performance/harness/performance_schema_test.mjs
```

`tests/performance/datasets/standard-request-boundary-v1.json` fixes the labels
and load shapes every standard result must record. It does not fabricate
measurements. Production modules expose counters through their own issues and
owners; WS-13 consumes those counters here and remains independent of the
implementation approval.

The recorded `60,808`-byte gzip eager result is scoped to the merged minimal
foundation shell at `a799f2e3d166eab4489e7451a5b53f59a9d78f50`. It is a delta
baseline for subsequent frontend PRs, not evidence that the mature
Devlane-derived Stead interface has completed `PERF-005`.
