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
