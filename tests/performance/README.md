# Performance evidence

WS-13 owns the independent harness and evidence contract. Feature owners emit
instrumented measurements and benchmark artifacts; they cannot define their
own scenario classification, count budget, baseline, candidate eligibility, or
review disposition. The release verifier derives those decisions from the
repository-owned manifest and the complete candidate suite.

## Phase 1 authority boundary

`tests/performance/datasets/standard-request-boundary-v1.json` is the trusted,
digest-addressed Phase 1 dataset and scenario manifest. It fixes:

- the deterministic corpus generator path, digest, seed, output digest, and
  exact cardinalities;
- numeric client/server resources, component versions, network shaping, and
  topology;
- cold/warm cache resets, warmups, concurrency, samples, and scale result
  counts;
- all nine PERF-002 scenarios and their ordinary-read, primary-surface,
  set-oriented, and frontend classifications;
- scenario-owned count budgets, engineering targets, release ceilings,
  critical-metric declarations, measured baselines, and required benchmark
  artifact kinds; and
- digest-only telemetry canaries plus normalized key/value scan rules.

The manifest is `standard/request_boundary`. A Phase 1 candidate suite that
references another manifest, injects `commit_boundary`, or relabels the trusted
manifest fails. Full `commit_boundary` measurement remains a separately
budgeted Phase 3 claim with guard/lease/quiescence/buffer proof.

Evidence producers supply no `candidate_eligible`, classification,
`count_budgets`, target, baseline-comparison, or free-form review field. The
canonical verifier applies strict JSON Schema and semantic validation to every
manifest, measurement, benchmark artifact, candidate suite, and regression
review it reads.

## Measurement and candidate contracts

Each measurement binds one scenario, source revision, exact dataset digest,
runner/version/command, full raw sample series and their canonical digest,
p50/p95/p99 summaries, count maxima, response bytes, bundle sizes, user-facing
metrics, scaling trials, and safe aggregate telemetry records. The verifier
recomputes percentiles, maxima, sample count, raw/telemetry digests, normalized
key/value scans, targets, count budgets, and baseline regression percentages.

Hard invariants are verifier-owned:

- zero browser requests to providers or internal infrastructure;
- zero authorization-decision cache hits;
- zero NATS waits in request handling;
- exactly one browser request for a trusted primary surface after shell load;
- zero provider calls for a trusted ordinary read; and
- exactly one logical authorization/audit operation for a composed ordinary
  request-boundary read.

A Phase 1 candidate suite becomes eligible only when it is clean and covers
every trusted scenario with `measurement` evidence from the same immutable
revision and dataset. It also requires digest-bound Go, browser, golden-slice,
bundle, projection, Peek, query, authorization, provider, and
response-before-relay artifacts. Runtime component versions must match the
trusted reference and carry immutable artifact digests. Relay evidence includes
a monotonic `authoritative_commit <= response_sent < relay_started` proof.

Critical regressions over ten percent are computed against baselines in the
trusted manifest. They require a separate structured review artifact bound to
the source revision, dataset digest, evidence file digest, scenario, baseline,
metric, and verifier-derived values. The implementation owner cannot provide
the independent approval. Engineering targets and absolute release ceilings
cannot be waived by that review.

The only carried-forward measured baseline in this foundation is the real
60,808-byte minimal-shell bundle result. Timing metrics are declared critical
but intentionally have no invented baseline until an owning benchmark produces
reviewed measurements; an empty producer comparison cannot change either the
critical-metric declarations or repository-owned baseline records.

Telemetry evidence contains only safe metric records and hashed correlation
context. The verifier scans normalized keys and normalized string values,
compares them with digest-only canaries, and reports only counts/paths rather
than protected values. Any canary, credential pattern, forbidden key, mismatched
scan count, or retained protected content fails.

## Required suites

- `T-PERF-001-ACCEPTANCE`: optimize useful golden-path behavior rather than an
  isolated throughput result.
- `T-PERF-002-ACCEPTANCE`: measure all engineering targets and release ceilings
  under the trusted standard fixture.
- `T-PERF-003-ACCEPTANCE`: prove the one-request projection-backed path, zero
  ordinary-read provider calls, and zero NATS waits.
- `T-PERF-004-ACCEPTANCE`: vary result count and prove bounded SQL,
  authorization, provider, write, and audit work.
- `T-PERF-005-ACCEPTANCE`: measure acknowledgement, Peek, command, route, cold
  interactive, layout, and capability-split bundle behavior.
- `T-PERF-006-ACCEPTANCE`: bind Go, browser, golden E2E, bundle, projection,
  raw-sample, and regression evidence to the exact candidate.

Owning Phase 1 modules still need to deliver the actual production runners and
instrumentation that emit these artifacts. This foundation deliberately does
not fabricate performance results or treat the contract fixture as release
evidence.

## Commands

Run the foundation adversarial tests and standalone fixture verification:

```bash
make performance-foundation-check
ruby tests/performance/harness/verify_evidence.rb \
  packages/test-fixtures/harness/performance/standard-request-boundary-valid.json
```

Verify a frozen candidate suite:

```bash
ruby tests/performance/harness/verify_evidence.rb --suite \
  artifacts/performance/phase1-candidate-suite.json
```

The recorded `60,808`-byte gzip eager result is scoped to the merged minimal
foundation shell at `a799f2e3d166eab4489e7451a5b53f59a9d78f50`. It is the
starting delta baseline for frontend PRs, not evidence that the mature
Devlane-derived interface satisfies PERF-005. The absolute universal-shell
budget remains 250 KiB gzip, or 256,000 bytes.
