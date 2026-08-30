# Performance evidence

WS-13 owns this independent harness and evidence contract. Feature owners emit
measurements and artifacts; they do not define scenario classification,
budgets, baselines, candidate eligibility, or review authority. The canonical
verifier derives those decisions from repository-owned controls and actual
artifact bytes.

## Phase 1 authority boundary

`tests/performance/harness/normative_controls.rb` is the closed verifier-owned
translation of PERF-002 through PERF-006, AUTH-002, and the Phase 1
`request_boundary` rules. It pins the nine scenarios, classifications, load
shapes, minima/exact counts, budgets, targets/ceilings, critical metrics, and
kind-specific instrumentation. The dataset manifest must match these controls
exactly; raising a target to `999999`, relabeling an ordinary read, disabling
set-oriented behavior, or dropping instrumentation fails semantic validation.

Candidate verification additionally requires a `controls_revision` that is an
ancestor of both `origin/main` and the candidate. The directive, verifier,
schemas, manifest, generator, baseline, reviewer registry, performance Make
target, and protected candidate workflow may not differ after that revision.
Changing one requires a newly merged immutable control revision.

`tests/performance/datasets/standard-request-boundary-v1.json` binds:

- the deterministic generator path and bytes, seed, output digest, and exact
  300,010-record cardinalities;
- schema-valid Organizations, hierarchical Teams and edges, Projects, Work,
  Docs/versions, People, Agents, relationships, activity, Inbox, audit, and
  software-capability records with same-organization referential integrity;
- bounded search text plus verifier-owned count ranges for status,
  classification, assignment, capability, scope, and lifecycle distributions;
- exact client/server CPU model, base frequency, cores, memory, OS, browser,
  component versions, shaped network, topology, and cache reset protocol;
- exact arrival model, concurrency, warmup, pacing, duration, samples, and
  scale cardinalities for every scenario; and
- digest-only telemetry canaries plus forbidden normalized key/value rules.

The manifest is only `standard/request_boundary`. `commit_boundary` is not a
valid Phase 1 candidate claim.

## Measurement and candidate contracts

Each measurement binds one scenario, source revision, dataset digest,
runner/version/command, raw samples, summaries, counts, sizes, user-facing
metrics, scaling trials, safe telemetry, and digest-bound request traces. A
candidate must carry one unique trace for every measured sample. Those traces
prove the exact pacing/duration schedule and the verifier applies every
exact/minimum/budget rule to every raw request, not only to a maximum summary.
The verifier recomputes percentiles, maxima, sample count, every evidence
digest, telemetry scan, target result, and compatible-baseline regression.

The closed count rules include:

- zero browser requests to provider/internal origins, authorization cache
  hits, and NATS waits;
- exactly one composed browser request on primary server surfaces;
- exactly one fresh OpenFGA call, deterministic policy call, and logical audit
  operation for protected server scenarios;
- zero provider calls on ordinary reads;
- bounded SQL/write/provider work under scale trials; and
- at least one authoritative-state write plus one transactional-outbox write
  for metadata mutations, with both writes and the authoritative commit bound
  to one transaction hash.

A suite is candidate-eligible only in the protected, manually dispatched
`phase1-candidate.yml` workflow from `main` in `ScottTpirate/stead`. The suite
revision must resolve to and equal clean checked-out `HEAD`, match the trusted
GitHub Actions environment, and use the trusted upstream remote. A synthetic
SHA or caller-asserted CI context cannot pass.

Runtime components, version-probe output, evidence, benchmark artifacts,
measurement files, runner stdout/stderr/binary, environment observations, and
reviews use verifier-recomputed SHA-256 references to actual files. The
verifier executes every component probe with closed arguments and compares the
resulting bytes. Every scenario requires exactly one candidate-revision
tracked runner attestation; the verifier re-executes its closed argv and its
environment probe, which must reproduce the exact evidence and declared CPU,
network, topology, corpus, cache, and load environment bytes. Each kind has a
strict runner-output record whose payload bytes and observations are replayed
through that controlled runner. Every wrapper binds that scenario's evidence,
complete request-traces digest, runner-attestation digest, strict record, and
exact kind-specific observation set. One generic `kind.result=1` artifact
cannot cover multiple scenarios.

All seven server scenarios with PostgreSQL/audit/outbox work require their own
trace-derived proof for every measured request. The transactional-outbox
write, authoritative commit, response, and relay carry one transaction hash
and one outbox-event hash and must satisfy
`outbox_write <= authoritative_commit <= response_sent < relay_started`.
Input acknowledgement and local command-palette scenarios remain client-local
and require exact zero server operations.

## Baselines, reviews, and protected telemetry

The carried-forward frontend baseline is the actual 60,808-byte gzip minimal
foundation shell at `a799f2e3d166eab4489e7451a5b53f59a9d78f50`. Verification
rebuilds that immutable source tree with its exact lock, pinned Node runner,
and measurement tool, then checks each output file's SHA-256 and uncompressed
and gzip byte counts. Its ID/value/source/environment are also bound to the
standard manifest. It is a delta baseline, not PERF-005 completion for the
mature Devlane-derived interface; the absolute ceiling remains 256,000 bytes.

Other timing metrics intentionally have no invented baseline. Once a critical
baseline is merged, the verifier accepts it only for the same profile,
disclosure mode, scenario environment, source commit, and reference artifact.
A regression over ten percent requires a structured review bound to the exact
candidate/evidence and verifier-computed values. Reviewer identity, role, and
Ed25519 key must come from an immutable registry revision already merged to
`origin/main` and remain active and unchanged at the candidate. The
implementation owner must also be repository-approved and match the immutable
candidate commit author; independence is compared against that verified owner,
not a caller-selected identity. The review signature must verify. Release
ceilings remain nonwaivable.

Telemetry scanning recursively examines every normalized key and string value.
It rejects forbidden fields/content and raw, prefixed/suffixed, hexadecimal,
percent-encoded, standard-Base64, and URL-safe-Base64 canaries, including
canaries revealed inside delimited encoded substrings of keys or values.
Evidence retains only safe records and scan counts, never protected canary
content.

## Current non-candidate gaps

This foundation deliberately does not claim a green release candidate. Phase
1 owners still must land the protected candidate workflow, production
scenario runner, byte-backed runtime component descriptors, real measurements,
and strict kind-specific runner outputs. Governance must separately merge
approved implementation-owner and independent-reviewer authority records
before a candidate or regression exception can pass; both registry lists are
intentionally empty today. No timing baseline is fabricated by the unit tests.

## Commands

Run the adversarial foundation gate and standalone noncandidate fixture:

```bash
make performance-foundation-check
ruby tests/performance/harness/verify_evidence.rb \
  packages/test-fixtures/harness/performance/standard-request-boundary-valid.json
```

Verify a frozen suite after the missing production pieces exist:

```bash
ruby tests/performance/harness/verify_evidence.rb --suite \
  artifacts/performance/phase1-candidate-suite.json
```
