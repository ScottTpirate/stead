#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "pathname"
require "tempfile"
require "tmpdir"
require_relative "evidence_contract"

ROOT = Pathname.new(__dir__).join("../../..").expand_path
FIXTURE_PATH = ROOT.join("packages/test-fixtures/harness/performance/standard-request-boundary-valid.json")
BASELINE_PATH = ROOT.join("packages/test-fixtures/harness/performance/foundation-shell-baseline.json")

EXPECTED_TEST_IDS = %w[
  T-P1-012-PERF-EVIDENCE-SCHEMA
  T-P1-012-PERF-TRUSTED-MANIFEST
  T-P1-012-PERF-CANDIDATE-COVERAGE
  T-P1-012-PERF-REPRODUCIBLE-SAMPLES
  T-P1-012-PERF-COUNTER-INVARIANTS
  T-P1-012-PERF-ONE-COMPOSED-REQUEST
  T-P1-012-PERF-ZERO-PROVIDER-READ
  T-P1-012-PERF-ZERO-NATS-WAIT
  T-P1-012-PERF-BUNDLE-DELTA
  T-P1-012-PERF-MODE-LABELING
  T-P1-012-PERF-REGRESSION-GATE
  T-P1-012-PERF-REDACTION
  T-P1-012-PERF-CAUSALITY
].freeze

results = Hash.new { |hash, key| hash[key] = [] }

assert = lambda do |test_id, condition, message|
  raise "unknown test ID #{test_id}" unless EXPECTED_TEST_IDS.include?(test_id)

  results[test_id]
  results[test_id] << message unless condition
end

parse = ->(path) { JSON.parse(path.read(encoding: "UTF-8")) }
copy = ->(value) { Marshal.load(Marshal.dump(value)) }
fixture = parse.call(FIXTURE_PATH)
baseline = parse.call(BASELINE_PATH)
verifier = Stead::PerformanceVerifier.new(root: ROOT)
manifest = verifier.manifest

semantic_errors = lambda do |document, candidate: false, reviews: [], evidence_sha256: nil, implementation_owner: nil|
  Stead::PerformanceEvidence.new(document, manifest: manifest).validate(
    candidate: candidate,
    regression_reviews: reviews,
    evidence_sha256: evidence_sha256,
    implementation_owner: implementation_owner
  )
end

canonical_errors = lambda do |document|
  Tempfile.create(["stead-performance-evidence-", ".json"]) do |file|
    file.write(JSON.pretty_generate(document))
    file.flush
    verifier.verify_evidence(file.path)["errors"]
  end
end

refresh_evidence = lambda do |document|
  raw = document.fetch("raw_samples")
  percentile = lambda do |values, quantile|
    values.sort.fetch([(quantile * values.length).ceil - 1, 0].max)
  end
  Stead::PerformanceEvidence::TIMING_GROUPS.each do |group|
    values = raw.dig("timings_ms", group)
    document["timings_ms"][group] = {
      "p50" => percentile.call(values, 0.50),
      "p95" => percentile.call(values, 0.95),
      "p99" => percentile.call(values, 0.99)
    }
  end
  Stead::PerformanceEvidence::COUNT_FIELDS.each do |field|
    document["counts"][field] = raw["counts"].map { |sample| sample.fetch(field) }.max
  end
  document["sizes"]["response_bytes"] = raw["response_bytes"].max
  %w[lcp_ms inp_ms cls].each do |metric|
    document["web_vitals"][metric] = percentile.call(raw.dig("web_vitals", metric), 0.95)
  end
  document["raw_samples_sha256"] = Stead::PerformanceCanonicalJSON.digest(raw)
  document["telemetry"]["records_sha256"] = Stead::PerformanceCanonicalJSON.digest(document.dig("telemetry", "records"))
  document
end

valid = verifier.verify_evidence(FIXTURE_PATH)
assert.call(
  "T-P1-012-PERF-EVIDENCE-SCHEMA",
  valid["errors"].empty? && valid["candidate_eligible"] == false,
  "the canonical verifier must apply strict JSON Schema and semantic validation to the reference fixture"
)

schema_only_invalid = copy.call(fixture)
schema_only_invalid["sizes"]["response_bytes"] = "x"
assert.call(
  "T-P1-012-PERF-EVIDENCE-SCHEMA",
  canonical_errors.call(schema_only_invalid).any? { |error| error.include?("JSON Schema") },
  "a structurally invalid value that semantic checks do not own must fail the canonical verifier"
)

producer_authority = copy.call(fixture)
producer_authority["candidate_eligible"] = true
producer_authority["count_budgets"] = { "sql_queries" => 99_999 }
producer_authority["ordinary_read"] = false
producer_errors = canonical_errors.call(producer_authority)
assert.call(
  "T-P1-012-PERF-TRUSTED-MANIFEST",
  producer_errors.any? { |error| error.include?("JSON Schema") } &&
    !fixture.key?("candidate_eligible") && !fixture.key?("count_budgets"),
  "evidence producers must not self-assert eligibility, scenario classifications, or budgets"
)

assert.call(
  "T-P1-012-PERF-TRUSTED-MANIFEST",
  manifest.validate.empty? &&
    manifest.document.dig("generator", "seed") == 2_026_083_001 &&
    manifest.document.dig("network", "round_trip_latency_ms") == 20 &&
    manifest.document.fetch("scenarios").length == 9,
  "the trusted digest-addressed manifest must bind generator, corpus, resources, network, cache, load, and every PERF-002 scenario"
)

wrong_dataset = copy.call(fixture)
wrong_dataset["dataset"]["sha256"] = "0" * 64
assert.call(
  "T-P1-012-PERF-TRUSTED-MANIFEST",
  semantic_errors.call(wrong_dataset).include?("evidence dataset digest does not match the trusted manifest"),
  "evidence must bind the exact repository-owned dataset manifest digest"
)

one_sample = copy.call(fixture)
one_sample["evidence_kind"] = "measurement"
one_sample["raw_samples"]["timings_ms"].each { |group, values| one_sample["raw_samples"]["timings_ms"][group] = [values.first] }
one_sample["raw_samples"]["counts"] = [one_sample["raw_samples"]["counts"].first]
one_sample["raw_samples"]["response_bytes"] = [one_sample["raw_samples"]["response_bytes"].first]
one_sample["raw_samples"]["web_vitals"].each { |metric, values| one_sample["raw_samples"]["web_vitals"][metric] = [values.first] }
refresh_evidence.call(one_sample)
assert.call(
  "T-P1-012-PERF-REPRODUCIBLE-SAMPLES",
  semantic_errors.call(one_sample, candidate: true).any? { |error| error.include?("does not match trusted load shape 100") },
  "candidate eligibility must derive sample count from the trusted load shape, not producer labels"
)

tampered_raw_digest = copy.call(fixture)
tampered_raw_digest["raw_samples"]["timings_ms"]["latency"][0] = 11
assert.call(
  "T-P1-012-PERF-REPRODUCIBLE-SAMPLES",
  semantic_errors.call(tampered_raw_digest).include?("raw_samples_sha256 does not match canonical raw samples"),
  "raw samples must be digest-bound and verifier-derived summaries must match them"
)

n_plus_one = copy.call(fixture)
n_plus_one["scaling_trials"].last["sql_queries"] = 250
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  semantic_errors.call(n_plus_one).any? { |error| error.include?("exceeds trusted scenario budget 4") },
  "set-oriented trials must use trusted scenario budgets and reject per-result SQL growth"
)

cached_authorization = copy.call(fixture)
cached_authorization["counts"]["authorization_cache_hits"] = 1
cached_authorization["raw_samples"]["counts"].each { |sample| sample["authorization_cache_hits"] = 1 }
refresh_evidence.call(cached_authorization)
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  semantic_errors.call(cached_authorization).include?("authorization decision cache hits must be zero"),
  "authorization-decision caching must be a hard global zero invariant"
)

direct_browser_call = copy.call(fixture)
direct_browser_call["counts"]["browser_forbidden_origin_requests"] = 1
direct_browser_call["raw_samples"]["counts"].each { |sample| sample["browser_forbidden_origin_requests"] = 1 }
refresh_evidence.call(direct_browser_call)
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  semantic_errors.call(direct_browser_call).include?("browser forbidden-origin requests must be zero"),
  "browser provider/internal-origin calls must be a hard global zero invariant"
)

[0, 2, 99].each do |browser_requests|
  fan_out = copy.call(fixture)
  fan_out["raw_samples"]["counts"].each { |sample| sample["browser_requests"] = browser_requests }
  refresh_evidence.call(fan_out)
  assert.call(
    "T-P1-012-PERF-ONE-COMPOSED-REQUEST",
    semantic_errors.call(fan_out).include?("primary surface after shell requires exactly one composed browser request"),
    "primary surfaces must require exactly one composed request, rejecting #{browser_requests}"
  )
end

zero_audit = copy.call(fixture)
zero_audit["raw_samples"]["counts"].each { |sample| sample["logical_audit_operations"] = 0 }
refresh_evidence.call(zero_audit)
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  semantic_errors.call(zero_audit).include?("request_boundary composed ordinary read requires exactly one logical audit operation"),
  "composed request-boundary reads must prove exactly one logical audit operation"
)

provider_waterfall = copy.call(fixture)
provider_waterfall["raw_samples"]["counts"].each { |sample| sample["provider_calls"] = 1 }
refresh_evidence.call(provider_waterfall)
assert.call(
  "T-P1-012-PERF-ZERO-PROVIDER-READ",
  semantic_errors.call(provider_waterfall).include?("ordinary read must make zero provider calls"),
  "ordinary reads must reject provider waterfalls regardless of producer claims"
)

nats_wait = copy.call(fixture)
nats_wait["raw_samples"]["counts"].each { |sample| sample["nats_waits"] = 1 }
refresh_evidence.call(nats_wait)
assert.call(
  "T-P1-012-PERF-ZERO-NATS-WAIT",
  semantic_errors.call(nats_wait).include?("request handling must wait for zero NATS operations"),
  "request handling must reject all NATS waits"
)

bundle_overage = copy.call(fixture)
bundle_overage["sizes"]["eager_javascript_gzip_bytes"] = 256_001
bundle_overage["sizes"]["frontend_baseline"]["current_gzip_bytes"] = 256_001
bundle_overage["sizes"]["frontend_baseline"]["delta_gzip_bytes"] = 195_193
assert.call(
  "T-P1-012-PERF-BUNDLE-DELTA",
  baseline["eager_javascript_bytes_gzip"] == 60_808 &&
    baseline["mature_devlane_interface_complete"] == false &&
    baseline["perf_005_complete"] == false &&
    canonical_errors.call(bundle_overage).any? { |error| error.include?("JSON Schema") || error.include?("budget exceeded") },
  "60,808 bytes remains a minimal-shell delta baseline and the 250 KiB gzip ceiling fails closed"
)

commit_claim = copy.call(fixture)
commit_claim["disclosure_mode"] = "commit_boundary"
assert.call(
  "T-P1-012-PERF-MODE-LABELING",
  canonical_errors.call(commit_claim).any? { |error| error.include?("JSON Schema") } &&
    manifest.document["disclosure_mode"] == "request_boundary",
  "Phase 1 evidence cannot inject or claim commit_boundary mode"
)

regression = copy.call(fixture)
regression["raw_samples"]["timings_ms"]["latency"][-2] = 90
refresh_evidence.call(regression)
evidence_sha = Digest::SHA256.hexdigest("regression-evidence")
regression_manifest_document = copy.call(manifest.document)
regression_manifest_document.fetch("scenarios").find { |scenario| scenario["id"] == "hot-composed-metadata" }["baselines"] = [{
  "baseline_id" => "measured-hot-p95",
  "metric" => "timings_ms.latency.p95",
  "value" => 75.0,
  "critical" => true,
  "source_revision" => "a799f2e3d166eab4489e7451a5b53f59a9d78f50"
}]
regression_manifest = Stead::TrustedPerformanceManifest.new(
  regression_manifest_document,
  path: manifest.path,
  root: ROOT
)
regression_validator = Stead::PerformanceEvidence.new(regression, manifest: regression_manifest)
regression_errors = regression_validator.validate(
  evidence_sha256: evidence_sha,
  implementation_owner: "owner@example.test"
)
comparison = regression_validator.regressions.find { |entry| entry["baseline_id"] == "measured-hot-p95" }
review = {
  "source_revision" => regression.dig("source", "revision"),
  "dataset_sha256" => manifest.digest,
  "evidence_sha256" => evidence_sha,
  "scenario_id" => regression["scenario_id"],
  "baseline_id" => comparison["baseline_id"],
  "metric" => comparison["metric"],
  "baseline" => comparison["value"],
  "current" => comparison["current"],
  "regression_percent" => comparison["regression_percent"],
  "reviewer" => { "identity" => "qa@example.test", "role" => "independent_qa" },
  "decision" => "approved_exception"
}
reviewed_errors = Stead::PerformanceEvidence.new(regression, manifest: regression_manifest).validate(
  regression_reviews: [review],
  evidence_sha256: evidence_sha,
  implementation_owner: "owner@example.test"
)
self_review = copy.call(review)
self_review["reviewer"]["identity"] = "owner@example.test"
self_review_errors = Stead::PerformanceEvidence.new(regression, manifest: regression_manifest).validate(
  regression_reviews: [self_review],
  evidence_sha256: evidence_sha,
  implementation_owner: "owner@example.test"
)
assert.call(
  "T-P1-012-PERF-REGRESSION-GATE",
  regression_errors.any? { |error| error.include?("without structured independent review") } &&
    reviewed_errors.none? { |error| error.include?("regression review") || error.include?("without structured") } &&
    self_review_errors.include?("implementation owner may not independently approve a regression"),
  "the verifier must compute compatible regressions and require a digest-bound independent structured review"
)

empty_comparison_bypass = copy.call(fixture)
empty_comparison_bypass["baseline_comparison"] = []
assert.call(
  "T-P1-012-PERF-REGRESSION-GATE",
  canonical_errors.call(empty_comparison_bypass).any? { |error| error.include?("JSON Schema") },
  "producers cannot waive trusted baselines by submitting an empty comparison list"
)

leaky_canary = copy.call(fixture)
leaky_canary["telemetry"]["records"][0]["attributes"]["description"] = "synthetic-canary"
leaky_canary["telemetry"]["records_sha256"] = Stead::PerformanceCanonicalJSON.digest(leaky_canary.dig("telemetry", "records"))
leaky_canary["telemetry"]["normalized_key_count"] = 6
leaky_canary["telemetry"]["normalized_string_value_count"] = 4
leak_errors = semantic_errors.call(leaky_canary)
assert.call(
  "T-P1-012-PERF-REDACTION",
  leak_errors.include?("telemetry.canary_value_hits does not match verifier-computed scan") &&
    leak_errors.include?("telemetry contains protected-content canary values"),
  "the verifier must scan normalized string values and detect a digest-only canary under an otherwise allowed key"
)

leaky_key = copy.call(fixture)
leaky_key["telemetry"]["records"][0]["attributes"]["Secret_Token"] = "redacted"
leaky_key["telemetry"]["records_sha256"] = Stead::PerformanceCanonicalJSON.digest(leaky_key.dig("telemetry", "records"))
leaky_key["telemetry"]["normalized_key_count"] = 6
leaky_key["telemetry"]["normalized_string_value_count"] = 4
assert.call(
  "T-P1-012-PERF-REDACTION",
  semantic_errors.call(leaky_key).include?("telemetry contains forbidden normalized keys"),
  "the verifier must normalize compound telemetry keys before redaction checks"
)

def build_candidate_evidence(manifest, scenario, revision)
  shape = manifest.load_shape(scenario.fetch("load_shape_id"))
  samples = shape.fetch("measured_samples")
  classifications = scenario.fetch("classifications")
  audit_count = classifications["ordinary_read"] && classifications["primary_surface_after_shell"] ? 1 : scenario.dig("count_budgets", "logical_audit_operations")
  counts = {
    "browser_requests" => classifications["primary_surface_after_shell"] ? 1 : 0,
    "sql_queries" => [scenario.dig("count_budgets", "sql_queries"), 1].min,
    "postgres_writes" => 0,
    "openfga_calls" => [scenario.dig("count_budgets", "openfga_calls"), 1].min,
    "policy_calls" => [scenario.dig("count_budgets", "policy_calls"), 1].min,
    "provider_calls" => 0,
    "nats_waits" => 0,
    "logical_audit_operations" => audit_count,
    "browser_forbidden_origin_requests" => 0,
    "authorization_cache_hits" => 0
  }
  timing_values = Stead::PerformanceEvidence::TIMING_GROUPS.to_h { |group| [group, Array.new(samples, 1.0)] }
  raw = {
    "timings_ms" => timing_values,
    "counts" => Array.new(samples) { Marshal.load(Marshal.dump(counts)) },
    "response_bytes" => Array.new(samples, 1_000),
    "web_vitals" => {
      "lcp_ms" => Array.new(samples, 1.0),
      "inp_ms" => Array.new(samples, 1.0),
      "cls" => Array.new(samples, 0.0)
    }
  }
  records = [{
    "metric" => "stead.performance.duration",
    "value" => 1.0,
    "attributes" => {
      "correlation_id_hash" => Digest::SHA256.hexdigest("#{scenario['id']}-correlation"),
      "scenario_id" => scenario["id"]
    }
  }]
  frontend_baseline = if classifications["frontend_touched"]
                        {
                          "baseline_id" => "foundation-shell-a799f2e",
                          "baseline_gzip_bytes" => 60_808,
                          "current_gzip_bytes" => 60_808,
                          "delta_gzip_bytes" => 0,
                          "lazy_chunk_delta_gzip_bytes" => 0
                        }
                      end
  {
    "artifact_type" => "performance_measurement",
    "schema_version" => "1.0",
    "evidence_id" => "candidate-#{scenario['id']}",
    "evidence_kind" => "measurement",
    "source" => {
      "revision" => revision,
      "dirty" => false,
      "recorded_at" => "2026-08-30T18:00:00Z",
      "tool_versions" => { "stead-reference-runner" => "1.0.0" }
    },
    "dataset" => { "manifest_id" => manifest.document["manifest_id"], "sha256" => manifest.digest },
    "scenario_id" => scenario["id"],
    "provenance" => {
      "runner" => "stead-reference-runner", "runner_version" => "1.0.0",
      "command" => "stead-perf run #{scenario['id']}",
      "started_at" => "2026-08-30T17:59:00Z", "ended_at" => "2026-08-30T18:00:00Z"
    },
    "counts" => counts,
    "timings_ms" => Stead::PerformanceEvidence::TIMING_GROUPS.to_h do |group|
      [group, { "p50" => 1.0, "p95" => 1.0, "p99" => 1.0 }]
    end,
    "sizes" => {
      "response_bytes" => 1_000,
      "eager_javascript_gzip_bytes" => 60_808,
      "lazy_javascript_chunks" => [],
      "frontend_baseline" => frontend_baseline
    },
    "web_vitals" => { "lcp_ms" => 1.0, "inp_ms" => 1.0, "cls" => 0.0 },
    "scaling_trials" => shape.fetch("result_counts").map do |result_count|
      { "result_count" => result_count }.merge(counts.slice(*Stead::PerformanceEvidence::BUDGET_COUNT_FIELDS))
    end,
    "raw_samples" => raw,
    "raw_samples_sha256" => Stead::PerformanceCanonicalJSON.digest(raw),
    "telemetry" => {
      "ruleset_id" => manifest.document.dig("telemetry_scan", "ruleset_id"),
      "records" => records,
      "records_sha256" => Stead::PerformanceCanonicalJSON.digest(records),
      "normalized_key_count" => 5,
      "normalized_string_value_count" => 3,
      "forbidden_key_hits" => 0,
      "forbidden_value_hits" => 0,
      "canary_value_hits" => 0,
      "protected_content_retained" => false
    }
  }
end

def write_json(path, document)
  File.write(path, "#{JSON.pretty_generate(document)}\n")
end

artifacts_parent = ROOT.join("artifacts/performance")
FileUtils.mkdir_p(artifacts_parent)
Dir.mktmpdir("foundation-contract-", artifacts_parent.to_s) do |directory|
  relative_directory = Pathname(directory).relative_path_from(ROOT).to_s
  revision = "b" * 40
  evidence_refs = manifest.document.fetch("scenarios").map do |scenario|
    evidence = build_candidate_evidence(manifest, scenario, revision)
    path = Pathname(directory).join("#{scenario['id']}.json")
    write_json(path, evidence)
    {
      "scenario_id" => scenario["id"],
      "path" => "#{relative_directory}/#{path.basename}",
      "sha256" => Stead::PerformanceCanonicalJSON.file_digest(path)
    }
  end

  artifact_refs = manifest.document.fetch("required_suite_artifact_kinds").map do |kind|
    measurements = [{ "metric" => "#{kind}.result", "value" => 1.0, "unit" => "count" }]
    causality = if kind == "response_before_relay"
                  {
                    "trace_id_hash" => Digest::SHA256.hexdigest("response-relay-trace"),
                    "events" => [
                      { "type" => "authoritative_commit", "monotonic_ns" => 100 },
                      { "type" => "response_sent", "monotonic_ns" => 200 },
                      { "type" => "relay_started", "monotonic_ns" => 300 }
                    ]
                  }
                end
    artifact = {
      "artifact_type" => "performance_benchmark_artifact",
      "schema_version" => "1.0",
      "artifact_id" => "candidate-#{kind}",
      "kind" => kind,
      "source_revision" => revision,
      "dataset_sha256" => manifest.digest,
      "scenario_ids" => manifest.scenario_ids,
      "producer" => { "tool" => "stead-reference-runner", "version" => "1.0.0", "command" => "stead-perf artifact #{kind}" },
      "status" => "PASS",
      "measurements" => measurements,
      "measurements_sha256" => Stead::PerformanceCanonicalJSON.digest(measurements),
      "recorded_at" => "2026-08-30T18:00:00Z",
      "causality" => causality
    }
    path = Pathname(directory).join("artifact-#{kind}.json")
    write_json(path, artifact)
    {
      "path" => "#{relative_directory}/#{path.basename}",
      "sha256" => Stead::PerformanceCanonicalJSON.file_digest(path)
    }
  end

  runtime_components = manifest.document.dig("server", "component_versions").map do |name, version|
    { "name" => name, "version" => version, "artifact_digest" => "sha256:#{Digest::SHA256.hexdigest(name)}" }
  end
  suite = {
    "artifact_type" => "performance_candidate_suite",
    "schema_version" => "1.0",
    "suite_id" => "phase1-candidate-contract-fixture",
    "phase" => "phase1",
    "source" => {
      "revision" => revision, "dirty" => false, "recorded_at" => "2026-08-30T18:00:00Z",
      "implementation_owner" => "implementation-owner@example.test",
      "tool_versions" => { "stead-reference-runner" => "1.0.0" }
    },
    "dataset" => {
      "path" => Stead::TrustedPerformanceManifest::MANIFEST_PATH,
      "sha256" => manifest.digest
    },
    "runtime_components" => runtime_components,
    "evidence" => evidence_refs,
    "benchmark_artifacts" => artifact_refs,
    "regression_reviews" => []
  }
  suite_path = Pathname(directory).join("candidate-suite.json")
  write_json(suite_path, suite)
  valid_suite = verifier.verify_suite(suite_path)
  assert.call(
    "T-P1-012-PERF-CANDIDATE-COVERAGE",
    valid_suite["candidate_eligible"] && valid_suite["errors"].empty?,
    "candidate eligibility must be verifier-derived only after exact scenario, artifact, source, dataset, and runtime coverage"
  )

  incomplete_suite = copy.call(suite)
  incomplete_suite["evidence"] = incomplete_suite["evidence"].drop(1)
  incomplete_path = Pathname(directory).join("candidate-suite-incomplete.json")
  write_json(incomplete_path, incomplete_suite)
  incomplete_result = verifier.verify_suite(incomplete_path)
  assert.call(
    "T-P1-012-PERF-CANDIDATE-COVERAGE",
    !incomplete_result["candidate_eligible"] &&
      incomplete_result["errors"].any? { |error| error.include?("cover every trusted Phase 1 scenario") || error.include?("JSON Schema") },
    "an incomplete evidence suite must never become candidate eligible"
  )

  weak_provenance = copy.call(suite)
  weak_provenance["runtime_components"].first["version"] = "x"
  weak_path = Pathname(directory).join("candidate-suite-weak-provenance.json")
  write_json(weak_path, weak_provenance)
  weak_result = verifier.verify_suite(weak_path)
  assert.call(
    "T-P1-012-PERF-CANDIDATE-COVERAGE",
    !weak_result["candidate_eligible"] && weak_result["errors"].any? { |error| error.include?("version must be") },
    "candidate runtime provenance must match trusted exact component versions"
  )

  missing_artifact = copy.call(suite)
  missing_artifact["benchmark_artifacts"].reject! { |reference| reference["path"].include?("response_before_relay") }
  missing_path = Pathname(directory).join("candidate-suite-missing-artifact.json")
  write_json(missing_path, missing_artifact)
  missing_result = verifier.verify_suite(missing_path)
  assert.call(
    "T-P1-012-PERF-CANDIDATE-COVERAGE",
    !missing_result["candidate_eligible"] && missing_result["errors"].any? { |error| error.include?("response_before_relay") },
    "candidate suites must include browser, Go, projection, bundle, golden, Peek, count, and relay evidence"
  )

  response_reference = suite["benchmark_artifacts"].find { |reference| reference["path"].include?("response_before_relay") }
  response_path = ROOT.join(response_reference["path"])
  response_document = parse.call(response_path)
  invalid_causality = copy.call(response_document)
  invalid_causality["causality"]["events"][1]["monotonic_ns"] = 400
  reversed_path = Pathname(directory).join("artifact-response-before-relay-reversed.json")
  write_json(reversed_path, invalid_causality)
  reversed_suite = copy.call(suite)
  reversed_ref = reversed_suite["benchmark_artifacts"].find { |reference| reference["path"].include?("response_before_relay") }
  reversed_ref["path"] = "#{relative_directory}/#{reversed_path.basename}"
  reversed_ref["sha256"] = Stead::PerformanceCanonicalJSON.file_digest(reversed_path)
  reversed_suite_path = Pathname(directory).join("candidate-suite-reversed-causality.json")
  write_json(reversed_suite_path, reversed_suite)
  reversed_result = verifier.verify_suite(reversed_suite_path)
  assert.call(
    "T-P1-012-PERF-CAUSALITY",
    !reversed_result["candidate_eligible"] && reversed_result["errors"].any? { |error| error.include?("commit <= response < relay") },
    "response-before-relay evidence must carry a digest-bound monotonic causality proof"
  )
end

Dir.rmdir(artifacts_parent) if artifacts_parent.directory? && artifacts_parent.children.empty?

missing_results = EXPECTED_TEST_IDS - results.keys
failures = results.flat_map { |test_id, messages| messages.map { |message| "#{test_id}: #{message}" } }
failures.concat(missing_results.map { |test_id| "#{test_id}: test did not execute" })

unless failures.empty?
  warn failures.join("\n")
  exit 1
end

EXPECTED_TEST_IDS.each { |test_id| puts "PASS #{test_id}" }
puts "Performance foundation validation passed: #{EXPECTED_TEST_IDS.length}/#{EXPECTED_TEST_IDS.length} named tests."
