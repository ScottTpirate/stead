#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "pathname"
require_relative "evidence_contract"

ROOT = Pathname.new(__dir__).join("../../..").expand_path
VALID_FIXTURE = ROOT.join("packages/test-fixtures/harness/performance/standard-request-boundary-valid.json")
FOUNDATION_BASELINE = ROOT.join("packages/test-fixtures/harness/performance/foundation-shell-baseline.json")
DATASET = ROOT.join("tests/performance/datasets/standard-request-boundary-v1.json")
SCHEMA = ROOT.join("tests/performance/harness/performance-evidence-v1.schema.json")

EXPECTED_TEST_IDS = %w[
  T-P1-012-PERF-EVIDENCE-SCHEMA
  T-P1-012-PERF-REPRODUCIBLE-FIXTURE
  T-P1-012-PERF-COUNTER-INVARIANTS
  T-P1-012-PERF-ONE-COMPOSED-REQUEST
  T-P1-012-PERF-ZERO-PROVIDER-READ
  T-P1-012-PERF-ZERO-NATS-WAIT
  T-P1-012-PERF-BUNDLE-DELTA
  T-P1-012-PERF-MODE-LABELING
  T-P1-012-PERF-REGRESSION-GATE
  T-P1-012-PERF-REDACTION
].freeze

results = Hash.new { |hash, key| hash[key] = [] }

assert = lambda do |test_id, condition, message|
  raise "unknown test ID #{test_id}" unless EXPECTED_TEST_IDS.include?(test_id)

  results[test_id]
  results[test_id] << message unless condition
end

parse = ->(path) { JSON.parse(path.read(encoding: "UTF-8")) }
copy = ->(value) { Marshal.load(Marshal.dump(value)) }
validate = ->(value) { Stead::PerformanceEvidence.new(value).validate }

schema = parse.call(SCHEMA)
fixture = parse.call(VALID_FIXTURE)
dataset = parse.call(DATASET)
baseline = parse.call(FOUNDATION_BASELINE)

assert.call(
  "T-P1-012-PERF-EVIDENCE-SCHEMA",
  schema["$schema"] == "https://json-schema.org/draft/2020-12/schema" &&
    schema["additionalProperties"] == false &&
    schema.fetch("required").sort == Stead::PerformanceEvidence::TOP_LEVEL_KEYS.sort &&
    validate.call(fixture).empty?,
  "evidence schema and semantic contract must accept the complete strict reference fixture"
)

missed_p50_target = copy.call(fixture)
missed_p50_target["timings_ms"]["latency"]["p50"] = 26.0
assert.call(
  "T-P1-012-PERF-EVIDENCE-SCHEMA",
  validate.call(missed_p50_target).any? { |error| error.include?("timings_ms.latency.p50: 26.0 ms > 25.0 ms") },
  "the hot composed metadata API p50 engineering target must fail closed"
)

missed_release_ceiling = copy.call(fixture)
missed_release_ceiling["timings_ms"]["latency"]["p95"] = 301.0
missed_release_ceiling["timings_ms"]["latency"]["p99"] = 310.0
assert.call(
  "T-P1-012-PERF-EVIDENCE-SCHEMA",
  validate.call(missed_release_ceiling).any? { |error| error.include?("absolute release ceiling") },
  "absolute OPS-005 release ceilings must fail independently of regression size"
)

[nil, "not-an-object", [], {}, { "scenario" => "not-an-object" }].each do |malformed|
  begin
    malformed_errors = validate.call(malformed)
    assert.call(
      "T-P1-012-PERF-EVIDENCE-SCHEMA",
      malformed_errors.is_a?(Array) && !malformed_errors.empty?,
      "malformed evidence must return validation errors"
    )
  rescue StandardError => error
    assert.call(
      "T-P1-012-PERF-EVIDENCE-SCHEMA",
      false,
      "malformed evidence must fail closed without crashing: #{error.class}: #{error.message}"
    )
  end
end

unknown_nested_field = copy.call(fixture)
unknown_nested_field["counts"]["hidden_provider_waterfall"] = 0
assert.call(
  "T-P1-012-PERF-EVIDENCE-SCHEMA",
  validate.call(unknown_nested_field).any? { |error| error.include?("counts unknown fields") },
  "the semantic verifier must reject undeclared nested evidence fields"
)

assert.call(
  "T-P1-012-PERF-REPRODUCIBLE-FIXTURE",
  dataset["dataset_id"] == fixture.dig("scenario", "dataset_version") &&
    dataset["benchmark_profile"] == "standard" &&
    dataset["disclosure_mode"] == "request_boundary" &&
    dataset.fetch("required_labels").length >= 10 &&
    fixture.dig("source", "revision").match?(/\A[0-9a-f]{40}\z/),
  "standard evidence must bind an exact source, dataset, topology, device, network, corpus, load, state, and disclosure mode"
)

n_plus_one = copy.call(fixture)
n_plus_one["scaling_trials"].last["sql_queries"] = 250
n_plus_one_errors = validate.call(n_plus_one)
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  n_plus_one_errors.any? { |error| error.include?("sql_queries exceeds bounded budget") },
  "set-oriented scale trials must reject per-result SQL growth"
)

cached_authorization = copy.call(fixture)
cached_authorization["counts"]["authorization_cache_hits"] = 1
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  validate.call(cached_authorization).include?("authorization decision cache hits are prohibited"),
  "performance optimization must never introduce authorization-decision caching"
)

direct_browser_call = copy.call(fixture)
direct_browser_call["counts"]["browser_forbidden_origin_requests"] = 1
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  validate.call(direct_browser_call).include?("browser must make zero direct provider or internal-infrastructure requests"),
  "the browser must never bypass the composed Stead API/BFF path"
)

fan_out = copy.call(fixture)
fan_out["counts"]["browser_requests"] = 2
assert.call(
  "T-P1-012-PERF-ONE-COMPOSED-REQUEST",
  validate.call(fan_out).include?("primary surface after shell may use at most one composed browser request"),
  "primary surfaces must reject browser fan-out"
)

provider_waterfall = copy.call(fixture)
provider_waterfall["counts"]["provider_calls"] = 1
assert.call(
  "T-P1-012-PERF-ZERO-PROVIDER-READ",
  validate.call(provider_waterfall).include?("ordinary read must make zero provider calls"),
  "ordinary reads must reject provider calls"
)

nats_wait = copy.call(fixture)
nats_wait["counts"]["nats_waits"] = 1
assert.call(
  "T-P1-012-PERF-ZERO-NATS-WAIT",
  validate.call(nats_wait).include?("ordinary read must wait for zero NATS operations"),
  "ordinary reads must reject NATS waits"
)

bundle_overage = copy.call(fixture)
bundle_overage["sizes"]["eager_javascript_gzip_bytes"] = 256_001
bundle_overage["sizes"]["frontend_baseline"]["current_gzip_bytes"] = 256_001
bundle_overage["sizes"]["frontend_baseline"]["delta_gzip_bytes"] = 195_193
bundle_errors = validate.call(bundle_overage)
assert.call(
  "T-P1-012-PERF-BUNDLE-DELTA",
  baseline["source_revision"] == "a799f2e3d166eab4489e7451a5b53f59a9d78f50" &&
    baseline["eager_javascript_bytes_gzip"] == 60_808 &&
    baseline["mature_devlane_interface_complete"] == false &&
    baseline["perf_005_complete"] == false &&
    bundle_errors.any? { |error| error.include?("eager JavaScript gzip budget exceeded") },
  "the 60,808-byte minimal baseline must remain scoped and the 250 KiB gzip ceiling must fail closed"
)

wrong_mode = copy.call(fixture)
wrong_mode["scenario"]["disclosure_mode"] = "commit_boundary"
assert.call(
  "T-P1-012-PERF-MODE-LABELING",
  validate.call(wrong_mode).include?("standard benchmark must use request_boundary"),
  "standard and high-assurance disclosure modes must never be mislabeled"
)

regression = copy.call(fixture)
regression["baseline_comparison"][0].merge!(
  "baseline" => 70.0,
  "current" => 80.0,
  "regression_percent" => 14.2857,
  "independent_review_ref" => nil
)
assert.call(
  "T-P1-012-PERF-REGRESSION-GATE",
  validate.call(regression).any? { |error| error.include?("regressed 14.29% without independent review") },
  "critical regressions over ten percent require explicit independent review"
)

leaky = copy.call(fixture)
leaky["telemetry"]["protected_content_canary_hits"] = 1
leaky["telemetry"]["secret"] = "synthetic-canary"
leak_errors = validate.call(leaky)
assert.call(
  "T-P1-012-PERF-REDACTION",
  leak_errors.include?("protected-content telemetry canary detected leakage") &&
    leak_errors.any? { |error| error.include?("forbidden sensitive evidence field") },
  "performance evidence must reject protected-content canaries and sensitive fields"
)

missing_results = EXPECTED_TEST_IDS - results.keys
failures = results.flat_map { |test_id, messages| messages.map { |message| "#{test_id}: #{message}" } }
failures.concat(missing_results.map { |test_id| "#{test_id}: test did not execute" })

unless failures.empty?
  warn failures.join("\n")
  exit 1
end

EXPECTED_TEST_IDS.each { |test_id| puts "PASS #{test_id}" }
puts "Performance foundation validation passed: #{EXPECTED_TEST_IDS.length}/#{EXPECTED_TEST_IDS.length} named tests."
