#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "open3"
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

parse = ->(path) { Stead::PerformanceStrictJSON.parse_file(path) }
copy = ->(value) { Marshal.load(Marshal.dump(value)) }
fixture = parse.call(FIXTURE_PATH)
baseline = parse.call(BASELINE_PATH)
verifier = Stead::PerformanceVerifier.new(root: ROOT)
manifest = verifier.manifest

strict_rejections = [
  '{"source":{"revision":"a","revision":"b"}}',
  '{"source":{"revision":"a","\\u0072evision":"b"}}',
  "[" * 33 + "0" + "]" * 33,
  JSON.generate("x" * (Stead::PerformanceStrictJSON::MAX_STRING_BYTES + 1)),
  "[" + (["0"] * (Stead::PerformanceStrictJSON::MAX_COLLECTION_ENTRIES + 1)).join(",") + "]"
]
strict_results = strict_rejections.map do |source|
  begin
    Stead::PerformanceStrictJSON.parse(source)
    false
  rescue JSON::ParserError
    true
  end
end
exact_depth = Stead::PerformanceStrictJSON.parse("[" * 32 + "0" + "]" * 32)
exact_string = Stead::PerformanceStrictJSON.parse(JSON.generate("x" * Stead::PerformanceStrictJSON::MAX_STRING_BYTES))
exact_bytes_source = '{"a":1}'
exact_bytes = Stead::PerformanceStrictJSON.parse(exact_bytes_source, max_bytes: exact_bytes_source.bytesize)
one_over_bytes = begin
  Stead::PerformanceStrictJSON.parse(exact_bytes_source, max_bytes: exact_bytes_source.bytesize - 1)
  false
rescue JSON::ParserError
  true
end
bounded_file_results = Tempfile.create(["stead-performance-bounded-", ".bin"]) do |file|
  file.binmode
  file.write("abcd")
  file.flush
  exact_read = Stead::PerformanceBoundedFile.read(file.path, max_bytes: 4) == "abcd"
  exact_digest = Stead::PerformanceBoundedFile.sha256(file.path, max_bytes: 4) == Digest::SHA256.hexdigest("abcd")
  one_over_read = begin
    Stead::PerformanceBoundedFile.read(file.path, max_bytes: 3)
    false
  rescue Stead::PerformanceBoundedFile::TooLarge
    true
  end
  one_over_digest = begin
    Stead::PerformanceBoundedFile.sha256(file.path, max_bytes: 3)
    false
  rescue Stead::PerformanceBoundedFile::TooLarge
    true
  end
  exact_read && exact_digest && one_over_read && one_over_digest
end
assert.call(
  "T-P1-012-PERF-EVIDENCE-SCHEMA",
  strict_results.all? && exact_depth.is_a?(Array) && exact_string.bytesize == Stead::PerformanceStrictJSON::MAX_STRING_BYTES &&
    exact_bytes == { "a" => 1 } && one_over_bytes && bounded_file_results,
  "all JSON and artifact entrypoints must reject duplicate decoded keys and enforce exact byte, depth, collection, and decoded-string ceilings before semantic parsing or hashing"
)

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

percentile = lambda do |values, quantile|
  values.sort.fetch([(quantile * values.length).ceil - 1, 0].max)
end

refresh_evidence = lambda do |document|
  raw = document.fetch("raw_samples")
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
  document["request_traces_sha256"] = Stead::PerformanceCanonicalJSON.digest(document.fetch("request_traces"))
  document["telemetry"]["records_sha256"] = Stead::PerformanceCanonicalJSON.digest(document.dig("telemetry", "records"))
  document
end

resize_samples = lambda do |document, count|
  raw = document.fetch("raw_samples")
  raw.fetch("timings_ms").each do |group, values|
    raw["timings_ms"][group] = Array.new(count) { |index| values[index % values.length] }
  end
  raw["counts"] = Array.new(count) { |index| copy.call(raw["counts"][index % raw["counts"].length]) }
  raw["response_bytes"] = Array.new(count) { |index| raw["response_bytes"][index % raw["response_bytes"].length] }
  raw.fetch("web_vitals").each do |metric, values|
    raw["web_vitals"][metric] = Array.new(count) { |index| values[index % values.length] }
  end
  refresh_evidence.call(document)
end

trace_for_counts = lambda do |counts, scenario_id, sample_index = 0|
  events = []
  scenario = manifest.scenario(scenario_id)
  load_shape = manifest.load_shape(scenario.fetch("load_shape_id"))
  sample_started_ns = sample_index * load_shape.fetch("pacing_ms") * 1_000_000
  monotonic_ns = sample_started_ns + 100
  transaction_id_hash = Digest::SHA256.hexdigest("#{scenario_id}-transaction-#{sample_index}")
  outbox_event_id_hash = Digest::SHA256.hexdigest("#{scenario_id}-outbox-event-#{sample_index}")
  add = lambda do |type, count, origin: nil, route_template: nil, write_role: nil, transaction_id_hash: nil|
    count.times do
      events << {
        "type" => type,
        "monotonic_ns" => monotonic_ns,
        "origin" => origin,
        "route_template" => route_template,
        "write_role" => write_role,
        "transaction_id_hash" => transaction_id_hash,
        "outbox_event_id_hash" => write_role == "transactional_outbox" ? outbox_event_id_hash : nil
      }
      monotonic_ns += 10
    end
  end
  add.call("browser_request", counts["browser_requests"], origin: "stead_api", route_template: "/api/v1/projects/{project_id}/overview")
  add.call("openfga_call", counts["openfga_calls"])
  add.call("policy_call", counts["policy_calls"])
  add.call("sql_query", counts["sql_queries"])
  if scenario_id == "metadata-mutation" && counts["postgres_writes"] >= 2
    add.call("postgres_write", 1, write_role: "authoritative_state", transaction_id_hash: transaction_id_hash)
    add.call("postgres_write", 1, write_role: "transactional_outbox", transaction_id_hash: transaction_id_hash)
    add.call("postgres_write", counts["postgres_writes"] - 2, write_role: "aggregate_audit", transaction_id_hash: transaction_id_hash)
  elsif scenario.fetch("required_artifact_kinds").include?("response_before_relay") && counts["postgres_writes"] >= 1
    add.call("postgres_write", 1, write_role: "transactional_outbox", transaction_id_hash: transaction_id_hash)
    add.call("postgres_write", counts["postgres_writes"] - 1, write_role: "aggregate_audit", transaction_id_hash: transaction_id_hash)
  else
    add.call("postgres_write", counts["postgres_writes"], write_role: "aggregate_audit", transaction_id_hash: transaction_id_hash)
  end
  add.call("provider_call", counts["provider_calls"])
  add.call("nats_wait", counts["nats_waits"])
  add.call("logical_audit_operation", counts["logical_audit_operations"])
  add.call("authorization_cache_hit", counts["authorization_cache_hits"])
  %w[authoritative_commit response_sent relay_started].each do |type|
    events << {
      "type" => type, "monotonic_ns" => monotonic_ns, "origin" => nil, "route_template" => nil,
      "write_role" => nil, "transaction_id_hash" => transaction_id_hash,
      "outbox_event_id_hash" => outbox_event_id_hash
    }
    monotonic_ns += 10
  end
  {
    "trace_id_hash" => Digest::SHA256.hexdigest("#{scenario_id}-trace-#{sample_index}"),
    "sample_index" => sample_index,
    "sample_started_monotonic_ns" => sample_started_ns,
    "events" => events
  }
end

traces_for_samples = lambda do |document|
  document.fetch("raw_samples").fetch("counts").each_with_index.map do |counts, sample_index|
    trace_for_counts.call(counts, document.fetch("scenario_id"), sample_index)
  end
end

valid = verifier.verify_evidence(FIXTURE_PATH)
assert.call(
  "T-P1-012-PERF-EVIDENCE-SCHEMA",
  valid["errors"].empty? && valid["candidate_eligible"] == false,
  "the canonical verifier must validate every strict schema and keep a synthetic fixture noncandidate"
)

schema_only_invalid = copy.call(fixture)
schema_only_invalid["sizes"]["response_bytes"] = "x"
assert.call(
  "T-P1-012-PERF-EVIDENCE-SCHEMA",
  canonical_errors.call(schema_only_invalid).any? { |error| error.include?("JSON Schema") },
  "a structurally invalid nested value must fail the canonical verifier"
)

producer_authority = copy.call(fixture)
producer_authority["candidate_eligible"] = true
producer_authority["count_budgets"] = { "sql_queries" => 99_999 }
producer_authority["ordinary_read"] = false
assert.call(
  "T-P1-012-PERF-TRUSTED-MANIFEST",
  canonical_errors.call(producer_authority).any? { |error| error.include?("JSON Schema") },
  "evidence producers must not self-assert eligibility, classification, or budgets"
)

manifest_document = manifest.document
assert.call(
  "T-P1-012-PERF-TRUSTED-MANIFEST",
  valid["errors"].empty? &&
    manifest_document.dig("client", "cpu_model") == "Intel Xeon Gold 6338N" &&
    manifest_document.dig("server", "cpu_base_frequency_mhz") == 2_200 &&
    manifest_document.fetch("load_shapes").all? { |shape| shape.key?("arrival_model") && shape.key?("pacing_ms") && shape.key?("duration_seconds") } &&
    manifest_document.fetch("corpus").values.sum == 300_010 &&
    manifest_document.dig("generator", "output_sha256") == "b49e366d5a1bb95718d53ef402b17e9e2f9612ad7404972b322f48030f80cd96",
  "the trusted manifest must bind exact CPU, network, load, realistic corpus, generator, and reproducible output bytes"
)

generated_output, generator_stderr, generator_status = Open3.capture3(
  "ruby", ROOT.join(manifest_document.dig("generator", "path")).to_s,
  chdir: ROOT.to_s
)
generated_corpus = generator_status.success? ? Stead::PerformanceStrictJSON.parse(generated_output) : {}
generated_corpus.dig("relationships", 0)&.store("target_id", "document_000000000000000000000000")
generated_corpus.dig("releases", 0)&.store("approver_person_id", "person_000000000000000000000000")
generated_corpus.dig("teams", 0)&.store("parent_team_id", generated_corpus.dig("teams", 1, "id"))
generated_corpus.dig("teams", 7)&.store("parent_team_id", nil)
generated_corpus["team_edges"] = generated_corpus.fetch("teams").filter_map do |team|
  next if team["parent_team_id"].nil?

  { "parent_team_id" => team["parent_team_id"], "child_team_id" => team["id"], "depth" => 1 }
end
generated_corpus.fetch("work_items").each_with_index do |work, index|
  work["status"] = index < Stead::PerformanceNormativeControls::CORPUS_DISTRIBUTION_COUNT_BOUNDS.fetch("work_status").length ?
    Stead::PerformanceNormativeControls::CORPUS_DISTRIBUTION_COUNT_BOUNDS.fetch("work_status").keys[index] : "backlog"
end
corrupt_corpus_errors = manifest.send(:validate_generated_corpus, generated_corpus)
assert.call(
  "T-P1-012-PERF-TRUSTED-MANIFEST",
  generator_status.success? && generator_stderr.empty? &&
    Digest::SHA256.hexdigest(generated_output) == manifest_document.dig("generator", "output_sha256") &&
    corrupt_corpus_errors.include?("generated Work-Doc relationships must have valid same-organization endpoints") &&
    corrupt_corpus_errors.include?("generated releases must reference same-repository packages and same-organization human approvers") &&
    corrupt_corpus_errors.include?("generated team hierarchy must be acyclic, rooted, and no deeper than two levels") &&
    corrupt_corpus_errors.include?("generated corpus lacks required work_status distribution"),
  "generator output must be byte-reproducible and endpoint, hierarchy, or distribution corruption must fail semantic checks"
)
generated_corpus = nil
generated_output = nil
GC.start

weakened_manifest_document = copy.call(manifest_document)
weakened = weakened_manifest_document.fetch("scenarios").find { |scenario| scenario["id"] == "hot-composed-metadata" }
weakened["classifications"] = { "ordinary_read" => false, "primary_surface_after_shell" => false, "set_oriented" => false, "frontend_touched" => false }
weakened["count_budgets"].transform_values! { 999_999 }
weakened["targets"].each { |target| target["maximum"] = 999_999 }
weakened["required_artifact_kinds"] = ["runner_attestation"]
weakened_manifest_document["telemetry_scan"]["forbidden_normalized_keys"] = ["password"]
weakened_manifest = Stead::TrustedPerformanceManifest.new(weakened_manifest_document, path: manifest.path, root: ROOT)
weakened_errors = weakened_manifest.validate
assert.call(
  "T-P1-012-PERF-TRUSTED-MANIFEST",
  weakened_errors.any? { |error| error.include?("classifications weakens") } &&
    weakened_errors.any? { |error| error.include?("count_budgets weakens") } &&
    weakened_errors.any? { |error| error.include?("targets or ceilings weaken") } &&
    weakened_errors.any? { |error| error.include?("required_artifact_kinds weakens") } &&
    weakened_errors.include?("trusted telemetry forbidden keys weaken verifier-owned scanning"),
  "a branch may not relabel a scenario or weaken hard budgets, targets, ceilings, or instrumentation"
)

wrong_dataset = copy.call(fixture)
wrong_dataset["dataset"]["sha256"] = "0" * 64
assert.call(
  "T-P1-012-PERF-TRUSTED-MANIFEST",
  semantic_errors.call(wrong_dataset).include?("evidence dataset digest does not match the trusted manifest"),
  "evidence must bind the repository-owned dataset manifest bytes"
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
  "candidate sample count must come from the exact trusted load shape"
)

tampered_raw_digest = copy.call(fixture)
tampered_raw_digest["raw_samples"]["timings_ms"]["latency"][0] = 11
assert.call(
  "T-P1-012-PERF-REPRODUCIBLE-SAMPLES",
  semantic_errors.call(tampered_raw_digest).include?("raw_samples_sha256 does not match canonical raw samples"),
  "raw samples and their derived summaries must be digest-bound"
)

zero_fresh_auth = resize_samples.call(copy.call(fixture), 100)
zero_fresh_auth["evidence_kind"] = "measurement"
zero_fresh_auth["raw_samples"]["counts"].each do |sample|
  sample["openfga_calls"] = 0
  sample["policy_calls"] = 0
end
zero_fresh_auth["request_traces"] = traces_for_samples.call(zero_fresh_auth)
refresh_evidence.call(zero_fresh_auth)
zero_fresh_auth_errors = semantic_errors.call(zero_fresh_auth, candidate: true)
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  zero_fresh_auth.dig("raw_samples", "counts").length == 100 &&
    zero_fresh_auth_errors.include?("counts.openfga_calls must equal verifier-owned value 1") &&
    zero_fresh_auth_errors.include?("counts.policy_calls must equal verifier-owned value 1"),
  "100 fast samples with no fresh OpenFGA and deterministic-policy calls must fail closed"
)

one_good_sample = resize_samples.call(copy.call(fixture), 100)
one_good_sample["evidence_kind"] = "measurement"
one_good_sample["raw_samples"]["counts"].drop(1).each do |sample|
  sample["postgres_writes"] = 0
  sample["openfga_calls"] = 0
  sample["policy_calls"] = 0
  sample["logical_audit_operations"] = 0
end
one_good_sample["request_traces"] = traces_for_samples.call(one_good_sample)
refresh_evidence.call(one_good_sample)
one_good_sample_errors = semantic_errors.call(one_good_sample, candidate: true)
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  one_good_sample_errors.include?("raw_samples.counts[1].openfga_calls must equal verifier-owned value 1") &&
    one_good_sample_errors.include?("raw_samples.counts[1].policy_calls must equal verifier-owned value 1") &&
    one_good_sample_errors.include?("raw_samples.counts[1].logical_audit_operations must equal verifier-owned value 1") &&
    one_good_sample_errors.include?("raw_samples.counts[1].postgres_writes must be at least verifier-owned minimum 1"),
  "one compliant maximum sample may not hide 99 requests that skipped authorization, audit, and writes"
)

incomplete_traces = resize_samples.call(copy.call(fixture), 100)
incomplete_traces["evidence_kind"] = "measurement"
incomplete_traces["request_traces"] = [trace_for_counts.call(incomplete_traces.dig("raw_samples", "counts", 0), incomplete_traces["scenario_id"])]
refresh_evidence.call(incomplete_traces)
assert.call(
  "T-P1-012-PERF-REPRODUCIBLE-SAMPLES",
  semantic_errors.call(incomplete_traces, candidate: true).include?("candidate request traces must cover every raw count sample exactly once"),
  "a candidate may not trace only one representative request from a 100-sample run"
)

false_load_schedule = resize_samples.call(copy.call(fixture), 100)
false_load_schedule["evidence_kind"] = "measurement"
false_load_schedule["request_traces"] = traces_for_samples.call(false_load_schedule)
false_load_schedule.dig("request_traces", 50)["sample_started_monotonic_ns"] += 1
refresh_evidence.call(false_load_schedule)
assert.call(
  "T-P1-012-PERF-REPRODUCIBLE-SAMPLES",
  semantic_errors.call(false_load_schedule, candidate: true).any? { |error| error.include?("exactly prove trusted pacing") },
  "candidate sample timestamps must prove the exact verifier-owned arrival pacing and measured duration"
)

zero_mutation = resize_samples.call(copy.call(fixture), 100)
zero_mutation["evidence_kind"] = "measurement"
zero_mutation["scenario_id"] = "metadata-mutation"
zero_mutation["go_microbenchmark"] = nil
zero_mutation["scaling_trials"] = []
zero_mutation["raw_samples"]["counts"].each do |sample|
  sample.keys.each { |field| sample[field] = 0 }
  sample["browser_requests"] = 1
end
zero_mutation["request_traces"] = traces_for_samples.call(zero_mutation)
refresh_evidence.call(zero_mutation)
zero_mutation_errors = semantic_errors.call(zero_mutation, candidate: true)
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  zero_mutation_errors.include?("counts.postgres_writes must be at least verifier-owned minimum 2") &&
    zero_mutation_errors.include?("counts.openfga_calls must equal verifier-owned value 1") &&
    zero_mutation_errors.include?("counts.policy_calls must equal verifier-owned value 1") &&
    zero_mutation_errors.include?("counts.logical_audit_operations must equal verifier-owned value 1") &&
    zero_mutation_errors.include?("metadata mutation trace must contain authoritative state and transactional outbox writes"),
  "a metadata mutation must prove actual authoritative/outbox writes, fresh central authorization, and logical audit"
)

n_plus_one = copy.call(fixture)
n_plus_one["scaling_trials"].last["sql_queries"] = 250
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  semantic_errors.call(n_plus_one).any? { |error| error.include?("exceeds trusted scenario budget 4") },
  "set-oriented trials must reject query growth with result count"
)

cached_authorization = copy.call(fixture)
cached_authorization["raw_samples"]["counts"].each { |sample| sample["authorization_cache_hits"] = 1 }
cached_authorization["request_traces"] = [trace_for_counts.call(cached_authorization.dig("raw_samples", "counts", 0), cached_authorization["scenario_id"])]
refresh_evidence.call(cached_authorization)
assert.call(
  "T-P1-012-PERF-COUNTER-INVARIANTS",
  semantic_errors.call(cached_authorization).include?("counts.authorization_cache_hits must equal verifier-owned value 0"),
  "authorization-decision caching must remain a hard global zero"
)

[0, 2, 99].each do |browser_requests|
  fan_out = copy.call(fixture)
  fan_out["raw_samples"]["counts"].each { |sample| sample["browser_requests"] = browser_requests }
  fan_out["request_traces"] = [trace_for_counts.call(fan_out.dig("raw_samples", "counts", 0), fan_out["scenario_id"])]
  refresh_evidence.call(fan_out)
  assert.call(
    "T-P1-012-PERF-ONE-COMPOSED-REQUEST",
    semantic_errors.call(fan_out).include?("counts.browser_requests must equal verifier-owned value 1"),
    "primary surfaces must reject #{browser_requests} composed browser requests"
  )
end

provider_waterfall = copy.call(fixture)
provider_waterfall["raw_samples"]["counts"].each { |sample| sample["provider_calls"] = 1 }
provider_waterfall["request_traces"] = [trace_for_counts.call(provider_waterfall.dig("raw_samples", "counts", 0), provider_waterfall["scenario_id"])]
refresh_evidence.call(provider_waterfall)
assert.call(
  "T-P1-012-PERF-ZERO-PROVIDER-READ",
  semantic_errors.call(provider_waterfall).include?("counts.provider_calls must equal verifier-owned value 0"),
  "ordinary reads must reject synchronous provider waterfalls"
)

nats_wait = copy.call(fixture)
nats_wait["raw_samples"]["counts"].each { |sample| sample["nats_waits"] = 1 }
nats_wait["request_traces"] = [trace_for_counts.call(nats_wait.dig("raw_samples", "counts", 0), nats_wait["scenario_id"])]
refresh_evidence.call(nats_wait)
assert.call(
  "T-P1-012-PERF-ZERO-NATS-WAIT",
  semantic_errors.call(nats_wait).include?("counts.nats_waits must equal verifier-owned value 0"),
  "request handling must reject every NATS wait"
)

fabricated_baseline = copy.call(fixture)
fabricated_baseline.dig("sizes", "frontend_baseline")["baseline_id"] = "producer-invented-baseline"
fabricated_baseline.dig("sizes", "frontend_baseline")["baseline_gzip_bytes"] = 1
fabricated_baseline.dig("sizes", "frontend_baseline")["delta_gzip_bytes"] = 60_807
fabricated_baseline_errors = semantic_errors.call(fabricated_baseline)
assert.call(
  "T-P1-012-PERF-BUNDLE-DELTA",
  fabricated_baseline_errors.include?("frontend baseline ID is not the trusted bundle baseline") &&
    fabricated_baseline_errors.include?("frontend baseline gzip bytes are not the trusted measured value") &&
    baseline["eager_javascript_bytes_gzip"] == 60_808 &&
    baseline.dig("measured_files", 0, "file_sha256") == "d523f43d46b2f22af76db4d471846beb35a46bb71c4a4aac45100bd710b53d6b" &&
    valid["errors"].empty?,
  "the 60,808-byte baseline must rebuild from its immutable source and bind actual bundle, tool, lock, and dataset bytes"
)

bundle_overage = copy.call(fixture)
bundle_overage["sizes"]["eager_javascript_gzip_bytes"] = 256_001
bundle_overage["sizes"]["frontend_baseline"]["current_gzip_bytes"] = 256_001
bundle_overage["sizes"]["frontend_baseline"]["delta_gzip_bytes"] = 195_193
assert.call(
  "T-P1-012-PERF-BUNDLE-DELTA",
  canonical_errors.call(bundle_overage).any? { |error| error.include?("JSON Schema") || error.include?("budget exceeded") },
  "the 250 KiB gzip ceiling must remain absolute"
)

commit_claim = copy.call(fixture)
commit_claim["disclosure_mode"] = "commit_boundary"
assert.call(
  "T-P1-012-PERF-MODE-LABELING",
  canonical_errors.call(commit_claim).any? { |error| error.include?("JSON Schema") } && manifest_document["disclosure_mode"] == "request_boundary",
  "Phase 1 candidate evidence cannot inject commit_boundary mode"
)

regression = copy.call(fixture)
regression["raw_samples"]["timings_ms"]["latency"][-2] = 90
refresh_evidence.call(regression)
regression_manifest_document = copy.call(manifest_document)
regression_manifest_document.fetch("scenarios").find { |scenario| scenario["id"] == "hot-composed-metadata" }["baselines"] = [{
  "baseline_id" => "measured-hot-p95",
  "metric" => "timings_ms.latency.p95",
  "value" => 75.0,
  "critical" => true,
  "source_revision" => fixture.dig("source", "revision"),
  "benchmark_profile" => "standard",
  "disclosure_mode" => "request_boundary",
  "environment_sha256" => manifest.environment_digest("hot-composed-metadata"),
  "reference_artifact_sha256" => "d" * 64
}]
regression_manifest = Stead::TrustedPerformanceManifest.new(regression_manifest_document, path: manifest.path, root: ROOT)
regression_validator = Stead::PerformanceEvidence.new(regression, manifest: regression_manifest)
evidence_sha = Digest::SHA256.hexdigest("regression-evidence")
unreviewed_errors = regression_validator.validate(evidence_sha256: evidence_sha, implementation_owner: "owner@example.test")
comparison = regression_validator.regressions.find { |entry| entry["baseline_id"] == "measured-hot-p95" }
self_asserted_review = {
  "source_revision" => regression.dig("source", "revision"), "dataset_sha256" => manifest.digest,
  "evidence_sha256" => evidence_sha, "scenario_id" => regression["scenario_id"],
  "baseline_id" => comparison["baseline_id"], "metric" => comparison["metric"],
  "baseline" => comparison["value"], "current" => comparison["current"],
  "regression_percent" => comparison["regression_percent"],
  "reviewer" => { "identity" => "qa@example.test", "role" => "independent_qa" },
  "decision" => "approved_exception"
}
self_asserted_errors = Stead::PerformanceEvidence.new(regression, manifest: regression_manifest).validate(
  regression_reviews: [self_asserted_review], evidence_sha256: evidence_sha, implementation_owner: "owner@example.test"
)
assert.call(
  "T-P1-012-PERF-REGRESSION-GATE",
  unreviewed_errors.any? { |error| error.include?("without structured independent review") } &&
    self_asserted_errors.include?("critical regression review lacks immutable independent reviewer authority verification") &&
    comparison["regression_percent"] > 10,
  "regressions must be verifier-computed and a producer-asserted reviewer role cannot waive them"
)

raw_canary = copy.call(fixture)
raw_canary["telemetry"]["records"][0]["attributes"]["description"] = "prefix--synthetic-canary--suffix"
raw_canary["telemetry"]["normalized_key_count"] = 6
raw_canary["telemetry"]["normalized_string_value_count"] = 4
raw_canary["telemetry"]["records_sha256"] = Stead::PerformanceCanonicalJSON.digest(raw_canary.dig("telemetry", "records"))
raw_canary_errors = semantic_errors.call(raw_canary)

encoded_canary = copy.call(fixture)
encoded_payload = "prefix--#{Stead::PerformanceNormativeControls::TELEMETRY_CANARIES.last}--suffix"
encoded = [encoded_payload].pack("m0").tr("+/", "-_").delete_suffix("=")
encoded_canary["telemetry"]["records"][0]["attributes"][encoded] = "redacted"
encoded_canary["telemetry"]["records"][0]["attributes"]["description"] = "otel:#{encoded}:tag"
encoded_canary["telemetry"]["normalized_key_count"] = 7
encoded_canary["telemetry"]["normalized_string_value_count"] = 5
encoded_canary["telemetry"]["records_sha256"] = Stead::PerformanceCanonicalJSON.digest(encoded_canary.dig("telemetry", "records"))
encoded_canary_errors = semantic_errors.call(encoded_canary)

split_encoded_canary = copy.call(fixture)
split_encoded = [Stead::PerformanceNormativeControls::TELEMETRY_CANARIES.first].pack("m0").scan(/.{1,4}/).join(" \n")
split_encoded_canary["telemetry"]["records"][0]["attributes"]["description"] = "otel:#{split_encoded}:tag"
split_encoded_canary["telemetry"]["normalized_key_count"] = 6
split_encoded_canary["telemetry"]["normalized_string_value_count"] = 4
split_encoded_canary["telemetry"]["records_sha256"] = Stead::PerformanceCanonicalJSON.digest(split_encoded_canary.dig("telemetry", "records"))
split_encoded_canary_errors = semantic_errors.call(split_encoded_canary)
assert.call(
  "T-P1-012-PERF-REDACTION",
  [raw_canary_errors, encoded_canary_errors, split_encoded_canary_errors].all? do |errors|
    errors.include?("telemetry.canary_value_hits does not match verifier-computed scan") &&
      errors.include?("telemetry contains protected-content canary values")
  end,
  "recursive telemetry scanning must detect raw, URL-safe, and separator-obfuscated encoded canaries as key/value substrings"
)

forbidden_key = copy.call(fixture)
forbidden_key["telemetry"]["records"][0]["attributes"]["Secret_Token"] = "redacted"
forbidden_key["telemetry"]["normalized_key_count"] = 6
forbidden_key["telemetry"]["normalized_string_value_count"] = 4
forbidden_key["telemetry"]["records_sha256"] = Stead::PerformanceCanonicalJSON.digest(forbidden_key.dig("telemetry", "records"))
assert.call(
  "T-P1-012-PERF-REDACTION",
  semantic_errors.call(forbidden_key).include?("telemetry contains forbidden normalized keys"),
  "telemetry keys must be normalized before protected-field scanning"
)

head = `git -C #{ROOT} rev-parse HEAD`.strip
synthetic_suite = {
  "artifact_type" => "performance_candidate_suite", "schema_version" => "1.0",
  "suite_id" => "synthetic-explicitly-noncandidate", "phase" => "phase1",
  "source" => {
    "revision" => "b" * 40, "controls_revision" => "a" * 40, "dirty" => false,
    "recorded_at" => "2026-08-30T18:00:00Z", "implementation_owner" => "owner@example.test",
    "tool_versions" => fixture.dig("source", "tool_versions")
  },
  "ci_context" => {
    "provider" => "github_actions", "repository" => "ScottTpirate/stead",
    "workflow_ref" => "ScottTpirate/stead/.github/workflows/phase1-candidate.yml@refs/heads/main",
    "event_name" => "workflow_dispatch", "run_id" => "1", "run_attempt" => 1, "ref_protected" => true
  },
  "dataset" => { "path" => Stead::TrustedPerformanceManifest::MANIFEST_PATH, "sha256" => manifest.digest },
  "runtime_components" => manifest_document.dig("server", "component_versions").map do |name, version|
    artifact_reference = { "path" => Stead::TrustedPerformanceManifest::FRONTEND_BASELINE_PATH, "sha256" => "0" * 64 }
    probe_argument = Stead::PerformanceCandidateSuite::VERSION_PROBES.fetch(name).first
    {
      "name" => name,
      "version" => version,
      "artifact" => artifact_reference,
      "version_probe" => {
        "argv" => [artifact_reference["path"], probe_argument],
        "stdout" => copy.call(artifact_reference),
        "invocation_sha256" => "0" * 64
      }
    }
  end,
  "evidence" => [], "benchmark_artifacts" => [], "regression_reviews" => []
}

artifacts_parent = ROOT.join("artifacts/performance")
FileUtils.mkdir_p(artifacts_parent)
Dir.mktmpdir("performance-adversarial-", artifacts_parent.to_s) do |directory|
  relative_directory = Pathname(directory).relative_path_from(ROOT).to_s
  suite_path = Pathname(directory).join("synthetic-noncandidate.json")
  suite_path.write("#{JSON.pretty_generate(synthetic_suite)}\n")
  suite_result = verifier.verify_suite(suite_path)
  assert.call(
    "T-P1-012-PERF-CANDIDATE-COVERAGE",
    suite_result["candidate_eligible"] == false &&
      suite_result["errors"].any? { |error| error.include?("does not resolve to a Git commit") } &&
      suite_result["errors"].include?("candidate CI run_id is not bound to the trusted release workflow") &&
      suite_result["errors"].any? { |error| error.include?("candidate requires controlled tracked infrastructure") } &&
      suite_result["errors"].any? { |error| error.include?("digest mismatch") } &&
      suite_result["errors"].any? { |error| error.include?("could not execute digest-bound artifact") } &&
      suite_result["errors"].any? { |error| error.include?("cover every trusted Phase 1 scenario") },
    "synthetic revisions, caller-asserted CI, arbitrary component bytes/stdout, and incomplete coverage must remain noncandidate"
  )

  actual_evidence_digest = Stead::PerformanceCanonicalJSON.file_digest(FIXTURE_PATH)
  artifact = {
    "artifact_type" => "performance_benchmark_artifact", "schema_version" => "1.0",
    "artifact_id" => "hot-query-count-adversarial", "kind" => "query_count",
    "source_revision" => head, "dataset_sha256" => manifest.digest,
    "scenario_id" => fixture["scenario_id"], "evidence_sha256" => "f" * 64,
    "request_traces_sha256" => "e" * 64,
    "producer" => { "tool" => "go", "version" => fixture.dig("source", "tool_versions", "go"), "command" => "go test ./..." },
    "status" => "PASS",
    "observations" => [
      { "metric" => "sql_queries", "value" => fixture.dig("counts", "sql_queries"), "unit" => "calls" },
      { "metric" => "postgres_writes", "value" => fixture.dig("counts", "postgres_writes"), "unit" => "calls" }
    ],
    "measurement_files" => [{ "path" => FIXTURE_PATH.relative_path_from(ROOT).to_s, "sha256" => actual_evidence_digest }],
    "recorded_at" => "2026-08-30T18:00:00Z", "runner_attestation_sha256" => "d" * 64,
    "causality" => nil, "runner_execution" => nil
  }
  artifact["observations_sha256"] = Stead::PerformanceCanonicalJSON.digest(artifact["observations"])
  artifact_path = Pathname(directory).join("query-count.json")
  artifact_path.write("#{JSON.pretty_generate(artifact)}\n")
  artifact_suite = copy.call(synthetic_suite)
  artifact_suite["source"]["revision"] = head
  artifact_suite["benchmark_artifacts"] = [{
    "path" => "#{relative_directory}/#{artifact_path.basename}",
    "sha256" => Stead::PerformanceCanonicalJSON.file_digest(artifact_path)
  }]
  artifact_validator = Stead::PerformanceCandidateSuite.new(artifact_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
  artifact_validator.send(
    :validate_benchmark_artifacts,
    { fixture["scenario_id"] => fixture },
    { fixture["scenario_id"] => actual_evidence_digest }
  )
  artifact_errors = artifact_validator.instance_variable_get(:@errors)
  assert.call(
    "T-P1-012-PERF-CANDIDATE-COVERAGE",
    artifact_errors.include?("benchmark artifact evidence digest does not match its scenario evidence") &&
      artifact_errors.include?("benchmark artifact request traces digest does not match its scenario evidence"),
    "every kind-specific artifact must bind one exact scenario evidence file and request trace"
  )

  generic_validator = Stead::PerformanceCandidateSuite.new(artifact_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
  generic_artifact = copy.call(artifact)
  generic_artifact["observations"] = [{ "metric" => "query_count.result", "value" => 1, "unit" => "count" }]
  generic_validator.send(:validate_kind_specific_observations, generic_artifact, fixture)
  assert.call(
    "T-P1-012-PERF-CANDIDATE-COVERAGE",
    generic_validator.instance_variable_get(:@errors).include?("query_count artifact must contain the exact kind-specific observation set"),
    "generic kind.result observations cannot stand in for scenario-owned instrumentation"
  )

  bundle_directory = Pathname(directory).join("bundle")
  FileUtils.mkdir_p(bundle_directory)
  capabilities = Stead::PerformanceEvidence::FRONTEND_CAPABILITIES
  bundle_spec = {
    "entry.js" => { "imports" => [], "dynamic_imports" => capabilities.map { |capability| "#{capability}.js" } },
    "docs_editor.js" => { "imports" => [], "dynamic_imports" => [] },
    "code.js" => { "imports" => ["shared.js"], "dynamic_imports" => [] },
    "delivery.js" => { "imports" => ["shared.js"], "dynamic_imports" => [] },
    "administration.js" => { "imports" => [], "dynamic_imports" => [] },
    "migration.js" => { "imports" => [], "dynamic_imports" => [] },
    "analytics.js" => { "imports" => [], "dynamic_imports" => [] },
    "shared.js" => { "imports" => [], "dynamic_imports" => [] }
  }
  relative_for = lambda { |name| "#{relative_directory}/bundle/#{name}" }
  bundle_files = bundle_spec.map do |name, edges|
    path = bundle_directory.join(name)
    path.write("export const #{name.delete_suffix('.js')} = #{name.bytes.sum};\n")
    bytes = path.binread
    {
      "path" => relative_for.call(name),
      "sha256" => Digest::SHA256.hexdigest(bytes),
      "uncompressed_bytes" => bytes.bytesize,
      "gzip_bytes" => Zlib.gzip(bytes, level: Zlib::BEST_COMPRESSION).bytesize,
      "imports" => edges["imports"].map { |child| relative_for.call(child) },
      "dynamic_imports" => edges["dynamic_imports"].map { |child| relative_for.call(child) }
    }
  end
  graph = {
    "eager_entry_path" => relative_for.call("entry.js"),
    "capability_entries" => capabilities.map { |capability| { "capability" => capability, "path" => relative_for.call("#{capability}.js") } },
    "files" => bundle_files
  }
  graph_files = bundle_files.to_h { |file| [file["path"], file] }
  closure = lambda do |start, dynamic|
    pending = [start]
    seen = []
    until pending.empty?
      path = pending.shift
      next if seen.include?(path)

      seen << path
      pending.concat(graph_files.fetch(path)["imports"])
      pending.concat(graph_files.fetch(path)["dynamic_imports"]) if dynamic
    end
    seen
  end
  eager_paths = closure.call(graph["eager_entry_path"], false)
  lazy_summaries = graph["capability_entries"].map do |entry|
    file_paths = (closure.call(entry["path"], true) - eager_paths).sort
    {
      "name" => entry["capability"], "capability" => entry["capability"], "entry_path" => entry["path"],
      "file_paths" => file_paths,
      "uncompressed_bytes" => file_paths.sum { |path| graph_files.fetch(path)["uncompressed_bytes"] },
      "gzip_bytes" => file_paths.sum { |path| graph_files.fetch(path)["gzip_bytes"] }
    }
  end
  unique_lazy_paths = lazy_summaries.flat_map { |summary| summary["file_paths"] }.uniq
  frontend_sizes = copy.call(fixture["sizes"])
  frontend_sizes["frontend_bundle_graph"] = graph
  frontend_sizes["lazy_javascript_chunks"] = lazy_summaries
  frontend_sizes["eager_javascript_gzip_bytes"] = eager_paths.sum { |path| graph_files.fetch(path)["gzip_bytes"] }
  frontend_sizes["lazy_javascript_gzip_bytes"] = unique_lazy_paths.sum { |path| graph_files.fetch(path)["gzip_bytes"] }
  frontend_sizes["frontend_baseline"]["current_gzip_bytes"] = frontend_sizes["eager_javascript_gzip_bytes"]
  frontend_sizes["frontend_baseline"]["delta_gzip_bytes"] =
    frontend_sizes["eager_javascript_gzip_bytes"] - frontend_sizes["frontend_baseline"]["baseline_gzip_bytes"]
  frontend_sizes["frontend_baseline"]["lazy_chunk_delta_gzip_bytes"] = frontend_sizes["lazy_javascript_gzip_bytes"]
  size_errors_for = lambda do |sizes|
    validator = Stead::PerformanceEvidence.new({ "sizes" => sizes }, manifest: manifest)
    validator.instance_variable_set(:@errors, [])
    validator.send(:validate_sizes, manifest.scenario("cold-initial-application"))
    validator.instance_variable_get(:@errors)
  end
  valid_bundle_errors = size_errors_for.call(frontend_sizes)
  fabricated_lazy_delta = copy.call(frontend_sizes)
  fabricated_lazy_delta["frontend_baseline"]["lazy_chunk_delta_gzip_bytes"] += 1
  substituted_digest = copy.call(frontend_sizes)
  substituted_digest["frontend_bundle_graph"]["files"][1]["sha256"] = "0" * 64
  omitted_transitive = copy.call(frontend_sizes)
  omitted_transitive["lazy_javascript_chunks"].find { |entry| entry["capability"] == "code" }["file_paths"].pop
  duplicate_capability = copy.call(frontend_sizes)
  duplicate_capability["frontend_bundle_graph"]["capability_entries"].last["capability"] = "code"

  bundle_artifact = {
    "kind" => "frontend_bundle",
    "measurement_files" => bundle_files.map { |file| file.slice("path", "sha256") },
    "observations" => [
      { "metric" => "eager_javascript_gzip_bytes", "value" => frontend_sizes["eager_javascript_gzip_bytes"], "unit" => "bytes" },
      { "metric" => "lazy_javascript_gzip_bytes", "value" => frontend_sizes["lazy_javascript_gzip_bytes"], "unit" => "bytes" },
      { "metric" => "lazy_javascript_chunk_count", "value" => capabilities.length, "unit" => "count" }
    ]
  }
  bundle_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
  bundle_suite.send(:validate_measurement_files, bundle_artifact, { "sizes" => frontend_sizes })
  incomplete_artifact = copy.call(bundle_artifact)
  incomplete_artifact["measurement_files"] = incomplete_artifact["measurement_files"].take(1)
  incomplete_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
  incomplete_suite.send(:validate_measurement_files, incomplete_artifact, { "sizes" => frontend_sizes })
  assert.call(
    "T-P1-012-PERF-BUNDLE-DELTA",
    valid_bundle_errors.empty? && bundle_suite.instance_variable_get(:@errors).empty? &&
      size_errors_for.call(fabricated_lazy_delta).include?("frontend lazy delta does not match verifier-computed lazy bytes") &&
      size_errors_for.call(substituted_digest).any? { |error| error.include?("sha256 does not match artifact bytes") } &&
      size_errors_for.call(omitted_transitive).any? { |error| error.include?("omits, substitutes, or duplicates transitive graph files") } &&
      size_errors_for.call(duplicate_capability).include?("frontend bundle graph must declare each lazy capability exactly once") &&
      incomplete_suite.instance_variable_get(:@errors).include?("frontend_bundle measurement files must exactly bind every eager, lazy, transitive, and shared graph file"),
    "eager and six lazy capability totals must be recomputed from unique digest-bound files and the complete transitive/shared graph"
  )

  encoded_canary = Stead::PerformanceRetainedEvidenceScan.encoded_forms("synthetic-canary")
  hexadecimal_canary = "synthetic-canary".unpack1("H*")
  percent_canary = "synthetic-canary".bytes.map { |byte| format("%%%02X", byte) }.join
  split_base64_canary = encoded_canary[1].scan(/.{1,4}/).join(" \n")
  retained_cases = {
    "runner-stderr.log" => "prefix synthetic-canary suffix",
    "environment.json" => JSON.generate({ "safe" => encoded_canary[1] }),
    "runner-output.json" => JSON.generate({ "safe" => hexadecimal_canary }),
    "split-encoded.log" => "prefix #{split_base64_canary} suffix",
    "payload.json" => JSON.generate({ "Secret_Token" => "redacted" }),
    "request-traces.json" => JSON.generate({ "safe" => percent_canary }),
    "measurement.txt" => "Authorization: Bearer prohibited",
    "evidence.json" => JSON.generate({ "safe" => "stead_perf_canary_alpha_7d9e" }),
    "runner.bin" => "\x00synthetic-canary\xff".b
  }
  redaction_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
  retained_cases.each do |name, bytes|
    path = Pathname(directory).join(name)
    path.binwrite(bytes)
    reference = { "path" => "#{relative_directory}/#{name}", "sha256" => Digest::SHA256.hexdigest(bytes) }
    redaction_suite.send(:resolve_reference, reference)
  end
  redaction_errors = redaction_suite.instance_variable_get(:@errors)

  duplicate_json_path = Pathname(directory).join("duplicate-evidence.json")
  duplicate_json_path.write('{"source":{"revision":"a","\\u0072evision":"b"}}')
  duplicate_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
  duplicate_suite.send(
    :resolve_reference,
    { "path" => "#{relative_directory}/duplicate-evidence.json", "sha256" => Stead::PerformanceCanonicalJSON.file_digest(duplicate_json_path) }
  )

  clean_path = Pathname(directory).join("clean-output.txt")
  clean_path.write("aggregate-count=1\n")
  clean_reference = { "path" => "#{relative_directory}/clean-output.txt", "sha256" => Stead::PerformanceCanonicalJSON.file_digest(clean_path) }
  exact_size_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
  exact_size_path = exact_size_suite.send(:resolve_reference, clean_reference, max_bytes: clean_path.size)
  one_over_size_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
  one_over_size_path = one_over_size_suite.send(:resolve_reference, clean_reference, max_bytes: clean_path.size - 1)

  outside_telemetry = copy.call(fixture)
  outside_telemetry["provenance"]["command"] = "runner --marker synthetic-canary"
  outside_telemetry_errors = semantic_errors.call(outside_telemetry)
  assert.call(
    "T-P1-012-PERF-REDACTION",
    retained_cases.keys.all? { |name| redaction_errors.any? { |error| error.include?(name) } },
    "runner stderr/environment/output/payload/trace/measurement/evidence/binary files must all receive protected-content scanning"
  )
  assert.call(
    "T-P1-012-PERF-REDACTION",
    duplicate_suite.instance_variable_get(:@errors).any? { |error| error.include?("strict JSON preflight failed: duplicate object key") },
    "referenced JSON artifacts must reject duplicate decoded keys before semantic parsing"
  )
  assert.call(
    "T-P1-012-PERF-REDACTION",
    exact_size_path == clean_path && exact_size_suite.instance_variable_get(:@errors).empty? && one_over_size_path.nil? &&
      one_over_size_suite.instance_variable_get(:@errors).any? { |error| error.include?("byte ceiling") },
    "referenced artifacts must accept the exact byte ceiling and reject one byte over before reading"
  )
  assert.call(
    "T-P1-012-PERF-REDACTION",
    outside_telemetry_errors.any? { |error| error.include?("performance evidence retains protected content") },
    "protected content outside telemetry.records must fail evidence validation"
  )
end

required_causality_scenarios = Stead::PerformanceNormativeControls::SCENARIOS.filter_map do |scenario_id, controls|
  scenario_id if controls["required_artifact_kinds"].include?("response_before_relay")
end
assert.call(
  "T-P1-012-PERF-CAUSALITY",
  required_causality_scenarios.sort == %w[
    cold-initial-application hot-composed-metadata metadata-mutation project-route-useful-content
    projection-to-visible remote-search-first-results same-region-metadata
  ].sort,
  "every server mutation/projection scenario requiring asynchronous relay must carry its own response-before-relay proof"
)

selected_trace = fixture.fetch("request_traces").first
trace_events = selected_trace.fetch("events").select do |event|
  (event["type"] == "postgres_write" && event["write_role"] == "transactional_outbox") ||
    %w[authoritative_commit response_sent relay_started].include?(event["type"])
end.map { |event| event.slice("type", "monotonic_ns", "transaction_id_hash", "outbox_event_id_hash") }
causality_artifact = {
  "kind" => "response_before_relay",
  "observations" => [{ "metric" => "response_to_relay_gap_ns", "value" => 100, "unit" => "nanoseconds" }],
  "causality" => { "trace_id_hash" => selected_trace["trace_id_hash"], "sample_index" => 0, "events" => trace_events }
}
causality_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
causality_suite.send(:validate_causality, causality_artifact, fixture)
valid_causality_errors = causality_suite.instance_variable_get(:@errors)
reversed_causality = copy.call(causality_artifact)
reversed_causality["causality"]["events"][1]["monotonic_ns"] = 400
reversed_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
reversed_suite.send(:validate_causality, reversed_causality, fixture)
unrelated_relay = copy.call(causality_artifact)
unrelated_relay["causality"]["events"].last["outbox_event_id_hash"] = "f" * 64
unrelated_relay_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
unrelated_relay_suite.send(:validate_causality, unrelated_relay, fixture)
assert.call(
  "T-P1-012-PERF-CAUSALITY",
  valid_causality_errors.empty? &&
    reversed_suite.instance_variable_get(:@errors).any? { |error| error.include?("outbox <= commit <= response < relay") } &&
    unrelated_relay_suite.instance_variable_get(:@errors).include?("response-before-relay causality must bind one transaction and outbox event"),
  "response-before-relay evidence must bind the outbox transaction and prove outbox <= commit <= response < relay"
)

runner_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
runner_suite.send(:validate_runner_execution, { "kind" => "runner_attestation", "runner_execution" => nil }, fixture)
assert.call(
  "T-P1-012-PERF-CANDIDATE-COVERAGE",
  runner_suite.instance_variable_get(:@errors).include?("runner_attestation requires byte-backed runner execution evidence"),
  "a PASS label without tracked runner binary, invocation, stdout, stderr, and environment bytes cannot establish execution"
)

evidence_reference = { "path" => FIXTURE_PATH.relative_path_from(ROOT).to_s, "sha256" => Stead::PerformanceCanonicalJSON.file_digest(FIXTURE_PATH) }
stderr_reference = { "path" => BASELINE_PATH.relative_path_from(ROOT).to_s, "sha256" => Stead::PerformanceCanonicalJSON.file_digest(BASELINE_PATH) }
runner_environment_sha = manifest.environment_digest(fixture["scenario_id"])
runner_argv = [
  evidence_reference["path"], "--scenario", fixture["scenario_id"], "--manifest",
  Stead::TrustedPerformanceManifest::MANIFEST_PATH, "--emit-evidence"
]
runner_invocation = {
  "binary_sha256" => evidence_reference["sha256"],
  "argv" => runner_argv,
  "source_revision" => head,
  "dataset_sha256" => manifest.digest,
  "scenario_id" => fixture["scenario_id"],
  "environment_sha256" => runner_environment_sha
}
untracked_runner_artifact = {
  "kind" => "runner_attestation", "source_revision" => head, "dataset_sha256" => manifest.digest,
  "scenario_id" => fixture["scenario_id"], "evidence_sha256" => evidence_reference["sha256"],
  "producer" => { "command" => fixture.dig("provenance", "command") },
  "measurement_files" => [evidence_reference, evidence_reference, stderr_reference],
  "runner_execution" => {
    "binary" => evidence_reference, "stdout" => evidence_reference, "stderr" => stderr_reference,
    "argv" => runner_argv, "command" => runner_argv.join(" "),
    "invocation_sha256" => Stead::PerformanceCanonicalJSON.digest(runner_invocation), "exit_code" => 0,
    "started_at" => fixture.dig("provenance", "started_at"), "ended_at" => fixture.dig("provenance", "ended_at"),
    "environment_sha256" => runner_environment_sha, "environment_probe" => nil, "outputs" => []
  }
}
untracked_runner_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
untracked_runner_suite.send(:validate_runner_execution, untracked_runner_artifact, fixture)
untracked_runner_errors = untracked_runner_suite.instance_variable_get(:@errors)
assert.call(
  "T-P1-012-PERF-CANDIDATE-COVERAGE",
  untracked_runner_errors.include?("runner execution requires kind-labelled raw output files") &&
    untracked_runner_errors.include?("runner execution binary must be the verifier-owned Phase 1 candidate runner"),
  "actual evidence bytes still cannot pass without controlled runner code and its kind-labelled raw execution outputs"
)

attested_query_output = { "kind" => "query_count", "path" => evidence_reference["path"], "sha256" => evidence_reference["sha256"] }
runner_binding_artifacts = [
  {
    "scenario_id" => fixture["scenario_id"], "kind" => "runner_attestation",
    "_verified_file_sha256" => "a" * 64, "runner_attestation_sha256" => nil,
    "runner_execution" => { "outputs" => [attested_query_output] }
  },
  {
    "scenario_id" => fixture["scenario_id"], "kind" => "query_count",
    "runner_attestation_sha256" => "a" * 64,
    "measurement_files" => [stderr_reference]
  }
]
runner_binding_suite = Stead::PerformanceCandidateSuite.new(synthetic_suite, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
runner_binding_suite.send(:validate_runner_attestation_bindings, runner_binding_artifacts)
assert.call(
  "T-P1-012-PERF-CANDIDATE-COVERAGE",
  runner_binding_suite.instance_variable_get(:@errors).include?("query_count artifact measurement files are not the exact runner-attested raw outputs"),
  "a kind-specific wrapper may not substitute files that the scenario runner did not attest"
)

authority_suite_document = copy.call(synthetic_suite)
authority_suite_document["source"]["revision"] = head
authority_suite_document["source"]["controls_revision"] = head
authority_suite = Stead::PerformanceCandidateSuite.new(authority_suite_document, root: ROOT, schema_gate: verifier.schema_gate, manifest: manifest)
authority_suite.send(:validate_implementation_owner_authority)
self_asserted_authority_review = {
  "authority_revision" => head, "authority_id" => "producer-claimed-independent",
  "reviewer" => { "identity" => "qa@example.test", "role" => "independent_qa" },
  "signature_base64" => "AAAA", "signature_algorithm" => "Ed25519"
}
authority_suite.send(:validate_reviewer_authority, self_asserted_authority_review)
assert.call(
  "T-P1-012-PERF-REGRESSION-GATE",
  !self_asserted_authority_review.key?("_authority_verified") &&
    authority_suite.instance_variable_get(:@errors).any? do |error|
      error.include?("reviewer authority registry is absent") || error.include?("not an active immutable repository-approved owner")
    end &&
    authority_suite.instance_variable_get(:@errors).any? { |error| error.include?("independently merged into origin/main") },
  "implementation owner and reviewer identity/role must come from immutable independently merged authority records and a valid signature"
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
