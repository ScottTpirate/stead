# frozen_string_literal: true

# Closed, verifier-owned Phase 1 controls transcribed from PERF-002 through
# PERF-006 and the request-boundary rules in the merged Master Build Directive.
# Candidate evidence may report observations; it may not redefine these values.
module Stead
  module PerformanceNormativeControls
    DIRECTIVE_PATH = "docs/architecture/MASTER_BUILD_DIRECTIVE.md"
    CANDIDATE_WORKFLOW_PATH = ".github/workflows/phase1-candidate.yml"
    CANDIDATE_RUNNER_PATH = "scripts/performance/phase1_candidate_runner"
    REQUIREMENT_IDS = %w[PERF-002 PERF-003 PERF-004 PERF-005 PERF-006 OPS-005].freeze
    CONTROLLED_PATHS = [
      DIRECTIVE_PATH,
      CANDIDATE_WORKFLOW_PATH,
      "Makefile",
      "tests/performance/harness",
      "tests/performance/datasets/standard-request-boundary-v1.json",
      "tests/performance/datasets/generate_standard_corpus.rb",
      "scripts/performance",
      "packages/test-fixtures/harness/performance/foundation-shell-baseline.json"
    ].freeze

    GLOBAL_EXACT_COUNTS = {
      "nats_waits" => 0,
      "browser_forbidden_origin_requests" => 0,
      "authorization_cache_hits" => 0
    }.freeze

    TELEMETRY_CANARIES = ["synthetic-canary", "stead_perf_canary_alpha_7d9e"].freeze
    GENERATOR_PATH = "tests/performance/datasets/generate_standard_corpus.rb"
    GENERATOR_SEED = 2_026_083_001
    GENERATOR_COMMAND = "ruby tests/performance/datasets/generate_standard_corpus.rb"
    TELEMETRY_RULESET_ID = "stead-performance-safe-scan-v1"
    FORBIDDEN_TELEMETRY_KEYS = %w[
      authorizationheader cookie credential credentials documentbody issuebody password policyinput policyinputs
      privatekey protectedcontent querytext rawresourceid rawresourceids secret secrets token tokens workbody
    ].freeze
    FORBIDDEN_TELEMETRY_VALUE_PATTERNS = [
      "authorization:bearer", "beginecprivatekey", "beginopensshprivatekey",
      "beginprivatekey", "password=", "set-cookie:"
    ].freeze

    CORPUS_DISTRIBUTION_COUNT_BOUNDS = {
      "project_classification" => {
        "baseline:internal" => 60..75,
        "baseline:confidential" => 60..75,
        "baseline:restricted" => 60..75
      },
      "work_status" => {
        "backlog" => 1_600..1_750, "ready" => 1_600..1_750, "in_progress" => 1_600..1_750,
        "blocked" => 1_600..1_750, "review" => 1_600..1_750, "done" => 1_600..1_750
      },
      "document_scope" => { "organization" => 1_600..1_750, "team" => 1_600..1_750, "project" => 1_600..1_750 },
      "assignment_subject" => { "agent" => 950..1_050, "person" => 8_950..9_050 }
    }.freeze

    LOAD_SHAPES = {
      "single-user-hot" => { "concurrency" => 1, "warmup_requests" => 20, "measured_samples" => 100, "state" => "warm", "arrival_model" => "closed_loop", "pacing_ms" => 100, "duration_seconds" => 10, "result_counts" => [1, 25, 100, 250] },
      "single-user-same-region" => { "concurrency" => 1, "warmup_requests" => 20, "measured_samples" => 100, "state" => "warm", "arrival_model" => "closed_loop", "pacing_ms" => 100, "duration_seconds" => 10, "result_counts" => [1, 25, 100, 250] },
      "single-user-mutation" => { "concurrency" => 1, "warmup_requests" => 10, "measured_samples" => 100, "state" => "warm", "arrival_model" => "closed_loop", "pacing_ms" => 200, "duration_seconds" => 20, "result_counts" => [] },
      "single-user-search" => { "concurrency" => 1, "warmup_requests" => 10, "measured_samples" => 100, "state" => "warm", "arrival_model" => "closed_loop", "pacing_ms" => 300, "duration_seconds" => 30, "result_counts" => [1, 25, 100, 250] },
      "single-user-route" => { "concurrency" => 1, "warmup_requests" => 10, "measured_samples" => 100, "state" => "warm", "arrival_model" => "closed_loop", "pacing_ms" => 500, "duration_seconds" => 50, "result_counts" => [1, 25, 100, 250] },
      "single-user-cold" => { "concurrency" => 1, "warmup_requests" => 0, "measured_samples" => 20, "state" => "cold", "arrival_model" => "isolated_iteration", "pacing_ms" => 2_000, "duration_seconds" => 40, "result_counts" => [] },
      "single-user-projection" => { "concurrency" => 1, "warmup_requests" => 10, "measured_samples" => 100, "state" => "warm", "arrival_model" => "closed_loop", "pacing_ms" => 1_000, "duration_seconds" => 100, "result_counts" => [] },
      "single-user-input" => { "concurrency" => 1, "warmup_requests" => 10, "measured_samples" => 100, "state" => "warm", "arrival_model" => "isolated_iteration", "pacing_ms" => 100, "duration_seconds" => 10, "result_counts" => [] },
      "single-user-command" => { "concurrency" => 1, "warmup_requests" => 10, "measured_samples" => 100, "state" => "warm", "arrival_model" => "isolated_iteration", "pacing_ms" => 100, "duration_seconds" => 10, "result_counts" => [] }
    }.freeze

    SCENARIOS = {
      "hot-composed-metadata" => {
        "type" => "hot_composed_metadata_api",
        "load_shape_id" => "single-user-hot",
        "classifications" => { "ordinary_read" => true, "primary_surface_after_shell" => true, "set_oriented" => true, "frontend_touched" => false },
        "count_budgets" => { "sql_queries" => 4, "postgres_writes" => 1, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 0, "logical_audit_operations" => 1 },
        "exact_counts" => { "browser_requests" => 1, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 0, "logical_audit_operations" => 1 },
        "minimum_counts" => { "sql_queries" => 1, "postgres_writes" => 1 },
        "targets" => [["timings_ms.latency.p50", 25.0, "engineering"], ["timings_ms.latency.p95", 100.0, "engineering"], ["timings_ms.latency.p95", 300.0, "release_ceiling"]],
        "critical_metrics" => ["timings_ms.latency.p95"],
        "required_artifact_kinds" => %w[authorization_count go_microbenchmark provider_count query_count response_before_relay runner_attestation]
      },
      "same-region-metadata" => {
        "type" => "same_region_metadata_api",
        "load_shape_id" => "single-user-same-region",
        "classifications" => { "ordinary_read" => true, "primary_surface_after_shell" => true, "set_oriented" => true, "frontend_touched" => false },
        "count_budgets" => { "sql_queries" => 4, "postgres_writes" => 1, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 0, "logical_audit_operations" => 1 },
        "exact_counts" => { "browser_requests" => 1, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 0, "logical_audit_operations" => 1 },
        "minimum_counts" => { "sql_queries" => 1, "postgres_writes" => 1 },
        "targets" => [["timings_ms.latency.p95", 150.0, "engineering"], ["timings_ms.latency.p95", 300.0, "release_ceiling"]],
        "critical_metrics" => ["timings_ms.latency.p95"],
        "required_artifact_kinds" => %w[authorization_count golden_slice_e2e provider_count query_count response_before_relay runner_attestation]
      },
      "metadata-mutation" => {
        "type" => "metadata_mutation",
        "load_shape_id" => "single-user-mutation",
        "classifications" => { "ordinary_read" => false, "primary_surface_after_shell" => true, "set_oriented" => false, "frontend_touched" => false },
        "count_budgets" => { "sql_queries" => 8, "postgres_writes" => 4, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 1, "logical_audit_operations" => 1 },
        "exact_counts" => { "browser_requests" => 1, "openfga_calls" => 1, "policy_calls" => 1, "logical_audit_operations" => 1 },
        "minimum_counts" => { "sql_queries" => 1, "postgres_writes" => 2 },
        "targets" => [["timings_ms.latency.p95", 200.0, "engineering"], ["timings_ms.latency.p95", 500.0, "release_ceiling"]],
        "critical_metrics" => ["timings_ms.latency.p95"],
        "required_artifact_kinds" => %w[authorization_count provider_count query_count response_before_relay runner_attestation]
      },
      "remote-search-first-results" => {
        "type" => "remote_search_first_results",
        "load_shape_id" => "single-user-search",
        "classifications" => { "ordinary_read" => true, "primary_surface_after_shell" => true, "set_oriented" => true, "frontend_touched" => true },
        "count_budgets" => { "sql_queries" => 5, "postgres_writes" => 1, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 0, "logical_audit_operations" => 1 },
        "exact_counts" => { "browser_requests" => 1, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 0, "logical_audit_operations" => 1 },
        "minimum_counts" => { "sql_queries" => 1, "postgres_writes" => 1 },
        "targets" => [["timings_ms.latency.p95", 300.0, "engineering"], ["timings_ms.latency.p95", 1_500.0, "release_ceiling"]],
        "critical_metrics" => ["timings_ms.latency.p95"],
        "required_artifact_kinds" => %w[authorization_count browser_performance golden_slice_e2e provider_count query_count response_before_relay runner_attestation]
      },
      "project-route-useful-content" => {
        "type" => "project_route_useful_content",
        "load_shape_id" => "single-user-route",
        "classifications" => { "ordinary_read" => true, "primary_surface_after_shell" => true, "set_oriented" => true, "frontend_touched" => true },
        "count_budgets" => { "sql_queries" => 8, "postgres_writes" => 1, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 0, "logical_audit_operations" => 1 },
        "exact_counts" => { "browser_requests" => 1, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 0, "logical_audit_operations" => 1 },
        "minimum_counts" => { "sql_queries" => 1, "postgres_writes" => 1 },
        "targets" => [["timings_ms.latency.p95", 500.0, "engineering"]],
        "critical_metrics" => ["timings_ms.latency.p95"],
        "required_artifact_kinds" => %w[authorization_count browser_performance golden_slice_e2e provider_count query_count response_before_relay runner_attestation]
      },
      "cold-initial-application" => {
        "type" => "cold_initial_application",
        "load_shape_id" => "single-user-cold",
        "classifications" => { "ordinary_read" => true, "primary_surface_after_shell" => false, "set_oriented" => false, "frontend_touched" => true },
        "count_budgets" => { "sql_queries" => 8, "postgres_writes" => 1, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 0, "logical_audit_operations" => 1 },
        "exact_counts" => { "browser_requests" => 1, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 0, "logical_audit_operations" => 1 },
        "minimum_counts" => { "sql_queries" => 1, "postgres_writes" => 1 },
        "targets" => [["timings_ms.latency.p95", 1_000.0, "engineering"], ["sizes.eager_javascript_gzip_bytes", 256_000, "release_ceiling"]],
        "critical_metrics" => ["timings_ms.latency.p95", "sizes.eager_javascript_gzip_bytes"],
        "required_artifact_kinds" => %w[authorization_count browser_performance frontend_bundle provider_count query_count response_before_relay runner_attestation]
      },
      "projection-to-visible" => {
        "type" => "projection_to_visible",
        "load_shape_id" => "single-user-projection",
        "classifications" => { "ordinary_read" => false, "primary_surface_after_shell" => false, "set_oriented" => false, "frontend_touched" => false },
        "count_budgets" => { "sql_queries" => 8, "postgres_writes" => 4, "openfga_calls" => 1, "policy_calls" => 1, "provider_calls" => 1, "logical_audit_operations" => 1 },
        "exact_counts" => { "browser_requests" => 0, "openfga_calls" => 1, "policy_calls" => 1, "logical_audit_operations" => 1 },
        "minimum_counts" => { "sql_queries" => 1, "postgres_writes" => 2 },
        "targets" => [["timings_ms.projection_lag.p95", 1_000.0, "engineering"], ["timings_ms.projection_lag.p95", 5_000.0, "release_ceiling"]],
        "critical_metrics" => ["timings_ms.projection_lag.p95"],
        "required_artifact_kinds" => %w[authorization_count projection_lag provider_count query_count response_before_relay runner_attestation]
      },
      "input-acknowledgement" => {
        "type" => "input_acknowledgement",
        "load_shape_id" => "single-user-input",
        "classifications" => { "ordinary_read" => false, "primary_surface_after_shell" => false, "set_oriented" => false, "frontend_touched" => true },
        "count_budgets" => { "sql_queries" => 0, "postgres_writes" => 0, "openfga_calls" => 0, "policy_calls" => 0, "provider_calls" => 0, "logical_audit_operations" => 0 },
        "exact_counts" => { "browser_requests" => 0, "sql_queries" => 0, "postgres_writes" => 0, "openfga_calls" => 0, "policy_calls" => 0, "provider_calls" => 0, "logical_audit_operations" => 0 },
        "minimum_counts" => {},
        "targets" => [["timings_ms.latency.p95", 50.0, "engineering"]],
        "critical_metrics" => ["timings_ms.latency.p95"],
        "required_artifact_kinds" => %w[browser_performance peek runner_attestation]
      },
      "command-palette-local-results" => {
        "type" => "command_palette_local_results",
        "load_shape_id" => "single-user-command",
        "classifications" => { "ordinary_read" => false, "primary_surface_after_shell" => false, "set_oriented" => false, "frontend_touched" => true },
        "count_budgets" => { "sql_queries" => 0, "postgres_writes" => 0, "openfga_calls" => 0, "policy_calls" => 0, "provider_calls" => 0, "logical_audit_operations" => 0 },
        "exact_counts" => { "browser_requests" => 0, "sql_queries" => 0, "postgres_writes" => 0, "openfga_calls" => 0, "policy_calls" => 0, "provider_calls" => 0, "logical_audit_operations" => 0 },
        "minimum_counts" => {},
        "targets" => [["timings_ms.latency.p95", 30.0, "engineering"]],
        "critical_metrics" => ["timings_ms.latency.p95"],
        "required_artifact_kinds" => %w[browser_performance runner_attestation]
      }
    }.freeze

    REQUIRED_OBSERVATIONS = {
      "authorization_count" => { "openfga_calls" => "calls", "policy_calls" => "calls", "logical_audit_operations" => "calls" },
      "browser_performance" => { "lcp_ms" => "milliseconds", "inp_ms" => "milliseconds", "cls" => "ratio" },
      "frontend_bundle" => { "eager_javascript_gzip_bytes" => "bytes", "lazy_javascript_chunk_count" => "count" },
      "go_microbenchmark" => { "nanoseconds_per_operation" => "nanoseconds", "allocations_per_operation" => "count", "bytes_per_operation" => "bytes" },
      "golden_slice_e2e" => { "latency_p50_ms" => "milliseconds", "latency_p95_ms" => "milliseconds", "latency_p99_ms" => "milliseconds" },
      "peek" => { "peek_p95_ms" => "milliseconds" },
      "projection_lag" => { "projection_lag_p95_ms" => "milliseconds" },
      "provider_count" => { "provider_calls" => "calls" },
      "query_count" => { "sql_queries" => "calls", "postgres_writes" => "calls" },
      "response_before_relay" => { "response_to_relay_gap_ns" => "nanoseconds" },
      "runner_attestation" => { "exit_code" => "count", "measured_sample_count" => "count" }
    }.freeze

    REQUIRED_SUITE_ARTIFACT_KINDS = REQUIRED_OBSERVATIONS.keys.sort.freeze
  end
end
