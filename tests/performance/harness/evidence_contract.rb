#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "pathname"
require "time"

module Stead
  class PerformanceEvidence
    SCHEMA_VERSION = "1.0"
    EAGER_BUNDLE_BUDGET_BYTES = 256_000
    MAX_UNREVIEWED_REGRESSION_PERCENT = 10.0

    TOP_LEVEL_KEYS = %w[
      schema_version evidence_id evidence_kind candidate_eligible source scenario
      counts timings_ms sizes web_vitals count_budgets scaling_trials
      baseline_comparison telemetry
    ].freeze

    COUNT_FIELDS = %w[
      browser_requests sql_queries postgres_writes openfga_calls policy_calls
      provider_calls nats_waits logical_audit_operations
      browser_forbidden_origin_requests authorization_cache_hits
    ].freeze

    SET_ORIENTED_COUNT_FIELDS = %w[
      sql_queries postgres_writes openfga_calls policy_calls provider_calls
      logical_audit_operations
    ].freeze

    PERCENTILE_FIELDS = %w[p50 p95 p99].freeze
    TIMING_GROUPS = %w[latency sql openfga policy provider projection_lag].freeze
    SCENARIO_STATES = %w[cold warm].freeze
    EVIDENCE_KINDS = %w[measurement test_fixture].freeze
    BENCHMARK_PROFILES = %w[standard high_assurance].freeze
    DISCLOSURE_MODES = %w[request_boundary commit_boundary].freeze
    SOURCE_KEYS = %w[revision dirty recorded_at tool_versions].freeze
    SCENARIO_KEYS = %w[
      id type benchmark_profile disclosure_mode dataset_version device network
      topology corpus load_shape state sample_count ordinary_read
      primary_surface_after_shell set_oriented frontend_touched
    ].freeze
    SIZE_KEYS = %w[
      response_bytes eager_javascript_gzip_bytes lazy_javascript_chunks
      frontend_baseline
    ].freeze
    FRONTEND_BASELINE_KEYS = %w[
      baseline_id baseline_gzip_bytes current_gzip_bytes delta_gzip_bytes
      lazy_chunk_delta_gzip_bytes
    ].freeze
    WEB_VITAL_KEYS = %w[lcp_ms inp_ms cls].freeze
    BASELINE_COMPARISON_KEYS = %w[
      metric baseline current regression_percent critical independent_review_ref
    ].freeze
    TELEMETRY_KEYS = %w[safe_correlation_id protected_content_canary_hits].freeze

    SCENARIO_TARGETS = {
      "hot_composed_metadata_api" => [["timings_ms.latency.p50", 25.0], ["timings_ms.latency.p95", 100.0]],
      "same_region_metadata_api" => [["timings_ms.latency.p95", 150.0]],
      "metadata_mutation" => [["timings_ms.latency.p95", 200.0]],
      "remote_search_first_results" => [["timings_ms.latency.p95", 300.0]],
      "project_route_useful_content" => [["timings_ms.latency.p95", 500.0]],
      "cold_initial_application" => [["timings_ms.latency.p95", 1_000.0]],
      "projection_to_visible" => [["timings_ms.projection_lag.p95", 1_000.0]],
      "input_acknowledgement" => [["timings_ms.latency.p95", 50.0]],
      "command_palette_local_results" => [["timings_ms.latency.p95", 30.0]]
    }.freeze

    RELEASE_CEILINGS = {
      "hot_composed_metadata_api" => ["timings_ms.latency.p95", 300.0],
      "same_region_metadata_api" => ["timings_ms.latency.p95", 300.0],
      "metadata_mutation" => ["timings_ms.latency.p95", 500.0],
      "remote_search_first_results" => ["timings_ms.latency.p95", 1_500.0],
      "projection_to_visible" => ["timings_ms.projection_lag.p95", 5_000.0]
    }.freeze

    FORBIDDEN_EVIDENCE_KEYS = %w[
      password secret secrets token tokens credential credentials private_key
      authorization_header cookie document_body work_body issue_body policy_input
      policy_inputs raw_resource_id raw_resource_ids query_text protected_content
    ].freeze

    attr_reader :document

    def self.load(path)
      new(JSON.parse(Pathname(path).read(encoding: "UTF-8")))
    end

    def initialize(document)
      @document = document
      @errors = []
    end

    def validate
      @errors = []
      validate_top_level
      return @errors.uniq unless document.is_a?(Hash)

      validate_source
      validate_scenario
      validate_counts
      validate_timings
      validate_sizes
      validate_web_vitals
      validate_set_oriented_trials
      validate_absolute_target
      validate_regressions
      validate_telemetry
      validate_sensitive_keys(document)
      @errors.uniq
    end

    private

    def validate_top_level
      return error("evidence document must be an object") unless document.is_a?(Hash)

      missing = TOP_LEVEL_KEYS.reject { |key| document.key?(key) }
      error("missing top-level fields: #{missing.join(', ')}") unless missing.empty?

      unknown = document.keys - TOP_LEVEL_KEYS
      error("unknown top-level fields: #{unknown.join(', ')}") unless unknown.empty?

      error("schema_version must be #{SCHEMA_VERSION}") unless document["schema_version"] == SCHEMA_VERSION
      require_nonempty_string("evidence_id")
      require_enum("evidence_kind", EVIDENCE_KINDS)
      require_boolean("candidate_eligible")

      if document["candidate_eligible"] && document["evidence_kind"] != "measurement"
        error("candidate-eligible evidence_kind must be measurement")
      end
    end

    def validate_source
      source = require_exact_hash("source", SOURCE_KEYS)
      return unless source

      revision = source["revision"]
      error("source.revision must be a full lowercase Git SHA") unless revision.is_a?(String) && revision.match?(/\A[0-9a-f]{40}\z/)
      require_boolean("source.dirty")
      require_nonempty_string("source.recorded_at")
      begin
        Time.iso8601(source["recorded_at"].to_s)
      rescue ArgumentError
        error("source.recorded_at must be RFC3339")
      end

      tools = source["tool_versions"]
      unless tools.is_a?(Hash) && !tools.empty? && tools.all? { |key, value| nonempty_string?(key) && nonempty_string?(value) }
        error("source.tool_versions must be a non-empty string map")
      end

      error("candidate-eligible evidence must come from a clean tree") if document["candidate_eligible"] && source["dirty"]
    end

    def validate_scenario
      scenario = require_exact_hash("scenario", SCENARIO_KEYS)
      return unless scenario

      %w[id dataset_version device network topology corpus load_shape].each do |field|
        require_nonempty_string("scenario.#{field}")
      end
      require_enum("scenario.type", SCENARIO_TARGETS.keys)
      require_enum("scenario.benchmark_profile", BENCHMARK_PROFILES)
      require_enum("scenario.disclosure_mode", DISCLOSURE_MODES)
      require_enum("scenario.state", SCENARIO_STATES)
      require_positive_integer("scenario.sample_count")
      %w[ordinary_read primary_surface_after_shell set_oriented frontend_touched].each do |field|
        require_boolean("scenario.#{field}")
      end

      profile = scenario["benchmark_profile"]
      mode = scenario["disclosure_mode"]
      if profile == "standard" && mode != "request_boundary"
        error("standard benchmark must use request_boundary")
      elsif profile == "high_assurance" && mode != "commit_boundary"
        error("high_assurance benchmark must use commit_boundary")
      end
    end

    def validate_counts
      counts = require_exact_hash("counts", COUNT_FIELDS)
      return unless counts

      COUNT_FIELDS.each { |field| require_nonnegative_integer("counts.#{field}") }
      return unless document["scenario"].is_a?(Hash)

      scenario = document["scenario"]
      if scenario["primary_surface_after_shell"] && counts["browser_requests"].to_i > 1
        error("primary surface after shell may use at most one composed browser request")
      end
      if scenario["primary_surface_after_shell"] && counts["browser_forbidden_origin_requests"] != 0
        error("browser must make zero direct provider or internal-infrastructure requests")
      end

      error("authorization decision cache hits are prohibited") unless counts["authorization_cache_hits"] == 0

      if scenario["ordinary_read"]
        error("ordinary read must make zero provider calls") unless counts["provider_calls"] == 0
        error("ordinary read must wait for zero NATS operations") unless counts["nats_waits"] == 0
        if scenario["primary_surface_after_shell"] && scenario["disclosure_mode"] == "request_boundary" && counts["logical_audit_operations"] != 1
          error("request_boundary composed ordinary read requires exactly one logical audit operation")
        end
      end
    end

    def validate_timings
      timings = require_exact_hash("timings_ms", TIMING_GROUPS)
      return unless timings

      TIMING_GROUPS.each do |group|
        percentiles = require_exact_hash("timings_ms.#{group}", PERCENTILE_FIELDS)
        next unless percentiles

        values = PERCENTILE_FIELDS.map do |field|
          path = "timings_ms.#{group}.#{field}"
          require_nonnegative_number(path)
          value_at(path)
        end
        next unless values.all? { |value| value.is_a?(Numeric) }

        error("timings_ms.#{group} percentiles must be nondecreasing") unless values.each_cons(2).all? { |left, right| left <= right }
      end
    end

    def validate_sizes
      sizes = require_exact_hash("sizes", SIZE_KEYS)
      return unless sizes

      require_nonnegative_integer("sizes.response_bytes")
      require_nonnegative_integer("sizes.eager_javascript_gzip_bytes")
      eager = sizes["eager_javascript_gzip_bytes"]
      if eager.is_a?(Integer) && eager > EAGER_BUNDLE_BUDGET_BYTES
        error("eager JavaScript gzip budget exceeded: #{eager} > #{EAGER_BUNDLE_BUDGET_BYTES}")
      end

      chunks = sizes["lazy_javascript_chunks"]
      unless chunks.is_a?(Array) && chunks.all? { |chunk| valid_lazy_chunk?(chunk) }
        error("sizes.lazy_javascript_chunks must contain strict name/capability/gzip_bytes objects")
      end

      baseline = sizes["frontend_baseline"]
      if baseline.nil?
        error("frontend-touched evidence requires sizes.frontend_baseline") if value_at("scenario.frontend_touched")
        return
      end
      unless baseline.is_a?(Hash)
        error("frontend-touched evidence requires sizes.frontend_baseline")
        return
      end
      require_exact_hash("sizes.frontend_baseline", FRONTEND_BASELINE_KEYS)

      %w[baseline_gzip_bytes current_gzip_bytes delta_gzip_bytes lazy_chunk_delta_gzip_bytes].each do |field|
        require_integer("sizes.frontend_baseline.#{field}")
      end
      require_nonempty_string("sizes.frontend_baseline.baseline_id")
      return unless %w[baseline_gzip_bytes current_gzip_bytes delta_gzip_bytes].all? { |field| baseline[field].is_a?(Integer) }

      error("frontend current gzip bytes must equal sizes.eager_javascript_gzip_bytes") unless baseline["current_gzip_bytes"] == eager
      expected_delta = baseline["current_gzip_bytes"] - baseline["baseline_gzip_bytes"]
      error("frontend eager delta does not match baseline/current values") unless baseline["delta_gzip_bytes"] == expected_delta
    end

    def validate_web_vitals
      return unless require_exact_hash("web_vitals", WEB_VITAL_KEYS)

      require_nonnegative_number("web_vitals.lcp_ms")
      require_nonnegative_number("web_vitals.inp_ms")
      require_nonnegative_number("web_vitals.cls")
    end

    def validate_set_oriented_trials
      budgets = require_exact_hash("count_budgets", SET_ORIENTED_COUNT_FIELDS)
      trials = document["scaling_trials"]
      return unless budgets

      SET_ORIENTED_COUNT_FIELDS.each { |field| require_nonnegative_integer("count_budgets.#{field}") }
      unless trials.is_a?(Array)
        error("scaling_trials must be an array")
        return
      end

      set_oriented = value_at("scenario.set_oriented")
      error("set-oriented evidence requires at least two scaling trials") if set_oriented && trials.length < 2
      previous_result_count = -1
      trials.each_with_index do |trial, index|
        unless trial.is_a?(Hash)
          error("scaling_trials[#{index}] must be an object")
          next
        end
        expect_exact_keys("scaling_trials[#{index}]", trial, ["result_count", *SET_ORIENTED_COUNT_FIELDS])

        result_count = trial["result_count"]
        unless result_count.is_a?(Integer) && result_count >= 0
          error("scaling_trials[#{index}].result_count must be a nonnegative integer")
        else
          error("scaling_trials result_count values must increase") unless result_count > previous_result_count
          previous_result_count = result_count
        end

        SET_ORIENTED_COUNT_FIELDS.each do |field|
          value = trial[field]
          unless value.is_a?(Integer) && value >= 0
            error("scaling_trials[#{index}].#{field} must be a nonnegative integer")
            next
          end
          budget = budgets[field]
          if set_oriented && budget.is_a?(Integer) && value > budget
            error("scaling_trials[#{index}].#{field} exceeds bounded budget #{budget}")
          end
        end
      end
    end

    def validate_absolute_target
      scenario_type = value_at("scenario.type")
      targets = SCENARIO_TARGETS[scenario_type] || []
      targets.each do |path, maximum|
        value = value_at(path)
        next unless value.is_a?(Numeric)

        error("#{scenario_type} exceeds engineering target at #{path}: #{value} ms > #{maximum} ms") if value > maximum
      end

      ceiling = RELEASE_CEILINGS[scenario_type]
      return unless ceiling

      path, maximum = ceiling
      value = value_at(path)
      return unless value.is_a?(Numeric)

      error("#{scenario_type} exceeds absolute release ceiling at #{path}: #{value} ms > #{maximum} ms") if value > maximum
    end

    def validate_regressions
      comparisons = document["baseline_comparison"]
      unless comparisons.is_a?(Array)
        error("baseline_comparison must be an array")
        return
      end

      comparisons.each_with_index do |comparison, index|
        unless comparison.is_a?(Hash)
          error("baseline_comparison[#{index}] must be an object")
          next
        end
        expect_exact_keys("baseline_comparison[#{index}]", comparison, BASELINE_COMPARISON_KEYS)

        %w[metric baseline current regression_percent critical independent_review_ref].each do |field|
          value = comparison[field]
          missing_nullable_ref = field == "independent_review_ref" ? !comparison.key?(field) : value.nil?
          error("baseline_comparison[#{index}].#{field} is required") if missing_nullable_ref || (field == "metric" && !nonempty_string?(value))
        end
        baseline = comparison["baseline"]
        current = comparison["current"]
        error("baseline_comparison[#{index}].baseline must be positive") unless baseline.is_a?(Numeric) && baseline.positive?
        error("baseline_comparison[#{index}].current must be nonnegative") unless current.is_a?(Numeric) && current >= 0
        error("baseline_comparison[#{index}].regression_percent must be numeric") unless comparison["regression_percent"].is_a?(Numeric)
        error("baseline_comparison[#{index}].critical must be boolean") unless [true, false].include?(comparison["critical"])
        review_ref = comparison["independent_review_ref"]
        unless review_ref.nil? || nonempty_string?(review_ref)
          error("baseline_comparison[#{index}].independent_review_ref must be null or a non-empty string")
        end
        next unless baseline.is_a?(Numeric) && baseline.positive? && current.is_a?(Numeric) && current >= 0

        computed = ((current - baseline) / baseline.to_f) * 100.0
        recorded = comparison["regression_percent"]
        unless recorded.is_a?(Numeric) && (recorded - computed).abs <= 0.01
          error("baseline_comparison[#{index}].regression_percent does not match baseline/current")
        end

        next unless comparison["critical"] == true && computed > MAX_UNREVIEWED_REGRESSION_PERCENT
        next if nonempty_string?(comparison["independent_review_ref"])

        error("critical metric #{comparison['metric']} regressed #{computed.round(2)}% without independent review")
      end
    end

    def validate_telemetry
      telemetry = require_exact_hash("telemetry", TELEMETRY_KEYS)
      return unless telemetry

      require_nonempty_string("telemetry.safe_correlation_id")
      require_nonnegative_integer("telemetry.protected_content_canary_hits")
      error("protected-content telemetry canary detected leakage") unless telemetry["protected_content_canary_hits"] == 0
    end

    def validate_sensitive_keys(value, path = "$")
      case value
      when Hash
        value.each do |key, child|
          normalized = key.to_s.downcase
          error("forbidden sensitive evidence field #{path}.#{key}") if FORBIDDEN_EVIDENCE_KEYS.include?(normalized)
          validate_sensitive_keys(child, "#{path}.#{key}")
        end
      when Array
        value.each_with_index { |child, index| validate_sensitive_keys(child, "#{path}[#{index}]") }
      end
    end

    def require_hash(path)
      value = value_at(path)
      return value if value.is_a?(Hash)

      error("#{path} must be an object")
      nil
    end

    def require_exact_hash(path, allowed_keys)
      value = require_hash(path)
      return unless value

      expect_exact_keys(path, value, allowed_keys)
      value
    end

    def expect_exact_keys(path, value, allowed_keys)
      missing = allowed_keys.reject { |key| value.key?(key) }
      error("#{path} missing fields: #{missing.join(', ')}") unless missing.empty?

      unknown = value.keys - allowed_keys
      error("#{path} unknown fields: #{unknown.join(', ')}") unless unknown.empty?
    end

    def require_nonempty_string(path)
      error("#{path} must be a non-empty string") unless nonempty_string?(value_at(path))
    end

    def require_boolean(path)
      value = value_at(path)
      error("#{path} must be boolean") unless value == true || value == false
    end

    def require_enum(path, allowed)
      value = value_at(path)
      error("#{path} must be one of #{allowed.join(', ')}") unless allowed.include?(value)
    end

    def require_positive_integer(path)
      value = value_at(path)
      error("#{path} must be a positive integer") unless value.is_a?(Integer) && value.positive?
    end

    def require_nonnegative_integer(path)
      value = value_at(path)
      error("#{path} must be a nonnegative integer") unless value.is_a?(Integer) && value >= 0
    end

    def require_integer(path)
      error("#{path} must be an integer") unless value_at(path).is_a?(Integer)
    end

    def require_nonnegative_number(path)
      value = value_at(path)
      error("#{path} must be a nonnegative number") unless value.is_a?(Numeric) && value >= 0
    end

    def value_at(path)
      path.split(".").reduce(document) do |value, segment|
        break nil unless value.is_a?(Hash)

        value[segment]
      end
    end

    def valid_lazy_chunk?(chunk)
      chunk.is_a?(Hash) &&
        chunk.keys.sort == %w[capability gzip_bytes name] &&
        nonempty_string?(chunk["name"]) &&
        nonempty_string?(chunk["capability"]) &&
        chunk["gzip_bytes"].is_a?(Integer) &&
        chunk["gzip_bytes"] >= 0
    end

    def nonempty_string?(value)
      value.is_a?(String) && !value.strip.empty?
    end

    def error(message)
      @errors << message
      nil
    end
  end
end
