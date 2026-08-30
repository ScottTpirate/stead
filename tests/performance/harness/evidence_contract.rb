#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require "open3"
require "pathname"
require "time"

module Stead
  module PerformanceCanonicalJSON
    module_function

    def generate(value)
      JSON.generate(canonical(value))
    end

    def digest(value)
      Digest::SHA256.hexdigest(generate(value))
    end

    def file_digest(path)
      Digest::SHA256.file(path).hexdigest
    end

    def canonical(value)
      case value
      when Hash
        value.keys.sort.to_h { |key| [key, canonical(value.fetch(key))] }
      when Array
        value.map { |child| canonical(child) }
      else
        value
      end
    end
  end

  class PerformanceSchemaGate
    SCHEMAS = {
      "dataset_manifest" => "performance-dataset-v1.schema.json",
      "performance_measurement" => "performance-evidence-v1.schema.json",
      "performance_candidate_suite" => "performance-candidate-suite-v1.schema.json",
      "performance_benchmark_artifact" => "performance-benchmark-artifact-v1.schema.json",
      "performance_regression_review" => "performance-regression-review-v1.schema.json"
    }.freeze

    attr_reader :root

    def initialize(root:)
      @root = Pathname(root).expand_path
    end

    def validate(path, expected_type: nil)
      document = JSON.parse(Pathname(path).read(encoding: "UTF-8"))
      artifact_type = document.is_a?(Hash) ? document["artifact_type"] : nil
      errors = []
      if expected_type && artifact_type != expected_type
        errors << "artifact_type must be #{expected_type}"
      end
      schema_name = SCHEMAS[artifact_type]
      return [document, errors << "unknown artifact_type #{artifact_type.inspect}"] unless schema_name

      schema = root.join("tests/performance/harness", schema_name)
      validator = root.join("tests/performance/harness/validate_schema.mjs")
      runner = root.join("scripts/run_pinned_node.sh")
      stdout, stderr, status = Open3.capture3(
        runner.to_s, "node", validator.to_s, schema.to_s, Pathname(path).expand_path.to_s,
        chdir: root.to_s
      )
      payload = JSON.parse(stdout) unless stdout.strip.empty?
      unless status.success?
        schema_errors = payload&.dig("results", 0, "errors")
        if schema_errors.is_a?(Array) && !schema_errors.empty?
          schema_errors.each do |schema_error|
            location = schema_error["instancePath"].to_s
            errors << "JSON Schema #{location.empty? ? '/' : location}: #{schema_error['message']}"
          end
        else
          errors << "JSON Schema validation failed: #{stderr.strip.empty? ? stdout.strip : stderr.strip}"
        end
      end
      [document, errors]
    rescue JSON::ParserError => error
      [nil, ["invalid JSON: #{error.message}"]]
    rescue SystemCallError => error
      [nil, ["schema verifier unavailable: #{error.message}"]]
    end
  end

  class TrustedPerformanceManifest
    MANIFEST_PATH = "tests/performance/datasets/standard-request-boundary-v1.json"
    EXPECTED_SCENARIO_TYPES = %w[
      hot_composed_metadata_api same_region_metadata_api metadata_mutation
      remote_search_first_results project_route_useful_content cold_initial_application
      projection_to_visible input_acknowledgement command_palette_local_results
    ].freeze

    attr_reader :document, :path, :root

    def self.load(root:)
      root_path = Pathname(root).expand_path
      path = root_path.join(MANIFEST_PATH)
      new(JSON.parse(path.read(encoding: "UTF-8")), path: path, root: root_path)
    end

    def initialize(document, path:, root:)
      @document = document
      @path = Pathname(path).expand_path
      @root = Pathname(root).expand_path
    end

    def digest
      PerformanceCanonicalJSON.file_digest(path)
    end

    def scenario(id)
      document.fetch("scenarios", []).find { |candidate| candidate["id"] == id }
    end

    def load_shape(id)
      document.fetch("load_shapes", []).find { |candidate| candidate["id"] == id }
    end

    def scenario_ids
      document.fetch("scenarios", []).map { |scenario| scenario["id"] }
    end

    def validate
      errors = []
      errors << "Phase 1 trusted manifest must be standard/request_boundary" unless
        document["phase"] == "phase1" &&
        document["benchmark_profile"] == "standard" &&
        document["disclosure_mode"] == "request_boundary"

      scenario_ids = self.scenario_ids
      errors << "trusted scenario IDs must be unique" unless scenario_ids.uniq.length == scenario_ids.length
      types = document.fetch("scenarios", []).map { |scenario| scenario["type"] }
      errors << "trusted manifest must define each PERF-002 scenario exactly once" unless
        types.sort == EXPECTED_SCENARIO_TYPES.sort && types.uniq.length == types.length

      load_ids = document.fetch("load_shapes", []).map { |shape| shape["id"] }
      errors << "trusted load-shape IDs must be unique" unless load_ids.uniq.length == load_ids.length
      document.fetch("scenarios", []).each do |scenario|
        shape = load_shape(scenario["load_shape_id"])
        errors << "scenario #{scenario['id']} references an unknown load shape" unless shape
        target_keys = scenario.fetch("targets", []).map { |target| [target["metric"], target["kind"]] }
        errors << "scenario #{scenario['id']} has duplicate target authority" unless target_keys.uniq.length == target_keys.length
        critical_metrics = scenario.fetch("critical_metrics", [])
        errors << "scenario #{scenario['id']} has duplicate critical metrics" unless critical_metrics.uniq.length == critical_metrics.length
        baseline_ids = scenario.fetch("baselines", []).map { |baseline| baseline["baseline_id"] }
        errors << "scenario #{scenario['id']} has duplicate baseline IDs" unless baseline_ids.uniq.length == baseline_ids.length
        baseline_metrics = scenario.fetch("baselines", []).map { |baseline| baseline["metric"] }
        unknown_baselines = baseline_metrics - critical_metrics
        errors << "scenario #{scenario['id']} baselines must name trusted critical metrics" unless unknown_baselines.empty?
      end

      generator = document.fetch("generator", {})
      generator_path = safe_repo_file(generator["path"])
      if generator_path
        actual_digest = PerformanceCanonicalJSON.file_digest(generator_path)
        errors << "trusted corpus generator digest mismatch" unless actual_digest == generator["sha256"]
        stdout, stderr, status = Open3.capture3("ruby", generator_path.to_s, chdir: root.to_s)
        if status.success?
          errors << "trusted corpus generator output digest mismatch" unless Digest::SHA256.hexdigest(stdout) == generator["output_sha256"]
          begin
            generated = JSON.parse(stdout)
            errors << "trusted corpus seed does not match generator output" unless generated["generator_seed"] == generator["seed"]
            errors << "trusted corpus cardinalities do not match generator output" unless generated["cardinalities"] == document["corpus"]
          rescue JSON::ParserError
            errors << "trusted corpus generator did not emit JSON"
          end
        else
          errors << "trusted corpus generator failed: #{stderr.lines.first.to_s.strip}"
        end
      end
      errors
    end

    private

    def safe_repo_file(relative)
      unless relative.is_a?(String) && !relative.empty? && !relative.start_with?("/") && !relative.split("/").include?("..")
        return nil
      end
      candidate = root.join(relative).cleanpath
      return nil unless candidate.to_s.start_with?("#{root}/") && candidate.file?

      candidate
    end
  end

  class PerformanceEvidence
    SCHEMA_VERSION = "1.0"
    EAGER_BUNDLE_BUDGET_BYTES = 256_000
    MAX_UNREVIEWED_REGRESSION_PERCENT = 10.0
    PERCENTILES = { "p50" => 0.50, "p95" => 0.95, "p99" => 0.99 }.freeze
    TIMING_GROUPS = %w[latency sql openfga policy provider projection_lag].freeze
    COUNT_FIELDS = %w[
      browser_requests sql_queries postgres_writes openfga_calls policy_calls provider_calls
      nats_waits logical_audit_operations browser_forbidden_origin_requests authorization_cache_hits
    ].freeze
    BUDGET_COUNT_FIELDS = %w[
      sql_queries postgres_writes openfga_calls policy_calls provider_calls logical_audit_operations
    ].freeze

    attr_reader :document, :manifest

    def self.load(path, manifest:)
      new(JSON.parse(Pathname(path).read(encoding: "UTF-8")), manifest: manifest)
    end

    def initialize(document, manifest:)
      @document = document
      @manifest = manifest
    end

    def validate(candidate: false, regression_reviews: [], evidence_sha256: nil, implementation_owner: nil)
      @errors = []
      return ["evidence document must be an object"] unless document.is_a?(Hash)

      scenario = manifest.scenario(document["scenario_id"])
      unless scenario
        return ["scenario_id is not present in the trusted manifest"]
      end
      load_shape = manifest.load_shape(scenario["load_shape_id"])

      validate_dataset_binding
      validate_source(candidate)
      validate_provenance
      validate_raw_samples(candidate, load_shape)
      validate_counts(scenario)
      validate_scaling_trials(candidate, scenario, load_shape)
      validate_targets(scenario)
      validate_sizes(scenario)
      validate_telemetry
      validate_regressions(
        scenario,
        reviews: regression_reviews,
        evidence_sha256: evidence_sha256,
        implementation_owner: implementation_owner
      )
      @errors.uniq
    rescue StandardError => error
      ["semantic validation failed closed: #{error.class}: #{error.message}"]
    end

    def regressions
      scenario = manifest.scenario(document["scenario_id"])
      return [] unless scenario

      scenario.fetch("baselines", []).filter_map do |baseline|
        current = value_at(baseline["metric"])
        next unless current.is_a?(Numeric) && baseline["value"].is_a?(Numeric) && baseline["value"].positive?

        percent = ((current - baseline["value"]) / baseline["value"].to_f) * 100.0
        baseline.merge("current" => current, "regression_percent" => percent)
      end
    end

    private

    def validate_dataset_binding
      dataset = document["dataset"]
      unless dataset.is_a?(Hash)
        error("dataset binding must be an object")
        return
      end
      error("evidence dataset manifest_id is not trusted") unless dataset["manifest_id"] == manifest.document["manifest_id"]
      error("evidence dataset digest does not match the trusted manifest") unless dataset["sha256"] == manifest.digest
    end

    def validate_source(candidate)
      source = document["source"]
      return error("source must be an object") unless source.is_a?(Hash)

      revision = source["revision"]
      error("source.revision must be a full lowercase Git SHA") unless revision.is_a?(String) && revision.match?(/\A[0-9a-f]{40}\z/)
      begin
        Time.iso8601(source["recorded_at"].to_s)
      rescue ArgumentError
        error("source.recorded_at must be RFC3339")
      end
      if candidate
        error("candidate evidence_kind must be measurement") unless document["evidence_kind"] == "measurement"
        error("candidate evidence must come from a clean tree") unless source["dirty"] == false
      end
    end

    def validate_provenance
      provenance = document["provenance"]
      return error("provenance must be an object") unless provenance.is_a?(Hash)

      begin
        started = Time.iso8601(provenance["started_at"].to_s)
        ended_at = Time.iso8601(provenance["ended_at"].to_s)
        error("provenance.ended_at must not precede started_at") if ended_at < started
      rescue ArgumentError
        error("provenance timestamps must be RFC3339")
      end
    end

    def validate_raw_samples(candidate, load_shape)
      samples = document["raw_samples"]
      return error("raw_samples must be an object") unless samples.is_a?(Hash)

      series = []
      TIMING_GROUPS.each do |group|
        values = samples.dig("timings_ms", group)
        series << ["raw_samples.timings_ms.#{group}", values]
      end
      series << ["raw_samples.counts", samples["counts"]]
      series << ["raw_samples.response_bytes", samples["response_bytes"]]
      %w[lcp_ms inp_ms cls].each do |metric|
        series << ["raw_samples.web_vitals.#{metric}", samples.dig("web_vitals", metric)]
      end

      lengths = series.filter_map do |path, values|
        if values.is_a?(Array) && !values.empty?
          values.length
        else
          error("#{path} must be a non-empty array")
          nil
        end
      end
      error("all raw sample series must have the same length") unless lengths.empty? || lengths.uniq.length == 1
      sample_count = lengths.first
      if candidate && sample_count && load_shape && sample_count != load_shape["measured_samples"]
        error("candidate raw sample count #{sample_count} does not match trusted load shape #{load_shape['measured_samples']}")
      end

      actual_digest = PerformanceCanonicalJSON.digest(samples)
      error("raw_samples_sha256 does not match canonical raw samples") unless document["raw_samples_sha256"] == actual_digest

      TIMING_GROUPS.each do |group|
        values = samples.dig("timings_ms", group)
        next unless numeric_series?(values)

        PERCENTILES.each do |name, quantile|
          expected = percentile(values, quantile)
          actual = document.dig("timings_ms", group, name)
          error("timings_ms.#{group}.#{name} does not match raw samples") unless same_number?(actual, expected)
        end
      end

      count_samples = samples["counts"]
      if count_samples.is_a?(Array) && count_samples.all? { |sample| sample.is_a?(Hash) }
        COUNT_FIELDS.each do |field|
          values = count_samples.map { |sample| sample[field] }
          next unless values.all? { |value| value.is_a?(Integer) && value >= 0 }

          error("counts.#{field} must equal the maximum raw sample count") unless document.dig("counts", field) == values.max
        end
      end

      response_sizes = samples["response_bytes"]
      if response_sizes.is_a?(Array) && response_sizes.all? { |value| value.is_a?(Integer) && value >= 0 }
        error("sizes.response_bytes must equal the maximum raw sample response size") unless document.dig("sizes", "response_bytes") == response_sizes.max
      end

      %w[lcp_ms inp_ms cls].each do |metric|
        values = samples.dig("web_vitals", metric)
        next unless numeric_series?(values)

        expected = percentile(values, 0.95)
        error("web_vitals.#{metric} must equal raw-sample p95") unless same_number?(document.dig("web_vitals", metric), expected)
      end
    end

    def validate_counts(scenario)
      counts = document["counts"]
      return error("counts must be an object") unless counts.is_a?(Hash)

      error("browser forbidden-origin requests must be zero") unless counts["browser_forbidden_origin_requests"] == 0
      error("authorization decision cache hits must be zero") unless counts["authorization_cache_hits"] == 0
      error("request handling must wait for zero NATS operations") unless counts["nats_waits"] == 0

      classifications = scenario["classifications"]
      if classifications["primary_surface_after_shell"]
        error("primary surface after shell requires exactly one composed browser request") unless counts["browser_requests"] == 1
      end
      if classifications["ordinary_read"]
        error("ordinary read must make zero provider calls") unless counts["provider_calls"] == 0
        if classifications["primary_surface_after_shell"]
          error("request_boundary composed ordinary read requires exactly one logical audit operation") unless counts["logical_audit_operations"] == 1
        end
      end

      scenario.fetch("count_budgets", {}).each do |field, maximum|
        value = counts[field]
        error("counts.#{field} exceeds trusted scenario budget #{maximum}") if value.is_a?(Integer) && value > maximum
      end
    end

    def validate_scaling_trials(candidate, scenario, load_shape)
      trials = document["scaling_trials"]
      return error("scaling_trials must be an array") unless trials.is_a?(Array)

      expected_counts = load_shape ? load_shape["result_counts"] : []
      if candidate
        actual_counts = trials.filter_map { |trial| trial.is_a?(Hash) ? trial["result_count"] : nil }
        error("candidate scaling trials must exactly match trusted result counts #{expected_counts.inspect}") unless actual_counts == expected_counts
      end
      if scenario.dig("classifications", "set_oriented") && trials.length < 2
        error("set-oriented evidence requires at least two scaling trials")
      end

      previous = -1
      trials.each_with_index do |trial, index|
        unless trial.is_a?(Hash)
          error("scaling_trials[#{index}] must be an object")
          next
        end
        result_count = trial["result_count"]
        if result_count.is_a?(Integer) && result_count > previous
          previous = result_count
        else
          error("scaling trial result counts must strictly increase")
        end
        scenario.fetch("count_budgets", {}).each do |field, maximum|
          value = trial[field]
          error("scaling_trials[#{index}].#{field} exceeds trusted scenario budget #{maximum}") if value.is_a?(Integer) && value > maximum
        end
      end
    end

    def validate_targets(scenario)
      scenario.fetch("targets", []).each do |target|
        value = value_at(target["metric"])
        unless value.is_a?(Numeric)
          error("trusted target metric #{target['metric']} is missing")
          next
        end
        next unless value > target["maximum"]

        error("#{scenario['type']} exceeds #{target['kind']} at #{target['metric']}: #{value} > #{target['maximum']}")
      end
    end

    def validate_sizes(scenario)
      sizes = document["sizes"]
      return error("sizes must be an object") unless sizes.is_a?(Hash)

      eager = sizes["eager_javascript_gzip_bytes"]
      error("eager JavaScript gzip budget exceeded: #{eager} > #{EAGER_BUNDLE_BUDGET_BYTES}") if eager.is_a?(Numeric) && eager > EAGER_BUNDLE_BUDGET_BYTES

      baseline = sizes["frontend_baseline"]
      if scenario.dig("classifications", "frontend_touched") && !baseline.is_a?(Hash)
        error("frontend-touched evidence requires sizes.frontend_baseline")
        return
      end
      return if baseline.nil?
      return error("sizes.frontend_baseline must be an object or null") unless baseline.is_a?(Hash)

      error("frontend current gzip bytes must equal eager JavaScript bytes") unless baseline["current_gzip_bytes"] == eager
      expected_delta = baseline["current_gzip_bytes"].to_i - baseline["baseline_gzip_bytes"].to_i
      error("frontend eager delta does not match baseline/current values") unless baseline["delta_gzip_bytes"] == expected_delta
    end

    def validate_telemetry
      telemetry = document["telemetry"]
      return error("telemetry must be an object") unless telemetry.is_a?(Hash)

      rules = manifest.document["telemetry_scan"]
      error("telemetry ruleset is not the trusted ruleset") unless telemetry["ruleset_id"] == rules["ruleset_id"]
      records = telemetry["records"]
      return error("telemetry.records must be an array") unless records.is_a?(Array)

      error("telemetry.records_sha256 does not match canonical records") unless telemetry["records_sha256"] == PerformanceCanonicalJSON.digest(records)
      scan = telemetry_scan(records, rules)
      %w[normalized_key_count normalized_string_value_count forbidden_key_hits forbidden_value_hits canary_value_hits].each do |field|
        error("telemetry.#{field} does not match verifier-computed scan") unless telemetry[field] == scan[field]
      end
      error("telemetry contains forbidden normalized keys") unless scan["forbidden_key_hits"].zero?
      error("telemetry contains forbidden normalized string values") unless scan["forbidden_value_hits"].zero?
      error("telemetry contains protected-content canary values") unless scan["canary_value_hits"].zero?
      error("telemetry evidence must not retain protected content") unless telemetry["protected_content_retained"] == false
    end

    def validate_regressions(scenario, reviews:, evidence_sha256:, implementation_owner:)
      regressions.each do |comparison|
        next unless comparison["critical"] && comparison["regression_percent"] > MAX_UNREVIEWED_REGRESSION_PERCENT

        review = reviews.find do |candidate|
          candidate["scenario_id"] == scenario["id"] &&
            candidate["baseline_id"] == comparison["baseline_id"] &&
            candidate["metric"] == comparison["metric"]
        end
        unless review
          error("critical metric #{comparison['metric']} regressed #{comparison['regression_percent'].round(2)}% without structured independent review")
          next
        end
        expected = {
          "source_revision" => document.dig("source", "revision"),
          "dataset_sha256" => manifest.digest,
          "evidence_sha256" => evidence_sha256,
          "scenario_id" => scenario["id"],
          "baseline_id" => comparison["baseline_id"],
          "metric" => comparison["metric"]
        }
        expected.each do |field, value|
          error("regression review #{field} is not bound to candidate evidence") unless review[field] == value
        end
        error("regression review baseline is not verifier-derived") unless same_number?(review["baseline"], comparison["value"])
        error("regression review current is not verifier-derived") unless same_number?(review["current"], comparison["current"])
        error("regression review percent is not verifier-derived") unless same_number?(review["regression_percent"], comparison["regression_percent"], tolerance: 0.01)
        error("regression review must explicitly approve the exception") unless review["decision"] == "approved_exception"
        if implementation_owner && review.dig("reviewer", "identity") == implementation_owner
          error("implementation owner may not independently approve a regression")
        end
      end
    end

    def telemetry_scan(records, rules)
      key_count = 0
      string_count = 0
      forbidden_key_hits = 0
      forbidden_value_hits = 0
      canary_hits = 0
      walk = lambda do |value|
        case value
        when Hash
          value.each do |key, child|
            key_count += 1
            normalized_key = normalize(key)
            forbidden_key_hits += 1 if rules["forbidden_normalized_keys"].any? do |forbidden|
              normalized_key == forbidden || normalized_key.include?(forbidden)
            end
            walk.call(child)
          end
        when Array
          value.each { |child| walk.call(child) }
        when String
          string_count += 1
          normalized_value = value.strip.downcase
          normalized_for_pattern = normalize_punctuation(value)
          digest = Digest::SHA256.hexdigest(normalized_value)
          canary_hits += 1 if rules["canary_value_sha256"].include?(digest)
          forbidden_value_hits += 1 if rules["forbidden_normalized_value_patterns"].any? do |pattern|
            normalized_for_pattern.include?(normalize_punctuation(pattern))
          end
        end
      end
      walk.call(records)
      {
        "normalized_key_count" => key_count,
        "normalized_string_value_count" => string_count,
        "forbidden_key_hits" => forbidden_key_hits,
        "forbidden_value_hits" => forbidden_value_hits,
        "canary_value_hits" => canary_hits
      }
    end

    def normalize(value)
      value.to_s.downcase.gsub(/[^a-z0-9]/, "")
    end

    def normalize_punctuation(value)
      value.to_s.downcase.gsub(/[^a-z0-9]/, "")
    end

    def percentile(values, quantile)
      sorted = values.sort
      index = [(quantile * sorted.length).ceil - 1, 0].max
      sorted[index]
    end

    def numeric_series?(values)
      values.is_a?(Array) && !values.empty? && values.all? { |value| value.is_a?(Numeric) && value >= 0 }
    end

    def same_number?(left, right, tolerance: 0.0001)
      left.is_a?(Numeric) && right.is_a?(Numeric) && (left - right).abs <= tolerance
    end

    def value_at(path)
      path.split(".").reduce(document) do |value, segment|
        break nil unless value.is_a?(Hash)

        value[segment]
      end
    end

    def error(message)
      @errors << message
    end
  end

  class PerformanceCandidateSuite
    ALLOWED_REFERENCE_PREFIXES = %w[
      artifacts/performance/ packages/test-fixtures/harness/performance/ tests/performance/datasets/
    ].freeze

    attr_reader :document, :root, :schema_gate, :manifest

    def initialize(document, root:, schema_gate:, manifest:)
      @document = document
      @root = Pathname(root).expand_path
      @schema_gate = schema_gate
      @manifest = manifest
      @errors = []
    end

    def validate
      return ["candidate suite must be an object"] unless document.is_a?(Hash)

      unless manifest.document["phase"] == "phase1" && manifest.document["disclosure_mode"] == "request_boundary"
        error("Phase 1 candidate suites reject commit_boundary or non-standard manifests")
      end
      error("candidate suite source must be clean") unless document.dig("source", "dirty") == false
      validate_dataset_reference
      validate_runtime_components
      evidence_by_scenario, evidence_digests = validate_evidence
      artifacts = validate_benchmark_artifacts
      reviews = validate_regression_reviews
      validate_evidence_regressions(evidence_by_scenario, evidence_digests, reviews)
      validate_coverage(evidence_by_scenario, artifacts)
      @errors.uniq
    rescue StandardError => error
      [*@errors, "candidate suite validation failed closed: #{error.class}: #{error.message}"].uniq
    end

    private

    def validate_dataset_reference
      reference = document["dataset"]
      path = resolve_reference(reference)
      return unless path

      error("candidate suite must use the repository-owned trusted Phase 1 manifest") unless path == manifest.path
      error("candidate suite dataset digest mismatch") unless reference["sha256"] == manifest.digest
    end

    def validate_runtime_components
      expected = manifest.document.dig("server", "component_versions") || {}
      components = document["runtime_components"]
      return error("runtime_components must be an array") unless components.is_a?(Array)

      names = components.filter_map { |component| component.is_a?(Hash) ? component["name"] : nil }
      error("runtime component names must be unique") unless names.uniq.length == names.length
      error("runtime component set must exactly match the trusted manifest") unless names.sort == expected.keys.sort
      expected.each do |name, version|
        component = components.find { |candidate| candidate["name"] == name }
        error("runtime component #{name} version must be #{version}") unless component && component["version"] == version
      end
    end

    def validate_evidence
      evidence_refs = document["evidence"]
      unless evidence_refs.is_a?(Array)
        error("evidence must be an array")
        return [{}, {}]
      end
      scenario_ids = evidence_refs.filter_map { |reference| reference.is_a?(Hash) ? reference["scenario_id"] : nil }
      error("candidate evidence scenario IDs must be unique") unless scenario_ids.uniq.length == scenario_ids.length
      error("candidate evidence must cover every trusted Phase 1 scenario exactly once") unless scenario_ids.sort == manifest.scenario_ids.sort

      by_scenario = {}
      digests = {}
      evidence_refs.each do |reference|
        path = resolve_reference(reference)
        next unless path
        next unless verify_reference_digest(reference, path, "evidence")

        evidence, schema_errors = schema_gate.validate(path, expected_type: "performance_measurement")
        schema_errors.each { |schema_error| error("#{reference['path']}: #{schema_error}") }
        next unless evidence.is_a?(Hash)

        scenario_id = reference["scenario_id"]
        error("evidence reference scenario_id does not match evidence") unless evidence["scenario_id"] == scenario_id
        error("candidate evidence source revision differs from suite") unless evidence.dig("source", "revision") == document.dig("source", "revision")
        error("candidate evidence tool versions differ from suite provenance") unless evidence.dig("source", "tool_versions") == document.dig("source", "tool_versions")
        runner = evidence.dig("provenance", "runner")
        runner_version = evidence.dig("provenance", "runner_version")
        error("candidate evidence runner/version is not pinned by suite provenance") unless document.dig("source", "tool_versions", runner) == runner_version
        by_scenario[scenario_id] = evidence
        digests[scenario_id] = reference["sha256"]
      end
      [by_scenario, digests]
    end

    def validate_benchmark_artifacts
      references = document["benchmark_artifacts"]
      return error("benchmark_artifacts must be an array") || [] unless references.is_a?(Array)

      artifacts = []
      references.each do |reference|
        path = resolve_reference(reference)
        next unless path
        next unless verify_reference_digest(reference, path, "benchmark artifact")

        artifact, schema_errors = schema_gate.validate(path, expected_type: "performance_benchmark_artifact")
        schema_errors.each { |schema_error| error("#{reference['path']}: #{schema_error}") }
        next unless artifact.is_a?(Hash)

        error("benchmark artifact source revision differs from suite") unless artifact["source_revision"] == document.dig("source", "revision")
        error("benchmark artifact dataset digest differs from trusted manifest") unless artifact["dataset_sha256"] == manifest.digest
        tool = artifact.dig("producer", "tool")
        version = artifact.dig("producer", "version")
        error("benchmark artifact producer tool/version is not pinned by suite provenance") unless document.dig("source", "tool_versions", tool) == version
        error("benchmark artifact measurements digest mismatch") unless artifact["measurements_sha256"] == PerformanceCanonicalJSON.digest(artifact["measurements"])
        validate_causality(artifact)
        artifacts << artifact
      end
      artifact_ids = artifacts.map { |artifact| artifact["artifact_id"] }
      error("benchmark artifact IDs must be unique") unless artifact_ids.uniq.length == artifact_ids.length
      artifacts
    end

    def validate_causality(artifact)
      causality = artifact["causality"]
      if artifact["kind"] == "response_before_relay"
        unless causality.is_a?(Hash)
          error("response_before_relay artifact requires causality proof")
          return
        end
        events = causality["events"]
        expected_types = %w[authoritative_commit response_sent relay_started]
        types = events.is_a?(Array) ? events.map { |event| event["type"] } : []
        times = events.is_a?(Array) ? events.map { |event| event["monotonic_ns"] } : []
        error("response-before-relay causality events must be commit, response, relay") unless types == expected_types
        if times.length == 3 && times.all? { |value| value.is_a?(Integer) }
          error("response-before-relay causality must prove commit <= response < relay") unless times[0] <= times[1] && times[1] < times[2]
        end
      elsif !causality.nil?
        error("only response_before_relay artifacts may carry causality proof")
      end
    end

    def validate_regression_reviews
      references = document["regression_reviews"]
      return error("regression_reviews must be an array") || [] unless references.is_a?(Array)

      reviews = references.filter_map do |reference|
        path = resolve_reference(reference)
        next unless path
        next unless verify_reference_digest(reference, path, "regression review")

        review, schema_errors = schema_gate.validate(path, expected_type: "performance_regression_review")
        schema_errors.each { |schema_error| error("#{reference['path']}: #{schema_error}") }
        if review.is_a?(Hash)
          error("regression review source revision differs from suite") unless review["source_revision"] == document.dig("source", "revision")
          error("regression review dataset digest differs from trusted manifest") unless review["dataset_sha256"] == manifest.digest
          if review.dig("reviewer", "identity") == document.dig("source", "implementation_owner")
            error("implementation owner may not author an independent regression review")
          end
        end
        review if review.is_a?(Hash)
      end
      review_ids = reviews.map { |review| review["review_id"] }
      error("regression review IDs must be unique") unless review_ids.uniq.length == review_ids.length
      reviews
    end

    def validate_evidence_regressions(evidence_by_scenario, evidence_digests, reviews)
      required_review_keys = []
      evidence_by_scenario.each do |scenario_id, evidence|
        validator = PerformanceEvidence.new(evidence, manifest: manifest)
        validator.regressions.each do |comparison|
          if comparison["critical"] && comparison["regression_percent"] > PerformanceEvidence::MAX_UNREVIEWED_REGRESSION_PERCENT
            required_review_keys << [scenario_id, comparison["baseline_id"], comparison["metric"]]
          end
        end
        semantic_errors = validator.validate(
          candidate: true,
          regression_reviews: reviews,
          evidence_sha256: evidence_digests[scenario_id],
          implementation_owner: document.dig("source", "implementation_owner")
        )
        semantic_errors.each { |semantic_error| error("evidence #{scenario_id}: #{semantic_error}") }
      end
      review_keys = reviews.map { |review| [review["scenario_id"], review["baseline_id"], review["metric"]] }
      error("regression review bindings must be unique") unless review_keys.uniq.length == review_keys.length
      unused = review_keys - required_review_keys
      error("candidate suite contains regression reviews not required by verifier-computed critical regressions") unless unused.empty?
    end

    def validate_coverage(evidence_by_scenario, artifacts)
      kinds = artifacts.map { |artifact| artifact["kind"] }
      required_global = manifest.document["required_suite_artifact_kinds"] || []
      missing_global = required_global - kinds
      error("candidate suite missing required benchmark artifact kinds: #{missing_global.join(', ')}") unless missing_global.empty?

      manifest.document.fetch("scenarios", []).each do |scenario|
        next unless evidence_by_scenario.key?(scenario["id"])

        covered = artifacts.select { |artifact| artifact.fetch("scenario_ids", []).include?(scenario["id"]) }.map { |artifact| artifact["kind"] }
        missing = scenario.fetch("required_artifact_kinds", []) - covered
        error("scenario #{scenario['id']} missing benchmark artifact coverage: #{missing.join(', ')}") unless missing.empty?
      end
    end

    def resolve_reference(reference)
      unless reference.is_a?(Hash) && reference["path"].is_a?(String)
        error("file reference must contain a path")
        return nil
      end
      relative = reference["path"]
      unless ALLOWED_REFERENCE_PREFIXES.any? { |prefix| relative.start_with?(prefix) } &&
          !relative.start_with?("/") &&
          !relative.split("/").include?("..") &&
          Pathname(relative).cleanpath.to_s == relative
        error("unsafe or unauthorized candidate artifact path")
        return nil
      end

      candidate = root.join(relative).cleanpath
      unless candidate.to_s.start_with?("#{root}/") && candidate.file?
        error("candidate artifact path does not name a file")
        return nil
      end
      current = root
      Pathname(relative).each_filename do |component|
        current = current.join(component)
        if current.symlink?
          error("candidate artifact paths may not traverse symlinks")
          return nil
        end
      end
      candidate
    end

    def verify_reference_digest(reference, path, label)
      actual = PerformanceCanonicalJSON.file_digest(path)
      return true if reference["sha256"] == actual

      error("#{label} digest mismatch for #{reference['path']}")
      false
    end

    def error(message)
      @errors << message
      nil
    end
  end

  class PerformanceVerifier
    attr_reader :root, :schema_gate, :manifest

    def initialize(root:)
      @root = Pathname(root).expand_path
      @schema_gate = PerformanceSchemaGate.new(root: @root)
      @manifest = TrustedPerformanceManifest.load(root: @root)
    end

    def verify_evidence(path)
      manifest_errors = verify_manifest
      document, schema_errors = schema_gate.validate(path, expected_type: "performance_measurement")
      semantic_errors = document.is_a?(Hash) ? PerformanceEvidence.new(document, manifest: manifest).validate : []
      {
        "path" => path.to_s,
        "evidence_id" => document.is_a?(Hash) ? document["evidence_id"] : nil,
        "candidate_eligible" => false,
        "errors" => (manifest_errors + schema_errors + semantic_errors).uniq
      }
    end

    def verify_suite(path)
      manifest_errors = verify_manifest
      document, schema_errors = schema_gate.validate(path, expected_type: "performance_candidate_suite")
      semantic_errors = if document.is_a?(Hash)
                          PerformanceCandidateSuite.new(
                            document,
                            root: root,
                            schema_gate: schema_gate,
                            manifest: manifest
                          ).validate
                        else
                          []
                        end
      errors = (manifest_errors + schema_errors + semantic_errors).uniq
      {
        "path" => path.to_s,
        "suite_id" => document.is_a?(Hash) ? document["suite_id"] : nil,
        "candidate_eligible" => errors.empty?,
        "errors" => errors
      }
    end

    private

    def verify_manifest
      _document, schema_errors = schema_gate.validate(manifest.path, expected_type: "dataset_manifest")
      schema_errors + manifest.validate
    end
  end
end
