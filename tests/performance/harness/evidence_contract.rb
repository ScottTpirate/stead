#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "open3"
require "openssl"
require "pathname"
require "tempfile"
require "time"
require "tmpdir"
require "zlib"
require_relative "normative_controls"
require_relative "strict_json"

module Stead
  module PerformanceBoundedFile
    class TooLarge < StandardError; end

    module_function

    def read(path, max_bytes:)
      File.open(path, "rb") do |file|
        bytes = file.read(max_bytes + 1)
        raise TooLarge, "file exceeds #{max_bytes} bytes" if bytes.bytesize > max_bytes

        bytes
      end
    end

    def sha256(path, max_bytes:)
      digest = Digest::SHA256.new
      total = 0
      File.open(path, "rb") do |file|
        while (chunk = file.read(64 * 1024))
          total += chunk.bytesize
          raise TooLarge, "file exceeds #{max_bytes} bytes" if total > max_bytes

          digest.update(chunk)
        end
      end
      digest.hexdigest
    end
  end

  module PerformanceRetainedEvidenceScan
    SAFE_CONTROL_KEYS = %w[protectedcontentretained].freeze
    RAW_SCAN_OVERLAP_BYTES = 8_192

    module_function

    def structured_findings(document, rules:)
      findings = []
      walk = lambda do |value, path|
        case value
        when Hash
          value.each do |key, child|
            normalized = normalize(key)
            if !SAFE_CONTROL_KEYS.include?(normalized) && rules.fetch("forbidden_normalized_keys", []).any? do |forbidden|
              normalized == forbidden || normalized.include?(forbidden)
            end
              findings << "forbidden key at #{path}/#{key}"
            end
            findings << "protected-content canary at #{path}/#{key}" if encoded_canary?(key.to_s)
            walk.call(child, "#{path}/#{key}")
          end
        when Array
          value.each_with_index { |child, index| walk.call(child, "#{path}/#{index}") }
        when String
          normalized = normalize_punctuation(value)
          if rules.fetch("forbidden_normalized_value_patterns", []).any? do |pattern|
            normalized.include?(normalize_punctuation(pattern))
          end
            findings << "forbidden value at #{path}"
          end
          findings << "protected-content canary at #{path}" if encoded_canary?(value)
        end
      end
      walk.call(document, "$")
      findings.uniq
    end

    def raw_file_findings(path, rules:, max_bytes:)
      forbidden_needles = rules.fetch("forbidden_normalized_value_patterns", []).map(&:downcase)
      findings = []
      tail = +""
      scanned_bytes = 0
      binary_extension = %w[.js .bin .wasm .so .a .o .exe].include?(Pathname(path).extname.downcase)
      File.open(path, "rb") do |file|
        while (chunk = file.read(64 * 1024))
          scanned_bytes += chunk.bytesize
          if scanned_bytes > max_bytes
            findings << "retained bytes exceed #{max_bytes} byte ceiling"
            break
          end
          haystack = (tail + chunk).downcase
          forbidden_needles.each do |needle|
            findings << "retained bytes contain protected or forbidden content" if haystack.include?(needle)
          end
          if encoded_canary?(haystack)
            findings << "retained bytes contain protected or forbidden content"
          end
          unless binary_extension
            without_whitespace = haystack.gsub(/\s+/, "")
            if rules.fetch("forbidden_normalized_value_patterns", []).any? do |pattern|
              without_whitespace.include?(normalize_punctuation(pattern))
            end
              findings << "retained bytes contain protected or forbidden content"
            end
            normalized_assignments = haystack.gsub(/[^a-z0-9:=]/, "")
            if rules.fetch("forbidden_normalized_keys", []).any? do |key|
              normalized_assignments.include?("#{key}:") || normalized_assignments.include?("#{key}=")
            end
              findings << "retained bytes contain a forbidden structured key"
            end
          end
          tail = haystack.byteslice(-RAW_SCAN_OVERLAP_BYTES, RAW_SCAN_OVERLAP_BYTES) || haystack
          break unless findings.empty?
        end
      end
      findings.uniq
    end

    def encoded_canary?(value)
      haystack = value.to_s.downcase
      representations = normalized_encoded_representations(haystack)
      PerformanceNormativeControls::TELEMETRY_CANARIES.any? do |canary|
        encoded_forms(canary).any? do |form|
          normalized_encoded_representations(form).each_with_index.any? do |needle, index|
            representations.fetch(index).include?(needle)
          end
        end
      end
    end

    def normalized_encoded_representations(value)
      normalized = value.to_s.downcase
      [
        normalized,
        normalized.gsub(/[[:space:]]+/, ""),
        normalized.gsub(/[^a-z0-9]/, "")
      ]
    end

    def encoded_forms(canary)
      base64 = [canary].pack("m0")
      urlsafe = base64.tr("+/", "-_")
      [
        canary,
        base64,
        base64.delete_suffix("="),
        urlsafe,
        urlsafe.delete_suffix("="),
        canary.unpack1("H*"),
        canary.bytes.map { |byte| format("%%%02X", byte) }.join
      ].map(&:downcase).uniq
    end

    def normalize(value)
      value.to_s.downcase.gsub(/[^a-z0-9]/, "")
    end

    def normalize_punctuation(value)
      value.to_s.downcase.gsub(/\s+/, "").gsub(/[^a-z0-9:=_-]/, "")
    end
  end

  module PerformanceCanonicalJSON
    module_function

    def generate(value)
      JSON.generate(canonical(value))
    end

    def digest(value)
      Digest::SHA256.hexdigest(generate(value))
    end

    def file_digest(path, max_bytes: PerformanceStrictJSON::MAX_JSON_BYTES)
      PerformanceBoundedFile.sha256(path, max_bytes: max_bytes)
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
      "performance_corpus" => "performance-corpus-v1.schema.json",
      "frontend_bundle_baseline" => "performance-frontend-baseline-v1.schema.json",
      "performance_reviewer_authority_registry" => "performance-reviewer-authorities-v1.schema.json",
      "performance_measurement" => "performance-evidence-v1.schema.json",
      "performance_candidate_suite" => "performance-candidate-suite-v1.schema.json",
      "performance_benchmark_artifact" => "performance-benchmark-artifact-v1.schema.json",
      "performance_runner_output" => "performance-runner-output-v1.schema.json",
      "performance_regression_review" => "performance-regression-review-v1.schema.json"
    }.freeze

    attr_reader :root

    def initialize(root:)
      @root = Pathname(root).expand_path
    end

    def validate(path, expected_type: nil)
      document = PerformanceStrictJSON.parse_file(path)
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
      payload = PerformanceStrictJSON.parse(stdout) unless stdout.strip.empty?
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
    FRONTEND_BASELINE_PATH = "packages/test-fixtures/harness/performance/foundation-shell-baseline.json"
    EXPECTED_SCENARIO_TYPES = %w[
      hot_composed_metadata_api same_region_metadata_api metadata_mutation
      remote_search_first_results project_route_useful_content cold_initial_application
      projection_to_visible input_acknowledgement command_palette_local_results
    ].freeze

    attr_reader :document, :path, :root

    def self.load(root:)
      root_path = Pathname(root).expand_path
      path = root_path.join(MANIFEST_PATH)
      new(PerformanceStrictJSON.parse_file(path), path: path, root: root_path)
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

    def frontend_baseline
      @frontend_baseline ||= PerformanceStrictJSON.parse_file(root.join(FRONTEND_BASELINE_PATH))
    end

    def benchmark_environment(scenario_id)
      scenario = self.scenario(scenario_id)
      return nil unless scenario

      {
        "manifest_id" => document["manifest_id"],
        "benchmark_profile" => document["benchmark_profile"],
        "disclosure_mode" => document["disclosure_mode"],
        "generator" => document["generator"],
        "client" => document["client"],
        "server" => document["server"],
        "network" => document["network"],
        "topology" => document["topology"],
        "corpus" => document["corpus"],
        "cache_protocol" => document["cache_protocol"],
        "load_shape" => load_shape(scenario["load_shape_id"])
      }
    end

    def environment_digest(scenario_id)
      environment = benchmark_environment(scenario_id)
      environment && PerformanceCanonicalJSON.digest(environment)
    end

    def validate
      errors = []
      errors << "Phase 1 trusted manifest must be standard/request_boundary" unless
        document["phase"] == "phase1" &&
        document["benchmark_profile"] == "standard" &&
        document["disclosure_mode"] == "request_boundary"

      scenario_ids = self.scenario_ids
      errors << "trusted scenario IDs must be unique" unless scenario_ids.uniq.length == scenario_ids.length
      errors << "trusted manifest must define the closed Phase 1 scenario set" unless
        scenario_ids.sort == PerformanceNormativeControls::SCENARIOS.keys.sort
      types = document.fetch("scenarios", []).map { |scenario| scenario["type"] }
      errors << "trusted manifest must define each PERF-002 scenario exactly once" unless types.sort == EXPECTED_SCENARIO_TYPES.sort && types.uniq.length == types.length

      load_ids = document.fetch("load_shapes", []).map { |shape| shape["id"] }
      errors << "trusted load-shape IDs must be unique" unless load_ids.uniq.length == load_ids.length
      errors << "trusted load-shape set must match verifier-owned controls" unless load_ids.sort == PerformanceNormativeControls::LOAD_SHAPES.keys.sort
      PerformanceNormativeControls::LOAD_SHAPES.each do |id, expected|
        actual = load_shape(id)
        errors << "load shape #{id} weakens verifier-owned arrival, pacing, duration, sample, or scale controls" unless actual && actual.reject { |key, _value| key == "id" } == expected
      end
      expected_global_artifacts = PerformanceNormativeControls::REQUIRED_SUITE_ARTIFACT_KINDS
      actual_global_artifacts = document.fetch("required_suite_artifact_kinds", []).sort
      errors << "trusted suite artifact kinds weaken verifier-owned instrumentation" unless actual_global_artifacts == expected_global_artifacts
      telemetry_scan = document.fetch("telemetry_scan", {})
      expected_canary_digests = PerformanceNormativeControls::TELEMETRY_CANARIES.map { |canary| Digest::SHA256.hexdigest(canary) }
      errors << "trusted telemetry ruleset ID weakens verifier-owned scanning" unless telemetry_scan["ruleset_id"] == PerformanceNormativeControls::TELEMETRY_RULESET_ID
      errors << "trusted telemetry canary digests weaken verifier-owned scanning" unless telemetry_scan["canary_value_sha256"] == expected_canary_digests
      errors << "trusted telemetry forbidden keys weaken verifier-owned scanning" unless telemetry_scan["forbidden_normalized_keys"] == PerformanceNormativeControls::FORBIDDEN_TELEMETRY_KEYS
      errors << "trusted telemetry forbidden values weaken verifier-owned scanning" unless telemetry_scan["forbidden_normalized_value_patterns"] == PerformanceNormativeControls::FORBIDDEN_TELEMETRY_VALUE_PATTERNS
      document.fetch("scenarios", []).each do |scenario|
        expected_scenario = PerformanceNormativeControls::SCENARIOS[scenario["id"]]
        shape = load_shape(scenario["load_shape_id"])
        errors << "scenario #{scenario['id']} references an unknown load shape" unless shape
        if expected_scenario
          %w[type load_shape_id classifications count_budgets critical_metrics required_artifact_kinds].each do |field|
            expected_value = expected_scenario[field]
            expected_value = expected_value.sort if expected_value.is_a?(Array)
            actual_value = scenario[field]
            actual_value = actual_value.sort if actual_value.is_a?(Array)
            errors << "scenario #{scenario['id']} #{field} weakens verifier-owned controls" unless actual_value == expected_value
          end
          actual_targets = scenario.fetch("targets", []).map { |target| [target["metric"], target["maximum"], target["kind"]] }
          errors << "scenario #{scenario['id']} targets or ceilings weaken verifier-owned controls" unless actual_targets == expected_scenario["targets"]
        end
        target_keys = scenario.fetch("targets", []).map { |target| [target["metric"], target["kind"]] }
        errors << "scenario #{scenario['id']} has duplicate target authority" unless target_keys.uniq.length == target_keys.length
        critical_metrics = scenario.fetch("critical_metrics", [])
        errors << "scenario #{scenario['id']} has duplicate critical metrics" unless critical_metrics.uniq.length == critical_metrics.length
        baseline_ids = scenario.fetch("baselines", []).map { |baseline| baseline["baseline_id"] }
        errors << "scenario #{scenario['id']} has duplicate baseline IDs" unless baseline_ids.uniq.length == baseline_ids.length
        baseline_metrics = scenario.fetch("baselines", []).map { |baseline| baseline["metric"] }
        unknown_baselines = baseline_metrics - critical_metrics
        errors << "scenario #{scenario['id']} baselines must name trusted critical metrics" unless unknown_baselines.empty?
        scenario.fetch("baselines", []).each do |baseline|
          errors << "scenario #{scenario['id']} baseline profile is incompatible" unless baseline["benchmark_profile"] == document["benchmark_profile"]
          errors << "scenario #{scenario['id']} baseline disclosure mode is incompatible" unless baseline["disclosure_mode"] == document["disclosure_mode"]
          errors << "scenario #{scenario['id']} baseline environment is incompatible" unless baseline["environment_sha256"] == environment_digest(scenario["id"])
          _stdout, _stderr, status = Open3.capture3("git", "cat-file", "-e", "#{baseline['source_revision']}^{commit}", chdir: root.to_s)
          errors << "scenario #{scenario['id']} baseline source revision is not a Git commit" unless status.success?
        end
      end

      generator = document.fetch("generator", {})
      errors << "trusted corpus generator path is not verifier-owned" unless generator["path"] == PerformanceNormativeControls::GENERATOR_PATH
      errors << "trusted corpus generator seed is not verifier-owned" unless generator["seed"] == PerformanceNormativeControls::GENERATOR_SEED
      errors << "trusted corpus generator command is not verifier-owned" unless generator["command"] == PerformanceNormativeControls::GENERATOR_COMMAND
      generator_path = safe_repo_file(generator["path"])
      if generator_path
        actual_digest = PerformanceCanonicalJSON.file_digest(generator_path)
        errors << "trusted corpus generator digest mismatch" unless actual_digest == generator["sha256"]
        stdout, stderr, status = Open3.capture3("ruby", generator_path.to_s, chdir: root.to_s)
        if status.success?
          errors << "trusted corpus generator output digest mismatch" unless Digest::SHA256.hexdigest(stdout) == generator["output_sha256"]
          begin
            generated = PerformanceStrictJSON.parse(stdout)
            errors << "trusted corpus seed does not match generator output" unless generated["generator_seed"] == generator["seed"]
            errors << "trusted corpus cardinalities do not match generator output" unless generated["cardinalities"] == document["corpus"]
            Tempfile.create(["stead-performance-corpus-", ".json"]) do |file|
              file.binmode
              file.write(stdout)
              file.flush
              _corpus, schema_errors = PerformanceSchemaGate.new(root: root).validate(file.path, expected_type: "performance_corpus")
              schema_errors.each { |schema_error| errors << "generated corpus #{schema_error}" }
            end
            errors.concat(validate_generated_corpus(generated))
          rescue JSON::ParserError
            errors << "trusted corpus generator did not emit JSON"
          end
        else
          errors << "trusted corpus generator failed: #{stderr.lines.first.to_s.strip}"
        end
      else
        errors << "trusted corpus generator path is missing or unsafe"
      end
      errors
    end

    private

    def validate_generated_corpus(corpus)
      errors = []
      collection_names = document.fetch("corpus", {}).keys
      collection_names.each do |name|
        collection = corpus[name]
        errors << "generated corpus #{name} count mismatch" unless collection.is_a?(Array) && collection.length == document.dig("corpus", name)
        next unless collection.is_a?(Array) && collection.first.is_a?(Hash) && collection.first.key?("id")

        ids = collection.map { |entry| entry["id"] }
        errors << "generated corpus #{name} IDs must be unique" unless ids.compact.uniq.length == ids.length
      end

      index = lambda do |name|
        corpus.fetch(name, []).to_h { |entry| [entry["id"], entry] }
      end
      organizations = index.call("organizations")
      teams = index.call("teams")
      people = index.call("people")
      agents = index.call("agents")
      projects = index.call("projects")
      work_items = index.call("work_items")
      documents = index.call("documents")
      activity_events = index.call("activity_events")
      repositories = index.call("repositories")
      pull_requests = index.call("pull_requests")
      packages = index.call("packages")

      team_refs_valid = corpus.fetch("teams", []).all? do |team|
        organizations.key?(team["organization_id"]) &&
          (team["parent_team_id"].nil? || (teams.key?(team["parent_team_id"]) && teams[team["parent_team_id"]]["organization_id"] == team["organization_id"]))
      end
      errors << "generated teams must reference same-organization parents" unless team_refs_valid
      roots_by_organization = corpus.fetch("teams", []).select { |team| team["parent_team_id"].nil? }.group_by { |team| team["organization_id"] }
      errors << "generated team hierarchy must have exactly one root per organization" unless
        organizations.keys.all? { |organization_id| roots_by_organization.fetch(organization_id, []).length == 1 }
      team_depths = {}
      hierarchy_valid = corpus.fetch("teams", []).all? do |team|
        seen = {}
        current = team
        depth = 0
        valid = true
        while current && current["parent_team_id"]
          if seen[current["id"]]
            valid = false
            break
          end
          seen[current["id"]] = true
          current = teams[current["parent_team_id"]]
          depth += 1
          if depth > 2
            valid = false
            break
          end
        end
        team_depths[team["id"]] = depth if valid && current
        valid && current
      end
      errors << "generated team hierarchy must be acyclic, rooted, and no deeper than two levels" unless hierarchy_valid
      expected_edges = corpus.fetch("teams", []).reject { |team| team["parent_team_id"].nil? }.map do |team|
        [team["parent_team_id"], team["id"], team_depths[team["id"]]]
      end.sort
      actual_edges = corpus.fetch("team_edges", []).map { |edge| [edge["parent_team_id"], edge["child_team_id"], edge["depth"]] }.sort
      errors << "generated team edges must exactly represent hierarchical team parents and computed depth" unless actual_edges == expected_edges

      errors << "generated people must reference same-organization home teams" unless corpus.fetch("people", []).all? do |person|
        organizations.key?(person["organization_id"]) && teams.dig(person["home_team_id"], "organization_id") == person["organization_id"]
      end
      errors << "generated agents must reference same-organization human delegators" unless corpus.fetch("agents", []).all? do |agent|
        organizations.key?(agent["organization_id"]) && people.dig(agent["delegated_by_person_id"], "organization_id") == agent["organization_id"]
      end
      errors << "generated projects must reference same-organization teams" unless corpus.fetch("projects", []).all? do |project|
        organizations.key?(project["organization_id"]) && teams.dig(project["team_id"], "organization_id") == project["organization_id"]
      end

      work_refs_valid = corpus.fetch("work_items", []).all? do |work|
        project = projects[work["project_id"]]
        creator = people[work["creator_person_id"]]
        assignee = work["assignee_type"] == "agent" ? agents[work["assignee_id"]] : people[work["assignee_id"]]
        project && creator && assignee &&
          project["organization_id"] == work["organization_id"] &&
          creator["organization_id"] == work["organization_id"] &&
          assignee["organization_id"] == work["organization_id"]
      end
      errors << "generated work must have referentially valid same-organization creators and assignees" unless work_refs_valid

      document_refs_valid = corpus.fetch("documents", []).all? do |doc|
        scope = case doc["scope_type"]
                when "organization" then organizations[doc["scope_id"]]
                when "team" then teams[doc["scope_id"]]
                when "project" then projects[doc["scope_id"]]
                end
        scope_organization_id = doc["scope_type"] == "organization" ? scope&.dig("id") : scope&.dig("organization_id")
        author = people[doc["author_person_id"]]
        project_ok = doc["project_id"].nil? || projects.dig(doc["project_id"], "organization_id") == doc["organization_id"]
        scope && author && scope_organization_id == doc["organization_id"] && author["organization_id"] == doc["organization_id"] && project_ok
      end
      errors << "generated documents must have valid Organization/Team/Project scopes and authors" unless document_refs_valid
      errors << "generated document versions must reference same-organization documents and authors" unless corpus.fetch("document_versions", []).all? do |version|
        document = documents[version["document_id"]]
        author = people[version["author_person_id"]]
        document && author && document["organization_id"] == author["organization_id"]
      end

      errors << "generated Work-Doc relationships must have valid same-organization endpoints" unless corpus.fetch("relationships", []).all? do |relationship|
        work = work_items[relationship["source_id"]]
        doc = documents[relationship["target_id"]]
        work && doc && work["organization_id"] == doc["organization_id"] && relationship["organization_id"] == work["organization_id"]
      end
      errors << "generated activity actors and objects must have valid endpoints" unless corpus.fetch("activity_events", []).all? do |event|
        actor = event["actor_type"] == "agent" ? agents[event["actor_id"]] : people[event["actor_id"]]
        work = work_items[event["object_id"]]
        actor && work && actor["organization_id"] == event["organization_id"] && work["organization_id"] == event["organization_id"]
      end
      errors << "generated inbox entries must reference same-organization recipients and activity" unless corpus.fetch("inbox_entries", []).all? do |entry|
        person = people[entry["recipient_person_id"]]
        event = activity_events[entry["activity_event_id"]]
        person && event && person["organization_id"] == entry["organization_id"] && event["organization_id"] == entry["organization_id"]
      end
      errors << "generated audit principals and resources must have valid endpoints" unless corpus.fetch("audit_events", []).all? do |event|
        principal = event["principal_type"] == "agent" ? agents[event["principal_id"]] : people[event["principal_id"]]
        work = work_items[event["resource_id"]]
        principal && work && principal["organization_id"] == event["organization_id"] && work["organization_id"] == event["organization_id"]
      end

      errors << "generated repositories must belong only to software-capability projects" unless corpus.fetch("repositories", []).all? do |repository|
        projects.dig(repository["project_id"], "capabilities") == %w[work docs code delivery]
      end
      errors << "generated pull requests must reference same-organization repositories and authors" unless corpus.fetch("pull_requests", []).all? do |pull_request|
        repository = repositories[pull_request["repository_id"]]
        author = people[pull_request["author_person_id"]]
        project = repository && projects[repository["project_id"]]
        repository && author && project && project["organization_id"] == author["organization_id"]
      end
      errors << "generated builds must reference pull requests from the same repository" unless corpus.fetch("builds", []).all? do |build|
        pull_request = pull_requests[build["pull_request_id"]]
        repositories.key?(build["repository_id"]) && pull_request && pull_request["repository_id"] == build["repository_id"]
      end
      errors << "generated packages must reference repositories" unless corpus.fetch("packages", []).all? { |package| repositories.key?(package["repository_id"]) }
      errors << "generated releases must reference same-repository packages and same-organization human approvers" unless corpus.fetch("releases", []).all? do |release|
        repository = repositories[release["repository_id"]]
        package = packages[release["package_id"]]
        approver = people[release["approver_person_id"]]
        project = repository && projects[repository["project_id"]]
        repository && package && approver && project &&
          package["repository_id"] == repository["id"] && approver["organization_id"] == project["organization_id"]
      end

      distribution_values = {
        "project_classification" => corpus.fetch("projects", []).map { |project| project["classification"] },
        "work_status" => corpus.fetch("work_items", []).map { |work| work["status"] },
        "document_scope" => corpus.fetch("documents", []).map { |doc| doc["scope_type"] },
        "assignment_subject" => corpus.fetch("work_items", []).map { |work| work["assignee_type"] }
      }
      distributions = PerformanceNormativeControls::CORPUS_DISTRIBUTION_COUNT_BOUNDS.to_h do |name, bounds|
        counts = distribution_values.fetch(name).tally
        [name, bounds.all? { |value, range| range.cover?(counts.fetch(value, 0)) }]
      end
      search_records = corpus.fetch("work_items", []) + corpus.fetch("documents", [])
      distributions["search_text"] = search_records.map { |record| record["search_text"] }.uniq.length >= 12 &&
        search_records.all? { |record| record["search_text"].length.between?(80, 240) }
      distributions["capability"] = corpus.fetch("projects", []).count { |project| project["capabilities"].include?("code") } == 50
      distributions.each { |name, valid| errors << "generated corpus lacks required #{name} distribution" unless valid }
      errors
    end

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
    FRONTEND_CAPABILITIES = %w[docs_editor code delivery administration migration analytics].freeze
    BUNDLE_PATH_PREFIXES = %w[artifacts/performance/ packages/test-fixtures/harness/performance/].freeze
    MAX_BUNDLE_FILE_BYTES = 32 * 1024 * 1024

    attr_reader :document, :manifest

    def self.load(path, manifest:)
      new(PerformanceStrictJSON.parse_file(path), manifest: manifest)
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
      validate_request_traces(candidate, scenario)
      validate_counts(scenario)
      validate_scaling_trials(candidate, scenario, load_shape)
      validate_go_microbenchmark(scenario)
      validate_targets(scenario)
      validate_sizes(scenario)
      validate_telemetry
      validate_retained_document
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

      validate_count_contract(counts, scenario, "counts")
      raw_counts = document.dig("raw_samples", "counts")
      if raw_counts.is_a?(Array)
        raw_counts.each_with_index do |sample, index|
          next error("raw_samples.counts[#{index}] must be an object") unless sample.is_a?(Hash)

          validate_count_contract(sample, scenario, "raw_samples.counts[#{index}]")
        end
      end
    end

    def validate_count_contract(counts, scenario, label)
      controls = PerformanceNormativeControls::SCENARIOS.fetch(scenario["id"])
      PerformanceNormativeControls::GLOBAL_EXACT_COUNTS.merge(controls["exact_counts"]).each do |field, expected|
        error("#{label}.#{field} must equal verifier-owned value #{expected}") unless counts[field] == expected
      end
      controls["minimum_counts"].each do |field, minimum|
        value = counts[field]
        error("#{label}.#{field} must be at least verifier-owned minimum #{minimum}") unless value.is_a?(Integer) && value >= minimum
      end

      scenario.fetch("count_budgets", {}).each do |field, maximum|
        value = counts[field]
        error("#{label}.#{field} exceeds trusted scenario budget #{maximum}") if value.is_a?(Integer) && value > maximum
      end
    end

    def validate_request_traces(candidate, scenario)
      traces = document["request_traces"]
      return error("request_traces must be a non-empty array") unless traces.is_a?(Array) && !traces.empty?

      error("request_traces_sha256 does not match canonical request traces") unless
        document["request_traces_sha256"] == PerformanceCanonicalJSON.digest(traces)
      samples = document.dig("raw_samples", "counts")
      return error("request traces require raw count samples") unless samples.is_a?(Array) && !samples.empty?

      indexes = traces.filter_map { |trace| trace.is_a?(Hash) ? trace["sample_index"] : nil }
      error("request trace sample indexes must be unique") unless indexes.uniq.length == indexes.length
      if candidate && (traces.length != samples.length || indexes.sort != (0...samples.length).to_a)
        error("candidate request traces must cover every raw count sample exactly once")
      end
      trace_ids = traces.filter_map { |trace| trace.is_a?(Hash) ? trace["trace_id_hash"] : nil }
      error("candidate request trace identities must be unique") if candidate && trace_ids.uniq.length != traces.length
      validate_load_schedule(traces, manifest.load_shape(scenario["load_shape_id"])) if candidate

      requires_relay_proof = PerformanceNormativeControls::SCENARIOS.fetch(scenario["id"])["required_artifact_kinds"].include?("response_before_relay")
      traces.each_with_index do |trace, trace_index|
        unless trace.is_a?(Hash)
          error("request_traces[#{trace_index}] must be an object")
          next
        end
        validate_request_trace(trace, trace_index, samples, requires_relay_proof)
      end
    end

    def validate_load_schedule(traces, load_shape)
      return error("candidate request traces require a trusted load shape") unless load_shape.is_a?(Hash)

      ordered = traces.select { |trace| trace.is_a?(Hash) }.sort_by { |trace| trace["sample_index"].to_i }
      starts = ordered.map { |trace| trace["sample_started_monotonic_ns"] }
      unless starts.length == traces.length && starts.all? { |value| value.is_a?(Integer) && value >= 0 }
        error("candidate request traces require a monotonic start for every sample")
        return
      end
      pacing_ns = load_shape["pacing_ms"] * 1_000_000
      duration_ns = load_shape["duration_seconds"] * 1_000_000_000
      error("candidate sample starts must exactly prove trusted pacing") unless
        starts.each_cons(2).all? { |left, right| right - left == pacing_ns }
      error("candidate sample schedule must exactly prove trusted measured duration") unless
        starts.length.positive? && (starts.last - starts.first) + pacing_ns == duration_ns
      ordered.each_cons(2) do |trace, following|
        response = trace.fetch("events", []).find { |event| event["type"] == "response_sent" }
        next unless response && response["monotonic_ns"].is_a?(Integer)

        error("single-user load schedule overlaps request responses") unless response["monotonic_ns"] <= following["sample_started_monotonic_ns"]
      end
      ordered.each_with_index do |trace, index|
        event_times = trace.fetch("events", []).filter_map { |event| event["monotonic_ns"] }
        error("request_traces[#{index}] contains events before its sample start") unless
          event_times.all? { |timestamp| timestamp.is_a?(Integer) && timestamp >= trace["sample_started_monotonic_ns"] }
      end
    end

    def validate_request_trace(trace, trace_index, samples, requires_relay_proof)
      label = "request_traces[#{trace_index}]"
      events = trace["events"]
      return error("#{label}.events must be a non-empty array") unless events.is_a?(Array) && !events.empty?

      times = events.filter_map { |event| event.is_a?(Hash) ? event["monotonic_ns"] : nil }
      error("#{label} monotonic timestamps must be nondecreasing") unless
        times.length == events.length && times.each_cons(2).all? { |left, right| left <= right }
      sample_index = trace["sample_index"]
      unless sample_index.is_a?(Integer) && sample_index >= 0 && sample_index < samples.length
        error("#{label}.sample_index must select a raw count sample")
        return
      end

      event_counts = Hash.new(0)
      events.each do |event|
        next unless event.is_a?(Hash)

        event_counts[event["type"]] += 1
        if event["type"] == "browser_request"
          error("#{label} browser request must use a route template") unless
            event["route_template"].is_a?(String) && event["route_template"].start_with?("/")
        end
      end
      expected = samples[sample_index]
      mapping = {
        "browser_requests" => event_counts["browser_request"],
        "sql_queries" => event_counts["sql_query"],
        "postgres_writes" => event_counts["postgres_write"],
        "openfga_calls" => event_counts["openfga_call"],
        "policy_calls" => event_counts["policy_call"],
        "provider_calls" => event_counts["provider_call"],
        "nats_waits" => event_counts["nats_wait"],
        "logical_audit_operations" => event_counts["logical_audit_operation"],
        "authorization_cache_hits" => event_counts["authorization_cache_hit"],
        "browser_forbidden_origin_requests" => events.count do |event|
          event.is_a?(Hash) && event["type"] == "browser_request" && event["origin"] != "stead_api"
        end
      }
      mapping.each do |field, value|
        error("#{label} #{field} does not match raw sample #{sample_index}") unless expected[field] == value
      end

      if requires_relay_proof
        outbox_writes = events.select { |event| event["type"] == "postgres_write" && event["write_role"] == "transactional_outbox" }
        causality = outbox_writes + events.select { |event| %w[authoritative_commit response_sent relay_started].include?(event["type"]) }
        types = causality.map { |event| event["type"] }
        causal_times = causality.map { |event| event["monotonic_ns"] }
        error("#{label} must contain exactly outbox write, commit, response, and relay causality events") unless
          types == %w[postgres_write authoritative_commit response_sent relay_started]
        transaction_ids = causality.map { |event| event["transaction_id_hash"] }
        outbox_event_ids = causality.map { |event| event["outbox_event_id_hash"] }
        error("#{label} relay causality must bind one transaction and outbox event") unless
          transaction_ids.length == 4 && transaction_ids.all? { |value| value.is_a?(String) && value.match?(/\A[0-9a-f]{64}\z/) } &&
          transaction_ids.uniq.length == 1 && outbox_event_ids.length == 4 &&
          outbox_event_ids.all? { |value| value.is_a?(String) && value.match?(/\A[0-9a-f]{64}\z/) } && outbox_event_ids.uniq.length == 1
        if causal_times.length == 4 && causal_times.all? { |value| value.is_a?(Integer) }
          error("#{label} must prove outbox <= commit <= response < relay") unless
            causal_times[0] <= causal_times[1] && causal_times[1] <= causal_times[2] && causal_times[2] < causal_times[3]
        end
      end

      return unless document["scenario_id"] == "metadata-mutation"

      state_writes = events.select { |event| event["type"] == "postgres_write" && event["write_role"] == "authoritative_state" }
      outbox_writes = events.select { |event| event["type"] == "postgres_write" && event["write_role"] == "transactional_outbox" }
      commits = events.select { |event| event["type"] == "authoritative_commit" }
      error("metadata mutation trace must contain authoritative state and transactional outbox writes") unless state_writes.length == 1 && outbox_writes.length == 1
      transaction_ids = (state_writes + outbox_writes + commits).map { |event| event["transaction_id_hash"] }
      error("metadata mutation state, outbox, and commit must share one digest-bound transaction") unless
        transaction_ids.length == 3 && transaction_ids.all? { |value| value.is_a?(String) && value.match?(/\A[0-9a-f]{64}\z/) } && transaction_ids.uniq.length == 1
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
        controls = PerformanceNormativeControls::SCENARIOS.fetch(scenario["id"])
        PerformanceNormativeControls::GLOBAL_EXACT_COUNTS.merge(controls["exact_counts"]).slice(*BUDGET_COUNT_FIELDS).each do |field, expected|
          error("scaling_trials[#{index}].#{field} must equal verifier-owned value #{expected}") unless trial[field] == expected
        end
        controls["minimum_counts"].each do |field, minimum|
          next unless BUDGET_COUNT_FIELDS.include?(field)

          value = trial[field]
          error("scaling_trials[#{index}].#{field} must be at least verifier-owned minimum #{minimum}") unless value.is_a?(Integer) && value >= minimum
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

    def validate_go_microbenchmark(scenario)
      measurement = document["go_microbenchmark"]
      required = PerformanceNormativeControls::SCENARIOS.fetch(scenario["id"])["required_artifact_kinds"].include?("go_microbenchmark")
      if required
        return error("scenario requires runner-produced Go microbenchmark evidence") unless measurement.is_a?(Hash)

        %w[nanoseconds_per_operation allocations_per_operation bytes_per_operation].each do |metric|
          value = measurement[metric]
          error("go_microbenchmark.#{metric} must be numeric") unless value.is_a?(Numeric)
        end
      elsif !measurement.nil?
        error("scenario without Go microbenchmark instrumentation must report null")
      end
    end

    def validate_sizes(scenario)
      sizes = document["sizes"]
      return error("sizes must be an object") unless sizes.is_a?(Hash)

      eager = sizes["eager_javascript_gzip_bytes"]
      error("eager JavaScript gzip budget exceeded: #{eager} > #{EAGER_BUNDLE_BUDGET_BYTES}") if eager.is_a?(Numeric) && eager > EAGER_BUNDLE_BUDGET_BYTES

      graph = sizes["frontend_bundle_graph"]
      frontend_touched = scenario.dig("classifications", "frontend_touched")
      error("frontend-touched evidence requires a byte-backed frontend bundle graph") if frontend_touched && !graph.is_a?(Hash)
      if graph.nil?
        error("lazy JavaScript summaries require a frontend bundle graph") unless sizes.fetch("lazy_javascript_chunks", []).empty?
        error("lazy JavaScript bytes must be zero without a frontend bundle graph") unless sizes["lazy_javascript_gzip_bytes"] == 0
      elsif graph.is_a?(Hash)
        validate_frontend_bundle_graph(graph, sizes)
      else
        error("sizes.frontend_bundle_graph must be an object or null")
      end

      baseline = sizes["frontend_baseline"]
      if frontend_touched && !baseline.is_a?(Hash)
        error("frontend-touched evidence requires sizes.frontend_baseline")
        return
      end
      return if baseline.nil?
      return error("sizes.frontend_baseline must be an object or null") unless baseline.is_a?(Hash)

      trusted = manifest.frontend_baseline
      error("frontend baseline ID is not the trusted bundle baseline") unless baseline["baseline_id"] == trusted["baseline_id"]
      error("frontend baseline gzip bytes are not the trusted measured value") unless baseline["baseline_gzip_bytes"] == trusted["eager_javascript_bytes_gzip"]
      error("frontend current gzip bytes must equal eager JavaScript bytes") unless baseline["current_gzip_bytes"] == eager
      expected_delta = baseline["current_gzip_bytes"].to_i - baseline["baseline_gzip_bytes"].to_i
      error("frontend eager delta does not match baseline/current values") unless baseline["delta_gzip_bytes"] == expected_delta
      error("frontend lazy delta does not match verifier-computed lazy bytes") unless
        baseline["lazy_chunk_delta_gzip_bytes"] == sizes["lazy_javascript_gzip_bytes"]
    end

    def validate_frontend_bundle_graph(graph, sizes)
      files = graph["files"]
      return error("frontend bundle graph files must be a non-empty array") unless files.is_a?(Array) && !files.empty?

      paths = files.filter_map { |file| file.is_a?(Hash) ? file["path"] : nil }
      error("frontend bundle graph file paths must be unique") unless paths.uniq.length == paths.length
      by_path = {}
      actual = {}
      files.each do |file|
        next unless file.is_a?(Hash)

        path = resolve_bundle_file(file["path"])
        next unless path

        bytes = PerformanceBoundedFile.read(path, max_bytes: MAX_BUNDLE_FILE_BYTES)
        measured = {
          "sha256" => Digest::SHA256.hexdigest(bytes),
          "uncompressed_bytes" => bytes.bytesize,
          "gzip_bytes" => Zlib.gzip(bytes, level: Zlib::BEST_COMPRESSION).bytesize
        }
        measured.each do |field, value|
          error("frontend bundle #{file['path']} #{field} does not match artifact bytes") unless file[field] == value
        end
        rules = manifest.document["telemetry_scan"] || {}
        PerformanceRetainedEvidenceScan.raw_file_findings(path, rules: rules, max_bytes: MAX_BUNDLE_FILE_BYTES).each do |finding|
          error("frontend bundle #{file['path']} #{finding}")
        end
        by_path[file["path"]] = file
        actual[file["path"]] = measured
      end

      files.each do |file|
        next unless file.is_a?(Hash)

        edges = Array(file["imports"]) + Array(file["dynamic_imports"])
        error("frontend bundle graph edges must reference declared files") unless (edges - paths).empty?
      end

      entries = graph["capability_entries"]
      entries = [] unless entries.is_a?(Array)
      capabilities = entries.filter_map { |entry| entry.is_a?(Hash) ? entry["capability"] : nil }
      entry_paths = entries.filter_map { |entry| entry.is_a?(Hash) ? entry["path"] : nil }
      error("frontend bundle graph must declare each lazy capability exactly once") unless
        capabilities.sort == FRONTEND_CAPABILITIES.sort && capabilities.uniq.length == capabilities.length
      error("frontend bundle lazy entry paths must be unique") unless entry_paths.uniq.length == entry_paths.length

      eager_paths = bundle_closure(graph["eager_entry_path"], by_path, dynamic: false)
      dynamic_frontier = eager_paths.flat_map { |path| Array(by_path.dig(path, "dynamic_imports")) }.uniq.sort
      error("frontend bundle eager graph must dynamically reference exactly the six capability entries") unless
        dynamic_frontier == entry_paths.sort

      summaries = sizes["lazy_javascript_chunks"]
      summaries = [] unless summaries.is_a?(Array)
      summary_capabilities = summaries.filter_map { |summary| summary.is_a?(Hash) ? summary["capability"] : nil }
      error("lazy JavaScript summaries must declare each capability exactly once") unless
        summary_capabilities.sort == FRONTEND_CAPABILITIES.sort && summary_capabilities.uniq.length == summary_capabilities.length

      lazy_union = []
      entries.each do |entry|
        next unless entry.is_a?(Hash)

        capability = entry["capability"]
        capability_paths = bundle_closure(entry["path"], by_path, dynamic: true) - eager_paths
        capability_paths = capability_paths.sort
        lazy_union.concat(capability_paths)
        summary = summaries.find { |candidate| candidate.is_a?(Hash) && candidate["capability"] == capability }
        unless summary
          error("lazy JavaScript summary is missing capability #{capability}")
          next
        end
        expected_uncompressed = capability_paths.sum { |path| actual.dig(path, "uncompressed_bytes").to_i }
        expected_gzip = capability_paths.sum { |path| actual.dig(path, "gzip_bytes").to_i }
        error("lazy JavaScript summary name must equal its capability") unless summary["name"] == capability
        error("lazy JavaScript summary entry path does not match graph") unless summary["entry_path"] == entry["path"]
        error("lazy JavaScript summary file set omits, substitutes, or duplicates transitive graph files") unless
          Array(summary["file_paths"]).sort == capability_paths
        error("lazy JavaScript summary uncompressed bytes do not match graph files") unless summary["uncompressed_bytes"] == expected_uncompressed
        error("lazy JavaScript summary gzip bytes do not match graph files") unless summary["gzip_bytes"] == expected_gzip
      end

      eager_gzip = eager_paths.sum { |path| actual.dig(path, "gzip_bytes").to_i }
      lazy_paths = lazy_union.uniq.sort
      lazy_gzip = lazy_paths.sum { |path| actual.dig(path, "gzip_bytes").to_i }
      error("frontend bundle graph contains unreachable or unclassified JavaScript files") unless
        (eager_paths + lazy_paths).uniq.sort == paths.sort
      error("eager JavaScript bytes do not match the transitive eager graph") unless sizes["eager_javascript_gzip_bytes"] == eager_gzip
      error("lazy JavaScript bytes do not match the unique transitive lazy graph") unless sizes["lazy_javascript_gzip_bytes"] == lazy_gzip
    end

    def bundle_closure(start, files, dynamic:)
      pending = [start]
      seen = []
      until pending.empty?
        path = pending.shift
        next if seen.include?(path)

        file = files[path]
        unless file
          error("frontend bundle entry or import is not declared: #{path.inspect}")
          next
        end
        seen << path
        pending.concat(Array(file["imports"]))
        pending.concat(Array(file["dynamic_imports"])) if dynamic
      end
      seen
    end

    def resolve_bundle_file(relative)
      unless relative.is_a?(String) && BUNDLE_PATH_PREFIXES.any? { |prefix| relative.start_with?(prefix) } &&
          !relative.start_with?("/") && !relative.split("/").include?("..") && Pathname(relative).cleanpath.to_s == relative
        error("frontend bundle graph contains an unsafe path")
        return nil
      end
      candidate = manifest.root.join(relative).cleanpath
      unless candidate.to_s.start_with?("#{manifest.root}/") && candidate.file?
        error("frontend bundle graph path does not name a file: #{relative}")
        return nil
      end
      current = manifest.root
      Pathname(relative).each_filename do |component|
        current = current.join(component)
        if current.symlink?
          error("frontend bundle graph paths may not traverse symlinks")
          return nil
        end
      end
      if candidate.size > MAX_BUNDLE_FILE_BYTES
        error("frontend bundle file exceeds #{MAX_BUNDLE_FILE_BYTES} bytes: #{relative}")
        return nil
      end
      candidate
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

    def validate_retained_document
      rules = manifest.document["telemetry_scan"] || {}
      PerformanceRetainedEvidenceScan.structured_findings(document, rules: rules).each do |finding|
        error("performance evidence retains protected content: #{finding}")
      end
    end

    def validate_regressions(scenario, reviews:, evidence_sha256:, implementation_owner:)
      # Independence is established only by PerformanceCandidateSuite against
      # immutable owner/reviewer registries before `_authority_verified` is set.
      # The caller-supplied compatibility argument is deliberately not authority.
      implementation_owner
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
        unless review["_authority_verified"] == true
          error("critical regression review lacks immutable independent reviewer authority verification")
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
            canary_hits += canary_substring_hits(key.to_s)
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
          canary_hits += canary_substring_hits(value)
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

    def canary_substring_hits(value)
      text = value.to_s
      haystack = text.downcase
      PerformanceNormativeControls::TELEMETRY_CANARIES.sum do |canary|
        base64 = [canary].pack("m0")
        urlsafe = base64.tr("+/", "-_")
        percent_encoded = canary.bytes.map { |byte| format("%%%02X", byte) }.join
        forms = [
          canary,
          base64,
          base64.delete_suffix("="),
          urlsafe,
          urlsafe.delete_suffix("="),
          canary.unpack1("H*"),
          percent_encoded
        ].map(&:downcase).uniq
        encoded_hits = forms.count { |form| haystack.include?(form) }
        decoded_hits = decoded_text_forms(text).count { |decoded| decoded.downcase.include?(canary.downcase) }
        representations = PerformanceRetainedEvidenceScan.normalized_encoded_representations(text)
        normalized_form_hit = forms.any? do |form|
          PerformanceRetainedEvidenceScan.normalized_encoded_representations(form).each_with_index.any? do |needle, index|
            representations.fetch(index).include?(needle)
          end
        end
        normalized_hit = normalized_form_hit ? 1 : 0
        [encoded_hits + decoded_hits, normalized_hit].max
      end
    end

    def decoded_text_forms(value)
      decoded = []
      if value.match?(/%(?:[0-9a-fA-F]{2})/)
        decoded << value.gsub(/%([0-9a-fA-F]{2})/) { [$1.to_i(16)].pack("C") }
      end
      bounded = value.byteslice(0, 16_384)
      bounded.scan(/(?<![0-9a-fA-F])[0-9a-fA-F]{16,4096}(?![0-9a-fA-F])/) do |token|
        decoded << [token].pack("H*") if token.length.even?
      end
      bounded.scan(/(?<![A-Za-z0-9+\/_-])[A-Za-z0-9+\/_-]{8,4096}={0,2}(?![A-Za-z0-9+\/_=-])/) do |token|
        normalized = token.tr("-_", "+/")
        padded = normalized + ("=" * ((4 - normalized.length % 4) % 4))
        candidate = padded.unpack1("m0")
        canonical = [candidate].pack("m0").delete_suffix("=").delete_suffix("=")
        decoded << candidate if canonical == normalized.delete_suffix("=").delete_suffix("=")
      end
      decoded.map { |candidate| candidate.dup.force_encoding(Encoding::UTF_8).scrub }.uniq
    rescue ArgumentError
      decoded
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
    REVIEWER_AUTHORITY_PATH = "tests/performance/harness/performance-reviewer-authorities-v1.json"
    TRUSTED_GITHUB_REPOSITORY = "ScottTpirate/stead"
    TRUSTED_WORKFLOW_REF = "ScottTpirate/stead/.github/workflows/phase1-candidate.yml@refs/heads/main"
    VERSION_PROBES = {
      "go" => ["version", /\bgo1\.27\.0\b/],
      "node" => ["--version", /\Av26\.8\.1\z/],
      "postgresql" => ["--version", /\b18\.0\b/],
      "openfga" => ["version", /\b1\.10\.2\b/],
      "nats_server" => ["--version", /\b2\.12\.0\b/],
      "gitea" => ["--version", /\b1\.25\.0\b/]
    }.freeze
    ALLOWED_REFERENCE_PREFIXES = %w[
      artifacts/performance/ packages/test-fixtures/harness/performance/ tests/performance/datasets/ scripts/performance/
    ].freeze
    MAX_RETAINED_ARTIFACT_BYTES = 128 * 1024 * 1024
    MAX_RUNTIME_COMPONENT_BYTES = 512 * 1024 * 1024

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
      validate_git_context
      validate_ci_context
      validate_control_immutability
      validate_required_candidate_infrastructure
      validate_implementation_owner_authority
      validate_dataset_reference
      validate_runtime_components
      evidence_by_scenario, evidence_digests = validate_evidence
      artifacts = validate_benchmark_artifacts(evidence_by_scenario, evidence_digests)
      reviews = validate_regression_reviews
      validate_evidence_regressions(evidence_by_scenario, evidence_digests, reviews)
      validate_coverage(evidence_by_scenario, artifacts)
      validate_structured_retained_document(document, "candidate suite")
      @errors.uniq
    rescue StandardError => error
      [*@errors, "candidate suite validation failed closed: #{error.class}: #{error.message}"].uniq
    end

    private

    def validate_git_context
      revision = document.dig("source", "revision")
      resolved, status = git("rev-parse", "--verify", "#{revision}^{commit}")
      error("candidate source revision does not resolve to a Git commit in the checked-out repository") unless status.success? && resolved.strip == revision
      head, head_status = git("rev-parse", "HEAD")
      error("candidate source revision must equal the checked-out immutable HEAD") unless head_status.success? && head.strip == revision
      main, main_status = git("rev-parse", "--verify", "origin/main^{commit}")
      error("candidate source revision must equal the fetched immutable origin/main commit") unless main_status.success? && main.strip == revision
      _stdout, tracked_status = git("diff", "--quiet")
      _stdout, staged_status = git("diff", "--cached", "--quiet")
      error("candidate verification requires a clean tracked worktree and index") unless tracked_status.success? && staged_status.success?
    end

    def validate_ci_context
      context = document["ci_context"]
      return error("candidate suite requires a trusted CI context") unless context.is_a?(Hash)

      expected = {
        "provider" => "github_actions",
        "repository" => TRUSTED_GITHUB_REPOSITORY,
        "workflow_ref" => TRUSTED_WORKFLOW_REF,
        "event_name" => "workflow_dispatch",
        "run_id" => ENV["GITHUB_RUN_ID"],
        "run_attempt" => ENV["GITHUB_RUN_ATTEMPT"]&.to_i,
        "ref_protected" => true
      }
      expected.each do |field, value|
        error("candidate CI #{field} is not bound to the trusted release workflow") unless context[field] == value
      end
      error("candidate eligibility is available only inside GitHub Actions") unless ENV["CI"] == "true" && ENV["GITHUB_ACTIONS"] == "true"
      error("candidate CI repository environment is not trusted") unless ENV["GITHUB_REPOSITORY"] == TRUSTED_GITHUB_REPOSITORY
      error("candidate CI workflow environment is not the protected main workflow") unless ENV["GITHUB_WORKFLOW_REF"] == TRUSTED_WORKFLOW_REF
      error("candidate CI event must be an explicit workflow dispatch") unless ENV["GITHUB_EVENT_NAME"] == "workflow_dispatch"
      error("candidate CI ref must be protected") unless ENV["GITHUB_REF_PROTECTED"] == "true"
      error("candidate CI SHA differs from the candidate revision") unless ENV["GITHUB_SHA"] == document.dig("source", "revision")
      origin, origin_status = git("remote", "get-url", "origin")
      trusted_origins = ["https://github.com/#{TRUSTED_GITHUB_REPOSITORY}.git", "git@github.com:#{TRUSTED_GITHUB_REPOSITORY}.git"]
      error("candidate repository origin is not the trusted upstream") unless origin_status.success? && trusted_origins.include?(origin.strip)
    end

    def validate_control_immutability
      control_revision = document.dig("source", "controls_revision")
      _stdout, main_status = git("rev-parse", "--verify", "origin/main^{commit}")
      unless main_status.success?
        error("candidate verification requires the trusted origin/main control context")
        return
      end
      _stdout, controls_status = git("rev-parse", "--verify", "#{control_revision}^{commit}")
      unless controls_status.success?
        error("controls_revision does not resolve to an immutable Git commit")
        return
      end
      _stdout, main_ancestor = git("merge-base", "--is-ancestor", control_revision.to_s, "origin/main")
      _stdout, candidate_ancestor = git("merge-base", "--is-ancestor", control_revision.to_s, document.dig("source", "revision").to_s)
      error("controls_revision must be merged into origin/main and be an ancestor of the candidate") unless main_ancestor.success? && candidate_ancestor.success?
      _stdout, diff_status = git(
        "diff", "--quiet", control_revision.to_s, document.dig("source", "revision").to_s, "--",
        *PerformanceNormativeControls::CONTROLLED_PATHS
      )
      error("candidate modifies verifier-owned directive, scenario, or manifest controls after controls_revision") unless diff_status.success?
    end

    def validate_required_candidate_infrastructure
      revision = document.dig("source", "revision")
      [PerformanceNormativeControls::CANDIDATE_WORKFLOW_PATH, PerformanceNormativeControls::CANDIDATE_RUNNER_PATH].each do |relative_path|
        _stdout, status = git("cat-file", "-e", "#{revision}:#{relative_path}")
        error("candidate requires controlled tracked infrastructure #{relative_path}") unless status.success? && root.join(relative_path).file?
      end
      runner = root.join(PerformanceNormativeControls::CANDIDATE_RUNNER_PATH)
      error("candidate performance runner must be executable") if runner.file? && !runner.executable?
    end

    def validate_implementation_owner_authority
      controls_revision = document.dig("source", "controls_revision")
      candidate_revision = document.dig("source", "revision")
      approved_registry = authority_registry_at(controls_revision, "approved controls")
      current_registry = authority_registry_at(candidate_revision, "candidate")
      return unless approved_registry && current_registry

      identity = document.dig("source", "implementation_owner").to_s.strip.downcase
      commit_author, author_status = git("show", "-s", "--format=%ae", candidate_revision.to_s)
      error("candidate implementation owner must match the immutable candidate commit author") unless
        author_status.success? && commit_author.strip.downcase == identity
      approved_owners = approved_registry.fetch("implementation_owners", [])
      current_owners = current_registry.fetch("implementation_owners", [])
      %w[owner_id identity].each do |field|
        values = approved_owners.map { |entry| field == "identity" ? entry[field].to_s.strip.downcase : entry[field] }
        error("implementation owner registry #{field} values must be unique") unless values.uniq.length == values.length
      end
      owner = approved_owners.find { |entry| entry["identity"].to_s.strip.downcase == identity && entry["status"] == "active" }
      unless owner
        error("candidate implementation owner is not an active immutable repository-approved owner")
        return
      end
      error("candidate implementation-owner authority was removed or changed after controls approval") unless current_owners.include?(owner)
      @verified_implementation_owner_identity = owner["identity"].to_s.strip.downcase if current_owners.include?(owner)
    end

    def authority_registry_at(revision, label)
      registry_json, registry_status = git("show", "#{revision}:#{REVIEWER_AUTHORITY_PATH}")
      unless registry_status.success?
        error("reviewer authority registry is absent at the #{label} revision")
        return nil
      end
      registry = PerformanceStrictJSON.parse(registry_json)
      Tempfile.create(["stead-reviewer-authorities-", ".json"]) do |file|
        file.write(registry_json)
        file.flush
        _registry, schema_errors = schema_gate.validate(file.path, expected_type: "performance_reviewer_authority_registry")
        schema_errors.each { |schema_error| error("reviewer authority registry #{schema_error}") }
      end
      registry
    rescue JSON::ParserError
      error("reviewer authority registry at the #{label} revision is invalid JSON")
      nil
    end

    def validate_dataset_reference
      reference = document["dataset"]
      # The verifier-owned manifest defines the forbidden canary literals themselves;
      # its exact digest and semantic controls are validated below. It is an input
      # authority, not candidate-retained measurement evidence.
      path = resolve_reference(reference, scan: false)
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
      paths = components.filter_map { |component| component.is_a?(Hash) ? component.dig("artifact", "path") : nil }
      error("runtime components must use distinct byte-backed artifacts") unless paths.uniq.length == paths.length
      probe_paths = components.filter_map { |component| component.is_a?(Hash) ? component.dig("version_probe", "stdout", "path") : nil }
      error("runtime components must use distinct version-probe output artifacts") unless probe_paths.uniq.length == probe_paths.length
      error("runtime component set must exactly match the trusted manifest") unless names.sort == expected.keys.sort
      expected.each do |name, version|
        component = components.find { |candidate| candidate["name"] == name }
        error("runtime component #{name} version must be #{version}") unless component && component["version"] == version
        next unless component

        artifact_reference = component["artifact"]
        artifact_path = resolve_reference(artifact_reference, max_bytes: MAX_RUNTIME_COMPONENT_BYTES)
        verify_reference_digest(
          artifact_reference,
          artifact_path,
          "runtime component #{name}",
          max_bytes: MAX_RUNTIME_COMPONENT_BYTES
        ) if artifact_path
        probe = component["version_probe"]
        unless probe.is_a?(Hash)
          error("runtime component #{name} requires a byte-backed version probe")
          next
        end
        output_reference = probe["stdout"]
        output_path = resolve_reference(output_reference)
        verify_reference_digest(output_reference, output_path, "runtime component #{name} version output") if output_path
        expected_argument, expected_pattern = VERSION_PROBES.fetch(name)
        expected_argv = [artifact_reference["path"], expected_argument]
        error("runtime component #{name} version probe command is not verifier-owned") unless probe["argv"] == expected_argv
        if output_path
          if output_path.size > 4_096
            error("runtime component #{name} version output exceeds 4096 bytes")
          else
            output = PerformanceBoundedFile.read(output_path, max_bytes: 4_096).dup.force_encoding(Encoding::UTF_8).scrub.strip
            error("runtime component #{name} version output does not prove #{version}") unless output.match?(expected_pattern)
          end
        end
        if artifact_path && output_path
          begin
            stdout, stderr, status = Open3.capture3(artifact_path.to_s, expected_argument, chdir: root.to_s)
            executed_output = stdout + stderr
            error("runtime component #{name} version probe execution failed") unless status.success?
            error("runtime component #{name} stored version output was not produced by executing the digest-bound artifact") unless
              executed_output == PerformanceBoundedFile.read(output_path, max_bytes: 4_096) &&
                Digest::SHA256.hexdigest(executed_output) == output_reference["sha256"]
          rescue SystemCallError => exception
            error("runtime component #{name} version probe could not execute digest-bound artifact: #{exception.class}")
          end
        end
        invocation = {
          "name" => name,
          "version" => version,
          "source_revision" => document.dig("source", "revision"),
          "artifact_sha256" => artifact_reference["sha256"],
          "argv" => probe["argv"],
          "stdout_sha256" => output_reference["sha256"]
        }
        error("runtime component #{name} version-probe invocation digest mismatch") unless
          probe["invocation_sha256"] == PerformanceCanonicalJSON.digest(invocation)
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

    def validate_benchmark_artifacts(evidence_by_scenario, evidence_digests)
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
        scenario_id = artifact["scenario_id"]
        evidence = evidence_by_scenario[scenario_id]
        unless evidence
          error("benchmark artifact references an unknown or missing candidate scenario")
          next
        end
        error("benchmark artifact evidence digest does not match its scenario evidence") unless artifact["evidence_sha256"] == evidence_digests[scenario_id]
        error("benchmark artifact request traces digest does not match its scenario evidence") unless artifact["request_traces_sha256"] == evidence["request_traces_sha256"]
        tool = artifact.dig("producer", "tool")
        version = artifact.dig("producer", "version")
        error("benchmark artifact producer tool/version is not pinned by suite provenance") unless document.dig("source", "tool_versions", tool) == version
        error("benchmark artifact observations digest mismatch") unless artifact["observations_sha256"] == PerformanceCanonicalJSON.digest(artifact["observations"])
        validate_measurement_files(artifact, evidence)
        validate_kind_specific_observations(artifact, evidence)
        validate_causality(artifact, evidence)
        validate_runner_execution(artifact, evidence)
        artifact["_verified_file_sha256"] = reference["sha256"]
        artifacts << artifact
      end
      artifact_ids = artifacts.map { |artifact| artifact["artifact_id"] }
      error("benchmark artifact IDs must be unique") unless artifact_ids.uniq.length == artifact_ids.length
      artifact_keys = artifacts.map { |artifact| [artifact["scenario_id"], artifact["kind"]] }
      error("candidate requires at most one kind-specific artifact per scenario") unless artifact_keys.uniq.length == artifact_keys.length
      validate_runner_attestation_bindings(artifacts)
      artifacts
    end

    def validate_measurement_files(artifact, evidence)
      references = artifact["measurement_files"]
      return error("benchmark artifact measurement_files must be non-empty") unless references.is_a?(Array) && !references.empty?

      resolved = {}
      references.each do |reference|
        path = resolve_reference(reference)
        if path && verify_reference_digest(reference, path, "benchmark measurement file")
          resolved[reference["path"]] = path
        end
      end
      return unless artifact["kind"] == "frontend_bundle"

      graph = evidence.dig("sizes", "frontend_bundle_graph")
      unless graph.is_a?(Hash)
        error("frontend_bundle artifact requires the evidence byte graph")
        return
      end
      files = graph["files"]
      unless files.is_a?(Array)
        error("frontend_bundle evidence byte graph files must be an array")
        return
      end
      expected_references = files.map { |file| file.slice("path", "sha256") }
      error("frontend_bundle measurement files must exactly bind every eager, lazy, transitive, and shared graph file") unless
        references == expected_references

      files_by_path = files.to_h { |file| [file["path"], file] }
      eager_paths = candidate_bundle_closure(graph["eager_entry_path"], files_by_path, dynamic: false)
      lazy_paths = Array(graph["capability_entries"]).flat_map do |entry|
        candidate_bundle_closure(entry["path"], files_by_path, dynamic: true)
      end.uniq - eager_paths
      gzip_by_path = resolved.to_h do |relative, path|
        unless path.extname == ".js"
          error("frontend_bundle measurement files must be actual JavaScript chunks")
          next [relative, 0]
        end
        bytes = PerformanceBoundedFile.read(path, max_bytes: PerformanceEvidence::MAX_BUNDLE_FILE_BYTES)
        [relative, Zlib.gzip(bytes, level: Zlib::BEST_COMPRESSION).bytesize]
      end
      observations = observation_map(artifact)
      eager_observed = observations.dig("eager_javascript_gzip_bytes", "value")
      lazy_observed = observations.dig("lazy_javascript_gzip_bytes", "value")
      error("frontend_bundle eager observation does not match verifier-compressed transitive eager bytes") unless
        eager_observed == eager_paths.sum { |path| gzip_by_path[path].to_i }
      error("frontend_bundle lazy observation does not match verifier-compressed unique transitive lazy bytes") unless
        lazy_observed == lazy_paths.sum { |path| gzip_by_path[path].to_i }
    end

    def candidate_bundle_closure(start, files, dynamic:)
      pending = [start]
      seen = []
      until pending.empty?
        path = pending.shift
        next if seen.include?(path)

        file = files[path]
        unless file
          error("frontend_bundle graph references an undeclared JavaScript file")
          next
        end
        seen << path
        pending.concat(Array(file["imports"]))
        pending.concat(Array(file["dynamic_imports"])) if dynamic
      end
      seen
    end

    def validate_kind_specific_observations(artifact, evidence)
      required = PerformanceNormativeControls::REQUIRED_OBSERVATIONS[artifact["kind"]]
      unless required
        error("benchmark artifact kind has no verifier-owned observation contract")
        return
      end
      observations = observation_map(artifact)
      error("benchmark artifact observation metrics must be unique") unless observations.length == artifact.fetch("observations", []).length
      error("#{artifact['kind']} artifact must contain the exact kind-specific observation set") unless observations.keys.sort == required.keys.sort
      required.each do |metric, unit|
        error("#{artifact['kind']} observation #{metric} must use #{unit}") unless observations.dig(metric, "unit") == unit
      end

      expected_values = case artifact["kind"]
                        when "authorization_count"
                          {
                            "openfga_calls" => evidence.dig("counts", "openfga_calls"),
                            "policy_calls" => evidence.dig("counts", "policy_calls"),
                            "logical_audit_operations" => evidence.dig("counts", "logical_audit_operations")
                          }
                        when "browser_performance"
                          {
                            "lcp_ms" => evidence.dig("web_vitals", "lcp_ms"),
                            "inp_ms" => evidence.dig("web_vitals", "inp_ms"),
                            "cls" => evidence.dig("web_vitals", "cls")
                          }
                        when "frontend_bundle"
                          {
                            "eager_javascript_gzip_bytes" => evidence.dig("sizes", "eager_javascript_gzip_bytes"),
                            "lazy_javascript_gzip_bytes" => evidence.dig("sizes", "lazy_javascript_gzip_bytes"),
                            "lazy_javascript_chunk_count" => evidence.dig("sizes", "lazy_javascript_chunks")&.length
                          }
                        when "go_microbenchmark"
                          {
                            "nanoseconds_per_operation" => evidence.dig("go_microbenchmark", "nanoseconds_per_operation"),
                            "allocations_per_operation" => evidence.dig("go_microbenchmark", "allocations_per_operation"),
                            "bytes_per_operation" => evidence.dig("go_microbenchmark", "bytes_per_operation")
                          }
                        when "golden_slice_e2e"
                          {
                            "latency_p50_ms" => evidence.dig("timings_ms", "latency", "p50"),
                            "latency_p95_ms" => evidence.dig("timings_ms", "latency", "p95"),
                            "latency_p99_ms" => evidence.dig("timings_ms", "latency", "p99")
                          }
                        when "peek"
                          { "peek_p95_ms" => evidence.dig("timings_ms", "latency", "p95") }
                        when "projection_lag"
                          { "projection_lag_p95_ms" => evidence.dig("timings_ms", "projection_lag", "p95") }
                        when "provider_count"
                          { "provider_calls" => evidence.dig("counts", "provider_calls") }
                        when "query_count"
                          {
                            "sql_queries" => evidence.dig("counts", "sql_queries"),
                            "postgres_writes" => evidence.dig("counts", "postgres_writes")
                          }
                        when "runner_attestation"
                          {
                            "exit_code" => 0,
                            "measured_sample_count" => evidence.dig("raw_samples", "counts")&.length
                          }
                        else
                          {}
                        end
      expected_values.each do |metric, value|
        error("#{artifact['kind']} observation #{metric} does not match scenario evidence") unless observations.dig(metric, "value") == value
      end
      if artifact["kind"] == "go_microbenchmark"
        error("go microbenchmark nanoseconds_per_operation must be positive") unless observations.dig("nanoseconds_per_operation", "value").to_f.positive?
      end
    end

    def validate_causality(artifact, evidence)
      causality = artifact["causality"]
      if artifact["kind"] == "response_before_relay"
        unless causality.is_a?(Hash)
          error("response_before_relay artifact requires causality proof")
          return
        end
        events = causality["events"]
        expected_types = %w[postgres_write authoritative_commit response_sent relay_started]
        types = events.is_a?(Array) ? events.map { |event| event["type"] } : []
        times = events.is_a?(Array) ? events.map { |event| event["monotonic_ns"] } : []
        error("response-before-relay causality events must be outbox write, commit, response, relay") unless types == expected_types
        transaction_ids = events.is_a?(Array) ? events.map { |event| event["transaction_id_hash"] } : []
        outbox_event_ids = events.is_a?(Array) ? events.map { |event| event["outbox_event_id_hash"] } : []
        error("response-before-relay causality must bind one transaction and outbox event") unless
          transaction_ids.length == 4 && transaction_ids.uniq.length == 1 && outbox_event_ids.length == 4 && outbox_event_ids.uniq.length == 1
        if times.length == 4 && times.all? { |value| value.is_a?(Integer) }
          error("response-before-relay causality must prove outbox <= commit <= response < relay") unless
            times[0] <= times[1] && times[1] <= times[2] && times[2] < times[3]
          gap = times[3] - times[2]
          error("response-before-relay gap observation must be verifier-derived") unless observation_map(artifact).dig("response_to_relay_gap_ns", "value") == gap
        end
        trace = evidence.fetch("request_traces", []).find { |candidate| candidate["sample_index"] == causality["sample_index"] }
        error("response-before-relay causality must select a bound request trace sample") unless trace
        return unless trace

        error("response-before-relay trace identity must match scenario request trace") unless causality["trace_id_hash"] == trace["trace_id_hash"]
        trace_events = trace["events"] || []
        trace_causality = trace_events.select do |event|
          (event["type"] == "postgres_write" && event["write_role"] == "transactional_outbox") || expected_types.drop(1).include?(event["type"])
        end.map { |event| event.slice("type", "monotonic_ns", "transaction_id_hash", "outbox_event_id_hash") }
        error("response-before-relay proof must be extracted from the bound request trace") unless trace_causality == events
      elsif !causality.nil?
        error("only response_before_relay artifacts may carry causality proof")
      end
    end

    def validate_runner_execution(artifact, evidence)
      execution = artifact["runner_execution"]
      if artifact["kind"] != "runner_attestation"
        error("only runner_attestation artifacts may carry runner_execution") unless execution.nil?
        return
      end
      unless execution.is_a?(Hash)
        error("runner_attestation requires byte-backed runner execution evidence")
        return
      end
      resolved = {}
      %w[binary stdout stderr].each do |field|
        reference = execution[field]
        path = resolve_reference(reference)
        verify_reference_digest(reference, path, "runner execution #{field}") if path
        resolved[field] = path
      end
      outputs = execution["outputs"]
      output_references = outputs.is_a?(Array) ? outputs.map { |output| output.slice("path", "sha256") } : []
      output_payload_references = []
      unless outputs.is_a?(Array) && !outputs.empty?
        error("runner execution requires kind-labelled raw output files")
      else
        output_paths = outputs.filter_map { |output| output.is_a?(Hash) ? output["path"] : nil }
        error("runner execution output paths must be unique") unless output_paths.uniq.length == output_paths.length
        outputs.each do |output|
          path = resolve_reference(output)
          verify_reference_digest(output, path, "runner execution #{output['kind']} output") if path
          next unless path

          record, schema_errors = schema_gate.validate(path, expected_type: "performance_runner_output")
          schema_errors.each { |schema_error| error("#{output['path']}: #{schema_error}") }
          next unless record.is_a?(Hash)

          validate_runner_output_record(output, record, artifact, evidence, resolved["binary"], path)
          output["_verified_record"] = record
          output_payload_references.concat(record.fetch("payload_files", []))
        end
      end
      environment_probe = execution["environment_probe"]
      environment_probe_reference = environment_probe.is_a?(Hash) ? environment_probe["stdout"] : nil
      environment_probe_path = resolve_reference(environment_probe_reference)
      verify_reference_digest(environment_probe_reference, environment_probe_path, "runner environment probe") if environment_probe_path
      execution_references = %w[binary stdout stderr].map { |field| execution[field] } +
        [environment_probe_reference] + output_references + output_payload_references
      error("runner attestation measurement files must exactly bind binary, stdout evidence, stderr, environment, output records, and payload bytes") unless
        artifact["measurement_files"] == execution_references
      binary_path = execution.dig("binary", "path").to_s
      unless binary_path == PerformanceNormativeControls::CANDIDATE_RUNNER_PATH
        error("runner execution binary must be the verifier-owned Phase 1 candidate runner")
      else
        tracked_bytes, tracked_status = git("show", "#{artifact['source_revision']}:#{binary_path}")
        if tracked_status.success?
          error("runner execution binary bytes differ from candidate Git object") unless Digest::SHA256.hexdigest(tracked_bytes) == execution.dig("binary", "sha256")
        else
          error("runner execution binary is not tracked by the candidate Git commit")
        end
      end
      expected_argv = [binary_path, "--scenario", artifact["scenario_id"], "--manifest", TrustedPerformanceManifest::MANIFEST_PATH, "--emit-evidence"]
      error("runner execution argv must equal the verifier-owned scenario invocation") unless execution["argv"] == expected_argv
      error("runner execution command must be the exact verifier-owned argv") unless execution["command"] == expected_argv.join(" ")
      error("runner execution command must match measurement provenance") unless execution["command"] == evidence.dig("provenance", "command")
      error("runner artifact producer command must match the executed measurement command") unless artifact.dig("producer", "command") == execution["command"]
      error("runner stdout must be the exact scenario evidence bytes") unless execution.dig("stdout", "sha256") == artifact["evidence_sha256"]
      if resolved["binary"] && execution["argv"] == expected_argv
        begin
          replay_stdout, replay_stderr, replay_status = Open3.capture3(
            resolved["binary"].to_s, *expected_argv.drop(1), chdir: root.to_s
          )
          error("verifier replay of scenario runner failed") unless replay_status.success?
          error("runner stdout evidence was not reproduced by verifier execution") unless
            resolved["stdout"] && replay_stdout == PerformanceBoundedFile.read(resolved["stdout"], max_bytes: MAX_RETAINED_ARTIFACT_BYTES)
          error("runner stderr evidence was not reproduced by verifier execution") unless
            resolved["stderr"] && replay_stderr == PerformanceBoundedFile.read(resolved["stderr"], max_bytes: MAX_RETAINED_ARTIFACT_BYTES)
        rescue SystemCallError => exception
          error("scenario runner could not be replayed by the verifier: #{exception.class}")
        end
      end
      begin
        started = Time.iso8601(execution["started_at"].to_s)
        ended_at = Time.iso8601(execution["ended_at"].to_s)
        error("runner execution ended_at must follow started_at") unless ended_at >= started
        error("runner execution timestamps must match measurement provenance") unless
          execution["started_at"] == evidence.dig("provenance", "started_at") && execution["ended_at"] == evidence.dig("provenance", "ended_at")
      rescue ArgumentError
        error("runner execution timestamps must be RFC3339")
      end
      environment = manifest.benchmark_environment(artifact["scenario_id"])
      error("runner execution environment digest does not match trusted reference") unless execution["environment_sha256"] == PerformanceCanonicalJSON.digest(environment)
      validate_environment_probe(environment_probe, environment_probe_path, resolved["binary"], binary_path, artifact)
      invocation = {
        "binary_sha256" => execution.dig("binary", "sha256"),
        "argv" => execution["argv"],
        "source_revision" => artifact["source_revision"],
        "dataset_sha256" => artifact["dataset_sha256"],
        "scenario_id" => artifact["scenario_id"],
        "environment_sha256" => execution["environment_sha256"]
      }
      error("runner execution invocation digest mismatch") unless execution["invocation_sha256"] == PerformanceCanonicalJSON.digest(invocation)
    end

    def validate_runner_output_record(output, record, artifact, evidence, runner_path, record_path)
      error("runner output kind differs from its execution label") unless record["kind"] == output["kind"]
      error("runner output source revision differs from its attestation") unless record["source_revision"] == artifact["source_revision"]
      error("runner output dataset differs from its attestation") unless record["dataset_sha256"] == artifact["dataset_sha256"]
      error("runner output scenario differs from its attestation") unless record["scenario_id"] == artifact["scenario_id"]
      error("runner output evidence digest differs from its attestation") unless record["evidence_sha256"] == artifact["evidence_sha256"]
      error("runner output request traces differ from scenario evidence") unless record["request_traces_sha256"] == evidence["request_traces_sha256"]
      error("runner output observations digest mismatch") unless record["observations_sha256"] == PerformanceCanonicalJSON.digest(record["observations"])
      record.fetch("payload_files", []).each do |reference|
        path = resolve_reference(reference)
        verify_reference_digest(reference, path, "runner output #{output['kind']} payload") if path
      end
      return unless runner_path

      argv = [
        runner_path.to_s, "--verify-output", output["path"], "--scenario", artifact["scenario_id"],
        "--manifest", TrustedPerformanceManifest::MANIFEST_PATH
      ]
      begin
        stdout, stderr, status = Open3.capture3(*argv, chdir: root.to_s)
        error("verifier replay rejected #{output['kind']} runner output") unless status.success? && stderr.empty?
        error("#{output['kind']} runner output record was not reproduced by verifier execution") unless
          stdout == PerformanceBoundedFile.read(record_path, max_bytes: MAX_RETAINED_ARTIFACT_BYTES)
      rescue SystemCallError => exception
        error("#{output['kind']} runner output could not be replayed by the verifier: #{exception.class}")
      end
    end

    def validate_environment_probe(probe, output_path, runner_path, binary_path, artifact)
      unless probe.is_a?(Hash)
        error("runner attestation requires a verifier-replayed environment probe")
        return
      end
      expected_argv = [binary_path, "--scenario", artifact["scenario_id"], "--manifest", TrustedPerformanceManifest::MANIFEST_PATH, "--probe-environment"]
      error("runner environment probe argv must be verifier-owned") unless probe["argv"] == expected_argv
      expected_invocation = {
        "binary_sha256" => artifact.dig("runner_execution", "binary", "sha256"),
        "argv" => expected_argv,
        "source_revision" => artifact["source_revision"],
        "environment_sha256" => artifact.dig("runner_execution", "environment_sha256")
      }
      error("runner environment probe invocation digest mismatch") unless probe["invocation_sha256"] == PerformanceCanonicalJSON.digest(expected_invocation)
      return unless output_path

      begin
        observed = PerformanceStrictJSON.parse_file(output_path)
        expected = manifest.benchmark_environment(artifact["scenario_id"])
        error("runner environment observation does not exactly match trusted CPU, network, topology, corpus, cache, and load controls") unless observed == expected
      rescue JSON::ParserError
        error("runner environment observation must be strict JSON")
      end
      return unless runner_path && probe["argv"] == expected_argv

      begin
        stdout, stderr, status = Open3.capture3(runner_path.to_s, *expected_argv.drop(1), chdir: root.to_s)
        error("verifier replay of runner environment probe failed") unless status.success? && stderr.empty?
        error("stored runner environment observation was not produced by verifier execution") unless
          stdout == PerformanceBoundedFile.read(output_path, max_bytes: MAX_RETAINED_ARTIFACT_BYTES)
      rescue SystemCallError => exception
        error("runner environment probe could not be replayed by the verifier: #{exception.class}")
      end
    end

    def validate_runner_attestation_bindings(artifacts)
      manifest.scenario_ids.each do |scenario_id|
        runners = artifacts.select { |artifact| artifact["scenario_id"] == scenario_id && artifact["kind"] == "runner_attestation" }
        unless runners.length == 1
          error("scenario #{scenario_id} requires exactly one runner_attestation artifact")
          next
        end
        runner_sha = runners.first["_verified_file_sha256"]
        runner_outputs = runners.first.dig("runner_execution", "outputs") || []
        required_kinds = PerformanceNormativeControls::SCENARIOS.fetch(scenario_id)["required_artifact_kinds"] - ["runner_attestation"]
        actual_output_kinds = runner_outputs.filter_map { |output| output["kind"] }.uniq
        error("scenario #{scenario_id} runner outputs must exactly cover required kind-specific evidence") unless
          actual_output_kinds.sort == required_kinds.sort
        artifacts.select { |artifact| artifact["scenario_id"] == scenario_id }.each do |artifact|
          if artifact["kind"] == "runner_attestation"
            error("runner_attestation may not self-assert its own digest") unless artifact["runner_attestation_sha256"].nil?
          else
            error("#{artifact['kind']} artifact is not bound to its scenario runner attestation") unless artifact["runner_attestation_sha256"] == runner_sha
            matching_outputs = runner_outputs.select { |output| output["kind"] == artifact["kind"] }
            expected_files = matching_outputs.flat_map { |output| output.dig("_verified_record", "payload_files") || [] }
            error("#{artifact['kind']} artifact measurement files are not the exact runner-attested raw outputs") unless artifact["measurement_files"] == expected_files
            record = matching_outputs.first&.dig("_verified_record")
            error("#{artifact['kind']} artifact observations do not match the strict runner output record") unless
              record && artifact["observations"] == record["observations"] && artifact["observations_sha256"] == record["observations_sha256"]
          end
        end
      end
    end

    def observation_map(artifact)
      artifact.fetch("observations", []).to_h { |observation| [observation["metric"], observation] }
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
          validate_reviewer_authority(review)
        end
        review if review.is_a?(Hash)
      end
      review_ids = reviews.map { |review| review["review_id"] }
      error("regression review IDs must be unique") unless review_ids.uniq.length == review_ids.length
      reviews
    end

    def validate_reviewer_authority(review)
      errors_before = @errors.length
      revision = review["authority_revision"]
      unless revision == document.dig("source", "controls_revision")
        error("reviewer authority revision must equal the suite's immutable controls revision")
        return
      end
      _stdout, main_ancestor = git("merge-base", "--is-ancestor", revision.to_s, "origin/main")
      _stdout, candidate_ancestor = git("merge-base", "--is-ancestor", revision.to_s, document.dig("source", "revision").to_s)
      unless main_ancestor.success? && candidate_ancestor.success?
        error("reviewer authority revision must be independently merged into origin/main before the candidate")
        return
      end

      registry = authority_registry_at(revision, "approved authority")
      current_registry = authority_registry_at(document.dig("source", "revision"), "candidate")
      return unless registry && current_registry

      authorities = registry.fetch("authorities", [])
      %w[authority_id identity public_key_pem].each do |field|
        values = authorities.map { |entry| field == "identity" ? entry[field].to_s.strip.downcase : entry[field] }
        if values.uniq.length != values.length
          error("reviewer authority registry #{field} values must be unique")
          return
        end
      end
      authority = authorities.find { |candidate| candidate["authority_id"] == review["authority_id"] }
      unless authority && authority["status"] == "active"
        error("regression reviewer is not an active immutable repository-approved authority")
        return
      end
      error("regression reviewer authority was removed or changed after controls approval") unless
        current_registry.fetch("authorities", []).include?(authority)
      error("regression reviewer identity differs from approved authority") unless
        review.dig("reviewer", "identity").to_s.strip.downcase == authority["identity"].to_s.strip.downcase
      error("regression reviewer role differs from approved authority") unless review.dig("reviewer", "role") == authority["role"]
      if @verified_implementation_owner_identity.nil?
        error("review independence requires a verified immutable implementation owner")
      elsif authority["identity"].to_s.strip.downcase == @verified_implementation_owner_identity
        error("repository-approved reviewer authority is not independent of implementation owner")
      end

      signature = review["signature_base64"].to_s.unpack1("m0")
      unless [signature].pack("m0") == review["signature_base64"]
        error("regression review signature must use canonical Base64")
        return
      end
      signed_document = review.reject { |key, _value| key == "signature_base64" }
      public_key = OpenSSL::PKey.read(authority["public_key_pem"])
      unless public_key.verify(nil, signature, PerformanceCanonicalJSON.generate(signed_document))
        error("regression review Ed25519 signature verification failed")
      end
      review["_authority_verified"] = true if @errors.length == errors_before
    rescue JSON::ParserError, OpenSSL::PKey::PKeyError, ArgumentError => exception
      error("regression reviewer authority verification failed closed: #{exception.class}")
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

        covered = artifacts.select { |artifact| artifact["scenario_id"] == scenario["id"] }.map { |artifact| artifact["kind"] }
        missing = scenario.fetch("required_artifact_kinds", []) - covered
        error("scenario #{scenario['id']} missing benchmark artifact coverage: #{missing.join(', ')}") unless missing.empty?
      end
    end

    def resolve_reference(reference, max_bytes: MAX_RETAINED_ARTIFACT_BYTES, scan: true)
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
      if candidate.size > max_bytes
        error("candidate artifact exceeds #{max_bytes} byte ceiling: #{relative}")
        return nil
      end
      scan_retained_reference(candidate, relative, max_bytes) if scan
      candidate
    end

    def scan_retained_reference(path, relative, max_bytes)
      @retained_scan_cache ||= {}
      return if @retained_scan_cache.key?(path.to_s)

      rules = manifest.document["telemetry_scan"] || {}
      findings = PerformanceRetainedEvidenceScan.raw_file_findings(path, rules: rules, max_bytes: max_bytes)
      if path.extname.downcase == ".json"
        begin
          parsed = PerformanceStrictJSON.parse_file(path)
          findings.concat(PerformanceRetainedEvidenceScan.structured_findings(parsed, rules: rules))
        rescue JSON::ParserError => exception
          findings << "strict JSON preflight failed: #{exception.message}"
        end
      end
      findings.uniq.each { |finding| error("#{relative}: #{finding}") }
      @retained_scan_cache[path.to_s] = true
    end

    def validate_structured_retained_document(value, label)
      rules = manifest.document["telemetry_scan"] || {}
      PerformanceRetainedEvidenceScan.structured_findings(value, rules: rules).each do |finding|
        error("#{label} retains protected content: #{finding}")
      end
    end

    def verify_reference_digest(reference, path, label, max_bytes: MAX_RETAINED_ARTIFACT_BYTES)
      actual = PerformanceCanonicalJSON.file_digest(path, max_bytes: max_bytes)
      return true if reference["sha256"] == actual

      error("#{label} digest mismatch for #{reference['path']}")
      false
    end

    def git(*arguments)
      stdout, _stderr, status = Open3.capture3("git", *arguments, chdir: root.to_s)
      [stdout, status]
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
      @manifest_errors ||= begin
        _document, schema_errors = schema_gate.validate(manifest.path, expected_type: "dataset_manifest")
        baseline_path = root.join(TrustedPerformanceManifest::FRONTEND_BASELINE_PATH)
        _baseline, baseline_schema_errors = schema_gate.validate(baseline_path, expected_type: "frontend_bundle_baseline")
        authority_path = root.join(PerformanceCandidateSuite::REVIEWER_AUTHORITY_PATH)
        registry, authority_schema_errors = schema_gate.validate(authority_path, expected_type: "performance_reviewer_authority_registry")
        registry_semantic_errors = validate_reviewer_registry(registry)
        (schema_errors + baseline_schema_errors + authority_schema_errors + registry_semantic_errors + manifest.validate + validate_frontend_baseline).freeze
      end
    end

    def validate_frontend_baseline
      errors = []
      baseline = manifest.frontend_baseline
      errors << "frontend baseline dataset manifest ID mismatch" unless baseline["dataset_manifest_id"] == manifest.document["manifest_id"]
      errors << "frontend baseline dataset digest mismatch" unless baseline["dataset_sha256"] == manifest.digest
      errors << "frontend baseline command is not the approved deterministic measurement" unless baseline["measured_command"] == "npm run build && npm run validate:web-bundle"
      measured_total = baseline.fetch("measured_files", []).sum { |file| file["gzip_bytes"].to_i }
      errors << "frontend baseline measured files do not sum to eager bytes" unless measured_total == baseline["eager_javascript_bytes_gzip"]
      cold_baseline = manifest.scenario("cold-initial-application").fetch("baselines", []).find do |entry|
        entry["metric"] == "sizes.eager_javascript_gzip_bytes"
      end
      unless cold_baseline &&
          cold_baseline["baseline_id"] == baseline["baseline_id"] &&
          cold_baseline["value"] == baseline["eager_javascript_bytes_gzip"] &&
          cold_baseline["source_revision"] == baseline["source_revision"] &&
          cold_baseline["benchmark_profile"] == manifest.document["benchmark_profile"] &&
          cold_baseline["disclosure_mode"] == manifest.document["disclosure_mode"] &&
          cold_baseline["environment_sha256"] == manifest.environment_digest("cold-initial-application") &&
          cold_baseline["reference_artifact_sha256"] == PerformanceCanonicalJSON.digest(baseline["measured_files"])
        errors << "frontend manifest baseline identity/value/source is not bound to the trusted bundle record"
      end
      _stdout, _stderr, commit_status = Open3.capture3("git", "cat-file", "-e", "#{baseline['source_revision']}^{commit}", chdir: root.to_s)
      errors << "frontend baseline source revision is not a Git commit" unless commit_status.success?
      return errors unless commit_status.success?

      source_revision = baseline["source_revision"]
      web_tree, _stderr, web_tree_status = Open3.capture3("git", "rev-parse", "#{source_revision}:apps/web", chdir: root.to_s)
      errors << "frontend baseline web source tree mismatch" unless web_tree_status.success? && web_tree.strip == baseline["source_web_tree_oid"]
      source_lock, _stderr, lock_status = Open3.capture3("git", "show", "#{source_revision}:package-lock.json", chdir: root.to_s)
      errors << "frontend baseline package lock is unavailable" unless lock_status.success?
      errors << "frontend baseline package lock digest mismatch" unless lock_status.success? && Digest::SHA256.hexdigest(source_lock) == baseline["package_lock_sha256"]
      %w[build_runner measurement_tool].each do |field|
        reference = baseline[field]
        source_bytes, _stderr, source_status = Open3.capture3("git", "show", "#{source_revision}:#{reference['path']}", chdir: root.to_s)
        errors << "frontend baseline #{field} is unavailable at source revision" unless source_status.success?
        errors << "frontend baseline #{field} digest mismatch" unless source_status.success? && Digest::SHA256.hexdigest(source_bytes) == reference["sha256"]
      end
      errors.concat(rebuild_frontend_baseline(baseline, source_lock)) if errors.empty?
      errors
    end

    def validate_reviewer_registry(registry)
      return ["reviewer authority registry must be an object"] unless registry.is_a?(Hash)

      authorities = registry.fetch("authorities", [])
      errors = []
      %w[authority_id identity public_key_pem].each do |field|
        values = authorities.map { |entry| field == "identity" ? entry[field].to_s.strip.downcase : entry[field] }
        errors << "reviewer authority registry #{field} values must be unique" unless values.uniq.length == values.length
      end
      errors
    end

    def rebuild_frontend_baseline(baseline, source_lock)
      errors = []
      Dir.mktmpdir("stead-frontend-baseline-") do |directory|
        archive_path = Pathname(directory).join("source.tar")
        archive, stderr, archive_status = Open3.capture3("git", "archive", "--format=tar", baseline["source_revision"], chdir: root.to_s)
        return ["frontend baseline source archive failed: #{stderr.lines.first.to_s.strip}"] unless archive_status.success?

        archive_path.binwrite(archive)
        _stdout, extract_stderr, extract_status = Open3.capture3("tar", "-xf", archive_path.to_s, "-C", directory)
        return ["frontend baseline source extraction failed: #{extract_stderr.lines.first.to_s.strip}"] unless extract_status.success?

        source_root = Pathname(directory)
        current_lock = root.join("package-lock.json")
        if current_lock.file? &&
            Digest::SHA256.file(current_lock).hexdigest == Digest::SHA256.hexdigest(source_lock) &&
            root.join("node_modules").directory? && root.join("apps/web/node_modules").directory?
          FileUtils.ln_s(root.join("node_modules"), source_root.join("node_modules"))
          FileUtils.ln_s(root.join("apps/web/node_modules"), source_root.join("apps/web/node_modules"))
        else
          _stdout, install_stderr, install_status = Open3.capture3(
            source_root.join("scripts/run_pinned_node.sh").to_s,
            "npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund",
            chdir: source_root.to_s
          )
          return ["frontend baseline dependency install failed: #{install_stderr.lines.first.to_s.strip}"] unless install_status.success?
        end

        _stdout, build_stderr, build_status = Open3.capture3(
          source_root.join("scripts/run_pinned_node.sh").to_s,
          "npm", "run", "build", "--workspace=@stead/web",
          chdir: source_root.to_s
        )
        return ["frontend baseline deterministic build failed: #{build_stderr.lines.first.to_s.strip}"] unless build_status.success?

        measured_json, measure_stderr, measure_status = Open3.capture3(
          source_root.join("scripts/run_pinned_node.sh").to_s,
          "node", source_root.join(baseline.dig("measurement_tool", "path")).to_s,
          chdir: source_root.to_s
        )
        return ["frontend baseline measurement failed: #{measure_stderr.lines.first.to_s.strip}"] unless measure_status.success?

        measured = PerformanceStrictJSON.parse(measured_json)
        errors << "frontend baseline budget differs from deterministic tool output" unless measured["budget_bytes_gzip"] == baseline["budget_bytes_gzip"]
        errors << "frontend baseline eager bytes differ from rebuilt bundle" unless measured["eager_javascript_bytes_gzip"] == baseline["eager_javascript_bytes_gzip"]
        measured_by_name = measured.fetch("measured_files", []).to_h { |entry| [entry["file"], entry] }
        errors << "frontend baseline measured file set differs from rebuilt bundle" unless measured_by_name.keys.sort == baseline.fetch("measured_files", []).map { |entry| entry["file"] }.sort
        baseline.fetch("measured_files", []).each do |entry|
          bytes_path = source_root.join("apps/web/dist", entry["file"])
          unless bytes_path.file?
            errors << "frontend baseline rebuilt bundle file is missing: #{entry['file']}"
            next
          end
          bytes = PerformanceBoundedFile.read(bytes_path, max_bytes: PerformanceEvidence::MAX_BUNDLE_FILE_BYTES)
          errors << "frontend baseline bundle byte digest mismatch for #{entry['file']}" unless Digest::SHA256.hexdigest(bytes) == entry["file_sha256"]
          errors << "frontend baseline uncompressed byte count mismatch for #{entry['file']}" unless bytes.bytesize == entry["uncompressed_bytes"]
          errors << "frontend baseline gzip byte count mismatch for #{entry['file']}" unless measured_by_name.dig(entry["file"], "gzip_bytes") == entry["gzip_bytes"]
        end
      end
      errors
    rescue JSON::ParserError, SystemCallError, PerformanceBoundedFile::TooLarge => error
      ["frontend baseline rebuild failed closed: #{error.class}: #{error.message}"]
    end
  end
end
