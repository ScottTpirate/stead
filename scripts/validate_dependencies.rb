#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "set"
require "time"
require "uri"
require "yaml"

ROOT = File.expand_path("..", __dir__)
REGISTRY_PATH = File.join(ROOT, "docs/governance/dependency-approvals.yaml")
SCHEMA_PATH = File.join(ROOT, "docs/governance/dependency-approvals.schema.json")
PROVENANCE_PATH = File.join(ROOT, "docs/governance/devlane-provenance.yaml")
NOTICES_PATH = File.join(ROOT, "THIRD_PARTY_NOTICES.md")
LOCK_PATH = File.join(ROOT, "package-lock.json")

REQUIRED_PINS = {
  "devlane-source" => ["7719dcadf91f881b5aefe8b74012ffcfbba0bc17", "7719dcadf91f881b5aefe8b74012ffcfbba0bc17"],
  "actions/checkout" => ["v7.0.1", "3d3c42e5aac5ba805825da76410c181273ba90b1"],
  "node-v26.8.1-linux-x64.tar.xz" => ["26.8.1", "3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d"],
  "go1.27.0.linux-amd64.tar.gz" => ["1.27.0", "675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685"]
}.freeze

DISALLOWED_NPM_LICENSE = /(?:^|\b)(?:AGPL|GPL|LGPL|SSPL|BUSL|BSL|Proprietary|UNLICENSED|NOASSERTION|Commons Clause)(?:\b|$)/i
DEFAULT_PERMISSIVE_NPM_LICENSES = Set.new(%w[0BSD Apache-2.0 BSD-2-Clause BSD-3-Clause ISC MIT]).freeze
PROHIBITED_DIRECT_PACKAGES = Set.new(["@asyncapi/cli", "ajv-cli"]).freeze
PROHIBITED_SETUP_ACTIONS = Set.new(["actions/setup-node", "actions/setup-go", "ruby/setup-ruby"]).freeze
FOUNDATION_ROLLBACK_TARGET = "git:e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31"

def allowed_lock_license?(license)
  license.is_a?(String) && DEFAULT_PERMISSIVE_NPM_LICENSES.include?(license)
end

if ARGV.first == "--test-lock-license"
  candidate = ARGV[1]
  abort "missing license fixture" if candidate.nil?

  exit(allowed_lock_license?(candidate) ? 0 : 1)
end

if ARGV.first == "--test-rollback"
  candidate = ARGV[1]
  abort "missing rollback fixture" if candidate.nil?

  exit(candidate == FOUNDATION_ROLLBACK_TARGET ? 0 : 1)
end

def load_yaml(path)
  YAML.safe_load_file(path, permitted_classes: [], permitted_symbols: [], aliases: false)
rescue Psych::Exception => e
  abort "#{path.delete_prefix(ROOT + "/")}: YAML error: #{e.message}"
end

def resolve_ref(root_schema, reference)
  raise "unsupported schema reference #{reference}" unless reference.start_with?("#/")

  reference.delete_prefix("#/").split("/").reduce(root_schema) do |cursor, token|
    cursor.fetch(token.gsub("~1", "/").gsub("~0", "~"))
  end
end

def schema_errors(value, schema, root_schema, path = "$")
  schema = resolve_ref(root_schema, schema.fetch("$ref")) if schema.key?("$ref")
  errors = []

  if schema.key?("oneOf")
    branches = schema.fetch("oneOf").map { |candidate| schema_errors(value, candidate, root_schema, path) }
    return ["#{path}: must match exactly one schema alternative"] unless branches.count(&:empty?) == 1

    return []
  end

  errors << "#{path}: expected #{schema["const"].inspect}, got #{value.inspect}" if schema.key?("const") && value != schema["const"]
  errors << "#{path}: value #{value.inspect} is outside enum" if schema.key?("enum") && !schema["enum"].include?(value)

  type_matches = case schema["type"]
                 when nil then true
                 when "object" then value.is_a?(Hash)
                 when "array" then value.is_a?(Array)
                 when "string" then value.is_a?(String)
                 when "null" then value.nil?
                 else false
                 end
  unless type_matches
    errors << "#{path}: expected #{schema["type"]}, got #{value.class}"
    return errors
  end

  if value.is_a?(Hash)
    Array(schema["required"]).each do |key|
      errors << "#{path}: missing required property #{key}" unless value.key?(key)
    end
    properties = schema.fetch("properties", {})
    if schema["additionalProperties"] == false
      (value.keys - properties.keys).each { |key| errors << "#{path}: unknown property #{key}" }
    end
    value.each do |key, child|
      next unless properties.key?(key)

      errors.concat(schema_errors(child, properties.fetch(key), root_schema, "#{path}.#{key}"))
    end
  elsif value.is_a?(Array)
    errors << "#{path}: requires at least #{schema["minItems"]} items" if schema["minItems"] && value.length < schema["minItems"]
    if schema["uniqueItems"]
      normalized = value.map { |item| JSON.generate(item) }
      errors << "#{path}: array items must be unique" unless normalized.uniq.length == normalized.length
    end
    value.each_with_index do |child, index|
      errors.concat(schema_errors(child, schema.fetch("items"), root_schema, "#{path}[#{index}]")) if schema["items"]
    end
  elsif value.is_a?(String)
    errors << "#{path}: string is too short" if schema["minLength"] && value.length < schema["minLength"]
    errors << "#{path}: does not match #{schema["pattern"]}" if schema["pattern"] && !Regexp.new(schema["pattern"]).match?(value)
    case schema["format"]
    when "uri"
      begin
        uri = URI.parse(value)
        errors << "#{path}: URI must use https and include a host" unless uri.is_a?(URI::HTTPS) && uri.host
      rescue URI::InvalidURIError
        errors << "#{path}: invalid URI"
      end
    when "date-time"
      begin
        Time.iso8601(value)
      rescue ArgumentError
        errors << "#{path}: invalid RFC3339 date-time"
      end
    end
  end

  errors
end

def direct_npm_dependencies(lockfile, errors)
  manifests = [["", JSON.parse(File.read(File.join(ROOT, "package.json")))]]
  Array(manifests.first.last["workspaces"]).each do |workspace|
    if workspace.include?("*")
      errors << "package.json: workspace globs are not allowed in the locked foundation"
      next
    end
    path = File.join(ROOT, workspace, "package.json")
    errors << "package.json: missing workspace manifest #{workspace}/package.json" and next unless File.file?(path)

    manifests << [workspace, JSON.parse(File.read(path))]
  end

  dependencies = []
  manifests.each do |workspace, manifest|
    %w[dependencies devDependencies optionalDependencies].each do |group|
      manifest.fetch(group, {}).each do |name, version|
        if PROHIBITED_DIRECT_PACKAGES.include?(name)
          errors << "#{workspace.empty? ? "package.json" : "#{workspace}/package.json"}: prohibited direct package #{name}"
        end
        unless version.match?(/\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\z/)
          errors << "#{workspace.empty? ? "package.json" : "#{workspace}/package.json"}: #{name} must use an exact version, got #{version.inspect}"
        end

        lock_manifest = lockfile.fetch("packages", {}).fetch(workspace, {})
        locked_spec = lock_manifest.fetch(group, {})[name]
        errors << "package-lock.json: #{workspace}:#{group}:#{name} does not match manifest version #{version}" unless locked_spec == version

        candidate_paths = []
        candidate_paths << "#{workspace}/node_modules/#{name}" unless workspace.empty?
        candidate_paths << "node_modules/#{name}"
        lock_path = candidate_paths.find { |candidate| lockfile.fetch("packages", {}).key?(candidate) }
        if lock_path.nil?
          errors << "package-lock.json: no installed package record for #{workspace}:#{name}"
          next
        end
        dependencies << { "workspace" => workspace, "name" => name, "version" => version, "lock" => lockfile["packages"][lock_path] }
      end
    end
  end
  dependencies
rescue JSON::ParserError => e
  errors << "npm manifest/lock JSON error: #{e.message}"
  []
end

registry = load_yaml(REGISTRY_PATH)
schema = JSON.parse(File.read(SCHEMA_PATH))
errors = schema_errors(registry, schema, schema)
records = registry.fetch("records", [])

ids = records.map { |record| record["approval_id"] }
errors << "dependency registry: approval_id values must be unique" unless ids.uniq.length == ids.length

components = records.to_h { |record| [record.dig("component", "name"), record] }
errors << "dependency registry: component names must be unique" unless components.length == records.length

records.each do |record|
  name = record.dig("component", "name")
  digest = record.dig("component", "digest", "value")
  algorithm = record.dig("component", "digest", "algorithm")
  status = record.dig("decision", "status")
  approvers = Array(record.dig("decision", "approvers"))
  approved_at = record.dig("decision", "approved_at")
  rollback_version = record.dig("change", "rollback_version")

  case algorithm
  when "git-sha1"
    errors << "#{name}: invalid immutable Git commit" unless digest&.match?(/\A[0-9a-f]{40}\z/)
  when "sha256"
    errors << "#{name}: invalid SHA-256" unless digest&.match?(/\A(?:sha256:)?[0-9a-f]{64}\z/)
  when "sha512-sri"
    errors << "#{name}: invalid SHA-512 SRI" unless digest&.match?(/\Asha512-[A-Za-z0-9+\/=]+\z/)
  end

  if status == "REVIEWED_PENDING_INDEPENDENT_APPROVAL"
    errors << "#{name}: pending candidate must not name approvers" unless approvers.empty?
    errors << "#{name}: pending candidate must not have approved_at" unless approved_at.nil?
  elsif status == "APPROVED"
    errors << "#{name}: approval requires at least two recorded independent identities" if approvers.length < 2
    errors << "#{name}: approval requires approved_at" if approved_at.nil?
  end

  errors << "#{name}: rollback target must be the immutable Phase 0 baseline" unless rollback_version == FOUNDATION_ROLLBACK_TARGET
end

REQUIRED_PINS.each do |name, (version, digest)|
  record = components[name]
  if record.nil?
    errors << "dependency registry: missing required candidate #{name}"
    next
  end
  errors << "#{name}: expected version #{version}" unless record.dig("component", "version") == version
  errors << "#{name}: immutable digest does not match the reviewed candidate" unless record.dig("component", "digest", "value") == digest
end

provenance = load_yaml(PROVENANCE_PATH)
expected_provenance = {
  ["status"] => "PINNED_SOURCE_NOT_IMPORTED",
  ["upstream", "repository"] => "https://github.com/Devlaner/devlane",
  ["upstream", "commit"] => "7719dcadf91f881b5aefe8b74012ffcfbba0bc17",
  ["upstream", "tree"] => "a568d1d11bab6012ffce1345193dcb537fa43556",
  ["upstream", "license", "blob"] => "b39a03349aaf17ccb61bef17f9f0e88d86a746ca",
  ["upstream", "license", "expression"] => "MIT",
  ["import", "imported"] => false
}
expected_provenance.each do |path, expected|
  actual = path.reduce(provenance) { |cursor, key| cursor.is_a?(Hash) ? cursor[key] : nil }
  errors << "devlane-provenance.yaml: #{path.join(".")} must equal #{expected.inspect}" unless actual == expected
end
errors << "devlane-provenance.yaml: imported_paths must be empty before import" unless provenance.dig("import", "imported_paths") == []
errors << "devlane-provenance.yaml: destination_paths must be empty before import" unless provenance.dig("import", "destination_paths") == []

lockfile = JSON.parse(File.read(LOCK_PATH))
errors << "package-lock.json: lockfileVersion must be 3" unless lockfile["lockfileVersion"] == 3
direct_dependencies = direct_npm_dependencies(lockfile, errors)
direct_names = direct_dependencies.map { |entry| entry["name"] }.to_set

direct_dependencies.each do |entry|
  name = entry["name"]
  locked = entry["lock"]
  record = components[name]
  if record.nil? || record.dig("component", "kind") != "npm_package"
    errors << "dependency registry: direct npm dependency #{name}@#{entry["version"]} has no candidate record"
    next
  end
  errors << "#{name}: registry version differs from manifest" unless record.dig("component", "version") == entry["version"]
  errors << "#{name}: registry source URL differs from lockfile" unless record.dig("component", "source_url") == locked["resolved"]
  errors << "#{name}: registry SRI differs from lockfile" unless record.dig("component", "digest", "value") == locked["integrity"]
  errors << "#{name}: registry license differs from lockfile" unless record.dig("component", "license_expression") == locked["license"]
end

registered_npm = records.select { |record| record.dig("component", "kind") == "npm_package" }.map { |record| record.dig("component", "name") }.to_set
(registered_npm - direct_names).each { |name| errors << "dependency registry: stale/non-direct npm candidate #{name}" }

review_licenses = Set.new
lockfile.fetch("packages", {}).each do |path, package|
  next unless path.include?("node_modules/")
  next if package["link"] || package["name"]&.start_with?("@stead/")

  license = package["license"]
  if license.nil? || license.empty?
    errors << "package-lock.json: #{path} has no license metadata"
  elsif license.match?(DISALLOWED_NPM_LICENSE)
    errors << "package-lock.json: #{path} has disallowed/unknown license #{license}"
  elsif !allowed_lock_license?(license)
    review_licenses << license
    errors << "package-lock.json: #{path} has non-allowlisted license #{license}; add a scoped approved exception or remove it"
  end
end

active_record_names = direct_names.dup
workflow_paths = Dir.glob(File.join(ROOT, ".github/workflows/*.{yml,yaml}"))
workflow_paths.each do |workflow_path|
  File.read(workflow_path).scan(/\buses:\s*["']?([^\s"'#]+)/).flatten.each do |reference|
    next if reference.start_with?("./")
    if (match = reference.match(/\A([^@]+)@([0-9a-f]{40})\z/))
      name = match[1]
      errors << "#{workflow_path.delete_prefix(ROOT + "/")}: prohibited setup action #{name}; execute reviewed toolchain artifacts directly" if PROHIBITED_SETUP_ACTIONS.include?(name)
      active_record_names << name
      record = components[name]
      errors << "#{workflow_path.delete_prefix(ROOT + "/")}: unregistered action #{name}" and next unless record
      errors << "#{workflow_path.delete_prefix(ROOT + "/")}: #{name} pin differs from approval registry" unless record.dig("component", "digest", "value") == match[2]
    else
      errors << "#{workflow_path.delete_prefix(ROOT + "/")}: action reference #{reference.inspect} is not pinned to a 40-character commit"
    end
  end
end

ci_path = File.join(ROOT, ".github/workflows/ci.yml")
if !File.file?(ci_path)
  errors << ".github/workflows/ci.yml: required foundation workflow is missing"
else
  ci = File.read(ci_path)
  {
    "contents: read" => "least-privilege contents permission",
    "persist-credentials: false" => "non-persistent checkout credential boundary",
    "scripts/run_pinned_node.sh npm ci" => "checksum-bound Node toolchain",
    "Ruby 3.2 or newer is required" => "host Ruby compatibility floor",
    "fetch-depth: 0" => "annotated baseline tag history",
    "fetch-tags: true" => "annotated baseline tag availability",
    "npm ci --ignore-scripts --no-audit --no-fund" => "lock-only npm installation",
    "make foundation-check" => "foundation gate",
    "DO_NOT_TRACK: \"1\"" => "default do-not-track signal",
    "NPM_CONFIG_IGNORE_SCRIPTS: \"true\"" => "default lifecycle-script disablement",
    "OTEL_SDK_DISABLED: \"true\"" => "default telemetry disablement",
    "REDOCLY_TELEMETRY: \"off\"" => "Redocly telemetry disablement"
  }.each do |snippet, purpose|
    errors << ".github/workflows/ci.yml: missing #{purpose}" unless ci.include?(snippet)
  end
  errors << ".github/workflows/ci.yml: pull_request_target is prohibited" if ci.match?(/\bpull_request_target\s*:/)
  errors << ".github/workflows/ci.yml: workflow may not request write or id-token permission" if ci.match?(/^\s+(?:contents|actions|checks|deployments|id-token|packages|pull-requests|security-events|statuses):\s*write\s*$/)
  errors << ".github/workflows/ci.yml: foundation workflow may not reference repository secrets" if ci.include?("secrets.")
  errors << ".github/workflows/ci.yml: floating runner label ubuntu-latest is prohibited" if ci.include?("ubuntu-latest")
end

go_runner = File.read(File.join(ROOT, "scripts/run_pinned_go.sh"))
errors << "scripts/run_pinned_go.sh: Go version pin is missing" unless go_runner.include?("go1.27.0")
errors << "scripts/run_pinned_go.sh: official Go archive digest is missing" unless go_runner.include?("675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685")
errors << "scripts/run_pinned_go.sh: extracted Go binary digest is missing" unless go_runner.include?("1db869c560a193573a71be466a34e0d4abb7792d78165c6102cdda069276a3a8")
errors << "scripts/run_pinned_go.sh: container fallback is not approved" if go_runner.match?(/\bdocker\s+run\b|golang@sha256/)
errors << "scripts/run_pinned_go.sh: host Go fast path is prohibited" if go_runner.include?("command -v go")

node_runner = File.read(File.join(ROOT, "scripts/run_pinned_node.sh"))
errors << "scripts/run_pinned_node.sh: Node version pin is missing" unless node_runner.include?("v26.8.1")
errors << "scripts/run_pinned_node.sh: official Node archive digest is missing" unless node_runner.include?("3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d")
errors << "scripts/run_pinned_node.sh: extracted Node binary digest is missing" unless node_runner.include?("19235a9b678f84729464c52623f92de130a165452747c6826d3fdc13df3abcc3")
errors << "scripts/run_pinned_node.sh: host Node fast path is prohibited" if node_runner.include?("command -v node")

openfga_runner = File.read(File.join(ROOT, "scripts/validate_openfga.sh"))
errors << "scripts/validate_openfga.sh: repository-owned model evaluator is missing" unless openfga_runner.include?("validate_openfga_model.mjs")
errors << "scripts/validate_openfga.sh: external OpenFGA CLI execution is prohibited until a vulnerability-clean exact release is approved" if openfga_runner.match?(/\bfga\s+model\s+test\b|openfga\/cli\/releases/)

notices = File.read(NOTICES_PATH)
required_notices = records.flat_map { |record| Array(record.dig("obligations", "notices")) }.uniq
required_notices.each do |notice_id|
  errors << "THIRD_PARTY_NOTICES.md: missing #{notice_id}" unless notices.include?(notice_id)
end
errors << "THIRD_PARTY_NOTICES.md: missing pinned Devlane commit" unless notices.include?("7719dcadf91f881b5aefe8b74012ffcfbba0bc17")
if lockfile.fetch("packages", {}).key?("node_modules/scheduler")
  errors << "THIRD_PARTY_NOTICES.md: distributed React scheduler notice/version is missing" unless notices.include?("`scheduler` 0.27.0")
end

release_mode = ARGV.include?("--release")
if release_mode
  workflow_source = workflow_paths.map { |path| File.read(path) }.join("\n")
  active_record_names << "node-v26.8.1-linux-x64.tar.xz" if workflow_source.include?("node-version: 26.8.1")
  makefile_source = File.read(File.join(ROOT, "Makefile"))
  if makefile_source.include?("scripts/run_pinned_go.sh")
    active_record_names << "go1.27.0.linux-amd64.tar.gz"
  end
  if makefile_source.include?("scripts/run_pinned_node.sh")
    active_record_names << "node-v26.8.1-linux-x64.tar.xz"
  end
  active_record_names.each do |name|
    record = components[name]
    next unless record
    errors << "#{name}: active dependency is not independently approved for release" unless registry["release_eligible_statuses"].include?(record.dig("decision", "status"))
  end
end

unless errors.empty?
  warn "dependency validation failed (#{errors.length} error#{errors.length == 1 ? "" : "s"}):"
  errors.each { |error| warn "- #{error}" }
  exit 1
end

pending = records.count { |record| record.dig("decision", "status") == "REVIEWED_PENDING_INDEPENDENT_APPROVAL" }
puts "dependency registry valid: #{records.length} exact candidate records; #{direct_dependencies.length} direct npm dependencies; #{pending} pending independent approval"
puts "transitive license review required before approval: #{review_licenses.to_a.sort.join(", ")}" unless review_licenses.empty?
puts "release eligibility verified for #{active_record_names.length} active dependencies" if release_mode
