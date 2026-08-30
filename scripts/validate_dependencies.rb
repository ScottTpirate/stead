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
POSTGRESQL_EVIDENCE_PATH = File.join(ROOT, "docs/governance/dependency-evidence/stead-p1-015-postgresql.yaml")
NOTICES_PATH = File.join(ROOT, "THIRD_PARTY_NOTICES.md")
LOCK_PATH = File.join(ROOT, "package-lock.json")
GO_MOD_PATH = File.join(ROOT, "go.mod")
GO_SUM_PATH = File.join(ROOT, "go.sum")

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
EXACT_GO_VERSION = /\Av\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z/
GO_H1_DIGEST = /\Ah1:[A-Za-z0-9+\/]{43}=\z/
PROHIBITED_GO_DIRECTIVES = Set.new(%w[exclude godebug replace retract tool toolchain]).freeze

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

def go_requirements(source, errors, label = "go.mod")
  requirements = []
  require_block = false

  source.each_line.with_index(1) do |raw_line, line_number|
    line = raw_line.strip
    next if line.empty? || line.start_with?("//")

    directive = line[/\A([A-Za-z]+)\b/, 1]
    if PROHIBITED_GO_DIRECTIVES.include?(directive)
      errors << "#{label}:#{line_number}: #{directive} directives are prohibited; approve the exact source through the dependency registry"
      next
    end

    if line.match?(/\Arequire\s*\(\s*\z/)
      errors << "#{label}:#{line_number}: nested require block" if require_block
      require_block = true
      next
    end
    if require_block && line == ")"
      require_block = false
      next
    end

    declaration = if require_block
                    line
                  elsif (match = line.match(/\Arequire\s+(.+)\z/))
                    match[1]
                  end
    next unless declaration

    requirement, comment = declaration.split(%r{\s+//\s*}, 2)
    indirect = comment&.strip == "indirect"
    if comment && !indirect
      errors << "#{label}:#{line_number}: require annotation must be exactly // indirect"
    end

    module_name, version, extra = requirement.split(/\s+/, 3)
    if module_name.nil? || version.nil? || extra
      errors << "#{label}:#{line_number}: malformed require declaration"
      next
    end
    unless version.match?(EXACT_GO_VERSION)
      errors << "#{label}:#{line_number}: #{module_name} must use an exact Go module version, got #{version.inspect}"
    end
    requirements << { "name" => module_name, "version" => version, "indirect" => indirect }
  end

  errors << "#{label}: unterminated require block" if require_block
  names = requirements.map { |entry| entry["name"] }
  errors << "#{label}: required module paths must be unique" unless names.uniq.length == names.length
  requirements
end

def go_sum_entries(source, errors, label = "go.sum")
  entries = {}
  source.each_line.with_index(1) do |raw_line, line_number|
    line = raw_line.strip
    next if line.empty?

    module_name, version, digest, extra = line.split(/\s+/, 4)
    if module_name.nil? || version.nil? || digest.nil? || extra
      errors << "#{label}:#{line_number}: malformed checksum entry"
      next
    end
    errors << "#{label}:#{line_number}: checksum must use Go h1 format" unless digest.match?(GO_H1_DIGEST)
    key = [module_name, version]
    errors << "#{label}:#{line_number}: duplicate checksum entry for #{module_name} #{version}" if entries.key?(key)
    entries[key] = digest
  end
  entries
end

def validate_go_dependencies(mod_source, sum_source, components, errors, allowed_indirect: {}, mod_label: "go.mod", sum_label: "go.sum")
  requirements = go_requirements(mod_source, errors, mod_label)
  dependencies = requirements.reject { |entry| entry["indirect"] }
  sums = go_sum_entries(sum_source, errors, sum_label)

  dependencies.each do |entry|
    name = entry["name"]
    version = entry["version"]
    record = components[name]
    if record.nil? || record.dig("component", "kind") != "go_module" || record.dig("component", "ecosystem") != "go"
      errors << "dependency registry: direct Go module #{name}@#{version} has no go_module candidate record"
      next
    end

    errors << "#{name}: registry version differs from go.mod" unless record.dig("component", "version") == version
    module_sum = sums[[name, version]]
    go_mod_sum = sums[[name, "#{version}/go.mod"]]
    errors << "#{sum_label}: missing module checksum for #{name} #{version}" if module_sum.nil?
    errors << "#{sum_label}: missing go.mod checksum for #{name} #{version}" if go_mod_sum.nil?
    if module_sum && record.dig("component", "digest", "value") != module_sum
      errors << "#{name}: registry module checksum differs from #{sum_label}"
    end
    if go_mod_sum && record.dig("component", "module_file_digest", "value") != go_mod_sum
      errors << "#{name}: registry go.mod checksum differs from #{sum_label}"
    end
  end
  indirect = requirements.select { |entry| entry["indirect"] }
  indirect.each do |entry|
    expected = allowed_indirect[entry["name"]]
    if expected.nil?
      errors << "dependency evidence: indirect Go module #{entry["name"]}@#{entry["version"]} is outside every reviewed runtime closure"
      next
    end
    expected_version, expected_sum, expected_go_mod_sum = expected
    errors << "#{entry["name"]}: indirect version differs from reviewed closure" unless entry["version"] == expected_version
    module_sum = sums[[entry["name"], entry["version"]]]
    go_mod_sum = sums[[entry["name"], "#{entry["version"]}/go.mod"]]
    errors << "#{sum_label}: missing module checksum for #{entry["name"]} #{entry["version"]}" if module_sum.nil?
    errors << "#{sum_label}: missing go.mod checksum for #{entry["name"]} #{entry["version"]}" if go_mod_sum.nil?
    errors << "#{entry["name"]}: module checksum differs from reviewed closure" if module_sum && module_sum != expected_sum
    errors << "#{entry["name"]}: go.mod checksum differs from reviewed closure" if go_mod_sum && go_mod_sum != expected_go_mod_sum
  end

  active_names = requirements.map { |entry| entry["name"] }.to_set
  expected_names = allowed_indirect.keys.to_set
  if active_names.include?("github.com/jackc/pgx/v5")
    errors << "go.mod: github.com/jackc/pgx/v5 must be a direct dependency" unless dependencies.any? { |entry| entry["name"] == "github.com/jackc/pgx/v5" }
    missing = expected_names - active_names
    errors << "go.mod: pgxpool reviewed runtime closure is incomplete: #{missing.to_a.sort.join(', ')}" unless missing.empty?
  elsif !(active_names & expected_names).empty?
    errors << "go.mod: pgxpool transitive modules may not be active without direct github.com/jackc/pgx/v5"
  end

  { "direct" => dependencies, "requirements" => requirements }
end

def oci_workflow_references(source, errors, label)
  references = []
  source.each_line.with_index(1) do |raw_line, line_number|
    value = if (match = raw_line.match(/^\s*image:\s*["']?([^\s"'#]+)["']?/))
              match[1]
            elsif (match = raw_line.match(/^\s*container:\s*["']?([^\s"'#]+)["']?/))
              match[1]
            elsif (match = raw_line.match(/^\s*uses:\s*["']?docker:\/\/([^\s"'#]+)["']?/))
              match[1]
            end
    next unless value

    match = value.match(/\A(.+?)(?::([^\/@]+))?@(sha256:[0-9a-f]{64})\z/)
    unless match
      errors << "#{label}:#{line_number}: OCI image #{value.inspect} is not pinned to an immutable SHA-256 digest"
      next
    end
    references << { "name" => match[1], "version" => match[2], "digest" => match[3], "line" => line_number }
  end
  references
end

def validate_oci_workflow_images(workflow_sources, components, errors)
  references = workflow_sources.flat_map do |label, source|
    oci_workflow_references(source, errors, label)
  end
  references.each do |reference|
    name = reference["name"]
    record = components[name]
    unless record && record.dig("component", "kind") == "oci_image" && record.dig("component", "ecosystem") == "oci"
      errors << "dependency registry: workflow OCI image #{name} has no oci_image candidate record"
      next
    end
    if reference["version"] && record.dig("component", "version") != reference["version"]
      errors << "#{name}: registry version differs from workflow image tag"
    end
    errors << "#{name}: workflow image digest differs from approval registry" unless record.dig("component", "digest", "value") == reference["digest"]
  end
  references
end

def release_approval_errors(active_names, components, release_eligible_statuses)
  active_names.filter_map do |name|
    record = components[name]
    next unless record
    next if release_eligible_statuses.include?(record.dig("decision", "status"))

    "#{name}: active dependency is not independently approved for release"
  end
end

def run_validator_self_tests
  pending_go = {
    "component" => {
      "name" => "example.com/db", "kind" => "go_module", "ecosystem" => "go", "version" => "v1.2.3",
      "digest" => { "algorithm" => "go-h1", "value" => "h1:#{'a' * 43}=" },
      "module_file_digest" => { "algorithm" => "go-h1", "value" => "h1:#{'b' * 43}=" }
    },
    "decision" => { "status" => "REVIEWED_PENDING_INDEPENDENT_APPROVAL" }
  }
  pending_oci = {
    "component" => {
      "name" => "postgres", "kind" => "oci_image", "ecosystem" => "oci", "version" => "16-bookworm",
      "digest" => { "algorithm" => "sha256", "value" => "sha256:#{'a' * 64}" }
    },
    "decision" => { "status" => "REVIEWED_PENDING_INDEPENDENT_APPROVAL" }
  }
  components = { "example.com/db" => pending_go, "postgres" => pending_oci }
  failures = []

  missing_errors = []
  validate_go_dependencies("module fixture\nrequire example.com/db v1.2.3\n", "", components, missing_errors, mod_label: "missing.mod", sum_label: "missing.sum")
  failures << "missing Go sum mutation was accepted" unless missing_errors.any? { |error| error.include?("missing module checksum") } && missing_errors.any? { |error| error.include?("missing go.mod checksum") }

  wrong_errors = []
  wrong_sum = "example.com/db v1.2.3 h1:#{'c' * 43}=\nexample.com/db v1.2.3/go.mod h1:#{'d' * 43}=\n"
  validate_go_dependencies("module fixture\nrequire example.com/db v1.2.3\n", wrong_sum, components, wrong_errors, mod_label: "wrong.mod", sum_label: "wrong.sum")
  failures << "wrong Go sum mutation was accepted" unless wrong_errors.any? { |error| error.include?("registry module checksum differs") } && wrong_errors.any? { |error| error.include?("registry go.mod checksum differs") }

  approval_errors = release_approval_errors(Set.new(["example.com/db"]), components, ["APPROVED"])
  failures << "unapproved active Go module mutation was accepted" unless approval_errors.any? { |error| error.include?("not independently approved") }

  replacement_errors = []
  go_requirements("module fixture\nreplace example.com/db => ./unreviewed\n", replacement_errors, "replace.mod")
  failures << "Go replace mutation was accepted" unless replacement_errors.any? { |error| error.include?("replace directives are prohibited") }

  indirect_errors = []
  validate_go_dependencies(
    "module fixture\nrequire example.com/transitive v1.0.0 // indirect\n",
    "example.com/transitive v1.0.0 h1:#{'e' * 43}=\nexample.com/transitive v1.0.0/go.mod h1:#{'f' * 43}=\n",
    components,
    indirect_errors,
    mod_label: "indirect.mod",
    sum_label: "indirect.sum"
  )
  failures << "unreviewed indirect Go module mutation was accepted" unless indirect_errors.any? { |error| error.include?("outside every reviewed runtime closure") }

  unpinned_errors = []
  validate_oci_workflow_images({ "unpinned.yml" => "services:\n  db:\n    image: postgres:16-bookworm\n" }, components, unpinned_errors)
  failures << "unpinned OCI image mutation was accepted" unless unpinned_errors.any? { |error| error.include?("not pinned") }

  wrong_oci_errors = []
  validate_oci_workflow_images({ "wrong.yml" => "container:\n  image: postgres:16-bookworm@sha256:#{'b' * 64}\n" }, components, wrong_oci_errors)
  failures << "wrong OCI digest mutation was accepted" unless wrong_oci_errors.any? { |error| error.include?("digest differs") }

  unless failures.empty?
    warn "dependency validator self-tests failed:"
    failures.each { |failure| warn "- #{failure}" }
    exit 1
  end
  puts "dependency validator self-tests passed: 7/7 mutation guards"
end

if ARGV.first == "--self-test"
  run_validator_self_tests
  exit 0
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
  when "go-h1"
    errors << "#{name}: invalid Go h1 checksum" unless digest&.match?(GO_H1_DIGEST)
  end

  kind = record.dig("component", "kind")
  ecosystem = record.dig("component", "ecosystem")
  if kind == "go_module"
    errors << "#{name}: go_module must use the go ecosystem" unless ecosystem == "go"
    errors << "#{name}: go_module artifact checksum must use go-h1" unless algorithm == "go-h1"
    errors << "#{name}: go_module requires an exact Go version" unless record.dig("component", "version")&.match?(EXACT_GO_VERSION)
    module_file_digest = record.dig("component", "module_file_digest")
    unless module_file_digest&.dig("algorithm") == "go-h1" && module_file_digest&.dig("value")&.match?(GO_H1_DIGEST)
      errors << "#{name}: go_module requires an exact go-h1 module_file_digest"
    end
  elsif ecosystem == "go"
    errors << "#{name}: go ecosystem record must use go_module kind"
  end
  if kind == "oci_image"
    errors << "#{name}: oci_image must use the oci ecosystem" unless ecosystem == "oci"
    errors << "#{name}: oci_image digest must use sha256" unless algorithm == "sha256"
  elsif ecosystem == "oci"
    errors << "#{name}: oci ecosystem record must use oci_image kind"
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

postgresql_evidence = load_yaml(POSTGRESQL_EVIDENCE_PATH)
expected_postgresql_evidence = {
  ["issue_id"] => "STEAD-P1-015",
  ["candidate_state"] => "GOVERNANCE_ONLY_NOT_INTEGRATED",
  ["go_candidate", "approval_id"] => "DEP-APP-GO-PGX-V5-5-10-0",
  ["go_candidate", "module"] => "github.com/jackc/pgx/v5",
  ["go_candidate", "version"] => "v5.10.0",
  ["go_candidate", "module_sum"] => "h1:VhSvgU2jSli8o3AqIEOTJr7rZwAEUVo4E4XhR94Zfr0=",
  ["go_candidate", "go_mod_sum"] => "h1:mal1tBGAFfLHvZzaYh77YS/eC6IX9OWbRV1QIIM0Jn4=",
  ["go_candidate", "upstream", "tag_commit"] => "7293fb11125be0373a92f716683f2d494f6fd4b0",
  ["oci_candidate", "approval_id"] => "DEP-APP-OCI-POSTGRES-16-BOOKWORM-BB3E1A57",
  ["oci_candidate", "reference"] => "postgres:16-bookworm",
  ["oci_candidate", "index_digest"] => "sha256:bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825",
  ["oci_candidate", "selected_platform", "manifest_digest"] => "sha256:1938c16e9d2f10a6a3623b344b64ae8d45f407f2c5f34f0979468bb689b9227a",
  ["oci_candidate", "selected_platform", "config_digest"] => "sha256:5f71c21b69a7977b82247582e2e731ed76bdebaadb7dd7945ed76bcc9ed06632",
  ["oci_candidate", "postgres_package_version"] => "16.15-1.pgdg12+2",
  ["oci_candidate", "created"] => "2026-08-25"
}
expected_postgresql_evidence.each do |path, expected|
  actual = path.reduce(postgresql_evidence) { |cursor, key| cursor.is_a?(Hash) ? cursor[key] : nil }
  errors << "dependency-evidence/stead-p1-015-postgresql.yaml: #{path.join(".")} must equal #{expected.inspect}" unless actual == expected
end

expected_pgxpool_closure = {
  "github.com/jackc/pgpassfile" => ["v1.0.0", "h1:/6Hmqy13Ss2zCq62VdNG8tM1wchn8zjSGOBJ6icpsIM=", "h1:CEx0iS5ambNFdcRtxPj5JhEz+xB6uRky5eyVu/W2HEg=", "99d8e8e28945ffceaf75b0299fcb2bb656b8a683", "MIT"],
  "github.com/jackc/pgservicefile" => ["v0.0.0-20240606120523-5a60cdf6a761", "h1:iCEnooe7UlwOQYpKFhBabPMi4aNAfoODPEFNiAnClxo=", "h1:5TJZWKEWniPve33vlWYSoGYefn3gLQRzjfDlhSJ9ZKM=", "5a60cdf6a76120dc3d5152b95f3b5fd8aa7cc9eb", "MIT"],
  "github.com/jackc/puddle/v2" => ["v2.2.2", "h1:PR8nw+E/1w0GLuRFSmiioY6UooMp6KJv0/61nB7icHo=", "h1:vriiEXHvEE654aYKXXjOvZM39qJ0q+azkZFrfEOc3H4=", "bd09d14bd4018b6d65a9d7770e2f3ddf8b00af1c", "MIT"],
  "golang.org/x/sync" => ["v0.17.0", "h1:l60nONMj9l5drqw6jlhIELNv9I0A4OFgRsG9k2oT9Ug=", "h1:9KTHXmSnoGruLpwFjVSX0lNNA75CykiMECbovNTZqGI=", "04914c200cb38d4ea960ee6a4c314a028c632991", "BSD-3-Clause"],
  "golang.org/x/text" => ["v0.29.0", "h1:1neNs90w9YzJ9BocxfsQNHKuAT4pkghyXc4nhZ6sJvk=", "h1:7MhJOA9CD2qZyOKYazxdYMF85OwPdEr9jTtBpO7ydH4=", "e69f31bf9cf2f46bd3325bc9bad37fe9001731c2", "BSD-3-Clause"]
}
actual_closure = Array(postgresql_evidence.dig("go_candidate", "pgxpool_module_closure")).to_h do |entry|
  [entry["module"], [entry["version"], entry["module_sum"], entry["go_mod_sum"], entry["upstream_commit"], entry["license_expression"]]]
end
errors << "dependency-evidence/stead-p1-015-postgresql.yaml: pgxpool module closure differs from the reviewed intake" unless actual_closure == expected_pgxpool_closure

pgx_record = components["github.com/jackc/pgx/v5"]
if pgx_record
  errors << "github.com/jackc/pgx/v5: registry artifact checksum differs from intake evidence" unless pgx_record.dig("component", "digest", "value") == postgresql_evidence.dig("go_candidate", "module_sum")
  errors << "github.com/jackc/pgx/v5: registry go.mod checksum differs from intake evidence" unless pgx_record.dig("component", "module_file_digest", "value") == postgresql_evidence.dig("go_candidate", "go_mod_sum")
end
postgres_record = components["postgres"]
if postgres_record
  errors << "postgres: registry index digest differs from intake evidence" unless postgres_record.dig("component", "digest", "value") == postgresql_evidence.dig("oci_candidate", "index_digest")
end
unless postgresql_evidence.dig("go_candidate", "vulnerability_scan") == { "status" => "PENDING_INDEPENDENT_SCAN", "result" => nil }
  errors << "dependency-evidence/stead-p1-015-postgresql.yaml: Go vulnerability evidence must remain honestly pending until an independent result is recorded"
end
unless postgresql_evidence.dig("oci_candidate", "vulnerability_scan") == { "status" => "PENDING_IMAGE_SCAN", "result" => nil } &&
       postgresql_evidence.dig("oci_candidate", "package_license_inventory") == { "status" => "PENDING_IMAGE_SCAN", "result" => nil }
  errors << "dependency-evidence/stead-p1-015-postgresql.yaml: image vulnerability/license evidence must remain honestly pending until scan results are recorded"
end

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

go_mod_source = File.read(GO_MOD_PATH)
go_sum_source = File.file?(GO_SUM_PATH) ? File.read(GO_SUM_PATH) : ""
errors << "go.work: workspace overrides are prohibited in release input" if File.file?(File.join(ROOT, "go.work"))
errors << "vendor: vendored Go source requires separate provenance and approval" if File.directory?(File.join(ROOT, "vendor"))
allowed_pgxpool_indirect = expected_pgxpool_closure.transform_values { |values| values.first(3) }
go_validation = validate_go_dependencies(
  go_mod_source,
  go_sum_source,
  components,
  errors,
  allowed_indirect: allowed_pgxpool_indirect
)
direct_go = go_validation["direct"]
direct_go_names = direct_go.map { |entry| entry["name"] }.to_set

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

active_record_names = direct_names | direct_go_names
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

workflow_sources = workflow_paths.to_h { |path| [path.delete_prefix(ROOT + "/"), File.read(path)] }
oci_references = validate_oci_workflow_images(workflow_sources, components, errors)
active_record_names.merge(oci_references.map { |reference| reference["name"] })

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
  errors.concat(release_approval_errors(active_record_names, components, registry["release_eligible_statuses"]))
end

unless errors.empty?
  warn "dependency validation failed (#{errors.length} error#{errors.length == 1 ? "" : "s"}):"
  errors.each { |error| warn "- #{error}" }
  exit 1
end

pending = records.count { |record| record.dig("decision", "status") == "REVIEWED_PENDING_INDEPENDENT_APPROVAL" }
puts "dependency registry valid: #{records.length} exact candidate records; #{direct_dependencies.length} direct npm dependencies; #{direct_go.length} direct Go modules; #{oci_references.length} workflow OCI images; #{pending} pending independent approval"
puts "transitive license review required before approval: #{review_licenses.to_a.sort.join(", ")}" unless review_licenses.empty?
puts "release eligibility verified for #{active_record_names.length} active dependencies" if release_mode
