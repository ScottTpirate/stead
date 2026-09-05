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
REJECTED_PGX_NOTICE_IDS = %w[
  NOTICE-PGX-MIT
  NOTICE-PGPASSFILE-MIT
  NOTICE-PGSERVICEFILE-MIT
  NOTICE-PUDDLE-MIT
  NOTICE-GO-X-SYNC-BSD-3-CLAUSE
  NOTICE-GO-X-TEXT-BSD-3-CLAUSE
].freeze
PGX_NOTICE_QUARANTINE_MARKER = "STEAD-NOTICE-QUARANTINE:DEP-APP-GO-PGX-V5-5-10-0:REJECTED-NOT-RELEASE-INPUT"
PGX_NOTICE_QUARANTINE_BEGIN = "<!-- BEGIN #{PGX_NOTICE_QUARANTINE_MARKER} -->"
PGX_NOTICE_QUARANTINE_END = "<!-- END #{PGX_NOTICE_QUARANTINE_MARKER} -->"
PGX_NOTICE_QUARANTINE_HEADING = "## REJECTED / QUARANTINED — pgx v5.10.0 closure notices (not release input)"
PGX_NOTICE_QUARANTINE_FRAMING = <<~MARKDOWN.chomp.freeze
  These exact six notices are rejected intake evidence only; this block is not approved,
  distributed, or a release-notice input. Any reuse requires a new approval ID and independent approval.
MARKDOWN
PGX_NOTICE_QUARANTINE_BINDING = {
  "marker" => PGX_NOTICE_QUARANTINE_MARKER,
  "status" => "REJECTED_EVIDENCE_ONLY",
  "release_notice_input" => false,
  "begin_marker" => PGX_NOTICE_QUARANTINE_BEGIN,
  "section_heading" => PGX_NOTICE_QUARANTINE_HEADING,
  "framing" => PGX_NOTICE_QUARANTINE_FRAMING,
  "end_marker" => PGX_NOTICE_QUARANTINE_END,
  "notice_ids" => REJECTED_PGX_NOTICE_IDS
}.freeze
EXPECTED_PGXPOOL_CLOSURE = {
  "github.com/jackc/pgpassfile" => ["v1.0.0", "h1:/6Hmqy13Ss2zCq62VdNG8tM1wchn8zjSGOBJ6icpsIM=", "h1:CEx0iS5ambNFdcRtxPj5JhEz+xB6uRky5eyVu/W2HEg=", "99d8e8e28945ffceaf75b0299fcb2bb656b8a683", "MIT", "NOTICE-PGPASSFILE-MIT"],
  "github.com/jackc/pgservicefile" => ["v0.0.0-20240606120523-5a60cdf6a761", "h1:iCEnooe7UlwOQYpKFhBabPMi4aNAfoODPEFNiAnClxo=", "h1:5TJZWKEWniPve33vlWYSoGYefn3gLQRzjfDlhSJ9ZKM=", "5a60cdf6a76120dc3d5152b95f3b5fd8aa7cc9eb", "MIT", "NOTICE-PGSERVICEFILE-MIT"],
  "github.com/jackc/puddle/v2" => ["v2.2.2", "h1:PR8nw+E/1w0GLuRFSmiioY6UooMp6KJv0/61nB7icHo=", "h1:vriiEXHvEE654aYKXXjOvZM39qJ0q+azkZFrfEOc3H4=", "bd09d14bd4018b6d65a9d7770e2f3ddf8b00af1c", "MIT", "NOTICE-PUDDLE-MIT"],
  "golang.org/x/sync" => ["v0.17.0", "h1:l60nONMj9l5drqw6jlhIELNv9I0A4OFgRsG9k2oT9Ug=", "h1:9KTHXmSnoGruLpwFjVSX0lNNA75CykiMECbovNTZqGI=", "04914c200cb38d4ea960ee6a4c314a028c632991", "BSD-3-Clause", "NOTICE-GO-X-SYNC-BSD-3-CLAUSE"],
  "golang.org/x/text" => ["v0.29.0", "h1:1neNs90w9YzJ9BocxfsQNHKuAT4pkghyXc4nhZ6sJvk=", "h1:7MhJOA9CD2qZyOKYazxdYMF85OwPdEr9jTtBpO7ydH4=", "e69f31bf9cf2f46bd3325bc9bad37fe9001731c2", "BSD-3-Clause", "NOTICE-GO-X-TEXT-BSD-3-CLAUSE"]
}.freeze
REJECTED_PGX_APPROVAL_ID = "DEP-APP-GO-PGX-V5-5-10-0"
REJECTED_POSTGRES_APPROVAL_ID = "DEP-APP-OCI-POSTGRES-16-BOOKWORM-BB3E1A57"
SUCCESSOR_PGX_APPROVAL_ID = "DEP-APP-GO-PGXPOOL-V5-10-0-XTEXT-0-41-0"
SUCCESSOR_POSTGRES_APPROVAL_ID = "DEP-APP-OCI-CHAINGUARD-POSTGRES-18-6-R2-99982050"
SUCCESSOR_PGX_NOTICE_IDS = %w[
  NOTICE-P1-015-PGX-MIT
  NOTICE-P1-015-PGPASSFILE-MIT
  NOTICE-P1-015-PGSERVICEFILE-MIT
  NOTICE-P1-015-PUDDLE-MIT
  NOTICE-P1-015-GO-X-SYNC-BSD-3-CLAUSE
  NOTICE-P1-015-GO-X-TEXT-BSD-3-CLAUSE
].freeze
EXPECTED_REJECTED_DECISIONS = {
  REJECTED_PGX_APPROVAL_ID => {
    "category" => "ALLOW-PERMISSIVE",
    "status" => "REJECTED",
    "independent_approval_required" => true,
    "approvers" => [],
    "approved_at" => nil,
    "reason_codes" => ["REACHABLE_KNOWN_VULNERABILITY"],
    "evidence_refs" => [
      "dependency-evidence/stead-p1-015-postgresql.yaml#go_candidate",
      "github-pr-39-comment-5471438314",
      "github-issue-38-comment-5471438378"
    ]
  },
  REJECTED_POSTGRES_APPROVAL_ID => {
    "category" => "UNKNOWN",
    "status" => "REJECTED",
    "independent_approval_required" => true,
    "approvers" => [],
    "approved_at" => nil,
    "reason_codes" => [
      "UNRESOLVED_CRITICAL_HIGH_FINDINGS",
      "INCOMPLETE_LICENSE_CLASSIFICATION",
      "MISSING_SIGNED_SUPPLY_CHAIN_EVIDENCE"
    ],
    "evidence_refs" => [
      "dependency-evidence/stead-p1-015-postgresql.yaml#oci_candidate",
      "github-pr-39-comment-5471438314",
      "github-issue-38-comment-5471438378"
    ]
  }
}.freeze
EXPECTED_POSTGRESQL_REJECTION_EVIDENCE = {
  ["candidate_state"] => "REJECTED_QUARANTINED_NOT_INTEGRATED",
  ["recorded_at"] => "2026-08-30T21:35:54Z",
  ["independent_review", "candidate_revision"] => "f929649e9c5896d579147b922fdd87659f26c2ff",
  ["independent_review", "completed_at"] => "2026-08-30T21:35:54Z",
  ["independent_review", "disposition"] => "REVISE_HOLD",
  ["independent_review", "release_eligible"] => false,
  ["independent_review", "evidence_references"] => ["github-pr-39-comment-5471438314", "github-issue-38-comment-5471438378"],
  ["go_candidate", "notice_id"] => "NOTICE-PGX-MIT",
  ["go_candidate", "notice_quarantine"] => PGX_NOTICE_QUARANTINE_BINDING,
  ["go_candidate", "vulnerability_scan", "status"] => "REJECTED_REACHABLE_VULNERABILITY",
  ["go_candidate", "vulnerability_scan", "completed_at"] => "2026-08-30T21:35:54Z",
  ["go_candidate", "vulnerability_scan", "tool"] => {
    "name" => "govulncheck", "version" => "v1.7.0", "go_version" => "go1.27.0",
    "database" => "https://vuln.go.dev", "database_updated_at" => "2026-08-28T14:47:45Z"
  },
  ["go_candidate", "vulnerability_scan", "result"] => {
    "advisory_id" => "GO-2026-5970", "cve_id" => "CVE-2026-56852",
    "vulnerable_module" => "golang.org/x/text", "vulnerable_version" => "v0.29.0",
    "fixed_version" => "v0.39.0", "reachable_path" => "github.com/jackc/pgx/v5 SCRAM authentication"
  },
  ["go_candidate", "vulnerability_scan", "evidence_digest"] => {
    "closure_go_mod_sha256" => "42d674c3b77defbc95c0b96a077302adc47f70b049520843df185b13cebada49",
    "closure_go_sum_sha256" => "2f18690ef7080bc7b609a33b4f779b44e197f6f6c5f405c34e51a8931579c8c0"
  },
  ["go_candidate", "provenance_review", "status"] => "REPRODUCED_NOT_APPROVED",
  ["go_candidate", "provenance_review", "result"] => "Exact tag commit, module and go.mod checksums, pgxpool closure, license files, and notice obligations reproduced.",
  ["go_candidate", "possible_successor", "status"] => "UNAPPROVED_INFORMATION_ONLY",
  ["go_candidate", "possible_successor", "selected_modules"] => [
    {
      "module" => "golang.org/x/text", "version" => "v0.39.0",
      "module_sum" => "h1:UbZz4pLOvn600D6Oh6GGEI6VAmndrEBLv8/6BEXzyus=",
      "go_mod_sum" => "h1:3UwRclnC2g0TU9x8PZiyfOajCd1zaUNHF9cvqcQZ+ZM="
    },
    {
      "module" => "golang.org/x/sync", "version" => "v0.21.0",
      "module_sum" => "h1:HLII4xRRTtCRkxYp4HNFF0Js/Og6q2i++KXbg0gHCwM=",
      "go_mod_sum" => "h1:9xrNwdLfx4jkKbNva9FpL6vEN7evnE43NNNJQ2LF3+0="
    }
  ],
  ["go_candidate", "possible_successor", "govulncheck_findings"] => 0,
  ["go_candidate", "possible_successor", "closure_go_mod_sha256"] => "925e120507c7b457b98f5dcb68a05f3044ab9883a608c591f6a9f7bdbb636ac4",
  ["go_candidate", "possible_successor", "closure_go_sum_sha256"] => "760a7e8525ac7caaf6fa69cbc51ae7661a0a942369b9412e1a2cd17655e51a33",
  ["go_candidate", "possible_successor", "required_next_step"] => "New immutable intake revision, exact closure/checksums/notices, compatibility tests, and fresh independent rescan.",
  ["oci_candidate", "created"] => "2026-08-25T00:42:19.848754437Z",
  ["oci_candidate", "source_revision"] => "9d15534160ade17f2b6c455a39ee967c49b1937d",
  ["oci_candidate", "vulnerability_scan", "status"] => "REJECTED_UNRESOLVED_CRITICAL_HIGH",
  ["oci_candidate", "vulnerability_scan", "completed_at"] => "2026-08-30T21:35:54Z",
  ["oci_candidate", "vulnerability_scan", "reviewed_disposition"] => "Both independent scanners retain unresolved Critical/High findings after the reviewed non-applicable results; RG-08 is not satisfied.",
  ["oci_candidate", "vulnerability_scan", "reports"] => [
    {
      "tool" => "trivy", "version" => "0.74.0", "database_version" => 2,
      "database_updated_at" => "2026-08-30T19:01:43.110912224Z",
      "report_created_at" => "2026-08-30T21:27:24.886430412Z",
      "report_sha256" => "928280778e02c072db6b3f05a4e8fee9b535b2a75eca668dfba689697e1be720",
      "raw_os_critical" => 15, "raw_os_high" => 45
    },
    {
      "tool" => "grype", "version" => "0.118.0", "database_schema" => "v6.1.9",
      "database_built_at" => "2026-08-30T06:27:52Z",
      "report_created_at" => "2026-08-30T21:29:44.933982995Z",
      "report_sha256" => "5307fb983fbe1d72971956244d538e4caec97d41e75a9f64304cc0bbbb010693",
      "raw_os_critical" => 26, "raw_os_high" => 49
    }
  ],
  ["oci_candidate", "package_license_inventory", "status"] => "REJECTED_INCOMPLETE_LICENSE_CLASSIFICATION",
  ["oci_candidate", "package_license_inventory", "tool"] => "syft",
  ["oci_candidate", "package_license_inventory", "version"] => "1.51.1",
  ["oci_candidate", "package_license_inventory", "report_sha256"] => "a5859ae8a27dac4117c518a4cc0a8433c6e336633143edb386a59c2eaba678e8",
  ["oci_candidate", "package_license_inventory", "published_spdx_license_concluded"] => "NOASSERTION",
  ["oci_candidate", "package_license_inventory", "published_spdx_noassertion_concluded_packages"] => 204,
  ["oci_candidate", "package_license_inventory", "scanner_custom_tokens"] => ["Custom-Unicode", "Custom-pg_dump", "Custom-regex"],
  ["oci_candidate", "package_license_inventory", "disposition"] => "Legal/policy normalization is incomplete; UNKNOWN remains rejected and quarantined.",
  ["oci_candidate", "published_supply_chain_statements", "status"] => "REPRODUCED_UNSIGNED_EVIDENCE_ONLY",
  ["oci_candidate", "published_supply_chain_statements", "attestation_manifest_digest"] => "sha256:4ba017d475bffe5bb91d50107c339b64a43853b264a2426ceddfa47557939ea3",
  ["oci_candidate", "published_supply_chain_statements", "subject_manifest_digest"] => "sha256:1938c16e9d2f10a6a3623b344b64ae8d45f407f2c5f34f0979468bb689b9227a",
  ["oci_candidate", "published_supply_chain_statements", "spdx"] => {
    "predicate_type" => "https://spdx.dev/Document", "version" => "SPDX-2.3",
    "layer_digest" => "sha256:90162b18863727e5883dc9c5fcae8c65b6ff353e7e9caa03292e77626d386d47"
  },
  ["oci_candidate", "published_supply_chain_statements", "slsa"] => {
    "predicate_type" => "https://slsa.dev/provenance/v0.2",
    "layer_digest" => "sha256:81926168df652b2566d246259a832e999ed94d3c134671eb1adb6e07a292f05e",
    "source_revision" => "9d15534160ade17f2b6c455a39ee967c49b1937d"
  },
  ["oci_candidate", "published_supply_chain_statements", "assurance_limit"] => "Published statements are digest-bound provenance evidence only; no SLSA level or approval is claimed.",
  ["oci_candidate", "signature_attestation_review", "status"] => "REJECTED_NO_COSIGN_SIGNATURE_OR_SIGNED_ATTESTATION",
  ["oci_candidate", "signature_attestation_review", "tool"] => "cosign",
  ["oci_candidate", "signature_attestation_review", "version"] => "3.1.3",
  ["oci_candidate", "signature_attestation_review", "checked_digests"] => [
    "sha256:bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825",
    "sha256:1938c16e9d2f10a6a3623b344b64ae8d45f407f2c5f34f0979468bb689b9227a"
  ],
  ["oci_candidate", "signature_attestation_review", "result"] => "No Cosign signature or signed Cosign attestation was found for either digest."
}.freeze

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

def candidate_records(records_by_name, name)
  value = records_by_name[name]
  return [] if value.nil?

  value.is_a?(Array) ? value : [value]
end

def select_approved_candidate(records_by_name, name, identity, errors, label: name)
  matches = candidate_records(records_by_name, name).select do |record|
    identity.all? { |path, expected| nested_value(record, path) == expected }
  end
  if matches.empty?
    errors << "#{label}: no exact candidate record matches the active version and digest"
    return nil
  end

  approved = matches.select { |record| record.dig("decision", "status") == "APPROVED" }
  if approved.empty?
    errors << "#{label}: exact candidate is not approved for use"
    return nil
  end
  if approved.length > 1
    errors << "#{label}: multiple approved exact candidate records make active selection ambiguous"
    return nil
  end

  approved.first
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

def validate_go_dependencies(mod_source, sum_source, records_by_name, errors, go_closures_by_approval_id: {}, mod_label: "go.mod", sum_label: "go.sum")
  requirements = go_requirements(mod_source, errors, mod_label)
  dependencies = requirements.reject { |entry| entry["indirect"] }
  sums = go_sum_entries(sum_source, errors, sum_label)
  selected_records = []

  dependencies.each do |entry|
    name = entry["name"]
    version = entry["version"]
    candidates = candidate_records(records_by_name, name).select do |record|
      record.dig("component", "kind") == "go_module" && record.dig("component", "ecosystem") == "go"
    end
    if candidates.empty?
      errors << "dependency registry: direct Go module #{name}@#{version} has no go_module candidate record"
      next
    end

    module_sum = sums[[name, version]]
    go_mod_sum = sums[[name, "#{version}/go.mod"]]
    errors << "#{sum_label}: missing module checksum for #{name} #{version}" if module_sum.nil?
    errors << "#{sum_label}: missing go.mod checksum for #{name} #{version}" if go_mod_sum.nil?
    version_candidates = candidates.select { |record| record.dig("component", "version") == version }
    errors << "#{name}: registry version differs from go.mod" if version_candidates.empty?
    if module_sum && version_candidates.none? { |record| record.dig("component", "digest", "value") == module_sum }
      errors << "#{name}: registry module checksum differs from #{sum_label}"
    end
    if go_mod_sum && version_candidates.none? { |record| record.dig("component", "module_file_digest", "value") == go_mod_sum }
      errors << "#{name}: registry go.mod checksum differs from #{sum_label}"
    end
    next if module_sum.nil? || go_mod_sum.nil?

    record = select_approved_candidate(
      records_by_name,
      name,
      {
        ["component", "kind"] => "go_module",
        ["component", "ecosystem"] => "go",
        ["component", "version"] => version,
        ["component", "digest", "value"] => module_sum,
        ["component", "module_file_digest", "value"] => go_mod_sum
      },
      errors,
      label: "#{name}@#{version}"
    )
    selected_records << record if record
  end

  pgx_record = selected_records.find { |record| record.dig("component", "name") == "github.com/jackc/pgx/v5" }
  allowed_indirect = pgx_record ? go_closures_by_approval_id[pgx_record["approval_id"]] : {}
  if pgx_record && allowed_indirect.nil?
    errors << "go.mod: approved pgx candidate #{pgx_record['approval_id']} has no approval-ID-bound runtime closure"
    allowed_indirect = {}
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
    errors << "go.mod: approval-ID-bound pgxpool runtime closure is incomplete: #{missing.to_a.sort.join(', ')}" unless missing.empty?
  elsif !(active_names & expected_names).empty?
    errors << "go.mod: pgxpool transitive modules may not be active without direct github.com/jackc/pgx/v5"
  end

  { "direct" => dependencies, "requirements" => requirements, "selected_records" => selected_records }
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

def validate_oci_workflow_images(workflow_sources, records_by_name, errors)
  references = workflow_sources.flat_map do |label, source|
    oci_workflow_references(source, errors, label)
  end
  references.each do |reference|
    name = reference["name"]
    candidates = candidate_records(records_by_name, name).select do |record|
      record.dig("component", "kind") == "oci_image" && record.dig("component", "ecosystem") == "oci"
    end
    if candidates.empty?
      errors << "dependency registry: workflow OCI image #{name} has no oci_image candidate record"
      next
    end

    if reference["version"] && candidates.none? { |record| record.dig("component", "version") == reference["version"] }
      errors << "#{name}: registry version differs from workflow image tag"
    end
    if candidates.none? { |record| record.dig("component", "digest", "value") == reference["digest"] }
      errors << "#{name}: workflow image digest differs from approval registry"
    end
    identity = {
      ["component", "kind"] => "oci_image",
      ["component", "ecosystem"] => "oci",
      ["component", "digest", "value"] => reference["digest"]
    }
    identity[["component", "version"]] = reference["version"] if reference["version"]
    record = select_approved_candidate(records_by_name, name, identity, errors, label: name)
    reference["approval_id"] = record["approval_id"] if record
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

def decision_state_errors(record)
  name = record.dig("component", "name")
  decision = record.fetch("decision", {})
  status = decision["status"]
  approvers = Array(decision["approvers"])
  approved_at = decision["approved_at"]
  reason_codes = Array(decision["reason_codes"])
  evidence_refs = Array(decision["evidence_refs"])
  errors = []

  if decision["category"] == "UNKNOWN" && status != "REJECTED"
    errors << "#{name}: UNKNOWN license category must remain rejected and quarantined"
  end

  case status
  when "REVIEWED_PENDING_INDEPENDENT_APPROVAL"
    errors << "#{name}: pending candidate must not name approvers" unless approvers.empty?
    errors << "#{name}: pending candidate must not have approved_at" unless approved_at.nil?
    errors << "#{name}: pending candidate must not carry rejection reason codes" unless reason_codes.empty?
    errors << "#{name}: pending candidate must not carry rejection evidence references" unless evidence_refs.empty?
  when "REJECTED"
    errors << "#{name}: rejected candidate must not name approvers" unless approvers.empty?
    errors << "#{name}: rejected candidate must not have approved_at" unless approved_at.nil?
    errors << "#{name}: rejected candidate requires stable reason codes" if reason_codes.empty?
    errors << "#{name}: rejected candidate requires stable evidence references" if evidence_refs.empty?
  when "APPROVED"
    errors << "#{name}: approval requires at least two recorded independent identities" if approvers.length < 2
    errors << "#{name}: approval requires approved_at" if approved_at.nil?
    errors << "#{name}: approved candidate must not retain rejection reason codes" unless reason_codes.empty?
    errors << "#{name}: approved candidate must not retain rejection evidence references" unless evidence_refs.empty?
  end

  errors
end

def exact_rejected_candidate_errors(records_by_id)
  errors = EXPECTED_REJECTED_DECISIONS.filter_map do |approval_id, expected|
    record = records_by_id[approval_id]
    if record.nil?
      "dependency registry: missing rejected evidence record #{approval_id}"
    elsif record["decision"] != expected
      "#{approval_id}: rejected decision or its immutable reason/evidence binding differs from the reviewed disposition"
    end
  end
  postgres_record = records_by_id[REJECTED_POSTGRES_APPROVAL_ID]
  if postgres_record && postgres_record.dig("component", "license_expression") != "NOASSERTION"
    errors << "postgres: rejected image license must remain NOASSERTION"
  end
  pgx_record = records_by_id[REJECTED_PGX_APPROVAL_ID]
  if pgx_record
    obligations = pgx_record.fetch("obligations", {})
    unless obligations["notices"] == REJECTED_PGX_NOTICE_IDS
      errors << "github.com/jackc/pgx/v5: rejected notice obligations must remain the exact six reviewed IDs"
    end
    unless obligations["notice_quarantine"] == PGX_NOTICE_QUARANTINE_BINDING
      errors << "github.com/jackc/pgx/v5: rejected notice quarantine binding differs from the reviewed fail-closed framing"
    end
  end
  errors
end

def nested_value(value, path)
  path.reduce(value) do |cursor, key|
    if cursor.is_a?(Hash)
      cursor[key]
    elsif cursor.is_a?(Array) && key.is_a?(Integer)
      cursor[key]
    end
  end
end

def pgxpool_closure_errors(evidence)
  closure = Array(evidence.dig("go_candidate", "pgxpool_module_closure"))
  actual = closure.to_h do |entry|
    [
      entry["module"],
      [entry["version"], entry["module_sum"], entry["go_mod_sum"], entry["upstream_commit"], entry["license_expression"], entry["notice_id"]]
    ]
  end
  return [] if closure.length == EXPECTED_PGXPOOL_CLOSURE.length && actual == EXPECTED_PGXPOOL_CLOSURE

  ["dependency-evidence/stead-p1-015-postgresql.yaml: pgxpool module closure and notice linkage differ from the reviewed intake"]
end

def postgresql_rejection_evidence_errors(evidence)
  errors = EXPECTED_POSTGRESQL_REJECTION_EVIDENCE.filter_map do |path, expected|
    actual = nested_value(evidence, path)
    next if actual == expected

    "dependency-evidence/stead-p1-015-postgresql.yaml: #{path.join('.')} must preserve rejected finding #{expected.inspect}"
  end
  errors.concat(pgxpool_closure_errors(evidence))
end

# Approval identity and reviewed artifact metadata are data, not locked Markdown prose.
def postgresql_successor_errors(records_by_id, evidence)
  errors = []
  intake = evidence.fetch("successor_intake", {})
  approvals = evidence.dig("successor_approval", "candidates") || {}
  %w[go_candidate oci_candidate].each do |key|
    candidate = intake.fetch(key, {})
    id = candidate["approval_id"]
    record = records_by_id[id]
    approval = approvals[id]
    next if record && record.dig("decision", "status") != "APPROVED" && approval.nil?
    unless record && approval
      errors << "dependency evidence: missing exact successor record or approval for #{key}"
      next
    end
    digest = candidate[key == "go_candidate" ? "module_sum" : "index_digest"]
    errors << "#{id}: reviewed version/digest mismatch" unless record.dig("component", "version") == candidate["version"] && record.dig("component", "digest", "value") == digest
    errors << "#{id}: approval identity mismatch" unless approval["approvers"] == record.dig("decision", "approvers") && approval["approved_at"] == record.dig("decision", "approved_at")
    errors << "#{id}: missing immutable review binding" unless approval["candidate_revision"]&.match?(/\A[0-9a-f]{40}\z/) && approval["evidence_manifest_sha256"]&.match?(/\A[0-9a-f]{64}\z/)
    errors << "#{id}: activation requires reviewed proof and rescan" unless approval.values_at("activation_allowed", "rescan", "functional_proof") == [true, "PASS", "PASS"]
    if key == "oci_candidate"
      errors << "#{id}: test image may not be distributed" unless record.dig("usage", "distributed_in") == [] && record.dig("usage", "relationship") == "test" && candidate["distribution_allowed"] == false
    else
      closure = Array(candidate["pgxpool_runtime_closure"])
      notices = [candidate["notice_id"], *closure.map { |entry| entry["notice_id"] }]
      errors << "#{id}: notice coverage differs from reviewed closure" unless record.dig("obligations", "notices") == notices
      errors << "#{id}: duplicate or missing runtime closure" unless closure.length == 5 && closure.map { |entry| entry["module"] }.uniq.length == closure.length
    end
  end
  errors
end

def notice_quarantine_errors(source)
  errors = []
  begin_count = source.scan(Regexp.new(Regexp.escape(PGX_NOTICE_QUARANTINE_BEGIN))).length
  end_count = source.scan(Regexp.new(Regexp.escape(PGX_NOTICE_QUARANTINE_END))).length
  errors << "THIRD_PARTY_NOTICES.md: rejected notice quarantine begin marker must occur exactly once" unless begin_count == 1
  errors << "THIRD_PARTY_NOTICES.md: rejected notice quarantine end marker must occur exactly once" unless end_count == 1
  return errors unless begin_count == 1 && end_count == 1

  begin_index = source.index(PGX_NOTICE_QUARANTINE_BEGIN)
  end_index = source.index(PGX_NOTICE_QUARANTINE_END)
  unless begin_index < end_index
    errors << "THIRD_PARTY_NOTICES.md: rejected notice quarantine markers are reversed"
    return errors
  end

  section = source[(begin_index + PGX_NOTICE_QUARANTINE_BEGIN.length)...end_index]
  expected_opening = "\n\n#{PGX_NOTICE_QUARANTINE_HEADING}\n\n#{PGX_NOTICE_QUARANTINE_FRAMING}\n\n"
  unless section.start_with?(expected_opening)
    errors << "THIRD_PARTY_NOTICES.md: rejected notice quarantine heading/framing differs from the exact evidence-only contract"
  end

  section_notice_ids = section.scan(/^## (NOTICE-[A-Z0-9-]+)(?:[ \t]|$)/).flatten
  unless section_notice_ids == REJECTED_PGX_NOTICE_IDS
    errors << "THIRD_PARTY_NOTICES.md: rejected quarantine must contain exactly the six reviewed notice IDs in closure order"
  end
  REJECTED_PGX_NOTICE_IDS.each do |notice_id|
    occurrence_count = source.scan(/^## #{Regexp.escape(notice_id)}(?:[ \t]|$)/).length
    unless occurrence_count == 1
      errors << "THIRD_PARTY_NOTICES.md: #{notice_id} must occur exactly once inside the rejected quarantine"
    end
  end

  outside = source[0...begin_index] + source[(end_index + PGX_NOTICE_QUARANTINE_END.length)..]
  REJECTED_PGX_NOTICE_IDS.each do |notice_id|
    if outside.match?(/^## #{Regexp.escape(notice_id)}(?:[ \t]|$)/)
      errors << "THIRD_PARTY_NOTICES.md: #{notice_id} appears outside the rejected quarantine"
    end
  end
  errors
end

def notice_entry_range(source, notice_id)
  heading = /^## #{Regexp.escape(notice_id)}(?:[ \t].*)?$/
  start_index = source.index(heading)
  return nil unless start_index

  next_notice = source.index(/^## NOTICE-[A-Z0-9-]+(?:[ \t].*)?$/, start_index + 1)
  quarantine_end = source.index(PGX_NOTICE_QUARANTINE_END, start_index + 1)
  end_index = [next_notice, quarantine_end].compact.min
  end_index ? (start_index...end_index) : nil
end

def delete_nested_key!(value, path)
  parent = path[0...-1].reduce(value) { |cursor, key| cursor.fetch(key) }
  parent.delete(path.last)
end

def run_validator_self_tests
  guard_count = 7
  pending_go = {
    "approval_id" => "DEP-APP-TEST-GO-PENDING",
    "component" => {
      "name" => "example.com/db", "kind" => "go_module", "ecosystem" => "go", "version" => "v1.2.3",
      "digest" => { "algorithm" => "go-h1", "value" => "h1:#{'a' * 43}=" },
      "module_file_digest" => { "algorithm" => "go-h1", "value" => "h1:#{'b' * 43}=" }
    },
    "decision" => { "status" => "REVIEWED_PENDING_INDEPENDENT_APPROVAL" }
  }
  pending_oci = {
    "approval_id" => "DEP-APP-TEST-OCI-PENDING",
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

  rejected_go = Marshal.load(Marshal.dump(pending_go))
  rejected_go["approval_id"] = "DEP-APP-TEST-GO-REJECTED"
  rejected_go["component"]["name"] = "example.com/rejected-db"
  rejected_go["decision"] = {
    "status" => "REJECTED", "approvers" => [], "approved_at" => nil,
    "reason_codes" => ["REACHABLE_KNOWN_VULNERABILITY"], "evidence_refs" => ["evidence/rejected-db"]
  }
  rejected_oci = Marshal.load(Marshal.dump(pending_oci))
  rejected_oci["approval_id"] = "DEP-APP-TEST-OCI-REJECTED"
  rejected_oci["component"]["name"] = "rejected-postgres"
  rejected_oci["decision"] = {
    "status" => "REJECTED", "approvers" => [], "approved_at" => nil,
    "reason_codes" => ["UNRESOLVED_CRITICAL_HIGH_FINDINGS"], "evidence_refs" => ["evidence/rejected-postgres"]
  }
  rejected_components = {
    "example.com/rejected-db" => rejected_go,
    "rejected-postgres" => rejected_oci
  }
  rejected_go_activation_errors = []
  rejected_go_sum = "example.com/rejected-db v1.2.3 h1:#{'a' * 43}=\nexample.com/rejected-db v1.2.3/go.mod h1:#{'b' * 43}=\n"
  validate_go_dependencies(
    "module fixture\nrequire example.com/rejected-db v1.2.3\n",
    rejected_go_sum,
    rejected_components,
    rejected_go_activation_errors,
    mod_label: "rejected.mod",
    sum_label: "rejected.sum"
  )
  failures << "rejected Go module activation mutation was accepted" unless rejected_go_activation_errors.any? { |error| error.include?("not approved for use") }

  rejected_oci_activation_errors = []
  rejected_oci_source = "services:\n  db:\n    image: rejected-postgres:16-bookworm@sha256:#{'a' * 64}\n"
  validate_oci_workflow_images({ "rejected.yml" => rejected_oci_source }, rejected_components, rejected_oci_activation_errors)
  failures << "rejected OCI image activation mutation was accepted" unless rejected_oci_activation_errors.any? { |error| error.include?("not approved for use") }
  guard_count += 2

  rejected_release_errors = release_approval_errors(Set.new(rejected_components.keys), rejected_components, ["APPROVED"])
  failures << "rejected Go module mutation became release eligible" unless rejected_release_errors.any? { |error| error.start_with?("example.com/rejected-db:") }
  failures << "rejected OCI image mutation became release eligible" unless rejected_release_errors.any? { |error| error.start_with?("rejected-postgres:") }
  guard_count += 2

  rejected_with_approval = Marshal.load(Marshal.dump(rejected_go))
  rejected_with_approval["decision"]["approvers"] = ["self-approval"]
  rejected_with_approval["decision"]["approved_at"] = "2026-08-30T21:35:54Z"
  approval_metadata_errors = decision_state_errors(rejected_with_approval)
  unless approval_metadata_errors.any? { |error| error.include?("must not name approvers") } &&
         approval_metadata_errors.any? { |error| error.include?("must not have approved_at") }
    failures << "rejected candidate approval metadata mutation was accepted"
  end
  guard_count += 1

  registry_fixture = load_yaml(REGISTRY_PATH)
  registry_records_by_id = registry_fixture.fetch("records").to_h { |record| [record.fetch("approval_id"), record] }
  failures << "approval-ID lookup lost rejected history beside a same-name successor" unless exact_rejected_candidate_errors(registry_records_by_id).empty?

  exact_identity = {
    ["component", "kind"] => "go_module",
    ["component", "version"] => pending_go.dig("component", "version"),
    ["component", "digest", "value"] => pending_go.dig("component", "digest", "value"),
    ["component", "module_file_digest", "value"] => pending_go.dig("component", "module_file_digest", "value")
  }
  rejected_history = Marshal.load(Marshal.dump(pending_go))
  rejected_history["decision"]["status"] = "REJECTED"
  selection_errors = []
  select_approved_candidate({ "example.com/db" => [rejected_history, pending_go] }, "example.com/db", exact_identity, selection_errors)
  failures << "pending successor activation was accepted" unless selection_errors.any? { |error| error.include?("not approved for use") }

  approved_successor = Marshal.load(Marshal.dump(pending_go))
  approved_successor["decision"]["status"] = "APPROVED"
  selection_errors = []
  selection = select_approved_candidate({ "example.com/db" => [rejected_history, approved_successor] }, "example.com/db", exact_identity, selection_errors)
  failures << "one approved exact successor was not selected" unless selection == approved_successor && selection_errors.empty?
  duplicate_approved = Marshal.load(Marshal.dump(approved_successor))
  duplicate_approved["approval_id"] = "DEP-APP-TEST-DUPLICATE-APPROVAL"
  ambiguous_errors = []
  ambiguous = select_approved_candidate({ "example.com/db" => [approved_successor, duplicate_approved] }, "example.com/db", exact_identity, ambiguous_errors)
  failures << "two approved exact records did not fail closed as ambiguous" unless ambiguous.nil? && ambiguous_errors.any? { |error| error.include?("multiple approved exact candidate") }

  approved_without_evidence = Marshal.load(Marshal.dump(registry_records_by_id))
  approved_without_evidence.fetch(SUCCESSOR_PGX_APPROVAL_ID)["decision"] = {
    "category" => "ALLOW-PERMISSIVE",
    "status" => "APPROVED",
    "independent_approval_required" => true,
    "approvers" => ["independent-qa", "independent-security"],
    "approved_at" => "2026-09-04T16:30:00Z"
  }
  missing_approval_evidence_errors = postgresql_successor_errors(approved_without_evidence, load_yaml(POSTGRESQL_EVIDENCE_PATH))
  unless missing_approval_evidence_errors.any? { |error| error.include?("approval identity mismatch") }
    failures << "successor was approved without exact-revision approval evidence"
  end

  approved_pgx = Marshal.load(Marshal.dump(registry_records_by_id.fetch(SUCCESSOR_PGX_APPROVAL_ID)))
  approved_pgx["decision"]["status"] = "APPROVED"
  pgx_sum = "github.com/jackc/pgx/v5 v5.10.0 #{approved_pgx.dig('component', 'digest', 'value')}\n" \
            "github.com/jackc/pgx/v5 v5.10.0/go.mod #{approved_pgx.dig('component', 'module_file_digest', 'value')}\n"
  incomplete_closure_errors = []
  validate_go_dependencies(
    "module fixture\nrequire github.com/jackc/pgx/v5 v5.10.0\n",
    pgx_sum,
    { "github.com/jackc/pgx/v5" => [approved_pgx] },
    incomplete_closure_errors,
    go_closures_by_approval_id: { SUCCESSOR_PGX_APPROVAL_ID => load_yaml(POSTGRESQL_EVIDENCE_PATH).dig("successor_intake", "go_candidate", "pgxpool_runtime_closure").to_h do |entry|
    [entry.fetch("module"), entry.values_at("version", "module_sum", "go_mod_sum")]
  end },
    mod_label: "incomplete-successor.mod",
    sum_label: "incomplete-successor.sum"
  )
  failures << "incomplete approval-ID-bound pgx closure was accepted" unless incomplete_closure_errors.any? { |error| error.include?("runtime closure is incomplete") }
  guard_count += 6

  decision_mutation_survivors = []
  EXPECTED_REJECTED_DECISIONS.each do |approval_id, expected_decision|
    expected_decision.each_key do |field|
      mutated_records = Marshal.load(Marshal.dump(registry_records_by_id))
      mutated_records.fetch(approval_id).fetch("decision").delete(field)
      decision_mutation_survivors << "#{approval_id}.decision.#{field}" if exact_rejected_candidate_errors(mutated_records).empty?
      guard_count += 1
    end
  end
  failures << "exact rejected-decision mutation survivors: #{decision_mutation_survivors.join(', ')}" unless decision_mutation_survivors.empty?

  softened_decision_mutations = [
    [REJECTED_PGX_APPROVAL_ID, "status", "APPROVED"],
    [REJECTED_PGX_APPROVAL_ID, "reason_codes", ["RISK_ACCEPTED"]],
    [REJECTED_POSTGRES_APPROVAL_ID, "category", "REVIEW-NONRUNTIME"],
    [REJECTED_POSTGRES_APPROVAL_ID, "reason_codes", ["SCAN_REVIEWED"]]
  ]
  softened_decision_survivors = []
  softened_decision_mutations.each do |approval_id, field, replacement|
    mutated_records = Marshal.load(Marshal.dump(registry_records_by_id))
    mutated_records.fetch(approval_id).fetch("decision")[field] = replacement
    softened_decision_survivors << "#{approval_id}.decision.#{field}" if exact_rejected_candidate_errors(mutated_records).empty?
    guard_count += 1
  end
  failures << "rejected decision softening mutation survivors: #{softened_decision_survivors.join(', ')}" unless softened_decision_survivors.empty?

  notice_obligation_mutations = {
    "notices empty" => lambda { |record| record.fetch("obligations")["notices"] = [] },
    "notices removed" => lambda { |record| record.fetch("obligations").delete("notices") },
    "notice ID changed" => lambda { |record| record.fetch("obligations").fetch("notices")[0] = "NOTICE-APPROVED-STYLE" },
    "quarantine binding removed" => lambda { |record| record.fetch("obligations").delete("notice_quarantine") },
    "quarantine marker changed" => lambda do |record|
      record.fetch("obligations").fetch("notice_quarantine")["marker"] = "APPROVED-NOTICE-INPUT"
    end
  }
  notice_obligation_survivors = []
  notice_obligation_mutations.each do |label, mutation|
    mutated_records = Marshal.load(Marshal.dump(registry_records_by_id))
    mutation.call(mutated_records.fetch(REJECTED_PGX_APPROVAL_ID))
    notice_obligation_survivors << label if exact_rejected_candidate_errors(mutated_records).empty?
    guard_count += 1
  end
  unless notice_obligation_survivors.empty?
    failures << "rejected notice-obligation mutation survivors: #{notice_obligation_survivors.join(', ')}"
  end

  softened_license_records = Marshal.load(Marshal.dump(registry_records_by_id))
  softened_license_records.fetch(REJECTED_POSTGRES_APPROVAL_ID).fetch("component")["license_expression"] = "MIT"
  if exact_rejected_candidate_errors(softened_license_records).empty?
    failures << "rejected OCI license softening mutation was accepted"
  end
  guard_count += 1

  evidence_fixture = load_yaml(POSTGRESQL_EVIDENCE_PATH)
  evidence_mutation_survivors = []
  EXPECTED_POSTGRESQL_REJECTION_EVIDENCE.each_key do |path|
    mutated_evidence = Marshal.load(Marshal.dump(evidence_fixture))
    delete_nested_key!(mutated_evidence, path)
    evidence_mutation_survivors << path.join(".") if postgresql_rejection_evidence_errors(mutated_evidence).empty?
    guard_count += 1
  end
  failures << "rejected evidence deletion mutation survivors: #{evidence_mutation_survivors.join(', ')}" unless evidence_mutation_survivors.empty?

  softened_evidence_mutations = {
    ["independent_review", "release_eligible"] => true,
    ["go_candidate", "notice_id"] => "NOTICE-PGPASSFILE-MIT",
    ["go_candidate", "vulnerability_scan", "status"] => "PASS",
    ["go_candidate", "possible_successor", "status"] => "APPROVED",
    ["oci_candidate", "vulnerability_scan", "status"] => "PASS",
    ["oci_candidate", "signature_attestation_review", "status"] => "VERIFIED"
  }
  softened_evidence_survivors = []
  softened_evidence_mutations.each do |path, replacement|
    mutated_evidence = Marshal.load(Marshal.dump(evidence_fixture))
    parent = path[0...-1].reduce(mutated_evidence) { |cursor, key| cursor.fetch(key) }
    parent[path.last] = replacement
    softened_evidence_survivors << path.join(".") if postgresql_rejection_evidence_errors(mutated_evidence).empty?
    guard_count += 1
  end
  failures << "rejected evidence softening mutation survivors: #{softened_evidence_survivors.join(', ')}" unless softened_evidence_survivors.empty?

  closure_notice_survivors = []
  closure = evidence_fixture.fetch("go_candidate").fetch("pgxpool_module_closure")
  closure.each_index do |index|
    module_name = closure.fetch(index).fetch("module")

    removed = Marshal.load(Marshal.dump(evidence_fixture))
    removed.dig("go_candidate", "pgxpool_module_closure", index).delete("notice_id")
    if postgresql_rejection_evidence_errors(removed).empty?
      closure_notice_survivors << "#{module_name}.notice_id removed"
    end
    guard_count += 1

    changed = Marshal.load(Marshal.dump(evidence_fixture))
    changed.dig("go_candidate", "pgxpool_module_closure", index)["notice_id"] = "NOTICE-APPROVED-STYLE"
    if postgresql_rejection_evidence_errors(changed).empty?
      closure_notice_survivors << "#{module_name}.notice_id changed"
    end
    guard_count += 1

    relinked = Marshal.load(Marshal.dump(evidence_fixture))
    next_index = (index + 1) % closure.length
    relinked.dig("go_candidate", "pgxpool_module_closure", index)["notice_id"] = closure.fetch(next_index).fetch("notice_id")
    if postgresql_rejection_evidence_errors(relinked).empty?
      closure_notice_survivors << "#{module_name}.notice_id relinked"
    end
    guard_count += 1
  end
  unless closure_notice_survivors.empty?
    failures << "pgxpool closure notice-link mutation survivors: #{closure_notice_survivors.join(', ')}"
  end

  evidence_quarantine_mutations = {
    "marker removed" => lambda { |binding| binding.delete("marker") },
    "marker approved-style relabel" => lambda { |binding| binding["marker"] = "APPROVED-NOTICE-INPUT" },
    "section heading removed" => lambda { |binding| binding.delete("section_heading") },
    "framing removed" => lambda { |binding| binding.delete("framing") },
    "release input softened" => lambda { |binding| binding["release_notice_input"] = true }
  }
  evidence_quarantine_survivors = []
  evidence_quarantine_mutations.each do |label, mutation|
    mutated_evidence = Marshal.load(Marshal.dump(evidence_fixture))
    mutation.call(mutated_evidence.dig("go_candidate", "notice_quarantine"))
    if postgresql_rejection_evidence_errors(mutated_evidence).empty?
      evidence_quarantine_survivors << label
    end
    guard_count += 1
  end
  unless evidence_quarantine_survivors.empty?
    failures << "evidence notice-quarantine mutation survivors: #{evidence_quarantine_survivors.join(', ')}"
  end

  notices_fixture = File.read(NOTICES_PATH)
  source_mutations = {
    "begin marker removed" => notices_fixture.sub(PGX_NOTICE_QUARANTINE_BEGIN, ""),
    "end marker removed" => notices_fixture.sub(PGX_NOTICE_QUARANTINE_END, ""),
    "section heading removed" => notices_fixture.sub(PGX_NOTICE_QUARANTINE_HEADING, ""),
    "framing removed" => notices_fixture.sub(PGX_NOTICE_QUARANTINE_FRAMING, ""),
    "approved-style section relabel" => notices_fixture.sub(PGX_NOTICE_QUARANTINE_HEADING, "## APPROVED — pgx v5.10.0 closure notices")
  }
  section_removed = notices_fixture.dup
  section_start = section_removed.index(PGX_NOTICE_QUARANTINE_BEGIN)
  section_end = section_removed.index(PGX_NOTICE_QUARANTINE_END) + PGX_NOTICE_QUARANTINE_END.length
  section_removed.slice!(section_start...section_end)
  source_mutations["quarantine section removed"] = section_removed

  REJECTED_PGX_NOTICE_IDS.each do |notice_id|
    range = notice_entry_range(notices_fixture, notice_id)
    if range.nil?
      failures << "self-test fixture cannot locate #{notice_id}"
      next
    end
    entry = notices_fixture[range]

    missing = notices_fixture.dup
    missing.slice!(range)
    source_mutations["#{notice_id} missing"] = missing

    duplicate = notices_fixture.dup
    duplicate.insert(range.end, entry)
    source_mutations["#{notice_id} duplicated"] = duplicate

    moved = notices_fixture.dup
    moved.slice!(range)
    moved.insert(moved.index(PGX_NOTICE_QUARANTINE_BEGIN), "#{entry}\n")
    source_mutations["#{notice_id} moved outside quarantine"] = moved
  end

  notice_source_survivors = source_mutations.filter_map do |label, mutated_source|
    guard_count += 1
    label if notice_quarantine_errors(mutated_source).empty?
  end
  unless notice_source_survivors.empty?
    failures << "THIRD_PARTY_NOTICES quarantine mutation survivors: #{notice_source_survivors.join(', ')}"
  end

  unless failures.empty?
    warn "dependency validator self-tests failed:"
    failures.each { |failure| warn "- #{failure}" }
    exit 1
  end
  puts "dependency validator self-tests passed: #{guard_count}/#{guard_count} mutation guards"
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

records_by_id = records.to_h { |record| [record["approval_id"], record] }
records_by_name = records.group_by { |record| record.dig("component", "name") }
components = records_by_name.transform_values do |candidates|
  candidates.length == 1 ? candidates.first : candidates.find { |record| record.dig("decision", "status") == "APPROVED" }
end

records.each do |record|
  name = record.dig("component", "name")
  digest = record.dig("component", "digest", "value")
  algorithm = record.dig("component", "digest", "algorithm")
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
  license_expression = record.dig("component", "license_expression")
  if license_expression&.match?(/\bNOASSERTION\b/i)
    errors << "#{name}: NOASSERTION license requires UNKNOWN category" unless record.dig("decision", "category") == "UNKNOWN"
    errors << "#{name}: NOASSERTION license must remain rejected" unless record.dig("decision", "status") == "REJECTED"
  end
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

  errors.concat(decision_state_errors(record))

  errors << "#{name}: rollback target must be the immutable Phase 0 baseline" unless rollback_version == FOUNDATION_ROLLBACK_TARGET
end
errors.concat(exact_rejected_candidate_errors(records_by_id))

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
  ["candidate_state"] => "REJECTED_QUARANTINED_NOT_INTEGRATED",
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
  ["oci_candidate", "created"] => "2026-08-25T00:42:19.848754437Z"
}
expected_postgresql_evidence.each do |path, expected|
  actual = path.reduce(postgresql_evidence) { |cursor, key| cursor.is_a?(Hash) ? cursor[key] : nil }
  errors << "dependency-evidence/stead-p1-015-postgresql.yaml: #{path.join(".")} must equal #{expected.inspect}" unless actual == expected
end

errors.concat(postgresql_rejection_evidence_errors(postgresql_evidence))
errors.concat(postgresql_successor_errors(records_by_id, postgresql_evidence))

pgx_record = records_by_id[REJECTED_PGX_APPROVAL_ID]
if pgx_record
  errors << "github.com/jackc/pgx/v5: registry artifact checksum differs from intake evidence" unless pgx_record.dig("component", "digest", "value") == postgresql_evidence.dig("go_candidate", "module_sum")
  errors << "github.com/jackc/pgx/v5: registry go.mod checksum differs from intake evidence" unless pgx_record.dig("component", "module_file_digest", "value") == postgresql_evidence.dig("go_candidate", "go_mod_sum")
end
postgres_record = records_by_id[REJECTED_POSTGRES_APPROVAL_ID]
if postgres_record
  errors << "postgres: registry index digest differs from intake evidence" unless postgres_record.dig("component", "digest", "value") == postgresql_evidence.dig("oci_candidate", "index_digest")
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
go_closures_by_approval_id = {
  SUCCESSOR_PGX_APPROVAL_ID => postgresql_evidence.dig("successor_intake", "go_candidate", "pgxpool_runtime_closure").to_h do |entry|
    [entry.fetch("module"), entry.values_at("version", "module_sum", "go_mod_sum")]
  end
}
go_validation = validate_go_dependencies(
  go_mod_source,
  go_sum_source,
  records_by_name,
  errors,
  go_closures_by_approval_id: go_closures_by_approval_id
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
oci_references = validate_oci_workflow_images(workflow_sources, records_by_name, errors)
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
errors.concat(notice_quarantine_errors(notices))
required_notices = records.select { |record| record.dig("decision", "status") == "APPROVED" }
                          .flat_map { |record| Array(record.dig("obligations", "notices")) }
                          .uniq
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
rejected = records.count { |record| record.dig("decision", "status") == "REJECTED" }
puts "dependency registry valid: #{records.length} exact candidate records; #{direct_dependencies.length} direct npm dependencies; #{direct_go.length} direct Go modules; #{oci_references.length} workflow OCI images; #{pending} pending independent approval; #{rejected} rejected/quarantined"
puts "transitive license review required before approval: #{review_licenses.to_a.sort.join(", ")}" unless review_licenses.empty?
puts "release eligibility verified for #{active_record_names.length} active dependencies" if release_mode
