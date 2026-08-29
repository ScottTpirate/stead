#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "open3"
require "pathname"
require "set"
require "yaml"

ROOT = Pathname.new(__dir__).join("../../..").expand_path
EXPECTED_TEST_IDS = %w[
  T-STEAD-P1-001-CONTRACT
  T-PRIN-002-ACCEPTANCE
  T-PRIN-005-ACCEPTANCE
  T-PRIN-006-ACCEPTANCE
  T-ARCH-001-ACCEPTANCE
  T-ARCH-002-ACCEPTANCE
  T-ARCH-005-ACCEPTANCE
  T-STD-001-ACCEPTANCE
  T-SEC-001-ACCEPTANCE
  T-SEC-006-ACCEPTANCE
  T-ADR-0001-URI-GRAMMAR
  T-ADR-0001-SCOPE
  T-ADR-0001-KIND-ID
  T-ADR-0001-HOST-INDEPENDENCE
].freeze

REQUIRED_LAYOUT = %w[
  apps/web apps/core apps/worker apps/steadctl
  modules/organization modules/identity modules/authorization modules/classification
  modules/project modules/work modules/knowledge modules/scm modules/ci modules/artifact
  modules/search modules/notification modules/audit modules/agent modules/migration
  providers/gitea providers/commonplace providers/blob-filesystem providers/blob-s3
  providers/blob-azure providers/blob-gcs providers/search-postgres providers/search-opensearch
  providers/identity-oidc providers/identity-scim providers/agent-a2a
  providers/notifications-email providers/notifications-webhook
  packages/domain-schemas packages/provider-sdk packages/event-schemas packages/design-system
  packages/api-client packages/test-fixtures policies/openfga policies/policy-decision
  policies/security-label-profiles specs/openapi specs/asyncapi specs/work-graph-profile
  specs/okf-profile specs/oscal specs/traceability specs/mcp specs/a2a deploy/compose deploy/helm deploy/airgap
  deploy/examples tests/contract tests/integration tests/e2e tests/security tests/performance
  tests/upgrade tests/backup-restore tests/classification docs/architecture docs/adr
  docs/governance docs/planning docs/security docs/testing docs/operator docs/user docs/contributor
].freeze

ALLOWED_LOCK_LICENSES = Set.new(%w[
  0BSD Apache-2.0 BSD-2-Clause BSD-3-Clause ISC MIT
]).freeze

results = Hash.new { |hash, key| hash[key] = [] }

assert = lambda do |test_id, condition, message|
  raise "unknown test ID #{test_id}" unless EXPECTED_TEST_IDS.include?(test_id)

  results[test_id] << message unless condition
end

read = ->(path) { ROOT.join(path).read(encoding: "UTF-8") }
json = ->(path) { JSON.parse(read.call(path)) }
yaml = lambda do |path|
  YAML.safe_load(read.call(path), permitted_classes: [], permitted_symbols: [], aliases: false)
end

package = json.call("package.json")
web_package = json.call("apps/web/package.json")
lockfile = json.call("package-lock.json")
issue_catalog = yaml.call("docs/planning/implementation-issue-catalog.yaml")
foundation_issue = issue_catalog.fetch("issues").find { |issue| issue["id"] == "STEAD-P1-001" }

assert.call(
  "T-STEAD-P1-001-CONTRACT",
  foundation_issue && foundation_issue.fetch("automated_tests", []).to_set == EXPECTED_TEST_IDS.to_set,
  "STEAD-P1-001 must link exactly every executable foundation acceptance test"
)
assert.call(
  "T-STEAD-P1-001-CONTRACT",
  foundation_issue&.fetch("status", nil) == "COMPLETED_PHASE_1",
  "foundation issue must be complete after independent acceptance is recorded"
)

provenance = yaml.call("docs/governance/devlane-provenance.yaml")
assert.call(
  "T-PRIN-002-ACCEPTANCE",
  provenance.dig("upstream", "commit") == "7719dcadf91f881b5aefe8b74012ffcfbba0bc17" &&
    provenance.dig("upstream", "tree") == "a568d1d11bab6012ffce1345193dcb537fa43556" &&
    provenance.dig("import", "imported") == false,
  "Devlane must be reproducibly pinned and explicitly not imported"
)
go_sources = Dir.glob(ROOT.join("**/*.go")).reject { |path| path.include?("node_modules") }.map { |path| File.read(path) }.join("\n")
assert.call(
  "T-PRIN-002-ACCEPTANCE",
  !go_sources.match?(%r{code\.gitea\.io/gitea|/gitea/(?:models|modules|services)/}),
  "Stead Go code must not import Gitea internals"
)

app_roots = ROOT.join("apps").children.select(&:directory?).map(&:basename).map(&:to_s).sort
assert.call(
  "T-PRIN-005-ACCEPTANCE",
  app_roots == %w[core steadctl web worker],
  "foundation may expose only the four locked deployable roots"
)
agent_runtime_files = Dir.glob(ROOT.join("{modules/agent,providers/agent-a2a}/**/*.{go,js,jsx,ts,tsx}"))
assert.call(
  "T-PRIN-005-ACCEPTANCE",
  agent_runtime_files.empty?,
  "foundation must not introduce agent execution or A2A dispatch"
)

assert.call(
  "T-PRIN-006-ACCEPTANCE",
  package.dig("scripts", "validate:openapi")&.include?("redocly") &&
    package.dig("scripts", "validate:asyncapi") == "node scripts/validate_asyncapi.mjs" &&
    package.dig("scripts", "validate:schemas") == "node scripts/validate_json_schemas.mjs",
  "standards validators must be repository-owned and invoked through locked scripts"
)
assert.call(
  "T-PRIN-006-ACCEPTANCE",
  package.dig("devDependencies", "@asyncapi/specs") == "6.11.1" &&
    package.dig("devDependencies", "@redocly/cli") == "2.49.0",
  "OpenAPI and AsyncAPI checks must use exact standards-tool pins"
)

go_mod = read.call("go.mod")
tool_versions = read.call(".tool-versions")
assert.call(
  "T-ARCH-001-ACCEPTANCE",
  go_mod.include?("go 1.27.0") && tool_versions.include?("golang 1.27.0") &&
    tool_versions.include?("nodejs 26.8.1") && tool_versions.include?("ruby 3.4.10"),
  "language toolchains must be exact and mutually consistent"
)
assert.call(
  "T-ARCH-001-ACCEPTANCE",
  web_package.dig("dependencies", "react") == "19.2.4" &&
    web_package.dig("dependencies", "react-dom") == "19.2.4" &&
    web_package.dig("devDependencies", "typescript") == "5.9.3",
  "stead-web must use exact React and TypeScript pins"
)
component_source = read.call("internal/component/component.go")
assert.call(
  "T-ARCH-001-ACCEPTANCE",
  %w[stead-api stead-worker steadctl].all? do |name|
    Dir.glob(ROOT.join("apps/**/*.go")).any? { |path| File.read(path).include?(%Q{"#{name}"}) }
  end && !component_source.include?("platform-core"),
  "Go composition roots must expose only normalized Stead component names"
)

missing_layout = REQUIRED_LAYOUT.reject { |path| ROOT.join(path).directory? }
assert.call(
  "T-ARCH-002-ACCEPTANCE",
  missing_layout.empty?,
  "locked monorepo directories are missing: #{missing_layout.join(', ')}"
)

adr = read.call("docs/adr/0001-canonical-uri-and-compatibility-profile.md")
openapi = read.call("specs/openapi/platform-v1.yaml")
owgp = json.call("specs/work-graph-profile/owgp-v0.1.schema.json")
baseline_sha, _stderr, baseline_status = Open3.capture3("git", "rev-parse", "phase0^{}", chdir: ROOT.to_s)
assert.call(
  "T-ARCH-005-ACCEPTANCE",
  baseline_status.success? && baseline_sha.strip == "e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31",
  "compatibility baseline tag must resolve to the immutable Phase 0 commit"
)
assert.call(
  "T-ARCH-005-ACCEPTANCE",
  adr.include?("**Status:** Accepted") && owgp.dig("$defs", "CanonicalResourceUri") &&
    openapi.include?("Stead-Schema-Version"),
  "accepted URI/version profile must be reflected in OWGP and OpenAPI"
)

owgp_stdout, owgp_stderr, owgp_status = Open3.capture3(
  "scripts/run_pinned_node.sh", "node", "scripts/validate_owgp_examples.js", chdir: ROOT.to_s
)
%w[
  T-ADR-0001-URI-GRAMMAR
  T-ADR-0001-SCOPE
  T-ADR-0001-KIND-ID
  T-ADR-0001-HOST-INDEPENDENCE
].each do |test_id|
  assert.call(
    test_id,
    owgp_status.success? && owgp_stdout.include?("PASS #{test_id}"),
    "named OWGP contract evidence must execute successfully: #{owgp_stderr.strip}"
  )
end

deferred_adr_test_owners = {
  "T-ADR-0001-ALIAS" => "STEAD-P1-002",
  "T-ADR-0001-COMPAT" => "STEAD-P1-007",
  "T-ADR-0001-MIGRATION" => "STEAD-P1-011"
}
deferred_adr_test_owners.each do |test_id, issue_id|
  owner_issue = issue_catalog.fetch("issues").find { |issue| issue["id"] == issue_id }
  assert.call(
    "T-ARCH-005-ACCEPTANCE",
    owner_issue&.fetch("automated_tests", [])&.include?(test_id),
    "#{test_id} must be owned by its executable downstream issue #{issue_id}"
  )
end

standards = read.call("docs/architecture/standards-matrix.md")
assert.call(
  "T-STD-001-ACCEPTANCE",
  standards.include?("OpenAPI 3.1.1") && standards.include?("AsyncAPI 3.1") &&
    standards.include?("JSON Schema 2020-12") && standards.include?("CloudEvents 1.0"),
  "the locked standards matrix must remain present"
)
assert.call(
  "T-STD-001-ACCEPTANCE",
  !package.fetch("devDependencies").key?("@asyncapi/cli") &&
    !package.fetch("devDependencies").key?("ajv-cli"),
  "known vulnerable validator dependency trees must remain excluded"
)

dependency_stdout, dependency_stderr, dependency_status = Open3.capture3(
  "ruby", "scripts/validate_dependencies.rb", "--release", chdir: ROOT.to_s
)
assert.call(
  "T-SEC-001-ACCEPTANCE",
  dependency_status.success?,
  "dependency approvals/notices must be release-eligible: #{dependency_stderr.strip} #{dependency_stdout.strip}"
)
_allowed_stdout, _allowed_stderr, allowed_license_status = Open3.capture3(
  "ruby", "scripts/validate_dependencies.rb", "--test-lock-license", "MIT", chdir: ROOT.to_s
)
_unknown_stdout, _unknown_stderr, unknown_license_status = Open3.capture3(
  "ruby", "scripts/validate_dependencies.rb", "--test-lock-license", "MPL-2.0", chdir: ROOT.to_s
)
assert.call(
  "T-SEC-001-ACCEPTANCE",
  allowed_license_status.success? && !unknown_license_status.success?,
  "license policy must accept an allowlisted fixture and fail closed on a non-allowlisted fixture"
)
_rollback_stdout, _rollback_stderr, rollback_status = Open3.capture3(
  "ruby", "scripts/validate_dependencies.rb", "--test-rollback",
  "git:e24a4d9d05ad6df19c5bcaa9c385ee74fd5d8c31", chdir: ROOT.to_s
)
_floating_stdout, _floating_stderr, floating_rollback_status = Open3.capture3(
  "ruby", "scripts/validate_dependencies.rb", "--test-rollback", "latest-known-good", chdir: ROOT.to_s
)
assert.call(
  "T-SEC-001-ACCEPTANCE",
  rollback_status.success? && !floating_rollback_status.success?,
  "foundation rollback policy must accept only the immutable Phase 0 target"
)
lock_license_failures = lockfile.fetch("packages").filter_map do |path, entry|
  next if path.empty? || entry["link"]
  next if ALLOWED_LOCK_LICENSES.include?(entry["license"])

  "#{path}=#{entry['license'] || 'MISSING'}"
end
assert.call(
  "T-SEC-001-ACCEPTANCE",
  lock_license_failures.empty?,
  "lockfile contains unapproved or unknown licenses: #{lock_license_failures.join(', ')}"
)

manifest_names = [package, web_package].flat_map do |manifest|
  %w[dependencies devDependencies optionalDependencies].flat_map { |key| manifest.fetch(key, {}).keys }
end
analytics = manifest_names.grep(/(?:analytics|amplitude|datadog|fullstory|mixpanel|posthog|segment|sentry)/i)
web_source = Dir.glob(ROOT.join("apps/web/src/**/*")).select { |path| File.file?(path) }.map { |path| File.read(path) }.join("\n")
workflow = read.call(".github/workflows/ci.yml")
assert.call(
  "T-SEC-006-ACCEPTANCE",
  analytics.empty? && !web_source.match?(%r{https?://}),
  "foundation must include no analytics dependency or default outbound browser endpoint"
)
assert.call(
  "T-SEC-006-ACCEPTANCE",
  workflow.include?("DO_NOT_TRACK") && workflow.include?("REDOCLY_TELEMETRY"),
  "CI must explicitly suppress optional tool telemetry"
)

failed = results.select { |_test_id, failures| !failures.empty? }
EXPECTED_TEST_IDS.each do |test_id|
  if results[test_id].empty?
    puts "PASS #{test_id}"
  else
    results[test_id].each { |failure| warn "FAIL #{test_id}: #{failure}" }
  end
end

if failed.empty?
  puts "Foundation contract validation passed: #{EXPECTED_TEST_IDS.length}/#{EXPECTED_TEST_IDS.length} named tests."
  exit 0
end

warn "Foundation contract validation failed: #{failed.length} named test(s)."
exit 1
