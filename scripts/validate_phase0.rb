#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require "set"
require "digest"
require "json"
require "open3"

ROOT = File.expand_path("..", __dir__)
DIRECTIVE_PATH = File.join(ROOT, "docs/architecture/MASTER_BUILD_DIRECTIVE.md")
INVENTORY_PATH = File.join(ROOT, "specs/traceability/directive-inventory.yaml")
REQUIREMENTS_PATH = File.join(ROOT, "specs/traceability/requirements.yaml")
ISSUES_PATH = File.join(ROOT, "docs/planning/implementation-issue-catalog.yaml")
SECURITY_FINDINGS_PATH = File.join(ROOT, "specs/traceability/security-findings.yaml")
WORKSTREAM_OWNERSHIP_PATH = File.join(ROOT, "docs/architecture/workstream-ownership.md")
ADR_CANDIDATE_INDEX_PATH = File.join(ROOT, "docs/governance/adr-candidate-index.md")

EXPECTED_DIRECTIVE_VERSION = "0.2"
EXPECTED_REQUIREMENT_COUNT = 128
EXPECTED_AGENT_IDS = (1..7).map { |number| format("AGENT-%03d", number) }.freeze
EXPECTED_V02_IDS = %w[PRIN-013 PRIN-014 PRIN-015 DOM-008 DOM-009 DOM-010 DOM-011 UX-006 UX-007 UX-008 UX-009 AUTH-006 TEST-010].freeze
EXPECTED_THREAT_IDS = (1..33).map { |number| format("TM-F%03d", number) }.freeze
EXPECTED_BYPASS_IDS = (1..47).map { |number| format("CBI-%03d", number) }.freeze
EXPECTED_WORKSTREAM_IDS = (1..13).map { |number| format("WS-%02d", number) }.freeze
EXPECTED_ADR_CANDIDATE_IDS = (1..21).map { |number| format("ADR-CAND-%03d", number) }.freeze
EXPECTED_MACHINE_ADR_GATE_IDS = ((1..8).to_a + [21]).map { |number| format("ADR-CAND-%03d", number) }.freeze
APPROVAL_GATE_ID = "GATE-P0-APPROVED"
EXPECTED_GATE_APPROVERS = %w[
  project-owner
  WS-01-architecture
  WS-06-security-contract
  WS-13-independent-qa
  WS-13-independent-security
].freeze
VALID_PHASES = %w[phase-0 phase-1 phase-2 phase-3].freeze
BLOCKED_PHASES = %w[phase-1 phase-2 phase-3].freeze
BLOCKED_STATUS = "BLOCKED_PENDING_PHASE_0_APPROVAL"
PHASE_ZERO_READY_STATUS = "READY_FOR_PHASE_0_APPROVAL"

REQUIRED_PHASE_ZERO_FILES = %w[
  README.md
  docs/adr/INDEX.md
  docs/adr/unresolved-implementation-choices.md
  docs/architecture/MASTER_BUILD_DIRECTIVE.md
  docs/architecture/PHASE0_RECONCILIATION_REPORT.md
  docs/architecture/activity-model.md
  docs/architecture/agent-access.md
  docs/architecture/agent-ready-compatibility.md
  docs/architecture/artifact-and-package-model.md
  docs/architecture/constitution.md
  docs/architecture/contract-ownership-matrix.md
  docs/architecture/repository-layout-and-boundaries.md
  docs/architecture/workstream-ownership.md
  docs/architecture/canonical-domain-model.md
  docs/architecture/product-and-ux-contracts.md
  docs/architecture/authorization-contract.md
  docs/architecture/blobstore-contract.md
  docs/architecture/ci-runner-and-secrets-contract.md
  docs/architecture/deployment-profiles.md
  docs/architecture/security-label-lattice.md
  docs/architecture/standards-matrix.md
  docs/architecture/knowledge-contract.md
  docs/architecture/provider-contracts/gitea.md
  docs/architecture/search-resource-model.md
  docs/architecture/search-contract.md
  docs/architecture/search-graph/mcp-a2a-compatibility.md
  docs/architecture/work-graph.md
  docs/architecture/event-contract.md
  docs/architecture/notification-contract.md
  docs/architecture/audit-model.md
  docs/architecture/observability-contract.md
  docs/architecture/migration-contract.md
  docs/architecture/unified-ux-contract.md
  docs/governance/adr-candidate-index.md
  docs/governance/license-and-dependency-approval.md
  docs/governance/release-gates.md
  docs/planning/epic-issue-hierarchy.md
  docs/planning/implementation-issue-catalog.yaml
  docs/planning/phase-0-artifact-backlog.md
  docs/security/classification-bypass-inventory.md
  docs/security/threat-model.md
  docs/testing/golden-vertical-slice.md
  docs/phase0/PHASE0_CLOSEOUT_PACKET.md
  docs/phase0/VALIDATION_EVIDENCE.md
  specs/traceability/directive-inventory.yaml
  specs/traceability/requirements.yaml
  specs/traceability/security-findings.yaml
  specs/schema-registry.yaml
  specs/oscal/README.md
  scripts/generate_directive_inventory.rb
  scripts/validate_contracts.rb
  scripts/validate_owgp_examples.js
  scripts/validate_json_schemas.sh
  specs/work-graph-profile/owgp-v0.1.md
  specs/work-graph-profile/owgp-v0.1.schema.json
  specs/work-graph-profile/examples.yaml
  specs/openapi/platform-v1.yaml
  specs/asyncapi/platform.yaml
  specs/provider-interfaces.yaml
  specs/migration/migration-job-v0.1.schema.json
  specs/migration/canonical-model-v0.1.yaml
  specs/mcp/compatibility-v0.1.yaml
  specs/a2a/compatibility-v0.1.yaml
  packages/event-schemas/common/actor-context/actor-context-v0.1.schema.json
  packages/event-schemas/platform/platform-event-v0.1.schema.json
  policies/openfga/model.fga
  policies/openfga/model-tests.yaml
  policies/opa/input-v0.1.schema.json
  policies/opa/output-v0.1.schema.json
  policies/opa/decision-table.yaml
  policies/security-label-profiles/profile-v0.1.schema.json
  policies/security-label-profiles/commercial.yaml
  policies/security-label-profiles/us-government.yaml
  policies/deployment-domains/domain-profile-v0.1.schema.json
  policies/deployment-domains/commercial.yaml
  policies/deployment-domains/us-government.yaml
].freeze

REQUIREMENT_ARRAY_FIELDS = %w[
  implementation_modules
  issue_ids
  test_ids
  documentation
].freeze

REQUIREMENT_TEXT_FIELDS = %w[
  title
  status
  release
].freeze

ISSUE_ARRAY_FIELDS = %w[
  requirement_ids
  module
  owned_directories
  prohibited_boundaries
  acceptance_criteria
  automated_tests
  documentation_obligations
].freeze

ISSUE_TEXT_FIELDS = %w[
  owner
  authorization_and_classification_behavior
  observability_and_audit_requirements
  migration_and_backward_compatibility_implications
  upgrade_and_rollback_behavior
].freeze

def relative_path(path)
  path.delete_prefix("#{ROOT}/")
end

def nonempty_string?(value)
  value.is_a?(String) && !value.strip.empty?
end

def duplicate_values(values)
  values.tally.select { |_value, count| count > 1 }.keys.sort
end

def format_ids(ids)
  ids.empty? ? "none" : ids.sort.join(", ")
end

def load_yaml(path, failures)
  source = File.read(path, encoding: "UTF-8")
  parsed = YAML.safe_load(
    source,
    permitted_classes: [],
    permitted_symbols: [],
    aliases: false,
    filename: relative_path(path)
  )

  unless parsed.is_a?(Hash)
    failures << "#{relative_path(path)}: top-level YAML value must be a mapping"
    return nil
  end

  parsed
rescue Errno::ENOENT => error
  failures << "#{relative_path(path)}: cannot read file (#{error.message})"
  nil
rescue Psych::Exception => error
  failures << "#{relative_path(path)}: invalid YAML (#{error.message.lines.first.strip})"
  nil
rescue EncodingError => error
  failures << "#{relative_path(path)}: invalid text encoding (#{error.message})"
  nil
end

def array_field(record, field, context, failures, allow_empty: false)
  unless record.key?(field)
    failures << "#{context}: missing required field #{field}"
    return []
  end

  value = record[field]
  unless value.is_a?(Array)
    failures << "#{context}: #{field} must be an array"
    return []
  end

  if value.empty? && !allow_empty
    failures << "#{context}: #{field} must not be empty"
  end

  invalid_indexes = value.each_index.reject { |index| nonempty_string?(value[index]) }
  unless invalid_indexes.empty?
    failures << "#{context}: #{field} must contain only nonempty strings (invalid indexes: #{invalid_indexes.join(', ')})"
  end

  value.select { |entry| nonempty_string?(entry) }
end

def text_field(record, field, context, failures)
  unless record.key?(field)
    failures << "#{context}: missing required field #{field}"
    return nil
  end

  value = record[field]
  unless nonempty_string?(value)
    failures << "#{context}: #{field} must be a nonempty string"
    return nil
  end

  value
end

def records_field(document, field, path, failures)
  return [] unless document

  value = document[field]
  unless value.is_a?(Array)
    failures << "#{relative_path(path)}: #{field} must be an array"
    return []
  end

  value
end

def validate_records_are_mappings(records, label, failures)
  records.each_with_index.filter_map do |record, index|
    unless record.is_a?(Hash)
      failures << "#{label}[#{index}]: entry must be a mapping"
      next
    end

    [record, index]
  end
end

def find_cycle(graph)
  state = {}
  stack = []
  cycle = nil
  visit = nil

  visit = lambda do |node|
    state[node] = :visiting
    stack << node

    graph.fetch(node, []).each do |dependency|
      next unless graph.key?(dependency)

      if state[dependency] == :visiting
        start = stack.index(dependency) || 0
        cycle = stack[start..] + [dependency]
        return
      end

      visit.call(dependency) unless state[dependency] == :visited
      return if cycle
    end

    stack.pop
    state[node] = :visited
  end

  graph.each_key do |node|
    next if state.key?(node)

    visit.call(node)
    break if cycle
  end

  cycle
end

failures = []

directive_bytes = nil
directive_text = nil
begin
  directive_bytes = File.binread(DIRECTIVE_PATH)
  directive_text = directive_bytes.dup.force_encoding(Encoding::UTF_8)
  unless directive_text.valid_encoding?
    failures << "#{relative_path(DIRECTIVE_PATH)}: directive is not valid UTF-8"
    directive_text = nil
  end
rescue Errno::ENOENT => error
  failures << "#{relative_path(DIRECTIVE_PATH)}: cannot read file (#{error.message})"
end

directive_heading_ids = []
directive_ids = []
directive_titles = {}
if directive_text
  directive_version = directive_text[/^\*\*Version:\*\*\s*([^\s<]+)/, 1]
  if directive_version != EXPECTED_DIRECTIVE_VERSION
    failures << "#{relative_path(DIRECTIVE_PATH)}: expected directive version #{EXPECTED_DIRECTIVE_VERSION.inspect}, found #{directive_version.inspect}"
  end

  directive_heading_ids = directive_text.scan(/^## ([A-Z]+-\d{3})(?=\s|$)/).flatten
  directive_ids = directive_heading_ids.uniq
  directive_titles = directive_text.scan(/^## ([A-Z]+-\d{3})\s+—\s+(.+)$/).to_h

  duplicate_headings = duplicate_values(directive_heading_ids)
  unless duplicate_headings.empty?
    failures << "#{relative_path(DIRECTIVE_PATH)}: duplicate requirement headings: #{format_ids(duplicate_headings)}"
  end

  if directive_ids.length != EXPECTED_REQUIREMENT_COUNT
    failures << "#{relative_path(DIRECTIVE_PATH)}: expected #{EXPECTED_REQUIREMENT_COUNT} unique requirement heading IDs, found #{directive_ids.length}"
  end

  missing_agent_ids = EXPECTED_AGENT_IDS - directive_ids
  unless missing_agent_ids.empty?
    failures << "#{relative_path(DIRECTIVE_PATH)}: missing agent-ready requirement IDs: #{format_ids(missing_agent_ids)}"
  end

  missing_v02_ids = EXPECTED_V02_IDS - directive_ids
  unless missing_v02_ids.empty?
    failures << "#{relative_path(DIRECTIVE_PATH)}: missing v0.2 reconciliation requirement IDs: #{format_ids(missing_v02_ids)}"
  end
end

inventory = load_yaml(INVENTORY_PATH, failures)
if inventory
  inventory_directive = inventory["directive"]
  unless inventory_directive.is_a?(Hash)
    failures << "#{relative_path(INVENTORY_PATH)}: directive must be a mapping"
    inventory_directive = {}
  end

  expected_directive_relative_path = relative_path(DIRECTIVE_PATH)
  if inventory_directive["path"] != expected_directive_relative_path
    failures << "#{relative_path(INVENTORY_PATH)}: directive.path must be #{expected_directive_relative_path.inspect}"
  end

  if inventory_directive["version"].to_s != EXPECTED_DIRECTIVE_VERSION
    failures << "#{relative_path(INVENTORY_PATH)}: directive.version must be #{EXPECTED_DIRECTIVE_VERSION.inspect}"
  end

  if directive_bytes
    expected_hash = Digest::SHA256.hexdigest(directive_bytes)
    unless inventory_directive["sha256"] == expected_hash
      failures << "#{relative_path(INVENTORY_PATH)}: directive.sha256 does not match the directive (expected #{expected_hash})"
    end
  end

  unless inventory_directive["named_requirement_count"] == directive_ids.length
    failures << "#{relative_path(INVENTORY_PATH)}: directive.named_requirement_count must equal the directive's #{directive_ids.length} unique IDs"
  end

  inventory_ids = inventory["requirement_ids"]
  unless inventory_ids.is_a?(Array)
    failures << "#{relative_path(INVENTORY_PATH)}: requirement_ids must be an array"
  else
    invalid_indexes = inventory_ids.each_index.reject { |index| nonempty_string?(inventory_ids[index]) }
    unless invalid_indexes.empty?
      failures << "#{relative_path(INVENTORY_PATH)}: requirement_ids must contain only nonempty strings (invalid indexes: #{invalid_indexes.join(', ')})"
    end

    inventory_duplicates = duplicate_values(inventory_ids.select { |entry| nonempty_string?(entry) })
    unless inventory_duplicates.empty?
      failures << "#{relative_path(INVENTORY_PATH)}: duplicate requirement IDs: #{format_ids(inventory_duplicates)}"
    end

    expected_inventory_ids = directive_ids.sort
    if inventory_ids != expected_inventory_ids
      missing = expected_inventory_ids - inventory_ids
      unexpected = inventory_ids - expected_inventory_ids
      if missing.empty? && unexpected.empty?
        failures << "#{relative_path(INVENTORY_PATH)}: requirement_ids must use canonical sorted directive order"
      else
        failures << "#{relative_path(INVENTORY_PATH)}: requirement_ids mismatch (missing: #{format_ids(missing)}; unexpected: #{format_ids(unexpected)})"
      end
    end
  end
end

requirements_document = load_yaml(REQUIREMENTS_PATH, failures)
requirement_records = records_field(requirements_document, "requirements", REQUIREMENTS_PATH, failures)
requirements_with_indexes = validate_records_are_mappings(
  requirement_records,
  "#{relative_path(REQUIREMENTS_PATH)} requirements",
  failures
)

requirement_ids = []
requirements_with_indexes.each do |requirement, index|
  context = "#{relative_path(REQUIREMENTS_PATH)} requirements[#{index}]"
  requirement_id = text_field(requirement, "requirement_id", context, failures)
  requirement_ids << requirement_id if requirement_id

  REQUIREMENT_ARRAY_FIELDS.each do |field|
    array_field(requirement, field, context, failures)
  end
  REQUIREMENT_TEXT_FIELDS.each do |field|
    text_field(requirement, field, context, failures)
  end
end

requirements_with_indexes.each do |requirement, index|
  requirement_id = requirement["requirement_id"]
  next unless directive_titles.key?(requirement_id)

  unless requirement["title"] == directive_titles[requirement_id]
    failures << "#{relative_path(REQUIREMENTS_PATH)} requirements[#{index}]: title for #{requirement_id} must exactly match directive heading #{directive_titles[requirement_id].inspect}"
  end
end

requirement_duplicates = duplicate_values(requirement_ids)
unless requirement_duplicates.empty?
  failures << "#{relative_path(REQUIREMENTS_PATH)}: duplicate requirement IDs: #{format_ids(requirement_duplicates)}"
end

unless directive_ids.empty?
  missing = directive_ids - requirement_ids
  unexpected = requirement_ids - directive_ids
  unless missing.empty? && unexpected.empty? && requirement_ids.length == directive_ids.length
    failures << "#{relative_path(REQUIREMENTS_PATH)}: requirement IDs do not exactly match the directive (missing: #{format_ids(missing)}; unexpected: #{format_ids(unexpected)})"
  end
end

issues_document = load_yaml(ISSUES_PATH, failures)
issue_records = records_field(issues_document, "issues", ISSUES_PATH, failures)
epic_records = records_field(issues_document, "epics", ISSUES_PATH, failures)
gate_records = records_field(issues_document, "gates", ISSUES_PATH, failures)
adr_gate_records = records_field(issues_document, "adr_decision_gates", ISSUES_PATH, failures)

issues_with_indexes = validate_records_are_mappings(
  issue_records,
  "#{relative_path(ISSUES_PATH)} issues",
  failures
)
epics_with_indexes = validate_records_are_mappings(
  epic_records,
  "#{relative_path(ISSUES_PATH)} epics",
  failures
)
gates_with_indexes = validate_records_are_mappings(
  gate_records,
  "#{relative_path(ISSUES_PATH)} gates",
  failures
)
adr_gates_with_indexes = validate_records_are_mappings(
  adr_gate_records,
  "#{relative_path(ISSUES_PATH)} adr_decision_gates",
  failures
)

issue_ids = []
issues_with_indexes.each do |issue, index|
  context = "#{relative_path(ISSUES_PATH)} issues[#{index}]"
  issue_id = text_field(issue, "id", context, failures)
  issue_ids << issue_id if issue_id
  text_field(issue, "epic_id", context, failures)
  phase = text_field(issue, "phase", context, failures)
  text_field(issue, "status", context, failures)

  if phase && !VALID_PHASES.include?(phase)
    failures << "#{context}: phase must be one of #{VALID_PHASES.join(', ')}"
  end

  ISSUE_ARRAY_FIELDS.each do |field|
    array_field(issue, field, context, failures)
  end
  array_field(issue, "dependencies", context, failures, allow_empty: true)
  ISSUE_TEXT_FIELDS.each do |field|
    text_field(issue, field, context, failures)
  end

  if phase == "phase-0" && issue["status"] != PHASE_ZERO_READY_STATUS
    failures << "#{context}: Phase 0 closeout issue #{issue_id} must have status #{PHASE_ZERO_READY_STATUS}"
  end
end

issue_duplicates = duplicate_values(issue_ids)
unless issue_duplicates.empty?
  failures << "#{relative_path(ISSUES_PATH)}: duplicate issue IDs: #{format_ids(issue_duplicates)}"
end

epic_ids = []
epics_with_indexes.each do |epic, index|
  context = "#{relative_path(ISSUES_PATH)} epics[#{index}]"
  epic_id = text_field(epic, "id", context, failures)
  epic_ids << epic_id if epic_id
  array_field(epic, "dependencies", context, failures, allow_empty: true)
end

gate_ids = []
gates_with_indexes.each do |gate, index|
  context = "#{relative_path(ISSUES_PATH)} gates[#{index}]"
  gate_id = text_field(gate, "id", context, failures)
  gate_ids << gate_id if gate_id
  text_field(gate, "state", context, failures)
  text_field(gate, "approval_rules", context, failures)
  array_field(gate, "approvers", context, failures)
  array_field(gate, "evidence", context, failures)
  array_field(gate, "dependencies", context, failures)
end

epic_duplicates = duplicate_values(epic_ids)
unless epic_duplicates.empty?
  failures << "#{relative_path(ISSUES_PATH)}: duplicate epic IDs: #{format_ids(epic_duplicates)}"
end

gate_duplicates = duplicate_values(gate_ids)
unless gate_duplicates.empty?
  failures << "#{relative_path(ISSUES_PATH)}: duplicate gate IDs: #{format_ids(gate_duplicates)}"
end

unless gate_ids.include?(APPROVAL_GATE_ID)
  failures << "#{relative_path(ISSUES_PATH)}: missing required approval gate #{APPROVAL_GATE_ID}"
end

id_kinds = Hash.new { |hash, key| hash[key] = [] }
issue_ids.each { |id| id_kinds[id] << "issue" }
epic_ids.each { |id| id_kinds[id] << "epic" }
gate_ids.each { |id| id_kinds[id] << "gate" }
id_kinds.each do |id, kinds|
  next if kinds.uniq.length == 1

  failures << "#{relative_path(ISSUES_PATH)}: ID #{id} is reused across node types: #{kinds.uniq.join(', ')}"
end

issue_by_id = {}
issues_with_indexes.each do |issue, _index|
  issue_by_id[issue["id"]] ||= issue if nonempty_string?(issue["id"])
end
requirement_by_id = {}
requirements_with_indexes.each do |requirement, _index|
  requirement_by_id[requirement["requirement_id"]] ||= requirement if nonempty_string?(requirement["requirement_id"])
end

adr_gate_ids = []
adr_gates_with_indexes.each do |adr_gate, index|
  context = "#{relative_path(ISSUES_PATH)} adr_decision_gates[#{index}]"
  adr_id = text_field(adr_gate, "adr_id", context, failures)
  deadline_issue = text_field(adr_gate, "decide_before_issue", context, failures)
  dependent_issues = array_field(adr_gate, "dependent_issues", context, failures)
  adr_gate_ids << adr_id if adr_id

  failures << "#{context}: unknown decide_before_issue #{deadline_issue}" if deadline_issue && !issue_by_id.key?(deadline_issue)
  dependent_issues.each do |issue_id|
    failures << "#{context}: unknown dependent issue #{issue_id}" unless issue_by_id.key?(issue_id)
  end
  if deadline_issue && !dependent_issues.include?(deadline_issue)
    failures << "#{context}: dependent_issues must include decide_before_issue #{deadline_issue}"
  end
end

adr_gate_duplicates = duplicate_values(adr_gate_ids)
failures << "#{relative_path(ISSUES_PATH)}: duplicate ADR decision gates: #{format_ids(adr_gate_duplicates)}" unless adr_gate_duplicates.empty?
missing_adr_gates = EXPECTED_MACHINE_ADR_GATE_IDS - adr_gate_ids
unexpected_adr_gates = adr_gate_ids - EXPECTED_MACHINE_ADR_GATE_IDS
unless missing_adr_gates.empty? && unexpected_adr_gates.empty? && adr_gate_ids.length == EXPECTED_MACHINE_ADR_GATE_IDS.length
  failures << "#{relative_path(ISSUES_PATH)}: ADR decision-gate IDs mismatch (missing: #{format_ids(missing_adr_gates)}; unexpected: #{format_ids(unexpected_adr_gates)})"
end

begin
  adr_index_text = File.read(ADR_CANDIDATE_INDEX_PATH, encoding: "UTF-8")
  documented_adr_ids = adr_index_text.scan(/ADR-CAND-\d{3}/).uniq
  missing_documented_adrs = EXPECTED_ADR_CANDIDATE_IDS - documented_adr_ids
  unexpected_documented_adrs = documented_adr_ids - EXPECTED_ADR_CANDIDATE_IDS
  unless missing_documented_adrs.empty? && unexpected_documented_adrs.empty?
    failures << "#{relative_path(ADR_CANDIDATE_INDEX_PATH)}: ADR candidate IDs mismatch (missing: #{format_ids(missing_documented_adrs)}; unexpected: #{format_ids(unexpected_documented_adrs)})"
  end

  undocumented_machine_gates = adr_gate_ids - documented_adr_ids
  unless undocumented_machine_gates.empty?
    failures << "#{relative_path(ADR_CANDIDATE_INDEX_PATH)}: missing machine-gated candidates #{format_ids(undocumented_machine_gates)}"
  end

  adr_gate_records.each do |adr_gate|
    next unless adr_gate.is_a?(Hash)

    adr_id = adr_gate["adr_id"]
    deadline_issue = adr_gate["decide_before_issue"]
    next unless nonempty_string?(adr_id) && nonempty_string?(deadline_issue)

    index_row = adr_index_text.lines.find { |line| line.start_with?("| `#{adr_id}` |") }
    unless index_row&.include?("`#{deadline_issue}`")
      failures << "#{relative_path(ADR_CANDIDATE_INDEX_PATH)}: #{adr_id} must document deadline #{deadline_issue}"
    end
  end
rescue Errno::ENOENT => error
  failures << "#{relative_path(ADR_CANDIDATE_INDEX_PATH)}: cannot read file (#{error.message})"
end

approval_gate = gates_with_indexes.map(&:first).find { |gate| gate["id"] == APPROVAL_GATE_ID }
if approval_gate
  approvers = approval_gate["approvers"].is_a?(Array) ? approval_gate["approvers"] : []
  missing_approvers = EXPECTED_GATE_APPROVERS - approvers
  unexpected_approvers = approvers - EXPECTED_GATE_APPROVERS
  unless missing_approvers.empty? && unexpected_approvers.empty? && approvers.length == EXPECTED_GATE_APPROVERS.length
    failures << "#{relative_path(ISSUES_PATH)}: #{APPROVAL_GATE_ID} approvers mismatch (missing: #{format_ids(missing_approvers)}; unexpected: #{format_ids(unexpected_approvers)})"
  end

  expected_dependencies = issues_with_indexes.filter_map do |issue, _index|
    issue["id"] if issue["phase"] == "phase-0" && nonempty_string?(issue["id"])
  end
  dependencies = approval_gate["dependencies"].is_a?(Array) ? approval_gate["dependencies"] : []
  missing_dependencies = expected_dependencies - dependencies
  unexpected_dependencies = dependencies - expected_dependencies
  unless missing_dependencies.empty? && unexpected_dependencies.empty? && dependencies.length == expected_dependencies.length
    failures << "#{relative_path(ISSUES_PATH)}: #{APPROVAL_GATE_ID} dependencies must include every and only Phase 0 issue (missing: #{format_ids(missing_dependencies)}; unexpected: #{format_ids(unexpected_dependencies)})"
  end
end

begin
  workstream_text = File.read(WORKSTREAM_OWNERSHIP_PATH, encoding: "UTF-8")
  workstream_headings = workstream_text.scan(/^## (WS-\d{2})\s/).flatten
  duplicate_workstream_headings = duplicate_values(workstream_headings)
  unless duplicate_workstream_headings.empty?
    failures << "#{relative_path(WORKSTREAM_OWNERSHIP_PATH)}: duplicate workstream headings: #{format_ids(duplicate_workstream_headings)}"
  end

  missing_workstream_headings = EXPECTED_WORKSTREAM_IDS - workstream_headings
  unexpected_workstream_headings = workstream_headings - EXPECTED_WORKSTREAM_IDS
  unless missing_workstream_headings.empty? && unexpected_workstream_headings.empty? && workstream_headings.length == EXPECTED_WORKSTREAM_IDS.length
    failures << "#{relative_path(WORKSTREAM_OWNERSHIP_PATH)}: workstream headings mismatch (missing: #{format_ids(missing_workstream_headings)}; unexpected: #{format_ids(unexpected_workstream_headings)})"
  end

  accountable_owners = Hash.new { |hash, key| hash[key] = [] }
  current_workstream = nil
  workstream_text.each_line do |line|
    heading_match = line.match(/^## (WS-\d{2})\s/)
    current_workstream = heading_match[1] if heading_match
    next unless current_workstream && line.start_with?("**Assigned requirements.**")

    line.scan(/`([A-Z]+-\d{3})`/).flatten.each do |requirement_id|
      accountable_owners[requirement_id] << current_workstream
    end
  end

  duplicate_accountability = accountable_owners.select { |_id, owners| owners.uniq.length > 1 }
  duplicate_accountability.each do |requirement_id, owners|
    failures << "#{relative_path(WORKSTREAM_OWNERSHIP_PATH)}: #{requirement_id} has multiple accountable workstreams: #{owners.uniq.sort.join(', ')}"
  end

  missing_accountability = directive_ids - accountable_owners.keys
  unexpected_accountability = accountable_owners.keys - directive_ids
  unless missing_accountability.empty? && unexpected_accountability.empty? && accountable_owners.length == directive_ids.length
    failures << "#{relative_path(WORKSTREAM_OWNERSHIP_PATH)}: accountable requirement coverage mismatch (missing: #{format_ids(missing_accountability)}; unexpected: #{format_ids(unexpected_accountability)})"
  end

  phase_zero_issues = issues_with_indexes.map(&:first).select { |issue| issue["phase"] == "phase-0" }
  accountable_owners.each do |requirement_id, owners|
    mapped_phase_zero_owners = phase_zero_issues.filter_map do |issue|
      issue["owner"] if issue["requirement_ids"].is_a?(Array) && issue["requirement_ids"].include?(requirement_id)
    end.uniq
    next unless (owners & mapped_phase_zero_owners).empty?

    failures << "ownership mismatch: #{requirement_id} accountable to #{owners.join(', ')}, but its Phase 0 issues are owned by #{mapped_phase_zero_owners.empty? ? 'none' : mapped_phase_zero_owners.join(', ')}"
  end
rescue Errno::ENOENT => error
  failures << "#{relative_path(WORKSTREAM_OWNERSHIP_PATH)}: cannot read file (#{error.message})"
end

issues_with_indexes.map(&:first).group_by { |issue| issue["phase"] }.each do |phase, issues|
  owned_paths = issues.flat_map do |issue|
    next [] unless issue["owned_directories"].is_a?(Array)

    issue["owned_directories"].filter_map do |path|
      [path.sub(%r{/+$}, ""), issue["id"], issue["owner"]] if nonempty_string?(path)
    end
  end
  owned_paths.combination(2) do |left, right|
    next if left[2] == right[2]
    next unless left[0] == right[0] || left[0].start_with?("#{right[0]}/") || right[0].start_with?("#{left[0]}/")

    failures << "#{relative_path(ISSUES_PATH)}: cross-owner path overlap in #{phase}: #{left[0]} (#{left[1]}/#{left[2]}) and #{right[0]} (#{right[1]}/#{right[2]})"
  end
end

requirements_with_indexes.each do |requirement, index|
  requirement_id = requirement["requirement_id"]
  next unless nonempty_string?(requirement_id)

  issue_references = requirement["issue_ids"].is_a?(Array) ? requirement["issue_ids"] : []
  issue_references.select { |id| nonempty_string?(id) }.each do |issue_id|
    issue = issue_by_id[issue_id]
    unless issue
      failures << "#{relative_path(REQUIREMENTS_PATH)} requirements[#{index}]: #{requirement_id} references unknown issue #{issue_id}"
      next
    end

    issue_requirement_ids = issue["requirement_ids"].is_a?(Array) ? issue["requirement_ids"] : []
    unless issue_requirement_ids.include?(requirement_id)
      failures << "traceability mismatch: requirement #{requirement_id} references issue #{issue_id}, but the issue omits #{requirement_id}"
    end
  end
end

issues_with_indexes.each do |issue, index|
  issue_id = issue["id"]
  next unless nonempty_string?(issue_id)

  requirement_references = issue["requirement_ids"].is_a?(Array) ? issue["requirement_ids"] : []
  requirement_references.select { |id| nonempty_string?(id) }.each do |requirement_id|
    requirement = requirement_by_id[requirement_id]
    unless requirement
      failures << "#{relative_path(ISSUES_PATH)} issues[#{index}]: #{issue_id} references unknown requirement #{requirement_id}"
      next
    end

    requirement_issue_ids = requirement["issue_ids"].is_a?(Array) ? requirement["issue_ids"] : []
    unless requirement_issue_ids.include?(issue_id)
      failures << "traceability mismatch: issue #{issue_id} references requirement #{requirement_id}, but the requirement omits #{issue_id}"
    end
  end
end

security_document = load_yaml(SECURITY_FINDINGS_PATH, failures)
security_relative_path = relative_path(SECURITY_FINDINGS_PATH)
if requirements_document && requirements_document["related_security_traceability"] != security_relative_path
  failures << "#{relative_path(REQUIREMENTS_PATH)}: related_security_traceability must be #{security_relative_path.inspect}"
end

threat_records = records_field(security_document, "threat_findings", SECURITY_FINDINGS_PATH, failures)
bypass_records = records_field(security_document, "bypass_controls", SECURITY_FINDINGS_PATH, failures)
threats_with_indexes = validate_records_are_mappings(threat_records, "#{security_relative_path} threat_findings", failures)
bypasses_with_indexes = validate_records_are_mappings(bypass_records, "#{security_relative_path} bypass_controls", failures)

validate_security_record = lambda do |record, index, collection, id_field|
  context = "#{security_relative_path} #{collection}[#{index}]"
  record_id = text_field(record, id_field, context, failures)
  owner = text_field(record, "owner", context, failures)
  requirement_references = array_field(record, "requirement_ids", context, failures)
  issue_references = array_field(record, "issue_ids", context, failures)
  test_references = array_field(record, "test_ids", context, failures)
  text_field(record, "status", context, failures)

  if owner && !EXPECTED_WORKSTREAM_IDS.include?(owner)
    failures << "#{context}: unknown owner #{owner}"
  end
  requirement_references.each do |requirement_id|
    failures << "#{context}: unknown requirement #{requirement_id}" unless requirement_by_id.key?(requirement_id)
  end
  issue_references.each do |issue_id|
    failures << "#{context}: unknown issue #{issue_id}" unless issue_by_id.key?(issue_id)
  end

  [record_id, test_references]
end

threat_ids = threats_with_indexes.map do |record, index|
  validate_security_record.call(record, index, "threat_findings", "finding_id").first
end.compact
bypass_pairs = bypasses_with_indexes.map do |record, index|
  validate_security_record.call(record, index, "bypass_controls", "bypass_id")
end
bypass_ids = bypass_pairs.map(&:first).compact

[["threat_findings", threat_ids, EXPECTED_THREAT_IDS], ["bypass_controls", bypass_ids, EXPECTED_BYPASS_IDS]].each do |collection, actual, expected|
  duplicates = duplicate_values(actual)
  failures << "#{security_relative_path}: duplicate #{collection} IDs: #{format_ids(duplicates)}" unless duplicates.empty?
  missing = expected - actual
  unexpected = actual - expected
  unless missing.empty? && unexpected.empty? && actual.length == expected.length
    failures << "#{security_relative_path}: #{collection} IDs mismatch (missing: #{format_ids(missing)}; unexpected: #{format_ids(unexpected)})"
  end
end

bypass_pairs.each_with_index do |(bypass_id, tests), index|
  match = bypass_id&.match(/^CBI-(\d{3})$/)
  next unless match

  expected_test = "SEC-BYP-#{match[1]}"
  unless tests.include?(expected_test)
    failures << "#{security_relative_path} bypass_controls[#{index}]: #{bypass_id} must include test #{expected_test}"
  end
end

expected_workstreams = EXPECTED_WORKSTREAM_IDS.to_set
actual_workstreams = issues_with_indexes.filter_map do |issue, _index|
  owner = issue["owner"]
  owner if nonempty_string?(owner)
end.to_set

missing_workstreams = expected_workstreams - actual_workstreams
unexpected_workstreams = actual_workstreams - expected_workstreams
unless missing_workstreams.empty?
  failures << "#{relative_path(ISSUES_PATH)}: missing required workstream owners: #{format_ids(missing_workstreams.to_a)}"
end
unless unexpected_workstreams.empty?
  failures << "#{relative_path(ISSUES_PATH)}: unknown workstream owners: #{format_ids(unexpected_workstreams.to_a)}"
end

all_node_ids = id_kinds.keys.to_set
graph = all_node_ids.to_h { |id| [id, []] }

gates_with_indexes.each do |gate, index|
  gate_id = gate["id"]
  next unless nonempty_string?(gate_id)

  dependencies = gate["dependencies"].is_a?(Array) ? gate["dependencies"] : []
  dependencies.select { |id| nonempty_string?(id) }.each do |dependency|
    unless all_node_ids.include?(dependency)
      failures << "#{relative_path(ISSUES_PATH)} gates[#{index}]: #{gate_id} has unresolved dependency #{dependency}"
      next
    end
    graph[gate_id] << dependency
  end
end

epics_with_indexes.each do |epic, index|
  epic_id = epic["id"]
  next unless nonempty_string?(epic_id)

  dependencies = epic["dependencies"].is_a?(Array) ? epic["dependencies"] : []
  dependencies.select { |id| nonempty_string?(id) }.each do |dependency|
    unless all_node_ids.include?(dependency)
      failures << "#{relative_path(ISSUES_PATH)} epics[#{index}]: #{epic_id} has unresolved dependency #{dependency}"
      next
    end

    unless (id_kinds[dependency] & %w[epic gate]).any?
      failures << "#{relative_path(ISSUES_PATH)} epics[#{index}]: #{epic_id} dependency #{dependency} must be an epic or gate"
      next
    end
    graph[epic_id] << dependency
  end
end

issues_with_indexes.each do |issue, index|
  issue_id = issue["id"]
  next unless nonempty_string?(issue_id)

  epic_id = issue["epic_id"]
  unless nonempty_string?(epic_id) && epic_ids.include?(epic_id)
    failures << "#{relative_path(ISSUES_PATH)} issues[#{index}]: #{issue_id} has unresolved epic_id #{epic_id.inspect}"
  end

  dependencies = issue["dependencies"].is_a?(Array) ? issue["dependencies"] : []
  dependencies.select { |id| nonempty_string?(id) }.each do |dependency|
    unless all_node_ids.include?(dependency)
      failures << "#{relative_path(ISSUES_PATH)} issues[#{index}]: #{issue_id} has unresolved dependency #{dependency}"
      next
    end
    graph[issue_id] << dependency
  end

  next unless BLOCKED_PHASES.include?(issue["phase"])

  unless issue["status"] == BLOCKED_STATUS
    failures << "#{relative_path(ISSUES_PATH)} issues[#{index}]: #{issue_id} in #{issue['phase']} must have status #{BLOCKED_STATUS}"
  end
  unless dependencies.include?(APPROVAL_GATE_ID)
    failures << "#{relative_path(ISSUES_PATH)} issues[#{index}]: #{issue_id} in #{issue['phase']} must directly depend on #{APPROVAL_GATE_ID}"
  end
end

cycle = find_cycle(graph)
failures << "#{relative_path(ISSUES_PATH)}: dependency graph contains a cycle: #{cycle.join(' -> ')}" if cycle

duplicate_required_files = duplicate_values(REQUIRED_PHASE_ZERO_FILES)
unless duplicate_required_files.empty?
  failures << "Phase 0 closeout artifact list contains duplicates: #{format_ids(duplicate_required_files)}"
end

REQUIRED_PHASE_ZERO_FILES.each do |path|
  failures << "#{path}: missing required Phase 0 closeout artifact" unless File.file?(File.join(ROOT, path))
end

markdown_paths = [File.join(ROOT, "README.md"), *Dir.glob(File.join(ROOT, "docs/**/*.md"))].uniq.sort
markdown_paths.each do |markdown_path|
  source = File.read(markdown_path, encoding: "UTF-8")
  source.scan(/\[[^\]]*\]\(([^)\n]+)\)/).flatten.each do |raw_target|
    target = raw_target.strip
    target = target[1...target.index(">")].to_s if target.start_with?("<") && target.include?(">")
    target = target.split(/\s+/, 2).first.to_s unless raw_target.strip.start_with?("<")

    next if target.empty?
    next if target.start_with?("#", "http://", "https://", "mailto:", "data:")

    local_path = target.split("#", 2).first
    next if local_path.empty?

    resolved_path = File.expand_path(local_path, File.dirname(markdown_path))
    unless File.exist?(resolved_path)
      failures << "#{relative_path(markdown_path)}: broken local Markdown link #{target.inspect}"
    end
  end
rescue EncodingError => error
  failures << "#{relative_path(markdown_path)}: invalid text encoding while checking links (#{error.message})"
end

json_contract_paths = %w[
  specs/work-graph-profile/owgp-v0.1.schema.json
  packages/event-schemas/common/actor-context/actor-context-v0.1.schema.json
  packages/event-schemas/platform/platform-event-v0.1.schema.json
  policies/opa/input-v0.1.schema.json
  policies/opa/output-v0.1.schema.json
  policies/security-label-profiles/profile-v0.1.schema.json
  policies/deployment-domains/domain-profile-v0.1.schema.json
  specs/migration/migration-job-v0.1.schema.json
]
parsed_json = {}
json_contract_paths.each do |path|
  begin
    parsed_json[path] = JSON.parse(File.read(File.join(ROOT, path), encoding: "UTF-8"))
  rescue Errno::ENOENT
    # Missing-file failure is already emitted above.
  rescue JSON::ParserError => error
    failures << "#{path}: invalid JSON (#{error.message.lines.first.strip})"
  end
end

yaml_contract_paths = %w[
  specs/openapi/platform-v1.yaml
  specs/asyncapi/platform.yaml
  specs/provider-interfaces.yaml
  specs/mcp/compatibility-v0.1.yaml
  specs/a2a/compatibility-v0.1.yaml
  policies/openfga/model-tests.yaml
  policies/opa/decision-table.yaml
  policies/security-label-profiles/commercial.yaml
  policies/security-label-profiles/us-government.yaml
  policies/deployment-domains/commercial.yaml
  policies/deployment-domains/us-government.yaml
  specs/migration/canonical-model-v0.1.yaml
]
yaml_contract_paths.each { |path| load_yaml(File.join(ROOT, path), failures) }

begin
  examples = YAML.safe_load(
    File.read(File.join(ROOT, "specs/work-graph-profile/examples.yaml"), encoding: "UTF-8"),
    permitted_classes: [],
    permitted_symbols: [],
    aliases: true
  )
  expected_examples = %w[Organization DirectoryGroup Team Project WorkItem Document Repository PrincipalRef Agent AgentRun SecurityLabel Comment Activity Notification Audit]
  actual_examples = examples.is_a?(Hash) && examples["examples"].is_a?(Hash) ? examples["examples"].keys : []
  missing_examples = expected_examples - actual_examples
  failures << "specs/work-graph-profile/examples.yaml: missing closeout examples: #{missing_examples.join(', ')}" unless missing_examples.empty?

  if examples.is_a?(Hash) && examples["examples"].is_a?(Hash)
    common_fields = %w[kind id uri schema_version version organization_id container title created_at created_by updated_at updated_by security_label_id effective_security_label provenance external_references relationships]
    expected_kinds = {
      "Organization" => "organization",
      "DirectoryGroup" => "directory_group",
      "Team" => "team",
      "Project" => "project",
      "WorkItem" => "work_item",
      "Document" => "document",
      "Repository" => "repository",
      "Agent" => "agent",
      "AgentRun" => "agent_run",
      "SecurityLabel" => "security_label",
      "Comment" => "comment",
      "Activity" => "activity",
      "Notification" => "notification",
      "Audit" => "audit_record"
    }
    expected_kinds.each do |name, kind|
      example = examples["examples"][name]
      next unless example.is_a?(Hash)

      missing_fields = common_fields - example.keys
      failures << "specs/work-graph-profile/examples.yaml: #{name} omits common envelope fields #{missing_fields.join(', ')}" unless missing_fields.empty?
      failures << "specs/work-graph-profile/examples.yaml: #{name} kind must be #{kind}" unless example["kind"] == kind
      container_kind = example.dig("container", "kind")
      failures << "specs/work-graph-profile/examples.yaml: #{name} container kind is invalid" unless %w[organization team project].include?(container_kind)
    end
  end
rescue Psych::Exception => error
  failures << "specs/work-graph-profile/examples.yaml: invalid YAML (#{error.message.lines.first.strip})"
end

owgp = parsed_json["specs/work-graph-profile/owgp-v0.1.schema.json"]
if owgp
  definitions = owgp["$defs"].is_a?(Hash) ? owgp["$defs"] : {}
  expected_definitions = %w[ResourceEnvelope ResourceRef ContainerRef Instance Organization User DirectoryGroup Agent AgentRun ServicePrincipal Team Initiative Project Cycle WorkItem Document Repository Branch Commit PullRequest Build Deployment Release Package Artifact Attachment PrincipalRef ActingPrincipalRef WorkAssigneeRef SecurityLabel SecurityLabelValue Comment Activity Notification AuditRecord]
  missing_definitions = expected_definitions - definitions.keys
  failures << "specs/work-graph-profile/owgp-v0.1.schema.json: missing definitions: #{missing_definitions.join(', ')}" unless missing_definitions.empty?

  principal_types = definitions.dig("PrincipalRef", "properties", "type", "enum") || []
  expected_principal_types = %w[user agent service_account directory_group]
  failures << "specs/work-graph-profile/owgp-v0.1.schema.json: PrincipalRef kinds mismatch" unless principal_types == expected_principal_types

  work_types = definitions.dig("WorkItem", "allOf", 1, "properties", "work_type", "enum") || []
  failures << "specs/work-graph-profile/owgp-v0.1.schema.json: WorkItem kinds must be deliverable/task/problem" unless work_types == %w[deliverable task problem]

  document_types = definitions.dig("Document", "allOf", 1, "properties", "document_type", "enum") || []
  failures << "specs/work-graph-profile/owgp-v0.1.schema.json: Document kinds must use universal values" unless document_types == %w[page specification decision procedure policy]

  envelope_required = definitions.dig("ResourceEnvelope", "required") || []
  expected_envelope_fields = %w[kind id uri schema_version version organization_id container title created_at created_by updated_at updated_by security_label_id effective_security_label provenance external_references relationships]
  missing_envelope_fields = expected_envelope_fields - envelope_required
  failures << "specs/work-graph-profile/owgp-v0.1.schema.json: common envelope omits #{missing_envelope_fields.join(', ')}" unless missing_envelope_fields.empty?

  assignee_ref = definitions.dig("WorkItem", "allOf", 1, "properties", "assignees", "items", "$ref")
  failures << "specs/work-graph-profile/owgp-v0.1.schema.json: Work Item assignees must use WorkAssigneeRef" unless assignee_ref == "#/$defs/WorkAssigneeRef"

  resource_ref_required = definitions.dig("ResourceRef", "required") || []
  failures << "specs/work-graph-profile/owgp-v0.1.schema.json: ResourceRef must use canonical kind/id/uri" unless resource_ref_required == %w[kind id uri]

  repository_required = definitions.dig("Repository", "allOf", 1, "required") || []
  failures << "specs/work-graph-profile/owgp-v0.1.schema.json: Repository must use a generic container" unless repository_required.include?("container") && !repository_required.include?("project_id")
end

begin
  fga = File.read(File.join(ROOT, "policies/openfga/model.fga"), encoding: "UTF-8")
  fga_without_comments = fga.lines.map { |line| line.split("#", 2).first }.join
  %w[type\ user type\ agent type\ service_account type\ directory_group type\ team type\ project].each do |fragment|
    failures << "policies/openfga/model.fga: missing #{fragment.tr('\\', '')}" unless fga.include?(fragment.tr("\\", ""))
  end
  team_block = fga_without_comments[/^type team\b.*?(?=^type\s|\z)/m] || ""
  failures << "policies/openfga/model.fga: Team hierarchy must not define viewer inheritance from parent" if team_block.match?(/define\s+(viewer|member|editor):[^\n]*from parent/)
rescue Errno::ENOENT
  # Missing-file failure is already emitted above.
end

forbidden_agent_runtime_files = Dir.glob(File.join(ROOT, "{modules/agent,providers/agent-a2a}/**/*"), File::FNM_EXTGLOB).select do |path|
  File.file?(path) && File.extname(path).match?(/\A\.(go|ts|tsx|js|jsx|py|rs|java|sh)\z/)
end
unless forbidden_agent_runtime_files.empty?
  failures << "Phase 0 agent scope guard: executable runtime files found: #{forbidden_agent_runtime_files.map { |path| relative_path(path) }.join(', ')}"
end

owgp_stdout, owgp_stderr, owgp_status = Open3.capture3("node", File.join(ROOT, "scripts/validate_owgp_examples.js"), chdir: ROOT)
unless owgp_status.success?
  diagnostic = [owgp_stdout, owgp_stderr].join(" ").strip.gsub(/\s+/, " ")
  failures << "scripts/validate_owgp_examples.js: #{diagnostic.empty? ? 'failed without diagnostic output' : diagnostic}"
end

contract_stdout, contract_stderr, contract_status = Open3.capture3("ruby", File.join(ROOT, "scripts/validate_contracts.rb"), chdir: ROOT)
unless contract_status.success?
  diagnostic = [contract_stdout, contract_stderr].join(" ").strip.gsub(/\s+/, " ")
  failures << "scripts/validate_contracts.rb: #{diagnostic.empty? ? 'failed without diagnostic output' : diagnostic}"
end

if failures.empty?
  dependency_count = graph.values.sum(&:length)
  puts "Phase 0 validation passed: requirements=#{directive_ids.length} issues=#{issue_ids.length} threat_findings=#{threat_ids.length} bypass_controls=#{bypass_ids.length} epics=#{epic_ids.length} gates=#{gate_ids.length} workstreams=#{actual_workstreams.length} dependency_links=#{dependency_count}"
  exit 0
end

warn "Phase 0 validation failed (#{failures.length} #{failures.length == 1 ? 'failure' : 'failures'}):"
failures.each { |failure| warn "- #{failure}" }
exit 1
