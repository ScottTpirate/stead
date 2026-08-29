#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require "set"
require "digest"

ROOT = File.expand_path("..", __dir__)
DIRECTIVE_PATH = File.join(ROOT, "unified_open_work_platform_master_build_directive.md")
INVENTORY_PATH = File.join(ROOT, "specs/traceability/directive-inventory.yaml")
REQUIREMENTS_PATH = File.join(ROOT, "specs/traceability/requirements.yaml")
ISSUES_PATH = File.join(ROOT, "docs/planning/implementation-issue-catalog.yaml")
SECURITY_FINDINGS_PATH = File.join(ROOT, "specs/traceability/security-findings.yaml")
WORKSTREAM_OWNERSHIP_PATH = File.join(ROOT, "docs/architecture/workstream-ownership.md")

EXPECTED_DIRECTIVE_VERSION = "0.2"
EXPECTED_REQUIREMENT_COUNT = 115
EXPECTED_AGENT_IDS = (1..7).map { |number| format("AGENT-%03d", number) }.freeze
EXPECTED_THREAT_IDS = (1..28).map { |number| format("TM-F%03d", number) }.freeze
EXPECTED_BYPASS_IDS = (1..42).map { |number| format("CBI-%03d", number) }.freeze
EXPECTED_WORKSTREAM_IDS = (1..13).map { |number| format("WS-%02d", number) }.freeze
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

if failures.empty?
  dependency_count = graph.values.sum(&:length)
  puts "Phase 0 validation passed: requirements=#{directive_ids.length} issues=#{issue_ids.length} threat_findings=#{threat_ids.length} bypass_controls=#{bypass_ids.length} epics=#{epic_ids.length} gates=#{gate_ids.length} workstreams=#{actual_workstreams.length} dependency_links=#{dependency_count}"
  exit 0
end

warn "Phase 0 validation failed (#{failures.length} #{failures.length == 1 ? 'failure' : 'failures'}):"
failures.each { |failure| warn "- #{failure}" }
exit 1
