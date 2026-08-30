#!/usr/bin/env ruby
# frozen_string_literal: true

require "pathname"
require "set"
require "yaml"

ROOT = Pathname.new(__dir__).parent.expand_path

EXPECTED_RECORDS = {
  "0001" => { candidate: "ADR-CAND-001", state: "ACCEPTED", owner_approval: false },
  "0002" => { candidate: "ADR-CAND-004", state: "ACCEPTED", owner_approval: true },
  "0003" => { candidate: "ADR-CAND-005", state: "ACCEPTED", owner_approval: true },
  "0004" => { candidate: "ADR-CAND-021", state: "ACCEPTED", owner_approval: true },
  "0005" => { candidate: "ADR-CAND-003", state: "ACCEPTED", owner_approval: false },
  "0006" => { candidate: "ADR-CAND-007", state: "ACCEPTED", owner_approval: true },
  "0007" => { candidate: "ADR-CAND-002", state: "PROPOSED", owner_approval: false }
}.freeze

EXPECTED_P1_006_ADR_CANDIDATES = %w[
  ADR-CAND-002
  ADR-CAND-003
  ADR-CAND-004
  ADR-CAND-005
  ADR-CAND-007
  ADR-CAND-021
].freeze
ADR_CANDIDATE_MENTION_PATTERN = /[A-Za-z0-9_-]*ADR-CAND-[A-Za-z0-9_-]+/.freeze
ADR_CANDIDATE_TOKEN_PATTERN = /\AADR-CAND-\d{3}\z/.freeze
ADR_CANDIDATE_MARKDOWN_UNDERSCORE_PATTERN = /(?<![A-Za-z0-9_-])(?<delimiter>_{1,3})(?<candidate>ADR-CAND-\d{3})\k<delimiter>(?![A-Za-z0-9_-])/.freeze

ACCEPTED_RECORD_METADATA = {
  "0002" => {
    immutable_revision: "24c74d52ef0a78840ab147da48c3d66589e49e3e",
    accepted_at: "2026-08-30",
    approval_record_path: "docs/governance/phase1-foundation-approval-record.md",
    approval_records: [
      { "role" => "WS-06-security-contract", "identity" => "/root/contract_owner_review", "disposition" => "APPROVED" },
      { "role" => "WS-01-architecture", "identity" => "/root/architecture_standards_review/profile_contract_audit", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-qa", "identity" => "/root/precommit_scope_audit", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-security", "identity" => "/root/revocation_mode_impact", "disposition" => "APPROVED" },
      { "role" => "project-owner", "identity" => "explicit 2026-08-30 project-owner instruction", "disposition" => "APPROVED" }
    ]
  },
  "0003" => {
    immutable_revision: "24c74d52ef0a78840ab147da48c3d66589e49e3e",
    accepted_at: "2026-08-30",
    approval_record_path: "docs/governance/phase1-foundation-approval-record.md",
    approval_records: [
      { "role" => "WS-06-security-contract", "identity" => "/root/contract_owner_review", "disposition" => "APPROVED" },
      { "role" => "WS-01-architecture", "identity" => "/root/architecture_standards_review/profile_contract_audit", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-qa", "identity" => "/root/precommit_scope_audit", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-security", "identity" => "/root/revocation_mode_impact", "disposition" => "APPROVED" },
      { "role" => "project-owner", "identity" => "explicit 2026-08-30 project-owner instruction", "disposition" => "APPROVED" }
    ]
  },
  "0004" => {
    immutable_revision: "24c74d52ef0a78840ab147da48c3d66589e49e3e",
    accepted_at: "2026-08-30",
    approval_record_path: "docs/governance/phase1-foundation-approval-record.md",
    approval_records: [
      { "role" => "WS-06-security-contract", "identity" => "/root/contract_owner_review", "disposition" => "APPROVED" },
      { "role" => "WS-02-team-domain", "identity" => "/root/core_owner_review", "disposition" => "APPROVED" },
      { "role" => "WS-01-architecture", "identity" => "/root/architecture_standards_review/profile_contract_audit", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-qa", "identity" => "/root/precommit_scope_audit", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-security", "identity" => "/root/revocation_mode_impact", "disposition" => "APPROVED" },
      { "role" => "project-owner", "identity" => "explicit 2026-08-30 project-owner instruction", "disposition" => "APPROVED" }
    ]
  },
  "0005" => {
    immutable_revision: "24c74d52ef0a78840ab147da48c3d66589e49e3e",
    accepted_at: "2026-08-30",
    approval_record_path: "docs/governance/phase1-foundation-approval-record.md",
    approval_records: [
      { "role" => "WS-06-security-contract", "identity" => "/root/contract_owner_review", "disposition" => "APPROVED" },
      { "role" => "WS-01-architecture", "identity" => "/root/architecture_standards_review/profile_contract_audit", "disposition" => "APPROVED" },
      { "role" => "WS-02-core-composition", "identity" => "/root/core_owner_review", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-qa", "identity" => "/root/precommit_scope_audit", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-security", "identity" => "/root/revocation_mode_impact", "disposition" => "APPROVED" },
      { "role" => "project-owner", "identity" => "explicit 2026-08-30 project-owner concurrence", "disposition" => "CONCURRED_NOT_REQUIRED" }
    ]
  },
  "0006" => {
    immutable_revision: "24c74d52ef0a78840ab147da48c3d66589e49e3e",
    accepted_at: "2026-08-30",
    approval_record_path: "docs/governance/phase1-foundation-approval-record.md",
    approval_records: [
      { "role" => "WS-06-security-contract", "identity" => "/root/contract_owner_review", "disposition" => "APPROVED" },
      { "role" => "WS-01-architecture", "identity" => "/root/architecture_standards_review/profile_contract_audit", "disposition" => "APPROVED" },
      { "role" => "WS-02-core-composition", "identity" => "/root/core_owner_review", "disposition" => "APPROVED" },
      { "role" => "WS-09-build-signing", "identity" => "/root/build_owner_review", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-qa", "identity" => "/root/precommit_scope_audit", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-security", "identity" => "/root/revocation_mode_impact", "disposition" => "APPROVED" },
      { "role" => "project-owner", "identity" => "explicit 2026-08-30 project-owner instruction", "disposition" => "APPROVED" }
    ]
  }
}.freeze
LEGACY_ACCEPTED_WITHOUT_IMMUTABLE_METADATA = Set["0001"].freeze

REQUIRED_SECTIONS = [
  "Context and decision scope",
  "Decision drivers",
  "Considered options",
  "Decision",
  "Consequences",
  "Verification",
  "Rollout and supersession",
  "Reviews and approvals"
].freeze

ADR_0007_REQUIREMENT_TEST_MAPPING = {
  "PRIN-005" => %w[
    T-ADR-0007-NAMESPACE-ROLES
    T-ADR-0007-FOREIGN-WRITE-DENIAL
    T-ADR-0007-CROSS-MODULE-READS
  ],
  "ARCH-003" => %w[
    T-ADR-0007-TRANSACTION-PORTS
  ],
  "ARCH-004" => %w[
    T-ADR-0007-NAMESPACE-ROLES
    T-ADR-0007-FOREIGN-WRITE-DENIAL
    T-ADR-0007-CROSS-MODULE-READS
    T-ADR-0007-MIGRATION-ORDERING
  ],
  "EVT-002" => %w[
    T-ADR-0007-OUTBOX-ATOMICITY
    T-ADR-0007-FAILURE-INJECTION
  ],
  "AUD-001" => %w[
    T-ADR-0007-OUTBOX-ATOMICITY
    T-ADR-0007-FAILURE-INJECTION
  ],
  "AUD-002" => %w[
    T-ADR-0007-OUTBOX-ATOMICITY
    T-ADR-0007-BACKUP-RESTORE
    T-ADR-0007-FAILURE-INJECTION
  ],
  "DEP-005" => %w[
    T-ADR-0007-MIGRATION-ORDERING
    T-ADR-0007-UPGRADE-ROLLBACK
    T-ADR-0007-BACKUP-RESTORE
    T-ADR-0007-FAILURE-INJECTION
  ],
  "OPS-003" => %w[
    T-ADR-0007-BACKUP-RESTORE
  ],
  "OPS-004" => %w[
    T-ADR-0007-BACKUP-RESTORE
    T-ADR-0007-FAILURE-INJECTION
  ],
  "PERF-003" => %w[
    T-ADR-0007-OUTBOX-ATOMICITY
    T-ADR-0007-CROSS-MODULE-READS
    T-ADR-0007-OBSERVABILITY-PERFORMANCE
  ],
  "PERF-004" => %w[
    T-ADR-0007-CROSS-MODULE-READS
    T-ADR-0007-DURABLE-EFFECTS
    T-ADR-0007-OBSERVABILITY-PERFORMANCE
  ],
  "TEST-005" => %w[
    T-ADR-0007-OUTBOX-ATOMICITY
    T-ADR-0007-FAILURE-INJECTION
  ],
  "TEST-007" => %w[
    T-ADR-0007-NAMESPACE-ROLES
    T-ADR-0007-FOREIGN-WRITE-DENIAL
    T-ADR-0007-MIGRATION-ORDERING
    T-ADR-0007-UPGRADE-ROLLBACK
    T-ADR-0007-BACKUP-RESTORE
    T-ADR-0007-FAILURE-INJECTION
  ]
}.transform_values(&:freeze).freeze

def load_yaml(relative)
  YAML.safe_load(
    ROOT.join(relative).read(encoding: "UTF-8"),
    permitted_classes: [],
    permitted_symbols: [],
    aliases: false,
    filename: relative
  )
end

def adr_requirement_traceability_failures(requirements:, adr_number:, claimed_requirement_ids:, declared_test_ids:)
  test_prefix = "T-ADR-#{adr_number}-"
  claimed_requirements = claimed_requirement_ids.to_set
  declared_tests = declared_test_ids.to_set
  registered_tests = Set.new
  tests_linked_to_claimed_requirements = Set.new
  covered_claimed_requirements = Set.new

  requirements.each do |record|
    adr_tests = Array(record["test_ids"]).select { |test_id| test_id.start_with?(test_prefix) }.to_set
    registered_tests.merge(adr_tests)
    next unless claimed_requirements.include?(record.fetch("requirement_id"))

    tests_linked_to_claimed_requirements.merge(adr_tests)
    covered_claimed_requirements << record.fetch("requirement_id") unless adr_tests.empty?
  end

  failures = []
  orphaned_tests = declared_tests - tests_linked_to_claimed_requirements
  unless orphaned_tests.empty?
    failures << "ADR-#{adr_number} declared tests orphaned from claimed requirements: #{orphaned_tests.to_a.sort.join(', ')}"
  end

  uncovered_requirements = claimed_requirements - covered_claimed_requirements
  unless uncovered_requirements.empty?
    failures << "ADR-#{adr_number} claimed requirements missing ADR test links: #{uncovered_requirements.to_a.sort.join(', ')}"
  end

  undeclared_tests = registered_tests - declared_tests
  unless undeclared_tests.empty?
    failures << "requirements register names undeclared ADR-#{adr_number} tests: #{undeclared_tests.to_a.sort.join(', ')}"
  end

  failures
end

def registered_adr_requirement_test_edges(requirements:, adr_number:)
  test_prefix = "T-ADR-#{adr_number}-"
  requirements.each_with_object(Set.new) do |record, edges|
    Array(record["test_ids"]).each do |test_id|
      edges << [record.fetch("requirement_id"), test_id] if test_id.start_with?(test_prefix)
    end
  end
end

def expected_adr_requirement_test_edges(requirement_test_mapping)
  requirement_test_mapping.each_with_object(Set.new) do |(requirement_id, test_ids), edges|
    test_ids.each { |test_id| edges << [requirement_id, test_id] }
  end
end

def format_adr_requirement_test_edges(edges)
  edges.to_a.sort.map { |edge| edge.join(" -> ") }.join(", ")
end

def exact_adr_requirement_mapping_failures(requirements:, adr_number:, expected_edges:)
  registered_edges = registered_adr_requirement_test_edges(requirements: requirements, adr_number: adr_number)
  failures = []

  missing_edges = expected_edges - registered_edges
  unless missing_edges.empty?
    failures << "ADR-#{adr_number} requirement mapping missing required edges: #{format_adr_requirement_test_edges(missing_edges)}"
  end

  unexpected_edges = registered_edges - expected_edges
  unless unexpected_edges.empty?
    failures << "ADR-#{adr_number} requirement mapping has unexpected edges: #{format_adr_requirement_test_edges(unexpected_edges)}"
  end

  failures
end

def p1_006_adr_gate_failures(adr_gates:, security_issue:)
  failures = []
  expected_candidates = EXPECTED_P1_006_ADR_CANDIDATES.to_set
  actual_gate_dependencies = adr_gates.each_with_object(Set.new) do |(candidate, gate), candidates|
    candidates << candidate if Array(gate["dependent_issues"]).include?("STEAD-P1-006")
  end
  missing_gate_dependencies = expected_candidates - actual_gate_dependencies
  unless missing_gate_dependencies.empty?
    failures << "ADR gates omit STEAD-P1-006 dependencies: #{missing_gate_dependencies.to_a.sort.join(', ')}"
  end
  unexpected_gate_dependencies = actual_gate_dependencies - expected_candidates
  unless unexpected_gate_dependencies.empty?
    failures << "ADR gates add unexpected STEAD-P1-006 dependencies: #{unexpected_gate_dependencies.to_a.sort.join(', ')}"
  end

  if security_issue
    criteria = Array(security_issue["acceptance_criteria"]).join(" ")
    criteria = criteria.gsub(ADR_CANDIDATE_MARKDOWN_UNDERSCORE_PATTERN) do
      Regexp.last_match[:candidate]
    end
    candidate_mentions = criteria.scan(ADR_CANDIDATE_MENTION_PATTERN)
    malformed_candidate_mentions = candidate_mentions.reject { |candidate| candidate.match?(ADR_CANDIDATE_TOKEN_PATTERN) }
    unless malformed_candidate_mentions.empty?
      failures << "STEAD-P1-006 acceptance criteria contain non-exact ADR tokens: #{malformed_candidate_mentions.uniq.sort.join(', ')}"
    end
    acceptance_candidates = candidate_mentions.grep(ADR_CANDIDATE_TOKEN_PATTERN).to_set
    missing_acceptance_candidates = expected_candidates - acceptance_candidates
    unless missing_acceptance_candidates.empty?
      failures << "STEAD-P1-006 acceptance criteria omit ADR gates: #{missing_acceptance_candidates.to_a.sort.join(', ')}"
    end
    unexpected_acceptance_candidates = acceptance_candidates - expected_candidates
    unless unexpected_acceptance_candidates.empty?
      failures << "STEAD-P1-006 acceptance criteria add unexpected ADR gates: #{unexpected_acceptance_candidates.to_a.sort.join(', ')}"
    end
  else
    failures << "implementation issue catalog: missing STEAD-P1-006"
  end

  failures
end

failures = []
requirements = load_yaml("specs/traceability/requirements.yaml").fetch("requirements")
known_requirement_ids = requirements.map { |record| record.fetch("requirement_id") }.to_set
issue_catalog = load_yaml("docs/planning/implementation-issue-catalog.yaml")
adr_gates = issue_catalog.fetch("adr_decision_gates").to_h { |gate| [gate.fetch("adr_id"), gate] }
issues = issue_catalog.fetch("issues").to_h { |issue| [issue.fetch("id"), issue] }
adr_index = ROOT.join("docs/adr/INDEX.md").read(encoding: "UTF-8")
candidate_index = ROOT.join("docs/governance/adr-candidate-index.md").read(encoding: "UTF-8")
choice_queue = ROOT.join("docs/adr/unresolved-implementation-choices.md").read(encoding: "UTF-8")
accepted_numbers = EXPECTED_RECORDS.select { |_number, record| record.fetch(:state) == "ACCEPTED" }.keys.to_set
expected_metadata_numbers = accepted_numbers - LEGACY_ACCEPTED_WITHOUT_IMMUTABLE_METADATA
unless ACCEPTED_RECORD_METADATA.keys.to_set == expected_metadata_numbers
  failures << "accepted ADR metadata mismatch: expected #{expected_metadata_numbers.to_a.sort.join(', ')}, found #{ACCEPTED_RECORD_METADATA.keys.sort.join(', ')}"
end

ACCEPTED_RECORD_METADATA.each do |number, metadata|
  approval_record_path = metadata.fetch(:approval_record_path)
  approval_record = ROOT.join(approval_record_path).read(encoding: "UTF-8")
  immutable_revision = metadata.fetch(:immutable_revision)
  failures << "#{approval_record_path}: ADR-#{number} missing exact immutable decision revision #{immutable_revision}" unless approval_record.include?(immutable_revision)
  metadata.fetch(:approval_records).map { |record| record.fetch("identity") }.uniq.each do |identity|
    failures << "#{approval_record_path}: ADR-#{number} missing reviewer identity #{identity}" unless approval_record.include?(identity)
  end
end

paths = Dir.glob(ROOT.join("docs/adr/0[0-9][0-9][1-9]-*.md")).sort.map { |path| Pathname.new(path) }
actual_numbers = paths.filter_map { |path| path.basename.to_s[/\A(\d{4})-/, 1] }
expected_numbers = EXPECTED_RECORDS.keys
failures << "ADR record set mismatch: expected #{expected_numbers.join(', ')}, found #{actual_numbers.join(', ')}" unless actual_numbers == expected_numbers

all_test_owners = Hash.new { |hash, key| hash[key] = [] }
tests_by_number = {}
requirements_by_number = {}

paths.each do |path|
  basename = path.basename.to_s
  number = basename[/\A(\d{4})-/, 1]
  next unless EXPECTED_RECORDS.key?(number)

  expected = EXPECTED_RECORDS.fetch(number)
  source = path.read(encoding: "UTF-8")
  relative = path.relative_path_from(ROOT).to_s
  expected_adr_id = "ADR-#{number}"

  failures << "#{relative}: title must begin '# #{expected_adr_id}:'" unless source.start_with?("# #{expected_adr_id}:")
  REQUIRED_SECTIONS.each do |section|
    failures << "#{relative}: missing section #{section.inspect}" unless source.match?(/^## #{Regexp.escape(section)}$/)
  end

  status = source[/^- \*\*Status:\*\*\s*(.+)$/, 1]
  expected_status_prefix = expected.fetch(:state) == "ACCEPTED" ? "Accepted" : "Proposed"
  failures << "#{relative}: status must begin #{expected_status_prefix.inspect}" unless status&.start_with?(expected_status_prefix)

  owner_approval = source[/^- \*\*Project-owner approval required:\*\*\s*(yes|no)\b/, 1]
  expected_owner_approval = expected.fetch(:owner_approval) ? "yes" : "no"
  failures << "#{relative}: project-owner approval flag must be #{expected_owner_approval}" unless owner_approval == expected_owner_approval

  requirement_line = source[/^- \*\*Requirement IDs:\*\*\s*(.+)$/, 1]
  requirement_ids = requirement_line.to_s.scan(/`([A-Z]+-\d{3})`/).flatten
  failures << "#{relative}: Requirement IDs header must not be empty" if requirement_ids.empty?
  failures << "#{relative}: duplicate Requirement IDs" unless requirement_ids.uniq.length == requirement_ids.length
  unknown_requirements = requirement_ids.reject { |id| known_requirement_ids.include?(id) }
  failures << "#{relative}: unknown Requirement IDs #{unknown_requirements.join(', ')}" unless unknown_requirements.empty?
  requirements_by_number[number] = requirement_ids

  candidate = expected.fetch(:candidate)
  resolution_line = source.lines.find { |line| line.start_with?("- **Resolves") }
  failures << "#{relative}: must declare that it resolves #{candidate}" unless resolution_line&.include?("`#{candidate}`")

  test_ids = source.scan(/`(T-ADR-#{number}-[A-Z0-9-]+)`/).flatten.uniq
  failures << "#{relative}: must declare at least one exact ADR test ID" if test_ids.empty?
  tests_by_number[number] = test_ids
  test_ids.each { |test_id| all_test_owners[test_id] << relative }

  failures << "docs/adr/INDEX.md: missing #{basename}" unless adr_index.include?("./#{basename}")
  failures << "docs/governance/adr-candidate-index.md: missing #{basename}" unless candidate_index.include?("../adr/#{basename}")
  failures << "docs/adr/unresolved-implementation-choices.md: missing #{basename}" unless choice_queue.include?("./#{basename}")

  gate = adr_gates[candidate]
  unless gate
    failures << "implementation issue catalog: missing decision gate #{candidate}"
    next
  end
  failures << "implementation issue catalog: #{candidate} state must be #{expected.fetch(:state)}" unless gate["state"] == expected.fetch(:state)
  failures << "implementation issue catalog: #{candidate} decision_record must be #{relative}" unless gate["decision_record"] == relative
  failures << "implementation issue catalog: #{candidate} project-owner flag mismatch" unless gate["project_owner_approval_required"] == expected.fetch(:owner_approval)

  acceptance = ACCEPTED_RECORD_METADATA[number]
  unless acceptance
    premature_fields = %w[immutable_revision accepted_at approval_record approval_records].select { |field| gate.key?(field) }
    failures << "implementation issue catalog: proposed #{candidate} carries premature acceptance fields #{premature_fields.join(', ')}" unless premature_fields.empty?
    next
  end

  immutable_revision = acceptance.fetch(:immutable_revision)
  accepted_at = acceptance.fetch(:accepted_at)
  approval_record_path = acceptance.fetch(:approval_record_path)
  expected_approval_records = acceptance.fetch(:approval_records)
  failures << "#{relative}: accepted record must name exact decision revision #{immutable_revision}" unless source.include?(immutable_revision)
  failures << "implementation issue catalog: #{candidate} immutable revision mismatch" unless gate["immutable_revision"] == immutable_revision
  failures << "implementation issue catalog: #{candidate} accepted_at must be #{accepted_at}" unless gate["accepted_at"] == accepted_at
  failures << "implementation issue catalog: #{candidate} approval_record mismatch" unless gate["approval_record"] == approval_record_path
  unless gate["approval_records"] == expected_approval_records
    failures << "implementation issue catalog: #{candidate} approval_records do not match the exact required decision-time dispositions"
  end

  approval_identities = Array(gate["approval_records"]).to_h { |record| [record["role"], record["identity"]] }
  if approval_identities["WS-13-independent-qa"] == approval_identities["WS-13-independent-security"]
    failures << "implementation issue catalog: #{candidate} independent QA and security identities must be distinct"
  end
end

all_test_owners.each do |test_id, owners|
  failures << "#{test_id}: declared by multiple ADR records: #{owners.join(', ')}" unless owners.length == 1
end

adr_0007_traceability_failures = adr_requirement_traceability_failures(
  requirements: requirements,
  adr_number: "0007",
  claimed_requirement_ids: requirements_by_number.fetch("0007", []),
  declared_test_ids: tests_by_number.fetch("0007", [])
)
failures.concat(adr_0007_traceability_failures)

adr_0007_expected_edges = expected_adr_requirement_test_edges(ADR_0007_REQUIREMENT_TEST_MAPPING).freeze
unless adr_0007_expected_edges.length == 36
  failures << "ADR-0007 closed requirement mapping must contain exactly 36 edges, found #{adr_0007_expected_edges.length}"
end

adr_0007_exact_mapping_failures = exact_adr_requirement_mapping_failures(
  requirements: requirements,
  adr_number: "0007",
  expected_edges: adr_0007_expected_edges
)
failures.concat(adr_0007_exact_mapping_failures)

# Delete every required edge independently from a copy of the repository-owned
# registry and exercise the same exact-mapping validator against each mutant.
adr_0007_mutation_survivors = []
adr_0007_expected_edges.to_a.sort.each do |requirement_id, test_id|
  mutated_requirements = requirements.map do |registered_requirement|
    registered_requirement.merge("test_ids" => Array(registered_requirement["test_ids"]).dup)
  end
  mutated_record = mutated_requirements.find { |record| record.fetch("requirement_id") == requirement_id }
  removed_test = mutated_record&.fetch("test_ids", [])&.delete(test_id)
  if removed_test.nil?
    adr_0007_mutation_survivors << "#{requirement_id} -> #{test_id} (edge absent before mutation)"
    next
  end

  mutation_failures = exact_adr_requirement_mapping_failures(
    requirements: mutated_requirements,
    adr_number: "0007",
    expected_edges: adr_0007_expected_edges
  )
  if mutation_failures.empty?
    adr_0007_mutation_survivors << "#{requirement_id} -> #{test_id}"
  end
end
unless adr_0007_mutation_survivors.empty?
  failures << "ADR-0007 exact-mapping mutation survivors: #{adr_0007_mutation_survivors.join(', ')}"
end

security_issue = issues["STEAD-P1-006"]
failures.concat(p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: security_issue))

# Exercise the coupled failure mode explicitly: deleting the same security ADR
# from both the decision-gate dependency list and the dependent issue text must
# be caught independently at both boundaries.
if security_issue && adr_gates["ADR-CAND-002"]
  mutated_adr_gates = adr_gates.transform_values do |gate|
    gate.merge("dependent_issues" => Array(gate["dependent_issues"]).dup)
  end
  mutated_adr_gates.fetch("ADR-CAND-002").fetch("dependent_issues").delete("STEAD-P1-006")
  mutated_security_issue = security_issue.merge(
    "acceptance_criteria" => Array(security_issue["acceptance_criteria"]).map do |criterion|
      criterion.gsub("ADR-CAND-002", "ADR-CAND-REMOVED-BY-MUTANT")
    end
  )
  mutation_failures = p1_006_adr_gate_failures(
    adr_gates: mutated_adr_gates,
    security_issue: mutated_security_issue
  )
  missing_dependency_killed = mutation_failures.any? do |failure|
    failure.start_with?("ADR gates omit STEAD-P1-006 dependencies:") && failure.include?("ADR-CAND-002")
  end
  missing_acceptance_killed = mutation_failures.any? do |failure|
    failure.start_with?("STEAD-P1-006 acceptance criteria omit ADR gates:") && failure.include?("ADR-CAND-002")
  end
  unless missing_dependency_killed && missing_acceptance_killed
    failures << "STEAD-P1-006 paired ADR-CAND-002 deletion mutant survived one or both independent gate checks"
  end

  added_adr_gates = adr_gates.transform_values do |gate|
    gate.merge("dependent_issues" => Array(gate["dependent_issues"]).dup)
  end
  added_adr_gates.fetch("ADR-CAND-001").fetch("dependent_issues") << "STEAD-P1-006"
  added_security_issue = security_issue.merge(
    "acceptance_criteria" => Array(security_issue["acceptance_criteria"]).dup << "Unexpected mutant ADR-CAND-001."
  )
  addition_failures = p1_006_adr_gate_failures(
    adr_gates: added_adr_gates,
    security_issue: added_security_issue
  )
  unexpected_dependency_killed = addition_failures.any? do |failure|
    failure.start_with?("ADR gates add unexpected STEAD-P1-006 dependencies:") && failure.include?("ADR-CAND-001")
  end
  unexpected_acceptance_killed = addition_failures.any? do |failure|
    failure.start_with?("STEAD-P1-006 acceptance criteria add unexpected ADR gates:") && failure.include?("ADR-CAND-001")
  end
  unless unexpected_dependency_killed && unexpected_acceptance_killed
    failures << "STEAD-P1-006 paired ADR-CAND-001 addition mutant survived one or both exact-set checks"
  end

  {
    "numeric suffix" => "ADR-CAND-0020",
    "hyphen suffix" => "ADR-CAND-002-EXTRA",
    "underscore suffix" => "ADR-CAND-002_EXTRA",
    "embedded prefix" => "XADR-CAND-002"
  }.each do |mutation_name, replacement|
    nonexact_token_issue = security_issue.merge(
      "acceptance_criteria" => Array(security_issue["acceptance_criteria"]).map do |criterion|
        criterion.gsub("ADR-CAND-002", replacement)
      end
    )
    nonexact_token_failures = p1_006_adr_gate_failures(
      adr_gates: adr_gates,
      security_issue: nonexact_token_issue
    )
    malformed_token_killed = nonexact_token_failures.any? do |failure|
      failure.start_with?("STEAD-P1-006 acceptance criteria contain non-exact ADR tokens:") && failure.include?(replacement)
    end
    missing_token_killed = nonexact_token_failures.any? do |failure|
      failure.start_with?("STEAD-P1-006 acceptance criteria omit ADR gates:") && failure.include?("ADR-CAND-002")
    end
    unless malformed_token_killed && missing_token_killed
      failures << "STEAD-P1-006 #{mutation_name} ADR-CAND-002 mutant survived exact-token parsing"
    end
  end

  {
    "single underscore emphasis" => "_ADR-CAND-002_",
    "double underscore emphasis" => "__ADR-CAND-002__",
    "triple underscore emphasis" => "___ADR-CAND-002___"
  }.each do |format_name, replacement|
    formatted_security_issue = security_issue.merge(
      "acceptance_criteria" => Array(security_issue["acceptance_criteria"]).map do |criterion|
        criterion.gsub("ADR-CAND-002", replacement)
      end
    )
    format_failures = p1_006_adr_gate_failures(
      adr_gates: adr_gates,
      security_issue: formatted_security_issue
    )
    unless format_failures.empty?
      failures << "STEAD-P1-006 valid #{format_name} failed exact-token parsing: #{format_failures.join('; ')}"
    end
  end
end

migration_namespace_issue = issues["STEAD-P1-017"]
if migration_namespace_issue
  expected_requirements = %w[ARCH-004 DEP-005 OPS-003 OPS-004 TEST-007]
  expected_dependencies = %w[GATE-P0-APPROVED STEAD-P1-001 STEAD-P1-015]
  expected_owned_directories = %w[
    modules/migration
    tests/contract/migration
    tests/integration/migration
    packages/test-fixtures/migration
  ]
  expected_tests = %w[
    T-STEAD-P1-017-CONTRACT
    T-ARCH-004-ACCEPTANCE
    T-DEP-005-ACCEPTANCE
    T-OPS-003-ACCEPTANCE
    T-OPS-004-ACCEPTANCE
    T-TEST-007-ACCEPTANCE
    T-ADR-0007-NAMESPACE-ROLES
    T-ADR-0007-FOREIGN-WRITE-DENIAL
    T-ADR-0007-MIGRATION-ORDERING
    T-ADR-0007-UPGRADE-ROLLBACK
  ]

  failures << "STEAD-P1-017 owner must be WS-11" unless migration_namespace_issue["owner"] == "WS-11"
  failures << "STEAD-P1-017 requirements must match live issue #30" unless migration_namespace_issue["requirement_ids"] == expected_requirements
  failures << "STEAD-P1-017 dependencies must remain limited to its gate, foundation, and generic harness" unless migration_namespace_issue["dependencies"] == expected_dependencies
  failures << "STEAD-P1-017 owned directories must remain WS-11 migration-only" unless migration_namespace_issue["owned_directories"] == expected_owned_directories
  failures << "STEAD-P1-017 automated tests must preserve its bounded requirement and ADR case split" unless migration_namespace_issue["automated_tests"] == expected_tests

  boundaries = Array(migration_namespace_issue["prohibited_boundaries"]).join(" ")
  %w[import mapping cutover redirect provider-sync aggregate traceability].each do |required_boundary|
    failures << "STEAD-P1-017 prohibited boundaries omit #{required_boundary}" unless boundaries.include?(required_boundary)
  end
else
  failures << "implementation issue catalog: missing STEAD-P1-017"
end

adr_0007_gate = adr_gates["ADR-CAND-002"]
unless Array(adr_0007_gate&.fetch("dependent_issues", nil)).include?("STEAD-P1-017")
  failures << "implementation issue catalog: ADR-CAND-002 dependent issues omit STEAD-P1-017"
end

%w[STEAD-P1-011 STEAD-P1-012].each do |dependent_issue_id|
  dependent_issue = issues[dependent_issue_id]
  if dependent_issue.nil?
    failures << "implementation issue catalog: missing #{dependent_issue_id}"
  elsif !Array(dependent_issue["dependencies"]).include?("STEAD-P1-017")
    failures << "#{dependent_issue_id} dependencies omit STEAD-P1-017"
  end
end

implementation_assignments = {
  "0002" => {
    "STEAD-P1-006" => tests_by_number.fetch("0002", []).reject { |test_id| test_id == "T-ADR-0002-CUI-PROFILE" },
    "STEAD-P3-002" => %w[
      T-ADR-0002-CUI-PROFILE
    ]
  },
  "0003" => {
    "STEAD-P1-006" => tests_by_number.fetch("0003", [])
  },
  "0004" => {
    "STEAD-P1-002" => %w[
      T-ADR-0004-ROLE-ENUM
      T-ADR-0004-SUBJECT-TYPES
      T-ADR-0004-LEAD-CARDINALITY
      T-ADR-0004-ACCOUNTABILITY-NON-GRANT
      T-ADR-0004-REVOCATION-AND-SOURCES
      T-ADR-0004-MIGRATION-ROLLBACK
    ],
    "STEAD-P1-004" => %w[
      T-ADR-0004-ACCOUNTABILITY-NON-GRANT
    ],
    "STEAD-P1-005" => %w[
      T-ADR-0004-ACCOUNTABILITY-NON-GRANT
      T-ADR-0004-NONDISCLOSURE
    ],
    "STEAD-P1-006" => %w[
      T-ADR-0004-PERMISSION-MATRIX
      T-ADR-0004-SUBJECT-TYPES
      T-ADR-0004-HIERARCHY-NON-GRANT
      T-ADR-0004-ACCOUNTABILITY-NON-GRANT
      T-ADR-0004-GROUP-PROVISIONING
      T-ADR-0004-REVOCATION-AND-SOURCES
      T-ADR-0004-NONDISCLOSURE
    ]
  },
  "0005" => {
    "STEAD-P1-003" => %w[
      T-ADR-0005-PROVIDER-PATH
    ],
    "STEAD-P1-006" => %w[
      T-ADR-0005-TOPOLOGY
      T-ADR-0005-FAIL-CLOSED
      T-ADR-0005-MODE-SELECTION
      T-ADR-0005-REQUEST-BOUNDARY
      T-ADR-0005-COMMIT-BOUNDARY-SEAM
      T-ADR-0005-ZERO-CACHE
      T-ADR-0005-DETERMINISM
      T-ADR-0005-FENCE
      T-ADR-0005-AGENT-INTERSECTION
      T-ADR-0005-PRINCIPALS
    ],
    "STEAD-P1-007" => %w[
      T-ADR-0005-REQUEST-BOUNDARY
      T-ADR-0005-OBSERVABILITY
    ],
    "STEAD-P1-008" => %w[
      T-ADR-0005-REQUEST-BOUNDARY
      T-ADR-0005-NONDISCLOSURE
    ],
    "STEAD-P1-011" => %w[
      T-ADR-0005-MIGRATION-ROLLBACK
      T-ADR-0005-OBSERVABILITY
    ],
    "STEAD-P1-015" => %w[
      T-ADR-0005-SEQUENCE
      T-ADR-0005-FENCE
      T-ADR-0005-REQUEST-BOUNDARY
      T-ADR-0005-COMMIT-BOUNDARY-SEAM
    ],
    "STEAD-P3-002" => %w[
      T-ADR-0005-COMMIT-BOUNDARY
    ],
    "STEAD-P3-007" => %w[
      T-ADR-0005-COMMIT-BOUNDARY
    ]
  },
  "0006" => {
    "STEAD-P1-006" => %w[
      T-ADR-0006-DSSE
      T-ADR-0006-CONTENT-INTEGRITY
      T-ADR-0006-ARCHIVE-SAFETY
      T-ADR-0006-TRUST-ROTATION
      T-ADR-0006-RECOVERY
      T-ADR-0006-MODEL-BINDING
      T-ADR-0006-ATOMIC-ACTIVATION
      T-ADR-0006-MIGRATION
      T-ADR-0006-POLICY-CONFORMANCE
      T-ADR-0006-ROLLBACK
      T-ADR-0006-FAILURE-INJECTION
      T-ADR-0006-AUDIT-PRIVACY
      T-ADR-0006-ASSURANCE-POLICY
      T-ADR-0006-CUSTODIAN-SEPARATION
      T-ADR-0006-TUF-NONAUTHORITY
    ],
    "STEAD-P1-011" => %w[
      T-ADR-0006-TRANSPORT-IDENTITY
      T-ADR-0006-TRUST-ROTATION
      T-ADR-0006-RECOVERY
      T-ADR-0006-OFFLINE
      T-ADR-0006-ATOMIC-ACTIVATION
      T-ADR-0006-ROLLBACK
      T-ADR-0006-FAILURE-INJECTION
      T-ADR-0006-BACKUP-RESTORE
      T-ADR-0006-AUDIT-PRIVACY
      T-ADR-0006-ASSURANCE-POLICY
      T-ADR-0006-CUSTODIAN-SEPARATION
      T-ADR-0006-TUF-NONAUTHORITY
    ],
    "STEAD-P1-015" => %w[
      T-ADR-0006-ATOMIC-ACTIVATION
      T-ADR-0006-AUDIT-PRIVACY
    ],
    "STEAD-P1-016" => %w[
      T-ADR-0006-DETERMINISTIC-BUILD
      T-ADR-0006-TRANSPORT-IDENTITY
      T-ADR-0006-DSSE
      T-ADR-0006-CONTENT-INTEGRITY
      T-ADR-0006-ARCHIVE-SAFETY
      T-ADR-0006-POLICY-CONFORMANCE
      T-ADR-0006-ASSURANCE-POLICY
      T-ADR-0006-CUSTODIAN-SEPARATION
      T-ADR-0006-TUF-NONAUTHORITY
    ],
    "STEAD-P3-007" => %w[
      T-ADR-0006-AIRGAP-EVIDENCE
    ]
  },
  "0007" => {
    "STEAD-P1-002" => %w[
      T-ADR-0007-NAMESPACE-ROLES
      T-ADR-0007-FOREIGN-WRITE-DENIAL
      T-ADR-0007-TRANSACTION-PORTS
      T-ADR-0007-OUTBOX-ATOMICITY
      T-ADR-0007-CROSS-MODULE-READS
      T-ADR-0007-MIGRATION-ORDERING
      T-ADR-0007-UPGRADE-ROLLBACK
      T-ADR-0007-OBSERVABILITY-PERFORMANCE
    ],
    "STEAD-P1-003" => %w[
      T-ADR-0007-NAMESPACE-ROLES
      T-ADR-0007-FOREIGN-WRITE-DENIAL
      T-ADR-0007-MIGRATION-ORDERING
      T-ADR-0007-UPGRADE-ROLLBACK
    ],
    "STEAD-P1-004" => %w[
      T-ADR-0007-NAMESPACE-ROLES
      T-ADR-0007-FOREIGN-WRITE-DENIAL
      T-ADR-0007-MIGRATION-ORDERING
      T-ADR-0007-UPGRADE-ROLLBACK
    ],
    "STEAD-P1-006" => %w[
      T-ADR-0007-NAMESPACE-ROLES
      T-ADR-0007-FOREIGN-WRITE-DENIAL
      T-ADR-0007-TRANSACTION-PORTS
      T-ADR-0007-OUTBOX-ATOMICITY
      T-ADR-0007-DURABLE-EFFECTS
      T-ADR-0007-MIGRATION-ORDERING
      T-ADR-0007-UPGRADE-ROLLBACK
      T-ADR-0007-FAILURE-INJECTION
      T-ADR-0007-OBSERVABILITY-PERFORMANCE
    ],
    "STEAD-P1-007" => %w[
      T-ADR-0007-NAMESPACE-ROLES
      T-ADR-0007-FOREIGN-WRITE-DENIAL
      T-ADR-0007-TRANSACTION-PORTS
      T-ADR-0007-OUTBOX-ATOMICITY
      T-ADR-0007-CROSS-MODULE-READS
      T-ADR-0007-MIGRATION-ORDERING
      T-ADR-0007-UPGRADE-ROLLBACK
      T-ADR-0007-FAILURE-INJECTION
      T-ADR-0007-OBSERVABILITY-PERFORMANCE
    ],
    "STEAD-P1-008" => %w[
      T-ADR-0007-NAMESPACE-ROLES
      T-ADR-0007-FOREIGN-WRITE-DENIAL
      T-ADR-0007-CROSS-MODULE-READS
      T-ADR-0007-MIGRATION-ORDERING
      T-ADR-0007-UPGRADE-ROLLBACK
    ],
    "STEAD-P1-009" => %w[
      T-ADR-0007-NAMESPACE-ROLES
      T-ADR-0007-FOREIGN-WRITE-DENIAL
      T-ADR-0007-MIGRATION-ORDERING
      T-ADR-0007-UPGRADE-ROLLBACK
    ],
    "STEAD-P1-017" => %w[
      T-ADR-0007-NAMESPACE-ROLES
      T-ADR-0007-FOREIGN-WRITE-DENIAL
      T-ADR-0007-MIGRATION-ORDERING
      T-ADR-0007-UPGRADE-ROLLBACK
    ],
    "STEAD-P1-011" => %w[
      T-ADR-0007-NAMESPACE-ROLES
      T-ADR-0007-FOREIGN-WRITE-DENIAL
      T-ADR-0007-MIGRATION-ORDERING
      T-ADR-0007-UPGRADE-ROLLBACK
      T-ADR-0007-BACKUP-RESTORE
      T-ADR-0007-FAILURE-INJECTION
      T-ADR-0007-OBSERVABILITY-PERFORMANCE
    ],
    "STEAD-P1-015" => %w[
      T-ADR-0007-NAMESPACE-ROLES
      T-ADR-0007-FOREIGN-WRITE-DENIAL
      T-ADR-0007-TRANSACTION-PORTS
      T-ADR-0007-OUTBOX-ATOMICITY
      T-ADR-0007-DURABLE-EFFECTS
      T-ADR-0007-MIGRATION-ORDERING
      T-ADR-0007-UPGRADE-ROLLBACK
      T-ADR-0007-FAILURE-INJECTION
      T-ADR-0007-OBSERVABILITY-PERFORMANCE
    ]
  }
}.freeze

implementation_assignments.each do |number, issue_assignments|
  declared_tests = tests_by_number.fetch(number, []).to_set
  issue_assignments.each do |issue_id, assigned_tests|
    issue = issues[issue_id]
    unless issue
      failures << "implementation issue catalog: missing #{issue_id} for ADR-#{number} ownership split"
      next
    end

    unknown_tests = assigned_tests.to_set - declared_tests
    failures << "#{issue_id} ADR-#{number} assignment names undeclared tests: #{unknown_tests.to_a.sort.join(', ')}" unless unknown_tests.empty?
    missing_tests = assigned_tests.to_set - Array(issue["automated_tests"]).to_set
    failures << "#{issue_id} automated tests omit assigned ADR-#{number} obligations: #{missing_tests.to_a.sort.join(', ')}" unless missing_tests.empty?
  end

  implementation_coverage = issue_assignments.values.flatten.to_set
  missing_implementation_tests = declared_tests - implementation_coverage
  failures << "ADR-#{number} owner-split implementation coverage omits: #{missing_implementation_tests.to_a.sort.join(', ')}" unless missing_implementation_tests.empty?
end

phase_one_adr5_tests = tests_by_number.fetch("0005", []).reject { |test_id| test_id == "T-ADR-0005-COMMIT-BOUNDARY" }
phase_one_independent_tests = tests_by_number.slice("0003", "0004").values.flatten.to_set
phase_one_independent_tests.merge(phase_one_adr5_tests)
phase_one_independent_tests.merge(
  tests_by_number.fetch("0002", []).reject { |test_id| test_id == "T-ADR-0002-CUI-PROFILE" }
)
phase_one_independent_tests.merge(
  tests_by_number.fetch("0006", []).reject { |test_id| test_id == "T-ADR-0006-AIRGAP-EVIDENCE" }
)
phase_one_independent_tests.merge(tests_by_number.fetch("0007", []))
phase_three_independent_tests = Set[
  "T-ADR-0002-CUI-PROFILE",
  "T-ADR-0005-COMMIT-BOUNDARY",
  "T-ADR-0006-AIRGAP-EVIDENCE"
]

{
  "STEAD-P1-012" => phase_one_independent_tests,
  "STEAD-P3-008" => phase_three_independent_tests
}.each do |issue_id, assigned_tests|
  issue = issues[issue_id]
  unless issue
    failures << "implementation issue catalog: missing #{issue_id} for independent ADR coverage"
    next
  end

  missing_tests = assigned_tests - Array(issue["automated_tests"]).to_set
  failures << "#{issue_id} independent ADR coverage omits: #{missing_tests.to_a.sort.join(', ')}" unless missing_tests.empty?
end

phase_three_independent_tests.each do |future_test|
  issues.each_value do |issue|
    next unless issue["phase"] == "phase-1"

    if Array(issue["automated_tests"]).include?(future_test)
      failures << "#{issue.fetch('id')} must defer #{future_test} to Phase 3"
    end
  end
end

phase_one_operations = issues["STEAD-P1-011"]
if phase_one_operations
  failures << "STEAD-P1-011 must defer DEP-004 to Phase 3" if Array(phase_one_operations["requirement_ids"]).include?("DEP-004")
  failures << "STEAD-P1-011 must not own deploy/airgap" if Array(phase_one_operations["owned_directories"]).include?("deploy/airgap")
end

catalog_test_ids = issues.values.flat_map { |issue| Array(issue["automated_tests"]) }.to_set
catalog_adr_test_ids = ROOT.join("docs/planning/implementation-issue-catalog.yaml")
                           .read(encoding: "UTF-8")
                           .scan(/T-ADR-\d{4}-[A-Z0-9-]+/)
                           .to_set
undeclared_catalog_adr_tests = catalog_adr_test_ids - all_test_owners.keys.to_set
unless undeclared_catalog_adr_tests.empty?
  failures << "implementation issue catalog names undeclared or retired ADR tests: #{undeclared_catalog_adr_tests.to_a.sort.join(', ')}"
end
missing_accepted_tests = tests_by_number.fetch("0001", []).to_set - catalog_test_ids
failures << "implementation issue catalog omits accepted ADR-0001 tests: #{missing_accepted_tests.to_a.sort.join(', ')}" unless missing_accepted_tests.empty?

if failures.empty?
  killed_mutations = adr_0007_expected_edges.length - adr_0007_mutation_survivors.length
  puts "ADR-0007 exact-mapping mutation guard: PASS (#{killed_mutations}/#{adr_0007_expected_edges.length} required edge deletions killed)"
  puts "ADR traceability validation: PASS (records=#{paths.length}, requirements=#{known_requirement_ids.length}, tests=#{all_test_owners.length})"
else
  warn "ADR traceability validation: FAIL (#{failures.length} issue#{failures.length == 1 ? '' : 's'})"
  failures.each { |failure| warn "- #{failure}" }
  exit 1
end
