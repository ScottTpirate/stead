#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
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
  "0007" => { candidate: "ADR-CAND-002", state: "ACCEPTED", owner_approval: false },
  "0008" => { candidate: "ADR-CAND-006", state: "PROPOSED", owner_approval: false }
}.freeze

ADR_0008_REQUIREMENT_TEST_MAPPING = {
  "EVT-001" => %w[
    T-ADR-0008-SUBJECT-PARTITION
    T-ADR-0008-SUBSCRIBER-ISOLATION
    T-ADR-0008-RETENTION
    T-ADR-0008-AUTHORIZED-REPLAY
  ],
  "EVT-002" => %w[
    T-ADR-0008-SUBJECT-PARTITION
    T-ADR-0008-RETENTION
    T-ADR-0008-IDEMPOTENCY
    T-ADR-0008-OUTBOX-RECOVERY-PORT
  ],
  "EVT-003" => %w[
    T-ADR-0008-SUBJECT-PARTITION
    T-ADR-0008-RESOURCE-ORDERING
    T-ADR-0008-RETENTION
    T-ADR-0008-IDEMPOTENCY
    T-ADR-0008-AUTHORIZED-REPLAY
    T-ADR-0008-SCHEMA-COMPATIBILITY
    T-ADR-0008-PAYLOAD-MINIMIZATION
  ],
  "EVT-004" => %w[
    T-ADR-0008-RESOURCE-ORDERING
    T-ADR-0008-RETENTION
    T-ADR-0008-IDEMPOTENCY
    T-ADR-0008-DLQ
    T-ADR-0008-AUTHORIZED-REPLAY
    T-ADR-0008-SCHEMA-COMPATIBILITY
    T-ADR-0008-PROJECTION-REBUILD
  ],
  "ACT-001" => %w[
    T-ADR-0008-RESOURCE-ORDERING
    T-ADR-0008-IDEMPOTENCY
    T-ADR-0008-PAYLOAD-MINIMIZATION
    T-ADR-0008-PROJECTION-REBUILD
  ],
  "NOTIF-001" => %w[
    T-ADR-0008-RESOURCE-ORDERING
    T-ADR-0008-IDEMPOTENCY
    T-ADR-0008-PAYLOAD-MINIMIZATION
    T-ADR-0008-PROJECTION-REBUILD
  ],
  "AUD-001" => %w[
    T-ADR-0008-AUTHORIZED-REPLAY
    T-ADR-0008-PAYLOAD-MINIMIZATION
  ],
  "AUD-002" => %w[
    T-ADR-0008-AUTHORIZED-REPLAY
    T-ADR-0008-PAYLOAD-MINIMIZATION
  ],
  "CLS-006" => %w[
    T-ADR-0008-SUBJECT-PARTITION
    T-ADR-0008-SUBSCRIBER-ISOLATION
    T-ADR-0008-AUTHORIZED-REPLAY
    T-ADR-0008-PAYLOAD-MINIMIZATION
    T-ADR-0008-PROJECTION-REBUILD
  ],
  "TEST-005" => %w[
    T-ADR-0008-SUBJECT-PARTITION
    T-ADR-0008-SUBSCRIBER-ISOLATION
    T-ADR-0008-RESOURCE-ORDERING
    T-ADR-0008-RETENTION
    T-ADR-0008-IDEMPOTENCY
    T-ADR-0008-DLQ
    T-ADR-0008-AUTHORIZED-REPLAY
      T-ADR-0008-SCHEMA-COMPATIBILITY
      T-ADR-0008-PAYLOAD-MINIMIZATION
      T-ADR-0008-ASYNC-PERFORMANCE
      T-ADR-0008-PROJECTION-REBUILD
    ],
    "PERF-002" => %w[
      T-ADR-0008-ASYNC-PERFORMANCE
    ],
    "PERF-003" => %w[
      T-ADR-0008-RESOURCE-ORDERING
      T-ADR-0008-ASYNC-PERFORMANCE
      T-ADR-0008-PROJECTION-REBUILD
    ],
    "PERF-004" => %w[
      T-ADR-0008-ASYNC-PERFORMANCE
    ],
    "DEP-001" => %w[
      T-ADR-0008-SUBJECT-PARTITION
    ],
    "DEP-005" => %w[
      T-ADR-0008-RETENTION
    ],
    "OPS-003" => %w[
      T-ADR-0008-PROJECTION-REBUILD
    ],
    "OPS-004" => %w[
      T-ADR-0008-PROJECTION-REBUILD
    ],
    "SEC-003" => %w[
      T-ADR-0008-SUBSCRIBER-ISOLATION
    ]
}.freeze

ADR_0008_LOGICAL_PRODUCER_SOURCES = {
  "organizationEvents" => "urn:stead:producer:organization",
  "identityEvents" => "urn:stead:producer:identity",
  "authorizationEvents" => "urn:stead:producer:authorization",
  "classificationEvents" => "urn:stead:producer:classification",
  "projectEvents" => "urn:stead:producer:project",
  "workEvents" => "urn:stead:producer:workitem",
  "commentEvents" => "urn:stead:producer:comment",
  "knowledgeEvents" => "urn:stead:producer:document",
  "scmEvents" => "urn:stead:producer:scm",
  "ciEvents" => "urn:stead:producer:ci",
  "artifactEvents" => "urn:stead:producer:artifact",
  "attachmentEvents" => "urn:stead:producer:attachment",
  "storageEvents" => "urn:stead:producer:storage",
  "searchGraphEvents" => "urn:stead:producer:search_graph",
  "notificationEvents" => "urn:stead:producer:notification",
  "auditEvents" => "urn:stead:producer:audit",
  "migrationEvents" => "urn:stead:producer:migration",
  "operationsEvents" => "urn:stead:producer:operations",
  "deadLetterEvents" => "urn:stead:producer:dead_letter"
}.freeze

ADR_0008_LOGICAL_PRODUCER_SOURCE_PATTERN =
  "^urn:stead:producer:(organization|identity|authorization|classification|project|workitem|comment|document|scm|ci|artifact|attachment|storage|search_graph|notification|audit|migration|operations|dead_letter)$"

ADR_0008_SERVERS = {
  "nats" => {
    "host" => "nats:4222",
    "protocol" => "nats",
    "x-production-transport" => "verified-mutual-tls",
    "x-tls-handshake-first" => "required-no-fallback"
  }
}.freeze

ADR_0008_DELIVERY_CONTRACT = {
  "delivery" => "at-least-once",
  "producer" => "transactional-outbox",
  "consumer" => "idempotent",
  "ordering" => "per-resource-only",
  "replay" => "authorized-and-audited",
  "dlq" => "required",
  "protected-body-payloads" => "prohibited",
  "logical-producer-source" => "closed-asyncapi-channel-registry",
  "account-topology" => "one-application-account-per-deployment-security-domain",
  "organization-broker-provisioning" => "forbidden",
  "stream-topology" => "two-fixed-streams-per-deployment-security-domain",
  "credential-topology" => "service-role-only-no-browser-or-end-user",
  "publish-ack-authority" => "transport-publication-only",
  "canonical-event" => "exact-stored-bytes-stable-identity-semantic-key-and-digest",
  "required-consumers" => "ws-07-closed-versioned-registry-frozen-in-authoritative-outbox",
  "core-outbox-owner" => "ws-02-provider-neutral-typed-port",
  "consumer-completion-owner" => "each-consumer-module",
  "publication-generation" => "provider-neutral-monotonic-fenced-cas",
  "nats-message-id" => "versioned-stable-per-canonical-event-digest-and-generation",
  "ambiguous-publish-retry" => "same-generation-same-message-id-across-retry-restart-and-restore",
  "recovery-publication" => "next-generation-new-message-id-same-canonical-event",
  "duplicate-false" => "sufficient-transport-publication-evidence",
  "duplicate-true" => "insufficient-until-regular-leader-stream-get-exact-match",
  "duplicate-readback-match" => "sequence-subject-message-id-canonical-identity-semantic-key-and-digest",
  "missing-readback" => "fenced-generation-advance-and-unchanged-canonical-republish",
  "mismatched-readback" => "quarantine-and-no-retirement",
  "direct-read" => "forbidden-allow-direct-false",
  "duplicate-window" => "positive-and-strictly-less-than-maxage-minus-positive-safety-margin",
  "recovery-source" => "postgresql-outbox-until-all-required-consumers-durable",
  "broker-expiry" => "bounded-republish-same-canonical-identity",
  "source-retirement" => "all-required-success-or-minimized-terminal-dlq-audit",
  "broker-max-deliver" => "unlimited-until-durable-terminal-outcome",
  "terminal-attempt-authority" => "consumer-owner-postgresql",
  "production-transport" => "verified-mutual-tls-no-fallback",
  "jetstream-at-rest-encryption" => "required-secretprovider-reference",
  "broker-manifest" => "closed-version-pinned-complete-readback",
  "manifest-owner" => "ws-12-renders-pins-validates-ws-07-registry",
  "failure-evidence" => "closed-minimized-postgresql-and-backup"
}.freeze

# CBI-030 is a security control, not free-form traceability prose. Pinning its
# complete row prevents an additive contradiction from surviving while the
# required positive fragments remain present.
ADR_0008_CBI_030_SHA256 =
  "25b5d8e6e7c32b572635a02622e8c429b54de8bbfed876b220d16e05da851082".freeze

ADR_0008_EXPECTED_SECURITY_MUTATION_GROUPS = {
  topology: 9,
  authorization: 1,
  streams: 1,
  delivery: 2,
  retention_recovery: 81,
  replay_recovery: 1,
  credentials: 11,
  tls: 1,
  opaque_receipt: 1,
  additive_contradiction: 1
}.freeze
ADR_0008_EXPECTED_SECURITY_MUTATION_COUNT =
  ADR_0008_EXPECTED_SECURITY_MUTATION_GROUPS.values.sum

ADR_0008_REQUIRED_DECISION_CLAUSES = {
  topology: [
    "one internal Stead NATS application account for each deployment security domain",
    "Organization creation never creates a NATS account, user, signing key, resolver entry, stream, or other broker resource",
    "Browser sessions, end users, external Agent runtimes, provider credentials, and ordinary API credentials receive no NATS credentials",
    "future per-Organization account topology is optional"
  ],
  authorization: [
    "No consumer may use account membership, subject access, or an event as an authorization grant",
    "perform the current central authorization and fence checks"
  ],
  streams: [
    "STEAD_EVENTS_V1",
    "STEAD_DLQ_V1",
    "small fixed stream set, not a stream set per Organization",
    "DiscardNew"
  ],
  delivery: [
    "API responses never wait for publication, a consumer, replay, or NATS availability",
    "active registry revision and closed required-consumer set are frozen into each outbox record in the authoritative transaction",
    "A successful JetStream acknowledgement with `duplicate:false` is sufficient transport-publication evidence for its generation",
    "An acknowledgement with `duplicate:true` is not sufficient by itself",
    "ordinary leader-served stream-message get path",
    "allow_direct: false",
    "every required consumer in the event's frozen registry has durably recorded success or a minimized terminal outcome with its dead-letter and logical audit intents"
  ],
  retention_recovery: [
    "provider-neutral monotonically increasing `publication_generation`",
    "stable across an ambiguous acknowledgement, safe retry, process restart, or restore of that generation",
    "A definitive missing result advances `publication_generation`",
    "A mismatch quarantines the attempt and leaves the PostgreSQL source unretired",
    "Broker age, administrative removal, stream replacement, or retention expiry is a transport event, not a delivery terminal",
    "republishes the retained canonical event under the same CloudEvent source, id, semantic idempotency key, canonical bytes, and payload digest",
    "Only durable success or that complete terminal transaction satisfies the frozen consumer registry and permits recovery-source retirement"
  ],
  replay_recovery: [
    "Replay is requested through a centrally authorized Stead operation",
    "JetStream is reconstructible transport, not backup authority",
    "expiry or loss of all streams must still permit incomplete events to advance generation when required, republish unchanged canonical events, complete terminal outcomes and their DLQ/audit intents, and rebuild projections"
  ],
  credentials: [
    "Production NATS client and cluster links use authenticated encrypted transport with peer verification and no plaintext fallback",
    "requires no operator-key ceremony, account JWT signing hierarchy, or external resolver"
  ]
}.transform_values(&:freeze).freeze

ADR_0008_FORBIDDEN_DECISION_CLAUSES = [
  "Every event-ready Organization has exactly one event partition",
  "For each partition generation the controller creates an account key",
  "one account per Organization/security-domain pair",
  "four stream configs"
].freeze

ADR_0008_PROPOSED_STATUS_LINE = "- **Status:** Proposed\n".freeze
ADR_0008_ACCEPTED_STATUS_PATTERN =
  /\A- \*\*Status:\*\* Accepted at immutable decision revision `[0-9a-f]{40}` on [0-9]{4}-[0-9]{2}-[0-9]{2}\n\z/
ADR_0008_PROPOSED_RESOLUTION_LINE =
  "- **Resolves on acceptance:** `ADR-CAND-006`\n".freeze
ADR_0008_ACCEPTED_RESOLUTION_LINE = "- **Resolves:** `ADR-CAND-006`\n".freeze
ADR_0008_REVIEWS_HEADING = "## Reviews and approvals\n".freeze
ADR_0008_NORMALIZED_STATUS_LINE =
  "- **Status:** <normalized-proposed-or-accepted-immutable-revision>\n".freeze
ADR_0008_NORMALIZED_RESOLUTION_LINE = "- **Resolution:** `ADR-CAND-006`\n".freeze
ADR_0008_NORMALIZED_REVIEWS_SECTION =
  "## Reviews and approvals\n<normalized-review-and-approval-records>\n".freeze
ADR_0008_DECISION_HEADING = "Decision".freeze
ADR_0008_DECISION_NEXT_HEADING = "Considered options".freeze
ADR_0008_SUBSTANTIVE_SOURCE_SHA256 =
  "f40b18cff7cddfffadcd359335e72f95a255233de01c57b2c7fc66982f1ead34".freeze

EXPECTED_P1_006_ADR_CANDIDATES = %w[
  ADR-CAND-002
  ADR-CAND-003
  ADR-CAND-004
  ADR-CAND-005
  ADR-CAND-007
  ADR-CAND-021
].freeze
EXPECTED_P1_006_ADR_GATE_CLAUSE =
  "Only after ADR-CAND-002, ADR-CAND-003, ADR-CAND-004, ADR-CAND-005, ADR-CAND-007, and ADR-CAND-021 are accepted,".freeze
P1_006_RAW_ISSUES_KEY_LINE = "issues:".freeze
P1_006_RAW_ISSUE_ID_LINE = '  - id: "STEAD-P1-006"'.freeze
P1_006_RAW_ACCEPTANCE_PREFIX =
  %(    acceptance_criteria: ["#{EXPECTED_P1_006_ADR_GATE_CLAUSE}).freeze
P1_006_FRAGMENT_NORMALIZATION_ROUNDS = 4
P1_006_FRAGMENT_MAX_BYTES = 8192
P1_006_INVALID_ENCODED_FRAGMENT = "invalid-encoded-ADR-fragment".freeze
P1_006_NON_ASCII_FRAGMENT = "non-ASCII-ADR-fragment".freeze
EXPECTED_P1_006_GATE_MUTATION_GROUPS = {
  paired_boundary: 2,
  candidate_boundary: 12,
  raw_yaml_source: 12,
  named_noncanonical: 33,
  unicode_dash: 25,
  escaped_code_run: 32,
  residual_fragment: 30,
  unicode_compatibility: 8,
  encoded_composition: 14,
  named_entity: 16,
  acceptance_structure: 8,
  continuation_control: 4,
  cross_item: 5
}.freeze
EXPECTED_P1_006_GATE_MUTATION_COUNT = EXPECTED_P1_006_GATE_MUTATION_GROUPS.values.sum

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
  },
  "0007" => {
    immutable_revision: "cc3dba0ccd740d18d138be52648fd4dba2008af5",
    accepted_at: "2026-08-30",
    approval_record_path: "docs/governance/adr-0007-approval-record.md",
    approval_records: [
      { "role" => "WS-01-architecture", "identity" => "/root/adr0007_cc3_arch_review", "disposition" => "APPROVED" },
      { "role" => "WS-02-core-composition", "identity" => "/root/adr0007_cc3_interface_review", "disposition" => "APPROVED" },
      { "role" => "WS-06-security-contract", "identity" => "/root/adr0007_cc3_interface_review", "disposition" => "APPROVED" },
      { "role" => "WS-07-events-audit", "identity" => "/root/adr0007_cc3_interface_review", "disposition" => "APPROVED" },
      { "role" => "WS-11-migration-namespace", "identity" => "/root/adr0007_cc3_ops_review", "disposition" => "APPROVED" },
      { "role" => "WS-12-deployment-operations", "identity" => "/root/adr0007_cc3_ops_review", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-qa", "identity" => "/root/adr0007_cc3_qa_review", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-security", "identity" => "/root/adr0007_cc3_security_review", "disposition" => "APPROVED" },
      { "role" => "project-owner", "identity" => "not required for this conforming selection", "disposition" => "NOT_REQUIRED" }
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

def parse_yaml(source, filename:)
  YAML.safe_load(
    source,
    permitted_classes: [],
    permitted_symbols: [],
    aliases: false,
    filename: filename
  )
end

def load_yaml(relative)
  parse_yaml(ROOT.join(relative).read(encoding: "UTF-8"), filename: relative)
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

def markdown_heading_structure(source)
  level_two_counts = Hash.new(0)
  level_three_sections = Hash.new { |hash, key| hash[key] = [] }
  current_level_two = nil
  current_level_three = nil
  fence = nil

  source.each_line do |line|
    if fence
      current_level_three&.fetch(:body)&.concat(line)
      delimiter = Regexp.escape(fence.fetch(:character))
      minimum_length = fence.fetch(:length)
      fence = nil if line.match?(/^ {0,3}#{delimiter}{#{minimum_length},}[ \t]*\n?$/)
      next
    end

    if (opening_fence = line.match(/^ {0,3}(`{3,}|~{3,})/))
      marker = opening_fence[1]
      fence = { character: marker[0], length: marker.length }
      current_level_three&.fetch(:body)&.concat(line)
      next
    end

    if (heading = line.match(/^## ([^#\n][^\n]*)\n?$/))
      current_level_two = heading[1]
      level_two_counts[current_level_two] += 1
      current_level_three = nil
    elsif (heading = line.match(/^### ([^#\n][^\n]*)\n?$/))
      current_level_three = {
        parent: current_level_two,
        body: +""
      }
      level_three_sections[heading[1]] << current_level_three
    elsif line.match?(/^# /)
      current_level_two = nil
      current_level_three = nil
    elsif current_level_three
      current_level_three.fetch(:body) << line
    end
  end

  {
    level_two_counts: level_two_counts,
    level_three_sections: level_three_sections
  }
end

def adr_0008_substantive_source_failures(adr_source)
  failures = []
  status_lines = adr_source.lines.select { |line| line.start_with?("- **Status:**") }
  if status_lines.length != 1
    failures << "ADR-0008 status must occur exactly once"
    return failures
  end

  status_line = status_lines.first
  state = if status_line == ADR_0008_PROPOSED_STATUS_LINE
            :proposed
          elsif status_line.match?(ADR_0008_ACCEPTED_STATUS_PATTERN)
            :accepted
          end
  unless state
    failures << "ADR-0008 status must use the exact Proposed or Accepted immutable-revision form"
    return failures
  end

  resolution_lines = adr_source.lines.select do |line|
    line.start_with?("- **Resolves on acceptance:**", "- **Resolves:**")
  end
  expected_resolution = state == :accepted ? ADR_0008_ACCEPTED_RESOLUTION_LINE : ADR_0008_PROPOSED_RESOLUTION_LINE
  unless resolution_lines == [expected_resolution]
    failures << "ADR-0008 #{state} status must use its exact paired resolution line"
    return failures
  end

  review_matches = adr_source.enum_for(
    :scan,
    /^#{Regexp.escape(ADR_0008_REVIEWS_HEADING)}/
  ).map { Regexp.last_match }
  if review_matches.length != 1
    failures << "ADR-0008 Reviews and approvals heading must occur exactly once"
    return failures
  end

  review_match = review_matches.first
  review_body = adr_source[review_match.end(0)..]
  if review_body.match?(/^ {0,3}[#]{1,2}[ \t]+|^<h[12](?:[ \t>])/i)
    failures << "ADR-0008 Reviews and approvals must remain the trailing level-two section"
    return failures
  end

  normalized = adr_source.sub(status_line, ADR_0008_NORMALIZED_STATUS_LINE)
                         .sub(expected_resolution, ADR_0008_NORMALIZED_RESOLUTION_LINE)
  review_offset = normalized.match(/^#{Regexp.escape(ADR_0008_REVIEWS_HEADING)}/).begin(0)
  normalized = normalized[0, review_offset] + ADR_0008_NORMALIZED_REVIEWS_SECTION
  actual_sha256 = Digest::SHA256.hexdigest(normalized)
  unless actual_sha256 == ADR_0008_SUBSTANTIVE_SOURCE_SHA256
    failures << "ADR-0008 substantive source digest mismatch: expected #{ADR_0008_SUBSTANTIVE_SOURCE_SHA256}, found #{actual_sha256}"
  end

  failures
end

def adr_0008_decision_body(adr_source)
  start_matches = adr_source.enum_for(
    :scan,
    /^## #{Regexp.escape(ADR_0008_DECISION_HEADING)}\n/
  ).map { Regexp.last_match }
  end_matches = adr_source.enum_for(
    :scan,
    /^## #{Regexp.escape(ADR_0008_DECISION_NEXT_HEADING)}\n/
  ).map { Regexp.last_match }
  return [nil, ["ADR-0008 Decision heading must occur exactly once"]] unless start_matches.length == 1
  return [nil, ["ADR-0008 Considered options heading must occur exactly once"]] unless end_matches.length == 1

  start_match = start_matches.first
  end_match = end_matches.first
  return [nil, ["ADR-0008 Decision must precede Considered options"]] if end_match.begin(0) <= start_match.end(0)

  intervening = adr_source.match(/^## ([^#\n][^\n]*)\n/, start_match.end(0))
  unless intervening&.begin(0) == end_match.begin(0)
    return [nil, ["ADR-0008 Decision body must terminate at Considered options"]]
  end

  [adr_source[start_match.end(0)...end_match.begin(0)], []]
end

def adr_0008_bypass_inventory_rows(source)
  failures = []
  section_heading = "## Complete bypass inventory\n"
  section_starts = source.enum_for(:scan, /^#{Regexp.escape(section_heading)}/).map { Regexp.last_match }
  section_ends = source.enum_for(:scan, /^## Common test fixture and oracle\n/).map { Regexp.last_match }
  unless section_starts.length == 1 && section_ends.length == 1 &&
         section_ends.first.begin(0) > section_starts.first.end(0)
    return [[], ["classification bypass inventory must contain one bounded complete-inventory table"]]
  end

  section = source[section_starts.first.end(0)...section_ends.first.begin(0)]
  lines = section.lines
  header_index = lines.index { |line| line.start_with?("| ID | Path / surface |") }
  if header_index.nil? || lines[header_index + 1] != "|---|---|---|---|---|---|---|\n"
    return [[], ["classification bypass inventory must contain the canonical complete-inventory table header"]]
  end

  rows = lines.drop(header_index + 2).take_while { |line| !line.strip.empty? }
  failures << "classification bypass inventory complete-inventory table must not be empty" if rows.empty?
  rows.each_with_index do |row, index|
    next if row.match?(/\A\| CBI-[0-9]{3} \|.*\|\n?\z/)

    failures << "classification bypass inventory row #{index + 1} must use canonical CBI table-row syntax"
  end
  [rows, failures]
end

def adr_0008_security_contract_failures(adr_source:, asyncapi:, bypass_source:)
  failures = adr_0008_substantive_source_failures(adr_source)
  decision_body, body_failures = adr_0008_decision_body(adr_source)
  failures.concat(body_failures)

  if decision_body
    ADR_0008_REQUIRED_DECISION_CLAUSES.each do |group, clauses|
      clauses.each do |clause|
        occurrences = decision_body.scan(Regexp.new(Regexp.escape(clause))).length
        failures << "ADR-0008 #{group} decision clause must occur exactly once: #{clause}" unless occurrences == 1
      end
    end
    ADR_0008_FORBIDDEN_DECISION_CLAUSES.each do |clause|
      failures << "ADR-0008 Decision retains superseded per-Organization topology: #{clause}" if decision_body.include?(clause)
    end
  end

  servers = asyncapi.fetch("servers", {})
  nats_server = servers.fetch("nats", {})
  unless nats_server["x-production-transport"] == "verified-mutual-tls" &&
         nats_server["x-tls-handshake-first"] == "required-no-fallback"
    failures << "AsyncAPI NATS server must require verified mutual TLS and a no-fallback TLS-first handshake"
  end
  unless servers == ADR_0008_SERVERS
    failures << "AsyncAPI servers must match the exact closed ADR-0008 NATS transport contract"
  end

  channels = asyncapi.fetch("channels", {})
  actual_sources = channels.to_h { |channel_name, channel| [channel_name, channel["x-logical-producer-source"]] }
  unless actual_sources == ADR_0008_LOGICAL_PRODUCER_SOURCES
    failures << "AsyncAPI logical producer-source registry must match the closed restore-stable registry"
  end

  ADR_0008_LOGICAL_PRODUCER_SOURCES.each do |channel_name, expected_source|
    channel = channels[channel_name] || {}
    message_refs = channel.fetch("messages", {}).values.filter_map { |message| message["$ref"] }
    if message_refs.length != 1
      failures << "AsyncAPI #{channel_name} must bind exactly one message"
      next
    end

    message_name = message_refs.first.delete_prefix("#/components/messages/")
    payload_ref = asyncapi.dig("components", "messages", message_name, "payload", "$ref")
    schema_name = payload_ref.to_s.delete_prefix("#/components/schemas/")
    source_const = asyncapi.dig("components", "schemas", schema_name, "allOf", 1, "properties", "source", "const")
    failures << "AsyncAPI #{channel_name} envelope source const must equal #{expected_source}" unless source_const == expected_source
  end

  source_schema = asyncapi.dig("components", "schemas", "SteadCloudEventEnvelope", "properties", "source") || {}
  expected_source_schema = {
    "type" => "string",
    "format" => "uri",
    "pattern" => ADR_0008_LOGICAL_PRODUCER_SOURCE_PATTERN
  }
  failures << "AsyncAPI CloudEvent source must use the closed restore-stable schema" unless source_schema == expected_source_schema

  delivery_contract = asyncapi.fetch("x-delivery-contract", {})
  ADR_0008_DELIVERY_CONTRACT.each do |field, expected|
    failures << "AsyncAPI x-delivery-contract #{field} must equal #{expected}" unless delivery_contract[field] == expected
  end
  unless delivery_contract == ADR_0008_DELIVERY_CONTRACT
    failures << "AsyncAPI x-delivery-contract must match the exact closed ADR-0008 delivery contract"
  end

  inventory_rows, inventory_failures = adr_0008_bypass_inventory_rows(bypass_source)
  failures.concat(inventory_failures)
  bypass_rows = inventory_rows.grep(/\A\| CBI-030 \|/)
  if bypass_rows.length != 1
    failures << "classification bypass inventory must contain exactly one CBI-030 row"
  else
    bypass_row = bypass_rows.first
    unless Digest::SHA256.hexdigest(bypass_row) == ADR_0008_CBI_030_SHA256
      failures << "CBI-030 must match the exact closed ADR-0008 security control row"
    end
    {
      topology: "One Stead application account per deployment security domain",
      lifecycle: "Organization creation creates no broker resource",
      credentials: "service-role credentials with no browser or end-user NATS credentials",
      fenced_recovery: "fenced claim and monotonic generation CAS",
      duplicate_readback: "`duplicate:true` accepted only after regular leader-served sequence/subject/message-ID/canonical-identity/semantic-key/digest verification",
      missing_copy: "definitive missing read-back advances generation and republishes unchanged canonical bytes",
      mismatch: "mismatch quarantines",
      retention_recovery: "PostgreSQL canonical recovery source that cannot retire before every consumer durably succeeds or records minimized terminal/DLQ/audit state",
      failure_evidence: "protected canaries remain absent from evidence"
    }.each do |group, fragment|
      failures << "CBI-030 omits ADR-0008 #{group} bypass coverage" unless bypass_row.include?(fragment)
    end
  end

  failures
end

# The P1-006 approval prerequisite is intentionally a strict raw-source clause,
# not rendered Markdown. Escapes, entities, formatting delimiters, links, HTML,
# and cross-item composition cannot stand in for the machine-reviewed wording.
def percent_decode_utf8_once(source)
  binary = source.b
  return [nil, true] if binary.match?(/%(?![0-9A-Fa-f]{2})/)

  decoded = binary.gsub(/%([0-9A-Fa-f]{2})/) { [Regexp.last_match(1).to_i(16)].pack("C") }
  decoded.force_encoding(Encoding::UTF_8)
  return [nil, true] unless decoded.valid_encoding?

  [decoded, false]
end

def decode_numeric_character_references(source)
  return [nil, true] if source.match?(/&#x[0-9A-F]{7,}/i) || source.match?(/&#[0-9]{8,}/)

  invalid = false
  decoded = source.gsub(/&#(?:x([0-9A-F]+)|([0-9]+));?/i) do |reference|
    codepoint = Regexp.last_match(1) ? Regexp.last_match(1).to_i(16) : Regexp.last_match(2).to_i(10)
    begin
      character = codepoint.chr(Encoding::UTF_8)
      if !character.valid_encoding? || codepoint.zero? || codepoint.between?(0xD800, 0xDFFF)
        invalid = true
        reference
      else
        character
      end
    rescue RangeError
      invalid = true
      reference
    end
  end
  invalid = true if decoded.match?(/&#/)

  [invalid ? nil : decoded, invalid]
end

def normalize_adr_candidate_fragment_once(source)
  # Literal YAML/Markdown layout whitespace is collapsed by the raw contract;
  # encoded controls are decoded only after this step and are rejected below.
  normalized, invalid = percent_decode_utf8_once(source.gsub(/[\t\n\f\r]/, ""))
  return [nil, true] if invalid

  normalized, invalid = decode_numeric_character_references(normalized)
  return [nil, true] if invalid

  normalized = normalized
               .gsub(/&(?:Tab);/, "\t")
               .gsub(/&(?:NewLine);/, "\n")
               .gsub(/&(?:nbsp);?/, " ")
               .gsub(/&(?:shy);?/, "\u00AD")
               .gsub(/&(?:NonBreakingSpace|ensp|emsp|thinsp|ThinSpace|hairsp|VeryThinSpace);/, " ")
               .gsub(/&(?:NegativeThinSpace|NegativeMediumSpace|NegativeThickSpace|NegativeVeryThinSpace|ZeroWidthSpace);/, "\u200B")
               .gsub(/&(?:dash|hyphen|minus|ndash|mdash|horbar);?/i, "-")
  # CommonMark uses HTML5 named references, including legacy names that render
  # without a semicolon. Reject any remaining entity-shaped name rather than
  # maintaining a partial decoder whose omissions can compose a hidden token.
  return [nil, true] if normalized.match?(/&[A-Za-z][A-Za-z0-9]*/)
  return [nil, true] if normalized.match?(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u)

  begin
    normalized = normalized.unicode_normalize(:nfkc)
  rescue ArgumentError
    return [nil, true]
  end

  normalized = normalized
               .gsub(/<!--.*?-->/m, "")
               .gsub(%r{</?[A-Za-z][^>\n]*>}, "")
               .gsub("\\-", "-")
               .tr("֊־᐀᠆‐‑‒–—―⁃⸗⸚⸺⸻⹀⹝〜〰゠︱︲﹘﹣－𐺭−", "-")
               .gsub(/[\p{Zs}\p{M}\t\n\f\r*_`\[\](){}"']/u, "")
  [normalized, false]
end

def normalize_adr_candidate_fragment(source)
  source_text = source.to_s
  return [nil, true] if source_text.bytesize > P1_006_FRAGMENT_MAX_BYTES

  begin
    normalized = source_text.encode(Encoding::UTF_8)
  rescue EncodingError
    return [nil, true]
  end
  return [nil, true] unless normalized.valid_encoding?

  P1_006_FRAGMENT_NORMALIZATION_ROUNDS.times do
    transformed, invalid = normalize_adr_candidate_fragment_once(normalized)
    return [nil, true] if invalid
    return [transformed, false] if transformed == normalized

    normalized = transformed
  end

  # A bounded fixed point prevents nested percent/entity encodings from turning
  # validation into an unbounded decoder. Anything requiring another pass is
  # rejected instead of being compared in a partially decoded form.
  transformed, invalid = normalize_adr_candidate_fragment_once(normalized)
  return [nil, true] if invalid || transformed != normalized

  [normalized, false]
end

def noncanonical_adr_candidate_fragments(criteria)
  criteria.flat_map do |criterion|
    collapsed, invalid = normalize_adr_candidate_fragment(criterion)
    next [P1_006_INVALID_ENCODED_FRAGMENT] if invalid
    next [P1_006_NON_ASCII_FRAGMENT] unless collapsed.ascii_only?
    next [] unless collapsed.include?("ADR-")

    exact_candidates = collapsed.scan(/ADR-CAND-\d{3}/)
    exact_candidates.empty? ? ["ADR-"] : exact_candidates
  end
end

def yaml_mapping_entries(node, key)
  return [] unless node.is_a?(Psych::Nodes::Mapping)

  node.children.each_slice(2).filter_map do |key_node, value_node|
    [key_node, value_node] if key_node.is_a?(Psych::Nodes::Scalar) && key_node.value == key
  end
end

def yaml_mapping_values(node, key)
  yaml_mapping_entries(node, key).map(&:last)
end

def p1_006_raw_gate_failures(issue_catalog_source)
  failures = []
  lines = issue_catalog_source.lines
  begin
    documents = Psych.parse_stream(issue_catalog_source).children
  rescue Psych::Exception => error
    return ["implementation issue catalog raw source is not parseable YAML: #{error.message}"]
  end
  unless documents.length == 1 && documents.first.root.is_a?(Psych::Nodes::Mapping)
    failures << "implementation issue catalog raw source must contain one mapping document"
    return failures
  end

  issues_entries = yaml_mapping_entries(documents.first.root, "issues")
  unless issues_entries.length == 1 && issues_entries.first.last.is_a?(Psych::Nodes::Sequence)
    failures << "implementation issue catalog raw source must contain one direct issues sequence"
    return failures
  end
  issues_key_node, issues_value = issues_entries.first
  unless lines.fetch(issues_key_node.start_line, "").chomp == P1_006_RAW_ISSUES_KEY_LINE
    failures << "implementation issue catalog raw issues key must use the canonical direct one-line representation"
    return failures
  end

  issue_nodes = issues_value.children.select do |node|
    yaml_mapping_values(node, "id").any? do |id_node|
      id_node.is_a?(Psych::Nodes::Scalar) && id_node.value == "STEAD-P1-006"
    end
  end
  unless issue_nodes.length == 1
    failures << "implementation issue catalog raw source must contain exactly one parsed STEAD-P1-006 issue mapping"
    return failures
  end

  id_nodes = yaml_mapping_values(issue_nodes.first, "id")
  unless id_nodes.length == 1 && lines.fetch(id_nodes.first.start_line, "").chomp == P1_006_RAW_ISSUE_ID_LINE
    failures << "STEAD-P1-006 raw issue ID must use the canonical direct one-line representation"
    return failures
  end

  acceptance_nodes = yaml_mapping_values(issue_nodes.first, "acceptance_criteria")
  unless acceptance_nodes.length == 1 && acceptance_nodes.first.is_a?(Psych::Nodes::Sequence)
    failures << "implementation issue catalog raw source must contain exactly one direct STEAD-P1-006 acceptance_criteria sequence"
    return failures
  end

  acceptance_node = acceptance_nodes.first
  first_criterion_node = acceptance_node.children.first
  canonical_scalar_shape = acceptance_node.style == Psych::Nodes::Sequence::FLOW &&
                           first_criterion_node.is_a?(Psych::Nodes::Scalar) &&
                           first_criterion_node.style == Psych::Nodes::Scalar::DOUBLE_QUOTED &&
                           first_criterion_node.start_line == first_criterion_node.end_line
  unless canonical_scalar_shape
    failures << "STEAD-P1-006 raw acceptance source must use a one-line flow sequence with a double-quoted first scalar"
    return failures
  end

  acceptance_line = lines.fetch(first_criterion_node.start_line, "")
  unless acceptance_line.start_with?(P1_006_RAW_ACCEPTANCE_PREFIX)
    failures << "STEAD-P1-006 raw acceptance source must begin with the exact canonical plain one-line ADR gate clause"
    return failures
  end

  residual_source = acceptance_line.delete_prefix(P1_006_RAW_ACCEPTANCE_PREFIX)
  residual_fragments = noncanonical_adr_candidate_fragments([residual_source])
  unless residual_fragments.empty?
    failures << "STEAD-P1-006 raw acceptance source contains ADR fragments outside the exact clause: #{residual_fragments.uniq.sort.join(', ')}"
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
    raw_criteria = security_issue["acceptance_criteria"]
    unless raw_criteria.is_a?(Array) && !raw_criteria.empty? && raw_criteria.all? { |criterion| criterion.is_a?(String) }
      failures << "STEAD-P1-006 acceptance criteria must be a non-empty array of strings"
    end
    criteria = raw_criteria.is_a?(Array) ? raw_criteria.select { |criterion| criterion.is_a?(String) } : []
    if criteria.any? { |criterion| criterion.match?(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u) }
      failures << "STEAD-P1-006 acceptance criteria contain prohibited control, format, or line-separator characters"
    end
    if criteria.any? { |criterion| !criterion.ascii_only? }
      failures << "STEAD-P1-006 acceptance criteria contain prohibited non-ASCII characters"
    end
    canonical_clause_present = criteria.first&.start_with?(EXPECTED_P1_006_ADR_GATE_CLAUSE)
    unless canonical_clause_present
      failures << "STEAD-P1-006 acceptance criteria omit ADR gates: #{EXPECTED_P1_006_ADR_CANDIDATES.join(', ')} (exact raw gate clause missing)"
    end

    residual_criteria = criteria.dup
    residual_criteria[0] = residual_criteria.first.delete_prefix(EXPECTED_P1_006_ADR_GATE_CLAUSE) if canonical_clause_present
    residual_fragments = noncanonical_adr_candidate_fragments(residual_criteria)
    unless residual_fragments.empty?
      failures << "STEAD-P1-006 acceptance criteria contain noncanonical ADR fragments outside the exact raw gate clause: #{residual_fragments.uniq.sort.join(', ')}"
    end

    residual_candidates = residual_fragments.grep(/\AADR-CAND-\d{3}\z/).to_set
    unexpected_acceptance_candidates = residual_candidates - expected_candidates
    unless unexpected_acceptance_candidates.empty?
      failures << "STEAD-P1-006 acceptance criteria add unexpected ADR gates: #{unexpected_acceptance_candidates.to_a.sort.join(', ')}"
    end
  else
    failures << "implementation issue catalog: missing STEAD-P1-006"
  end

  failures
end

failures = []
canonical_clause_candidates = EXPECTED_P1_006_ADR_GATE_CLAUSE.scan(/ADR-CAND-\d{3}/)
unless canonical_clause_candidates == EXPECTED_P1_006_ADR_CANDIDATES
  failures << "STEAD-P1-006 canonical raw ADR gate clause must contain the ordered exact expected candidate set"
end
requirements = load_yaml("specs/traceability/requirements.yaml").fetch("requirements")
known_requirement_ids = requirements.map { |record| record.fetch("requirement_id") }.to_set
issue_catalog_relative = "docs/planning/implementation-issue-catalog.yaml"
issue_catalog_source = ROOT.join(issue_catalog_relative).read(encoding: "UTF-8")
issue_catalog = load_yaml(issue_catalog_relative)
adr_gates = issue_catalog.fetch("adr_decision_gates").to_h { |gate| [gate.fetch("adr_id"), gate] }
issues = issue_catalog.fetch("issues").to_h { |issue| [issue.fetch("id"), issue] }
asyncapi = load_yaml("specs/asyncapi/stead.yaml")
classification_bypass_source = ROOT.join("docs/security/classification-bypass-inventory.md").read(encoding: "UTF-8")
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
adr_0008_source = nil

paths.each do |path|
  basename = path.basename.to_s
  number = basename[/\A(\d{4})-/, 1]
  next unless EXPECTED_RECORDS.key?(number)

  expected = EXPECTED_RECORDS.fetch(number)
  source = path.read(encoding: "UTF-8")
  adr_0008_source = source if number == "0008"
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

if adr_0008_source
  failures.concat(
    adr_0008_security_contract_failures(
      adr_source: adr_0008_source,
      asyncapi: asyncapi,
      bypass_source: classification_bypass_source
    )
  )
else
  failures << "ADR-0008 source unavailable for security contract validation"
end

# Mutate executable security invariants only. Metadata prose and review text are
# protected by the immutable revision rather than expanded into mutation cases.
adr_0008_security_mutations = []
deep_copy_asyncapi = -> { Marshal.load(Marshal.dump(asyncapi)) }

if adr_0008_source
  {
    topology: [
      "one internal Stead NATS application account for each deployment security domain",
      "one shared account for all deployment security domains",
      "ADR-0008 topology decision clause"
    ],
    authorization: [
      "No consumer may use account membership, subject access, or an event as an authorization grant",
      "Consumers may treat account membership as authorization",
      "ADR-0008 authorization decision clause"
    ],
    streams: [
      "small fixed stream set, not a stream set per Organization",
      "four-stream set for every Organization",
      "ADR-0008 streams decision clause"
    ],
    delivery: [
      "API responses never wait for publication, a consumer, replay, or NATS availability",
      "API responses wait for consumer completion",
      "ADR-0008 delivery decision clause"
    ],
    retention_recovery: [
      "Broker age, administrative removal, stream replacement, or retention expiry is a transport event, not a delivery terminal",
      "Broker age, administrative removal, stream replacement, or retention expiry completes delivery",
      "ADR-0008 retention_recovery decision clause"
    ],
    replay_recovery: [
      "JetStream is reconstructible transport, not backup authority",
      "JetStream is authoritative backup state",
      "ADR-0008 replay_recovery decision clause"
    ],
    credentials: [
      "requires no operator-key ceremony, account JWT signing hierarchy, or external resolver",
      "requires an operator-key ceremony and external resolver",
      "ADR-0008 credentials decision clause"
    ]
  }.each do |group, (from, to, expected_failure)|
    adr_0008_security_mutations << {
      group: group,
      name: "remove #{group} invariant",
      adr: adr_0008_source.sub(from, to),
      asyncapi: deep_copy_asyncapi.call,
      bypass: classification_bypass_source,
      expected_failure_fragment: expected_failure
    }
  end

  forbidden_topology = adr_0008_source.sub(
    "\n## Considered options\n",
    "\nEvery event-ready Organization has exactly one event partition.\n\n## Considered options\n"
  )
  adr_0008_security_mutations << {
    group: :topology,
    name: "restore per-Organization decision",
    adr: forbidden_topology,
    asyncapi: deep_copy_asyncapi.call,
    bypass: classification_bypass_source,
    expected_failure_fragment: "retains superseded per-Organization topology"
  }
end

mutated_topology_asyncapi = deep_copy_asyncapi.call
mutated_topology_asyncapi.fetch("x-delivery-contract")["account-topology"] =
  "one-account-per-organization"
adr_0008_security_mutations << {
  group: :topology,
  name: "per-Organization AsyncAPI account topology",
  adr: adr_0008_source,
  asyncapi: mutated_topology_asyncapi,
  bypass: classification_bypass_source,
  expected_failure_fragment: "x-delivery-contract account-topology"
}

mutated_transport_asyncapi = deep_copy_asyncapi.call
mutated_transport_asyncapi.dig("servers", "nats")["x-production-transport"] = "optional-tls"
adr_0008_security_mutations << {
  group: :credentials,
  name: "optional production TLS",
  adr: adr_0008_source,
  asyncapi: mutated_transport_asyncapi,
  bypass: classification_bypass_source,
  expected_failure_fragment: "require verified mutual TLS"
}

mutated_source_asyncapi = deep_copy_asyncapi.call
mutated_source_asyncapi.dig("channels", "organizationEvents")["x-logical-producer-source"] =
  "https://runtime.example/organization"
adr_0008_security_mutations << {
  group: :delivery,
  name: "runtime-bound producer source",
  adr: adr_0008_source,
  asyncapi: mutated_source_asyncapi,
  bypass: classification_bypass_source,
  expected_failure_fragment: "logical producer-source registry"
}

mutated_retirement_asyncapi = deep_copy_asyncapi.call
mutated_retirement_asyncapi.fetch("x-delivery-contract")["source-retirement"] =
  "broker-publish-ack"
adr_0008_security_mutations << {
  group: :retention_recovery,
  name: "broker acknowledgement retires recovery source",
  adr: adr_0008_source,
  asyncapi: mutated_retirement_asyncapi,
  bypass: classification_bypass_source,
  expected_failure_fragment: "x-delivery-contract source-retirement"
}

mutated_registry_asyncapi = deep_copy_asyncapi.call
mutated_registry_asyncapi.fetch("x-delivery-contract")["required-consumers"] =
  "resolved-after-publication"
adr_0008_security_mutations << {
  group: :retention_recovery,
  name: "consumer registry resolved after publication",
  adr: adr_0008_source,
  asyncapi: mutated_registry_asyncapi,
  bypass: classification_bypass_source,
  expected_failure_fragment: "x-delivery-contract required-consumers"
}

ADR_0008_DELIVERY_CONTRACT.each_key do |field|
  mutated_delivery_asyncapi = deep_copy_asyncapi.call
  mutated_delivery_asyncapi.fetch("x-delivery-contract")[field] = "unsafe-mutant-#{field}"
  adr_0008_security_mutations << {
    group: :retention_recovery,
    name: "unsafe #{field} contract",
    adr: adr_0008_source,
    asyncapi: mutated_delivery_asyncapi,
    bypass: classification_bypass_source,
    expected_failure_fragment: "x-delivery-contract #{field}"
  }

  missing_delivery_asyncapi = deep_copy_asyncapi.call
  missing_delivery_asyncapi.fetch("x-delivery-contract").delete(field)
  adr_0008_security_mutations << {
    group: :retention_recovery,
    name: "missing #{field} contract",
    adr: adr_0008_source,
    asyncapi: missing_delivery_asyncapi,
    bypass: classification_bypass_source,
    expected_failure_fragment: "x-delivery-contract #{field}"
  }
end

mutated_additive_delivery_asyncapi = deep_copy_asyncapi.call
mutated_additive_delivery_asyncapi.fetch("x-delivery-contract")["allow_direct"] = true
adr_0008_security_mutations << {
  group: :retention_recovery,
  name: "unexpected delivery-contract field",
  adr: adr_0008_source,
  asyncapi: mutated_additive_delivery_asyncapi,
  bypass: classification_bypass_source,
  expected_failure_fragment: "exact closed ADR-0008 delivery contract"
}

ADR_0008_SERVERS.fetch("nats").each_key do |field|
  mutated_server_asyncapi = deep_copy_asyncapi.call
  mutated_server_asyncapi.dig("servers", "nats")[field] = "unsafe-mutant-#{field}"
  adr_0008_security_mutations << {
    group: :credentials,
    name: "unsafe NATS server #{field}",
    adr: adr_0008_source,
    asyncapi: mutated_server_asyncapi,
    bypass: classification_bypass_source,
    expected_failure_fragment: "exact closed ADR-0008 NATS transport contract"
  }

  missing_server_asyncapi = deep_copy_asyncapi.call
  missing_server_asyncapi.dig("servers", "nats").delete(field)
  adr_0008_security_mutations << {
    group: :credentials,
    name: "missing NATS server #{field}",
    adr: adr_0008_source,
    asyncapi: missing_server_asyncapi,
    bypass: classification_bypass_source,
    expected_failure_fragment: "exact closed ADR-0008 NATS transport contract"
  }
end

mutated_additive_server_asyncapi = deep_copy_asyncapi.call
mutated_additive_server_asyncapi.dig("servers", "nats")["x-plaintext-fallback"] = true
adr_0008_security_mutations << {
  group: :credentials,
  name: "unexpected plaintext fallback field",
  adr: adr_0008_source,
  asyncapi: mutated_additive_server_asyncapi,
  bypass: classification_bypass_source,
  expected_failure_fragment: "exact closed ADR-0008 NATS transport contract"
}

mutated_alias_server_asyncapi = deep_copy_asyncapi.call
mutated_alias_server_asyncapi.fetch("servers")["natsPerOrganization"] =
  Marshal.load(Marshal.dump(mutated_alias_server_asyncapi.dig("servers", "nats")))
adr_0008_security_mutations << {
  group: :topology,
  name: "per-Organization server alias",
  adr: adr_0008_source,
  asyncapi: mutated_alias_server_asyncapi,
  bypass: classification_bypass_source,
  expected_failure_fragment: "exact closed ADR-0008 NATS transport contract"
}

mutated_bypass = classification_bypass_source.sub(
  "Organization creation creates no broker resource",
  "Organization creation provisions broker resources"
)
adr_0008_security_mutations << {
  group: :topology,
  name: "broker lifecycle bypass coverage removed",
  adr: adr_0008_source,
  asyncapi: deep_copy_asyncapi.call,
  bypass: mutated_bypass,
  expected_failure_fragment: "CBI-030 omits ADR-0008 lifecycle"
}

mutated_retention_bypass = classification_bypass_source.sub(
  "PostgreSQL canonical recovery source that cannot retire before every consumer durably succeeds or records minimized terminal/DLQ/audit state",
  "broker publish acknowledgement retires the recovery source"
)
adr_0008_security_mutations << {
  group: :retention_recovery,
  name: "broker expiry bypass coverage removed",
  adr: adr_0008_source,
  asyncapi: deep_copy_asyncapi.call,
  bypass: mutated_retention_bypass,
  expected_failure_fragment: "CBI-030 omits ADR-0008 retention_recovery"
}

{
  tls: ["verified TLS with no fallback", "plaintext fallback permitted"],
  opaque_receipt: ["opaque receipt and retirement port", "broker-native receipt and retirement port"],
  additive_contradiction: [
    "Per-Organization broker accounts remain an unproven later high-isolation option.",
    "A broker acknowledgement may retire the PostgreSQL source. Per-Organization broker accounts remain an unproven later high-isolation option."
  ]
}.each do |group, (from, to)|
  mutated_closed_bypass = classification_bypass_source.sub(from, to)
  adr_0008_security_mutations << {
    group: group,
    name: "CBI-030 #{group} contradiction",
    adr: adr_0008_source,
    asyncapi: deep_copy_asyncapi.call,
    bypass: mutated_closed_bypass,
    expected_failure_fragment: "exact closed ADR-0008 security control row"
  }
end

canonical_bypass_row = classification_bypass_source.lines.grep(/\A\| CBI-030 \|/).first
if canonical_bypass_row
  {
    "space-indented duplicate CBI-030 row" => " #{canonical_bypass_row}",
    "no-leading-pipe duplicate CBI-030 row" => canonical_bypass_row.delete_prefix("| "),
    "no-padding duplicate CBI-030 row" => canonical_bypass_row.sub("| CBI-030 |", "|CBI-030|"),
    "entity-spelled duplicate CBI-030 row" => canonical_bypass_row.sub("CBI-030", "CBI-&#48;30")
  }.each do |name, duplicate_row|
    mutated_duplicate_bypass = classification_bypass_source.sub(
      canonical_bypass_row,
      "#{canonical_bypass_row}#{duplicate_row}"
    )
    adr_0008_security_mutations << {
      group: :topology,
      name: name,
      adr: adr_0008_source,
      asyncapi: deep_copy_asyncapi.call,
      bypass: mutated_duplicate_bypass,
      expected_failure_fragment: "canonical CBI table-row syntax"
    }
  end
end

adr_0008_security_mutation_survivors = adr_0008_security_mutations.filter_map do |mutation|
  mutation_failures = adr_0008_security_contract_failures(
    adr_source: mutation.fetch(:adr),
    asyncapi: mutation.fetch(:asyncapi),
    bypass_source: mutation.fetch(:bypass)
  )
  expected = mutation.fetch(:expected_failure_fragment)
  "#{mutation.fetch(:group)}/#{mutation.fetch(:name)}" unless mutation_failures.any? { |failure| failure.include?(expected) }
end
unless adr_0008_security_mutation_survivors.empty?
  failures << "ADR-0008 security contract mutation survivors: #{adr_0008_security_mutation_survivors.join(', ')}"
end

adr_0008_security_mutation_groups = adr_0008_security_mutations.each_with_object(Hash.new(0)) do |mutation, counts|
  counts[mutation.fetch(:group)] += 1
end
unless adr_0008_security_mutation_groups == ADR_0008_EXPECTED_SECURITY_MUTATION_GROUPS
  failures << "ADR-0008 security mutation inventory groups changed: expected #{ADR_0008_EXPECTED_SECURITY_MUTATION_GROUPS.inspect}, found #{adr_0008_security_mutation_groups.inspect}"
end
unless adr_0008_security_mutations.length == ADR_0008_EXPECTED_SECURITY_MUTATION_COUNT
  failures << "ADR-0008 security mutation inventory must contain exactly #{ADR_0008_EXPECTED_SECURITY_MUTATION_COUNT} cases, found #{adr_0008_security_mutations.length}"
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

adr_0008_traceability_failures = adr_requirement_traceability_failures(
  requirements: requirements,
  adr_number: "0008",
  claimed_requirement_ids: requirements_by_number.fetch("0008", []),
  declared_test_ids: tests_by_number.fetch("0008", [])
)
failures.concat(adr_0008_traceability_failures)

adr_0008_expected_edges = expected_adr_requirement_test_edges(ADR_0008_REQUIREMENT_TEST_MAPPING).freeze
unless adr_0008_expected_edges.length == 60
  failures << "ADR-0008 closed requirement mapping must contain exactly 60 edges, found #{adr_0008_expected_edges.length}"
end
failures.concat(
  exact_adr_requirement_mapping_failures(
    requirements: requirements,
    adr_number: "0008",
    expected_edges: adr_0008_expected_edges
  )
)

# Prove the closed mapping is enforced at each individual reciprocal edge, not
# merely that every requirement and test name appears somewhere in the registry.
adr_0008_mutation_survivors = []
adr_0008_expected_edges.to_a.sort.each do |requirement_id, test_id|
  mutated_requirements = requirements.map do |registered_requirement|
    registered_requirement.merge("test_ids" => Array(registered_requirement["test_ids"]).dup)
  end
  mutated_record = mutated_requirements.find { |record| record.fetch("requirement_id") == requirement_id }
  removed_test = mutated_record&.fetch("test_ids", [])&.delete(test_id)
  if removed_test.nil?
    adr_0008_mutation_survivors << "#{requirement_id} -> #{test_id} (edge absent before mutation)"
    next
  end

  mutation_failures = exact_adr_requirement_mapping_failures(
    requirements: mutated_requirements,
    adr_number: "0008",
    expected_edges: adr_0008_expected_edges
  )
  adr_0008_mutation_survivors << "#{requirement_id} -> #{test_id}" if mutation_failures.empty?
end
unless adr_0008_mutation_survivors.empty?
  failures << "ADR-0008 exact-mapping mutation survivors: #{adr_0008_mutation_survivors.join(', ')}"
end

security_issue = issues["STEAD-P1-006"]
failures.concat(p1_006_raw_gate_failures(issue_catalog_source))
failures.concat(p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: security_issue))
p1_006_gate_mutation_count = 0
p1_006_gate_mutation_groups = Hash.new(0)
record_p1_006_mutation = lambda do |group|
  p1_006_gate_mutation_count += 1
  p1_006_gate_mutation_groups[group] += 1
end

# Exercise the coupled failure mode explicitly: deleting the same security ADR
# from both the decision-gate dependency list and the dependent issue text must
# be caught independently at both boundaries.
if security_issue && adr_gates["ADR-CAND-002"]
  candidate_gate_fixture = {
    "acceptance_criteria" => [
      "#{EXPECTED_P1_006_ADR_GATE_CLAUSE} continue with the bounded implementation."
    ]
  }

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
  record_p1_006_mutation.call(:paired_boundary)

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
  record_p1_006_mutation.call(:paired_boundary)

  canonical_fixture_failures = p1_006_adr_gate_failures(
    adr_gates: adr_gates,
    security_issue: candidate_gate_fixture
  )
  unless canonical_fixture_failures.empty?
    failures << "STEAD-P1-006 exact raw ADR gate fixture failed: #{canonical_fixture_failures.join('; ')}"
  end

  raw_acceptance_line = issue_catalog_source.lines.find do |line|
    line.start_with?(P1_006_RAW_ACCEPTANCE_PREFIX)
  end
  if raw_acceptance_line
    canonical_criteria = security_issue.fetch("acceptance_criteria")
    first_criterion = canonical_criteria.first
    remaining_json = canonical_criteria.drop(1).map { |criterion| JSON.generate(criterion) }
    flow_acceptance_line = lambda do |encoded_first|
      encoded_items = [encoded_first, *remaining_json]
      "    acceptance_criteria: [#{encoded_items.join(', ')}]\n"
    end

    escaped_continuation = JSON.generate(first_criterion).sub("Only after", "Only \\\n        after")
    folded_flow_scalar = JSON.generate(first_criterion).sub("Only after", "Only\n        after")
    single_quoted_scalar = first_criterion.sub("Only after", "Only\n        after").gsub("'", "''")
    folded_block_scalar = first_criterion.sub(
      "ADR-CAND-003, ADR-CAND-004",
      "ADR-CAND-003,\nADR-CAND-004"
    )
    folded_block_items = [
      "    acceptance_criteria:\n",
      "      - >-\n",
      *folded_block_scalar.lines.map { |line| "        #{line}" },
      *canonical_criteria.drop(1).map { |criterion| "      - #{JSON.generate(criterion)}\n" }
    ].join

    raw_yaml_bypass_mutations = {
      "YAML hex-escaped initial character" => raw_acceptance_line.sub('"Only', '"\\x4Fnly'),
      "YAML Unicode-escaped initial character" => raw_acceptance_line.sub('"Only', '"\\u004Fnly'),
      "YAML Unicode-escaped candidate hyphen" => raw_acceptance_line.sub("ADR-CAND-002", "ADR-CAND\\u002D002"),
      "YAML hex-escaped candidate digits" => raw_acceptance_line.sub("ADR-CAND-002", "ADR-CAND-\\x30\\x30\\x32"),
      "YAML escaped physical-line continuation" => flow_acceptance_line.call(escaped_continuation),
      "YAML folded physical line in flow scalar" => flow_acceptance_line.call(folded_flow_scalar),
      "YAML multiline single-quoted scalar" => flow_acceptance_line.call("'#{single_quoted_scalar}'"),
      "YAML folded block scalar" => folded_block_items
    }

    raw_yaml_bypass_mutations.each do |mutation_name, mutated_acceptance_source|
      record_p1_006_mutation.call(:raw_yaml_source)
      mutated_catalog_source = issue_catalog_source.sub(raw_acceptance_line, mutated_acceptance_source)
      begin
        mutated_catalog = parse_yaml(mutated_catalog_source, filename: "#{issue_catalog_relative} (#{mutation_name})")
        mutated_issue = mutated_catalog.fetch("issues").find { |issue| issue["id"] == "STEAD-P1-006" }
        decoded_failures = p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: mutated_issue)
        unless decoded_failures.empty?
          failures << "STEAD-P1-006 #{mutation_name} fixture no longer decodes to the canonical clause: #{decoded_failures.join('; ')}"
        end
      rescue Psych::Exception => error
        failures << "STEAD-P1-006 #{mutation_name} fixture must remain valid YAML: #{error.message}"
      end

      raw_failures = p1_006_raw_gate_failures(mutated_catalog_source)
      unless raw_failures.any? { |failure| failure.start_with?("STEAD-P1-006 raw acceptance source") }
        failures << "STEAD-P1-006 #{mutation_name} mutant survived physical raw-source validation"
      end
    end

    raw_binding_mutations = {
      "YAML escaped top-level issues key" => issue_catalog_source.sub(
        "#{P1_006_RAW_ISSUES_KEY_LINE}\n",
        '"\\x69ssues":' + "\n"
      ),
      "YAML escaped P1-006 issue ID" => issue_catalog_source.sub(
        P1_006_RAW_ISSUE_ID_LINE,
        '  - id: "STEAD-P1-\\x30\\x30\\x36"'
      ),
      "YAML escaped acceptance key" => issue_catalog_source.sub(
        raw_acceptance_line,
        raw_acceptance_line.sub("    acceptance_criteria:", '    "acceptance_\\x63riteria":')
      ),
      "YAML duplicate acceptance key" => issue_catalog_source.sub(
        raw_acceptance_line,
        "#{raw_acceptance_line}#{raw_acceptance_line}"
      )
    }
    raw_binding_mutations.each do |mutation_name, mutated_catalog_source|
      record_p1_006_mutation.call(:raw_yaml_source)
      begin
        mutated_catalog = parse_yaml(mutated_catalog_source, filename: "#{issue_catalog_relative} (#{mutation_name})")
        mutated_issue = mutated_catalog.fetch("issues").find { |issue| issue["id"] == "STEAD-P1-006" }
        decoded_failures = p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: mutated_issue)
        unless decoded_failures.empty?
          failures << "STEAD-P1-006 #{mutation_name} fixture no longer preserves the decoded canonical gate: #{decoded_failures.join('; ')}"
        end
      rescue Psych::Exception => error
        failures << "STEAD-P1-006 #{mutation_name} fixture must remain valid YAML: #{error.message}"
      end

      if p1_006_raw_gate_failures(mutated_catalog_source).empty?
        failures << "STEAD-P1-006 #{mutation_name} mutant survived AST-bound raw-source validation"
      end
    end
  else
    failures << "STEAD-P1-006 mutation guard could not locate the canonical raw acceptance line"
  end

  EXPECTED_P1_006_ADR_CANDIDATES.each do |candidate|
    missing_candidate_issue = candidate_gate_fixture.merge(
      "acceptance_criteria" => candidate_gate_fixture.fetch("acceptance_criteria").map do |criterion|
        criterion.gsub(candidate) { "ADR-CAND-REMOVED-BY-MUTANT" }
      end
    )
    missing_candidate_failures = p1_006_adr_gate_failures(
      adr_gates: adr_gates,
      security_issue: missing_candidate_issue
    )
    unless missing_candidate_failures.any? { |failure| failure.start_with?("STEAD-P1-006 acceptance criteria omit ADR gates:") }
      failures << "STEAD-P1-006 #{candidate} raw-clause deletion mutant survived acceptance validation"
    end
    record_p1_006_mutation.call(:candidate_boundary)

    missing_gate_dependencies = adr_gates.transform_values do |gate|
      gate.merge("dependent_issues" => Array(gate["dependent_issues"]).dup)
    end
    missing_gate_dependencies.fetch(candidate).fetch("dependent_issues").delete("STEAD-P1-006")
    missing_gate_failures = p1_006_adr_gate_failures(
      adr_gates: missing_gate_dependencies,
      security_issue: candidate_gate_fixture
    )
    unless missing_gate_failures.any? { |failure| failure.start_with?("ADR gates omit STEAD-P1-006 dependencies:") && failure.include?(candidate) }
      failures << "STEAD-P1-006 #{candidate} decision-gate deletion mutant survived dependency validation"
    end
    record_p1_006_mutation.call(:candidate_boundary)
  end

  noncanonical_gate_replacements = {
    "numeric suffix" => "ADR-CAND-0020",
    "ASCII hyphen suffix" => "ADR-CAND-002-EXTRA",
    "underscore suffix" => "ADR-CAND-002_EXTRA",
    "embedded prefix" => "XADR-CAND-002",
    "Unicode letter prefix" => "éADR-CAND-002",
    "Unicode letter suffix" => "ADR-CAND-002界",
    "combining-mark suffix" => "ADR-CAND-002\u0301",
    "Unicode connector suffix" => "ADR-CAND-002‿EXTRA",
    "zero-width suffix" => "ADR-CAND-002\u200BEXTRA",
    "soft-hyphen suffix" => "ADR-CAND-002\u00ADextra",
    "vertical-tab suffix" => "ADR-CAND-002\u000BEXTRA",
    "next-line suffix" => "ADR-CAND-002\u0085EXTRA",
    "escaped underscore suffix" => "ADR-CAND-002\\_EXTRA",
    "escaped hyphen suffix" => "ADR-CAND-002\\-EXTRA",
    "escaped exact token" => "ADR\\-CAND\\-002",
    "numeric underscore entity" => "ADR-CAND-002&#95;EXTRA",
    "numeric hyphen entity" => "ADR-CAND-002&#45;EXTRA",
    "numeric zero-width entity" => "ADR-CAND-002&#x200B;EXTRA",
    "numeric combining entity" => "ADR-CAND-002&#x301;EXTRA",
    "numeric connector entity" => "ADR-CAND-002&#x203F;EXTRA",
    "numeric letter entity" => "ADR-CAND-002&#x754C;EXTRA",
    "named underscore entity" => "ADR-CAND-002&lowbar;EXTRA",
    "named hyphen entity" => "ADR-CAND-002&hyphen;EXTRA",
    "single underscore emphasis" => "_ADR-CAND-002_",
    "arbitrary underscore emphasis" => "_______ADR-CAND-002_______",
    "code span" => "`ADR-CAND-002`",
    "code-span literal emphasis" => "`_ADR-CAND-002_`",
    "distant delimiter interaction" => "_ADR-CAND-002 __a_",
    "partial strong delimiter" => "__ADR-CAND-002 is required___",
    "valid nested delimiter A" => "___ADR-CAND-002__ x_",
    "valid nested delimiter B" => "___ADR-CAND-002_ x__",
    "HTML comment" => "<!-- ADR-CAND-002 -->",
    "link label" => "[ADR-CAND-002](https://example.invalid/gate)"
  }
  "֊־᐀᠆‐‑‒–—―⸗⸚⸺⸻⹀⹝〜〰゠︱︲﹘﹣－𐺭".each_char.with_index do |dash, index|
    noncanonical_gate_replacements["Unicode dash #{index + 1}"] = "ADR-CAND-002#{dash}EXTRA"
  end
  (1..32).each do |delimiter_length|
    noncanonical_gate_replacements["escaped code opener length #{delimiter_length}"] =
      "\\#{'`' * (delimiter_length + 1)}_ADR-CAND-002_#{'`' * delimiter_length}"
  end

  noncanonical_gate_replacements.each do |mutation_name, replacement|
    mutation_group = if mutation_name.start_with?("Unicode dash ")
                       :unicode_dash
                     elsif mutation_name.start_with?("escaped code opener length ")
                       :escaped_code_run
                     else
                       :named_noncanonical
                     end
    record_p1_006_mutation.call(mutation_group)
    noncanonical_token_issue = candidate_gate_fixture.merge(
      "acceptance_criteria" => Array(candidate_gate_fixture["acceptance_criteria"]).map do |criterion|
        criterion.gsub("ADR-CAND-002") { replacement }
      end
    )
    noncanonical_failures = p1_006_adr_gate_failures(
      adr_gates: adr_gates,
      security_issue: noncanonical_token_issue
    )
    canonical_clause_killed = noncanonical_failures.any? do |failure|
      failure.start_with?("STEAD-P1-006 acceptance criteria omit ADR gates:") && failure.include?("ADR-CAND-002")
    end
    unless canonical_clause_killed
      failures << "STEAD-P1-006 #{mutation_name} mutant survived strict raw gate-clause validation"
    end
  end

  residual_fragment_mutations = {
    "bare residual prefix" => "ADR-CAND",
    "bare residual hyphen" => "ADR-CAND-",
    "residual hyphen before comma" => "ADR-CAND-,",
    "residual hyphen before ASCII space" => "ADR-CAND- ",
    "residual hyphen before tab" => "ADR-CAND-\t",
    "residual hyphen before nonbreaking space" => "ADR-CAND-\u00A0",
    "residual formatted digits" => "ADR-CAND-**001**",
    "residual code-formatted digits" => "ADR-CAND-`001`",
    "residual linked digits" => "ADR-CAND-[001]",
    "residual parenthesized digits" => "ADR-CAND-(001)",
    "residual line-split digits" => "ADR-CAND-\n001",
    "residual tab-split digits" => "ADR-CAND-\t001",
    "residual embedded prefix" => "XADR-CAND",
    "residual extended prefix" => "ADR-CANDX",
    "residual numeric hyphen entity" => "ADR-CAND&#45;001",
    "residual hexadecimal hyphen entity" => "ADR-CAND&#x2D;001",
    "residual split candidate entity" => "ADR&#45;CAND-001",
    "residual backslash-split candidate" => "ADR\\-CAND\\-001",
    "residual HTML-split candidate" => "ADR-<!-- split -->CAND-001",
    "residual space-split candidate" => "ADR-CAND- 001",
    "residual numeric encoded initial" => "&#65;DR-CAND-001",
    "residual numeric encoded final letter" => "AD&#82;-CAND-001",
    "residual formatted identifier letters" => "AD**R-CAND-001",
    "residual tagged identifier letters" => "ADR-<span>CAND</span>-001",
    "residual Unicode candidate dashes" => "ADR‐CAND‐001",
    "residual fully numeric encoded identifier" => "&#65;&#68;&#82;&#45;&#67;&#65;&#78;&#68;&#45;001",
    "residual fully percent encoded identifier" => "%41%44%52%2D%43%41%4E%44%2D001",
    "residual named Unicode dash entities" => "ADR&ndash;CAND&mdash;001",
    "residual combining-mark identifier" => "AD\u0301R-CAND-001",
    "residual underscore-formatted identifier" => "A_D_R-CAND-001"
  }
  residual_fragment_mutations.each do |mutation_name, fragment|
    record_p1_006_mutation.call(:residual_fragment)
    residual_issue = candidate_gate_fixture.merge(
      "acceptance_criteria" => ["#{candidate_gate_fixture.fetch('acceptance_criteria').first} #{fragment}"]
    )
    residual_failures = p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: residual_issue)
    unless residual_failures.any? { |failure| failure.start_with?("STEAD-P1-006 acceptance criteria contain noncanonical ADR fragments") }
      failures << "STEAD-P1-006 #{mutation_name} mutant survived residual-fragment validation"
    end
  end

  unicode_compatibility_mutations = {
    "fullwidth initial letter" => "ＡDR-CAND-001",
    "mathematical-bold initial letter" => "𝐀DR-CAND-001",
    "fully fullwidth identifier" => "ＡＤＲ－ＣＡＮＤ－００１",
    "fullwidth candidate letters" => "ADR-ＣＡＮＤ-001",
    "fullwidth digits" => "ADR-CAND-００１",
    "mathematical-bold identifier" => "𝐀𝐃𝐑-𝐂𝐀𝐍𝐃-𝟎𝟎𝟏",
    "fullwidth identifier hyphens" => "ADR－CAND－001",
    "hyphen-bullet identifier" => "ADR⁃CAND⁃001"
  }
  unicode_compatibility_mutations.each do |mutation_name, fragment|
    record_p1_006_mutation.call(:unicode_compatibility)
    residual_issue = candidate_gate_fixture.merge(
      "acceptance_criteria" => ["#{candidate_gate_fixture.fetch('acceptance_criteria').first} #{fragment}"]
    )
    residual_failures = p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: residual_issue)
    unless residual_failures.any? { |failure| failure.start_with?("STEAD-P1-006 acceptance criteria contain noncanonical ADR fragments") }
      failures << "STEAD-P1-006 #{mutation_name} mutant survived Unicode-compatibility validation"
    end
  end

  encoded_composition_mutations = {
    "double-percent encoded identifier" => "%2541%2544%2552%252D%2543%2541%254E%2544%252D001",
    "percent-encoded numeric entities" => "%26%2365%3B%26%2368%3B%26%2382%3B-CAND-001",
    "double-percent encoded numeric entities" => "%2526%252365%253B%2526%252368%253B%2526%252382%253B-CAND-001",
    "invalid percent byte" => "%FFADR-CAND-001",
    "invalid percent UTF-8 sequence" => "AD%C3%28R-CAND-001",
    "truncated percent UTF-8 sequence" => "AD%E2%82R-CAND-001",
    "malformed percent escape" => "AD%G1R-CAND-001",
    "percent-encoded null control" => "AD%00R-CAND-001",
    "percent-encoded vertical-tab control" => "AD%0BR-CAND-001",
    "percent-encoded delete control" => "AD%7FR-CAND-001",
    "overlong decimal numeric entity" => "&#99999999;ADR-CAND-001",
    "overlong hexadecimal numeric entity" => "&#xFFFFFFF;ADR-CAND-001",
    "oversized encoded fragment" => "#{'A' * (P1_006_FRAGMENT_MAX_BYTES + 1)}ADR-CAND-001",
    "over-nested percent encoding" => "%2525252541DR-CAND-001"
  }
  encoded_composition_mutations.each do |mutation_name, fragment|
    record_p1_006_mutation.call(:encoded_composition)
    residual_issue = candidate_gate_fixture.merge(
      "acceptance_criteria" => ["#{candidate_gate_fixture.fetch('acceptance_criteria').first} #{fragment}"]
    )
    residual_failures = p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: residual_issue)
    unless residual_failures.any? { |failure| failure.start_with?("STEAD-P1-006 acceptance criteria contain noncanonical ADR fragments") }
      failures << "STEAD-P1-006 #{mutation_name} mutant survived encoded-composition validation"
    end
  end

  named_entity_mutations = {
    "HTML5 Tab entity" => "AD&Tab;R-CAND-001",
    "HTML5 NewLine entity" => "AD&NewLine;R-CAND-001",
    "HTML5 ThinSpace entity" => "AD&ThinSpace;R-CAND-001",
    "HTML5 emsp entity" => "AD&emsp;R-CAND-001",
    "HTML5 NegativeThinSpace entity" => "AD&NegativeThinSpace;R-CAND-001",
    "HTML5 legacy semicolonless nbsp entity" => "AD&nbspR-CAND-001",
    "HTML5 legacy semicolonless shy entity" => "AD&shyR-CAND-001",
    "HTML5 legacy semicolonless acute entity" => "AD&acuteR-CAND-001",
    "HTML5 legacy semicolonless cedil entity" => "AD&cedilR-CAND-001",
    "HTML5 legacy semicolonless macr entity" => "AD&macrR-CAND-001",
    "HTML5 legacy semicolonless uml entity" => "AD&umlR-CAND-001",
    "HTML5 legacy semicolonless quot entity" => "AD&quotR-CAND-001",
    "HTML5 legacy semicolonless QUOT entity" => "AD&QUOTR-CAND-001",
    "HTML5 legacy semicolonless lt tag composition" => "AD&ltspan>R-CAND-001&lt/span>",
    "HTML5 legacy semicolonless LT tag composition" => "AD&LTspan>R-CAND-001&LT/span>",
    "HTML5 legacy semicolonless lt comment composition" => "AD&lt!--split--&gtR-CAND-001"
  }
  named_entity_mutations.each do |mutation_name, fragment|
    record_p1_006_mutation.call(:named_entity)
    residual_issue = candidate_gate_fixture.merge(
      "acceptance_criteria" => ["#{candidate_gate_fixture.fetch('acceptance_criteria').first} #{fragment}"]
    )
    residual_failures = p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: residual_issue)
    unless residual_failures.any? { |failure| failure.start_with?("STEAD-P1-006 acceptance criteria contain noncanonical ADR fragments") }
      failures << "STEAD-P1-006 #{mutation_name} mutant survived named-entity validation"
    end
  end

  reordered_clause = EXPECTED_P1_006_ADR_GATE_CLAUSE.sub(
    "ADR-CAND-002, ADR-CAND-003",
    "ADR-CAND-003, ADR-CAND-002"
  )
  duplicated_clause = EXPECTED_P1_006_ADR_GATE_CLAUSE.sub("ADR-CAND-003", "ADR-CAND-002")
  structural_gate_mutations = {
    "empty acceptance array" => [],
    "null acceptance field" => nil,
    "non-string first acceptance item" => [42, candidate_gate_fixture.fetch("acceptance_criteria").first],
    "non-string later acceptance item" => [candidate_gate_fixture.fetch("acceptance_criteria").first, { "mutant" => true }],
    "canonical clause in second item" => ["introductory text", candidate_gate_fixture.fetch("acceptance_criteria").first],
    "reordered canonical candidates" => ["#{reordered_clause} continue with the bounded implementation."],
    "duplicated canonical candidate" => ["#{duplicated_clause} continue with the bounded implementation."],
    "clause split across array items" => ["Only after ADR-CAND-002, ADR-CAND-003,", "ADR-CAND-004, ADR-CAND-005, ADR-CAND-007, and ADR-CAND-021 are accepted,"]
  }
  structural_gate_mutations.each do |mutation_name, acceptance_criteria|
    record_p1_006_mutation.call(:acceptance_structure)
    structural_issue = candidate_gate_fixture.merge("acceptance_criteria" => acceptance_criteria)
    structural_failures = p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: structural_issue)
    if structural_failures.empty?
      failures << "STEAD-P1-006 #{mutation_name} mutant survived strict acceptance-structure validation"
    end
  end

  {
    "continuation vertical tab" => "\u000B",
    "continuation next-line control" => "\u0085",
    "continuation zero-width format" => "\u200B",
    "continuation Unicode line separator" => "\u2028"
  }.each do |mutation_name, character|
    record_p1_006_mutation.call(:continuation_control)
    control_issue = candidate_gate_fixture.merge(
      "acceptance_criteria" => ["#{candidate_gate_fixture.fetch('acceptance_criteria').first}#{character}"]
    )
    control_failures = p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: control_issue)
    unless control_failures.any? { |failure| failure.include?("prohibited control, format, or line-separator") }
      failures << "STEAD-P1-006 #{mutation_name} mutant survived continuation-character validation"
    end
  end

  ["_", "__", "___", "``", "```"].each do |delimiter|
    record_p1_006_mutation.call(:cross_item)
    split_item_issue = candidate_gate_fixture.merge(
      "acceptance_criteria" => [
        candidate_gate_fixture.fetch("acceptance_criteria").first.gsub("ADR-CAND-002") { "#{delimiter}ADR-CAND-002" },
        "later#{delimiter}"
      ]
    )
    split_item_failures = p1_006_adr_gate_failures(adr_gates: adr_gates, security_issue: split_item_issue)
    unless split_item_failures.any? { |failure| failure.start_with?("STEAD-P1-006 acceptance criteria omit ADR gates:") }
      failures << "STEAD-P1-006 cross-item #{delimiter.inspect} delimiter mutant survived strict item-boundary validation"
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

adr_0008_gate = adr_gates["ADR-CAND-006"]
adr_0008_expected_dependents = %w[
  STEAD-P1-015
  STEAD-P1-007
  STEAD-P1-008
  STEAD-P1-011
  STEAD-P1-012
  STEAD-P2-005
].to_set
adr_0008_actual_dependents = Array(adr_0008_gate&.fetch("dependent_issues", nil)).to_set
unless adr_0008_actual_dependents == adr_0008_expected_dependents
  failures << "implementation issue catalog: ADR-CAND-006 exact dependent issues must be #{adr_0008_expected_dependents.to_a.sort.join(', ')}, found #{adr_0008_actual_dependents.to_a.sort.join(', ')}"
end
unless adr_0008_gate&.fetch("decide_before_issue", nil) == "STEAD-P1-015"
  failures << "implementation issue catalog: ADR-CAND-006 must precede the STEAD-P1-015 recovery-port sub-slice"
end

outbox_issue = issues["STEAD-P1-015"]
outbox_acceptance = Array(outbox_issue&.fetch("acceptance_criteria", nil)).join(" ")
unless outbox_acceptance.include?("exact canonical event bytes/digest") &&
       outbox_acceptance.include?("monotonic publication-generation expected-value CAS") &&
       outbox_acceptance.include?("opaque publication receipt") &&
       outbox_acceptance.include?("provider-neutral")
  failures << "STEAD-P1-015 acceptance must own the provider-neutral ADR-0008 outbox recovery port"
end
outbox_boundaries = Array(outbox_issue&.fetch("prohibited_boundaries", nil)).join(" ")
unless %w[NATS PubAck broker-client].all? { |fragment| outbox_boundaries.include?(fragment) }
  failures << "STEAD-P1-015 boundaries must exclude NATS/PubAck/broker semantics from the core port"
end

event_issue = issues["STEAD-P1-007"]
unless Array(event_issue&.fetch("dependencies", nil)).include?("STEAD-P1-015")
  failures << "STEAD-P1-007 dependencies omit the WS-02-owned STEAD-P1-015 outbox port"
end
if Array(event_issue&.fetch("dependencies", nil)).include?("STEAD-P1-011")
  failures << "STEAD-P1-007 must consume the early WS-12 config/preflight child, not depend on downstream STEAD-P1-011 completion"
end
event_acceptance = Array(event_issue&.fetch("acceptance_criteria", nil)).join(" ")
unless event_acceptance.include?("deployment-domain account, two-stream, service-credential, registry-pinning/rendering, and local-startup contract") &&
       event_acceptance.include?("Organization lifecycle creates no broker resource") &&
       event_acceptance.include?("not completion of STEAD-P1-011") &&
       event_acceptance.include?("leader-served stream get") &&
       event_acceptance.include?("fenced WS-02 generation CAS")
  failures << "STEAD-P1-007 acceptance must consume the early domain-account/local-stack contract without Organization broker provisioning"
end

operations_issue = issues["STEAD-P1-011"]
operations_acceptance = Array(operations_issue&.fetch("acceptance_criteria", nil)).join(" ")
unless Array(operations_issue&.fetch("dependencies", nil)).include?("STEAD-P1-007")
  failures << "STEAD-P1-011 must remain downstream of STEAD-P1-007"
end
unless operations_acceptance.include?("early dependency-ready WS-12 child under this issue") &&
       operations_acceptance.include?("generated local-only credentials") &&
       operations_acceptance.include?("requires no operator-key ceremony") &&
       operations_acceptance.include?("without claiming this parent complete")
  failures << "STEAD-P1-011 acceptance must split its generated local development stack from downstream parent completion"
end

adr_0008_owned_path_requirements = {
  "STEAD-P1-015" => %w[apps/core/internal/outbox tests/integration/core packages/test-fixtures/core docs/architecture/core],
  "STEAD-P1-007" => %w[apps/worker packages/event-schemas specs/asyncapi tests/contract/events packages/test-fixtures/events],
  "STEAD-P1-011" => %w[apps/steadctl deploy/compose packages/domain-schemas/config docs/operator tests/contract/operations tests/performance/datasets tests/backup-restore packages/test-fixtures/operations]
}.freeze
adr_0008_owned_path_requirements.each do |issue_id, required_paths|
  issue = issues[issue_id]
  unless issue
    failures << "implementation issue catalog: missing #{issue_id} for ADR-0008 owned-path split"
    next
  end

  missing_paths = required_paths.to_set - Array(issue["owned_directories"]).to_set
  failures << "#{issue_id} owned directories omit ADR-0008 contribution paths: #{missing_paths.to_a.sort.join(', ')}" unless missing_paths.empty?
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
  },
  "0008" => {
    "STEAD-P1-015" => %w[
      T-ADR-0008-OUTBOX-RECOVERY-PORT
    ],
    "STEAD-P1-007" => tests_by_number.fetch("0008", []).reject { |test_id| test_id == "T-ADR-0008-OUTBOX-RECOVERY-PORT" },
    "STEAD-P1-008" => %w[
      T-ADR-0008-RESOURCE-ORDERING
      T-ADR-0008-IDEMPOTENCY
      T-ADR-0008-SCHEMA-COMPATIBILITY
      T-ADR-0008-PAYLOAD-MINIMIZATION
      T-ADR-0008-PROJECTION-REBUILD
    ],
    "STEAD-P1-011" => %w[
      T-ADR-0008-SUBJECT-PARTITION
      T-ADR-0008-SUBSCRIBER-ISOLATION
      T-ADR-0008-RETENTION
      T-ADR-0008-IDEMPOTENCY
      T-ADR-0008-PAYLOAD-MINIMIZATION
      T-ADR-0008-ASYNC-PERFORMANCE
      T-ADR-0008-PROJECTION-REBUILD
    ],
    "STEAD-P1-012" => tests_by_number.fetch("0008", []),
    "STEAD-P2-005" => %w[
      T-ADR-0008-SUBSCRIBER-ISOLATION
      T-ADR-0008-AUTHORIZED-REPLAY
      T-ADR-0008-PAYLOAD-MINIMIZATION
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

# ADR-0008 crosses fixed WS-02, WS-07, WS-08, WS-12, external-channel, and
# independent-gate boundaries. Keep the complete cumulative issue assignment
# closed in both directions so one owner cannot silently claim or shed another
# owner's case contribution while the union still happens to cover every test.
adr_0008_expected_issue_assignments = implementation_assignments.fetch("0008").transform_values(&:to_set)
adr_0008_actual_issue_assignments = issues.each_with_object({}) do |(issue_id, issue), assignments|
  adr_tests = Array(issue["automated_tests"]).grep(/^T-ADR-0008-/).to_set
  assignments[issue_id] = adr_tests unless adr_tests.empty?
end
(adr_0008_expected_issue_assignments.keys | adr_0008_actual_issue_assignments.keys).sort.each do |issue_id|
  expected_tests = adr_0008_expected_issue_assignments.fetch(issue_id, Set.new)
  actual_tests = adr_0008_actual_issue_assignments.fetch(issue_id, Set.new)
  next if actual_tests == expected_tests

  missing_tests = expected_tests - actual_tests
  unexpected_tests = actual_tests - expected_tests
  failures << "#{issue_id} ADR-0008 exact owner assignment mismatch: missing [#{missing_tests.to_a.sort.join(', ')}], unexpected [#{unexpected_tests.to_a.sort.join(', ')}]"
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
phase_one_independent_tests.merge(tests_by_number.fetch("0008", []))
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

unless p1_006_gate_mutation_groups == EXPECTED_P1_006_GATE_MUTATION_GROUPS
  actual_groups = EXPECTED_P1_006_GATE_MUTATION_GROUPS.keys.to_h do |group|
    [group, p1_006_gate_mutation_groups[group]]
  end
  failures << "STEAD-P1-006 mutation inventory groups changed: expected #{EXPECTED_P1_006_GATE_MUTATION_GROUPS.inspect}, found #{actual_groups.inspect}"
end
unless p1_006_gate_mutation_count == EXPECTED_P1_006_GATE_MUTATION_COUNT
  failures << "STEAD-P1-006 mutation inventory must contain exactly #{EXPECTED_P1_006_GATE_MUTATION_COUNT} cases, found #{p1_006_gate_mutation_count}"
end

if failures.empty?
  adr_0007_killed_mutations = adr_0007_expected_edges.length - adr_0007_mutation_survivors.length
  adr_0008_killed_mutations = adr_0008_expected_edges.length - adr_0008_mutation_survivors.length
  puts "STEAD-P1-006 strict raw gate mutation guard: PASS (#{p1_006_gate_mutation_count}/#{EXPECTED_P1_006_GATE_MUTATION_COUNT} mutations killed)"
  puts "ADR-0007 exact-mapping mutation guard: PASS (#{adr_0007_killed_mutations}/#{adr_0007_expected_edges.length} required edge deletions killed)"
  puts "ADR-0008 exact-mapping mutation guard: PASS (#{adr_0008_killed_mutations}/#{adr_0008_expected_edges.length} required edge deletions killed)"
  puts "ADR-0008 security-contract mutation guard: PASS (#{adr_0008_security_mutations.length}/#{adr_0008_security_mutations.length} mutations killed across #{adr_0008_security_mutation_groups.length} gap groups)"
  puts "ADR traceability validation: PASS (records=#{paths.length}, requirements=#{known_requirement_ids.length}, tests=#{all_test_owners.length})"
else
  warn "ADR traceability validation: FAIL (#{failures.length} issue#{failures.length == 1 ? '' : 's'})"
  failures.each { |failure| warn "- #{failure}" }
  exit 1
end
