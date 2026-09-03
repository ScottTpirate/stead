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
  "0009" => { candidate: "ADR-CAND-008", state: "PROPOSED", owner_approval: true }
}.freeze

EXPECTED_REQUIREMENT_TEST_LINKS = {
  "0009" => {
    "PRIN-002" => %w[T-ADR-0009-UPGRADE-ROLLBACK],
    "ARCH-004" => %w[T-ADR-0009-DIRECT-CHANGE-ACCEPT T-ADR-0009-AMBIGUOUS-MUTATION],
    "DOM-004" => %w[T-ADR-0009-PRECEDENCE],
    "SCM-001" => %w[
      T-ADR-0009-WEBHOOK-IDEMPOTENCY
      T-ADR-0009-PROVIDER-OUTAGE
      T-ADR-0009-FULL-RECONCILIATION
      T-ADR-0009-UPGRADE-ROLLBACK
    ],
    "SCM-002" => %w[
      T-ADR-0009-PRECEDENCE
      T-ADR-0009-DIRECT-CHANGE-RESET
      T-ADR-0009-FULL-RECONCILIATION
    ],
    "SCM-003" => %w[
      T-ADR-0009-PRECEDENCE
      T-ADR-0009-DIRECT-CHANGE-ACCEPT
      T-ADR-0009-DIRECT-CHANGE-RESET
      T-ADR-0009-CONFLICT-QUARANTINE
      T-ADR-0009-AMBIGUOUS-MUTATION
      T-ADR-0009-FULL-RECONCILIATION
    ],
    "SCM-004" => %w[
      T-ADR-0009-WEBHOOK-IDEMPOTENCY
      T-ADR-0009-DIRECT-CHANGE-ACCEPT
      T-ADR-0009-DIRECT-CHANGE-RESET
      T-ADR-0009-CONFLICT-QUARANTINE
      T-ADR-0009-AMBIGUOUS-MUTATION
    ],
    "SCM-005" => %w[
      T-ADR-0009-AMBIGUOUS-MUTATION
      T-ADR-0009-FULL-RECONCILIATION
      T-ADR-0009-UPGRADE-ROLLBACK
    ],
    "CLS-006" => %w[
      T-ADR-0009-CONFLICT-QUARANTINE
      T-ADR-0009-PERMISSION-DRIFT
      T-ADR-0009-PROVIDER-OUTAGE
    ],
    "CLS-007" => %w[
      T-ADR-0009-PERMISSION-DRIFT
      T-ADR-0009-PROVIDER-OUTAGE
      T-ADR-0009-AMBIGUOUS-MUTATION
      T-ADR-0009-FULL-RECONCILIATION
    ],
    "TEST-006" => %w[
      T-ADR-0009-PRECEDENCE
      T-ADR-0009-WEBHOOK-IDEMPOTENCY
      T-ADR-0009-DIRECT-CHANGE-ACCEPT
      T-ADR-0009-DIRECT-CHANGE-RESET
      T-ADR-0009-CONFLICT-QUARANTINE
      T-ADR-0009-PERMISSION-DRIFT
      T-ADR-0009-PROVIDER-OUTAGE
      T-ADR-0009-AMBIGUOUS-MUTATION
      T-ADR-0009-FULL-RECONCILIATION
      T-ADR-0009-UPGRADE-ROLLBACK
    ],
    "PERF-003" => %w[
      T-ADR-0009-PROVIDER-OUTAGE
      T-ADR-0009-FULL-RECONCILIATION
    ]
  }.freeze
}.freeze

# Close the complete ADR-0009 Decision body as a separate integrity guard.
# Semantic mutation self-tests below never use this digest as their oracle.
ADR_0009_DECISION_BODY_SHA256 =
  "9577e0488c7f05a324ae420a8c5722c1820c3b43185ce2d9dcc41299f757d16d".freeze
ADR_0009_OWNER_APPROVAL_LINE =
  "- **Project-owner approval required:** yes; this proposal narrowly changes the locked per-provider-HTTP-call durable-permit granularity in ADR-0005, CLS-007, and ADR-0007 for one closed bounded internal read plan, so acceptance requires explicit project-owner approval naming the exact immutable commit SHA".freeze
ADR_0009_SUPERSESSION_LINE =
  "- **Supersedes / superseded by:** only on acceptance at an exact immutable commit SHA with explicit project-owner approval, supersedes only ADR-0005, CLS-007, and ADR-0007's per-provider-HTTP-call durable-permit granularity for the one closed bounded internal pagination/snapshot/verification/safe-idempotent-read plan defined here; every other decision and fence remains in force, and any broader exception requires a superseding ADR".freeze
ADR_0009_PROJECT_OWNER_REVIEW_LINE =
  "| Project owner | pending explicit approver | pending | must name the exact immutable commit SHA; no approval or acceptance record exists |".freeze
ADR_0009_EXACT_SHA_APPROVAL_SENTENCE =
  "Each approval must name the exact immutable commit SHA containing the decision; approval of a branch, tag, pull request, moving head, unspecified revision, or later-mutated text is insufficient.".freeze
ADR_0009_METADATA_KEY_ORDER = [
  "Status",
  "Date",
  "Decision owners",
  "Project-owner approval required",
  "Requirement IDs",
  "Affected contracts/modules/directories",
  "Resolves on acceptance",
  "Supersedes / superseded by"
].freeze
ADR_0009_APPROVAL_PARAGRAPH =
  "Because this proposal narrowly supersedes an accepted/locked call-granularity rule, every named review and explicit project-owner approval is required. #{ADR_0009_EXACT_SHA_APPROVAL_SENTENCE} Until those records exist, ADR-0009 remains Proposed, `ADR-CAND-008` remains blocking, and no bounded-read permit exception is authorized. Decision acceptance would approve this contract and its future verification obligations, not claim that runtime implementation or evidence already exists.".freeze
ADR_0009_EXPECTED_REVIEW_ROWS = [
  "| Contract owner (WS-03) | pending non-author reviewer | pending | pending |",
  "| Architecture and standards (WS-01) | pending | pending | pending |",
  "| Canonical transaction owner (WS-02) | pending | pending | pending |",
  "| Authorization/classification owner (WS-06) | pending | pending | pending |",
  "| Event/audit owner (WS-07) | pending | pending | pending |",
  "| Deployment/operations owner (WS-12) | pending | pending | pending |",
  "| Independent QA and C-QA traceability owner (distinct WS-13 identity) | pending non-author reviewer | pending | pending |",
  "| Independent security (distinct WS-13 identity) | pending non-author reviewer | pending | pending |",
  ADR_0009_PROJECT_OWNER_REVIEW_LINE
].freeze
ADR_0009_REVIEW_TABLE_HEADER = "| Role | Identity | Disposition | Evidence/date |".freeze
ADR_0009_REVIEW_TABLE_SEPARATOR = "|---|---|---|---|".freeze
ADR_0009_HIDDEN_GOVERNANCE_MARKERS = (
  ADR_0009_METADATA_KEY_ORDER.map { |key| "- **#{key}:**" } +
  [
    "## Reviews and approvals",
    ADR_0009_EXACT_SHA_APPROVAL_SENTENCE,
    ADR_0009_REVIEW_TABLE_HEADER
  ] +
  ADR_0009_EXPECTED_REVIEW_ROWS.map { |row| "| #{row.split('|', -1)[1].strip} |" }
).freeze
ADR_0009_SEMANTIC_FRAGMENT_PREDICATES = {
  scope_id: ["unique, nontransferable `scope_id`"],
  logical_operation_id: ["`scope_id` and `logical_operation_id` and binding"],
  scope_nontransferable: [
    "The scope cannot be renewed, transferred, output-widened, or reused across a logical operation, `ReconciliationGeneration`, provider installation, `ProviderResourceKey`, resource, security domain, or compatibility profile."
  ],
  acting_principal: [
    "binding the acting service principal",
    "Authenticate the acting service principal and resolve the exact initiating principal"
  ],
  initiating_principal: [
    "exact initiating principal (including an explicit system initiator for scheduled work)",
    "resolve the exact initiating principal; scheduled work binds an explicit system initiator rather than omitting that field"
  ],
  organization: ["Organization, security domain"],
  security_domain: ["security domain, exact canonical container"],
  canonical_container_resource: ["exact canonical container and closed resource set"],
  provider_installation: ["exact provider installation UUID"],
  provider_path: ["provider installation UUID and API path"],
  provider_resource_key: ["API path plus `ProviderResourceKey`"],
  reconciliation_generation: ["`ProviderResourceKey`, `ReconciliationGeneration`"],
  operation_class: ["`ReconciliationGeneration`, one allowed operation class"],
  closed_call_plan: [
    "one allowed operation class and closed call plan",
    "The plan fixes the exact HTTP method/path templates, resource set, cursor derivation rules, call order, retry classes, and maximum attempts/calls/pages/items/response bytes before the first provider call."
  ],
  activation_vector_definition: [
    "the complete immutable ADR-0005 activation snapshot and consistency vector, durable monotonic dispatch/page ordinals"
  ],
  activation_vector_expiry: [
    "earliest bound temporal input in the complete ADR-0005 activation snapshot and consistency vector or the original logical-operation deadline"
  ],
  activation_vector_revalidation_summary: [
    "operation class/call plan, complete activation snapshot and consistency vector, compatibility profile, ordinals/counters, deadline, and earliest-bound expiry"
  ],
  activation_vector_persistence: [
    "persist its immutable identity, complete ADR-0005 activation snapshot and consistency vector, fixed deadline/expiry, cumulative accounting"
  ],
  activation_vector_pre_call: [
    "Revalidate every component of the complete activation snapshot and consistency vector, including the latest provider-enforcement and resource fences"
  ],
  activation_vector_pre_commit: [
    "compare the complete activation snapshot, consistency vector, exact installation/path/resource key"
  ],
  accounting_attempt: ["reserved and actual attempt/call/", "never-reused attempt/call/"],
  accounting_call: ["cumulative call/page/item/response-byte accounting", "attempt/call/page/item/byte counts"],
  accounting_page: ["durable monotonic dispatch/page ordinals", "call/page/item/byte bounds"],
  accounting_item: ["cumulative call/page/item/response-byte accounting", "page/item/byte counts"],
  accounting_byte: ["item/response-byte accounting", "item/byte counts"],
  accounting_crash_persistence: [
    "Crash/resume never rolls back, resets, or narrows those cumulative counters to manufacture more budget."
  ],
  compatibility_profile: ["the exact compatibility-profile ID/version/schema digest"],
  original_deadline: ["the original deadline, and immutable expiry", "original logical-operation deadline"],
  earliest_expiry: [
    "Its expiry is fixed at creation to no later than the earliest bound temporal input in the complete ADR-0005 activation snapshot and consistency vector or the original logical-operation deadline"
  ],
  provider_output_no_widen: [
    "Provider output may supply only a cursor admitted by those rules; it cannot add an endpoint, method, resource, operation class, retry, result field, or budget."
  ],
  pre_call_revalidation: ["Immediately before every provider call"],
  pre_commit_revalidation: [
    "immediately before every local outcome commit",
    "Immediately before the local outcome commit"
  ],
  latest_provider_fence: ["including the latest provider-enforcement and resource fences, immediately before dispatch"],
  latest_resource_fence: ["provider-enforcement and resource fences, immediately before dispatch"],
  effect_latest_fences: ["revalidate the complete scope/temporal state plus the latest fences"],
  actor_isolation: ["one actor can never authorize a combined snapshot"],
  causal_proof: [
    "A complete contiguous proof chain must connect the last confirmed token to the freshly read token."
  ],
  impersonation_chain: [
    "binds the effective actor and every administrator/Sudo impersonator",
    "Resolve the effective actor and every impersonator to current canonical principals"
  ],
  actor_laundering: [
    "administrator-laundered",
    "The service actor's read scope, historical permission, webhook HMAC, and provider-local permission cannot authorize acceptance."
  ],
  operation_bound_create_identity: [
    "Exactly one candidate carrying that verified operation-bound key may be adopted."
  ],
  before_state_not_terminal: [
    "a current before, intended-after, absent, or recreated snapshot is never by itself terminal proof"
  ],
  aba_not_terminal: [
    "Without such proof, snapshot comparison guides containment only; the original permit remains `reconciling`"
  ],
  effect_permit_sequence: [
    "freshly authorize that exact effect, commit its own durable one-use `AuthorizationEffectPermit`",
    "atomically consume only that permit, and invoke the effect once",
    "These categories retain per-effect-call permits"
  ],
  read_scope_not_effect_authority: ["the read scope can neither authorize nor substitute for them"],
  effective_principal_fresh_decision: [
    "Run a separate complete fresh central decision for that effective acting principal, impersonation constraint, and exact canonical delta",
    "run the required fresh decision for the effective initiating/provider principal and exact delta"
  ],
  final_transaction_fence: [
    "then compare final activation, authorization, provider-enforcement, resource, and operation revisions inside the owning transaction"
  ]
}.freeze
ADR_0009_EXCLUDED_EFFECT_PREDICATES = {
  effect_permit_provider_mutation: "provider mutation",
  effect_permit_credential: "credential issuance",
  effect_permit_direct_protocol: "direct Git/protocol access",
  effect_permit_export_download: "export/download",
  effect_permit_non_idempotent: "non-idempotent call",
  effect_permit_ambiguous: "ambiguous external effect",
  effect_permit_outliving: "operation that can outlive the logical request/job"
}.freeze
ADR_0009_SEMANTIC_FORBIDDEN_FRAGMENTS = {
  scope_nontransferable: ["The scope may be transferred or reused"],
  acting_principal: ["The acting principal may be omitted"],
  initiating_principal: ["The initiating principal may be omitted"],
  accounting_crash_persistence: ["Crash/resume may reset cumulative accounting"],
  earliest_expiry: ["The scope expiry may be extended"],
  provider_output_no_widen: ["Provider output may widen the call plan"],
  actor_isolation: ["A later actor may authorize a combined snapshot"],
  causal_proof: ["The causal proof may be omitted"],
  impersonation_chain: ["Administrator or Sudo impersonation may be ignored"],
  actor_laundering: ["An administrator-laundered identity may be accepted"],
  operation_bound_create_identity: ["A content match alone may prove create operation identity"],
  before_state_not_terminal: ["A before-state snapshot alone may terminalize no effect"],
  aba_not_terminal: ["An apply-revert or delete-recreate snapshot may terminalize the operation"],
  read_scope_not_effect_authority: ["The read scope may authorize a retained effect category"],
  effective_principal_fresh_decision: ["The final fresh effective-principal decision may be skipped"],
  final_transaction_fence: ["The final transaction fence may be skipped"]
}.freeze
ADR_0009_EXPECTED_CRITICAL_VERIFICATION_ROWS = {
  ambiguous_mutation_verification: "| `T-ADR-0009-AMBIGUOUS-MUTATION` | Lost responses for update/delete/create exercise before/after/third-state, apply/revert, delete/recreate, delayed true create, and coincident zero/one/multiple-candidate states. No snapshot alone or absence-after-horizon can terminalize success or `failed_without_effect`; create adoption requires a verified operation-bound immutable key. Tests prove the bounded read scope cannot authorize a mutation, credential, direct Git/protocol operation, export/download, non-idempotent call, ambiguous effect, or operation outliving its logical request/job; each retains its own durable one-use permit and complete immediate pre-call/final-commit revalidation. No widening, blind retry, duplicate, ABA terminalization, candidate misadoption, cross-installation/generation reuse, expired outcome commit, or false success occurs. |",
  full_reconciliation_verification: "| `T-ADR-0009-FULL-RECONCILIATION` | One fresh `ProviderAuthorizationScope` binds unique nontransferable scope/logical-operation IDs; acting and initiating principals; Organization/security domain; exact canonical container/resource set; installation/path/`ProviderResourceKey`; `ReconciliationGeneration`; operation class/closed call plan; the complete ADR-0005 activation snapshot and consistency vector; monotonic attempt/call/page ordinals and cumulative call/page/item/byte accounting; exact compatibility profile; original deadline; and earliest-bound immutable expiry. Negative fixtures omit or swap every binding, alter activation/vector components, widen/reorder the call plan from provider output, roll back or reset counters across crash/resume, reuse across operation/generation/installation/resource/domain/profile, renew or extend expiry, and cross a deadline. Bounded pagination, snapshot/verification reads, and declared safe idempotent-read retries omit per-call permits only inside that plan; exact scope/temporal revalidation occurs immediately before every provider call and local outcome commit, while one logical audit reports reserved/actual counts/results and measured call/query/memory bounds. |"
}.freeze
ADR_0009_EXPECTED_SEMANTIC_MUTATIONS = {
  "scope ID uniqueness removed" => :scope_id,
  "logical-operation ID binding removed" => :logical_operation_id,
  "scope transfer and reuse admitted" => :scope_nontransferable,
  "scope renewal admitted" => :scope_nontransferable,
  "scope output widening admitted" => :scope_nontransferable,
  "logical-operation reuse admitted" => :scope_nontransferable,
  "cross-generation reuse admitted" => :scope_nontransferable,
  "cross-installation reuse admitted" => :scope_nontransferable,
  "acting principal binding removed" => :acting_principal,
  "initiating principal binding removed" => :initiating_principal,
  "organization binding removed" => :organization,
  "security-domain binding removed" => :security_domain,
  "canonical container/resource binding removed" => :canonical_container_resource,
  "provider installation binding removed" => :provider_installation,
  "provider path binding removed" => :provider_path,
  "provider resource-key binding removed" => :provider_resource_key,
  "reconciliation-generation binding removed" => :reconciliation_generation,
  "operation-class binding removed" => :operation_class,
  "closed call-plan binding removed" => :closed_call_plan,
  "activation/vector definition binding removed" => :activation_vector_definition,
  "activation/vector earliest-expiry binding removed" => :activation_vector_expiry,
  "activation/vector revalidation summary removed" => :activation_vector_revalidation_summary,
  "activation/vector persistence binding removed" => :activation_vector_persistence,
  "activation/vector pre-call binding removed" => :activation_vector_pre_call,
  "activation/vector pre-commit binding removed" => :activation_vector_pre_commit,
  "attempt accounting dimension removed" => :accounting_attempt,
  "call accounting dimension removed" => :accounting_call,
  "page accounting dimension removed" => :accounting_page,
  "item accounting dimension removed" => :accounting_item,
  "byte accounting dimension removed" => :accounting_byte,
  "crash persistence guarantee removed" => :accounting_crash_persistence,
  "compatibility-profile binding removed" => :compatibility_profile,
  "original-deadline binding removed" => :original_deadline,
  "earliest-bound expiry removed" => :earliest_expiry,
  "provider-output widening admitted" => :provider_output_no_widen,
  "pre-call revalidation removed" => :pre_call_revalidation,
  "pre-commit revalidation removed" => :pre_commit_revalidation,
  "latest provider-enforcement fence removed" => :latest_provider_fence,
  "latest resource fence removed" => :latest_resource_fence,
  "latest effect fence removed" => :effect_latest_fences,
  "later actor authorizes combined snapshot" => :actor_isolation,
  "causal proof made optional" => :causal_proof,
  "administrator impersonation ignored" => :impersonation_chain,
  "administrator laundering admitted" => :actor_laundering,
  "create adopted without operation identity" => :operation_bound_create_identity,
  "before snapshot treated as no-effect proof" => :before_state_not_terminal,
  "apply-revert ABA admitted" => :aba_not_terminal,
  "fresh effect-permit sequence removed" => :effect_permit_sequence,
  "read scope authorizes retained effect" => :read_scope_not_effect_authority,
  "provider mutation permit removed" => :effect_permit_provider_mutation,
  "credential permit removed" => :effect_permit_credential,
  "direct protocol permit removed" => :effect_permit_direct_protocol,
  "export/download permit removed" => :effect_permit_export_download,
  "non-idempotent permit removed" => :effect_permit_non_idempotent,
  "ambiguous-effect permit removed" => :effect_permit_ambiguous,
  "outliving-operation permit removed" => :effect_permit_outliving,
  "excluded-effect list widened" => :effect_permit_exhaustive,
  "final fresh effective-principal authorization removed" => :effective_principal_fresh_decision,
  "final transaction fence removed" => :final_transaction_fence,
  "ambiguous-mutation verification weakened" => :ambiguous_mutation_verification,
  "full-reconciliation verification weakened" => :full_reconciliation_verification,
  "Decision hidden in HTML comment" => :visible_decision_structure,
  "Decision hidden in fenced code" => :visible_decision_structure,
  "Decision hidden in type-one raw HTML" => :visible_decision_structure,
  "Decision hidden in processing-instruction raw HTML" => :visible_decision_structure,
  "Decision hidden in declaration raw HTML" => :visible_decision_structure,
  "Decision hidden in CDATA raw HTML" => :visible_decision_structure,
  "Decision heading hidden in type-six raw HTML" => :visible_decision_structure,
  "Decision heading hidden in type-seven raw HTML" => :visible_decision_structure,
  "Verification hidden in type-one raw HTML" => :verification_structure,
  "Markdown byte bound exceeded" => :markdown_resource_bounds,
  "Markdown line-count bound exceeded" => :markdown_resource_bounds,
  "Markdown line-length bound exceeded" => :markdown_resource_bounds,
  "contradictory scope reuse appended" => :scope_nontransferable,
  "contradictory acting-principal omission appended" => :acting_principal,
  "contradictory initiating-principal omission appended" => :initiating_principal,
  "contradictory crash reset appended" => :accounting_crash_persistence,
  "contradictory expiry extension appended" => :earliest_expiry,
  "contradictory provider widening appended" => :provider_output_no_widen,
  "contradictory combined-actor authorization appended" => :actor_isolation,
  "contradictory optional causal proof appended" => :causal_proof,
  "contradictory impersonation bypass appended" => :impersonation_chain,
  "contradictory actor laundering appended" => :actor_laundering,
  "contradictory content-only create identity appended" => :operation_bound_create_identity,
  "contradictory before-state terminalization appended" => :before_state_not_terminal,
  "contradictory ABA terminalization appended" => :aba_not_terminal,
  "contradictory read-scope effect authority appended" => :read_scope_not_effect_authority,
  "contradictory final fresh authorization bypass appended" => :effective_principal_fresh_decision,
  "contradictory final-fence bypass appended" => :final_transaction_fence
}.freeze
ADR_0009_EXPECTED_REVIEW_MUTATIONS = {
  "missing independent QA row" => :review_rows,
  "missing independent security row" => :review_rows,
  "combined QA/security row" => :review_duplicates_conflicts,
  "duplicate independent QA row" => :review_duplicates_conflicts
}.freeze
ADR_0009_EXPECTED_GOVERNANCE_MUTATIONS = {
  "supersession removed" => :metadata_supersession_narrow,
  "supersession broadened beyond read-plan granularity" => :metadata_supersession_narrow,
  "project-owner metadata weakened" => :metadata_owner_required,
  "project-owner review row weakened" => :project_owner_row,
  "immutable-SHA approval weakened" => :exact_sha_approval_placement,
  "catalog project-owner gate weakened" => :catalog_owner_gate,
  "catalog state changed to accepted" => :catalog_proposed,
  "catalog acceptance record fabricated" => :catalog_no_acceptance,
  "catalog decision record redirected" => :catalog_decision_record,
  "catalog ADR-CAND-008 gate duplicated" => :catalog_gate_unique,
  "comment-hidden composite with visible contradictions" => :hidden_governance_substitution,
  "fence-hidden composite with visible contradictions" => :hidden_governance_substitution,
  "comment-hidden owner line with visible contradiction" => :hidden_governance_substitution,
  "fence-hidden owner line with visible contradiction" => :hidden_governance_substitution,
  "comment-hidden supersession with visible contradiction" => :hidden_governance_substitution,
  "fence-hidden supersession with visible contradiction" => :hidden_governance_substitution,
  "comment-hidden immutable-SHA paragraph with visible contradiction" => :hidden_governance_substitution,
  "fence-hidden immutable-SHA paragraph with visible contradiction" => :hidden_governance_substitution,
  "comment-hidden project-owner row with visible contradiction" => :hidden_governance_substitution,
  "fence-hidden project-owner row with visible contradiction" => :hidden_governance_substitution,
  "duplicate conflicting owner metadata" => :metadata_duplicates_conflicts,
  "duplicate conflicting supersession metadata" => :metadata_duplicates_conflicts,
  "misplaced owner metadata" => :metadata_duplicates_conflicts,
  "misplaced supersession metadata" => :metadata_duplicates_conflicts,
  "misplaced immutable-SHA sentence" => :exact_sha_approval_placement,
  "misplaced project-owner review row" => :project_owner_row,
  "duplicate conflicting project-owner review row" => :review_duplicates_conflicts,
  "Reviews table hidden in HTML comment" => :review_layout,
  "Reviews table hidden in fenced code" => :review_layout,
  "Reviews section hidden in type-one raw HTML" => :review_layout,
  "Reviews heading hidden in type-six raw HTML" => :review_layout,
  "Reviews heading hidden in type-seven raw HTML" => :review_layout,
  "Project-owner review row hidden in type-one raw HTML" => :project_owner_row
}.freeze
ADR_0009_EXPECTED_REVIEW_MUTATION_COUNT = 4
ADR_0009_EXPECTED_SEMANTIC_MUTATION_COUNT = 89
ADR_0009_EXPECTED_GOVERNANCE_MUTATION_COUNT = 33
ADR_0009_EXPECTED_MARKDOWN_CONTROLS = [
  "closed type-one raw HTML after protected sections",
  "closed type-six raw HTML after protected sections",
  "closed type-seven raw HTML after protected sections",
  "inline-code comment opener outside protected sections",
  "fenced HTML-like example outside protected sections",
  "closed HTML comment outside protected sections"
].freeze
ADR_0009_EXPECTED_MARKDOWN_CONTROL_COUNT = ADR_0009_EXPECTED_MARKDOWN_CONTROLS.length
ADR_0009_MARKDOWN_MAX_BYTES = 1_048_576
ADR_0009_MARKDOWN_MAX_LINES = 20_000
ADR_0009_MARKDOWN_MAX_LINE_CHARACTERS = 262_144

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

def adr_0009_markdown_mask_characters(source)
  source.gsub(/[^\r\n]/, " ")
end

def adr_0009_markdown_backtick_closers(source)
  source = source.b
  runs_by_length = Hash.new { |hash, length| hash[length] = [] }
  cursor = 0
  while cursor < source.length
    if source[cursor] == "`"
      run_end = cursor + 1
      run_end += 1 while run_end < source.length && source[run_end] == "`"
      runs_by_length[run_end - cursor] << cursor
      cursor = run_end
    else
      cursor += 1
    end
  end
  runs_by_length.each_value.each_with_object({}) do |positions, closers|
    positions.each_cons(2) { |opening, closing| closers[opening] = closing }
  end
end

def adr_0009_markdown_mask_inline_comments(source)
  original_encoding = source.encoding
  source = source.b
  closers = adr_0009_markdown_backtick_closers(source)
  masked = +""
  hidden = []
  cursor = 0
  unclosed = false
  while cursor < source.length
    if source[cursor] == "`" && closers[cursor]
      closing = closers.fetch(cursor)
      run_end = cursor + 1
      run_end += 1 while run_end < source.length && source[run_end] == "`"
      end_offset = closing + run_end - cursor
      masked << source[cursor...end_offset]
      cursor = end_offset
    elsif source[cursor, 4] == "<!--"
      comment_end = source.index("-->", cursor + 4)
      unless comment_end
        hidden << source[cursor..].dup.force_encoding(original_encoding)
        masked << adr_0009_markdown_mask_characters(source[cursor..])
        unclosed = true
        break
      end
      hidden_end = comment_end + 3
      hidden << source[cursor...hidden_end].dup.force_encoding(original_encoding)
      masked << adr_0009_markdown_mask_characters(source[cursor...hidden_end])
      cursor = hidden_end
    else
      masked << source[cursor]
      cursor += 1
    end
  end
  [masked.force_encoding(original_encoding), hidden, unclosed]
end

def adr_0009_markdown_html_block_descriptor(line, previous_blank:)
  body = line.delete_suffix("\n").delete_suffix("\r")
  type_one = body.match(/\A {0,3}<(script|pre|style|textarea)(?=[\t >]|\z)/i)
  if type_one
    tag = type_one[1].downcase
    return { terminator: %r{</#{Regexp.escape(tag)}[ \t\r\n]*>}i }
  end
  return { terminator: "-->" } if body.match?(/\A {0,3}<!--/)
  return { terminator: "?>" } if body.match?(/\A {0,3}<\?/)
  return { terminator: "]]>" } if body.match?(/\A {0,3}<!\[CDATA\[/)
  return { terminator: ">" } if body.match?(/\A {0,3}<![A-Z]/)

  block_html_tags = %w[
    address article aside base basefont blockquote body caption center col colgroup
    dd details dialog dir div dl dt fieldset figcaption figure footer form frame
    frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend li link main menu
    menuitem nav noframes ol optgroup option p param search section summary table
    tbody td tfoot th thead title tr track ul
  ].join("|")
  return { terminator: :blank } if body.match?(/\A {0,3}<\/?(?:#{block_html_tags})(?:[ \t\/>]|\z)/i)

  complete_tag = /\A {0,3}<\/?[A-Za-z][A-Za-z0-9-]*(?:[ \t]+[A-Za-z_:][A-Za-z0-9_.:-]*(?:[ \t]*=[ \t]*(?:"[^"]*"|'[^']*'|[^ \t\r\n"'=<>`]+))?)*[ \t]*\/?>[ \t]*\z/
  return { terminator: :blank } if previous_blank && body.match?(complete_tag)

  nil
end

def adr_0009_markdown_html_block_terminated?(source, descriptor)
  terminator = descriptor.fetch(:terminator)
  return false if terminator == :blank

  terminator.is_a?(Regexp) ? source.match?(terminator) : source.include?(terminator)
end

def markdown_visibility(source)
  empty = {
    raw_lines: [],
    visible_lines: [],
    hidden_text: "",
    unclosed_fence: false,
    unclosed_comment: false,
    resource_bounds_exceeded: true
  }
  return empty if source.bytesize > ADR_0009_MARKDOWN_MAX_BYTES

  line_count = source.count("\n") + (source.end_with?("\n") ? 0 : 1)
  return empty if line_count > ADR_0009_MARKDOWN_MAX_LINES
  return empty if source.each_line.any? { |line| line.length > ADR_0009_MARKDOWN_MAX_LINE_CHARACTERS }

  raw_lines = source.lines(chomp: true)
  structural = +""
  hidden_fragments = []
  lines = source.lines
  fence = nil
  previous_blank = true
  index = 0
  while index < lines.length
    line = lines[index]
    if fence
      hidden_fragments << line
      structural << adr_0009_markdown_mask_characters(line)
      delimiter = Regexp.escape(fence.fetch(:character))
      minimum_length = fence.fetch(:length)
      fence = nil if line.match?(/\A {0,3}#{delimiter}{#{minimum_length},}[ \t]*(?:\r?\n)?\z/)
      previous_blank = false
      index += 1
      next
    end

    opening = line.match(/\A {0,3}(`{3,}|~{3,})([^\r\n]*)(?:\r?\n)?\z/)
    if opening && !(opening[1].start_with?("`") && opening[2].include?("`"))
      marker = opening[1]
      fence = { character: marker[0], length: marker.length }
      hidden_fragments << line
      structural << adr_0009_markdown_mask_characters(line)
      previous_blank = false
      index += 1
      next
    end

    descriptor = adr_0009_markdown_html_block_descriptor(line, previous_blank: previous_blank)
    if descriptor
      raw = +""
      while index < lines.length
        candidate = lines[index]
        break if descriptor.fetch(:terminator) == :blank && candidate.strip.empty?

        raw << candidate
        structural << adr_0009_markdown_mask_characters(candidate)
        index += 1
        break if adr_0009_markdown_html_block_terminated?(raw, descriptor)
      end
      hidden_fragments << raw
      previous_blank = false
      next
    end

    if line.start_with?("    ", "\t")
      code = +""
      while index < lines.length && (lines[index].strip.empty? || lines[index].start_with?("    ", "\t"))
        candidate = lines[index]
        code << candidate
        structural << adr_0009_markdown_mask_characters(candidate)
        index += 1
      end
      hidden_fragments << code
      previous_blank = false
      next
    end

    structural << line
    previous_blank = line.strip.empty?
    index += 1
  end

  masked, hidden_comments, unclosed_comment = adr_0009_markdown_mask_inline_comments(structural)
  hidden_fragments.concat(hidden_comments)
  {
    raw_lines: raw_lines,
    visible_lines: masked.lines(chomp: true),
    hidden_text: hidden_fragments.join("\n"),
    unclosed_fence: !fence.nil?,
    unclosed_comment: unclosed_comment,
    resource_bounds_exceeded: false
  }
end

def visible_markdown_section(visibility:, heading:, next_heading:)
  visible_lines = visibility.fetch(:visible_lines)
  heading_indexes = visible_lines.each_index.select { |index| visible_lines[index] == heading }
  next_heading_indexes = visible_lines.each_index.select { |index| visible_lines[index] == next_heading }
  return nil unless heading_indexes.length == 1 && next_heading_indexes.length == 1

  heading_index = heading_indexes.first
  next_heading_index = next_heading_indexes.first
  return nil unless next_heading_index > heading_index

  intervening_h2_indexes = visible_lines.each_index.select do |index|
    index > heading_index && index <= next_heading_index && visible_lines[index].match?(/\A## [^#]/)
  end
  return nil unless intervening_h2_indexes == [next_heading_index]

  {
    heading_index: heading_index,
    next_heading_index: next_heading_index,
    lines: visible_lines[(heading_index + 1)...next_heading_index]
  }
end

def markdown_table_cells(line)
  return nil unless line.start_with?("|") && line.end_with?("|")

  cells = line.split("|", -1)[1...-1].map(&:strip)
  cells.length == 4 ? cells : nil
end

def adr_0009_semantic_predicate_failures(source)
  decision_predicates = ADR_0009_SEMANTIC_FRAGMENT_PREDICATES.keys |
                        ADR_0009_EXCLUDED_EFFECT_PREDICATES.keys |
                        [:effect_permit_exhaustive, :visible_decision_structure]
  failed = adr_0009_verification_predicate_failures(source)
  visibility = markdown_visibility(source)
  failed << :markdown_resource_bounds if visibility.fetch(:resource_bounds_exceeded)
  decision = visible_markdown_section(
    visibility: visibility,
    heading: "## Decision",
    next_heading: "## Consequences"
  )
  unless decision
    failed.merge(decision_predicates)
    return failed
  end

  if visibility.fetch(:unclosed_fence) || visibility.fetch(:unclosed_comment)
    failed << :visible_decision_structure
  end
  visible_body = decision.fetch(:lines).join("\n")

  ADR_0009_SEMANTIC_FRAGMENT_PREDICATES.each do |predicate, fragments|
    fragments.each do |fragment|
      count = visible_body.scan(Regexp.new(Regexp.escape(fragment))).length
      failed << predicate unless count == 1
    end
  end
  ADR_0009_SEMANTIC_FORBIDDEN_FRAGMENTS.each do |predicate, fragments|
    fragments.each do |fragment|
      failed << predicate unless visible_body.scan(Regexp.new(Regexp.escape(fragment))).empty?
    end
  end

  execute_lines = decision.fetch(:lines).select { |line| line.start_with?("2. **Execute:**") }
  if execute_lines.length != 1
    ADR_0009_EXCLUDED_EFFECT_PREDICATES.each_key { |predicate| failed << predicate }
    failed << :effect_permit_exhaustive
    failed << :effect_permit_sequence
    failed << :read_scope_not_effect_authority
  else
    execute_line = execute_lines.first
    effect_list_match = execute_line.match(
      /Immediately before each (.+?), freshly authorize that exact effect,/
    )
    if effect_list_match
      actual_effects = effect_list_match[1].sub(/, or /, ", ").split(", ")
      expected_effects = ADR_0009_EXCLUDED_EFFECT_PREDICATES.values
      failed << :effect_permit_exhaustive unless actual_effects == expected_effects
      ADR_0009_EXCLUDED_EFFECT_PREDICATES.each do |predicate, category|
        failed << predicate unless actual_effects.count(category) == 1
      end
    else
      ADR_0009_EXCLUDED_EFFECT_PREDICATES.each_key { |predicate| failed << predicate }
      failed << :effect_permit_exhaustive
    end
  end

  failed
end

def adr_0009_verification_predicate_failures(source)
  visibility = markdown_visibility(source)
  visible_lines = visibility.fetch(:visible_lines)
  hidden_text = visibility.fetch(:hidden_text)
  failed = Set.new
  failed << :markdown_resource_bounds if visibility.fetch(:resource_bounds_exceeded)
  verification = visible_markdown_section(
    visibility: visibility,
    heading: "## Verification",
    next_heading: "## Rollout and supersession"
  )
  unless verification
    failed << :verification_structure
    failed.merge(ADR_0009_EXPECTED_CRITICAL_VERIFICATION_ROWS.keys)
    return failed
  end

  heading_index = verification.fetch(:heading_index)
  header_index = heading_index + 4
  separator_index = heading_index + 5
  first_row_index = heading_index + 6
  table_rows = []
  index = first_row_index
  while index < verification.fetch(:next_heading_index) && !visible_lines[index].empty?
    table_rows << [index, visible_lines[index]]
    index += 1
  end
  layout_valid =
    visible_lines[heading_index + 1] == "" &&
    visible_lines[heading_index + 2] == "Decision acceptance names future implementation obligations; it does not claim they already pass." &&
    visible_lines[heading_index + 3] == "" &&
    visible_lines[header_index] == "| Test ID | Required evidence |" &&
    visible_lines[separator_index] == "|---|---|" &&
    table_rows.length == 10 &&
    table_rows.all? { |_row_index, row| row.start_with?("|") && row.end_with?("|") && row.split("|", -1)[1...-1].length == 2 }
  failed << :verification_structure unless layout_valid

  ADR_0009_EXPECTED_CRITICAL_VERIFICATION_ROWS.each do |predicate, expected_row|
    test_id = expected_row[/`(T-ADR-0009-[A-Z0-9-]+)`/, 1]
    matching_rows = table_rows.select { |_row_index, row| row.include?("`#{test_id}`") }
    visible_occurrences = visible_lines.each_index.select { |line_index| visible_lines[line_index].include?("`#{test_id}`") }
    unless matching_rows.length == 1 &&
           matching_rows.first.last == expected_row &&
           visible_occurrences == [matching_rows.first.first] &&
           !hidden_text.include?("`#{test_id}`")
      failed << predicate
    end
  end

  failed
end

def adr_0009_semantic_contract_failures(source)
  adr_0009_semantic_predicate_failures(source).to_a.sort.map do |predicate|
    "ADR-0009 independent semantic predicate failed: #{predicate}"
  end
end

def adr_0009_document_governance_predicate_failures(source)
  visibility = markdown_visibility(source)
  raw_lines = visibility.fetch(:raw_lines)
  visible_lines = visibility.fetch(:visible_lines)
  hidden_text = visibility.fetch(:hidden_text)
  failed = Set.new
  failed << :markdown_resource_bounds if visibility.fetch(:resource_bounds_exceeded)

  unless source.valid_encoding? && source.end_with?("\n") &&
         !source.start_with?("\uFEFF") && !source.include?("\r") && !source.include?("\0")
    failed << :canonical_markdown_bytes
  end
  if visibility.fetch(:unclosed_fence) || visibility.fetch(:unclosed_comment)
    failed << :markdown_visibility
  end

  metadata_lines = raw_lines[2, ADR_0009_METADATA_KEY_ORDER.length] || []
  metadata_keys = metadata_lines.map { |line| line[/\A- \*\*([^*]+):\*\*\s*/, 1] }
  metadata_shape_valid =
    raw_lines[0] == "# ADR-0009: Gitea provider reconciliation precedence and conflict handling" &&
    raw_lines[1] == "" &&
    metadata_lines.length == ADR_0009_METADATA_KEY_ORDER.length &&
    metadata_keys == ADR_0009_METADATA_KEY_ORDER &&
    raw_lines[2 + ADR_0009_METADATA_KEY_ORDER.length] == "" &&
    raw_lines[3 + ADR_0009_METADATA_KEY_ORDER.length] == "## Context and decision scope" &&
    metadata_lines.each_with_index.all? { |line, offset| visible_lines[2 + offset] == line }
  failed << :metadata_layout unless metadata_shape_valid

  owner_index = 2 + ADR_0009_METADATA_KEY_ORDER.index("Project-owner approval required")
  supersession_index = 2 + ADR_0009_METADATA_KEY_ORDER.index("Supersedes / superseded by")
  status_index = 2 + ADR_0009_METADATA_KEY_ORDER.index("Status")
  failed << :metadata_status_proposed unless raw_lines[status_index] == "- **Status:** Proposed"
  failed << :metadata_owner_required unless raw_lines[owner_index] == ADR_0009_OWNER_APPROVAL_LINE
  failed << :metadata_supersession_narrow unless raw_lines[supersession_index] == ADR_0009_SUPERSESSION_LINE

  visible_metadata_rows = visible_lines.each_with_index.filter_map do |line, index|
    match = line.match(/\A- \*\*([^*]+):\*\*\s*/)
    [match[1], index] if match && ADR_0009_METADATA_KEY_ORDER.include?(match[1])
  end
  metadata_occurrences = visible_metadata_rows.group_by(&:first)
  metadata_duplicates_or_misplacements = ADR_0009_METADATA_KEY_ORDER.any? do |key|
    expected_index = 2 + ADR_0009_METADATA_KEY_ORDER.index(key)
    Array(metadata_occurrences[key]).map(&:last) != [expected_index]
  end
  failed << :metadata_duplicates_conflicts if metadata_duplicates_or_misplacements

  if ADR_0009_HIDDEN_GOVERNANCE_MARKERS.any? { |marker| hidden_text.include?(marker) }
    failed << :hidden_governance_substitution
  end

  review_heading_indexes = visible_lines.each_index.select do |index|
    visible_lines[index] == "## Reviews and approvals"
  end
  if review_heading_indexes.length != 1
    failed << :review_layout
    failed << :exact_sha_approval_placement
    failed << :review_rows
    failed << :project_owner_row
    failed << :review_duplicates_conflicts
    return failed
  end

  heading_index = review_heading_indexes.first
  paragraph_index = heading_index + 2
  table_header_index = heading_index + 4
  table_separator_index = heading_index + 5
  first_row_index = heading_index + 6
  expected_row_indexes = (first_row_index...(first_row_index + ADR_0009_EXPECTED_REVIEW_ROWS.length)).to_a
  review_layout_valid =
    raw_lines[heading_index] == "## Reviews and approvals" &&
    raw_lines[heading_index + 1] == "" &&
    raw_lines[paragraph_index] == ADR_0009_APPROVAL_PARAGRAPH &&
    visible_lines[paragraph_index] == ADR_0009_APPROVAL_PARAGRAPH &&
    raw_lines[heading_index + 3] == "" &&
    raw_lines[table_header_index] == ADR_0009_REVIEW_TABLE_HEADER &&
    raw_lines[table_separator_index] == ADR_0009_REVIEW_TABLE_SEPARATOR &&
    raw_lines[first_row_index + ADR_0009_EXPECTED_REVIEW_ROWS.length] == ""
  failed << :review_layout unless review_layout_valid

  visible_sha_indexes = visible_lines.each_index.select do |index|
    visible_lines[index].include?(ADR_0009_EXACT_SHA_APPROVAL_SENTENCE)
  end
  unless visible_sha_indexes == [paragraph_index] &&
         raw_lines[paragraph_index] == ADR_0009_APPROVAL_PARAGRAPH
    failed << :exact_sha_approval_placement
  end

  actual_review_rows = expected_row_indexes.map { |index| raw_lines[index] }
  failed << :review_rows unless actual_review_rows == ADR_0009_EXPECTED_REVIEW_ROWS

  project_owner_indexes = visible_lines.each_index.select do |index|
    cells = markdown_table_cells(visible_lines[index])
    cells && cells.first == "Project owner"
  end
  expected_project_owner_index = expected_row_indexes.last
  unless project_owner_indexes == [expected_project_owner_index] &&
         raw_lines[expected_project_owner_index] == ADR_0009_PROJECT_OWNER_REVIEW_LINE
    failed << :project_owner_row
  end

  expected_roles = ADR_0009_EXPECTED_REVIEW_ROWS.map { |row| markdown_table_cells(row).first }
  visible_review_role_rows = visible_lines.each_with_index.filter_map do |line, index|
    cells = markdown_table_cells(line)
    [cells.first, index] if cells && expected_roles.include?(cells.first)
  end
  actual_roles = expected_row_indexes.filter_map do |index|
    markdown_table_cells(visible_lines[index])&.first
  end
  unless actual_roles == expected_roles &&
         actual_roles.uniq.length == expected_roles.length &&
         visible_review_role_rows.map(&:last) == expected_row_indexes
    failed << :review_duplicates_conflicts
  end

  combined_role = visible_lines.any? do |line|
    cells = markdown_table_cells(line)
    role = cells&.first.to_s
    role.match?(/independent/i) && role.match?(/\bqa\b/i) && role.match?(/security/i)
  end
  failed << :review_duplicates_conflicts if combined_role

  failed
end

def adr_0009_review_structure_failures(source)
  review_predicates = Set[
    :canonical_markdown_bytes,
    :markdown_resource_bounds,
    :markdown_visibility,
    :hidden_governance_substitution,
    :review_layout,
    :exact_sha_approval_placement,
    :review_rows,
    :project_owner_row,
    :review_duplicates_conflicts
  ]
  failures = adr_0009_document_governance_predicate_failures(source) & review_predicates
  failures.to_a.sort.map { |predicate| "ADR-0009 review structure predicate failed: #{predicate}" }
end

def adr_0009_decision_body_failures(source)
  failures = []
  decision_matches = source.to_enum(:scan, /^## Decision\n/).map { Regexp.last_match }
  consequence_matches = source.to_enum(:scan, /^## Consequences\n/).map { Regexp.last_match }
  if decision_matches.length != 1 || consequence_matches.length != 1
    failures << "ADR-0009 raw Decision and Consequences headings must each occur exactly once"
    return failures
  end

  decision_match = decision_matches.first
  consequence_match = consequence_matches.first
  if consequence_match.begin(0) <= decision_match.end(0)
    failures << "ADR-0009 raw Decision body must precede Consequences"
    return failures
  end

  first_h2 = source.match(/^## ([^#\n][^\n]*)\n/, decision_match.end(0))
  unless first_h2&.begin(0) == consequence_match.begin(0)
    failures << "ADR-0009 Consequences must be the next raw level-two section after Decision"
  end

  body = source.byteslice(decision_match.end(0), consequence_match.begin(0) - decision_match.end(0))
  actual = Digest::SHA256.hexdigest(body)
  unless actual == ADR_0009_DECISION_BODY_SHA256
    failures << "ADR-0009 Decision body must match closed semantic digest #{ADR_0009_DECISION_BODY_SHA256}, found #{actual}"
  end
  failures
end

def adr_0009_governance_predicate_failures(source:, gate:, gate_count:)
  failed = adr_0009_document_governance_predicate_failures(source)
  failed << :catalog_gate_unique unless gate_count == 1
  if gate.nil?
    failed.merge(%i[catalog_proposed catalog_owner_gate catalog_no_acceptance catalog_decision_record])
    return failed
  end

  failed << :catalog_proposed unless gate["state"] == "PROPOSED"
  failed << :catalog_owner_gate unless gate["project_owner_approval_required"] == true
  failed << :catalog_decision_record unless gate["decision_record"] ==
                                                "docs/adr/0009-gitea-provider-reconciliation-precedence-and-conflict-handling.md"
  acceptance_fields = %w[immutable_revision accepted_at approval_record approval_records]
  present_acceptance_fields = acceptance_fields.select { |field| gate.key?(field) }
  failed << :catalog_no_acceptance unless present_acceptance_fields.empty?

  failed
end

def adr_0009_governance_gate_failures(source:, gate:, gate_count:)
  adr_0009_governance_predicate_failures(
    source: source,
    gate: gate,
    gate_count: gate_count
  ).to_a.sort.map do |predicate|
    "ADR-0009 governance predicate failed: #{predicate}"
  end
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
adr_gate_records = issue_catalog.fetch("adr_decision_gates")
adr_0009_gate_records = adr_gate_records.select { |gate| gate["adr_id"] == "ADR-CAND-008" }
adr_gates = adr_gate_records.to_h { |gate| [gate.fetch("adr_id"), gate] }
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
adr_0009_review_mutation_survivors = []
adr_0009_review_mutation_count = 0
adr_0009_security_mutation_survivors = []
adr_0009_security_mutation_count = 0
adr_0009_governance_mutation_survivors = []
adr_0009_governance_mutation_count = 0
adr_0009_markdown_control_failures = []
adr_0009_markdown_control_count = 0

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

  if number == "0009"
    failures.concat(adr_0009_decision_body_failures(source))
    failures.concat(adr_0009_semantic_contract_failures(source))
    adr_0009_gate = adr_gates["ADR-CAND-008"]
    failures.concat(
      adr_0009_governance_gate_failures(
        source: source,
        gate: adr_0009_gate,
        gate_count: adr_0009_gate_records.length
      )
    )
    qa_line = source.lines.find { |line| line.start_with?("| Independent QA and C-QA traceability owner (distinct WS-13 identity) |") }
    security_line = source.lines.find { |line| line.start_with?("| Independent security (distinct WS-13 identity) |") }
    if qa_line && security_line
      combined_line = "| Independent QA/security (WS-13) | pending distinct reviewer | pending | pending |\n"
      review_mutations = {
        "missing independent QA row" => { source: source.sub(qa_line, ""), predicate: :review_rows },
        "missing independent security row" => { source: source.sub(security_line, ""), predicate: :review_rows },
        "combined QA/security row" => {
          source: source.sub(qa_line, combined_line).sub(security_line, ""),
          predicate: :review_duplicates_conflicts
        },
        "duplicate independent QA row" => {
          source: source.sub(qa_line, qa_line * 2),
          predicate: :review_duplicates_conflicts
        }
      }
      actual_review_inventory = review_mutations.transform_values { |mutation| mutation.fetch(:predicate) }
      unless actual_review_inventory == ADR_0009_EXPECTED_REVIEW_MUTATIONS
        failures << "ADR-0009 review-separation mutation inventory/mapping differs from the pinned inventory"
      end
      unless review_mutations.values.map { |mutation| mutation.fetch(:source) }.uniq.length == review_mutations.length
        failures << "ADR-0009 review-separation mutations must have unique source payloads"
      end
      review_mutations.each do |label, mutation|
        adr_0009_review_mutation_count += 1
        mutated_source = mutation.fetch(:source)
        expected_predicate = mutation.fetch(:predicate)
        mutation_failures = adr_0009_document_governance_predicate_failures(mutated_source)
        if mutated_source == source || !mutation_failures.include?(expected_predicate)
          adr_0009_review_mutation_survivors <<
            "#{label} (expected #{expected_predicate}; got #{mutation_failures.to_a.sort.join(', ')})"
        end
      end
    end

    # Each mutant names and must trigger its own source-level predicate. The
    # whole-Decision digest is intentionally absent from this mutation oracle.
    semantic_mutation_specs = [
      ["scope ID uniqueness removed", :scope_id, "unique, nontransferable `scope_id`", "reusable `scope_id`"],
      ["logical-operation ID binding removed", :logical_operation_id, "`scope_id` and `logical_operation_id` and binding", "`scope_id` and binding"],
      ["scope transfer and reuse admitted", :scope_nontransferable, "The scope cannot be renewed, transferred, output-widened, or reused across a logical operation, `ReconciliationGeneration`, provider installation, `ProviderResourceKey`, resource, security domain, or compatibility profile.", "The scope may be transferred and reused across operations, generations, installations, resources, domains, and profiles."],
      ["scope renewal admitted", :scope_nontransferable, "cannot be renewed, transferred", "may be renewed but cannot be transferred"],
      ["scope output widening admitted", :scope_nontransferable, "transferred, output-widened, or reused", "transferred or reused"],
      ["logical-operation reuse admitted", :scope_nontransferable, "reused across a logical operation, `ReconciliationGeneration`", "reused across `ReconciliationGeneration`"],
      ["cross-generation reuse admitted", :scope_nontransferable, "`ReconciliationGeneration`, provider installation", "provider installation"],
      ["cross-installation reuse admitted", :scope_nontransferable, "provider installation, `ProviderResourceKey`", "`ProviderResourceKey`"],
      ["acting principal binding removed", :acting_principal, "binding the acting service principal, exact initiating principal", "binding the exact initiating principal"],
      ["initiating principal binding removed", :initiating_principal, "exact initiating principal (including an explicit system initiator for scheduled work)", "an optional initiating-principal hint"],
      ["organization binding removed", :organization, "Organization, security domain", "security domain"],
      ["security-domain binding removed", :security_domain, "security domain, exact canonical container", "exact canonical container"],
      ["canonical container/resource binding removed", :canonical_container_resource, "exact canonical container and closed resource set", "unscoped resource set"],
      ["provider installation binding removed", :provider_installation, "exact provider installation UUID", "provider type"],
      ["provider path binding removed", :provider_path, "provider installation UUID and API path", "provider installation UUID"],
      ["provider resource-key binding removed", :provider_resource_key, "API path plus `ProviderResourceKey`", "API path"],
      ["reconciliation-generation binding removed", :reconciliation_generation, "`ProviderResourceKey`, `ReconciliationGeneration`", "`ProviderResourceKey`"],
      ["operation-class binding removed", :operation_class, "`ReconciliationGeneration`, one allowed operation class", "`ReconciliationGeneration`"],
      ["closed call-plan binding removed", :closed_call_plan, "one allowed operation class and closed call plan", "one allowed operation class and dynamic call plan"],
      ["activation/vector definition binding removed", :activation_vector_definition, "the complete immutable ADR-0005 activation snapshot and consistency vector, durable monotonic dispatch/page ordinals", "an incomplete activation snapshot, durable monotonic dispatch/page ordinals"],
      ["activation/vector earliest-expiry binding removed", :activation_vector_expiry, "earliest bound temporal input in the complete ADR-0005 activation snapshot and consistency vector or the original logical-operation deadline", "worker-selected expiry input"],
      ["activation/vector revalidation summary removed", :activation_vector_revalidation_summary, "operation class/call plan, complete activation snapshot and consistency vector, compatibility profile, ordinals/counters, deadline, and earliest-bound expiry", "operation class/call plan and compatibility profile"],
      ["activation/vector persistence binding removed", :activation_vector_persistence, "persist its immutable identity, complete ADR-0005 activation snapshot and consistency vector, fixed deadline/expiry, cumulative accounting", "persist its immutable identity and fixed deadline/expiry"],
      ["activation/vector pre-call binding removed", :activation_vector_pre_call, "Revalidate every component of the complete activation snapshot and consistency vector, including the latest provider-enforcement and resource fences", "Revalidate only the scope identity"],
      ["activation/vector pre-commit binding removed", :activation_vector_pre_commit, "compare the complete activation snapshot, consistency vector, exact installation/path/resource key", "compare the exact installation/path/resource key"],
      ["attempt accounting dimension removed", :accounting_attempt, "reserved and actual attempt/call/page/item/byte counts", "reserved and actual call/page/item/byte counts"],
      ["call accounting dimension removed", :accounting_call, "cumulative call/page/item/response-byte accounting", "cumulative page/item/response-byte accounting"],
      ["page accounting dimension removed", :accounting_page, "durable monotonic dispatch/page ordinals", "durable monotonic dispatch ordinals"],
      ["item accounting dimension removed", :accounting_item, "page/item/response-byte accounting", "page/response-byte accounting"],
      ["byte accounting dimension removed", :accounting_byte, "item/response-byte accounting", "item accounting"],
      ["crash persistence guarantee removed", :accounting_crash_persistence, "Crash/resume never rolls back, resets, or narrows those cumulative counters to manufacture more budget.", "Crash/resume may reset counters and manufacture a fresh budget."],
      ["compatibility-profile binding removed", :compatibility_profile, "the exact compatibility-profile ID/version/schema digest", "a provider-family profile"],
      ["original-deadline binding removed", :original_deadline, "the original deadline, and immutable expiry", "an immutable expiry"],
      ["earliest-bound expiry removed", :earliest_expiry, "Its expiry is fixed at creation to no later than the earliest bound temporal input", "Its expiry is selected by the worker after creation"],
      ["provider-output widening admitted", :provider_output_no_widen, "Provider output may supply only a cursor admitted by those rules; it cannot add an endpoint, method, resource, operation class, retry, result field, or budget.", "Provider output may add endpoints, methods, resources, operation classes, retries, result fields, and budget."],
      ["pre-call revalidation removed", :pre_call_revalidation, "Immediately before every provider call and immediately before every local outcome commit", "At scope creation and immediately before every local outcome commit"],
      ["pre-commit revalidation removed", :pre_commit_revalidation, "Immediately before every provider call and immediately before every local outcome commit", "Immediately before every provider call and only after every local outcome commit"],
      ["latest provider-enforcement fence removed", :latest_provider_fence, "including the latest provider-enforcement and resource fences, immediately before dispatch", "including the latest resource fences, immediately before dispatch"],
      ["latest resource fence removed", :latest_resource_fence, "including the latest provider-enforcement and resource fences, immediately before dispatch", "including the latest provider-enforcement fence, immediately before dispatch"],
      ["latest effect fence removed", :effect_latest_fences, "revalidate the complete scope/temporal state plus the latest fences", "reuse the fences captured at scope creation"],
      ["later actor authorizes combined snapshot", :actor_isolation, "one actor can never authorize a combined snapshot", "the latest actor may authorize the combined snapshot"],
      ["causal proof made optional", :causal_proof, "A complete contiguous proof chain must connect the last confirmed token to the freshly read token.", "A current readable snapshot makes the causal proof optional."],
      ["administrator impersonation ignored", :impersonation_chain, "binds the effective actor and every administrator/Sudo impersonator", "binds only the displayed sender"],
      ["administrator laundering admitted", :actor_laundering, "administrator-laundered", "administrator-approved"],
      ["create adopted without operation identity", :operation_bound_create_identity, "Exactly one candidate carrying that verified operation-bound key may be adopted.", "Exactly one content-matching candidate may be adopted."],
      ["before snapshot treated as no-effect proof", :before_state_not_terminal, "a current before, intended-after, absent, or recreated snapshot is never by itself terminal proof", "a current before snapshot proves no effect"],
      ["apply-revert ABA admitted", :aba_not_terminal, "Without such proof, snapshot comparison guides containment only; the original permit remains `reconciling`", "Without such proof, an apply-revert snapshot may terminalize the permit"],
      ["fresh effect-permit sequence removed", :effect_permit_sequence, "freshly authorize that exact effect, commit its own durable one-use `AuthorizationEffectPermit`", "invoke that effect under the read scope"],
      ["read scope authorizes retained effect", :read_scope_not_effect_authority, "the read scope can neither authorize nor substitute for them", "the read scope may authorize them"],
      ["provider mutation permit removed", :effect_permit_provider_mutation, "each provider mutation, credential issuance", "each credential issuance"],
      ["credential permit removed", :effect_permit_credential, "provider mutation, credential issuance, direct Git/protocol access", "provider mutation, direct Git/protocol access"],
      ["direct protocol permit removed", :effect_permit_direct_protocol, "credential issuance, direct Git/protocol access, export/download", "credential issuance, export/download"],
      ["export/download permit removed", :effect_permit_export_download, "direct Git/protocol access, export/download, non-idempotent call", "direct Git/protocol access, non-idempotent call"],
      ["non-idempotent permit removed", :effect_permit_non_idempotent, "export/download, non-idempotent call, ambiguous external effect", "export/download, ambiguous external effect"],
      ["ambiguous-effect permit removed", :effect_permit_ambiguous, "non-idempotent call, ambiguous external effect, or operation", "non-idempotent call, or operation"],
      ["outliving-operation permit removed", :effect_permit_outliving, "ambiguous external effect, or operation that can outlive the logical request/job", "ambiguous external effect"],
      ["excluded-effect list widened", :effect_permit_exhaustive, "provider mutation, credential issuance", "provider mutation, plugin-defined external effect, credential issuance"],
      ["final fresh effective-principal authorization removed", :effective_principal_fresh_decision, "run the required fresh decision for the effective initiating/provider principal and exact delta", "reuse the decision captured before provider I/O"],
      ["final transaction fence removed", :final_transaction_fence, "then compare final activation, authorization, provider-enforcement, resource, and operation revisions inside the owning transaction", "then commit without another revision comparison"],
      ["ambiguous-mutation verification weakened", :ambiguous_mutation_verification, ADR_0009_EXPECTED_CRITICAL_VERIFICATION_ROWS.fetch(:ambiguous_mutation_verification), "| `T-ADR-0009-AMBIGUOUS-MUTATION` | One happy-path ambiguous mutation test passes. |"],
      ["full-reconciliation verification weakened", :full_reconciliation_verification, ADR_0009_EXPECTED_CRITICAL_VERIFICATION_ROWS.fetch(:full_reconciliation_verification), "| `T-ADR-0009-FULL-RECONCILIATION` | One happy-path full reconciliation test passes. |"]
    ]
    security_mutations = semantic_mutation_specs.to_h do |label, predicate, target, replacement|
      [label, { source: source.sub(target, replacement), predicate: predicate }]
    end
    security_mutations["Decision hidden in HTML comment"] = {
      source: source.sub("## Decision\n", "<!--\n## Decision\n").sub("## Consequences\n", "## Consequences\n-->\n"),
      predicate: :visible_decision_structure
    }
    security_mutations["Decision hidden in fenced code"] = {
      source: source.sub("## Decision\n", "```text\n## Decision\n").sub("## Consequences\n", "## Consequences\n```\n"),
      predicate: :visible_decision_structure
    }
    security_mutations["Decision hidden in type-one raw HTML"] = {
      source: source.sub("## Decision\n", "<pre\n>\n## Decision\n").sub("## Consequences\n", "## Consequences\n</pre>\n"),
      predicate: :visible_decision_structure
    }
    security_mutations["Decision hidden in processing-instruction raw HTML"] = {
      source: source.sub("## Decision\n", "<?stead\n## Decision\n").sub("## Consequences\n", "## Consequences\n?>\n"),
      predicate: :visible_decision_structure
    }
    security_mutations["Decision hidden in declaration raw HTML"] = {
      source: source.sub("## Decision\n", "<!STEAD\n## Decision\n").sub("## Consequences\n", "## Consequences\n>\n"),
      predicate: :visible_decision_structure
    }
    security_mutations["Decision hidden in CDATA raw HTML"] = {
      source: source.sub("## Decision\n", "<![CDATA[\n## Decision\n").sub("## Consequences\n", "## Consequences\n]]>\n"),
      predicate: :visible_decision_structure
    }
    security_mutations["Decision heading hidden in type-six raw HTML"] = {
      source: source.sub("## Decision\n", "<div>\n## Decision\n") + "</div>\n",
      predicate: :visible_decision_structure
    }
    security_mutations["Decision heading hidden in type-seven raw HTML"] = {
      source: source.sub("## Decision\n", "<stead-contract>\n## Decision\n") + "</stead-contract>\n",
      predicate: :visible_decision_structure
    }
    security_mutations["Verification hidden in type-one raw HTML"] = {
      source: source.sub("## Verification\n", "<pre\n>\n## Verification\n").sub(
        "## Rollout and supersession\n",
        "## Rollout and supersession\n</pre>\n"
      ),
      predicate: :verification_structure
    }
    security_mutations["Markdown byte bound exceeded"] = {
      source: source + ("x" * (ADR_0009_MARKDOWN_MAX_BYTES - source.bytesize + 1)),
      predicate: :markdown_resource_bounds
    }
    security_mutations["Markdown line-count bound exceeded"] = {
      source: source + ("\n" * (ADR_0009_MARKDOWN_MAX_LINES + 1)),
      predicate: :markdown_resource_bounds
    }
    security_mutations["Markdown line-length bound exceeded"] = {
      source: source + ("x" * (ADR_0009_MARKDOWN_MAX_LINE_CHARACTERS + 1)) + "\n",
      predicate: :markdown_resource_bounds
    }
    ADR_0009_SEMANTIC_FORBIDDEN_FRAGMENTS.each do |predicate, fragments|
      label = {
        scope_nontransferable: "contradictory scope reuse appended",
        acting_principal: "contradictory acting-principal omission appended",
        initiating_principal: "contradictory initiating-principal omission appended",
        accounting_crash_persistence: "contradictory crash reset appended",
        earliest_expiry: "contradictory expiry extension appended",
        provider_output_no_widen: "contradictory provider widening appended",
        actor_isolation: "contradictory combined-actor authorization appended",
        causal_proof: "contradictory optional causal proof appended",
        impersonation_chain: "contradictory impersonation bypass appended",
        actor_laundering: "contradictory actor laundering appended",
        operation_bound_create_identity: "contradictory content-only create identity appended",
        before_state_not_terminal: "contradictory before-state terminalization appended",
        aba_not_terminal: "contradictory ABA terminalization appended",
        read_scope_not_effect_authority: "contradictory read-scope effect authority appended",
        effective_principal_fresh_decision: "contradictory final fresh authorization bypass appended",
        final_transaction_fence: "contradictory final-fence bypass appended"
      }.fetch(predicate)
      security_mutations[label] = {
        source: source.sub("## Decision\n\n", "## Decision\n\n#{fragments.first}.\n\n"),
        predicate: predicate
      }
    end
    actual_semantic_inventory = security_mutations.transform_values { |mutation| mutation.fetch(:predicate) }
    unless actual_semantic_inventory == ADR_0009_EXPECTED_SEMANTIC_MUTATIONS
      failures << "ADR-0009 semantic-security mutation inventory/mapping differs from the pinned inventory"
    end
    unless security_mutations.values.map { |mutation| mutation.fetch(:source) }.uniq.length == security_mutations.length
      failures << "ADR-0009 semantic-security mutations must have unique source payloads"
    end
    security_mutations.each do |label, mutation|
      adr_0009_security_mutation_count += 1
      mutated_source = mutation.fetch(:source)
      expected_predicate = mutation.fetch(:predicate)
      mutation_failures = adr_0009_semantic_predicate_failures(mutated_source)
      if mutated_source == source || !mutation_failures.include?(expected_predicate)
        adr_0009_security_mutation_survivors <<
          "#{label} (expected #{expected_predicate}; got #{mutation_failures.to_a.sort.join(', ')})"
      end
    end

    if adr_0009_gate
      weakened_owner_line = "- **Project-owner approval required:** no"
      weakened_supersession_line = "- **Supersedes / superseded by:** on acceptance supersedes ADR-0005, CLS-007, and ADR-0007 in full"
      weakened_approval_paragraph = "This proposal may be accepted by approval of the pull request or current branch head."
      weakened_project_owner_row = "| Project owner | same author | approved | no immutable revision required |"
      review_table = ([ADR_0009_REVIEW_TABLE_HEADER, ADR_0009_REVIEW_TABLE_SEPARATOR] +
                      ADR_0009_EXPECTED_REVIEW_ROWS).join("\n")
      weakened_review_table = [
        ADR_0009_REVIEW_TABLE_HEADER,
        ADR_0009_REVIEW_TABLE_SEPARATOR,
        weakened_project_owner_row
      ].join("\n")
      hidden_governance_controls = [
        ADR_0009_OWNER_APPROVAL_LINE,
        ADR_0009_SUPERSESSION_LINE,
        ADR_0009_APPROVAL_PARAGRAPH,
        ADR_0009_PROJECT_OWNER_REVIEW_LINE
      ].join("\n")
      weakened_composite = source
        .sub(ADR_0009_OWNER_APPROVAL_LINE, weakened_owner_line)
        .sub(ADR_0009_SUPERSESSION_LINE, weakened_supersession_line)
        .sub(ADR_0009_APPROVAL_PARAGRAPH, weakened_approval_paragraph)
        .sub(ADR_0009_PROJECT_OWNER_REVIEW_LINE, weakened_project_owner_row)
      comment_hidden_composite = weakened_composite.sub(
        "\n\n- **Status:**",
        "\n\n<!--\n#{hidden_governance_controls}\n-->\n- **Status:**"
      )
      fence_hidden_composite = weakened_composite.sub(
        "\n\n- **Status:**",
        "\n\n~~~text\n#{hidden_governance_controls}\n~~~\n- **Status:**"
      )
      governance_mutations = {
        "supersession removed" => {
          source: source.sub(
            ADR_0009_SUPERSESSION_LINE,
            "- **Supersedes / superseded by:** supersedes no accepted decision"
          ),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :metadata_supersession_narrow
        },
        "supersession broadened beyond read-plan granularity" => {
          source: source.sub(ADR_0009_SUPERSESSION_LINE, weakened_supersession_line),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :metadata_supersession_narrow
        },
        "project-owner metadata weakened" => {
          source: source.sub(ADR_0009_OWNER_APPROVAL_LINE, weakened_owner_line),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :metadata_owner_required
        },
        "project-owner review row weakened" => {
          source: source.sub(ADR_0009_PROJECT_OWNER_REVIEW_LINE, weakened_project_owner_row),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :project_owner_row
        },
        "immutable-SHA approval weakened" => {
          source: source.sub(ADR_0009_APPROVAL_PARAGRAPH, weakened_approval_paragraph),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :exact_sha_approval_placement
        },
        "catalog project-owner gate weakened" => {
          source: source,
          gate: adr_0009_gate.merge("project_owner_approval_required" => false),
          gate_count: 1,
          predicate: :catalog_owner_gate
        },
        "catalog state changed to accepted" => {
          source: source,
          gate: adr_0009_gate.merge("state" => "ACCEPTED"),
          gate_count: 1,
          predicate: :catalog_proposed
        },
        "catalog acceptance record fabricated" => {
          source: source,
          gate: adr_0009_gate.merge("immutable_revision" => "deadbeef"),
          gate_count: 1,
          predicate: :catalog_no_acceptance
        },
        "catalog decision record redirected" => {
          source: source,
          gate: adr_0009_gate.merge("decision_record" => "docs/adr/accepted-elsewhere.md"),
          gate_count: 1,
          predicate: :catalog_decision_record
        },
        "catalog ADR-CAND-008 gate duplicated" => {
          source: source,
          gate: adr_0009_gate,
          gate_count: 2,
          predicate: :catalog_gate_unique
        },
        "comment-hidden composite with visible contradictions" => {
          source: comment_hidden_composite,
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :hidden_governance_substitution
        },
        "fence-hidden composite with visible contradictions" => {
          source: fence_hidden_composite,
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :hidden_governance_substitution
        },
        "comment-hidden owner line with visible contradiction" => {
          source: source.sub(ADR_0009_OWNER_APPROVAL_LINE, "<!--\n#{ADR_0009_OWNER_APPROVAL_LINE}\n-->\n#{weakened_owner_line}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :hidden_governance_substitution
        },
        "fence-hidden owner line with visible contradiction" => {
          source: source.sub(ADR_0009_OWNER_APPROVAL_LINE, "~~~text\n#{ADR_0009_OWNER_APPROVAL_LINE}\n~~~\n#{weakened_owner_line}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :hidden_governance_substitution
        },
        "comment-hidden supersession with visible contradiction" => {
          source: source.sub(ADR_0009_SUPERSESSION_LINE, "<!--\n#{ADR_0009_SUPERSESSION_LINE}\n-->\n#{weakened_supersession_line}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :hidden_governance_substitution
        },
        "fence-hidden supersession with visible contradiction" => {
          source: source.sub(ADR_0009_SUPERSESSION_LINE, "~~~text\n#{ADR_0009_SUPERSESSION_LINE}\n~~~\n#{weakened_supersession_line}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :hidden_governance_substitution
        },
        "comment-hidden immutable-SHA paragraph with visible contradiction" => {
          source: source.sub(ADR_0009_APPROVAL_PARAGRAPH, "<!--\n#{ADR_0009_APPROVAL_PARAGRAPH}\n-->\n#{weakened_approval_paragraph}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :hidden_governance_substitution
        },
        "fence-hidden immutable-SHA paragraph with visible contradiction" => {
          source: source.sub(ADR_0009_APPROVAL_PARAGRAPH, "~~~text\n#{ADR_0009_APPROVAL_PARAGRAPH}\n~~~\n#{weakened_approval_paragraph}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :hidden_governance_substitution
        },
        "comment-hidden project-owner row with visible contradiction" => {
          source: source.sub(ADR_0009_PROJECT_OWNER_REVIEW_LINE, "<!--\n#{ADR_0009_PROJECT_OWNER_REVIEW_LINE}\n-->\n#{weakened_project_owner_row}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :hidden_governance_substitution
        },
        "fence-hidden project-owner row with visible contradiction" => {
          source: source.sub(ADR_0009_PROJECT_OWNER_REVIEW_LINE, "~~~text\n#{ADR_0009_PROJECT_OWNER_REVIEW_LINE}\n~~~\n#{weakened_project_owner_row}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :hidden_governance_substitution
        },
        "duplicate conflicting owner metadata" => {
          source: source.sub(ADR_0009_OWNER_APPROVAL_LINE, "#{ADR_0009_OWNER_APPROVAL_LINE}\n#{weakened_owner_line}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :metadata_duplicates_conflicts
        },
        "duplicate conflicting supersession metadata" => {
          source: source.sub(ADR_0009_SUPERSESSION_LINE, "#{ADR_0009_SUPERSESSION_LINE}\n#{weakened_supersession_line}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :metadata_duplicates_conflicts
        },
        "misplaced owner metadata" => {
          source: source.sub("#{ADR_0009_OWNER_APPROVAL_LINE}\n", "").sub("## Context and decision scope", "## Context and decision scope\n\n#{ADR_0009_OWNER_APPROVAL_LINE}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :metadata_duplicates_conflicts
        },
        "misplaced supersession metadata" => {
          source: source.sub("#{ADR_0009_SUPERSESSION_LINE}\n", "").sub("## Context and decision scope", "## Context and decision scope\n\n#{ADR_0009_SUPERSESSION_LINE}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :metadata_duplicates_conflicts
        },
        "misplaced immutable-SHA sentence" => {
          source: source.sub(ADR_0009_APPROVAL_PARAGRAPH, weakened_approval_paragraph).sub("## Reviews and approvals", "#{ADR_0009_EXACT_SHA_APPROVAL_SENTENCE}\n\n## Reviews and approvals"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :exact_sha_approval_placement
        },
        "misplaced project-owner review row" => {
          source: source.sub("#{ADR_0009_PROJECT_OWNER_REVIEW_LINE}\n", "").sub("## Reviews and approvals", "#{ADR_0009_PROJECT_OWNER_REVIEW_LINE}\n\n## Reviews and approvals"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :project_owner_row
        },
        "duplicate conflicting project-owner review row" => {
          source: source.sub(ADR_0009_PROJECT_OWNER_REVIEW_LINE, "#{ADR_0009_PROJECT_OWNER_REVIEW_LINE}\n#{weakened_project_owner_row}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :review_duplicates_conflicts
        },
        "Reviews table hidden in HTML comment" => {
          source: source.sub(review_table, "<!--\n#{review_table}\n-->\n#{weakened_review_table}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :review_layout
        },
        "Reviews table hidden in fenced code" => {
          source: source.sub(review_table, "~~~text\n#{review_table}\n~~~\n#{weakened_review_table}"),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :review_layout
        },
        "Reviews section hidden in type-one raw HTML" => {
          source: source.sub("## Reviews and approvals\n", "<pre\n>\n## Reviews and approvals\n") + "</pre>\n",
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :review_layout
        },
        "Reviews heading hidden in type-six raw HTML" => {
          source: source.sub("## Reviews and approvals\n", "<div>\n## Reviews and approvals\n") + "</div>\n",
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :review_layout
        },
        "Reviews heading hidden in type-seven raw HTML" => {
          source: source.sub("## Reviews and approvals\n", "<stead-contract>\n## Reviews and approvals\n") + "</stead-contract>\n",
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :review_layout
        },
        "Project-owner review row hidden in type-one raw HTML" => {
          source: source.sub(
            "#{ADR_0009_PROJECT_OWNER_REVIEW_LINE}\n",
            "<pre\n>\n#{ADR_0009_PROJECT_OWNER_REVIEW_LINE}\n</pre>\n"
          ),
          gate: adr_0009_gate,
          gate_count: 1,
          predicate: :project_owner_row
        }
      }
      actual_governance_inventory = governance_mutations.transform_values { |mutation| mutation.fetch(:predicate) }
      unless actual_governance_inventory == ADR_0009_EXPECTED_GOVERNANCE_MUTATIONS
        failures << "ADR-0009 governance mutation inventory/mapping differs from the pinned inventory"
      end
      governance_payloads = governance_mutations.values.map do |mutation|
        [mutation.fetch(:source), mutation.fetch(:gate), mutation.fetch(:gate_count)]
      end
      unless governance_payloads.uniq.length == governance_mutations.length
        failures << "ADR-0009 governance mutations must have unique source/catalog payloads"
      end
      governance_mutations.each do |label, mutation|
        adr_0009_governance_mutation_count += 1
        unchanged = mutation.fetch(:source) == source &&
                    mutation.fetch(:gate) == adr_0009_gate &&
                    mutation.fetch(:gate_count) == 1
        expected_predicate = mutation.fetch(:predicate)
        mutation_failures = adr_0009_governance_predicate_failures(
          source: mutation.fetch(:source),
          gate: mutation.fetch(:gate),
          gate_count: mutation.fetch(:gate_count)
        )
        if unchanged || !mutation_failures.include?(expected_predicate)
          adr_0009_governance_mutation_survivors <<
            "#{label} (expected #{expected_predicate}; got #{mutation_failures.to_a.sort.join(', ')})"
        end
      end

      markdown_controls = {
        "closed type-one raw HTML after protected sections" =>
          source + "\n<pre\n>\nBenign operator example.\n</pre>\n",
        "closed type-six raw HTML after protected sections" =>
          source + "\n<aside>\nBenign operator example.\n</aside>\n\n",
        "closed type-seven raw HTML after protected sections" =>
          source + "\n<stead-note>\nBenign operator example.\n</stead-note>\n\n",
        "inline-code comment opener outside protected sections" =>
          source + "\nBenign literal `<!--` remains inline code.\n",
        "fenced HTML-like example outside protected sections" =>
          source + "\n```text\n<!-- benign example without a closer\n## Example heading\n```\n",
        "closed HTML comment outside protected sections" =>
          source + "\n<!-- benign operator note -->\n"
      }
      unless markdown_controls.keys == ADR_0009_EXPECTED_MARKDOWN_CONTROLS
        failures << "ADR-0009 benign Markdown control inventory differs from the pinned inventory"
      end
      unless markdown_controls.values.uniq.length == markdown_controls.length &&
             markdown_controls.values.none? { |control_source| control_source == source }
        failures << "ADR-0009 benign Markdown controls must be unique source-changing cases"
      end
      markdown_controls.each do |label, control_source|
        adr_0009_markdown_control_count += 1
        control_failures = adr_0009_decision_body_failures(control_source)
        control_failures.concat(adr_0009_semantic_contract_failures(control_source))
        control_failures.concat(
          adr_0009_governance_gate_failures(
            source: control_source,
            gate: adr_0009_gate,
            gate_count: 1
          )
        )
        unless control_failures.empty?
          adr_0009_markdown_control_failures << "#{label} (#{control_failures.join('; ')})"
        end
      end
    end
  end

  if expected.fetch(:state) == "ACCEPTED"
    failures << "docs/adr/INDEX.md: missing #{basename}" unless adr_index.include?("./#{basename}")
    failures << "docs/governance/adr-candidate-index.md: missing #{basename}" unless candidate_index.include?("../adr/#{basename}")
    failures << "docs/adr/unresolved-implementation-choices.md: missing #{basename}" unless choice_queue.include?("./#{basename}")
  elsif expected.fetch(:state) == "PROPOSED"
    failures << "docs/adr/INDEX.md: missing proposed #{basename}" unless adr_index.include?("./#{basename}")
    failures << "docs/governance/adr-candidate-index.md: missing proposed #{basename}" unless candidate_index.include?("../adr/#{basename}")
    failures << "docs/adr/unresolved-implementation-choices.md: missing proposed #{basename}" unless choice_queue.include?("./#{basename}")
  else
    failures << "docs/adr/INDEX.md: missing deferred candidate #{candidate}" unless adr_index.include?(candidate)
    failures << "docs/governance/adr-candidate-index.md: missing deferred candidate #{candidate}" unless candidate_index.include?(candidate)
    failures << "docs/adr/unresolved-implementation-choices.md: missing deferred candidate #{candidate}" unless choice_queue.include?(candidate)
  end

  gate = adr_gates[candidate]
  unless gate
    failures << "implementation issue catalog: missing decision gate #{candidate}"
    next
  end
  failures << "implementation issue catalog: #{candidate} state must be #{expected.fetch(:state)}" unless gate["state"] == expected.fetch(:state)
  if expected.fetch(:state) == "ACCEPTED"
    failures << "implementation issue catalog: #{candidate} decision_record must be #{relative}" unless gate["decision_record"] == relative
    failures << "implementation issue catalog: #{candidate} project-owner flag mismatch" unless gate["project_owner_approval_required"] == expected.fetch(:owner_approval)
  elsif expected.fetch(:state) == "PROPOSED"
    failures << "implementation issue catalog: proposed #{candidate} decision_record must be #{relative}" unless gate["decision_record"] == relative
    failures << "implementation issue catalog: proposed #{candidate} project-owner flag mismatch" unless gate["project_owner_approval_required"] == expected.fetch(:owner_approval)
    acceptance_fields = %w[immutable_revision accepted_at approval_record approval_records]
    present_acceptance_fields = acceptance_fields.select { |field| gate.key?(field) }
    unless present_acceptance_fields.empty?
      failures << "implementation issue catalog: proposed #{candidate} must not carry acceptance fields: #{present_acceptance_fields.join(', ')}"
    end
  else
    acceptance_fields = %w[decision_record immutable_revision accepted_at approval_record approval_records]
    present_acceptance_fields = acceptance_fields.select { |field| gate.key?(field) }
    unless present_acceptance_fields.empty?
      failures << "implementation issue catalog: deferred #{candidate} must not carry acceptance fields: #{present_acceptance_fields.join(', ')}"
    end
  end

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

adr_0009_traceability_failures = adr_requirement_traceability_failures(
  requirements: requirements,
  adr_number: "0009",
  claimed_requirement_ids: requirements_by_number.fetch("0009", []),
  declared_test_ids: tests_by_number.fetch("0009", [])
)
failures.concat(adr_0009_traceability_failures)

adr_0009_expected_edges = expected_adr_requirement_test_edges(EXPECTED_REQUIREMENT_TEST_LINKS.fetch("0009")).freeze
unless adr_0009_expected_edges.length == 44
  failures << "ADR-0009 closed requirement mapping must contain exactly 44 edges, found #{adr_0009_expected_edges.length}"
end
failures.concat(
  exact_adr_requirement_mapping_failures(
    requirements: requirements,
    adr_number: "0009",
    expected_edges: adr_0009_expected_edges
  )
)

adr_0009_mutation_survivors = []
adr_0009_expected_edges.to_a.sort.each do |requirement_id, test_id|
  mutated_requirements = requirements.map do |registered_requirement|
    registered_requirement.merge("test_ids" => Array(registered_requirement["test_ids"]).dup)
  end
  mutated_record = mutated_requirements.find { |record| record.fetch("requirement_id") == requirement_id }
  removed_test = mutated_record&.fetch("test_ids", [])&.delete(test_id)
  if removed_test.nil?
    adr_0009_mutation_survivors << "#{requirement_id} -> #{test_id} (edge absent before mutation)"
    next
  end

  mutation_failures = exact_adr_requirement_mapping_failures(
    requirements: mutated_requirements,
    adr_number: "0009",
    expected_edges: adr_0009_expected_edges
  )
  adr_0009_mutation_survivors << "#{requirement_id} -> #{test_id}" if mutation_failures.empty?
end
unless adr_0009_mutation_survivors.empty?
  failures << "ADR-0009 exact-mapping mutation survivors: #{adr_0009_mutation_survivors.join(', ')}"
end
unless ADR_0009_EXPECTED_REVIEW_MUTATIONS.length == ADR_0009_EXPECTED_REVIEW_MUTATION_COUNT
  failures << "ADR-0009 pinned review-separation mutation inventory constant must contain exactly #{ADR_0009_EXPECTED_REVIEW_MUTATION_COUNT} cases"
end
unless adr_0009_review_mutation_count == ADR_0009_EXPECTED_REVIEW_MUTATION_COUNT
  failures << "ADR-0009 review-separation mutation inventory must contain exactly #{ADR_0009_EXPECTED_REVIEW_MUTATION_COUNT} cases, found #{adr_0009_review_mutation_count}"
end
unless adr_0009_review_mutation_survivors.empty?
  failures << "ADR-0009 review-separation mutation survivors: #{adr_0009_review_mutation_survivors.join(', ')}"
end
unless ADR_0009_EXPECTED_SEMANTIC_MUTATIONS.length == ADR_0009_EXPECTED_SEMANTIC_MUTATION_COUNT
  failures << "ADR-0009 pinned semantic-security mutation inventory constant must contain exactly #{ADR_0009_EXPECTED_SEMANTIC_MUTATION_COUNT} cases"
end
unless adr_0009_security_mutation_count == ADR_0009_EXPECTED_SEMANTIC_MUTATION_COUNT
  failures << "ADR-0009 semantic-security mutation inventory must contain exactly #{ADR_0009_EXPECTED_SEMANTIC_MUTATION_COUNT} cases, found #{adr_0009_security_mutation_count}"
end
unless adr_0009_security_mutation_survivors.empty?
  failures << "ADR-0009 semantic-security mutation survivors: #{adr_0009_security_mutation_survivors.join(', ')}"
end
unless ADR_0009_EXPECTED_GOVERNANCE_MUTATIONS.length == ADR_0009_EXPECTED_GOVERNANCE_MUTATION_COUNT
  failures << "ADR-0009 pinned governance mutation inventory constant must contain exactly #{ADR_0009_EXPECTED_GOVERNANCE_MUTATION_COUNT} cases"
end
unless adr_0009_governance_mutation_count == ADR_0009_EXPECTED_GOVERNANCE_MUTATION_COUNT
  failures << "ADR-0009 supersession/owner-gate mutation inventory must contain exactly #{ADR_0009_EXPECTED_GOVERNANCE_MUTATION_COUNT} cases, found #{adr_0009_governance_mutation_count}"
end
unless adr_0009_governance_mutation_survivors.empty?
  failures << "ADR-0009 supersession/owner-gate mutation survivors: #{adr_0009_governance_mutation_survivors.join(', ')}"
end
unless adr_0009_markdown_control_count == ADR_0009_EXPECTED_MARKDOWN_CONTROL_COUNT
  failures << "ADR-0009 benign Markdown control inventory must contain exactly #{ADR_0009_EXPECTED_MARKDOWN_CONTROL_COUNT} cases, found #{adr_0009_markdown_control_count}"
end
unless adr_0009_markdown_control_failures.empty?
  failures << "ADR-0009 benign Markdown control failures: #{adr_0009_markdown_control_failures.join(', ')}"
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

adr_0009_gate = adr_gates["ADR-CAND-008"]
adr_0009_expected_dependents = %w[
  STEAD-P1-002
  STEAD-P1-003
  STEAD-P1-011
  STEAD-P1-012
  STEAD-P2-001
].to_set
adr_0009_actual_dependents = Array(adr_0009_gate&.fetch("dependent_issues", nil)).to_set
unless adr_0009_actual_dependents == adr_0009_expected_dependents
  failures << "implementation issue catalog: ADR-CAND-008 exact dependent issues must be #{adr_0009_expected_dependents.to_a.sort.join(', ')}, found #{adr_0009_actual_dependents.to_a.sort.join(', ')}"
end

provider_issue = issues["STEAD-P1-003"]
provider_requirements = Array(provider_issue&.fetch("requirement_ids", nil)).to_set
missing_provider_requirements = requirements_by_number.fetch("0009", []).to_set - provider_requirements
unless missing_provider_requirements.empty?
  failures << "STEAD-P1-003 requirement IDs omit ADR-0009 provider obligations: #{missing_provider_requirements.to_a.sort.join(', ')}"
end
provider_acceptance = Array(provider_issue&.fetch("acceptance_criteria", nil)).join(" ")
unless provider_acceptance.include?("Only after ADR-CAND-008 is accepted") &&
       provider_acceptance.include?("deterministic accept/reset/quarantine") &&
       provider_acceptance.include?("without holding PostgreSQL transactions across provider I/O")
  failures << "STEAD-P1-003 acceptance must preserve the ADR-CAND-008 gate, closed outcomes, and no-transaction-across-provider-I/O boundary"
end

operations_issue = issues["STEAD-P1-011"]
operations_acceptance = Array(operations_issue&.fetch("acceptance_criteria", nil)).join(" ")
unless operations_acceptance.include?("Own ADR-0009's versioned reconciliation configuration") &&
       operations_acceptance.include?("without selecting reconciliation outcomes or declaring ambiguous effects terminal")
  failures << "STEAD-P1-011 acceptance must preserve WS-12 configuration/operations ownership without moving reconciliation authority"
end

adr_0009_owned_path_requirements = {
  "STEAD-P1-002" => %w[apps/core modules/project modules/work tests/integration/core packages/test-fixtures/core],
  "STEAD-P1-003" => %w[modules/scm providers/gitea tests/contract/gitea],
  "STEAD-P1-011" => %w[apps/steadctl docs/operator tests/upgrade tests/backup-restore],
  "STEAD-P1-012" => %w[specs/traceability tests/security tests/contract/harness]
}.freeze
adr_0009_owned_path_requirements.each do |issue_id, required_paths|
  issue = issues[issue_id]
  unless issue
    failures << "implementation issue catalog: missing #{issue_id} for ADR-0009 owned-path split"
    next
  end

  missing_paths = required_paths.to_set - Array(issue["owned_directories"]).to_set
  failures << "#{issue_id} owned directories omit ADR-0009 contribution paths: #{missing_paths.to_a.sort.join(', ')}" unless missing_paths.empty?
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
  "0009" => {
    "STEAD-P1-002" => %w[
      T-ADR-0009-DIRECT-CHANGE-ACCEPT
      T-ADR-0009-CONFLICT-QUARANTINE
      T-ADR-0009-AMBIGUOUS-MUTATION
    ],
    "STEAD-P1-003" => tests_by_number.fetch("0009", []),
    "STEAD-P1-011" => %w[
      T-ADR-0009-WEBHOOK-IDEMPOTENCY
      T-ADR-0009-PERMISSION-DRIFT
      T-ADR-0009-PROVIDER-OUTAGE
      T-ADR-0009-AMBIGUOUS-MUTATION
      T-ADR-0009-FULL-RECONCILIATION
      T-ADR-0009-UPGRADE-ROLLBACK
    ],
    "STEAD-P1-012" => tests_by_number.fetch("0009", []),
    "STEAD-P2-001" => %w[
      T-ADR-0009-PRECEDENCE
      T-ADR-0009-PERMISSION-DRIFT
      T-ADR-0009-PROVIDER-OUTAGE
      T-ADR-0009-FULL-RECONCILIATION
      T-ADR-0009-UPGRADE-ROLLBACK
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

# ADR-0009 crosses canonical-owner, provider, operations, and independent-gate
# boundaries. Close every issue assignment in both directions so a test cannot
# be silently transferred to a foreign implementation owner.
adr_0009_expected_issue_assignments = implementation_assignments.fetch("0009").transform_values(&:to_set)
adr_0009_actual_issue_assignments = issues.each_with_object({}) do |(issue_id, issue), assignments|
  adr_tests = Array(issue["automated_tests"]).grep(/^T-ADR-0009-/).to_set
  assignments[issue_id] = adr_tests unless adr_tests.empty?
end
(adr_0009_expected_issue_assignments.keys | adr_0009_actual_issue_assignments.keys).sort.each do |issue_id|
  expected_tests = adr_0009_expected_issue_assignments.fetch(issue_id, Set.new)
  actual_tests = adr_0009_actual_issue_assignments.fetch(issue_id, Set.new)
  next if actual_tests == expected_tests

  missing_tests = expected_tests - actual_tests
  unexpected_tests = actual_tests - expected_tests
  failures << "#{issue_id} ADR-0009 exact owner assignment mismatch: missing [#{missing_tests.to_a.sort.join(', ')}], unexpected [#{unexpected_tests.to_a.sort.join(', ')}]"
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
phase_one_independent_tests.merge(tests_by_number.fetch("0009", []))
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
  adr_0009_killed_mutations = adr_0009_expected_edges.length - adr_0009_mutation_survivors.length
  puts "STEAD-P1-006 strict raw gate mutation guard: PASS (#{p1_006_gate_mutation_count}/#{EXPECTED_P1_006_GATE_MUTATION_COUNT} mutations killed)"
  puts "ADR-0007 exact-mapping mutation guard: PASS (#{adr_0007_killed_mutations}/#{adr_0007_expected_edges.length} required edge deletions killed)"
  puts "ADR-0009 exact-mapping mutation guard: PASS (#{adr_0009_killed_mutations}/#{adr_0009_expected_edges.length} required edge deletions killed)"
  puts "ADR-0009 review-separation mutation guard: PASS (#{adr_0009_review_mutation_count}/#{ADR_0009_EXPECTED_REVIEW_MUTATION_COUNT} mutations killed)"
  puts "ADR-0009 semantic-security mutation guard: PASS (#{adr_0009_security_mutation_count}/#{ADR_0009_EXPECTED_SEMANTIC_MUTATION_COUNT} mutations killed)"
  puts "ADR-0009 supersession/owner-gate mutation guard: PASS (#{adr_0009_governance_mutation_count}/#{ADR_0009_EXPECTED_GOVERNANCE_MUTATION_COUNT} mutations killed)"
  puts "ADR-0009 benign Markdown controls: PASS (#{adr_0009_markdown_control_count}/#{ADR_0009_EXPECTED_MARKDOWN_CONTROL_COUNT})"
  puts "ADR traceability validation: PASS (records=#{paths.length}, requirements=#{known_requirement_ids.length}, tests=#{all_test_owners.length})"
else
  warn "ADR traceability validation: FAIL (#{failures.length} issue#{failures.length == 1 ? '' : 's'})"
  failures.each { |failure| warn "- #{failure}" }
  exit 1
end
