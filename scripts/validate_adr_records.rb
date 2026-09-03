#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "date"
require "json"
require "open3"
require "pathname"
require "rbconfig"
require "securerandom"
require "tmpdir"
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
  # ADR-0008 remains the immutable Proposed bootstrap here. Its future
  # acceptance state and metadata are derived from the catalog gate and then
  # bound to an exact Git parent transition, so the acceptance-only child must
  # not edit this executable validator.
  "0008" => { candidate: "ADR-CAND-006", state: "PROPOSED", owner_approval: false },
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
    "AUTH-002" => %w[
      T-ADR-0009-AMBIGUOUS-MUTATION
      T-ADR-0009-FULL-RECONCILIATION
    ],
    "AUTH-006" => %w[T-ADR-0009-FULL-RECONCILIATION],
    "CLS-003" => %w[T-ADR-0009-FULL-RECONCILIATION],
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
    "SEC-006" => %w[T-ADR-0009-AUDIT-MINIMIZATION],
    "EVT-003" => %w[T-ADR-0009-AUDIT-MINIMIZATION],
    "AUD-001" => %w[T-ADR-0009-AUDIT-MINIMIZATION],
    "AUD-002" => %w[T-ADR-0009-AUDIT-MINIMIZATION],
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
    ],
    "PERF-004" => %w[T-ADR-0009-FULL-RECONCILIATION]
  }.freeze
}.freeze

# Close the complete ADR-0009 Decision body as a separate integrity guard.
# Semantic mutation self-tests below never use this digest as their oracle.
ADR_0009_DECISION_BODY_SHA256 =
  "23ea099cb6927464210f1b097000dd38af9f83041fd2af0a6aab919da68c9eb5".freeze
ADR_0009_OWNER_APPROVAL_LINE =
  "- **Project-owner approval required:** yes; this proposal narrowly changes locked per-provider-HTTP-call durable-permit clauses in the Master Build Directive's CLS-003/CLS-007 rules, constitution section 4.6, ADR-0005, and ADR-0007 for one closed bounded internal read plan".freeze
ADR_0009_SUPERSESSION_LINE =
  "- **Supersedes / superseded by:** only on acceptance at an exact immutable commit SHA with explicit project-owner approval, supersedes only the Master Build Directive CLS-003 final durable-effect sentence and CLS-007 durable-effect paragraph, constitution section 4.6's provider-effect sentence, ADR-0005 option 6/decision item 15/`T-ADR-0005-REQUEST-BOUNDARY` provider-call clauses, and ADR-0007's durable-effects provider-call sentence, and only for the bounded internal pagination/snapshot/verification/safe-idempotent-read plan defined here".freeze
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
ADR_0009_PROPOSED_REVIEWS_BYTES = 1_269
ADR_0009_PROPOSED_REVIEWS_SHA256 =
  "e1c67e2d156e880034269febcd571835a564cfa886ed4e30d33fe8cdc60375b3".freeze
ADR_0009_MARKDOWN_MAX_BYTES = 262_144
ADR_0009_SPEC_PATH = "specs/provider-reconciliation/gitea-v1.yaml".freeze
ADR_0009_SPEC_MAX_BYTES = 131_072
ADR_0009_SPEC_TOP_LEVEL_KEYS = %w[
  schema_version status owner decision_record activation_gate requirements authority
  field_classes authorization_scope snapshot_and_change_proof webhook reconciliation
  provider_mutation compatibility_profile privacy_and_observability verification
].freeze
ADR_0009_SPEC_SECTION_DIGESTS = {
  "authority" => "947858adec5cddd08322e65e8f4ab4f3be623eadc5265166ed0edd2b571f8835",
  "field_classes" => "d7bd40843dca2b1a6f121285cdd0db34ea40b49a5978dd6f411d45b2bab94ea1",
  "authorization_scope" => "6fb464dbfe0a18b31d22a0e60a538ddd663ae01257d93cdda2d226242f649540",
  "snapshot_and_change_proof" => "c672ab550b3daa59e083785fd0a1f514fa27931ec4966270729452672f443378",
  "webhook" => "689ea3cfbae79f23cccf842ed28ab11f757dad81f008824ec88fe956fbfded26",
  "reconciliation" => "b340a9ea20d0f7164ac97e1d5dfcdb35c1740649c0c7d0a6dffa80c0fc9fd5ae",
  "provider_mutation" => "04d003d64cbe5cc58f23e14d26e22a936d2a9f8c1ad1b089973b1f9fbb8d2e13",
  "compatibility_profile" => "dfd004f9311eba2574f0bc213ca1d31801c55fe1e8cb2d86294cbf3bb83a57f5",
  "privacy_and_observability" => "0b61aca3546e0f1c9088a9543798925f098bd3f2de1cff8c366c4005dd7cb265",
  "verification" => "9cf2f70d90f5134877d6b4cb2369683534ccd65d39c7fb0db0f1f63ce6831eac"
}.freeze
ADR_0009_SPEC_EXPECTATIONS = {
  "schema_version" => "1.0",
  "status" => "governed_by_adr_0009",
  "owner" => "WS-03",
  "decision_record" => "docs/adr/0009-gitea-provider-reconciliation-precedence-and-conflict-handling.md",
  "activation_gate" => "ADR-CAND-008_ACCEPTED_AT_EXACT_IMMUTABLE_SHA",
  "requirements" => %w[
    PRIN-002 ARCH-004 DOM-004 SCM-001 SCM-002 SCM-003 SCM-004 SCM-005
    AUTH-002 AUTH-006 CLS-003 CLS-006 CLS-007 SEC-006 EVT-003 AUD-001 AUD-002
    TEST-006 PERF-003 PERF-004
  ],
  "authority.ordinary_ui_synchronous_provider_calls" => 0,
  "authority.provider_permission" => "enforcement_not_authority",
  "authorization_scope.type" => "ProviderAuthorizationScope",
  "authorization_scope.owner" => "WS-06",
  "authorization_scope.consumer" => "WS-03",
  "authorization_scope.reusable" => false,
  "authorization_scope.renewable" => false,
  "authorization_scope.transferable" => false,
  "authorization_scope.purpose" => "one_bounded_logical_internal_reconciliation_read_operation",
  "authorization_scope.eligible_calls" => %w[
    pagination_read snapshot_read bounded_verification_read
    compatibility_profile_safe_idempotent_read_retry
  ],
  "authorization_scope.excluded_effects_requiring_own_durable_one_use_permit" => %w[
    provider_mutation credential_issuance direct_git_or_protocol_access export_or_download
    non_idempotent_call ambiguous_external_effect operation_outliving_logical_request_or_job
  ],
  "authorization_scope.required_bindings" => %w[
    scope_id logical_operation_id acting_service_principal
    initiating_principal_or_explicit_system_initiator organization_id security_domain_id
    canonical_container closed_resource_set_or_container_inventory_scope provider_installation_id
    provider_api_path provider_resource_key_when_resource_specific reconciliation_generation
    allowed_operation_class closed_call_plan activation_snapshot authorization_consistency_vector
    compatibility_profile_id_version_and_schema_digest original_deadline
    immutable_earliest_bound_expiry execution_claim_id execution_holder_instance_id
    execution_fencing_token execution_claim_deadline
  ],
  "authorization_scope.call_plan_fixed_before_first_provider_call" => %w[
    http_method_and_path_templates resource_set_or_container_inventory_scope
    cursor_derivation_rules call_order retry_classes maximum_attempts maximum_calls
    maximum_pages maximum_items maximum_response_bytes
  ],
  "authorization_scope.execution_claim.owner" => "WS-03",
  "authorization_scope.execution_claim.activation" => "atomic_issued_to_active_once_before_first_provider_call",
  "authorization_scope.execution_claim.bound_fields" => %w[
    execution_claim_id execution_holder_instance_id execution_fencing_token execution_claim_deadline
  ],
  "authorization_scope.execution_claim.holder_identity_source" =>
    "process_start_bound_replica_boot_pid_start_and_random_nonce",
  "authorization_scope.execution_claim.allowed_states" => %w[
    issued active completed abandoned expired
  ],
  "authorization_scope.execution_claim.dispatch_requires" =>
    "active_exact_process_instance_holder_and_monotonic_fencing_token_before_claim_deadline",
  "authorization_scope.execution_claim.same_holder_concurrency" =>
    "process_local_single_flight_guard_on_non_shareable_instance_binding_required_before_validation",
  "authorization_scope.execution_claim.fork_or_clone_behavior" =>
    "inherited_binding_invalid_when_current_process_identity_differs_and_child_must_rekey_with_new_scope",
  "authorization_scope.execution_claim.concurrent_or_forked_claim" => "denied_before_provider_io",
  "authorization_scope.execution_claim.handoff_or_resume" => "prohibited",
  "authorization_scope.execution_claim.same_scope_takeover" => "prohibited_new_scope_required",
  "authorization_scope.execution_claim.terminal_transition" =>
    "permanent_compare_and_swap_to_completed_abandoned_or_expired",
  "authorization_scope.execution_claim.stale_holder_after_fence_or_terminal_transition" =>
    "denied_before_provider_io",
  "authorization_scope.execution_claim.per_eligible_call_or_page_claim_writes" => 0,
  "authorization_scope.before_each_provider_call.mode" => "read_only_validation",
  "authorization_scope.before_each_provider_call.checks" => %w[
    exact_scope_and_logical_operation principals_organization_domain_container_and_resources
    installation_path_resource_key_generation_and_operation_class
    call_plan_method_path_cursor_order_and_local_counters
    active_execution_claim_current_process_instance_holder_fencing_token_state_and_deadline
    activation_snapshot_and_authorization_consistency_vector
    latest_provider_enforcement_and_resource_fences compatibility_profile_deadline_and_expiry
  ],
  "authorization_scope.persistence.start_transaction" => %w[
    immutable_scope_identity_and_bindings conservative_whole_plan_envelope
    atomic_one_time_execution_claim_activation
    reserved_terminal_audit_event_intent_reference_and_preassigned_uuidv7_audit_record_id_only_not_outbox_or_audit_row
  ],
  "authorization_scope.persistence.per_eligible_read_writes" => 0,
  "authorization_scope.persistence.per_eligible_page_writes" => 0,
  "authorization_scope.persistence.accounting_during_execution" => "process_local_monotonic_counters",
  "authorization_scope.persistence.uncertain_dispatch" => "consumes_local_attempt_and_allowance",
  "authorization_scope.persistence.terminalization" =>
    "permanent_claim_transition_and_exactly_one_validated_ws07_owned_audit_event_intent_through_ws02_core_outbox_port",
  "authorization_scope.persistence.terminal_transaction.coordinator" => "WS-02_WithinTransaction",
  "authorization_scope.persistence.terminal_transaction.participant_plan" => %w[
    WS-03_scm_reconciliation_terminalize_writes_only_scm_state
    WS-02_core_outbox_append_validated_intent_is_final_write_participant
  ],
  "authorization_scope.persistence.terminal_transaction.atomicity" =>
    "claim_accounting_terminal_evidence_and_intent_commit_together_or_none",
  "authorization_scope.persistence.terminal_transaction.failure_behavior" =>
    "any_participant_failure_lost_commit_response_or_clean_expiry_race_is_resolved_by_cas_and_exact_intent_identity_without_partial_state",
  "authorization_scope.persistence.terminal_transaction.external_calls_inside_transaction" =>
    "prohibited_including_gitea_nats_openfga_and_evidence_resolution",
  "authorization_scope.persistence.terminal_transaction.audit_table_write" => "prohibited",
  "authorization_scope.persistence.terminal_intent_cardinality" =>
    "exactly_one_per_scope_appended_only_by_successful_terminalization_or_expiry_recovery",
  "authorization_scope.persistence.clean_completion" =>
    "one_terminal_intent_with_exact_attempt_call_page_item_byte_counts",
  "authorization_scope.persistence.interrupted_completion" =>
    "one_terminal_intent_with_reserved_upper_bounds_and_abandoned_or_crash_result",
  "authorization_scope.persistence.page_count_growth" =>
    "constant_scope_claim_accounting_and_terminal_intent_control_write_count",
  "authorization_scope.persistence.audit_materialization.owner" => "WS-07",
  "authorization_scope.persistence.audit_materialization.source" =>
    "exact_ws07_validated_canonical_event_bytes_from_ws02_core_outbox_before_transfer_or_immutable_ws07_successor_bindings_after_transfer",
  "authorization_scope.persistence.audit_materialization.event_lookup_reference" =>
    "logical_operation_id_is_the_only_protected_operation_reference_and_is_correlation_not_authority_or_provider_locator",
  "authorization_scope.persistence.audit_materialization.authorization" =>
    "fresh_central_decision_for_ws07_service_principal_per_bounded_set_oriented_resolution_batch",
  "authorization_scope.persistence.audit_materialization.resolution_port_owner" => "WS-03",
  "authorization_scope.persistence.audit_materialization.resolution_port_mode" =>
    "authenticated_authorized_typed_bounded_set_oriented_read",
  "authorization_scope.persistence.audit_materialization.resolution_request_bindings" => %w[
    event_source event_id canonical_event_digest organization_id security_domain_id
    canonical_container_and_resource_scope logical_operation_id
  ],
  "authorization_scope.persistence.audit_materialization.resolution_response" =>
    "immutable_closed_audit_v1_1_ready_projection_sufficient_for_every_owgp_audit_field_and_provider_extension",
  "authorization_scope.persistence.audit_materialization.original_authorization_revisions" =>
    "historical_evidence_only_not_reused_authority",
  "authorization_scope.persistence.audit_materialization.prohibited_resolution_output" => %w[
    provider_table_or_protected_backing_record raw_provider_payload raw_call_plan provider_path
    provider_resource_key pagination_cursor credential
  ],
  "authorization_scope.persistence.audit_materialization.write_semantics" =>
    "append_only_insert_or_exact_identity_and_digest_match_never_update_or_rewriting_upsert",
  "authorization_scope.persistence.audit_materialization.stable_identity" =>
    "preassigned_uuidv7_audit_record_id_plus_logical_operation_id",
  "authorization_scope.persistence.audit_materialization.mismatch" =>
    "identity_digest_event_binding_or_domain_mismatch_quarantines_and_never_overwrites",
  "authorization_scope.persistence.audit_materialization.consumer_completion.successful" =>
    "only_after_exact_audit_record_is_durable",
  "authorization_scope.persistence.audit_materialization.consumer_completion.minimized_terminal" =>
    "only_after_closed_failure_successor_obligation_and_dlq_failure_audit_intents_are_durable_in_one_transaction",
  "authorization_scope.persistence.audit_materialization.consumer_completion.original_audit_obligation" =>
    "remains_open_until_exact_audit_record_is_durable",
  "authorization_scope.persistence.audit_materialization.duplicate_replay_restart_out_of_order" =>
    "exactly_one_logical_audit_record",
  "authorization_scope.persistence.audit_materialization.unavailable_or_malformed_evidence" =>
    "retry_or_quarantine_fail_closed_without_successful_completion",
  "authorization_scope.persistence.audit_materialization.generic_terminal_or_dlq_substitution" =>
    "prohibited_without_same_transaction_successor_obligation_transfer",
  "authorization_scope.persistence.audit_materialization.deadline_terminal_transaction.coordinator" =>
    "WS-02_WithinTransaction",
  "authorization_scope.persistence.audit_materialization.deadline_terminal_transaction.participant_plan" => %w[
    WS-07_audit_consumer_terminalize_and_create_successor_obligation_writes_only_ws07_state
    WS-02_core_outbox_append_minimized_dlq_and_failure_audit_intents_is_final_write_participant
  ],
  "authorization_scope.persistence.audit_materialization.deadline_terminal_transaction.atomicity" =>
    "closed_failure_terminal_evidence_successor_obligation_and_intents_commit_together_or_none",
  "authorization_scope.persistence.audit_materialization.deadline_terminal_transaction.original_outbox_retirement" =>
    "denied_until_this_transfer_commits",
  "authorization_scope.persistence.audit_materialization.deadline_terminal_transaction.external_calls_inside_transaction" =>
    "prohibited_including_gitea_nats_openfga_evidence_resolution_and_other_network_io",
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.owner" =>
    "WS-07",
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.selection" =>
    "required_real_failure_path_when_adr0008_application_deadline_closes_before_materialization",
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.stable_identity" =>
    "preassigned_audit_record_id_plus_logical_operation_id",
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.immutable_contents" => %w[
    preassigned_audit_record_id event_source event_id canonical_event_digest organization_id
    security_domain_id canonical_container_and_resource_scope logical_operation_id
  ],
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.owner_written_fenced_monotonic_recovery_state" => %w[
    status fencing_token attempt_count next_attempt_at last_closed_failure_code
    materialized_audit_digest
  ],
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.allowed_state_progression" =>
    "open_to_claimed_to_retry_wait_or_repair_required_then_exact_materialized",
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.prohibited_contents" => %w[
    provider_binding_evidence_ref call_plan_evidence_ref raw_provider_payload raw_call_plan
    provider_path provider_resource_key pagination_cursor credential
  ],
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.immutable_binding_creation" =>
    "insert_or_exact_identity_and_digest_match_never_rewrite_immutable_fields",
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.lifecycle_writes" =>
    "fenced_monotonic_owner_state_transitions_only",
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.duplicate_deadline_race" =>
    "exact_match_is_idempotent_and_identity_digest_or_binding_collision_quarantines_and_prevents_original_source_retirement",
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.authority" =>
    "recovery_obligation_only_not_authorization",
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.retirement" =>
    "only_after_exact_original_audit_record_is_durable",
  "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.backup_restore_and_rollback" =>
    "preserve_open_and_completed_obligations_with_exact_identity_and_digest",
  "authorization_scope.persistence.audit_materialization.protected_evidence_retention" =>
    "immutable_digest_bound_backed_up_restored_and_resolvable_until_exact_audit_record_is_durable_then_for_its_full_audit_retention_and_reference_resolution_window",
  "authorization_scope.persistence.page_independent_async_audit_writes" =>
    "exactly_one_on_success_with_deadline_transfer_measured_separately_as_failure_recovery",
  "authorization_scope.persistence.changed_resource_writes" =>
    "measured_batched_set_oriented_and_may_scale_only_with_actual_projection_domain_unrelated_outbox_or_quarantine_changes",
  "authorization_scope.before_local_outcome_commit.mode" => "read_only_validation_plus_owner_transaction_fence",
  "authorization_scope.before_local_outcome_commit.checks" => %w[
    all_before_call_checks final_execution_local_totals_within_whole_plan_envelope
    active_execution_claim_current_process_instance_holder_fencing_token_state_and_deadline
    no_newer_dirty_generation
    canonical_owner_revision
  ],
  "authorization_scope.process_loss.old_scope" =>
    "permanently_abandoned_or_expired_by_fenced_compare_and_swap",
  "authorization_scope.process_loss.remaining_envelope" => "conservatively_consumed",
  "authorization_scope.process_loss.stale_holder_or_fork" =>
    "denied_before_provider_io_by_process_instance_claim_state_fencing_token_and_deadline",
  "authorization_scope.process_loss.restart" =>
    "only_after_old_claim_terminalization_then_fresh_central_decision_and_new_scope_from_last_trusted_job_cursor",
  "authorization_scope.canonical_acceptance.service_read_scope_authorizes_acceptance" => false,
  "authorization_scope.canonical_acceptance.required_before_accept" => %w[
    fresh_effective_principal_central_decision_for_exact_delta current_impersonation_constraints
    final_activation_authorization_provider_enforcement_resource_and_operation_fences
    optimistic_canonical_owner_precondition
  ],
  "reconciliation.postgresql_transaction_across_provider_io" => "prohibited",
  "reconciliation.general_project_creates_code_repository" => false,
  "provider_mutation.permit" => "one_use_per_excluded_effect_call",
  "provider_mutation.ambiguous_result" => "reconciling_until_terminal_proof",
  "provider_mutation.blind_retry" => "prohibited",
  "verification.T-ADR-0009-AMBIGUOUS-MUTATION.owners" => %w[WS-03 WS-06],
  "verification.T-ADR-0009-FULL-RECONCILIATION.owners" => %w[WS-02 WS-03 WS-06 WS-07 WS-12],
  "verification.T-ADR-0009-FULL-RECONCILIATION.cases" => %w[
    every_scope_binding_omitted_or_swapped call_plan_widen_or_reorder cross_scope_reuse
    atomic_one_time_execution_claim same_scope_fork stale_holder post_terminal_replay
    claim_deadline permanent_terminal_invalidation process_loss bounded_inventory
    zero_per_page_control_writes ws03_then_ws02_terminal_participant_order
    cross_owner_write_denial terminal_claim_and_intent_atomicity_at_each_crash_boundary
    lost_commit_response clean_expiry_race exactly_one_terminal_intent
    exact_or_conservative_terminal_counts constant_control_writes_as_pages_grow
    fresh_ws07_service_authorization swapped_event_operation_domain_resource_or_digest_denied
    set_oriented_resolution_bounds
    exactly_one_ws07_audit_materialization_under_duplicate_out_of_order_replay_restart_and_nats_outage
    application_deadline_atomic_successor_obligation_transfer
    deadline_transfer_no_external_call_and_each_crash_boundary_atomic
    changed_resource_writes_measured_separately
  ],
  "privacy_and_observability.propagation_surfaces" => %w[
    logical_audit event outbox dlq log trace metric diagnostic support_evidence
  ],
  "privacy_and_observability.canonical_composition.activation" =>
    "all_named_versioned_schemas_registered_validated_and_consumer_readable_before_first_emission",
  "privacy_and_observability.canonical_composition.rollback" =>
    "stop_new_emission_preserve_old_and_new_readers_and_reconcile_forward_without_reinterpreting_committed_evidence",
  "privacy_and_observability.canonical_composition.logical_audit.predecessor_contract" =>
    "specs/work-graph-profile/owgp-v0.1.schema.json#/$defs/AuditRecord",
  "privacy_and_observability.canonical_composition.logical_audit.predecessor_schema_version" =>
    "1.0",
  "privacy_and_observability.canonical_composition.logical_audit.resource_envelope_successor_contract" =>
    "packages/domain-schemas/common/resource-envelope/resource-envelope-v1.1.schema.json",
  "privacy_and_observability.canonical_composition.logical_audit.resource_envelope_successor_contract_id" =>
    "https://stead.example/packages/domain-schemas/common/resource-envelope/resource-envelope-v1.1.schema.json",
  "privacy_and_observability.canonical_composition.logical_audit.emission_contract" =>
    "packages/domain-schemas/resources/audit-record/audit-record-v1.1.schema.json",
  "privacy_and_observability.canonical_composition.logical_audit.emission_contract_id" =>
    "https://stead.example/packages/domain-schemas/resources/audit-record/audit-record-v1.1.schema.json",
  "privacy_and_observability.canonical_composition.logical_audit.schema_version" => "1.1",
  "privacy_and_observability.canonical_composition.logical_audit.schema_owner" => "WS-01",
  "privacy_and_observability.canonical_composition.logical_audit.composition" =>
    "resource_envelope_v1_1_plus_all_predecessor_audit_fields_plus_closed_optional_provider_evidence",
  "privacy_and_observability.canonical_composition.logical_audit.closure" =>
    "unevaluated_properties_false_at_composed_record",
  "privacy_and_observability.canonical_composition.logical_audit.predecessor_compatibility" =>
    "every_resource_envelope_and_audit_required_field_and_constraint_preserved_except_schema_version_advances_from_1_0_to_1_1",
  "privacy_and_observability.canonical_composition.logical_audit.provider_evidence_property" =>
    "provider_reconciliation_evidence",
  "privacy_and_observability.canonical_composition.logical_audit.provider_evidence_contract" =>
    "logical_audit_provider_evidence",
  "privacy_and_observability.canonical_composition.logical_audit.compatibility" =>
    "preconsumer_minor_successor_with_v1_0_and_v1_1_dual_readers_consumer_first",
  "privacy_and_observability.canonical_composition.canonical_event.predecessor_data_contract" =>
    "packages/event-schemas/stead/stead-event-v0.1.schema.json",
  "privacy_and_observability.canonical_composition.canonical_event.emission_data_contract" =>
    "packages/event-schemas/stead/provider-reconciliation-event-v1.schema.json",
  "privacy_and_observability.canonical_composition.canonical_event.emission_data_contract_id" =>
    "https://stead.example/packages/event-schemas/stead/provider-reconciliation-event-v1.schema.json",
  "privacy_and_observability.canonical_composition.canonical_event.schema_version" => "1.0",
  "privacy_and_observability.canonical_composition.canonical_event.schema_owner" => "WS-07",
  "privacy_and_observability.canonical_composition.canonical_event.predecessor_compatibility" =>
    "every_stead_event_v0_1_required_field_and_constraint_preserved_except_schema_version_advances_from_0_1_to_1_0",
  "privacy_and_observability.canonical_composition.canonical_event.provider_evidence_property" =>
    "provider_reconciliation_evidence",
  "privacy_and_observability.canonical_composition.canonical_event.provider_evidence_contract" =>
    "canonical_event_provider_evidence",
  "privacy_and_observability.canonical_composition.canonical_event.envelope_common_attributes_contract" =>
    "specs/asyncapi/stead.yaml#/components/schemas/SteadCloudEventAttributesV1",
  "privacy_and_observability.canonical_composition.canonical_event.envelope_contract" =>
    "specs/asyncapi/stead.yaml#/components/schemas/ProviderReconciliationCloudEventEnvelope",
  "privacy_and_observability.canonical_composition.canonical_event.message_contract" =>
    "specs/asyncapi/stead.yaml#/components/messages/ProviderReconciliationCloudEvent",
  "privacy_and_observability.canonical_composition.canonical_event.channel_binding" =>
    "specs/asyncapi/stead.yaml#/channels/scmEvents/messages/ProviderReconciliationCloudEvent",
  "privacy_and_observability.canonical_composition.canonical_event.source" =>
    "urn:stead:producer:scm",
  "privacy_and_observability.canonical_composition.canonical_event.type" =>
    "stead.scm.reconciled.v1",
  "privacy_and_observability.canonical_composition.canonical_event.dataschema" =>
    "https://stead.example/packages/event-schemas/stead/provider-reconciliation-event-v1.schema.json",
  "privacy_and_observability.canonical_composition.canonical_event.generic_v0_1_data_route_for_same_type" =>
    "prohibited",
  "privacy_and_observability.canonical_composition.canonical_event.compatibility" =>
    "registered_consumer_first_closed_specialization_preserves_all_common_event_fields",
  "privacy_and_observability.canonical_composition.canonical_event.protected_operation_lookup_reference" =>
    "logical_operation_id_only_correlation_not_authority_or_provider_locator",
  "privacy_and_observability.canonical_composition.canonical_outbox.owner" => "WS-02",
  "privacy_and_observability.canonical_composition.canonical_outbox.representation" =>
    "exact_serialized_bytes_and_digest_of_the_registered_canonical_event",
  "privacy_and_observability.canonical_composition.canonical_outbox.additional_provider_metadata_or_reserialization" =>
    "prohibited",
  "privacy_and_observability.canonical_composition.canonical_outbox.terminal_transaction_participant" =>
    "final_write_after_ws03_scm_terminalization",
  "privacy_and_observability.canonical_composition.canonical_outbox.audit_materialization_recovery" =>
    "retain_until_ws07_exact_record_durable_or_obligation_atomically_transferred",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.predecessor_data_contract" =>
    "packages/event-schemas/stead/stead-event-v0.1.schema.json",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.emission_data_contract" =>
    "packages/event-schemas/stead/provider-reconciliation-dead-letter-v1.schema.json",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.emission_data_contract_id" =>
    "https://stead.example/packages/event-schemas/stead/provider-reconciliation-dead-letter-v1.schema.json",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.schema_version" =>
    "1.0",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.schema_owner" => "WS-07",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.predecessor_compatibility" =>
    "every_stead_event_v0_1_required_field_and_constraint_preserved_except_schema_version_advances_from_0_1_to_1_0",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.provider_evidence_property" =>
    "provider_reconciliation_evidence",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.provider_evidence_contract" =>
    "dead_letter_provider_evidence",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.envelope_common_attributes_contract" =>
    "specs/asyncapi/stead.yaml#/components/schemas/SteadCloudEventAttributesV1",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.envelope_contract" =>
    "specs/asyncapi/stead.yaml#/components/schemas/ProviderReconciliationDeadLetterCloudEventEnvelope",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.message_contract" =>
    "specs/asyncapi/stead.yaml#/components/messages/ProviderReconciliationDeadLetterCloudEvent",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.channel_binding" =>
    "specs/asyncapi/stead.yaml#/channels/deadLetterEvents/messages/ProviderReconciliationDeadLetterCloudEvent",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.source" =>
    "urn:stead:producer:dead_letter",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.type" =>
    "stead.dead_letter.provider_reconciliation_recorded.v1",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.dataschema" =>
    "https://stead.example/packages/event-schemas/stead/provider-reconciliation-dead-letter-v1.schema.json",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.generic_v0_1_data_route_for_same_type" =>
    "prohibited",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.compatibility" =>
    "registered_consumer_first_closed_specialization_preserves_all_common_event_fields",
  "privacy_and_observability.canonical_composition.minimized_dead_letter_event.original_canonical_event_or_provider_payload_copy" =>
    "prohibited",
  "privacy_and_observability.canonical_composition.asyncapi_envelope_refactor.common_attributes_component" =>
    "SteadCloudEventAttributesV1",
  "privacy_and_observability.canonical_composition.asyncapi_envelope_refactor.standard_envelope_component" =>
    "StandardSteadCloudEventEnvelope",
  "privacy_and_observability.canonical_composition.asyncapi_envelope_refactor.union_component" =>
    "SteadCloudEventEnvelope",
  "privacy_and_observability.canonical_composition.asyncapi_envelope_refactor.specialized_components" => %w[
    ProviderReconciliationCloudEventEnvelope
    ProviderReconciliationDeadLetterCloudEventEnvelope
  ],
  "privacy_and_observability.canonical_composition.asyncapi_envelope_refactor.closure" =>
    "each_standard_or_specialized_envelope_is_closed_after_common_attribute_and_data_composition",
  "privacy_and_observability.canonical_composition.asyncapi_envelope_refactor.discrimination" =>
    "exact_source_type_and_dataschema_tuple",
  "privacy_and_observability.canonical_composition.asyncapi_envelope_refactor.standard_route_exclusion" =>
    "both_provider_reconciliation_source_type_pairs_rejected_regardless_of_dataschema",
  "privacy_and_observability.canonical_composition.asyncapi_envelope_refactor.no_data_schema_fallback" =>
    "a_provider_reconciliation_type_cannot_validate_with_stead_event_v0_1_data",
  "privacy_and_observability.logical_audit_provider_evidence.closed_schema" => true,
  "privacy_and_observability.logical_audit_provider_evidence.allowed_fields" => %w[
    schema_version logical_operation_id decision_id operation_class outcome_code
    authorization_scope_id execution_claim_id disclosure_mode activation_revision
    authorization_revision provider_enforcement_revision resource_revision compatibility_profile_id
    compatibility_profile_schema_digest provider_binding_evidence_ref call_plan_class
    call_plan_evidence_ref count_mode attempt_count provider_call_count page_count item_count
    response_byte_count started_at finished_at
  ],
  "privacy_and_observability.canonical_event_provider_evidence.closed_schema" => true,
  "privacy_and_observability.canonical_event_provider_evidence.required_fields" => %w[
    schema_version logical_operation_id
  ],
  "privacy_and_observability.canonical_event_provider_evidence.allowed_fields" => %w[
    schema_version logical_operation_id
  ],
  "privacy_and_observability.canonical_event_provider_evidence.field_constraints.schema_version.type" =>
    "string",
  "privacy_and_observability.canonical_event_provider_evidence.field_constraints.schema_version.const" =>
    "1.0",
  "privacy_and_observability.canonical_event_provider_evidence.field_constraints.logical_operation_id.type" =>
    "string",
  "privacy_and_observability.canonical_event_provider_evidence.field_constraints.logical_operation_id.format" =>
    "uuid",
  "privacy_and_observability.canonical_event_provider_evidence.field_constraints.logical_operation_id.pattern" =>
    "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
  "privacy_and_observability.canonical_event_provider_evidence.field_constraints.logical_operation_id.min_length" =>
    36,
  "privacy_and_observability.canonical_event_provider_evidence.field_constraints.logical_operation_id.max_length" =>
    36,
  "privacy_and_observability.dead_letter_provider_evidence.closed_schema" => true,
  "privacy_and_observability.dead_letter_provider_evidence.allowed_fields" => %w[
    schema_version logical_operation_id source_event_id consumer_class_id operation_class
    terminal_failure_code count_mode attempt_count deadline_at
  ],
  "privacy_and_observability.operational_surface_evidence.base_contract" =>
    "docs/architecture/observability-contract.md",
  "privacy_and_observability.operational_surface_evidence.provider_attribute_namespace" =>
    "stead.provider_reconciliation",
  "privacy_and_observability.operational_surface_evidence.profiles.correlated_operation_v1.closed_schema" => true,
  "privacy_and_observability.operational_surface_evidence.profiles.correlated_operation_v1.allowed_fields" => %w[
    schema_version logical_operation_id operation_class outcome_code compatibility_profile_id
    count_mode attempt_count provider_call_count page_count item_count response_byte_count
    duration_ms correlation_id causation_id
  ],
  "privacy_and_observability.operational_surface_evidence.profiles.bounded_metric_v1.closed_schema" => true,
  "privacy_and_observability.operational_surface_evidence.profiles.bounded_metric_v1.allowed_fields" => %w[
    schema_version operation_class outcome_code compatibility_profile_id count_mode
  ],
  "privacy_and_observability.operational_surface_evidence.profiles.support_summary_v1.closed_schema" => true,
  "privacy_and_observability.operational_surface_evidence.profiles.support_summary_v1.allowed_fields" => %w[
    schema_version operation_class outcome_code compatibility_profile_id count_mode attempt_count
    provider_call_count page_count item_count response_byte_count duration_ms correlation_id
  ],
  "privacy_and_observability.operational_surface_evidence.surface_bindings.log" =>
    "correlated_operation_v1",
  "privacy_and_observability.operational_surface_evidence.surface_bindings.trace" =>
    "correlated_operation_v1",
  "privacy_and_observability.operational_surface_evidence.surface_bindings.metric" =>
    "bounded_metric_v1",
  "privacy_and_observability.operational_surface_evidence.surface_bindings.diagnostic" =>
    "support_summary_v1",
  "privacy_and_observability.operational_surface_evidence.surface_bindings.support_evidence" =>
    "support_summary_v1",
  "privacy_and_observability.operational_surface_evidence.full_record_validation" =>
    "scan_base_envelope_and_nested_provider_attributes_against_every_forbidden_value_canary",
  "privacy_and_observability.operational_surface_evidence.provider_binding_or_call_plan_evidence_references" =>
    "prohibited",
  "privacy_and_observability.audit_representation.provider_binding" =>
    "opaque_random_reference_to_ws03_protected_operation_record",
  "privacy_and_observability.audit_representation.bounded_call_plan" =>
    "closed_class_plus_opaque_random_reference_to_ws03_protected_operation_record",
  "privacy_and_observability.audit_representation.compatibility_profile" =>
    "id_and_schema_digest_only",
  "privacy_and_observability.safe_value_rules.unknown_field" => "reject",
  "privacy_and_observability.safe_value_rules.provider_derived_free_text" => "prohibited",
  "privacy_and_observability.safe_value_rules.opaque_identifier_max_bytes" => 128,
  "privacy_and_observability.safe_value_rules.codes" => "closed_server_owned_enums",
  "privacy_and_observability.safe_value_rules.counts" =>
    "nonnegative_integers_within_scope_envelope",
  "privacy_and_observability.safe_value_rules.digests" =>
    "exactly_64_lowercase_hex_sha256",
  "privacy_and_observability.safe_value_rules.timestamps" => "bounded_utc_rfc3339",
  "privacy_and_observability.safe_value_rules.canonical_references" =>
    "authorized_audit_or_partition_scope_only",
  "privacy_and_observability.safe_value_rules.evidence_references" =>
    "at_least_128_bits_csprng_opaque_non_content_derived_unique_per_logical_operation_and_authorized_resolution_only",
  "privacy_and_observability.logical_audit_semantics" => %w[
    acting_service_principal initiating_and_effective_principal_when_relevant
    safe_canonical_containing_scope source_class_and_outcome
    authorization_model_policy_and_provider_enforcement_revisions
    scope_operation_and_permit_references
    bounded_counts_opaque_plan_and_provider_references_and_safe_profile_reference
    exact_or_conservative_execution_counts correlation_and_causation
  ],
  "privacy_and_observability.forbidden_from_all_propagation_surfaces" => %w[
    raw_provider_bodies parsed_provider_bodies request_or_response_headers request_query_strings
    raw_bounded_call_plans provider_api_paths provider_resource_keys_or_locators pagination_cursors
    webhook_secrets webhook_signatures credentials protected_content
    work_titles comments document_bodies authorization_inputs policy_inputs exception_text stack_traces
  ],
  "verification.T-ADR-0009-AUDIT-MINIMIZATION.owners" => %w[WS-01 WS-03 WS-07],
  "verification.T-ADR-0009-AUDIT-MINIMIZATION.cases" => %w[
    canonical_audit_record_v1_0_to_v1_1_composition resource_envelope_v1_1_constraint_parity
    audit_v1_0_and_v1_1_dual_read specialized_cloudevent_data_composition
    event_data_schema_version_0_1_to_1_0
    exact_source_type_dataschema_discrimination
    generic_v0_1_route_rejects_provider_reconciliation_types
    canonical_event_reconciliation_evidence_requires_exact_schema_version_and_logical_operation_id_fields
    exact_outbox_canonical_bytes minimized_dead_letter_composition
    named_versioned_schema_ownership consumer_first_schema_activation schema_rollback_coexistence
    closed_operational_surface_profiles closed_nested_provider_evidence_fields
    typed_ws03_audit_evidence_resolution
    provider_binding_opaque_reference_only call_plan_opaque_reference_only
    opaque_references_materialized_logical_audit_only
    unavailable_evidence_retry_without_terminal_success audit_identity_digest_collision_quarantine
    low_entropy_offline_guessing_denied
    cross_event_provider_plan_reference_correlation_denied raw_body_canary parsed_body_canary
    request_header_canary query_string_canary raw_call_plan_canary provider_api_path_canary
    provider_resource_key_canary pagination_cursor_canary webhook_secret_canary
    webhook_signature_canary credential_canary protected_content_canary
    work_title_canary comment_canary document_body_canary authorization_input_canary policy_input_canary
    exception_text_canary stack_trace_canary
    every_canary_across_every_base_envelope_nested_evidence_and_propagation_surface
  ],
  "verification.T-ADR-0009-UPGRADE-ROLLBACK.cases" => %w[
    support_matrix unknown_capability preflight shadow_read full_scan compatible_rollback
    forward_recovery nonterminal_operation_preservation
    backup_restore_preserves_reference_resolution_and_successor_obligations
  ]
}.transform_values(&:freeze).freeze
ADR_0009_SPEC_VERIFICATION_OWNERS = {
  "T-ADR-0009-PRECEDENCE" => %w[WS-03],
  "T-ADR-0009-WEBHOOK-IDEMPOTENCY" => %w[WS-03 WS-07],
  "T-ADR-0009-DIRECT-CHANGE-ACCEPT" => %w[WS-03 WS-02 WS-06],
  "T-ADR-0009-DIRECT-CHANGE-RESET" => %w[WS-03 WS-06],
  "T-ADR-0009-CONFLICT-QUARANTINE" => %w[WS-03 WS-06],
  "T-ADR-0009-PERMISSION-DRIFT" => %w[WS-03 WS-06],
  "T-ADR-0009-PROVIDER-OUTAGE" => %w[WS-03 WS-12],
  "T-ADR-0009-AMBIGUOUS-MUTATION" => %w[WS-03 WS-06],
  "T-ADR-0009-FULL-RECONCILIATION" => %w[WS-02 WS-03 WS-06 WS-07 WS-12],
  "T-ADR-0009-AUDIT-MINIMIZATION" => %w[WS-01 WS-03 WS-07],
  "T-ADR-0009-UPGRADE-ROLLBACK" => %w[WS-01 WS-03 WS-07 WS-12]
}.transform_values(&:freeze).freeze
ADR_0009_REQUIRED_PROPAGATION_SURFACES = %w[
  logical_audit event outbox dlq log trace metric diagnostic support_evidence
].freeze
ADR_0009_CANONICAL_COMPOSITION_KEYS = %w[
  activation rollback logical_audit canonical_event canonical_outbox minimized_dead_letter_event
  asyncapi_envelope_refactor
].freeze
ADR_0009_CANONICAL_COMPOSITION_RECORD_KEYS = {
  "logical_audit" => %w[
    predecessor_contract predecessor_schema_version resource_envelope_successor_contract
    resource_envelope_successor_contract_id emission_contract emission_contract_id schema_version
    schema_owner composition closure predecessor_compatibility provider_evidence_property
    provider_evidence_contract compatibility
  ],
  "canonical_event" => %w[
    predecessor_data_contract emission_data_contract emission_data_contract_id schema_version
    schema_owner predecessor_compatibility provider_evidence_property provider_evidence_contract
    envelope_common_attributes_contract envelope_contract message_contract channel_binding source
    type dataschema generic_v0_1_data_route_for_same_type compatibility
    protected_operation_lookup_reference
  ],
  "canonical_outbox" => %w[
    owner representation additional_provider_metadata_or_reserialization
    terminal_transaction_participant audit_materialization_recovery
  ],
  "minimized_dead_letter_event" => %w[
    predecessor_data_contract emission_data_contract emission_data_contract_id schema_version
    schema_owner predecessor_compatibility provider_evidence_property provider_evidence_contract
    envelope_common_attributes_contract envelope_contract message_contract channel_binding source
    type dataschema generic_v0_1_data_route_for_same_type compatibility
    original_canonical_event_or_provider_payload_copy
  ],
  "asyncapi_envelope_refactor" => %w[
    common_attributes_component standard_envelope_component union_component specialized_components
    closure discrimination standard_route_exclusion no_data_schema_fallback
  ]
}.transform_values(&:freeze).freeze
ADR_0009_NESTED_PROVIDER_EVIDENCE_CONTRACTS = %w[
  logical_audit_provider_evidence canonical_event_provider_evidence
  dead_letter_provider_evidence
].freeze
ADR_0009_NESTED_PROVIDER_EVIDENCE_KEYS = {
  "logical_audit_provider_evidence" => %w[closed_schema allowed_fields],
  "canonical_event_provider_evidence" => %w[
    closed_schema required_fields allowed_fields field_constraints
  ],
  "dead_letter_provider_evidence" => %w[closed_schema allowed_fields]
}.transform_values(&:freeze).freeze
ADR_0009_OPERATIONAL_PROFILE_NAMES = %w[
  correlated_operation_v1 bounded_metric_v1 support_summary_v1
].freeze
ADR_0009_OPERATIONAL_SURFACE_BINDINGS = {
  "log" => "correlated_operation_v1",
  "trace" => "correlated_operation_v1",
  "metric" => "bounded_metric_v1",
  "diagnostic" => "support_summary_v1",
  "support_evidence" => "support_summary_v1"
}.freeze
ADR_0009_PROTECTED_OPERATION_REFERENCE_FIELDS = %w[
  provider_binding_evidence_ref call_plan_evidence_ref
].freeze
ADR_0009_FORBIDDEN_PROPAGATED_FIELD_PATTERNS = {
  raw_provider_bodies: /\Araw_provider_(?:body|bodies)\z/,
  parsed_provider_bodies: /\Aparsed_provider_(?:body|bodies)\z/,
  request_or_response_headers: /\A(?:request|response)(?:_or_response)?_headers?\z/,
  request_query_strings: /\Arequest_query_strings?\z/,
  raw_bounded_call_plans: /\Araw_(?:bounded_)?call_plans?\z/,
  guessable_provider_or_plan_digest: /\A(?:provider_binding|call_plan)_sha256\z/,
  provider_api_paths: /\Aprovider_(?:api_)?paths?\z/,
  provider_resource_keys_or_locators: /\Aprovider_resource_(?:key|keys|locator|locators|keys_or_locators)\z/,
  pagination_cursors: /\Apagination_cursors?\z/,
  webhook_secrets: /\Awebhook_secrets?\z/,
  webhook_signatures: /\Awebhook_signatures?\z/,
  credentials: /\Acredentials?\z/,
  protected_content: /\Aprotected_content\z/,
  work_titles: /\Awork_titles?\z/,
  comments: /\Acomments?\z/,
  document_bodies: /\Adocument_(?:body|bodies)\z/,
  authorization_inputs: /\Aauthorization_inputs?\z/,
  policy_inputs: /\Apolicy_inputs?\z/,
  exception_text: /\Aexception_text\z/,
  stack_traces: /\Astack_traces?\z/
}.freeze
ADR_0009_FORBIDDEN_PROPAGATED_FIELD_MUTANTS = {
  raw_provider_bodies: "raw_provider_body",
  parsed_provider_bodies: "parsed_provider_body",
  request_or_response_headers: "response_header",
  request_query_strings: "request_query_string",
  raw_bounded_call_plans: "raw_bounded_call_plan",
  provider_api_paths: "provider_api_path",
  provider_resource_keys_or_locators: "provider_resource_locator",
  pagination_cursors: "pagination_cursor",
  webhook_secrets: "webhook_secret",
  webhook_signatures: "webhook_signature",
  credentials: "credential",
  protected_content: "protected_content",
  work_titles: "work_title",
  comments: "comment",
  document_bodies: "document_body",
  authorization_inputs: "authorization_input",
  policy_inputs: "policy_input",
  exception_text: "exception_text",
  stack_traces: "stack_trace"
}.freeze
ADR_0009_REQUIRED_AUDIT_CANARY_CASES = %w[
  canonical_event_reconciliation_evidence_requires_exact_schema_version_and_logical_operation_id_fields
  typed_ws03_audit_evidence_resolution
  opaque_references_materialized_logical_audit_only
  unavailable_evidence_retry_without_terminal_success audit_identity_digest_collision_quarantine
  low_entropy_offline_guessing_denied cross_event_provider_plan_reference_correlation_denied
  raw_body_canary parsed_body_canary request_header_canary query_string_canary
  raw_call_plan_canary provider_api_path_canary provider_resource_key_canary
  pagination_cursor_canary webhook_secret_canary webhook_signature_canary credential_canary
  protected_content_canary work_title_canary comment_canary document_body_canary
  authorization_input_canary policy_input_canary exception_text_canary stack_trace_canary
  every_canary_across_every_base_envelope_nested_evidence_and_propagation_surface
].freeze
ADR_0009_REQUIRED_FULL_RECONCILIATION_CASES = %w[
  ws03_then_ws02_terminal_participant_order cross_owner_write_denial
  terminal_claim_and_intent_atomicity_at_each_crash_boundary lost_commit_response clean_expiry_race
  exactly_one_terminal_intent exact_or_conservative_terminal_counts
  fresh_ws07_service_authorization swapped_event_operation_domain_resource_or_digest_denied
  set_oriented_resolution_bounds
  exactly_one_ws07_audit_materialization_under_duplicate_out_of_order_replay_restart_and_nats_outage
  application_deadline_atomic_successor_obligation_transfer
  deadline_transfer_no_external_call_and_each_crash_boundary_atomic
].freeze
ADR_0009_REQUIRED_UPGRADE_ROLLBACK_CASES = %w[
  backup_restore_preserves_reference_resolution_and_successor_obligations
].freeze
ADR_0009_EXPECTED_SPEC_CUSTOM_MUTATIONS = 52
ADR_0009_DECISION_FRAGMENT_PREDICATES = {
  process_bound_holder: "The holder binding covers replica boot identity, current PID/start identity, and a fresh process nonce; every dispatch rechecks the current process identity.",
  fork_rekeys_scope: "A keyed process-local single-flight guard prevents same-holder concurrency, while a fork or clone inherits an invalid parent binding and must rekey under a new scope.",
  scope_and_local_accounting: "Before every dispatch and local outcome commit, WS-03 proves that the claim remains active for that exact process-instance holder and fencing token and is before its deadline, then invokes the WS-06 read-only scope/fence validator and enforces execution-local monotonic counters.",
  terminal_no_handoff: "Claim handoff, takeover, renewal, and resume are prohibited; completion, abandonment, or expiry is a permanent compare-and-swap terminal transition, and recovery requires a new scope.",
  zero_page_control_writes: "The operation performs one atomic start/claim transaction and one terminal transaction, but zero durable reservation, permit, audit-record, claim-renewal, or accounting writes per eligible call or page.",
  reserved_intent_only: "The start transaction persists only a reserved terminal audit/event-intent reference and preassigned UUIDv7 audit identity in WS-03 operation state; it creates neither a `core_outbox` row nor an append-only audit record.",
  terminal_participant_order: "The terminal transaction uses the predeclared WS-03 `scm.reconciliation_terminalize` claim/accounting participant, which writes only `scm.*`, followed by the WS-02 `core_outbox.append_validated_intent` participant as its final writer.",
  terminal_atomicity: "It commits the permanent claim transition, durable closed audit-materialization evidence, and exactly one validated immutable WS-07-owned audit/event intent together, or commits none of them; WS-03 never writes an `audit.*` table.",
  event_minimization: "The canonical terminal event retains every required EVT-003/base-schema field; its additional reconciliation evidence is exactly `schema_version` and `logical_operation_id`.",
  ws07_append_only_materialization: "Materialization is insert-or-exact-identity-and-digest-match, never an update or rewriting upsert; an identity/digest collision quarantines.",
  fresh_authorized_resolver: "For each bounded set-oriented resolution batch, WS-07 obtains a fresh central authorization for its service principal and invokes an authenticated typed WS-03 read port bound to the exact event source, event ID, canonical digest, Organization, security domain, container/resource scope, and logical operation.",
  no_generic_dlq_substitution: "A generic minimized terminal/DLQ outcome cannot silently substitute for the required reconciliation `AuditRecord`",
  deadline_successor_atomicity: "If the ADR-0008 application deadline closes first, one predeclared transaction runs the WS-07 terminal-state/successor-obligation participant, which writes only WS-07-owned state, followed by the WS-02 `core_outbox` append participant as the final writer.",
  successor_recovery_authority: "Phase 1 implements this real failure path in WS-07-owned state; the successor becomes the recovery authority and cannot retire until the exact original `AuditRecord` is durable.",
  local_transaction_only: "Neither the reconciliation-terminal transaction nor the deadline-transfer transaction performs Gitea, NATS, OpenFGA, evidence-resolution, or other network I/O; each failure boundary rolls back its complete predeclared local participant plan.",
  constant_control_write_accounting: "Scope, claim, accounting, and terminal-intent control writes remain constant as page count grows; successful asynchronous audit materialization is exactly one write independent of page count, while the deadline-transfer write is measured separately as failure recovery.",
  changed_resource_write_accounting: "Batched projection, domain, unrelated outbox, and quarantine writes are measured separately and may grow only with actual changed resources.",
  schema_ownership: "WS-01 owns the versioned canonical `AuditRecord` schema. WS-07 owns the audit/event intent semantics, idempotent audit-store materialization and consumer completion, the versioned event/dead-letter schemas, schema registration, AsyncAPI, and delivery.",
  process_loss_fresh_scope: "Recovery starts from the last trusted job cursor only after the old claim is terminal and a fresh decision creates a new scope.",
  excluded_effect_permits: "Each such effect retains its own fresh decision, durable one-use `AuthorizationEffectPermit`",
  effective_principal: "Before canonical state accepts provider-originated data, Stead performs a separate fresh central decision for the effective provider principal",
  no_provider_transaction: "never holds a PostgreSQL transaction across Gitea I/O"
}.freeze
ADR_0009_CROSS_FILE_REQUIRED_FRAGMENTS = {
  "docs/architecture/authorization-contract.md" => [
    "one fresh centrally issued `ProviderAuthorizationScope`",
    "without a separate durable permit transaction for each eligible read"
  ],
  "docs/architecture/contract-ownership-matrix.md" => [
    "`P-SCM-RECONCILIATION-GITEA-V1`",
    "`/specs/provider-reconciliation/gitea-v1.yaml`",
    "scope issuance/validation remains WS-06-owned",
    "execution-claim and protected audit-evidence state plus its authenticated/authorized typed resolution port remain WS-03-owned",
    "`core_outbox` persistence/append remains WS-02-owned",
    "common resource-envelope and canonical AuditRecord schemas remain WS-01-owned",
    "event/DLQ consumption and idempotent audit materialization/completion remain WS-07-owned",
    "audit records are append-only insert-or-exact-match",
    "deadline recovery atomically creates a real immutable successor obligation before source retirement",
    "ADR-0009 source cannot retire before exact WS-07 audit materialization or atomic deadline transfer to the real WS-07 recovery obligation"
  ],
  "specs/provider-interfaces.yaml" => [
    "id: P-SCM-RECONCILIATION-GITEA-V1",
    "authorization_scope_owner: WS-06",
    "protected_audit_evidence_resolution_port: authenticated_authorized_typed_bounded_set_oriented_read",
    "core_outbox_owner: WS-02",
    "audit_record_materialization_owner: WS-07",
    "terminal_transaction: predeclared_ws03_scm_then_ws02_core_outbox_final_participant_atomic_state_and_intent",
    "audit_recovery: adr0008_deadline_atomically_transfers_to_real_ws07_successor_obligation_before_core_outbox_retirement",
    "activation_gate: ADR-CAND-008_ACCEPTED_AT_EXACT_IMMUTABLE_SHA"
  ],
  "docs/planning/epic-issue-hierarchy.md" => [
    "STEAD-P1-007",
    "accepted ADR-CAND-008",
    "ADR-0009 idempotent audit materialization and atomic deadline transfer to a real successor obligation"
  ]
}.transform_values(&:freeze).freeze
ADR_0009_PROVIDER_INTERFACE_NEW_FIELDS = %w[
  protected_audit_evidence_owner protected_audit_evidence_resolution_port
  protected_audit_evidence_consumer core_outbox_owner audit_record_materialization_owner
  audit_record_materialization propagated_evidence terminal_transaction audit_recovery
].freeze
ADR_0009_P1_007_REQUIRED_TESTS = %w[
  T-ADR-0009-FULL-RECONCILIATION T-ADR-0009-AUDIT-MINIMIZATION
  T-ADR-0009-UPGRADE-ROLLBACK
].freeze
ADR_0009_P1_007_MATERIALIZATION_FRAGMENTS = [
  "additional reconciliation event evidence contains exactly `schema_version` and the correlation-only `logical_operation_id`",
  "fresh central authorization for the WS-07 service principal",
  "bounded set-oriented immutable audit-v1.1-ready projection through the authenticated WS-03 typed port",
  "Append exactly one canonical AuditRecord",
  "insert-or-exact-stable-UUIDv7-identity-and-digest-match semantics",
  "never update or rewriting-upsert an audit row",
  "Successful materialization completion occurs only after the row is durable",
  "A generic terminal/DLQ result cannot substitute for the record",
  "predeclared WS-07 terminal-state participant followed by the WS-02 core_outbox final participant",
  "real immutable WS-07-owned successor materialization obligation",
  "only then may terminal consumer completion and original-source retirement occur",
  "without protected provider references",
  "retain the successor until the exact original AuditRecord is durable"
].freeze
ADR_0009_EXPECTED_CROSS_CONTRACT_MUTATIONS = 26
ADR_0009_EXPECTED_ADR_MUTATIONS = %i[
  decision_digest
  owner_metadata
  supersession_metadata
  proposed_reviews
].freeze
ADR_0009_PROPOSED_STATUS_LINE = "- **Status:** Proposed\n".freeze
ADR_0009_PROPOSED_RESOLUTION_LINE =
  "- **Resolves on acceptance:** `ADR-CAND-008`\n".freeze
ADR_0009_ACCEPTED_RESOLUTION_LINE = "- **Resolves:** `ADR-CAND-008`\n".freeze
ADR_0009_REVIEWS_HEADING = "## Reviews and approvals\n".freeze
ADR_0009_FOOTNOTE_MARKER = "[^gitea-webhooks]:".freeze
ADR_0009_APPROVAL_RECORD_PATH = "docs/governance/adr-0009-approval-record.md".freeze
ADR_0009_DECISION_RECORD_PATH =
  "docs/adr/0009-gitea-provider-reconciliation-precedence-and-conflict-handling.md".freeze
ADR_0009_ISSUE_CATALOG_PATH = "docs/planning/implementation-issue-catalog.yaml".freeze
ADR_0009_ADR_INDEX_PATH = "docs/adr/INDEX.md".freeze
ADR_0009_CHOICE_QUEUE_PATH = "docs/adr/unresolved-implementation-choices.md".freeze
ADR_0009_CANDIDATE_INDEX_PATH = "docs/governance/adr-candidate-index.md".freeze
ADR_0009_ACCEPTANCE_RECORD_SCAN_MAX = 16
ADR_0009_ACCEPTANCE_HISTORY_MAX_COMMITS = 4_096
ADR_0009_ACCEPTANCE_SNAPSHOT_MAX_BYTES = 524_288
ADR_0009_ACCEPTANCE_TRANSITION_CHANGES = {
  ADR_0009_DECISION_RECORD_PATH => "M",
  ADR_0009_APPROVAL_RECORD_PATH => "A",
  ADR_0009_ISSUE_CATALOG_PATH => "M",
  ADR_0009_ADR_INDEX_PATH => "M",
  ADR_0009_CHOICE_QUEUE_PATH => "M",
  ADR_0009_CANDIDATE_INDEX_PATH => "M"
}.freeze
ADR_0009_CHOICE_QUEUE_PROPOSED_STATUS =
  "**Status:** Active candidate queue; eight candidates are resolved, ADR-CAND-008 is proposed, and the remaining entries are deferred to their named decision point<br>\n".freeze
ADR_0009_CHOICE_QUEUE_ACCEPTED_STATUS =
  "**Status:** Active candidate queue; nine candidates are resolved, and the remaining entries are deferred to their named decision point<br>\n".freeze
ADR_0009_CANDIDATE_INDEX_PROPOSED_STATUS =
  "Status: **Phase 1 active; eight candidates are resolved, ADR-CAND-008 is proposed, and the remaining candidates stay deferred to their named gates**\n".freeze
ADR_0009_CANDIDATE_INDEX_ACCEPTED_STATUS =
  "Status: **Phase 1 active; nine candidates are resolved, and the remaining candidates stay deferred to their named gates**\n".freeze
ADR_0009_ACCEPTED_REVIEW_HEADER =
  "| Role | Identity | Decision revision | Disposition | Evidence |\n".freeze
ADR_0009_ACCEPTED_REVIEW_DELIMITER = "|---|---|---|---|---|\n".freeze
ADR_0009_ACCEPTED_REVIEW_ROLES = [
  {
    role: "WS-03-provider-reconciliation",
    label: "Contract owner (WS-03)",
    evidence: "Provider reconciliation contract review accepted"
  },
  {
    role: "WS-01-architecture",
    label: "Architecture and standards (WS-01)",
    evidence: "Architecture, compatibility, and narrow supersession review accepted"
  },
  {
    role: "WS-02-canonical-transaction",
    label: "Canonical transaction owner (WS-02)",
    evidence: "Canonical acceptance and transaction-boundary review accepted"
  },
  {
    role: "WS-06-authorization-classification",
    label: "Authorization/classification owner (WS-06)",
    evidence: "Central decision, scope, and fence review accepted"
  },
  {
    role: "WS-07-event-audit",
    label: "Event/audit owner (WS-07)",
    evidence: "Logical audit and event-boundary review accepted"
  },
  {
    role: "WS-12-deployment-operations",
    label: "Deployment/operations owner (WS-12)",
    evidence: "Configuration, recovery, upgrade, and performance review accepted"
  },
  {
    role: "WS-13-independent-qa",
    label: "Independent QA and C-QA traceability owner (WS-13)",
    evidence: "Independent traceability and failure-path review accepted"
  },
  {
    role: "WS-13-independent-security",
    label: "Independent security (WS-13)",
    evidence: "Independent authorization, ambiguity, and nondisclosure review accepted"
  },
  {
    role: "project-owner",
    label: "Project owner",
    evidence: "Explicit project-owner approval of this exact immutable decision revision"
  }
].map(&:freeze).freeze
ADR_0009_ACCEPTED_REVIEW_ROLE_NAMES =
  ADR_0009_ACCEPTED_REVIEW_ROLES.map { |record| record.fetch(:role) }.freeze
ADR_0009_ACCEPTED_REVIEWS_INTRO =
  "Every required non-author review and the explicit project-owner approval below bind the exact immutable decision revision. Acceptance adopts only that decision content and its future evidence obligations; implementation remains separately gated.\n".freeze
ADR_0009_EXPECTED_ACCEPTANCE_MUTATION_NAMES = [
  "accepted gate missing immutable revision",
  "accepted gate missing project-owner approval",
  "accepted gate wrong project-owner disposition",
  "accepted gate invalid project-owner identity",
  "accepted gate duplicate project-owner approval",
  "accepted gate mixed reviewer revision surface",
  "approval record missing project-owner row",
  "approval record wrong project-owner revision",
  "approval record mixed non-owner revision",
  "acceptance change adds implementation path",
  "acceptance change omits required record path",
  "acceptance change uses wrong path status",
  "history omits acceptance transition",
  "history uses non-direct acceptance descendant",
  "history uses merge acceptance child",
  "history contains multiple acceptance transitions",
  "history decision revision is not reachable"
].freeze

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
ADR_0008_CBI_TABLE_HEADER =
  "| ID | Path / surface | Bypass or leakage risk | Required preventive/detective controls | Automated test contract | Owner | Residual risk and status |\n".freeze
ADR_0008_CBI_TABLE_DELIMITER = "|---|---|---|---|---|---|---|\n".freeze
ADR_0008_CLASSIFICATION_BYPASS_SOURCE_BYTES = 42_378
ADR_0008_CLASSIFICATION_BYPASS_SOURCE_SHA256 =
  "c744bdda4a0a482d8554e2227998fa14343a191ee2796fd68236fd8b55c993c0".freeze
ADR_0008_CBI_SOURCE_MUTATION_NAMES = [
  "multiline type-one pre block hides canonical table",
  "inline HTML comment splits rendered CBI-030",
  "multiline HTML comment splits rendered CBI-030",
  "inline link text splits rendered CBI-030",
  "reference link text splits rendered CBI-030",
  "entity-escaped angles preserve rendered CBI-030",
  "numeric entity-escaped angles preserve rendered CBI-030",
  "raw HTML block exposes rendered CBI-030 text",
  "inline HTML tag splits rendered CBI-030",
  "fenced code exposes rendered CBI-030 text",
  "indented paragraph entity exposes rendered CBI-030",
  "invalid inline link destination exposes rendered CBI-030",
  "Unicode-folded reference link exposes rendered CBI-030",
  "multiline reference destination is a source change",
  "same-length non-CBI source byte change"
].freeze

ADR_0008_EXPECTED_SECURITY_MUTATION_GROUPS = {
  topology: 33,
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
ADR_0008_PROPOSED_RESOLUTION_LINE =
  "- **Resolves on acceptance:** `ADR-CAND-006`\n".freeze
ADR_0008_ACCEPTED_RESOLUTION_LINE = "- **Resolves:** `ADR-CAND-006`\n".freeze
ADR_0008_REVIEWS_HEADING = "## Reviews and approvals\n".freeze
ADR_0008_REVIEWS_MAX_BYTES = 8_192
ADR_0008_REVIEWS_MAX_LINES = 64
ADR_0008_ACCEPTANCE_RECORD_SCAN_MAX = 16
ADR_0008_PROPOSED_REVIEWS_BYTES = 2_117
ADR_0008_PROPOSED_REVIEWS_SHA256 =
  "a3c458df69ef62ff71365f7d8806dbb50bee840b34c30a3c4bba9980e4612dd4".freeze
ADR_0008_APPROVAL_RECORD_PATH = "docs/governance/adr-0008-approval-record.md".freeze
ADR_0008_DECISION_RECORD_PATH =
  "docs/adr/0008-nats-stream-subject-retention-replay-ordering-and-dlq.md".freeze
ADR_0008_ISSUE_CATALOG_PATH = "docs/planning/implementation-issue-catalog.yaml".freeze
ADR_0008_ACCEPTANCE_HISTORY_MAX_COMMITS = 4_096
ADR_0008_ACCEPTANCE_SNAPSHOT_MAX_BYTES = 524_288
ADR_0008_REAL_HISTORY_PROBE_TOKEN_ENV =
  "STEAD_ADR_0008_REAL_HISTORY_PROBE_TOKEN".freeze
ADR_0008_REAL_HISTORY_PROBE_CONFIG_KEY =
  "stead.adr0008RealHistoryProbeToken".freeze
ADR_0008_REAL_HISTORY_PROBE_TOKEN_PATTERN = /\A[0-9a-f]{64}\z/
ADR_0008_ACCEPTANCE_TRANSITION_CHANGES = {
  ADR_0008_DECISION_RECORD_PATH => "M",
  ADR_0008_APPROVAL_RECORD_PATH => "A",
  ADR_0008_ISSUE_CATALOG_PATH => "M",
  "docs/adr/INDEX.md" => "M",
  "docs/adr/unresolved-implementation-choices.md" => "M",
  "docs/governance/adr-candidate-index.md" => "M"
}.freeze
ADR_0008_ADR_INDEX_PATH = "docs/adr/INDEX.md".freeze
ADR_0008_CHOICE_QUEUE_PATH = "docs/adr/unresolved-implementation-choices.md".freeze
ADR_0008_CANDIDATE_INDEX_PATH = "docs/governance/adr-candidate-index.md".freeze
ADR_0008_CHOICE_QUEUE_PROPOSED_STATUS =
  "**Status:** Active candidate queue; seven candidates are resolved, ADR-CAND-006 is proposed, and the remaining entries are deferred to their named decision point<br>\n".freeze
ADR_0008_CHOICE_QUEUE_ACCEPTED_STATUS =
  "**Status:** Active candidate queue; eight candidates are resolved, and the remaining entries are deferred to their named decision point<br>\n".freeze
ADR_0008_CANDIDATE_INDEX_PROPOSED_STATUS =
  "Status: **Phase 1 active; seven candidates are resolved, ADR-CAND-006 is proposed, and the remaining candidates stay deferred to their named gates**\n".freeze
ADR_0008_CANDIDATE_INDEX_ACCEPTED_STATUS =
  "Status: **Phase 1 active; eight candidates are resolved, and the remaining candidates stay deferred to their named gates**\n".freeze
ADR_0008_ACCEPTED_REVIEW_ROLES = [
  {
    role: "WS-01-architecture",
    label: "Architecture and standards (WS-01)",
    evidence: "Topology, portability, compatibility, and supersession review accepted"
  },
  {
    role: "WS-02-core-outbox",
    label: "Core/outbox integration (WS-02)",
    evidence: "Atomic outbox and failure-boundary review accepted"
  },
  {
    role: "WS-06-security-contract",
    label: "Authorization/classification/security (WS-06)",
    evidence: "Domain isolation, credential, replay, and nondisclosure review accepted"
  },
  {
    role: "WS-07-events-worker",
    label: "Events/worker consumer (WS-07, non-author)",
    evidence: "Delivery, retry, replay, DLQ, and audit review accepted"
  },
  {
    role: "WS-08-projection",
    label: "Projection consumer (WS-08)",
    evidence: "Ordering, rebuild, lag, and visibility review accepted"
  },
  {
    role: "WS-12-deployment-operations",
    label: "Deployment operations (WS-12)",
    evidence: "Local startup, production transport, capacity, recovery, and rollback review accepted"
  },
  {
    role: "WS-13-independent-qa",
    label: "Independent QA (WS-13)",
    evidence: "Traceability, compatibility, performance, and recovery review accepted"
  },
  {
    role: "WS-13-independent-security",
    label: "Independent security (WS-13)",
    evidence: "Fail-closed credential, payload, replay, and DLQ review accepted"
  },
  {
    role: "project-owner",
    label: "Project owner",
    evidence: "Conforming selection; project-owner approval not required"
  }
].map(&:freeze).freeze
ADR_0008_ACCEPTED_REVIEW_ROLE_NAMES =
  ADR_0008_ACCEPTED_REVIEW_ROLES.map { |record| record.fetch(:role) }.freeze
ADR_0008_ACCEPTED_REVIEW_HEADER =
  "| Role | Identity | Decision revision | Disposition | Evidence |\n".freeze
ADR_0008_ACCEPTED_REVIEW_DELIMITER = "|---|---|---|---|---|\n".freeze
ADR_0008_EXPECTED_RECORD_MUTATION_NAMES = [
  "proposed review amendment",
  "wrong accepted status revision with expected revision in review tail",
  "wrong accepted status date",
  "mixed accepted review revision",
  "accepted review amendment",
  "accepted level-three amendment",
  "accepted raw-HTML amendment",
  "missing accepted review role",
  "duplicate accepted review role",
  "missing acceptance-metadata role",
  "duplicate acceptance-metadata role"
].freeze
ADR_0008_EXPECTED_APPROVAL_RECORD_MUTATION_NAMES = [
  "post-table level-three contradictory amendment",
  "post-table prose",
  "post-table raw HTML",
  "post-table HTML comment",
  "post-table blank tail",
  "pre-table addition",
  "duplicate approval row",
  "foreign approval row",
  "missing approval row",
  "mixed approval-row revision"
].freeze
ADR_0008_EXPECTED_CATALOG_SOURCE_MUTATION_NAMES = [
  "duplicate foreign immutable revision before canonical",
  "alternate acceptance field ordering",
  "alternate immutable revision quoting",
  "acceptance inline comment",
  "acceptance trailing whitespace",
  "acceptance blank-line addition",
  "mixed canonical revision",
  "unrelated top-level raw quoting"
].freeze
ADR_0008_EXPECTED_HISTORY_MUTATION_NAMES = [
  "unavailable Git history",
  "shallow Git history",
  "ambiguous acceptance transition",
  "consistent nonexistent decision revision",
  "consistent ancestor decision revision",
  "consistent sibling decision revision",
  "uppercase decision revision",
  "malformed decision revision",
  "mixed decision revisions",
  "unrelated catalog semantics",
  "unrelated index row",
  "extra implementation path",
  "validator self-edit in acceptance transition"
].freeze
ADR_0008_FUTURE_ACCEPTED_FIXTURE_STATUS_LINE =
  "- **Status:** Accepted at immutable decision revision `0123456789abcdef0123456789abcdef01234567` on 2026-09-04\n".freeze
ADR_0008_FUTURE_ACCEPTED_FIXTURE_REVIEWS_BYTES = 2_071
ADR_0008_FUTURE_ACCEPTED_FIXTURE_REVIEWS_SHA256 =
  "76621d3459103b8784cbca0731166e59fffd6dd8a46f8d807f6c73467ba68c95".freeze
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
  ADR-CAND-008
  ADR-CAND-021
].freeze
EXPECTED_P1_006_ADR_GATE_CLAUSE =
  "Only after ADR-CAND-002, ADR-CAND-003, ADR-CAND-004, ADR-CAND-005, ADR-CAND-007, ADR-CAND-008, and ADR-CAND-021 are accepted,".freeze
P1_006_ALLOWED_ACCEPTED_ADR_0009_CLAUSE = "For accepted ADR-0009 only,".freeze
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
  candidate_boundary: 14,
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

YAML_AST_MAX_NODES = 250_000
YAML_AST_MAX_DEPTH = 128

class YamlAstValidationError < Psych::Exception; end
class DuplicateYamlMappingKeyError < YamlAstValidationError; end
class NonCanonicalYamlMappingKeyError < YamlAstValidationError; end
class MultipleYamlDocumentsError < YamlAstValidationError; end
class YamlAstResourceLimitError < YamlAstValidationError; end

def yaml_mapping_key_identity!(node, filename:, scanner:)
  line = node.respond_to?(:start_line) ? node.start_line + 1 : "unknown"
  unless node.is_a?(Psych::Nodes::Scalar)
    raise NonCanonicalYamlMappingKeyError,
          "#{filename}: mapping key at line #{line} must be one scalar String"
  end
  unless node.tag.nil? && node.anchor.nil?
    raise NonCanonicalYamlMappingKeyError,
          "#{filename}: mapping key at line #{line} must be untagged and unanchored"
  end

  value = node.value
  unless value.is_a?(String) && value.encoding == Encoding::UTF_8 && value.valid_encoding?
    raise NonCanonicalYamlMappingKeyError,
          "#{filename}: mapping key at line #{line} must be valid UTF-8"
  end
  if value == "<<"
    raise NonCanonicalYamlMappingKeyError,
          "#{filename}: YAML merge mapping key at line #{line} is prohibited"
  end

  semantic_value = node.plain ? scanner.tokenize(value) : value
  unless semantic_value.is_a?(String) && semantic_value.encoding == Encoding::UTF_8 &&
         semantic_value.valid_encoding?
    raise NonCanonicalYamlMappingKeyError,
          "#{filename}: mapping key at line #{line} must resolve to a String"
  end
  semantic_value
end

def validate_yaml_ast_node!(node, filename:, scanner:, state:, depth:, mapping_key: false)
  state[:nodes] += 1
  if state[:nodes] > YAML_AST_MAX_NODES || depth > YAML_AST_MAX_DEPTH
    raise YamlAstResourceLimitError,
          "#{filename}: YAML AST exceeds #{YAML_AST_MAX_NODES} nodes or depth #{YAML_AST_MAX_DEPTH}"
  end

  return yaml_mapping_key_identity!(node, filename: filename, scanner: scanner) if mapping_key

  case node
  when Psych::Nodes::Mapping
    unless node.children.length.even?
      raise YamlAstValidationError, "#{filename}: malformed YAML mapping node"
    end

    seen_keys = {}
    node.children.each_slice(2) do |key_node, value_node|
      key_identity = validate_yaml_ast_node!(
        key_node,
        filename: filename,
        scanner: scanner,
        state: state,
        depth: depth + 1,
        mapping_key: true
      )
      if seen_keys.key?(key_identity)
        line = key_node.respond_to?(:start_line) ? key_node.start_line + 1 : "unknown"
        raise DuplicateYamlMappingKeyError,
              "#{filename}: duplicate YAML mapping key at line #{line}"
      end
      seen_keys[key_identity] = true
      validate_yaml_ast_node!(
        value_node,
        filename: filename,
        scanner: scanner,
        state: state,
        depth: depth + 1
      )
    end
  else
    Array(node.children).each do |child|
      validate_yaml_ast_node!(
        child,
        filename: filename,
        scanner: scanner,
        state: state,
        depth: depth + 1
      )
    end
  end
end

def validate_yaml_ast_mapping_keys!(source, filename:)
  unless source.is_a?(String) && source.encoding == Encoding::UTF_8 && source.valid_encoding?
    raise YamlAstValidationError, "#{filename}: YAML source must be valid UTF-8"
  end

  ast = Psych.parse_stream(source, filename: filename)
  unless ast.children.length == 1
    raise MultipleYamlDocumentsError,
          "#{filename}: YAML source must contain exactly one document, found #{ast.children.length}"
  end
  class_loader = Psych::ClassLoader::Restricted.new([], [])
  scanner = Psych::ScalarScanner.new(class_loader)
  validate_yaml_ast_node!(
    ast,
    filename: filename,
    scanner: scanner,
    state: { nodes: 0 },
    depth: 0
  )
end

def parse_yaml(source, filename:)
  validate_yaml_ast_mapping_keys!(source, filename: filename)
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

def adr_0009_decision_body(source)
  start_matches = source.enum_for(:scan, /^## Decision\n/).map { Regexp.last_match }
  end_matches = source.enum_for(:scan, /^## Consequences\n/).map { Regexp.last_match }
  return [nil, ["ADR-0009 Decision heading must occur exactly once"]] unless start_matches.length == 1
  return [nil, ["ADR-0009 Consequences heading must occur exactly once"]] unless end_matches.length == 1

  start_match = start_matches.first
  end_match = end_matches.first
  return [nil, ["ADR-0009 Decision must precede Consequences"]] if end_match.begin(0) <= start_match.end(0)

  next_heading = source.match(/^## ([^#\n][^\n]*)\n/, start_match.end(0))
  unless next_heading&.begin(0) == end_match.begin(0)
    return [nil, ["ADR-0009 Consequences must immediately follow the Decision section"]]
  end
  [source.byteslice(start_match.end(0), end_match.begin(0) - start_match.end(0)), []]
end

def adr_0009_decision_body_failures(source)
  body, failures = adr_0009_decision_body(source)
  return failures unless failures.empty?

  actual = Digest::SHA256.hexdigest(body)
  return [] if actual == ADR_0009_DECISION_BODY_SHA256

  ["ADR-0009 Decision body must match closed semantic digest #{ADR_0009_DECISION_BODY_SHA256}, found #{actual}"]
end

def adr_0009_semantic_contract_failures(source)
  body, body_failures = adr_0009_decision_body(source)
  return body_failures unless body

  failures = []
  ADR_0009_DECISION_FRAGMENT_PREDICATES.each do |predicate, fragment|
    count = body.scan(Regexp.new(Regexp.escape(fragment))).length
    failures << "ADR-0009 Decision predicate failed: #{predicate}" unless count == 1
  end
  failures
end

def adr_0009_document_governance_predicate_failures(source)
  failed = Set.new
  unless source.is_a?(String) && source.valid_encoding? && source.end_with?("\n") &&
         source.bytesize <= ADR_0009_MARKDOWN_MAX_BYTES &&
         !source.start_with?("\uFEFF") && !source.include?("\r") && !source.include?("\0")
    failed << :canonical_markdown
    return failed
  end

  lines = source.lines(chomp: true)
  metadata_lines = lines[2, ADR_0009_METADATA_KEY_ORDER.length] || []
  metadata_keys = metadata_lines.map { |line| line[/\A- \*\*([^*]+):\*\*\s*/, 1] }
  unless lines[0] == "# ADR-0009: Gitea provider reconciliation precedence and conflict handling" &&
         lines[1] == "" &&
         metadata_keys == ADR_0009_METADATA_KEY_ORDER &&
         lines[2 + ADR_0009_METADATA_KEY_ORDER.length] == "" &&
         lines[3 + ADR_0009_METADATA_KEY_ORDER.length] == "## Context"
    failed << :metadata_layout
  end

  status_index = 2 + ADR_0009_METADATA_KEY_ORDER.index("Status")
  owner_index = 2 + ADR_0009_METADATA_KEY_ORDER.index("Project-owner approval required")
  supersession_index = 2 + ADR_0009_METADATA_KEY_ORDER.index("Supersedes / superseded by")
  failed << :metadata_status_proposed unless lines[status_index] == ADR_0009_PROPOSED_STATUS_LINE.chomp
  failed << :metadata_owner_required unless lines[owner_index] == ADR_0009_OWNER_APPROVAL_LINE
  failed << :metadata_supersession_narrow unless lines[supersession_index] == ADR_0009_SUPERSESSION_LINE

  review_offset = source.index(ADR_0009_REVIEWS_HEADING)
  footnote_offset = source.index(ADR_0009_FOOTNOTE_MARKER, review_offset.to_i)
  if review_offset.nil? || footnote_offset.nil? || footnote_offset <= review_offset
    failed << :proposed_reviews
    return failed
  end
  reviews = source[review_offset...footnote_offset]
  unless reviews.bytesize == ADR_0009_PROPOSED_REVIEWS_BYTES &&
         Digest::SHA256.hexdigest(reviews) == ADR_0009_PROPOSED_REVIEWS_SHA256
    failed << :proposed_reviews
  end
  failed
end

def adr_0009_canonical_value(value)
  case value
  when Hash
    value.keys.sort.to_h { |key| [key, adr_0009_canonical_value(value.fetch(key))] }
  when Array
    value.map { |entry| adr_0009_canonical_value(entry) }
  else
    value
  end
end

def adr_0009_spec_value(spec, path)
  path.split(".").reduce(spec) do |value, component|
    break nil unless value.is_a?(Hash) && value.key?(component)

    value.fetch(component)
  end
end

def adr_0009_mutate_spec_path(spec, path)
  mutated = Marshal.load(Marshal.dump(spec))
  components = path.split(".")
  leaf = components.pop
  parent = components.reduce(mutated) { |value, component| value.fetch(component) }
  original = parent.fetch(leaf)
  parent[leaf] = case original
                 when false then true
                 when true then false
                 when Integer then original + 1
                 when String then "mutated_#{original}"
                 when Array then original + ["mutated_extra_value"]
                 when Hash then original.merge("mutated_extra_key" => true)
                 else nil
                 end
  mutated
end

def adr_0009_spec_failures(spec_source:, spec:)
  failures = []
  unless spec_source.is_a?(String) && spec_source.valid_encoding? &&
         spec_source.bytesize <= ADR_0009_SPEC_MAX_BYTES && spec_source.end_with?("\n")
    failures << "ADR-0009 structured reconciliation spec exceeds its canonical resource or encoding bounds"
  end
  unless spec.is_a?(Hash)
    failures << "ADR-0009 structured reconciliation spec must be one mapping"
    return failures
  end
  unless spec.keys == ADR_0009_SPEC_TOP_LEVEL_KEYS
    failures << "ADR-0009 structured reconciliation spec top-level keys must match the closed order"
  end

  ADR_0009_SPEC_SECTION_DIGESTS.each do |section, expected_digest|
    value = spec[section]
    actual_digest = Digest::SHA256.hexdigest(JSON.generate(adr_0009_canonical_value(value)))
    unless actual_digest == expected_digest
      failures << "ADR-0009 structured reconciliation spec section digest mismatch: #{section}"
    end
  end

  ADR_0009_SPEC_EXPECTATIONS.each do |path, expected|
    actual = adr_0009_spec_value(spec, path)
    failures << "ADR-0009 structured reconciliation spec invariant failed: #{path}" unless actual == expected
  end

  field_classes = spec["field_classes"]
  if field_classes.is_a?(Hash)
    expected_classes = %w[canonical_only provider_content mapped_value managed_configuration central_security provider_identity derived_projection]
    failures << "ADR-0009 field-class registry must use the closed class order" unless field_classes.keys == expected_classes
    example_classes = Hash.new { |hash, example| hash[example] = [] }
    field_classes.each do |name, definition|
      unless definition.is_a?(Hash) && definition.keys == %w[examples disagreement] &&
             definition["examples"].is_a?(Array) && !definition["examples"].empty? &&
             definition["examples"].uniq == definition["examples"]
        failures << "ADR-0009 field class #{name} must have unique examples and one disagreement rule"
      end
      Array(definition["examples"]).each { |example| example_classes[example] << name } if definition.is_a?(Hash)
    end
    cross_class_duplicates = example_classes.filter_map do |example, classes|
      "#{example}=#{classes.uniq.join('/')}" if classes.uniq.length > 1
    end
    unless cross_class_duplicates.empty?
      failures << "ADR-0009 field-class examples must be globally unique: #{cross_class_duplicates.sort.join(', ')}"
    end
  else
    failures << "ADR-0009 field-class registry must be a mapping"
  end

  privacy = spec["privacy_and_observability"]
  if privacy.is_a?(Hash)
    surfaces = privacy["propagation_surfaces"]
    unless surfaces == ADR_0009_REQUIRED_PROPAGATION_SURFACES
      failures << "ADR-0009 provider evidence propagation surfaces must match the closed audit/event/outbox/DLQ/telemetry set"
    end

    composition = privacy["canonical_composition"]
    unless composition.is_a?(Hash) &&
           composition.keys == ADR_0009_CANONICAL_COMPOSITION_KEYS
      failures << "ADR-0009 canonical audit/event/outbox/dead-letter composition must use the closed contract set"
    else
      ADR_0009_CANONICAL_COMPOSITION_RECORD_KEYS.each do |name, expected_keys|
        record = composition[name]
        unless record.is_a?(Hash) && record.keys == expected_keys
          failures << "ADR-0009 canonical composition #{name} must use its closed field set"
        end
      end
    end

    nested_field_sets = ADR_0009_NESTED_PROVIDER_EVIDENCE_CONTRACTS.to_h do |name|
      record = privacy[name]
      expected_keys = ADR_0009_NESTED_PROVIDER_EVIDENCE_KEYS.fetch(name)
      unless record.is_a?(Hash) && record.keys == expected_keys &&
             record["closed_schema"] == true && record["allowed_fields"].is_a?(Array) &&
             !record["allowed_fields"].empty? && record["allowed_fields"].uniq == record["allowed_fields"] &&
             record["allowed_fields"].all? { |field| field.is_a?(String) } &&
             record["allowed_fields"].first == "schema_version"
        failures << "ADR-0009 nested provider evidence #{name} must be a closed schema with unique string fields"
        [name, []]
      else
        [name, record.fetch("allowed_fields")]
      end
    end

    canonical_event_evidence = privacy["canonical_event_provider_evidence"]
    unless canonical_event_evidence.is_a?(Hash) &&
           canonical_event_evidence["required_fields"] == canonical_event_evidence["allowed_fields"] &&
           canonical_event_evidence["allowed_fields"] == %w[schema_version logical_operation_id] &&
           canonical_event_evidence["field_constraints"].is_a?(Hash) &&
           canonical_event_evidence["field_constraints"].keys == %w[schema_version logical_operation_id] &&
           canonical_event_evidence.dig("field_constraints", "schema_version")&.keys == %w[type const] &&
           canonical_event_evidence.dig("field_constraints", "logical_operation_id")&.keys ==
             %w[type format pattern min_length max_length]
      failures << "ADR-0009 canonical event reconciliation evidence must require exactly const schema_version and bounded UUIDv7 logical_operation_id"
    end

    operational_field_sets = {}
    operational = privacy["operational_surface_evidence"]
    expected_operational_keys = %w[
      base_contract provider_attribute_namespace profiles surface_bindings full_record_validation
      provider_binding_or_call_plan_evidence_references
    ]
    unless operational.is_a?(Hash) && operational.keys == expected_operational_keys
      failures << "ADR-0009 operational-surface provider evidence must use the closed base/profile/binding contract"
    else
      profiles = operational["profiles"]
      if profiles.is_a?(Hash) && profiles.keys == ADR_0009_OPERATIONAL_PROFILE_NAMES
        ADR_0009_OPERATIONAL_PROFILE_NAMES.each do |name|
          record = profiles[name]
          unless record.is_a?(Hash) && record.keys == %w[closed_schema allowed_fields] &&
                 record["closed_schema"] == true && record["allowed_fields"].is_a?(Array) &&
                 !record["allowed_fields"].empty? &&
                 record["allowed_fields"].uniq == record["allowed_fields"] &&
                 record["allowed_fields"].all? { |field| field.is_a?(String) } &&
                 record["allowed_fields"].first == "schema_version"
            failures << "ADR-0009 operational provider-attribute profile #{name} must be a closed schema"
            next
          end
          operational_field_sets[name] = record.fetch("allowed_fields")
        end
      else
        failures << "ADR-0009 operational provider-attribute profiles must match the closed profile registry"
      end
      bindings = operational["surface_bindings"]
      unless bindings.is_a?(Hash) && bindings.keys == ADR_0009_OPERATIONAL_SURFACE_BINDINGS.keys &&
             bindings == ADR_0009_OPERATIONAL_SURFACE_BINDINGS
        failures << "ADR-0009 operational propagation surfaces must bind exactly to closed provider-attribute profiles"
      end
    end

    propagated_fields = nested_field_sets.values.flatten + operational_field_sets.values.flatten
    leaked_classes = ADR_0009_FORBIDDEN_PROPAGATED_FIELD_PATTERNS.filter_map do |name, pattern|
      name if propagated_fields.any? { |field| field.match?(pattern) }
    end
    unless leaked_classes.empty?
      failures << "ADR-0009 closed nested or operational schemas expose forbidden provider evidence: #{leaked_classes.join(', ')}"
    end

    logical_audit_fields = nested_field_sets.fetch("logical_audit_provider_evidence", [])
    non_audit_fields = nested_field_sets.reject do |name, _fields|
      name == "logical_audit_provider_evidence"
    end.values.flatten + operational_field_sets.values.flatten
    unless (logical_audit_fields & ADR_0009_PROTECTED_OPERATION_REFERENCE_FIELDS) ==
           ADR_0009_PROTECTED_OPERATION_REFERENCE_FIELDS &&
           (non_audit_fields & ADR_0009_PROTECTED_OPERATION_REFERENCE_FIELDS).empty?
      failures << "ADR-0009 opaque provider-binding and call-plan references must occur only in logical-audit evidence"
    end

    forbidden = privacy["forbidden_from_all_propagation_surfaces"]
    unless forbidden == ADR_0009_SPEC_EXPECTATIONS.fetch(
      "privacy_and_observability.forbidden_from_all_propagation_surfaces"
    )
      failures << "ADR-0009 every propagation surface must apply the closed exclusion list"
    end
  else
    failures << "ADR-0009 privacy and observability contract must be a mapping"
  end

  verification = spec["verification"]
  unless verification.is_a?(Hash) && verification.keys == ADR_0009_SPEC_VERIFICATION_OWNERS.keys
    failures << "ADR-0009 structured reconciliation verification registry must match the eleven closed test IDs"
  else
    ADR_0009_SPEC_VERIFICATION_OWNERS.each do |test_id, expected_owners|
      record = verification[test_id]
      unless record.is_a?(Hash) && record.keys == %w[owners cases] &&
             record["owners"] == expected_owners && record["cases"].is_a?(Array) &&
             !record["cases"].empty? && record["cases"].uniq == record["cases"]
        failures << "ADR-0009 structured reconciliation verification contract failed: #{test_id}"
      end
    end
    audit_cases = verification.dig("T-ADR-0009-AUDIT-MINIMIZATION", "cases")
    unless audit_cases.is_a?(Array) &&
           (ADR_0009_REQUIRED_AUDIT_CANARY_CASES - audit_cases).empty?
      failures << "ADR-0009 audit minimization must cover every forbidden-value canary across every base envelope, nested evidence object, and propagation surface"
    end
    full_reconciliation_cases = verification.dig("T-ADR-0009-FULL-RECONCILIATION", "cases")
    unless full_reconciliation_cases.is_a?(Array) &&
           (ADR_0009_REQUIRED_FULL_RECONCILIATION_CASES - full_reconciliation_cases).empty?
      failures << "ADR-0009 full reconciliation must cover terminal ownership, atomic intent, recovery, and exactly-once WS-07 audit materialization"
    end
    upgrade_rollback_cases = verification.dig("T-ADR-0009-UPGRADE-ROLLBACK", "cases")
    unless upgrade_rollback_cases.is_a?(Array) &&
           (ADR_0009_REQUIRED_UPGRADE_ROLLBACK_CASES - upgrade_rollback_cases).empty?
      failures << "ADR-0009 upgrade and rollback must preserve protected-evidence resolution and successor obligations across backup/restore"
    end
  end
  failures
rescue JSON::GeneratorError, TypeError => error
  failures << "ADR-0009 structured reconciliation spec cannot be canonicalized: #{error.class}"
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

def adr_0008_acceptance_metadata_failures(metadata)
  failures = []
  unless metadata.is_a?(Hash)
    return ["ADR-0008 acceptance metadata must be a mapping"]
  end

  expected_keys = Set[:immutable_revision, :accepted_at, :approval_record_path, :approval_records]
  unless metadata.keys.to_set == expected_keys
    failures << "ADR-0008 acceptance metadata must contain only immutable revision, date, approval record, and approval records"
  end

  immutable_revision = metadata[:immutable_revision]
  unless immutable_revision.is_a?(String) && immutable_revision.bytesize == 40 &&
         immutable_revision.match?(/\A[0-9a-f]{40}\z/)
    failures << "ADR-0008 acceptance metadata immutable revision must be exactly 40 lowercase hexadecimal characters"
  end

  accepted_at = metadata[:accepted_at]
  valid_date = accepted_at.is_a?(String) && accepted_at.bytesize == 10 &&
               accepted_at.match?(/\A[0-9]{4}-[0-9]{2}-[0-9]{2}\z/)
  if valid_date
    begin
      Date.iso8601(accepted_at)
    rescue Date::Error
      valid_date = false
    end
  end
  failures << "ADR-0008 acceptance metadata date must be a valid YYYY-MM-DD date" unless valid_date

  unless metadata[:approval_record_path] == ADR_0008_APPROVAL_RECORD_PATH
    failures << "ADR-0008 acceptance metadata must use #{ADR_0008_APPROVAL_RECORD_PATH}"
  end

  records = metadata[:approval_records]
  unless records.is_a?(Array)
    failures << "ADR-0008 acceptance approval records must be an ordered list"
    return failures
  end
  if records.length > ADR_0008_ACCEPTANCE_RECORD_SCAN_MAX
    failures << "ADR-0008 acceptance approval records exceed their resource bound"
    return failures
  end
  if records.length > ADR_0008_ACCEPTED_REVIEW_ROLE_NAMES.length
    failures << "ADR-0008 acceptance approval records exceed the closed role count"
  end

  roles = []
  identities = {}
  records.each_with_index do |record, index|
    unless record.is_a?(Hash)
      failures << "ADR-0008 acceptance approval record #{index + 1} must be a mapping"
      next
    end
    unless record.keys.to_set == Set["role", "identity", "disposition"]
      failures << "ADR-0008 acceptance approval record #{index + 1} must contain only role, identity, and disposition"
    end

    role = record["role"]
    identity = record["identity"]
    disposition = record["disposition"]
    roles << role
    identities[role] = identity if role.is_a?(String)
    next unless ADR_0008_ACCEPTED_REVIEW_ROLE_NAMES.include?(role)

    expected_disposition = role == "project-owner" ? "NOT_REQUIRED" : "APPROVED"
    unless disposition == expected_disposition
      failures << "ADR-0008 acceptance role #{role} disposition must be #{expected_disposition}"
    end

    if role == "project-owner"
      unless identity == "not required for this conforming selection"
        failures << "ADR-0008 conforming acceptance must retain the exact project-owner non-requirement"
      end
      next
    end

    safe_identity = identity.is_a?(String) && identity.bytesize.between?(1, 160) &&
                    identity.ascii_only? && identity.match?(/\A\/root\/[a-z0-9][a-z0-9_\/-]*\z/)
    failures << "ADR-0008 acceptance role #{role} must name one bounded non-author reviewer identity" unless safe_identity
    if identity == "/root/adr_cand_006"
      failures << "ADR-0008 decision author cannot supply acceptance role #{role}"
    end
  end

  missing_roles = ADR_0008_ACCEPTED_REVIEW_ROLE_NAMES - roles
  duplicate_roles = roles.select { |role| roles.count(role) > 1 }.uniq
  unexpected_roles = roles.compact - ADR_0008_ACCEPTED_REVIEW_ROLE_NAMES
  failures << "ADR-0008 acceptance approval records omit roles: #{missing_roles.join(', ')}" unless missing_roles.empty?
  failures << "ADR-0008 acceptance approval records duplicate roles: #{duplicate_roles.join(', ')}" unless duplicate_roles.empty?
  failures << "ADR-0008 acceptance approval records contain unexpected roles: #{unexpected_roles.join(', ')}" unless unexpected_roles.empty?
  unless roles == ADR_0008_ACCEPTED_REVIEW_ROLE_NAMES
    failures << "ADR-0008 acceptance approval records must use the exact canonical role order"
  end
  if identities["WS-13-independent-qa"] == identities["WS-13-independent-security"]
    failures << "ADR-0008 independent QA and security reviewer identities must be distinct"
  end

  failures
end

def adr_0008_acceptance_metadata_from_gate(gate)
  unless gate.is_a?(Hash)
    return [nil, ["ADR-0008 catalog gate must be a mapping"]]
  end

  acceptance_fields = %w[immutable_revision accepted_at approval_record approval_records]
  case gate["state"]
  when "PROPOSED"
    premature_fields = acceptance_fields.select { |field| gate.key?(field) }
    failures = if premature_fields.empty?
                 []
               else
                 ["ADR-0008 proposed catalog gate has premature acceptance fields: #{premature_fields.join(', ')}"]
               end
    [nil, failures]
  when "ACCEPTED"
    missing_fields = acceptance_fields.reject { |field| gate.key?(field) }
    unless missing_fields.empty?
      return [nil, ["ADR-0008 accepted catalog gate omits acceptance fields: #{missing_fields.join(', ')}"]]
    end

    metadata = {
      immutable_revision: gate["immutable_revision"],
      accepted_at: gate["accepted_at"],
      approval_record_path: gate["approval_record"],
      approval_records: gate["approval_records"]
    }
    metadata_failures = adr_0008_acceptance_metadata_failures(metadata)
    [metadata_failures.empty? ? metadata : nil, metadata_failures]
  else
    [nil, ["ADR-0008 catalog gate state must be PROPOSED or ACCEPTED"]]
  end
end

def adr_0008_accepted_status_line(metadata)
  "- **Status:** Accepted at immutable decision revision `#{metadata.fetch(:immutable_revision)}` on #{metadata.fetch(:accepted_at)}\n"
end

def adr_0008_accepted_reviews_tail(metadata)
  records_by_role = metadata.fetch(:approval_records).to_h { |record| [record.fetch("role"), record] }
  immutable_revision = metadata.fetch(:immutable_revision)
  tail = +ADR_0008_REVIEWS_HEADING
  tail << "\n"
  tail << ADR_0008_ACCEPTED_REVIEW_HEADER
  tail << ADR_0008_ACCEPTED_REVIEW_DELIMITER
  tail << "| Decision author (WS-07) | `/root/adr_cand_006` | `#{immutable_revision}` | AUTHOR — NOT APPROVAL | Authored decision; author cannot approve |\n"
  ADR_0008_ACCEPTED_REVIEW_ROLES.each do |definition|
    record = records_by_role.fetch(definition.fetch(:role))
    tail << "| #{definition.fetch(:label)} | `#{record.fetch('identity')}` | `#{immutable_revision}` | " \
            "#{record.fetch('disposition')} | #{definition.fetch(:evidence)} |\n"
  end
  tail
end

def adr_0008_exact_revision?(value)
  value.is_a?(String) && value.bytesize == 40 && value.match?(/\A[0-9a-f]{40}\z/)
end

def adr_0008_catalog_gate_from_source(source, filename:)
  catalog = parse_yaml(source, filename: filename)
  gates = catalog.fetch("adr_decision_gates")
  unless gates.is_a?(Array)
    return [nil, ["#{filename}: adr_decision_gates must be an array"]]
  end

  matching = gates.select { |gate| gate.is_a?(Hash) && gate["adr_id"] == "ADR-CAND-006" }
  return [nil, ["#{filename}: must contain exactly one ADR-CAND-006 gate"]] unless matching.length == 1

  [matching.first, []]
rescue KeyError, Psych::Exception, TypeError => error
  [nil, ["#{filename}: cannot parse ADR-CAND-006 gate: #{error.class}"]]
end

def adr_0008_catalog_transition_failures(parent_source:, child_source:, metadata:)
  failures = []
  canonical_child_source, canonical_source_failures = adr_0008_accepted_catalog_source_fixture(
    parent_source,
    metadata
  )
  failures.concat(canonical_source_failures)
  if canonical_child_source && child_source != canonical_child_source
    failures << "ADR-0008 acceptance catalog child must exactly match the metadata-derived canonical source"
  end

  parent_catalog = parse_yaml(parent_source, filename: "ADR-0008 immutable parent catalog fixture")
  child_catalog = parse_yaml(child_source, filename: "ADR-0008 acceptance child catalog fixture")
  parent_gates = parent_catalog.fetch("adr_decision_gates")
  child_gates = child_catalog.fetch("adr_decision_gates")
  unless parent_gates.is_a?(Array) && child_gates.is_a?(Array)
    return ["ADR-0008 acceptance catalog transition requires gate arrays"]
  end

  parent_indices = parent_gates.each_index.select do |index|
    parent_gates[index].is_a?(Hash) && parent_gates[index]["adr_id"] == "ADR-CAND-006"
  end
  child_indices = child_gates.each_index.select do |index|
    child_gates[index].is_a?(Hash) && child_gates[index]["adr_id"] == "ADR-CAND-006"
  end
  unless parent_indices.length == 1 && child_indices == parent_indices
    return ["ADR-0008 acceptance catalog transition must preserve one gate at the same position"]
  end

  gate_index = parent_indices.first
  parent_gate = parent_gates.fetch(gate_index)
  child_gate = child_gates.fetch(gate_index)
  unless parent_gate["state"] == "PROPOSED"
    failures << "ADR-0008 acceptance catalog parent gate must be PROPOSED"
  end
  premature_fields = %w[immutable_revision accepted_at approval_record approval_records].select do |field|
    parent_gate.key?(field)
  end
  unless premature_fields.empty?
    failures << "ADR-0008 acceptance catalog parent has premature fields: #{premature_fields.join(', ')}"
  end

  expected_child_gate = parent_gate.merge(
    "state" => "ACCEPTED",
    "immutable_revision" => metadata.fetch(:immutable_revision),
    "accepted_at" => metadata.fetch(:accepted_at),
    "approval_record" => metadata.fetch(:approval_record_path),
    "approval_records" => metadata.fetch(:approval_records)
  )
  unless child_gate == expected_child_gate
    failures << "ADR-0008 acceptance catalog child may change only exact metadata-derived gate fields"
  end

  normalized_child = Marshal.load(Marshal.dump(child_catalog))
  normalized_child.fetch("adr_decision_gates")[gate_index] = parent_gate
  unless normalized_child == parent_catalog
    failures << "ADR-0008 acceptance catalog child changes unrelated catalog semantics"
  end

  failures
rescue KeyError, Psych::Exception, TypeError => error
  failures << "ADR-0008 acceptance catalog transition cannot be compared: #{error.class}"
  failures
end

def adr_0008_acceptance_transition_change_failures(changes)
  unless changes.is_a?(Hash) && changes.keys.all? { |path| path.is_a?(String) } &&
         changes.values.all? { |status| status.is_a?(String) }
    return ["ADR-0008 acceptance transition change inventory is malformed"]
  end

  failures = []
  unexpected_paths = changes.keys - ADR_0008_ACCEPTANCE_TRANSITION_CHANGES.keys
  unless unexpected_paths.empty?
    failures << "ADR-0008 acceptance transition changes paths outside the closed approval/gate/review allowlist: " \
                "#{unexpected_paths.sort.join(', ')}"
  end
  missing_paths = ADR_0008_ACCEPTANCE_TRANSITION_CHANGES.keys - changes.keys
  unless missing_paths.empty?
    failures << "ADR-0008 acceptance transition omits required record paths: #{missing_paths.sort.join(', ')}"
  end
  wrong_statuses = ADR_0008_ACCEPTANCE_TRANSITION_CHANGES.filter_map do |path, expected_status|
    actual_status = changes[path]
    "#{path}=#{actual_status.inspect} (expected #{expected_status})" if actual_status && actual_status != expected_status
  end
  unless wrong_statuses.empty?
    failures << "ADR-0008 acceptance transition has noncanonical record changes: #{wrong_statuses.join(', ')}"
  end
  failures
end

def adr_0009_exact_revision?(value)
  value.is_a?(String) && value.bytesize == 40 && value.match?(/\A[0-9a-f]{40}\z/)
end

def adr_0009_acceptance_metadata_failures(metadata)
  return ["ADR-0009 acceptance metadata must be a mapping"] unless metadata.is_a?(Hash)

  failures = []
  expected_keys = Set[:immutable_revision, :accepted_at, :approval_record_path, :approval_records]
  unless metadata.keys.to_set == expected_keys
    failures << "ADR-0009 acceptance metadata must contain only immutable revision, date, approval record, and approval records"
  end

  immutable_revision = metadata[:immutable_revision]
  unless adr_0009_exact_revision?(immutable_revision)
    failures << "ADR-0009 acceptance metadata immutable revision must be exactly 40 lowercase hexadecimal characters"
  end

  accepted_at = metadata[:accepted_at]
  valid_date = accepted_at.is_a?(String) && accepted_at.match?(/\A[0-9]{4}-[0-9]{2}-[0-9]{2}\z/)
  if valid_date
    begin
      Date.iso8601(accepted_at)
    rescue Date::Error
      valid_date = false
    end
  end
  failures << "ADR-0009 acceptance metadata date must be a valid YYYY-MM-DD date" unless valid_date

  unless metadata[:approval_record_path] == ADR_0009_APPROVAL_RECORD_PATH
    failures << "ADR-0009 acceptance metadata must use #{ADR_0009_APPROVAL_RECORD_PATH}"
  end

  records = metadata[:approval_records]
  unless records.is_a?(Array)
    failures << "ADR-0009 acceptance approval records must be an ordered list"
    return failures
  end
  if records.length > ADR_0009_ACCEPTANCE_RECORD_SCAN_MAX
    failures << "ADR-0009 acceptance approval records exceed their resource bound"
    return failures
  end

  roles = []
  identities = {}
  records.each_with_index do |record, index|
    unless record.is_a?(Hash)
      failures << "ADR-0009 acceptance approval record #{index + 1} must be a mapping"
      next
    end
    unless record.keys.to_set == Set["role", "identity", "disposition"]
      failures << "ADR-0009 acceptance approval record #{index + 1} must contain only role, identity, and disposition"
    end

    role = record["role"]
    identity = record["identity"]
    disposition = record["disposition"]
    roles << role
    identities[role] = identity if role.is_a?(String)
    next unless ADR_0009_ACCEPTED_REVIEW_ROLE_NAMES.include?(role)

    failures << "ADR-0009 acceptance role #{role} disposition must be APPROVED" unless disposition == "APPROVED"
    if role == "project-owner"
      safe_owner = identity.is_a?(String) && identity.bytesize.between?(1, 240) &&
                   identity.ascii_only? && !identity.match?(/[\r\n`|]/) &&
                   identity.start_with?("explicit ") && identity.include?("project-owner")
      failures << "ADR-0009 project-owner approval must name one explicit bounded project-owner identity" unless safe_owner
    else
      safe_identity = identity.is_a?(String) && identity.bytesize.between?(1, 160) &&
                      identity.ascii_only? && identity.match?(/\A\/root\/[a-z0-9][a-z0-9_\/-]*\z/)
      failures << "ADR-0009 acceptance role #{role} must name one bounded non-author reviewer identity" unless safe_identity
      if identity == "/root/adr_cand_008"
        failures << "ADR-0009 decision author cannot supply acceptance role #{role}"
      end
    end
  end

  missing_roles = ADR_0009_ACCEPTED_REVIEW_ROLE_NAMES - roles
  duplicate_roles = roles.select { |role| roles.count(role) > 1 }.uniq
  unexpected_roles = roles.compact - ADR_0009_ACCEPTED_REVIEW_ROLE_NAMES
  failures << "ADR-0009 acceptance approval records omit roles: #{missing_roles.join(', ')}" unless missing_roles.empty?
  failures << "ADR-0009 acceptance approval records duplicate roles: #{duplicate_roles.join(', ')}" unless duplicate_roles.empty?
  failures << "ADR-0009 acceptance approval records contain unexpected roles: #{unexpected_roles.join(', ')}" unless unexpected_roles.empty?
  unless roles == ADR_0009_ACCEPTED_REVIEW_ROLE_NAMES
    failures << "ADR-0009 acceptance approval records must use the exact canonical role order"
  end
  if identities["WS-13-independent-qa"] == identities["WS-13-independent-security"]
    failures << "ADR-0009 independent QA and security reviewer identities must be distinct"
  end
  failures
end

def adr_0009_acceptance_metadata_from_gate(gate)
  return [nil, ["ADR-0009 catalog gate must be a mapping"]] unless gate.is_a?(Hash)

  acceptance_fields = %w[immutable_revision accepted_at approval_record approval_records]
  case gate["state"]
  when "PROPOSED"
    premature = acceptance_fields.select { |field| gate.key?(field) }
    failures = premature.empty? ? [] : ["ADR-0009 proposed catalog gate has premature acceptance fields: #{premature.join(', ')}"]
    [nil, failures]
  when "ACCEPTED"
    missing = acceptance_fields.reject { |field| gate.key?(field) }
    return [nil, ["ADR-0009 accepted catalog gate omits acceptance fields: #{missing.join(', ')}"]] unless missing.empty?

    metadata = {
      immutable_revision: gate["immutable_revision"],
      accepted_at: gate["accepted_at"],
      approval_record_path: gate["approval_record"],
      approval_records: gate["approval_records"]
    }
    metadata_failures = adr_0009_acceptance_metadata_failures(metadata)
    [metadata_failures.empty? ? metadata : nil, metadata_failures]
  else
    [nil, ["ADR-0009 catalog gate state must be PROPOSED or ACCEPTED"]]
  end
end

def adr_0009_accepted_status_line(metadata)
  "- **Status:** Accepted at immutable decision revision `#{metadata.fetch(:immutable_revision)}` on #{metadata.fetch(:accepted_at)}\n"
end

def adr_0009_accepted_reviews_section(metadata)
  records_by_role = metadata.fetch(:approval_records).to_h { |record| [record.fetch("role"), record] }
  immutable_revision = metadata.fetch(:immutable_revision)
  source = +ADR_0009_REVIEWS_HEADING
  source << "\n"
  source << ADR_0009_ACCEPTED_REVIEWS_INTRO
  source << "\n"
  source << ADR_0009_ACCEPTED_REVIEW_HEADER
  source << ADR_0009_ACCEPTED_REVIEW_DELIMITER
  source << "| Decision author (WS-03) | `/root/adr_cand_008` | `#{immutable_revision}` | AUTHOR - NOT APPROVAL | Authored decision; author cannot approve |\n"
  ADR_0009_ACCEPTED_REVIEW_ROLES.each do |definition|
    record = records_by_role.fetch(definition.fetch(:role))
    source << "| #{definition.fetch(:label)} | `#{record.fetch('identity')}` | `#{immutable_revision}` | " \
              "#{record.fetch('disposition')} | #{definition.fetch(:evidence)} |\n"
  end
  source << "\n"
  source
end

def adr_0009_approval_record_fixture(metadata)
  immutable_revision = metadata.fetch(:immutable_revision)
  records_by_role = metadata.fetch(:approval_records).to_h { |record| [record.fetch("role"), record] }
  source = +"# ADR-0009 approval record\n\n"
  source << "Status: **APPROVED**\n\n"
  source << "- **Immutable decision revision:** `#{immutable_revision}`\n"
  source << "- **Approval scope:** ADR-CAND-008 only; implementation and release evidence remain separately gated.\n\n"
  source << "## Exact-revision dispositions\n\n"
  source << ADR_0009_ACCEPTED_REVIEW_HEADER
  source << ADR_0009_ACCEPTED_REVIEW_DELIMITER
  ADR_0009_ACCEPTED_REVIEW_ROLES.each do |definition|
    record = records_by_role.fetch(definition.fetch(:role))
    source << "| #{definition.fetch(:label)} | `#{record.fetch('identity')}` | `#{immutable_revision}` | " \
              "#{record.fetch('disposition')} | #{definition.fetch(:evidence)} |\n"
  end
  source
end

def adr_0009_accepted_adr_fixture(proposed_source, metadata)
  accepted = proposed_source
             .sub(ADR_0009_PROPOSED_STATUS_LINE, adr_0009_accepted_status_line(metadata))
             .sub(ADR_0009_PROPOSED_RESOLUTION_LINE, ADR_0009_ACCEPTED_RESOLUTION_LINE)
  reviews_offset = accepted.index(ADR_0009_REVIEWS_HEADING)
  footnotes_offset = accepted.index(ADR_0009_FOOTNOTE_MARKER, reviews_offset.to_i)
  return accepted unless reviews_offset && footnotes_offset

  accepted[0...reviews_offset] + adr_0009_accepted_reviews_section(metadata) + accepted[footnotes_offset..]
end

def adr_0009_catalog_gate_from_source(source, filename:)
  catalog = parse_yaml(source, filename: filename)
  gates = catalog.fetch("adr_decision_gates")
  return [nil, ["#{filename}: adr_decision_gates must be an array"]] unless gates.is_a?(Array)

  matching = gates.select { |gate| gate.is_a?(Hash) && gate["adr_id"] == "ADR-CAND-008" }
  return [nil, ["#{filename}: must contain exactly one ADR-CAND-008 gate"]] unless matching.length == 1

  [matching.first, []]
rescue KeyError, Psych::Exception, TypeError => error
  [nil, ["#{filename}: cannot parse ADR-CAND-008 gate: #{error.class}"]]
end

def adr_0009_accepted_catalog_source_fixture(parent_source, metadata)
  unless parent_source.is_a?(String) && parent_source.valid_encoding? &&
         parent_source.bytesize <= ADR_0009_ACCEPTANCE_SNAPSHOT_MAX_BYTES
    return [nil, ["ADR-0009 Proposed catalog source fixture is unavailable, invalid, or oversized"]]
  end

  header = "  - adr_id: ADR-CAND-008\n"
  offsets = parent_source.enum_for(:scan, /^#{Regexp.escape(header)}/).map { Regexp.last_match.begin(0) }
  return [nil, ["ADR-0009 Proposed catalog source must contain one canonical gate header"]] unless offsets.length == 1

  block_start = offsets.first
  next_header = parent_source.match(/^  - adr_id: /, block_start + header.bytesize)
  return [nil, ["ADR-0009 Proposed catalog gate must have a bounded successor"]] unless next_header

  block = parent_source[block_start...next_header.begin(0)]
  proposed_state = "    state: PROPOSED\n"
  premature = %w[immutable_revision accepted_at approval_record approval_records].select do |field|
    block.match?(/^    #{Regexp.escape(field)}:/)
  end
  unless block.lines.count(proposed_state) == 1 && premature.empty?
    return [nil, ["ADR-0009 Proposed catalog gate has noncanonical state or premature acceptance fields"]]
  end

  accepted_fields = +"    state: ACCEPTED\n"
  accepted_fields << "    immutable_revision: #{JSON.generate(metadata.fetch(:immutable_revision))}\n"
  accepted_fields << "    accepted_at: #{JSON.generate(metadata.fetch(:accepted_at))}\n"
  accepted_fields << "    approval_record: #{JSON.generate(metadata.fetch(:approval_record_path))}\n"
  accepted_fields << "    approval_records:\n"
  metadata.fetch(:approval_records).each do |record|
    accepted_fields << "      - {role: #{JSON.generate(record.fetch('role'))}, " \
                       "identity: #{JSON.generate(record.fetch('identity'))}, " \
                       "disposition: #{JSON.generate(record.fetch('disposition'))}}\n"
  end
  accepted_block = block.sub(proposed_state, accepted_fields)
  [parent_source[0...block_start] + accepted_block + parent_source[next_header.begin(0)..], []]
rescue KeyError, TypeError => error
  [nil, ["ADR-0009 accepted catalog source fixture failed: #{error.class}"]]
end

def adr_0009_catalog_transition_failures(parent_source:, child_source:, metadata:)
  failures = []
  expected_child_source, source_failures = adr_0009_accepted_catalog_source_fixture(parent_source, metadata)
  failures.concat(source_failures)
  if expected_child_source && child_source != expected_child_source
    failures << "ADR-0009 acceptance catalog child must exactly match the metadata-derived canonical source"
  end

  parent_catalog = parse_yaml(parent_source, filename: "ADR-0009 immutable parent catalog fixture")
  child_catalog = parse_yaml(child_source, filename: "ADR-0009 acceptance child catalog fixture")
  parent_gates = parent_catalog.fetch("adr_decision_gates")
  child_gates = child_catalog.fetch("adr_decision_gates")
  unless parent_gates.is_a?(Array) && child_gates.is_a?(Array)
    return ["ADR-0009 acceptance catalog transition requires gate arrays"]
  end
  parent_indices = parent_gates.each_index.select do |index|
    parent_gates[index].is_a?(Hash) && parent_gates[index]["adr_id"] == "ADR-CAND-008"
  end
  child_indices = child_gates.each_index.select do |index|
    child_gates[index].is_a?(Hash) && child_gates[index]["adr_id"] == "ADR-CAND-008"
  end
  return ["ADR-0009 acceptance catalog transition must preserve one gate at the same position"] unless parent_indices.length == 1 && child_indices == parent_indices

  gate_index = parent_indices.first
  parent_gate = parent_gates.fetch(gate_index)
  child_gate = child_gates.fetch(gate_index)
  failures << "ADR-0009 acceptance catalog parent gate must be PROPOSED" unless parent_gate["state"] == "PROPOSED"
  premature = %w[immutable_revision accepted_at approval_record approval_records].select { |field| parent_gate.key?(field) }
  failures << "ADR-0009 acceptance catalog parent has premature fields: #{premature.join(', ')}" unless premature.empty?
  expected_child_gate = parent_gate.merge(
    "state" => "ACCEPTED",
    "immutable_revision" => metadata.fetch(:immutable_revision),
    "accepted_at" => metadata.fetch(:accepted_at),
    "approval_record" => metadata.fetch(:approval_record_path),
    "approval_records" => metadata.fetch(:approval_records)
  )
  failures << "ADR-0009 acceptance catalog child may change only exact metadata-derived gate fields" unless child_gate == expected_child_gate
  normalized_child = Marshal.load(Marshal.dump(child_catalog))
  normalized_child.fetch("adr_decision_gates")[gate_index] = parent_gate
  failures << "ADR-0009 acceptance catalog child changes unrelated catalog semantics" unless normalized_child == parent_catalog
  failures
rescue KeyError, Psych::Exception, TypeError => error
  failures << "ADR-0009 acceptance catalog transition cannot be compared: #{error.class}"
  failures
end

def adr_0009_acceptance_transition_change_failures(changes)
  unless changes.is_a?(Hash) && changes.keys.all? { |path| path.is_a?(String) } &&
         changes.values.all? { |status| status.is_a?(String) }
    return ["ADR-0009 acceptance transition change inventory is malformed"]
  end

  failures = []
  unexpected = changes.keys - ADR_0009_ACCEPTANCE_TRANSITION_CHANGES.keys
  failures << "ADR-0009 acceptance transition changes paths outside the closed approval/gate/review allowlist: #{unexpected.sort.join(', ')}" unless unexpected.empty?
  missing = ADR_0009_ACCEPTANCE_TRANSITION_CHANGES.keys - changes.keys
  failures << "ADR-0009 acceptance transition omits required record paths: #{missing.sort.join(', ')}" unless missing.empty?
  wrong = ADR_0009_ACCEPTANCE_TRANSITION_CHANGES.filter_map do |path, expected_status|
    actual_status = changes[path]
    "#{path}=#{actual_status.inspect} (expected #{expected_status})" if actual_status && actual_status != expected_status
  end
  failures << "ADR-0009 acceptance transition has noncanonical record changes: #{wrong.join(', ')}" unless wrong.empty?
  failures
end

def adr_0009_expected_index_transition(path:, parent_source:, metadata:)
  unless parent_source.is_a?(String) && parent_source.valid_encoding? &&
         parent_source.bytesize <= ADR_0009_ACCEPTANCE_SNAPSHOT_MAX_BYTES
    return [nil, ["ADR-0009 #{path} Proposed parent fixture is unavailable, invalid, or oversized"]]
  end

  immutable_revision = metadata.fetch(:immutable_revision)
  accepted_at = metadata.fetch(:accepted_at)
  lines = parent_source.lines
  case path
  when ADR_0009_ADR_INDEX_PATH
    accepted_rows = lines.select { |line| line.start_with?("| Accepted |") }
    proposed_rows = lines.select { |line| line.start_with?("| Proposed |") }
    unless accepted_rows.length == 1 && proposed_rows.length == 1 &&
           proposed_rows.first.include?("ADR-0009") && proposed_rows.first.include?("ADR-CAND-008")
      return [nil, ["ADR-0009 ADR index parent rows are not canonical"]]
    end
    accepted_base = accepted_rows.first.delete_suffix(" |\n")
    addition =
      " [ADR-0009: Gitea provider reconciliation precedence and conflict handling]" \
      "(./0009-gitea-provider-reconciliation-precedence-and-conflict-handling.md) (`ADR-CAND-008`) is accepted " \
      "at immutable decision revision `#{immutable_revision}` with explicit project-owner approval; implementation evidence remains separately gated."
    expected = parent_source.sub(accepted_rows.first, "#{accepted_base}#{addition} |\n")
    expected = expected.sub(proposed_rows.first, "| Proposed | None. |\n")
    [expected, []]
  when ADR_0009_CHOICE_QUEUE_PATH
    unless lines.count(ADR_0009_CHOICE_QUEUE_PROPOSED_STATUS) == 1
      return [nil, ["ADR-0009 choice queue parent status is not canonical"]]
    end
    candidate_rows = lines.select { |line| line.start_with?("| `ADR-CAND-008` Provider reconciliation conflict semantics |") }
    insertion_rows = lines.select { |line| line.start_with?("| `ADR-CAND-021` Initial Team relation model |") }
    unless candidate_rows.length == 1 && insertion_rows.length == 1
      return [nil, ["ADR-0009 choice queue parent candidate rows are not canonical"]]
    end
    cells = adr_0008_markdown_table_cells(candidate_rows.first)
    return [nil, ["ADR-0009 choice queue candidate row is malformed"]] unless cells&.length == 3

    selected = cells[1].sub(" proposes ", " selects ")
                       .sub("On acceptance it would supersede", "It supersedes")
                       .sub("; it is non-operative while Proposed.", ".")
    return [nil, ["ADR-0009 choice queue row omits canonical proposal wording"]] if selected == cells[1]

    accepted_row = "| #{cells[0]} | `ACCEPTED` on #{accepted_at} at `#{immutable_revision}` with explicit project-owner approval | #{selected} |\n"
    expected = parent_source.sub(ADR_0009_CHOICE_QUEUE_PROPOSED_STATUS, ADR_0009_CHOICE_QUEUE_ACCEPTED_STATUS)
    expected = expected.sub(insertion_rows.first, accepted_row + insertion_rows.first)
    expected = expected.sub(candidate_rows.first, "| None. | None. | None. |\n")
    [expected, []]
  when ADR_0009_CANDIDATE_INDEX_PATH
    unless lines.count(ADR_0009_CANDIDATE_INDEX_PROPOSED_STATUS) == 1
      return [nil, ["ADR-0009 candidate index parent status is not canonical"]]
    end
    candidate_rows = lines.select { |line| line.start_with?("| `ADR-CAND-008` |") }
    return [nil, ["ADR-0009 candidate index parent row is not canonical"]] unless candidate_rows.length == 1

    cells = adr_0008_markdown_table_cells(candidate_rows.first)
    return [nil, ["ADR-0009 candidate index row is malformed"]] unless cells&.length == 4

    accepted_note = cells[3]
                    .sub("The revised proposal selects", "The accepted decision selects")
                    .sub("It would supersede", "It supersedes")
                    .sub(
                      "Required WS-01/02/03/06/07/12, distinct WS-13 reviews, and explicit project-owner approval must name the same exact immutable commit SHA; none is yet recorded.",
                      "Decision-time reviews and explicit project-owner approval are recorded at the immutable revision; implementation evidence remains separately gated."
                    )
    if accepted_note == cells[3] || accepted_note.include?("none is yet recorded")
      return [nil, ["ADR-0009 candidate index row omits canonical pending-review wording"]]
    end
    accepted_row =
      "| #{cells[0]} | **RESOLVED by accepted [ADR-0009]" \
      "(../adr/0009-gitea-provider-reconciliation-precedence-and-conflict-handling.md) at `#{immutable_revision}` " \
      "with explicit project-owner approval** | #{cells[2]} | #{accepted_note} |\n"
    expected = parent_source.sub(
      ADR_0009_CANDIDATE_INDEX_PROPOSED_STATUS,
      ADR_0009_CANDIDATE_INDEX_ACCEPTED_STATUS
    )
    expected = expected.sub(candidate_rows.first, accepted_row)
    [expected, []]
  else
    [nil, ["ADR-0009 acceptance index path is outside the closed record set: #{path}"]]
  end
rescue KeyError, TypeError => error
  [nil, ["ADR-0009 acceptance index fixture failed: #{error.class}"]]
end

def adr_0009_acceptance_surface_failures(
  current_adr_source:,
  proposed_adr_source:,
  gate:,
  approval_record:,
  metadata:
)
  failures = adr_0009_acceptance_metadata_failures(metadata)
  return failures unless failures.empty?

  expected_adr_source = adr_0009_accepted_adr_fixture(proposed_adr_source, metadata)
  unless current_adr_source == expected_adr_source
    failures << "ADR-0009 accepted decision record must exactly match the metadata-derived records-only transition"
  end
  failures.concat(adr_0009_decision_body_failures(current_adr_source))
  failures.concat(adr_0009_semantic_contract_failures(current_adr_source))

  unless gate.is_a?(Hash)
    failures << "ADR-0009 accepted catalog gate must be a mapping"
    return failures
  end
  failures << "ADR-0009 accepted catalog gate state must be ACCEPTED" unless gate["state"] == "ACCEPTED"
  failures << "ADR-0009 accepted catalog project-owner gate must remain true" unless gate["project_owner_approval_required"] == true
  failures << "ADR-0009 accepted catalog immutable revision mismatch" unless gate["immutable_revision"] == metadata.fetch(:immutable_revision)
  failures << "ADR-0009 accepted catalog date mismatch" unless gate["accepted_at"] == metadata.fetch(:accepted_at)
  failures << "ADR-0009 accepted catalog approval record mismatch" unless gate["approval_record"] == metadata.fetch(:approval_record_path)
  failures << "ADR-0009 accepted catalog approval records mismatch" unless gate["approval_records"] == metadata.fetch(:approval_records)

  expected_approval_record = adr_0009_approval_record_fixture(metadata)
  unless approval_record == expected_approval_record
    failures << "ADR-0009 approval record must exactly match the metadata-derived exact-revision dispositions and end after its final row"
  end
  failures
end

def adr_0009_acceptance_graph_failures(
  immutable_revision:,
  repository_available:,
  shallow:,
  head_revision:,
  commits:,
  acceptance_transitions:
)
  return ["ADR-0009 acceptance history immutable revision must be exactly 40 lowercase hexadecimal characters"] unless adr_0009_exact_revision?(immutable_revision)
  return ["ADR-0009 acceptance history repository is unavailable"] unless repository_available
  return ["ADR-0009 acceptance history is shallow and cannot prove the immutable transition"] if shallow

  failures = []
  unless adr_0009_exact_revision?(head_revision)
    return ["ADR-0009 acceptance history HEAD must resolve to one exact commit"]
  end
  unless commits.is_a?(Hash) && commits.length <= ADR_0009_ACCEPTANCE_HISTORY_MAX_COMMITS &&
         commits.keys.all? { |revision| adr_0009_exact_revision?(revision) } &&
         commits.values.all? { |parents| parents.is_a?(Array) && parents.all? { |revision| adr_0009_exact_revision?(revision) } }
    return ["ADR-0009 acceptance history contains a malformed or oversized commit graph"]
  end
  return ["ADR-0009 immutable decision revision does not exist in the available Git history"] unless commits.key?(immutable_revision)
  return ["ADR-0009 acceptance history does not contain HEAD"] unless commits.key?(head_revision)

  reachable = Set.new
  pending = [head_revision]
  until pending.empty?
    revision = pending.pop
    next if reachable.include?(revision)

    reachable << revision
    pending.concat(commits.fetch(revision, []))
    return ["ADR-0009 acceptance history reachability exceeds its closed commit bound"] if reachable.length > ADR_0009_ACCEPTANCE_HISTORY_MAX_COMMITS
  end
  return ["ADR-0009 immutable decision revision is not an ancestor of HEAD"] unless reachable.include?(immutable_revision)

  unless acceptance_transitions.is_a?(Array) && acceptance_transitions.uniq == acceptance_transitions &&
         acceptance_transitions.all? { |revision| adr_0009_exact_revision?(revision) && commits.key?(revision) }
    return ["ADR-0009 acceptance transition set is malformed or ambiguous"]
  end
  reachable_transitions = acceptance_transitions.select { |revision| reachable.include?(revision) }
  unless reachable_transitions.length == 1
    return ["ADR-0009 acceptance history must contain exactly one reachable mechanical acceptance transition"]
  end
  transition = reachable_transitions.first
  unless commits.fetch(transition) == [immutable_revision]
    failures << "ADR-0009 mechanical acceptance transition must be the single-parent immediate child of the immutable decision revision"
  end
  failures
end

def adr_0009_proposed_decision_snapshot_failures(revision)
  failures = []
  adr_source, adr_error = adr_0008_git_file_at(revision, ADR_0009_DECISION_RECORD_PATH)
  catalog_source, catalog_error = adr_0008_git_file_at(revision, ADR_0009_ISSUE_CATALOG_PATH)
  failures << adr_error if adr_error
  failures << catalog_error if catalog_error
  return failures unless failures.empty?

  failures.concat(adr_0009_decision_body_failures(adr_source))
  failures.concat(adr_0009_semantic_contract_failures(adr_source))
  gate, gate_failures = adr_0009_catalog_gate_from_source(
    catalog_source,
    filename: "#{ADR_0009_ISSUE_CATALOG_PATH}@#{revision}"
  )
  failures.concat(gate_failures)
  if gate
    failures.concat(
      adr_0009_governance_gate_failures(
        source: adr_source,
        gate: gate,
        gate_count: 1
      )
    )
  end
  approval = adr_0008_git_capture("cat-file", "-e", "#{revision}:#{ADR_0009_APPROVAL_RECORD_PATH}")
  failures << "ADR-0009 immutable decision parent must not contain an acceptance approval record" if approval.fetch(:success)
  failures
end

def adr_0009_accepted_transition_snapshot_failures(revision, metadata)
  failures = []
  immutable_revision = metadata.fetch(:immutable_revision)
  current_adr, current_adr_error = adr_0008_git_file_at(revision, ADR_0009_DECISION_RECORD_PATH)
  proposed_adr, proposed_adr_error = adr_0008_git_file_at(immutable_revision, ADR_0009_DECISION_RECORD_PATH)
  current_catalog, current_catalog_error = adr_0008_git_file_at(revision, ADR_0009_ISSUE_CATALOG_PATH)
  proposed_catalog, proposed_catalog_error = adr_0008_git_file_at(immutable_revision, ADR_0009_ISSUE_CATALOG_PATH)
  approval_record, approval_error = adr_0008_git_file_at(revision, metadata.fetch(:approval_record_path))
  [current_adr_error, proposed_adr_error, current_catalog_error, proposed_catalog_error, approval_error].compact.each do |error|
    failures << error
  end
  return failures unless failures.empty?

  gate, gate_failures = adr_0009_catalog_gate_from_source(
    current_catalog,
    filename: "#{ADR_0009_ISSUE_CATALOG_PATH}@#{revision}"
  )
  failures.concat(gate_failures)
  if gate
    failures.concat(
      adr_0009_acceptance_surface_failures(
        current_adr_source: current_adr,
        proposed_adr_source: proposed_adr,
        gate: gate,
        approval_record: approval_record,
        metadata: metadata
      )
    )
  end
  failures.concat(
    adr_0009_catalog_transition_failures(
      parent_source: proposed_catalog,
      child_source: current_catalog,
      metadata: metadata
    )
  )

  diff = adr_0008_git_capture(
    "diff-tree",
    "--no-commit-id",
    "--name-status",
    "-r",
    immutable_revision,
    revision
  )
  unless diff.fetch(:success)
    failures << "ADR-0009 acceptance transition diff is unavailable: #{adr_0008_git_failure(diff)}"
    return failures
  end
  changes = {}
  malformed = false
  diff.fetch(:stdout).lines.each do |line|
    fields = line.chomp.split("\t", -1)
    unless fields.length == 2 && fields[0].match?(/\A[A-Z]\z/) && !fields[1].empty?
      malformed = true
      next
    end
    malformed = true if changes.key?(fields[1])
    changes[fields[1]] = fields[0]
  end
  failures << "ADR-0009 acceptance transition Git diff contains a malformed or duplicate path" if malformed
  failures.concat(adr_0009_acceptance_transition_change_failures(changes))

  [ADR_0009_ADR_INDEX_PATH, ADR_0009_CHOICE_QUEUE_PATH, ADR_0009_CANDIDATE_INDEX_PATH].each do |path|
    parent_source, parent_error = adr_0008_git_file_at(immutable_revision, path)
    child_source, child_error = adr_0008_git_file_at(revision, path)
    failures << parent_error if parent_error
    failures << child_error if child_error
    next if parent_error || child_error

    expected_source, expected_failures = adr_0009_expected_index_transition(
      path: path,
      parent_source: parent_source,
      metadata: metadata
    )
    failures.concat(expected_failures)
    if expected_source && child_source != expected_source
      failures << "ADR-0009 acceptance transition changes unrelated #{path} content or omits exact accepted wording"
    end
  end
  failures
end

def adr_0009_parse_git_commit_lines(lines)
  commits = {}
  failures = []
  lines.each do |line|
    fields = line.split
    unless fields.any? && fields.all? { |revision| adr_0009_exact_revision?(revision) }
      failures << "ADR-0009 acceptance history contains malformed Git revision output"
      next
    end
    revision = fields.first
    parents = fields.drop(1)
    if commits.key?(revision) && commits.fetch(revision) != parents
      failures << "ADR-0009 acceptance history contains conflicting parent records"
    else
      commits[revision] = parents
    end
  end
  [commits, failures]
end

def adr_0009_live_acceptance_history_failures(metadata)
  metadata_failures = adr_0009_acceptance_metadata_failures(metadata)
  return metadata_failures unless metadata_failures.empty?

  immutable_revision = metadata.fetch(:immutable_revision)
  inside = adr_0008_git_capture("rev-parse", "--is-inside-work-tree")
  unless inside.fetch(:success) && inside.fetch(:stdout) == "true\n"
    return ["ADR-0009 acceptance history repository is unavailable: #{adr_0008_git_failure(inside)}"]
  end
  shallow_result = adr_0008_git_capture("rev-parse", "--is-shallow-repository")
  unless shallow_result.fetch(:success) && ["true\n", "false\n"].include?(shallow_result.fetch(:stdout))
    return ["ADR-0009 acceptance history cannot determine shallow state: #{adr_0008_git_failure(shallow_result)}"]
  end
  return ["ADR-0009 acceptance history is shallow and cannot prove the immutable transition"] if shallow_result.fetch(:stdout) == "true\n"

  decision_result = adr_0008_git_capture("rev-parse", "--verify", "#{immutable_revision}^{commit}")
  unless decision_result.fetch(:success) && decision_result.fetch(:stdout) == "#{immutable_revision}\n"
    return ["ADR-0009 immutable decision revision does not resolve to the exact available commit"]
  end
  head_result = adr_0008_git_capture("rev-parse", "--verify", "HEAD^{commit}")
  unless head_result.fetch(:success) && adr_0009_exact_revision?(head_result.fetch(:stdout).strip)
    return ["ADR-0009 acceptance history HEAD does not resolve to one exact commit"]
  end
  head_revision = head_result.fetch(:stdout).strip
  ancestor = adr_0008_git_capture("merge-base", "--is-ancestor", immutable_revision, head_revision)
  unless ancestor.fetch(:success)
    return ["ADR-0009 immutable decision revision is not an ancestor of HEAD"] if ancestor.fetch(:exitstatus) == 1

    return ["ADR-0009 acceptance history cannot prove ancestry: #{adr_0008_git_failure(ancestor)}"]
  end

  range = adr_0008_git_capture(
    "rev-list",
    "--parents",
    "--ancestry-path",
    "--max-count=#{ADR_0009_ACCEPTANCE_HISTORY_MAX_COMMITS + 1}",
    "#{immutable_revision}..#{head_revision}"
  )
  return ["ADR-0009 acceptance history cannot enumerate the decision ancestry path: #{adr_0008_git_failure(range)}"] unless range.fetch(:success)
  range_lines = range.fetch(:stdout).lines
  return ["ADR-0009 acceptance history exceeds its closed commit bound"] if range_lines.length > ADR_0009_ACCEPTANCE_HISTORY_MAX_COMMITS

  decision_line = adr_0008_git_capture("rev-list", "--parents", "--max-count=1", immutable_revision)
  unless decision_line.fetch(:success) && decision_line.fetch(:stdout).lines.length == 1
    return ["ADR-0009 acceptance history cannot read the immutable decision parent record"]
  end
  commits, parse_failures = adr_0009_parse_git_commit_lines(range_lines + decision_line.fetch(:stdout).lines)
  return parse_failures unless parse_failures.empty?

  proposed_failures = adr_0009_proposed_decision_snapshot_failures(immutable_revision)
  unless proposed_failures.empty?
    return proposed_failures.map { |failure| "ADR-0009 immutable decision parent invalid: #{failure}" }
  end
  direct_children = commits.filter_map { |revision, parents| revision if parents.include?(immutable_revision) }
  snapshots = {}
  transitions = direct_children.filter_map do |revision|
    child_failures = adr_0009_accepted_transition_snapshot_failures(revision, metadata)
    snapshots[revision] = child_failures
    revision if child_failures.empty?
  end
  history_failures = adr_0009_acceptance_graph_failures(
    immutable_revision: immutable_revision,
    repository_available: true,
    shallow: false,
    head_revision: head_revision,
    commits: commits,
    acceptance_transitions: transitions
  )
  if transitions.empty? && snapshots.any?
    detail = snapshots.sort_by(&:first).first(3).map { |revision, child_failures| "#{revision}: #{child_failures.first}" }
    history_failures << "ADR-0009 direct-child acceptance snapshots failed: #{detail.join('; ')}"
  end
  history_failures
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

def adr_0008_markdown_table_cells(line)
  return nil unless line.is_a?(String) && line.start_with?("|") && line.end_with?("|\n")

  line.chomp.split("|", -1)[1...-1].to_a.map(&:strip)
end

def adr_0008_expected_index_transition(path:, parent_source:, metadata:)
  unless parent_source.is_a?(String) && parent_source.valid_encoding? &&
         parent_source.bytesize <= ADR_0008_ACCEPTANCE_SNAPSHOT_MAX_BYTES
    return [nil, ["ADR-0008 #{path} Proposed parent fixture is unavailable, invalid, or oversized"]]
  end

  immutable_revision = metadata.fetch(:immutable_revision)
  accepted_at = metadata.fetch(:accepted_at)
  lines = parent_source.lines

  case path
  when ADR_0008_ADR_INDEX_PATH
    accepted_rows = lines.select { |line| line.start_with?("| Accepted |") }
    proposed_rows = lines.select { |line| line.start_with?("| Proposed |") }
    unless accepted_rows.length == 1 && proposed_rows.length == 1 &&
           proposed_rows.first.include?("ADR-0008") && proposed_rows.first.include?("ADR-CAND-006")
      return [nil, ["ADR-0008 ADR index parent rows are not canonical"]]
    end

    accepted_row = accepted_rows.first
    accepted_base = accepted_row.delete_suffix(" |\n")
    accepted_addition =
      " [ADR-0008: NATS stream, subject, retention, replay, ordering, and dead-letter contract]" \
      "(./0008-nats-stream-subject-retention-replay-ordering-and-dlq.md) (`ADR-CAND-006`) is accepted " \
      "at immutable decision revision `#{immutable_revision}`; implementation evidence remains separately gated."
    expected = parent_source.sub(accepted_row, "#{accepted_base}#{accepted_addition} |\n")
    expected = expected.sub(proposed_rows.first, "| Proposed | None. |\n")
    [expected, []]
  when ADR_0008_CHOICE_QUEUE_PATH
    unless lines.count(ADR_0008_CHOICE_QUEUE_PROPOSED_STATUS) == 1
      return [nil, ["ADR-0008 choice queue parent status is not canonical"]]
    end
    candidate_rows = lines.select { |line| line.start_with?("| `ADR-CAND-006` ") }
    insertion_rows = lines.select { |line| line.start_with?("| `ADR-CAND-007` ") }
    unless candidate_rows.length == 1 && insertion_rows.length == 1
      return [nil, ["ADR-0008 choice queue parent candidate rows are not canonical"]]
    end
    cells = adr_0008_markdown_table_cells(candidate_rows.first)
    return [nil, ["ADR-0008 choice queue candidate row is malformed"]] unless cells&.length == 3

    selected_decision = cells[1].sub(" proposes ", " selects ")
    if selected_decision == cells[1]
      return [nil, ["ADR-0008 choice queue candidate row omits the canonical proposal verb"]]
    end
    accepted_row =
      "| #{cells[0]} | `ACCEPTED` on #{accepted_at} at `#{immutable_revision}` | #{selected_decision} |\n"
    expected = parent_source.sub(ADR_0008_CHOICE_QUEUE_PROPOSED_STATUS, ADR_0008_CHOICE_QUEUE_ACCEPTED_STATUS)
    expected = expected.sub(insertion_rows.first, accepted_row + insertion_rows.first)
    expected = expected.sub(candidate_rows.first, "")
    [expected, []]
  when ADR_0008_CANDIDATE_INDEX_PATH
    unless lines.count(ADR_0008_CANDIDATE_INDEX_PROPOSED_STATUS) == 1
      return [nil, ["ADR-0008 candidate index parent status is not canonical"]]
    end
    candidate_rows = lines.select { |line| line.start_with?("| `ADR-CAND-006` |") }
    return [nil, ["ADR-0008 candidate index parent row is not canonical"]] unless candidate_rows.length == 1

    cells = adr_0008_markdown_table_cells(candidate_rows.first)
    return [nil, ["ADR-0008 candidate index row is malformed"]] unless cells&.length == 4

    old_review_sentence = "Required non-author reviews and immutable-revision acceptance remain open."
    new_review_sentence =
      "Decision-time reviews are recorded at the immutable revision; implementation evidence remains separately gated."
    accepted_note = cells[3].sub(old_review_sentence, new_review_sentence)
    if accepted_note == cells[3]
      return [nil, ["ADR-0008 candidate index row omits the canonical open-review sentence"]]
    end
    accepted_row =
      "| #{cells[0]} | **RESOLVED by accepted [ADR-0008]" \
      "(../adr/0008-nats-stream-subject-retention-replay-ordering-and-dlq.md) at `#{immutable_revision}`** | " \
      "#{cells[2]} | #{accepted_note} |\n"
    expected = parent_source.sub(
      ADR_0008_CANDIDATE_INDEX_PROPOSED_STATUS,
      ADR_0008_CANDIDATE_INDEX_ACCEPTED_STATUS
    )
    expected = expected.sub(candidate_rows.first, accepted_row)
    [expected, []]
  else
    [nil, ["ADR-0008 acceptance index path is outside the closed record set: #{path}"]]
  end
end

def adr_0008_index_transition_failures(path:, parent_source:, child_source:, metadata:)
  expected_source, expectation_failures = adr_0008_expected_index_transition(
    path: path,
    parent_source: parent_source,
    metadata: metadata
  )
  return expectation_failures unless expectation_failures.empty?

  return [] if child_source == expected_source

  ["ADR-0008 acceptance transition changes unrelated #{path} content or omits exact accepted wording"]
end

def adr_0008_acceptance_surface_failures(adr_source:, gate:, approval_record:, metadata:)
  failures = adr_0008_acceptance_metadata_failures(metadata)
  return failures unless failures.empty?

  immutable_revision = metadata.fetch(:immutable_revision)
  failures.concat(adr_0008_substantive_source_failures(adr_source, acceptance_metadata: metadata))

  unless gate.is_a?(Hash)
    failures << "ADR-0008 accepted catalog gate must be a mapping"
    return failures
  end
  failures << "ADR-0008 accepted catalog gate state must be ACCEPTED" unless gate["state"] == "ACCEPTED"
  unless gate["immutable_revision"] == immutable_revision
    failures << "ADR-0008 accepted catalog immutable revision must derive from acceptance metadata"
  end
  unless gate["accepted_at"] == metadata.fetch(:accepted_at)
    failures << "ADR-0008 accepted catalog date must derive from acceptance metadata"
  end
  unless gate["approval_record"] == metadata.fetch(:approval_record_path)
    failures << "ADR-0008 accepted catalog approval record must derive from acceptance metadata"
  end
  unless gate["approval_records"] == metadata.fetch(:approval_records)
    failures << "ADR-0008 accepted catalog review records must derive from acceptance metadata"
  end

  unless approval_record.is_a?(String)
    failures << "ADR-0008 accepted approval record must exist"
    return failures
  end
  canonical_approval_record = adr_0008_approval_record_fixture(metadata)
  unless approval_record == canonical_approval_record
    failures << "ADR-0008 approval record must exactly match the metadata-derived canonical document and end after its final row"
  end

  failures
end

def adr_0008_acceptance_graph_failures(
  immutable_revision:,
  repository_available:,
  shallow:,
  head_revision:,
  commits:,
  acceptance_transitions:
)
  failures = []
  unless adr_0008_exact_revision?(immutable_revision)
    return ["ADR-0008 acceptance history immutable revision must be exactly 40 lowercase hexadecimal characters"]
  end
  return ["ADR-0008 acceptance history repository is unavailable"] unless repository_available
  return ["ADR-0008 acceptance history is shallow and cannot prove the immutable transition"] if shallow

  unless adr_0008_exact_revision?(head_revision)
    failures << "ADR-0008 acceptance history HEAD must resolve to one exact commit"
    return failures
  end
  unless commits.is_a?(Hash) && commits.length <= ADR_0008_ACCEPTANCE_HISTORY_MAX_COMMITS
    failures << "ADR-0008 acceptance history exceeds its closed commit bound"
    return failures
  end
  unless commits.keys.all? { |revision| adr_0008_exact_revision?(revision) } &&
         commits.values.all? do |parents|
           parents.is_a?(Array) && parents.all? { |revision| adr_0008_exact_revision?(revision) }
         end
    failures << "ADR-0008 acceptance history contains a malformed commit graph"
    return failures
  end
  unless commits.key?(immutable_revision)
    failures << "ADR-0008 immutable decision revision does not exist in the available Git history"
    return failures
  end
  unless commits.key?(head_revision)
    failures << "ADR-0008 acceptance history does not contain HEAD"
    return failures
  end

  reachable = Set.new
  pending = [head_revision]
  until pending.empty?
    revision = pending.pop
    next if reachable.include?(revision)

    reachable << revision
    pending.concat(commits.fetch(revision, []))
    if reachable.length > ADR_0008_ACCEPTANCE_HISTORY_MAX_COMMITS
      failures << "ADR-0008 acceptance history reachability exceeds its closed commit bound"
      return failures
    end
  end
  unless reachable.include?(immutable_revision)
    failures << "ADR-0008 immutable decision revision is not an ancestor of HEAD"
    return failures
  end

  unless acceptance_transitions.is_a?(Array) && acceptance_transitions.uniq == acceptance_transitions &&
         acceptance_transitions.all? { |revision| adr_0008_exact_revision?(revision) && commits.key?(revision) }
    failures << "ADR-0008 acceptance transition set is malformed or ambiguous"
    return failures
  end
  reachable_transitions = acceptance_transitions.select { |revision| reachable.include?(revision) }
  unless reachable_transitions.length == 1
    failures << "ADR-0008 acceptance history must contain exactly one reachable mechanical acceptance transition"
    return failures
  end

  transition_revision = reachable_transitions.first
  unless commits.fetch(transition_revision) == [immutable_revision]
    failures << "ADR-0008 mechanical acceptance transition must be the single-parent immediate child of the immutable decision revision"
  end

  failures
end

def adr_0008_approval_record_fixture(metadata)
  immutable_revision = metadata.fetch(:immutable_revision)
  records_by_role = metadata.fetch(:approval_records).to_h { |record| [record.fetch("role"), record] }
  source = +"# ADR-0008 approval record\n\n"
  source << "Status: **APPROVED**\n\n"
  source << "- **Immutable decision revision:** `#{immutable_revision}`\n\n"
  source << "## Exact-revision dispositions\n\n"
  source << ADR_0008_ACCEPTED_REVIEW_HEADER
  source << ADR_0008_ACCEPTED_REVIEW_DELIMITER
  ADR_0008_ACCEPTED_REVIEW_ROLES.each do |definition|
    record = records_by_role.fetch(definition.fetch(:role))
    source << "| #{definition.fetch(:label)} | `#{record.fetch('identity')}` | `#{immutable_revision}` | " \
              "#{record.fetch('disposition')} | #{definition.fetch(:evidence)} |\n"
  end
  source
end

def adr_0008_accepted_adr_fixture(proposed_source, metadata)
  accepted = proposed_source
             .sub(ADR_0008_PROPOSED_STATUS_LINE, adr_0008_accepted_status_line(metadata))
             .sub(ADR_0008_PROPOSED_RESOLUTION_LINE, ADR_0008_ACCEPTED_RESOLUTION_LINE)
  reviews_offset = accepted.index(ADR_0008_REVIEWS_HEADING)
  return accepted unless reviews_offset

  accepted[0, reviews_offset] + adr_0008_accepted_reviews_tail(metadata)
end

def adr_0008_accepted_catalog_gate_fixture(metadata)
  {
    "adr_id" => "ADR-CAND-006",
    "state" => "ACCEPTED",
    "immutable_revision" => metadata.fetch(:immutable_revision),
    "accepted_at" => metadata.fetch(:accepted_at),
    "approval_record" => metadata.fetch(:approval_record_path),
    "approval_records" => metadata.fetch(:approval_records)
  }
end

def adr_0008_accepted_catalog_source_fixture(parent_source, metadata)
  unless parent_source.is_a?(String) && parent_source.valid_encoding? &&
         parent_source.bytesize <= ADR_0008_ACCEPTANCE_SNAPSHOT_MAX_BYTES
    return [nil, ["ADR-0008 Proposed catalog source fixture is unavailable, invalid, or oversized"]]
  end

  header = "  - adr_id: ADR-CAND-006\n"
  header_offsets = parent_source.enum_for(:scan, /^#{Regexp.escape(header)}/).map { Regexp.last_match.begin(0) }
  return [nil, ["ADR-0008 Proposed catalog source must contain one canonical gate header"]] unless header_offsets.length == 1

  block_start = header_offsets.first
  next_header = parent_source.match(/^  - adr_id: /, block_start + header.bytesize)
  return [nil, ["ADR-0008 Proposed catalog gate must have a bounded successor"]] unless next_header

  block = parent_source[block_start...next_header.begin(0)]
  proposed_state = "    state: PROPOSED\n"
  premature_fields = %w[immutable_revision accepted_at approval_record approval_records].select do |field|
    block.match?(/^    #{Regexp.escape(field)}:/)
  end
  unless block.lines.count(proposed_state) == 1 && premature_fields.empty?
    return [nil, ["ADR-0008 Proposed catalog gate has noncanonical state or premature acceptance fields"]]
  end

  accepted_fields = +"    state: ACCEPTED\n"
  accepted_fields << "    immutable_revision: #{JSON.generate(metadata.fetch(:immutable_revision))}\n"
  accepted_fields << "    accepted_at: #{JSON.generate(metadata.fetch(:accepted_at))}\n"
  accepted_fields << "    approval_record: #{JSON.generate(metadata.fetch(:approval_record_path))}\n"
  accepted_fields << "    approval_records:\n"
  metadata.fetch(:approval_records).each do |record|
    accepted_fields << "      - {role: #{JSON.generate(record.fetch('role'))}, " \
                       "identity: #{JSON.generate(record.fetch('identity'))}, " \
                       "disposition: #{JSON.generate(record.fetch('disposition'))}}\n"
  end
  accepted_block = block.sub(proposed_state, accepted_fields)
  [parent_source[0...block_start] + accepted_block + parent_source[next_header.begin(0)..], []]
rescue KeyError, TypeError => error
  [nil, ["ADR-0008 accepted catalog source fixture failed: #{error.class}"]]
end

def adr_0008_substantive_source_failures(
  adr_source,
  acceptance_metadata: ACCEPTED_RECORD_METADATA["0008"]
)
  failures = []
  status_lines = adr_source.lines.select { |line| line.start_with?("- **Status:**") }
  if status_lines.length != 1
    failures << "ADR-0008 status must occur exactly once"
    return failures
  end

  status_line = status_lines.first
  state = acceptance_metadata.nil? ? :proposed : :accepted
  metadata_failures = state == :accepted ? adr_0008_acceptance_metadata_failures(acceptance_metadata) : []
  failures.concat(metadata_failures)
  return failures unless metadata_failures.empty?

  expected_status = if state == :accepted
                      adr_0008_accepted_status_line(acceptance_metadata)
                    else
                      ADR_0008_PROPOSED_STATUS_LINE
                    end
  unless status_line == expected_status
    status_source = state == :accepted ? "acceptance metadata" : "Proposed record state"
    failures << "ADR-0008 #{state} status must exactly match its #{status_source}"
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

  reviews_tail = adr_source[review_match.begin(0)..]
  if reviews_tail.bytesize > ADR_0008_REVIEWS_MAX_BYTES ||
     reviews_tail.lines.length > ADR_0008_REVIEWS_MAX_LINES
    failures << "ADR-0008 Reviews and approvals tail exceeds its closed resource bounds"
    return failures
  end

  if state == :proposed
    actual_reviews_sha256 = Digest::SHA256.hexdigest(reviews_tail)
    unless reviews_tail.bytesize == ADR_0008_PROPOSED_REVIEWS_BYTES &&
           actual_reviews_sha256 == ADR_0008_PROPOSED_REVIEWS_SHA256
      failures << "ADR-0008 proposed Reviews and approvals tail must match the exact pinned proposal"
    end
  else
    expected_reviews_tail = adr_0008_accepted_reviews_tail(acceptance_metadata)
    unless expected_reviews_tail.bytesize <= ADR_0008_REVIEWS_MAX_BYTES &&
           expected_reviews_tail.lines.length <= ADR_0008_REVIEWS_MAX_LINES
      failures << "ADR-0008 metadata-derived accepted Reviews and approvals tail exceeds its closed resource bounds"
      return failures
    end
    unless reviews_tail == expected_reviews_tail
      failures << "ADR-0008 accepted Reviews and approvals tail must match the exact metadata-derived table"
    end
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

def adr_0008_git_capture(*arguments, root: ROOT, environment: {})
  stdout, stderr, status = Open3.capture3(
    { "GIT_NO_REPLACE_OBJECTS" => "1", "GIT_OPTIONAL_LOCKS" => "0" }.merge(environment),
    "git",
    "-C",
    root.to_s,
    *arguments
  )
  {
    stdout: stdout,
    stderr: stderr,
    success: status.success?,
    exitstatus: status.exitstatus
  }
rescue Errno::ENOENT, SystemCallError => error
  {
    stdout: "",
    stderr: "#{error.class}: #{error.message}",
    success: false,
    exitstatus: nil
  }
end

def adr_0008_git_failure(result)
  detail = result.fetch(:stderr).to_s.lines.first.to_s.strip
  detail = "exit #{result.fetch(:exitstatus).inspect}" if detail.empty?
  detail.byteslice(0, 240)
end

def adr_0008_git_file_at(revision, path)
  result = adr_0008_git_capture("cat-file", "blob", "#{revision}:#{path}")
  return [nil, "#{path} is unavailable at #{revision}: #{adr_0008_git_failure(result)}"] unless result.fetch(:success)

  source = result.fetch(:stdout)
  if source.bytesize > ADR_0008_ACCEPTANCE_SNAPSHOT_MAX_BYTES
    return [nil, "#{path} at #{revision} exceeds the acceptance snapshot byte bound"]
  end
  unless source.valid_encoding?
    return [nil, "#{path} at #{revision} is not valid UTF-8"]
  end

  [source, nil]
end

def adr_0008_proposed_decision_snapshot_failures(revision)
  failures = []
  adr_source, adr_error = adr_0008_git_file_at(revision, ADR_0008_DECISION_RECORD_PATH)
  catalog_source, catalog_error = adr_0008_git_file_at(revision, ADR_0008_ISSUE_CATALOG_PATH)
  failures << adr_error if adr_error
  failures << catalog_error if catalog_error
  return failures unless failures.empty?

  failures.concat(adr_0008_substantive_source_failures(adr_source, acceptance_metadata: nil))
  gate, gate_failures = adr_0008_catalog_gate_from_source(
    catalog_source,
    filename: "#{ADR_0008_ISSUE_CATALOG_PATH}@#{revision}"
  )
  failures.concat(gate_failures)
  if gate
    failures << "ADR-0008 immutable decision parent catalog state must be PROPOSED" unless gate["state"] == "PROPOSED"
    premature_fields = %w[immutable_revision accepted_at approval_record approval_records].select { |field| gate.key?(field) }
    unless premature_fields.empty?
      failures << "ADR-0008 immutable decision parent catalog has premature acceptance fields: #{premature_fields.join(', ')}"
    end
  end

  approval = adr_0008_git_capture("cat-file", "-e", "#{revision}:#{ADR_0008_APPROVAL_RECORD_PATH}")
  if approval.fetch(:success)
    failures << "ADR-0008 immutable decision parent must not contain an acceptance approval record"
  end

  failures
end

def adr_0008_accepted_transition_snapshot_failures(revision, metadata)
  failures = []
  adr_source, adr_error = adr_0008_git_file_at(revision, ADR_0008_DECISION_RECORD_PATH)
  catalog_source, catalog_error = adr_0008_git_file_at(revision, ADR_0008_ISSUE_CATALOG_PATH)
  parent_catalog_source, parent_catalog_error = adr_0008_git_file_at(
    metadata.fetch(:immutable_revision),
    ADR_0008_ISSUE_CATALOG_PATH
  )
  approval_record, approval_error = adr_0008_git_file_at(revision, metadata.fetch(:approval_record_path))
  failures << adr_error if adr_error
  failures << catalog_error if catalog_error
  failures << parent_catalog_error if parent_catalog_error
  failures << approval_error if approval_error
  return failures unless failures.empty?

  gate, gate_failures = adr_0008_catalog_gate_from_source(
    catalog_source,
    filename: "#{ADR_0008_ISSUE_CATALOG_PATH}@#{revision}"
  )
  failures.concat(gate_failures)
  return failures unless gate

  failures.concat(
    adr_0008_acceptance_surface_failures(
      adr_source: adr_source,
      gate: gate,
      approval_record: approval_record,
      metadata: metadata
    )
  )
  failures.concat(
    adr_0008_catalog_transition_failures(
      parent_source: parent_catalog_source,
      child_source: catalog_source,
      metadata: metadata
    )
  )

  diff_result = adr_0008_git_capture(
    "diff-tree",
    "--no-commit-id",
    "--name-status",
    "-r",
    metadata.fetch(:immutable_revision),
    revision
  )
  unless diff_result.fetch(:success)
    failures << "ADR-0008 acceptance transition diff is unavailable: #{adr_0008_git_failure(diff_result)}"
    return failures
  end
  changes = {}
  malformed_change = false
  diff_result.fetch(:stdout).lines.each do |line|
    fields = line.chomp.split("\t", -1)
    unless fields.length == 2 && fields[0].match?(/\A[A-Z]\z/) && !fields[1].empty?
      malformed_change = true
      next
    end
    malformed_change = true if changes.key?(fields[1])
    changes[fields[1]] = fields[0]
  end
  failures << "ADR-0008 acceptance transition Git diff contains a malformed or duplicate path" if malformed_change
  failures.concat(adr_0008_acceptance_transition_change_failures(changes))

  [ADR_0008_ADR_INDEX_PATH, ADR_0008_CHOICE_QUEUE_PATH, ADR_0008_CANDIDATE_INDEX_PATH].each do |path|
    parent_source, parent_error = adr_0008_git_file_at(metadata.fetch(:immutable_revision), path)
    child_source, child_error = adr_0008_git_file_at(revision, path)
    failures << parent_error if parent_error
    failures << child_error if child_error
    next if parent_error || child_error

    failures.concat(
      adr_0008_index_transition_failures(
        path: path,
        parent_source: parent_source,
        child_source: child_source,
        metadata: metadata
      )
    )
  end
  failures
end

def adr_0008_parse_git_commit_lines(lines)
  commits = {}
  failures = []
  lines.each do |line|
    fields = line.split
    unless fields.any? && fields.all? { |revision| adr_0008_exact_revision?(revision) }
      failures << "ADR-0008 acceptance history contains malformed Git revision output"
      next
    end

    revision = fields.first
    parents = fields.drop(1)
    if commits.key?(revision) && commits.fetch(revision) != parents
      failures << "ADR-0008 acceptance history contains conflicting parent records"
    else
      commits[revision] = parents
    end
  end
  [commits, failures]
end

def adr_0008_live_acceptance_history_failures(metadata)
  metadata_failures = adr_0008_acceptance_metadata_failures(metadata)
  return metadata_failures unless metadata_failures.empty?

  immutable_revision = metadata.fetch(:immutable_revision)
  inside = adr_0008_git_capture("rev-parse", "--is-inside-work-tree")
  unless inside.fetch(:success) && inside.fetch(:stdout) == "true\n"
    return ["ADR-0008 acceptance history repository is unavailable: #{adr_0008_git_failure(inside)}"]
  end

  shallow_result = adr_0008_git_capture("rev-parse", "--is-shallow-repository")
  unless shallow_result.fetch(:success) && ["true\n", "false\n"].include?(shallow_result.fetch(:stdout))
    return ["ADR-0008 acceptance history cannot determine shallow state: #{adr_0008_git_failure(shallow_result)}"]
  end
  shallow = shallow_result.fetch(:stdout) == "true\n"
  return ["ADR-0008 acceptance history is shallow and cannot prove the immutable transition"] if shallow

  decision_result = adr_0008_git_capture("rev-parse", "--verify", "#{immutable_revision}^{commit}")
  unless decision_result.fetch(:success) && decision_result.fetch(:stdout) == "#{immutable_revision}\n"
    return ["ADR-0008 immutable decision revision does not resolve to the exact available commit"]
  end
  head_result = adr_0008_git_capture("rev-parse", "--verify", "HEAD^{commit}")
  unless head_result.fetch(:success) && adr_0008_exact_revision?(head_result.fetch(:stdout).strip)
    return ["ADR-0008 acceptance history HEAD does not resolve to one exact commit"]
  end
  head_revision = head_result.fetch(:stdout).strip

  ancestor_result = adr_0008_git_capture("merge-base", "--is-ancestor", immutable_revision, head_revision)
  unless ancestor_result.fetch(:success)
    return ["ADR-0008 immutable decision revision is not an ancestor of HEAD"] if ancestor_result.fetch(:exitstatus) == 1

    return ["ADR-0008 acceptance history cannot prove ancestry: #{adr_0008_git_failure(ancestor_result)}"]
  end

  range_result = adr_0008_git_capture(
    "rev-list",
    "--parents",
    "--ancestry-path",
    "--max-count=#{ADR_0008_ACCEPTANCE_HISTORY_MAX_COMMITS + 1}",
    "#{immutable_revision}..#{head_revision}"
  )
  unless range_result.fetch(:success)
    return ["ADR-0008 acceptance history cannot enumerate the decision ancestry path: #{adr_0008_git_failure(range_result)}"]
  end
  range_lines = range_result.fetch(:stdout).lines
  if range_lines.length > ADR_0008_ACCEPTANCE_HISTORY_MAX_COMMITS
    return ["ADR-0008 acceptance history exceeds its closed commit bound"]
  end

  decision_line_result = adr_0008_git_capture("rev-list", "--parents", "--max-count=1", immutable_revision)
  unless decision_line_result.fetch(:success) && decision_line_result.fetch(:stdout).lines.length == 1
    return ["ADR-0008 acceptance history cannot read the immutable decision parent record"]
  end
  commits, parse_failures = adr_0008_parse_git_commit_lines(
    range_lines + decision_line_result.fetch(:stdout).lines
  )
  return parse_failures unless parse_failures.empty?

  proposed_failures = adr_0008_proposed_decision_snapshot_failures(immutable_revision)
  unless proposed_failures.empty?
    return proposed_failures.map { |failure| "ADR-0008 immutable decision parent invalid: #{failure}" }
  end

  direct_children = commits.filter_map do |revision, parents|
    revision if parents.include?(immutable_revision)
  end
  snapshot_failures = {}
  acceptance_transitions = direct_children.filter_map do |revision|
    child_failures = adr_0008_accepted_transition_snapshot_failures(revision, metadata)
    snapshot_failures[revision] = child_failures
    revision if child_failures.empty?
  end

  history_failures = adr_0008_acceptance_graph_failures(
    immutable_revision: immutable_revision,
    repository_available: true,
    shallow: false,
    head_revision: head_revision,
    commits: commits,
    acceptance_transitions: acceptance_transitions
  )
  if acceptance_transitions.empty? && snapshot_failures.any?
    detail = snapshot_failures.sort_by(&:first).first(3).map do |revision, child_failures|
      "#{revision}: #{child_failures.first}"
    end
    history_failures << "ADR-0008 direct-child acceptance snapshots failed: #{detail.join('; ')}"
  end
  history_failures
end

def adr_0008_real_history_probe_write_acceptance(root, metadata)
  failures = []
  adr_path = root.join(ADR_0008_DECISION_RECORD_PATH)
  adr_source = adr_path.read(encoding: "UTF-8")
  adr_path.write(adr_0008_accepted_adr_fixture(adr_source, metadata), mode: "w", encoding: "UTF-8")

  catalog_path = root.join(ADR_0008_ISSUE_CATALOG_PATH)
  accepted_catalog, catalog_failures = adr_0008_accepted_catalog_source_fixture(
    catalog_path.read(encoding: "UTF-8"),
    metadata
  )
  failures.concat(catalog_failures)
  catalog_path.write(accepted_catalog, mode: "w", encoding: "UTF-8") if accepted_catalog

  approval_path = root.join(ADR_0008_APPROVAL_RECORD_PATH)
  approval_path.write(adr_0008_approval_record_fixture(metadata), mode: "w", encoding: "UTF-8")

  [ADR_0008_ADR_INDEX_PATH, ADR_0008_CHOICE_QUEUE_PATH, ADR_0008_CANDIDATE_INDEX_PATH].each do |path|
    index_path = root.join(path)
    parent_source = index_path.read(encoding: "UTF-8")
    accepted_source, index_failures = adr_0008_expected_index_transition(
      path: path,
      parent_source: parent_source,
      metadata: metadata
    )
    failures.concat(index_failures)
    next unless accepted_source

    index_path.write(accepted_source, mode: "w", encoding: "UTF-8")
  end
  failures
rescue Errno::ENOENT, KeyError, Psych::Exception, SystemCallError => error
  failures << "ADR-0008 real-history probe fixture generation failed: #{error.class}: #{error.message}"
end

def adr_0008_real_history_probe_git(root, *arguments, environment: {})
  result = adr_0008_git_capture(*arguments, root: root, environment: environment)
  return [result.fetch(:stdout), nil] if result.fetch(:success)

  [nil, "git #{arguments.first} failed: #{adr_0008_git_failure(result)}"]
end

def adr_0008_real_history_probe_validator(root, stage, token:)
  stdout, stderr, status = Open3.capture3(
    { ADR_0008_REAL_HISTORY_PROBE_TOKEN_ENV => token },
    RbConfig.ruby,
    "scripts/validate_adr_records.rb",
    chdir: root.to_s
  )
  return [] if status.success? && stdout.include?("ADR traceability validation: PASS")

  detail = (stderr + stdout).lines.first(8).join(" ").strip
  ["ADR-0008 real-history #{stage} complete validator failed: #{detail.byteslice(0, 1_000)}"]
rescue Errno::ENOENT, SystemCallError => error
  ["ADR-0008 real-history #{stage} validator could not run: #{error.class}: #{error.message}"]
end

def adr_0008_real_history_probe_failures(decision_revision:, metadata_template:)
  return ["ADR-0008 real-history probe decision revision is malformed"] unless adr_0008_exact_revision?(decision_revision)

  base = Pathname.new(ENV.fetch("STEAD_TEST_TMPDIR", ROOT.parent.to_s)).expand_path
  unless base.directory? && base.writable?
    return ["ADR-0008 real-history probe temporary base is unavailable"]
  end
  root_real = ROOT.realpath
  base_real = base.realpath
  if base_real == root_real || base_real.to_s.start_with?("#{root_real}/")
    return ["ADR-0008 real-history probe temporary base must be outside the repository"]
  end

  failures = []
  Dir.mktmpdir("stead-adr0008-history-", base_real.to_s) do |temporary|
    probe_root = Pathname.new(temporary).join("repository")
    probe_token = SecureRandom.hex(32)
    _output, error = adr_0008_real_history_probe_git(
      ROOT,
      "clone",
      "--quiet",
      "--no-local",
      ROOT.to_s,
      probe_root.to_s
    )
    return ["ADR-0008 real-history probe clone failed: #{error}"] if error

    {
      "user.name" => "Stead ADR probe",
      "user.email" => "adr-probe@stead.invalid",
      ADR_0008_REAL_HISTORY_PROBE_CONFIG_KEY => probe_token
    }.each do |key, value|
      _config_output, config_error = adr_0008_real_history_probe_git(probe_root, "config", key, value)
      return ["ADR-0008 real-history probe #{config_error}"] if config_error
    end
    _checkout_output, checkout_error = adr_0008_real_history_probe_git(
      probe_root,
      "switch",
      "--detach",
      decision_revision
    )
    return ["ADR-0008 real-history probe #{checkout_error}"] if checkout_error
    _branch_output, branch_error = adr_0008_real_history_probe_git(
      probe_root,
      "switch",
      "-c",
      "probe-accepted"
    )
    return ["ADR-0008 real-history probe #{branch_error}"] if branch_error

    metadata = metadata_template.merge(immutable_revision: decision_revision)
    fixture_failures = adr_0008_real_history_probe_write_acceptance(probe_root, metadata)
    return fixture_failures unless fixture_failures.empty?

    paths = ADR_0008_ACCEPTANCE_TRANSITION_CHANGES.keys
    _add_output, add_error = adr_0008_real_history_probe_git(probe_root, "add", "--", *paths)
    return ["ADR-0008 real-history probe #{add_error}"] if add_error
    staged_output, staged_error = adr_0008_real_history_probe_git(
      probe_root,
      "diff",
      "--cached",
      "--name-status"
    )
    return ["ADR-0008 real-history probe #{staged_error}"] if staged_error
    staged_changes = staged_output.lines.to_h do |line|
      status, path = line.chomp.split("\t", 2)
      [path, status]
    end
    staged_failures = adr_0008_acceptance_transition_change_failures(staged_changes)
    return staged_failures unless staged_failures.empty?

    commit_environment = {
      "GIT_AUTHOR_DATE" => "2026-09-04T00:00:00Z",
      "GIT_COMMITTER_DATE" => "2026-09-04T00:00:00Z"
    }
    _commit_output, commit_error = adr_0008_real_history_probe_git(
      probe_root,
      "commit",
      "--quiet",
      "--no-gpg-sign",
      "-m",
      "test: accept ADR-0008 fixture",
      environment: commit_environment
    )
    return ["ADR-0008 real-history probe #{commit_error}"] if commit_error
    failures.concat(
      adr_0008_real_history_probe_validator(
        probe_root,
        "immediate-child",
        token: probe_token
      )
    )
    return failures unless failures.empty?

    _descendant_output, descendant_error = adr_0008_real_history_probe_git(
      probe_root,
      "commit",
      "--quiet",
      "--allow-empty",
      "--no-gpg-sign",
      "-m",
      "test: later accepted descendant",
      environment: commit_environment.merge("GIT_AUTHOR_DATE" => "2026-09-05T00:00:00Z", "GIT_COMMITTER_DATE" => "2026-09-05T00:00:00Z")
    )
    return ["ADR-0008 real-history probe #{descendant_error}"] if descendant_error
    failures.concat(
      adr_0008_real_history_probe_validator(
        probe_root,
        "later-descendant",
        token: probe_token
      )
    )
    return failures unless failures.empty?

    _side_output, side_error = adr_0008_real_history_probe_git(
      probe_root,
      "switch",
      "-c",
      "probe-side",
      decision_revision
    )
    return ["ADR-0008 real-history probe #{side_error}"] if side_error
    _side_commit_output, side_commit_error = adr_0008_real_history_probe_git(
      probe_root,
      "commit",
      "--quiet",
      "--allow-empty",
      "--no-gpg-sign",
      "-m",
      "test: sibling branch",
      environment: commit_environment.merge("GIT_AUTHOR_DATE" => "2026-09-06T00:00:00Z", "GIT_COMMITTER_DATE" => "2026-09-06T00:00:00Z")
    )
    return ["ADR-0008 real-history probe #{side_commit_error}"] if side_commit_error
    _return_output, return_error = adr_0008_real_history_probe_git(probe_root, "switch", "probe-accepted")
    return ["ADR-0008 real-history probe #{return_error}"] if return_error
    _merge_output, merge_error = adr_0008_real_history_probe_git(
      probe_root,
      "merge",
      "--quiet",
      "--no-ff",
      "--no-gpg-sign",
      "-m",
      "test: normal integration merge",
      "probe-side",
      environment: commit_environment.merge("GIT_COMMITTER_DATE" => "2026-09-07T00:00:00Z")
    )
    return ["ADR-0008 real-history probe #{merge_error}"] if merge_error
    failures.concat(
      adr_0008_real_history_probe_validator(
        probe_root,
        "normal-merge",
        token: probe_token
      )
    )
  end
  failures
rescue ArgumentError, Errno::ENOENT, SystemCallError => error
  ["ADR-0008 real-history probe failed closed: #{error.class}: #{error.message}"]
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

# CBI-030 is interpreted only after the complete classification-bypass
# inventory matches its reviewed byte length and digest. This deliberately
# avoids a partial Markdown renderer: any source change, including hidden or
# alternate rendered syntax, requires an explicit reviewed digest update.
def adr_0008_bypass_inventory_rows(source)
  failures = []
  unless source.bytesize == ADR_0008_CLASSIFICATION_BYPASS_SOURCE_BYTES
    return [[], [
      "classification bypass inventory source byte length mismatch: expected " \
      "#{ADR_0008_CLASSIFICATION_BYPASS_SOURCE_BYTES}, found #{source.bytesize}"
    ]]
  end

  actual_source_sha256 = Digest::SHA256.hexdigest(source)
  unless actual_source_sha256 == ADR_0008_CLASSIFICATION_BYPASS_SOURCE_SHA256
    return [[], [
      "classification bypass inventory source digest mismatch: expected " \
      "#{ADR_0008_CLASSIFICATION_BYPASS_SOURCE_SHA256}, found #{actual_source_sha256}"
    ]]
  end

  visible_source = source
  section_heading = "## Complete bypass inventory\n"
  section_end_heading = "## Common test fixture and oracle\n"
  section_starts = visible_source.enum_for(:scan, /^#{Regexp.escape(section_heading)}/).map { Regexp.last_match }
  section_ends = visible_source.enum_for(:scan, /^#{Regexp.escape(section_end_heading)}/).map { Regexp.last_match }
  unless section_starts.length == 1 && section_ends.length == 1 &&
         section_ends.first.begin(0) > section_starts.first.end(0)
    return [[], ["classification bypass inventory must contain one bounded visible complete-inventory section"]]
  end

  section = visible_source[section_starts.first.end(0)...section_ends.first.begin(0)]
  lines = section.lines
  header_indices = lines.each_index.select { |index| lines[index] == ADR_0008_CBI_TABLE_HEADER }
  unless header_indices.length == 1
    return [[], ["classification bypass inventory must contain exactly one canonical visible complete-inventory table"]]
  end

  header_index = header_indices.first
  delimiter_index = header_index + 1
  unless (header_index.zero? || lines[header_index - 1].strip.empty?) &&
         lines[delimiter_index] == ADR_0008_CBI_TABLE_DELIMITER
    return [[], ["classification bypass inventory must contain the canonical complete-inventory table header"]]
  end

  rows = lines.drop(delimiter_index + 1).take_while { |line| !line.strip.empty? }
  failures << "classification bypass inventory complete-inventory table must not be empty" if rows.empty?
  rows.each_with_index do |row, index|
    next if row.match?(/\A\| CBI-[0-9]{3} \|.*\|\n?\z/)

    failures << "classification bypass inventory row #{index + 1} must use canonical CBI table-row syntax"
  end

  unless rows.grep(/\A\| CBI-030 \|/).length == 1
    failures << "classification bypass inventory canonical table must contain exactly one CBI-030 row"
  end
  [rows, failures]
end

def adr_0008_security_contract_failures(adr_source:, asyncapi:, bypass_source:, acceptance_metadata: nil)
  failures = adr_0008_substantive_source_failures(adr_source, acceptance_metadata: acceptance_metadata)
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

def p1_006_without_allowed_accepted_adr_reference(criteria)
  residual_criteria = criteria.dup
  occurrence_count = residual_criteria.sum do |criterion|
    criterion.is_a?(String) ? criterion.scan(P1_006_ALLOWED_ACCEPTED_ADR_0009_CLAUSE).length : 0
  end
  return residual_criteria unless occurrence_count == 1

  reference_index = residual_criteria.index do |criterion|
    criterion.is_a?(String) && criterion.include?(P1_006_ALLOWED_ACCEPTED_ADR_0009_CLAUSE)
  end
  residual_criteria[reference_index] = residual_criteria.fetch(reference_index).sub(
    P1_006_ALLOWED_ACCEPTED_ADR_0009_CLAUSE,
    ""
  )
  residual_criteria
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
  residual_fragments = noncanonical_adr_candidate_fragments(
    p1_006_without_allowed_accepted_adr_reference([residual_source])
  )
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
    residual_fragments = noncanonical_adr_candidate_fragments(
      p1_006_without_allowed_accepted_adr_reference(residual_criteria)
    )
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
adr_0008_acceptance_metadata, adr_0008_gate_metadata_failures =
  adr_0008_acceptance_metadata_from_gate(adr_gates["ADR-CAND-006"])
failures.concat(adr_0008_gate_metadata_failures)
adr_0009_acceptance_metadata, adr_0009_gate_metadata_failures =
  adr_0009_acceptance_metadata_from_gate(adr_gates["ADR-CAND-008"])
failures.concat(adr_0009_gate_metadata_failures)
adr_0009_spec_path = ROOT.join(ADR_0009_SPEC_PATH)
adr_0009_spec_source = if adr_0009_spec_path.file? && !adr_0009_spec_path.symlink?
                         adr_0009_spec_path.open("rb") { |file| file.read(ADR_0009_SPEC_MAX_BYTES + 1).to_s }
                       else
                         ""
                       end
adr_0009_spec_source.force_encoding(Encoding::UTF_8)
begin
  adr_0009_spec = parse_yaml(adr_0009_spec_source, filename: ADR_0009_SPEC_PATH)
rescue Psych::Exception => error
  failures << "#{ADR_0009_SPEC_PATH}: cannot parse closed reconciliation contract: #{error.class}"
  adr_0009_spec = nil
end
failures.concat(adr_0009_spec_failures(spec_source: adr_0009_spec_source, spec: adr_0009_spec))

adr_0009_spec_mutation_survivors = []
adr_0009_spec_mutation_count = 0
if adr_0009_spec.is_a?(Hash)
  ADR_0009_SPEC_EXPECTATIONS.each_key do |path|
    adr_0009_spec_mutation_count += 1
    mutated = adr_0009_mutate_spec_path(adr_0009_spec, path)
    mutation_failures = adr_0009_spec_failures(spec_source: adr_0009_spec_source, spec: mutated)
    expected_failure = "ADR-0009 structured reconciliation spec invariant failed: #{path}"
    adr_0009_spec_mutation_survivors << path unless mutation_failures.include?(expected_failure)
  end
  ADR_0009_SPEC_SECTION_DIGESTS.each_key do |section|
    adr_0009_spec_mutation_count += 1
    mutated = Marshal.load(Marshal.dump(adr_0009_spec))
    mutated.fetch(section)["adversarial_extra_key"] = true
    mutation_failures = adr_0009_spec_failures(spec_source: adr_0009_spec_source, spec: mutated)
    expected_failure = "ADR-0009 structured reconciliation spec section digest mismatch: #{section}"
    adr_0009_spec_mutation_survivors << "#{section} digest" unless mutation_failures.include?(expected_failure)
  end
  adr_0009_spec_mutation_count += 1
  mutated_top_level = adr_0009_spec.merge("adversarial_extra_contract" => {})
  top_level_failures = adr_0009_spec_failures(spec_source: adr_0009_spec_source, spec: mutated_top_level)
  unless top_level_failures.include?("ADR-0009 structured reconciliation spec top-level keys must match the closed order")
    adr_0009_spec_mutation_survivors << "top-level key injection"
  end

  adr_0009_spec_mutation_count += 1
  duplicate_example_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  duplicate_example = duplicate_example_spec.fetch("field_classes").fetch("canonical_only").fetch("examples").first
  duplicate_example_spec.fetch("field_classes").fetch("central_security").fetch("examples")[0] = duplicate_example
  duplicate_example_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: duplicate_example_spec
  )
  unless duplicate_example_failures.any? { |failure| failure.start_with?("ADR-0009 field-class examples must be globally unique:") }
    adr_0009_spec_mutation_survivors << "cross-class duplicate example"
  end

  record_yaml_source_rejection = lambda do |name:, source:, expected_error:, control_matches_original:|
    adr_0009_spec_mutation_count += 1
    if source == adr_0009_spec_source
      adr_0009_spec_mutation_survivors << "#{name} fixture unavailable"
      next
    end

    if control_matches_original
      begin
        control = YAML.safe_load(
          source,
          permitted_classes: [],
          permitted_symbols: [],
          aliases: false,
          filename: "#{ADR_0009_SPEC_PATH} (#{name} safe-load control)"
        )
        unless control == adr_0009_spec
          adr_0009_spec_mutation_survivors << "#{name} fixture does not preserve safe-load result"
        end
      rescue Psych::Exception => error
        adr_0009_spec_mutation_survivors << "#{name} safe-load control failed: #{error.class}"
      end
    end

    begin
      parse_yaml(source, filename: "#{ADR_0009_SPEC_PATH} (#{name} fixture)")
      adr_0009_spec_mutation_survivors << name
    rescue Psych::Exception => error
      unless error.is_a?(expected_error)
        adr_0009_spec_mutation_survivors << "#{name} wrong failure: #{error.class}"
      end
    end
  end

  yaml_key_marker = "  reusable: false\n"
  {
    "duplicate YAML mapping key" => [
      "  reusable: true\n  reusable: false\n",
      DuplicateYamlMappingKeyError,
      true
    ],
    "escaped semantic duplicate YAML mapping key" => [
      "  \"\\x72eusable\": true\n  reusable: false\n",
      DuplicateYamlMappingKeyError,
      true
    ],
    "plain inline YAML merge mapping key" => [
      "  <<: {reusable: true}\n  reusable: false\n",
      NonCanonicalYamlMappingKeyError,
      true
    ],
    "explicit !!merge inline YAML mapping key" => [
      "  !!merge <<: {reusable: true}\n  reusable: false\n",
      NonCanonicalYamlMappingKeyError,
      true
    ],
    "explicit !!binary semantic duplicate YAML mapping key" => [
      "  !!binary cmV1c2FibGU=: true\n  reusable: false\n",
      NonCanonicalYamlMappingKeyError,
      true
    ],
    "explicit !!str YAML mapping key" => [
      "  !!str reusable: true\n  reusable: false\n",
      NonCanonicalYamlMappingKeyError,
      true
    ],
    "anchored YAML mapping key" => [
      "  &adversarial_key reusable: false\n",
      NonCanonicalYamlMappingKeyError,
      true
    ],
    "complex YAML mapping key" => [
      "  ? [adversarial_complex_key]\n  : true\n  reusable: false\n",
      NonCanonicalYamlMappingKeyError,
      false
    ],
    "alias YAML mapping key" => [
      "  adversarial_alias_source: &adversarial_key reusable\n  *adversarial_key: true\n  reusable: false\n",
      NonCanonicalYamlMappingKeyError,
      false
    ],
    "non-String YAML mapping key" => [
      "  true: adversarial\n  reusable: false\n",
      NonCanonicalYamlMappingKeyError,
      false
    ]
  }.each do |name, (replacement, expected_error, control_matches_original)|
    record_yaml_source_rejection.call(
      name: name,
      source: adr_0009_spec_source.sub(yaml_key_marker, replacement),
      expected_error: expected_error,
      control_matches_original: control_matches_original
    )
  end

  invalid_utf8_key_source = adr_0009_spec_source.b.sub(
    yaml_key_marker.b,
    "  adversarial_\xFF: true\n  reusable: false\n".b
  ).force_encoding(Encoding::UTF_8)
  record_yaml_source_rejection.call(
    name: "invalid UTF-8 YAML mapping key",
    source: invalid_utf8_key_source,
    expected_error: YamlAstValidationError,
    control_matches_original: false
  )

  adr_0009_spec_mutation_count += 1
  second_document_source = "#{adr_0009_spec_source}---\nreusable: true\n"
  first_document_only = YAML.safe_load(
    second_document_source,
    permitted_classes: [],
    permitted_symbols: [],
    aliases: false,
    filename: "#{ADR_0009_SPEC_PATH} (first-document-only control)"
  )
  unless first_document_only == adr_0009_spec
    adr_0009_spec_mutation_survivors << "multiple YAML document fixture does not preserve first loaded document"
  end
  begin
    parse_yaml(second_document_source, filename: "#{ADR_0009_SPEC_PATH} (trailing document fixture)")
    adr_0009_spec_mutation_survivors << "trailing YAML document"
  rescue MultipleYamlDocumentsError
    # Expected: reject ignored trailing documents before safe loading.
  rescue Psych::Exception => error
    adr_0009_spec_mutation_survivors << "trailing YAML document wrong failure: #{error.class}"
  end

  ADR_0009_FORBIDDEN_PROPAGATED_FIELD_MUTANTS.each do |category, field|
    adr_0009_spec_mutation_count += 1
    leaked_provider_field_spec = Marshal.load(Marshal.dump(adr_0009_spec))
    leaked_provider_field_spec
      .fetch("privacy_and_observability")
      .fetch("logical_audit_provider_evidence")
      .fetch("allowed_fields") << field
    leaked_provider_field_failures = adr_0009_spec_failures(
      spec_source: adr_0009_spec_source,
      spec: leaked_provider_field_spec
    )
    unless leaked_provider_field_failures.any? do |failure|
             failure.start_with?(
               "ADR-0009 closed nested or operational schemas expose forbidden provider evidence:"
             ) && failure.include?(category.to_s)
           end
      adr_0009_spec_mutation_survivors << "#{category} in nested logical-audit evidence"
    end
  end

  adr_0009_spec_mutation_count += 1
  guessable_provider_digest_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  guessable_provider_digest_spec
    .fetch("privacy_and_observability")
    .fetch("logical_audit_provider_evidence")
    .fetch("allowed_fields") << "provider_binding_sha256"
  guessable_provider_digest_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: guessable_provider_digest_spec
  )
  unless guessable_provider_digest_failures.any? do |failure|
           failure.start_with?("ADR-0009 closed nested or operational schemas expose forbidden provider evidence:")
         end
    adr_0009_spec_mutation_survivors << "guessable provider digest in propagated audit evidence"
  end

  non_audit_reference_mutations = {
    "canonical event provider evidence" => %w[
      canonical_event_provider_evidence
    ],
    "dead-letter provider evidence" => %w[
      dead_letter_provider_evidence
    ],
    "correlated-operation provider attributes" => %w[
      operational_surface_evidence profiles correlated_operation_v1
    ],
    "bounded-metric provider attributes" => %w[
      operational_surface_evidence profiles bounded_metric_v1
    ],
    "support-summary provider attributes" => %w[
      operational_surface_evidence profiles support_summary_v1
    ]
  }
  non_audit_reference_mutations.each do |name, components|
    adr_0009_spec_mutation_count += 1
    leaked_reference_spec = Marshal.load(Marshal.dump(adr_0009_spec))
    record = components.reduce(leaked_reference_spec.fetch("privacy_and_observability")) do |value, component|
      value.fetch(component)
    end
    record.fetch("allowed_fields") << "provider_binding_evidence_ref"
    leaked_reference_failures = adr_0009_spec_failures(
      spec_source: adr_0009_spec_source,
      spec: leaked_reference_spec
    )
    unless leaked_reference_failures.include?(
      "ADR-0009 opaque provider-binding and call-plan references must occur only in logical-audit evidence"
    )
      adr_0009_spec_mutation_survivors << "protected operation-record reference in #{name}"
    end
  end

  adr_0009_spec_mutation_count += 1
  missing_logical_audit_reference_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  missing_logical_audit_reference_spec
    .fetch("privacy_and_observability")
    .fetch("logical_audit_provider_evidence")
    .fetch("allowed_fields")
    .delete("call_plan_evidence_ref")
  missing_logical_audit_reference_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: missing_logical_audit_reference_spec
  )
  unless missing_logical_audit_reference_failures.include?(
    "ADR-0009 opaque provider-binding and call-plan references must occur only in logical-audit evidence"
  )
    adr_0009_spec_mutation_survivors << "missing logical-audit protected operation-record reference"
  end

  adr_0009_spec_mutation_count += 1
  reordered_surface_bindings_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  operational_evidence = reordered_surface_bindings_spec
    .fetch("privacy_and_observability")
    .fetch("operational_surface_evidence")
  operational_evidence["surface_bindings"] = operational_evidence
    .fetch("surface_bindings")
    .to_a
    .reverse
    .to_h
  reordered_surface_bindings_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: reordered_surface_bindings_spec
  )
  unless reordered_surface_bindings_failures.include?(
    "ADR-0009 operational propagation surfaces must bind exactly to closed provider-attribute profiles"
  )
    adr_0009_spec_mutation_survivors << "reordered operational surface bindings"
  end

  adr_0009_spec_mutation_count += 1
  missing_cross_product_canary_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  missing_cross_product_canary_spec
    .fetch("verification")
    .fetch("T-ADR-0009-AUDIT-MINIMIZATION")
    .fetch("cases")
    .delete("every_canary_across_every_base_envelope_nested_evidence_and_propagation_surface")
  missing_cross_product_canary_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: missing_cross_product_canary_spec
  )
  unless missing_cross_product_canary_failures.include?(
    "ADR-0009 audit minimization must cover every forbidden-value canary across every base envelope, nested evidence object, and propagation surface"
  )
    adr_0009_spec_mutation_survivors << "missing base-envelope/nested-evidence/surface canary cross-product"
  end

  adr_0009_spec_mutation_count += 1
  reordered_terminal_participants_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  reordered_terminal_participants_spec
    .fetch("authorization_scope")
    .fetch("persistence")
    .fetch("terminal_transaction")
    .fetch("participant_plan")
    .reverse!
  reordered_terminal_participants_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: reordered_terminal_participants_spec
  )
  unless reordered_terminal_participants_failures.include?(
    "ADR-0009 structured reconciliation spec invariant failed: authorization_scope.persistence.terminal_transaction.participant_plan"
  )
    adr_0009_spec_mutation_survivors << "reordered WS-03 then WS-02 terminal participant plan"
  end

  adr_0009_spec_mutation_count += 1
  expanded_event_evidence_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  expanded_event_evidence_spec
    .fetch("privacy_and_observability")
    .fetch("canonical_event_provider_evidence")
    .fetch("allowed_fields") << "operation_class"
  expanded_event_evidence_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: expanded_event_evidence_spec
  )
  unless expanded_event_evidence_failures.include?(
    "ADR-0009 structured reconciliation spec invariant failed: privacy_and_observability.canonical_event_provider_evidence.allowed_fields"
  )
    adr_0009_spec_mutation_survivors << "expanded canonical event reconciliation evidence"
  end

  adr_0009_spec_mutation_count += 1
  missing_terminal_atomicity_case_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  missing_terminal_atomicity_case_spec
    .fetch("verification")
    .fetch("T-ADR-0009-FULL-RECONCILIATION")
    .fetch("cases")
    .delete("terminal_claim_and_intent_atomicity_at_each_crash_boundary")
  missing_terminal_atomicity_case_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: missing_terminal_atomicity_case_spec
  )
  unless missing_terminal_atomicity_case_failures.include?(
    "ADR-0009 full reconciliation must cover terminal ownership, atomic intent, recovery, and exactly-once WS-07 audit materialization"
  )
    adr_0009_spec_mutation_survivors << "missing terminal claim and intent atomicity case"
  end

  adr_0009_spec_mutation_count += 1
  missing_typed_resolution_case_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  missing_typed_resolution_case_spec
    .fetch("verification")
    .fetch("T-ADR-0009-AUDIT-MINIMIZATION")
    .fetch("cases")
    .delete("typed_ws03_audit_evidence_resolution")
  missing_typed_resolution_case_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: missing_typed_resolution_case_spec
  )
  unless missing_typed_resolution_case_failures.include?(
    "ADR-0009 audit minimization must cover every forbidden-value canary across every base envelope, nested evidence object, and propagation surface"
  )
    adr_0009_spec_mutation_survivors << "missing typed WS-03 audit-evidence resolution case"
  end

  adr_0009_spec_mutation_count += 1
  missing_event_required_field_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  missing_event_required_field_spec
    .fetch("privacy_and_observability")
    .fetch("canonical_event_provider_evidence")
    .fetch("required_fields")
    .delete("logical_operation_id")
  missing_event_required_field_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: missing_event_required_field_spec
  )
  unless missing_event_required_field_failures.include?(
    "ADR-0009 canonical event reconciliation evidence must require exactly const schema_version and bounded UUIDv7 logical_operation_id"
  )
    adr_0009_spec_mutation_survivors << "optional canonical event logical operation identifier"
  end

  adr_0009_spec_mutation_count += 1
  weakened_event_uuid_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  weakened_event_uuid_spec
    .fetch("privacy_and_observability")
    .fetch("canonical_event_provider_evidence")
    .fetch("field_constraints")
    .fetch("logical_operation_id")["pattern"] = "^.*$"
  weakened_event_uuid_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: weakened_event_uuid_spec
  )
  unless weakened_event_uuid_failures.include?(
    "ADR-0009 structured reconciliation spec invariant failed: privacy_and_observability.canonical_event_provider_evidence.field_constraints.logical_operation_id.pattern"
  )
    adr_0009_spec_mutation_survivors << "weakened canonical event UUIDv7 constraint"
  end

  adr_0009_spec_mutation_count += 1
  reordered_deadline_participants_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  reordered_deadline_participants_spec
    .fetch("authorization_scope")
    .fetch("persistence")
    .fetch("audit_materialization")
    .fetch("deadline_terminal_transaction")
    .fetch("participant_plan")
    .reverse!
  reordered_deadline_participants_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: reordered_deadline_participants_spec
  )
  unless reordered_deadline_participants_failures.include?(
    "ADR-0009 structured reconciliation spec invariant failed: authorization_scope.persistence.audit_materialization.deadline_terminal_transaction.participant_plan"
  )
    adr_0009_spec_mutation_survivors << "reordered WS-07 then WS-02 deadline participant plan"
  end

  adr_0009_spec_mutation_count += 1
  mutable_successor_binding_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  successor_source = mutable_successor_binding_spec
    .fetch("authorization_scope")
    .fetch("persistence")
    .fetch("audit_materialization")
    .fetch("phase1_successor_recovery_source")
  successor_source.fetch("immutable_contents").delete("canonical_event_digest")
  successor_source.fetch("owner_written_fenced_monotonic_recovery_state") << "canonical_event_digest"
  mutable_successor_binding_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: mutable_successor_binding_spec
  )
  immutable_path =
    "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.immutable_contents"
  lifecycle_path =
    "authorization_scope.persistence.audit_materialization.phase1_successor_recovery_source.owner_written_fenced_monotonic_recovery_state"
  unless mutable_successor_binding_failures.include?(
    "ADR-0009 structured reconciliation spec invariant failed: #{immutable_path}"
  ) && mutable_successor_binding_failures.include?(
    "ADR-0009 structured reconciliation spec invariant failed: #{lifecycle_path}"
  )
    adr_0009_spec_mutation_survivors << "mutable successor event digest binding"
  end

  adr_0009_spec_mutation_count += 1
  missing_deadline_atomicity_case_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  missing_deadline_atomicity_case_spec
    .fetch("verification")
    .fetch("T-ADR-0009-FULL-RECONCILIATION")
    .fetch("cases")
    .delete("deadline_transfer_no_external_call_and_each_crash_boundary_atomic")
  missing_deadline_atomicity_case_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: missing_deadline_atomicity_case_spec
  )
  unless missing_deadline_atomicity_case_failures.include?(
    "ADR-0009 full reconciliation must cover terminal ownership, atomic intent, recovery, and exactly-once WS-07 audit materialization"
  )
    adr_0009_spec_mutation_survivors << "missing no-external-call deadline crash-boundary case"
  end

  adr_0009_spec_mutation_count += 1
  missing_successor_restore_case_spec = Marshal.load(Marshal.dump(adr_0009_spec))
  missing_successor_restore_case_spec
    .fetch("verification")
    .fetch("T-ADR-0009-UPGRADE-ROLLBACK")
    .fetch("cases")
    .delete("backup_restore_preserves_reference_resolution_and_successor_obligations")
  missing_successor_restore_case_failures = adr_0009_spec_failures(
    spec_source: adr_0009_spec_source,
    spec: missing_successor_restore_case_spec
  )
  unless missing_successor_restore_case_failures.include?(
    "ADR-0009 upgrade and rollback must preserve protected-evidence resolution and successor obligations across backup/restore"
  )
    adr_0009_spec_mutation_survivors << "missing successor-obligation backup/restore case"
  end
end

ADR_0009_CROSS_FILE_REQUIRED_FRAGMENTS.each do |relative_path, fragments|
  cross_source = ROOT.join(relative_path).read(encoding: "UTF-8")
  fragments.each do |fragment|
    failures << "#{relative_path}: omits ADR-0009 cross-file contract #{fragment.inspect}" unless cross_source.include?(fragment)
  end
end

adr_0009_cross_contract_mutation_count = 0
adr_0009_cross_contract_mutation_survivors = []

provider_interfaces = load_yaml("specs/provider-interfaces.yaml")
reconciliation_records = Array(provider_interfaces["reconciliation_contracts"])
expected_reconciliation_record = {
  "id" => "P-SCM-RECONCILIATION-GITEA-V1",
  "owner" => "WS-03",
  "status" => "governed_by_adr_0009",
  "source" => ADR_0009_SPEC_PATH,
  "provider" => "gitea",
  "authorization_scope_owner" => "WS-06",
  "execution_claim_owner" => "WS-03",
  "protected_audit_evidence_owner" => "WS-03",
  "protected_audit_evidence_resolution_port" =>
    "authenticated_authorized_typed_bounded_set_oriented_read",
  "protected_audit_evidence_consumer" => "WS-07",
  "core_outbox_owner" => "WS-02",
  "audit_record_schema_owner" => "WS-01",
  "audit_record_materialization_owner" => "WS-07",
  "audit_record_materialization" => "append_only_insert_or_exact_identity_and_digest_match",
  "audit_resource_envelope_contract" =>
    "packages/domain-schemas/common/resource-envelope/resource-envelope-v1.1.schema.json",
  "audit_record_contract" =>
    "packages/domain-schemas/resources/audit-record/audit-record-v1.1.schema.json",
  "audit_record_contract_id" =>
    "https://stead.example/packages/domain-schemas/resources/audit-record/audit-record-v1.1.schema.json",
  "audit_event_contract_owner" => "WS-07",
  "canonical_event_contract" =>
    "packages/event-schemas/stead/provider-reconciliation-event-v1.schema.json",
  "canonical_event_contract_id" =>
    "https://stead.example/packages/event-schemas/stead/provider-reconciliation-event-v1.schema.json",
  "dead_letter_event_contract" =>
    "packages/event-schemas/stead/provider-reconciliation-dead-letter-v1.schema.json",
  "dead_letter_event_contract_id" =>
    "https://stead.example/packages/event-schemas/stead/provider-reconciliation-dead-letter-v1.schema.json",
  "canonical_event_envelope" =>
    "specs/asyncapi/stead.yaml#/components/schemas/ProviderReconciliationCloudEventEnvelope",
  "canonical_event_message" =>
    "specs/asyncapi/stead.yaml#/components/messages/ProviderReconciliationCloudEvent",
  "canonical_event_channel_binding" =>
    "specs/asyncapi/stead.yaml#/channels/scmEvents/messages/ProviderReconciliationCloudEvent",
  "dead_letter_event_envelope" =>
    "specs/asyncapi/stead.yaml#/components/schemas/ProviderReconciliationDeadLetterCloudEventEnvelope",
  "dead_letter_event_message" =>
    "specs/asyncapi/stead.yaml#/components/messages/ProviderReconciliationDeadLetterCloudEvent",
  "dead_letter_event_channel_binding" =>
    "specs/asyncapi/stead.yaml#/channels/deadLetterEvents/messages/ProviderReconciliationDeadLetterCloudEvent",
  "evidence_emission_gate" => %w[
    every_named_schema_id_registered_and_validated
    audit_v1_0_and_v1_1_consumer_readiness
    specialized_event_and_dead_letter_consumer_readiness
    exact_asyncapi_envelope_message_and_channel_bindings_active
    generic_v0_1_data_route_rejects_provider_reconciliation_types
  ],
  "execution_scope" => "atomic_process_instance_single_holder",
  "propagated_evidence" =>
    "canonical_event_uses_only_logical_operation_id_as_protected_lookup_and_opaque_ws03_references_exist_in_materialized_audit_only",
  "terminal_transaction" =>
    "predeclared_ws03_scm_then_ws02_core_outbox_final_participant_atomic_state_and_intent",
  "audit_recovery" =>
    "adr0008_deadline_atomically_transfers_to_real_ws07_successor_obligation_before_core_outbox_retirement",
  "ordinary_ui_synchronous_provider_calls" => 0,
  "activation_gate" => "ADR-CAND-008_ACCEPTED_AT_EXACT_IMMUTABLE_SHA"
}
reconciliation_registry_failures = lambda do |records|
  if records == [expected_reconciliation_record]
    []
  else
    ["specs/provider-interfaces.yaml: ADR-0009 reconciliation registry must match the exact owner/source/schema/activation contract"]
  end
end
failures.concat(reconciliation_registry_failures.call(reconciliation_records))

ADR_0009_PROVIDER_INTERFACE_NEW_FIELDS.each do |field|
  adr_0009_cross_contract_mutation_count += 1
  mutated_records = Marshal.load(Marshal.dump(reconciliation_records))
  removed = mutated_records.first&.delete(field)
  mutation_failures = reconciliation_registry_failures.call(mutated_records)
  if removed.nil? || mutation_failures.empty?
    adr_0009_cross_contract_mutation_survivors << "provider interface #{field} deletion"
  end
end

p1_003 = issues["STEAD-P1-003"]
p1_006 = issues["STEAD-P1-006"]
p1_007 = issues["STEAD-P1-007"]
if p1_003 && p1_006 && p1_007
  unless Array(p1_003["owned_directories"]).include?("specs/provider-reconciliation") &&
         Array(p1_003["dependencies"]).include?("STEAD-P1-006")
    failures << "STEAD-P1-003 must own the reconciliation spec and consume STEAD-P1-006"
  end
  unless %w[T-ADR-0009-AMBIGUOUS-MUTATION T-ADR-0009-FULL-RECONCILIATION].all? do |test_id|
           Array(p1_003["automated_tests"]).include?(test_id) &&
             Array(p1_006["automated_tests"]).include?(test_id)
         end
    failures << "STEAD-P1-003 and STEAD-P1-006 must share the two closed ADR-0009 authorization/effect integration suites"
  end
  if Array(p1_006["owned_directories"]).include?("specs/provider-reconciliation")
    failures << "STEAD-P1-006 must not own the WS-03 provider-reconciliation specification"
  end

  schema_contract_paths = %w[
    packages/domain-schemas/common/resource-envelope/resource-envelope-v1.1.schema.json
    packages/domain-schemas/resources/audit-record/audit-record-v1.1.schema.json
    packages/event-schemas/stead/provider-reconciliation-event-v1.schema.json
    packages/event-schemas/stead/provider-reconciliation-dead-letter-v1.schema.json
  ]
  p1_003_acceptance = Array(p1_003["acceptance_criteria"]).join("\n")
  unless p1_003_acceptance.include?("Consume, but do not own or emit before readiness of") &&
         p1_003_acceptance.include?("predeclared WS-03 then WS-02 terminal transaction") &&
         p1_003_acceptance.include?("WS-03 never writes `audit.*`") &&
         p1_003_acceptance.include?("authenticated, fresh-authorized, bounded set-oriented typed read port") &&
         p1_003_acceptance.include?("event's additional reconciliation evidence is exactly `schema_version` and `logical_operation_id`")
    failures << "STEAD-P1-003 must own the WS-03 terminal/evidence-resolver seam and consume, but not prematurely emit, the closed ADR-0009 evidence schemas"
  end

  p1_007_acceptance = Array(p1_007["acceptance_criteria"]).join("\n")
  p1_007_materialization_failures = lambda do |issue|
    acceptance = Array(issue["acceptance_criteria"]).join("\n")
    tests = Array(issue["automated_tests"])
    next [] if ADR_0009_P1_007_REQUIRED_TESTS.all? { |test_id| tests.include?(test_id) } &&
               ADR_0009_P1_007_MATERIALIZATION_FRAGMENTS.all? do |fragment|
                 acceptance.include?(fragment)
               end

    ["STEAD-P1-007 must own ADR-0009 full-reconciliation, audit-minimization, and upgrade/rollback tests plus the exact audit-materialization and successor-obligation acceptance"]
  end
  unless p1_007["owner"] == "WS-07" &&
         p1_007["contributors"] == %w[WS-01 WS-02 WS-03 WS-06 WS-12 WS-13] &&
         schema_contract_paths.all? { |path| p1_007_acceptance.include?(path) } &&
         p1_007_acceptance.include?("Activate emission only after all named schemas are registered and validated") &&
         p1_007_acceptance.include?("audit v1.0/v1.1 and both specialized events are consumer-readable") &&
         p1_007_acceptance.include?("rollback stops new emission while old and new readers remain available") &&
         p1_007_materialization_failures.call(p1_007).empty?
    failures << "STEAD-P1-007 must preserve exact ADR-0009 schema ownership, tests, event minimization, fresh-authorized evidence resolution, append-only idempotent audit materialization, recovery, and compatible rollback"
  end

  ADR_0009_P1_007_REQUIRED_TESTS.each do |test_id|
    adr_0009_cross_contract_mutation_count += 1
    mutated_issue = Marshal.load(Marshal.dump(p1_007))
    removed = mutated_issue.fetch("automated_tests").delete(test_id)
    if removed.nil? || p1_007_materialization_failures.call(mutated_issue).empty?
      adr_0009_cross_contract_mutation_survivors << "P1-007 #{test_id} deletion"
    end
  end
  ADR_0009_P1_007_MATERIALIZATION_FRAGMENTS.each do |fragment|
    adr_0009_cross_contract_mutation_count += 1
    mutated_issue = Marshal.load(Marshal.dump(p1_007))
    changed = false
    mutated_issue.fetch("acceptance_criteria").map! do |criterion|
      next criterion unless criterion.include?(fragment)

      changed = true
      criterion.sub(fragment, "mutated ADR-0009 materialization clause")
    end
    if !changed || p1_007_materialization_failures.call(mutated_issue).empty?
      adr_0009_cross_contract_mutation_survivors << "P1-007 acceptance fragment #{fragment.inspect}"
    end
  end
else
  failures << "implementation issue catalog must contain STEAD-P1-003, STEAD-P1-006, and STEAD-P1-007"
end
asyncapi = load_yaml("specs/asyncapi/stead.yaml")
classification_bypass_path = ROOT.join("docs/security/classification-bypass-inventory.md")
classification_bypass_source = classification_bypass_path.open("rb") do |file|
  file.read(ADR_0008_CLASSIFICATION_BYPASS_SOURCE_BYTES + 1).to_s
end
classification_bypass_source.force_encoding(Encoding::UTF_8)
unless classification_bypass_source.valid_encoding?
  failures << "docs/security/classification-bypass-inventory.md must be valid UTF-8"
  classification_bypass_source = ""
end
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
adr_0009_adr_mutation_survivors = []
adr_0009_adr_mutation_count = 0
adr_0008_source = nil
adr_0009_source = nil
adr_0009_proposed_fixture_source = nil
adr_0009_proposed_fixture_catalog_source = nil
adr_0009_proposed_fixture_gate = nil

paths.each do |path|
  basename = path.basename.to_s
  number = basename[/\A(\d{4})-/, 1]
  next unless EXPECTED_RECORDS.key?(number)

  expected = EXPECTED_RECORDS.fetch(number)
  source = path.read(encoding: "UTF-8")
  adr_0008_source = source if number == "0008"
  adr_0009_source = source if number == "0009"
  relative = path.relative_path_from(ROOT).to_s
  expected_adr_id = "ADR-#{number}"

  failures << "#{relative}: title must begin '# #{expected_adr_id}:'" unless source.start_with?("# #{expected_adr_id}:")
  required_sections = if number == "0009"
                        [
                          "Context",
                          "Decision drivers",
                          "Considered options",
                          "Decision",
                          "Consequences",
                          "Migration, upgrade, rollback, and recovery",
                          "Verification",
                          "Reviews and approvals"
                        ]
                      else
                        REQUIRED_SECTIONS
                      end
  required_sections.each do |section|
    failures << "#{relative}: missing section #{section.inspect}" unless source.match?(/^## #{Regexp.escape(section)}$/)
  end

  status = source[/^- \*\*Status:\*\*\s*(.+)$/, 1]
  expected_state = if (number == "0008" && adr_0008_acceptance_metadata) ||
                      (number == "0009" && adr_0009_acceptance_metadata)
                     "ACCEPTED"
                   else
                     expected.fetch(:state)
                   end
  expected_status_prefix = expected_state == "ACCEPTED" ? "Accepted" : "Proposed"
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
    current_adr_0009_source = source
    adr_0009_gate = adr_gates["ADR-CAND-008"]
    if adr_0009_acceptance_metadata
      decision_revision = adr_0009_acceptance_metadata.fetch(:immutable_revision)
      proposed_source, proposed_source_error = adr_0008_git_file_at(
        decision_revision,
        ADR_0009_DECISION_RECORD_PATH
      )
      proposed_catalog, proposed_catalog_error = adr_0008_git_file_at(
        decision_revision,
        ADR_0009_ISSUE_CATALOG_PATH
      )
      failures << proposed_source_error if proposed_source_error
      failures << proposed_catalog_error if proposed_catalog_error
      if proposed_catalog
        proposed_gate, proposed_gate_failures = adr_0009_catalog_gate_from_source(
          proposed_catalog,
          filename: "#{ADR_0009_ISSUE_CATALOG_PATH}@#{decision_revision}"
        )
        failures.concat(proposed_gate_failures)
        adr_0009_gate = proposed_gate
      end
      source = proposed_source if proposed_source
      adr_0009_proposed_fixture_source = proposed_source
      adr_0009_proposed_fixture_catalog_source = proposed_catalog
      adr_0009_proposed_fixture_gate = adr_0009_gate
    else
      adr_0009_proposed_fixture_source = source
      adr_0009_proposed_fixture_catalog_source = issue_catalog_source
      adr_0009_proposed_fixture_gate = adr_0009_gate
    end

    failures.concat(
      adr_0009_governance_gate_failures(
        source: source,
        gate: adr_0009_gate,
        gate_count: adr_0009_gate_records.length
      )
    )

    adr_mutations = {
      decision_digest: [
        source.sub(
          ADR_0009_DECISION_FRAGMENT_PREDICATES.fetch(:zero_page_control_writes),
          "The operation permits one durable write per eligible page"
        ),
        ->(mutated) { adr_0009_decision_body_failures(mutated).any? }
      ],
      owner_metadata: [
        source.sub(ADR_0009_OWNER_APPROVAL_LINE, "- **Project-owner approval required:** no"),
        ->(mutated) { adr_0009_document_governance_predicate_failures(mutated).include?(:metadata_owner_required) }
      ],
      supersession_metadata: [
        source.sub(ADR_0009_SUPERSESSION_LINE, "- **Supersedes / superseded by:** supersedes all provider rules"),
        ->(mutated) { adr_0009_document_governance_predicate_failures(mutated).include?(:metadata_supersession_narrow) }
      ],
      proposed_reviews: [
        source.sub(ADR_0009_FOOTNOTE_MARKER, "Unreviewed amendment.\n\n#{ADR_0009_FOOTNOTE_MARKER}"),
        ->(mutated) { adr_0009_document_governance_predicate_failures(mutated).include?(:proposed_reviews) }
      ]
    }
    unless adr_mutations.keys == ADR_0009_EXPECTED_ADR_MUTATIONS
      failures << "ADR-0009 bounded ADR mutation inventory differs from the pinned inventory"
    end
    adr_mutations.each do |name, (mutated, oracle)|
      adr_0009_adr_mutation_count += 1
      unless mutated != source && oracle.call(mutated)
        adr_0009_adr_mutation_survivors << name
      end
    end
    source = current_adr_0009_source
  end

  if expected_state == "ACCEPTED"
    failures << "docs/adr/INDEX.md: missing #{basename}" unless adr_index.include?("./#{basename}")
    failures << "docs/governance/adr-candidate-index.md: missing #{basename}" unless candidate_index.include?("../adr/#{basename}")
    failures << "docs/adr/unresolved-implementation-choices.md: missing #{basename}" unless choice_queue.include?("./#{basename}")
  elsif expected_state == "PROPOSED"
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
  failures << "implementation issue catalog: #{candidate} state must be #{expected_state}" unless gate["state"] == expected_state
  failures << "implementation issue catalog: #{candidate} decision_record must be #{relative}" unless gate["decision_record"] == relative
  failures << "implementation issue catalog: #{candidate} project-owner flag mismatch" unless gate["project_owner_approval_required"] == expected.fetch(:owner_approval)

  acceptance = case number
               when "0008" then adr_0008_acceptance_metadata
               when "0009" then adr_0009_acceptance_metadata
               else ACCEPTED_RECORD_METADATA[number]
               end
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
      bypass_source: classification_bypass_source,
      acceptance_metadata: adr_0008_acceptance_metadata
    )
  )
else
  failures << "ADR-0008 source unavailable for security contract validation"
end

if adr_0008_acceptance_metadata && adr_0008_source
  approval_record_path = ROOT.join(ADR_0008_APPROVAL_RECORD_PATH)
  if approval_record_path.file? && !approval_record_path.symlink?
    approval_record = approval_record_path.read(encoding: "UTF-8")
    failures.concat(
      adr_0008_acceptance_surface_failures(
        adr_source: adr_0008_source,
        gate: adr_gates["ADR-CAND-006"],
        approval_record: approval_record,
        metadata: adr_0008_acceptance_metadata
      )
    )
  else
    failures << "#{ADR_0008_APPROVAL_RECORD_PATH}: accepted ADR-0008 approval record is missing"
  end
  failures.concat(adr_0008_live_acceptance_history_failures(adr_0008_acceptance_metadata))
end

if adr_0009_acceptance_metadata && adr_0009_source && adr_0009_proposed_fixture_source
  approval_record_path = ROOT.join(ADR_0009_APPROVAL_RECORD_PATH)
  if approval_record_path.file? && !approval_record_path.symlink?
    approval_record = approval_record_path.read(encoding: "UTF-8")
    failures.concat(
      adr_0009_acceptance_surface_failures(
        current_adr_source: adr_0009_source,
        proposed_adr_source: adr_0009_proposed_fixture_source,
        gate: adr_gates["ADR-CAND-008"],
        approval_record: approval_record,
        metadata: adr_0009_acceptance_metadata
      )
    )
  else
    failures << "#{ADR_0009_APPROVAL_RECORD_PATH}: accepted ADR-0009 approval record is missing"
  end
  failures.concat(adr_0009_live_acceptance_history_failures(adr_0009_acceptance_metadata))
end

# Exercise ADR-0009's future mechanical acceptance seam while the live record
# remains Proposed. These fixtures never mutate repository state.
adr_0009_acceptance_mutation_survivors = []
adr_0009_acceptance_mutation_names = []
if adr_0009_proposed_fixture_source && adr_0009_proposed_fixture_catalog_source && adr_0009_proposed_fixture_gate
  future_metadata = {
    immutable_revision: "0123456789abcdef0123456789abcdef01234567",
    accepted_at: "2026-09-04",
    approval_record_path: ADR_0009_APPROVAL_RECORD_PATH,
    approval_records: [
      { "role" => "WS-03-provider-reconciliation", "identity" => "/root/adr0009_fixture_contract_review", "disposition" => "APPROVED" },
      { "role" => "WS-01-architecture", "identity" => "/root/adr0009_fixture_arch_review", "disposition" => "APPROVED" },
      { "role" => "WS-02-canonical-transaction", "identity" => "/root/adr0009_fixture_transaction_review", "disposition" => "APPROVED" },
      { "role" => "WS-06-authorization-classification", "identity" => "/root/adr0009_fixture_authorization_review", "disposition" => "APPROVED" },
      { "role" => "WS-07-event-audit", "identity" => "/root/adr0009_fixture_audit_review", "disposition" => "APPROVED" },
      { "role" => "WS-12-deployment-operations", "identity" => "/root/adr0009_fixture_operations_review", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-qa", "identity" => "/root/adr0009_fixture_qa_review", "disposition" => "APPROVED" },
      { "role" => "WS-13-independent-security", "identity" => "/root/adr0009_fixture_security_review", "disposition" => "APPROVED" },
      { "role" => "project-owner", "identity" => "explicit 2026-09-03 project-owner approval", "disposition" => "APPROVED" }
    ].map(&:freeze).freeze
  }.freeze
  accepted_gate = adr_0009_proposed_fixture_gate.merge(
    "state" => "ACCEPTED",
    "immutable_revision" => future_metadata.fetch(:immutable_revision),
    "accepted_at" => future_metadata.fetch(:accepted_at),
    "approval_record" => future_metadata.fetch(:approval_record_path),
    "approval_records" => future_metadata.fetch(:approval_records)
  )
  accepted_adr = adr_0009_accepted_adr_fixture(adr_0009_proposed_fixture_source, future_metadata)
  approval_record = adr_0009_approval_record_fixture(future_metadata)
  positive_metadata, positive_metadata_failures = adr_0009_acceptance_metadata_from_gate(accepted_gate)
  failures << "ADR-0009 future accepted metadata fixture failed: #{positive_metadata_failures.join('; ')}" unless positive_metadata == future_metadata && positive_metadata_failures.empty?
  positive_surface_failures = adr_0009_acceptance_surface_failures(
    current_adr_source: accepted_adr,
    proposed_adr_source: adr_0009_proposed_fixture_source,
    gate: accepted_gate,
    approval_record: approval_record,
    metadata: future_metadata
  )
  failures << "ADR-0009 future accepted surface fixture failed: #{positive_surface_failures.join('; ')}" unless positive_surface_failures.empty?
  accepted_catalog_source, accepted_catalog_failures = adr_0009_accepted_catalog_source_fixture(
    adr_0009_proposed_fixture_catalog_source,
    future_metadata
  )
  failures.concat(accepted_catalog_failures)
  if accepted_catalog_source
    transition_failures = adr_0009_catalog_transition_failures(
      parent_source: adr_0009_proposed_fixture_catalog_source,
      child_source: accepted_catalog_source,
      metadata: future_metadata
    )
    failures << "ADR-0009 future accepted catalog fixture failed: #{transition_failures.join('; ')}" unless transition_failures.empty?
  end
  [ADR_0009_ADR_INDEX_PATH, ADR_0009_CHOICE_QUEUE_PATH, ADR_0009_CANDIDATE_INDEX_PATH].each do |path|
    expected_source, index_failures = adr_0009_expected_index_transition(
      path: path,
      parent_source: ROOT.join(path).read(encoding: "UTF-8"),
      metadata: future_metadata
    )
    failures << "ADR-0009 future accepted #{path} fixture failed: #{index_failures.join('; ')}" unless expected_source && index_failures.empty?
  end

  decision_revision = "a" * 40
  acceptance_revision = "b" * 40
  side_revision = "c" * 40
  merge_revision = "d" * 40
  positive_graph = {
    decision_revision => [],
    acceptance_revision => [decision_revision],
    side_revision => [decision_revision],
    merge_revision => [acceptance_revision, side_revision]
  }
  positive_graph_failures = adr_0009_acceptance_graph_failures(
    immutable_revision: decision_revision,
    repository_available: true,
    shallow: false,
    head_revision: merge_revision,
    commits: positive_graph,
    acceptance_transitions: [acceptance_revision]
  )
  failures << "ADR-0009 future acceptance graph must allow later normal merges: #{positive_graph_failures.join('; ')}" unless positive_graph_failures.empty?

  record_mutation = lambda do |name, killed|
    adr_0009_acceptance_mutation_names << name
    adr_0009_acceptance_mutation_survivors << name unless killed
  end

  missing_revision_gate = accepted_gate.reject { |key, _value| key == "immutable_revision" }
  _metadata, mutation_failures = adr_0009_acceptance_metadata_from_gate(missing_revision_gate)
  record_mutation.call("accepted gate missing immutable revision", mutation_failures.any? { |failure| failure.include?("omits acceptance fields") })

  missing_owner_metadata = future_metadata.merge(
    approval_records: future_metadata.fetch(:approval_records).reject { |record| record.fetch("role") == "project-owner" }
  )
  record_mutation.call(
    "accepted gate missing project-owner approval",
    adr_0009_acceptance_metadata_failures(missing_owner_metadata).any? { |failure| failure.include?("omit roles: project-owner") }
  )

  wrong_owner_records = future_metadata.fetch(:approval_records).map do |record|
    record.fetch("role") == "project-owner" ? record.merge("disposition" => "NOT_REQUIRED") : record
  end
  record_mutation.call(
    "accepted gate wrong project-owner disposition",
    adr_0009_acceptance_metadata_failures(future_metadata.merge(approval_records: wrong_owner_records)).any? do |failure|
      failure.include?("project-owner disposition must be APPROVED")
    end
  )

  invalid_owner_records = future_metadata.fetch(:approval_records).map do |record|
    record.fetch("role") == "project-owner" ? record.merge("identity" => "implicit owner approval") : record
  end
  record_mutation.call(
    "accepted gate invalid project-owner identity",
    adr_0009_acceptance_metadata_failures(future_metadata.merge(approval_records: invalid_owner_records)).any? do |failure|
      failure.include?("must name one explicit bounded project-owner identity")
    end
  )

  duplicate_owner_records = future_metadata.fetch(:approval_records) + [future_metadata.fetch(:approval_records).last]
  record_mutation.call(
    "accepted gate duplicate project-owner approval",
    adr_0009_acceptance_metadata_failures(future_metadata.merge(approval_records: duplicate_owner_records)).any? do |failure|
      failure.include?("duplicate roles: project-owner")
    end
  )

  wrong_revision = "f" * 40
  mixed_adr = accepted_adr.sub(
    "| Contract owner (WS-03) | `/root/adr0009_fixture_contract_review` | `#{future_metadata.fetch(:immutable_revision)}` |",
    "| Contract owner (WS-03) | `/root/adr0009_fixture_contract_review` | `#{wrong_revision}` |"
  )
  record_mutation.call(
    "accepted gate mixed reviewer revision surface",
    adr_0009_acceptance_surface_failures(
      current_adr_source: mixed_adr,
      proposed_adr_source: adr_0009_proposed_fixture_source,
      gate: accepted_gate,
      approval_record: approval_record,
      metadata: future_metadata
    ).any? { |failure| failure.include?("records-only transition") }
  )

  owner_row = ADR_0009_ACCEPTED_REVIEW_ROLES.last
  owner_record = future_metadata.fetch(:approval_records).last
  canonical_owner_line = "| #{owner_row.fetch(:label)} | `#{owner_record.fetch('identity')}` | `#{future_metadata.fetch(:immutable_revision)}` | #{owner_record.fetch('disposition')} | #{owner_row.fetch(:evidence)} |\n"
  record_mutation.call(
    "approval record missing project-owner row",
    adr_0009_acceptance_surface_failures(
      current_adr_source: accepted_adr,
      proposed_adr_source: adr_0009_proposed_fixture_source,
      gate: accepted_gate,
      approval_record: approval_record.sub(canonical_owner_line, ""),
      metadata: future_metadata
    ).any? { |failure| failure.include?("approval record must exactly match") }
  )
  record_mutation.call(
    "approval record wrong project-owner revision",
    adr_0009_acceptance_surface_failures(
      current_adr_source: accepted_adr,
      proposed_adr_source: adr_0009_proposed_fixture_source,
      gate: accepted_gate,
      approval_record: approval_record.sub(canonical_owner_line, canonical_owner_line.sub(future_metadata.fetch(:immutable_revision), wrong_revision)),
      metadata: future_metadata
    ).any? { |failure| failure.include?("approval record must exactly match") }
  )
  record_mutation.call(
    "approval record mixed non-owner revision",
    adr_0009_acceptance_surface_failures(
      current_adr_source: accepted_adr,
      proposed_adr_source: adr_0009_proposed_fixture_source,
      gate: accepted_gate,
      approval_record: approval_record.sub(future_metadata.fetch(:immutable_revision), wrong_revision),
      metadata: future_metadata
    ).any? { |failure| failure.include?("approval record must exactly match") }
  )

  canonical_changes = ADR_0009_ACCEPTANCE_TRANSITION_CHANGES.dup
  record_mutation.call(
    "acceptance change adds implementation path",
    adr_0009_acceptance_transition_change_failures(canonical_changes.merge("providers/gitea/client.go" => "A")).any? do |failure|
      failure.include?("outside the closed approval/gate/review allowlist")
    end
  )
  record_mutation.call(
    "acceptance change omits required record path",
    adr_0009_acceptance_transition_change_failures(canonical_changes.reject { |path, _status| path == ADR_0009_APPROVAL_RECORD_PATH }).any? do |failure|
      failure.include?("omits required record paths")
    end
  )
  record_mutation.call(
    "acceptance change uses wrong path status",
    adr_0009_acceptance_transition_change_failures(canonical_changes.merge(ADR_0009_APPROVAL_RECORD_PATH => "M")).any? do |failure|
      failure.include?("noncanonical record changes")
    end
  )

  graph_check = lambda do |commits, transitions, head = merge_revision|
    adr_0009_acceptance_graph_failures(
      immutable_revision: decision_revision,
      repository_available: true,
      shallow: false,
      head_revision: head,
      commits: commits,
      acceptance_transitions: transitions
    )
  end
  record_mutation.call(
    "history omits acceptance transition",
    graph_check.call(positive_graph, []).any? { |failure| failure.include?("exactly one reachable") }
  )
  intermediate_revision = "e" * 40
  non_direct_graph = {
    decision_revision => [],
    intermediate_revision => [decision_revision],
    acceptance_revision => [intermediate_revision]
  }
  record_mutation.call(
    "history uses non-direct acceptance descendant",
    graph_check.call(non_direct_graph, [acceptance_revision], acceptance_revision).any? { |failure| failure.include?("single-parent immediate child") }
  )
  merge_child_graph = {
    decision_revision => [],
    side_revision => [decision_revision],
    acceptance_revision => [decision_revision, side_revision]
  }
  record_mutation.call(
    "history uses merge acceptance child",
    graph_check.call(merge_child_graph, [acceptance_revision], acceptance_revision).any? { |failure| failure.include?("single-parent immediate child") }
  )
  second_acceptance_revision = "e" * 40
  multiple_graph = positive_graph.merge(
    second_acceptance_revision => [decision_revision],
    merge_revision => [acceptance_revision, second_acceptance_revision]
  )
  record_mutation.call(
    "history contains multiple acceptance transitions",
    graph_check.call(multiple_graph, [acceptance_revision, second_acceptance_revision]).any? { |failure| failure.include?("exactly one reachable") }
  )
  unreachable_graph = {
    decision_revision => [],
    acceptance_revision => [decision_revision],
    side_revision => [],
    merge_revision => [side_revision]
  }
  record_mutation.call(
    "history decision revision is not reachable",
    graph_check.call(unreachable_graph, [acceptance_revision]).any? { |failure| failure.include?("not an ancestor") }
  )
end

unless adr_0009_acceptance_mutation_names == ADR_0009_EXPECTED_ACCEPTANCE_MUTATION_NAMES
  failures << "ADR-0009 acceptance mutation inventory differs from the pinned inventory"
end
unless adr_0009_acceptance_mutation_survivors.empty?
  failures << "ADR-0009 acceptance mutation survivors: #{adr_0009_acceptance_mutation_survivors.join(', ')}"
end

adr_0008_proposed_fixture_source = adr_0008_source
adr_0008_proposed_fixture_gate = adr_gates["ADR-CAND-006"]
adr_0008_proposed_fixture_catalog_source = issue_catalog_source
if adr_0008_acceptance_metadata
  fixture_parent_revision = adr_0008_acceptance_metadata.fetch(:immutable_revision)
  parent_adr_source, parent_adr_error = adr_0008_git_file_at(
    fixture_parent_revision,
    ADR_0008_DECISION_RECORD_PATH
  )
  parent_catalog_source, parent_catalog_error = adr_0008_git_file_at(
    fixture_parent_revision,
    ADR_0008_ISSUE_CATALOG_PATH
  )
  failures << parent_adr_error if parent_adr_error
  failures << parent_catalog_error if parent_catalog_error
  adr_0008_proposed_fixture_source = parent_adr_source
  adr_0008_proposed_fixture_catalog_source = parent_catalog_source
  if parent_catalog_source
    parent_gate, parent_gate_failures = adr_0008_catalog_gate_from_source(
      parent_catalog_source,
      filename: "#{ADR_0008_ISSUE_CATALOG_PATH}@#{fixture_parent_revision}"
    )
    failures.concat(parent_gate_failures)
    adr_0008_proposed_fixture_gate = parent_gate
  else
    adr_0008_proposed_fixture_gate = nil
  end
end

# Exercise both sides of the acceptance seam before an approval record exists.
# The fixture is local data only: repository state remains Proposed until a
# later mechanical commit supplies the matching metadata and record updates.
adr_0008_record_mutations = []
adr_0008_future_acceptance_metadata = {
  immutable_revision: "0123456789abcdef0123456789abcdef01234567",
  accepted_at: "2026-09-04",
  approval_record_path: ADR_0008_APPROVAL_RECORD_PATH,
  approval_records: [
    { "role" => "WS-01-architecture", "identity" => "/root/adr0008_fixture_arch_review", "disposition" => "APPROVED" },
    { "role" => "WS-02-core-outbox", "identity" => "/root/adr0008_fixture_outbox_review", "disposition" => "APPROVED" },
    { "role" => "WS-06-security-contract", "identity" => "/root/adr0008_fixture_contract_review", "disposition" => "APPROVED" },
    { "role" => "WS-07-events-worker", "identity" => "/root/adr0008_fixture_events_review", "disposition" => "APPROVED" },
    { "role" => "WS-08-projection", "identity" => "/root/adr0008_fixture_projection_review", "disposition" => "APPROVED" },
    { "role" => "WS-12-deployment-operations", "identity" => "/root/adr0008_fixture_ops_review", "disposition" => "APPROVED" },
    { "role" => "WS-13-independent-qa", "identity" => "/root/adr0008_fixture_qa_review", "disposition" => "APPROVED" },
    { "role" => "WS-13-independent-security", "identity" => "/root/adr0008_fixture_security_review", "disposition" => "APPROVED" },
    { "role" => "project-owner", "identity" => "not required for this conforming selection", "disposition" => "NOT_REQUIRED" }
  ].map(&:freeze).freeze
}.freeze

if adr_0008_proposed_fixture_source
  if adr_0008_proposed_fixture_source.include?(ADR_0008_REVIEWS_HEADING)
    fixture_status = adr_0008_accepted_status_line(adr_0008_future_acceptance_metadata)
    fixture_reviews = adr_0008_accepted_reviews_tail(adr_0008_future_acceptance_metadata)
    unless fixture_status == ADR_0008_FUTURE_ACCEPTED_FIXTURE_STATUS_LINE &&
           fixture_reviews.bytesize == ADR_0008_FUTURE_ACCEPTED_FIXTURE_REVIEWS_BYTES &&
           Digest::SHA256.hexdigest(fixture_reviews) == ADR_0008_FUTURE_ACCEPTED_FIXTURE_REVIEWS_SHA256
      failures << "ADR-0008 future accepted fixture serialization changed"
    end
    accepted_fixture = adr_0008_accepted_adr_fixture(
      adr_0008_proposed_fixture_source,
      adr_0008_future_acceptance_metadata
    )
    accepted_fixture_failures = adr_0008_substantive_source_failures(
      accepted_fixture,
      acceptance_metadata: adr_0008_future_acceptance_metadata
    )
    unless accepted_fixture_failures.empty?
      failures << "ADR-0008 future accepted positive fixture failed: #{accepted_fixture_failures.join('; ')}"
    end

    fixture_revision = adr_0008_future_acceptance_metadata.fetch(:immutable_revision)
    wrong_revision = "f" * 40
    expected_status = adr_0008_accepted_status_line(adr_0008_future_acceptance_metadata)
    wrong_status_revision = expected_status.sub(fixture_revision, wrong_revision)
    adr_0008_record_mutations << {
      name: "wrong accepted status revision with expected revision in review tail",
      source: accepted_fixture.sub(expected_status, wrong_status_revision),
      metadata: adr_0008_future_acceptance_metadata,
      baseline: accepted_fixture,
      expected_failure_fragment: "accepted status must exactly match its acceptance metadata"
    }

    adr_0008_record_mutations << {
      name: "wrong accepted status date",
      source: accepted_fixture.sub(" on 2026-09-04\n", " on 2026-09-05\n"),
      metadata: adr_0008_future_acceptance_metadata,
      baseline: accepted_fixture,
      expected_failure_fragment: "accepted status must exactly match its acceptance metadata"
    }

    architecture_revision = "| Architecture and standards (WS-01) | `/root/adr0008_fixture_arch_review` | `#{fixture_revision}` |"
    adr_0008_record_mutations << {
      name: "mixed accepted review revision",
      source: accepted_fixture.sub(architecture_revision, architecture_revision.sub(fixture_revision, wrong_revision)),
      metadata: adr_0008_future_acceptance_metadata,
      baseline: accepted_fixture,
      expected_failure_fragment: "accepted Reviews and approvals tail must match the exact metadata-derived table"
    }

    {
      "accepted review amendment" => "\nReview amendment: accept a different revision.\n",
      "accepted level-three amendment" => "\n### Amendment\n\nAccept a different revision.\n",
      "accepted raw-HTML amendment" => "\n<aside>Accept a different revision.</aside>\n"
    }.each do |name, addition|
      adr_0008_record_mutations << {
        name: name,
        source: accepted_fixture + addition,
        metadata: adr_0008_future_acceptance_metadata,
        baseline: accepted_fixture,
        expected_failure_fragment: "accepted Reviews and approvals tail must match the exact metadata-derived table"
      }
    end

    qa_row = accepted_fixture.lines.find { |line| line.start_with?("| Independent QA (WS-13) |") }
    if qa_row
      adr_0008_record_mutations << {
        name: "missing accepted review role",
        source: accepted_fixture.sub(qa_row, ""),
        metadata: adr_0008_future_acceptance_metadata,
        baseline: accepted_fixture,
        expected_failure_fragment: "accepted Reviews and approvals tail must match the exact metadata-derived table"
      }
      adr_0008_record_mutations << {
        name: "duplicate accepted review role",
        source: accepted_fixture.sub(qa_row, qa_row * 2),
        metadata: adr_0008_future_acceptance_metadata,
        baseline: accepted_fixture,
        expected_failure_fragment: "accepted Reviews and approvals tail must match the exact metadata-derived table"
      }
    end

    missing_role_metadata = adr_0008_future_acceptance_metadata.merge(
      approval_records: adr_0008_future_acceptance_metadata.fetch(:approval_records).reject do |record|
        record.fetch("role") == "WS-13-independent-qa"
      end
    )
    adr_0008_record_mutations << {
      name: "missing acceptance-metadata role",
      source: accepted_fixture,
      metadata: missing_role_metadata,
      baseline: accepted_fixture,
      baseline_metadata: adr_0008_future_acceptance_metadata,
      expected_failure_fragment: "acceptance approval records omit roles"
    }

    duplicate_role_records = adr_0008_future_acceptance_metadata.fetch(:approval_records).dup
    duplicate_role_records.insert(7, duplicate_role_records.fetch(6).dup)
    duplicate_role_metadata = adr_0008_future_acceptance_metadata.merge(
      approval_records: duplicate_role_records
    )
    adr_0008_record_mutations << {
      name: "duplicate acceptance-metadata role",
      source: accepted_fixture,
      metadata: duplicate_role_metadata,
      baseline: accepted_fixture,
      baseline_metadata: adr_0008_future_acceptance_metadata,
      expected_failure_fragment: "acceptance approval records duplicate roles"
    }
  end

  adr_0008_record_mutations << {
    name: "proposed review amendment",
    source: adr_0008_proposed_fixture_source + "\nReview amendment: accept a different revision.\n",
    metadata: nil,
    baseline: adr_0008_proposed_fixture_source,
    expected_failure_fragment: "proposed Reviews and approvals tail must match the exact pinned proposal"
  }
end

actual_record_mutation_names = adr_0008_record_mutations.map { |mutation| mutation.fetch(:name) }
unless actual_record_mutation_names.sort == ADR_0008_EXPECTED_RECORD_MUTATION_NAMES.sort
  failures << "ADR-0008 record mutation inventory changed: expected #{ADR_0008_EXPECTED_RECORD_MUTATION_NAMES.inspect}, found #{actual_record_mutation_names.inspect}"
end
unless adr_0008_record_mutations.map { |mutation| [mutation.fetch(:source), mutation.fetch(:metadata)] }.uniq.length ==
       adr_0008_record_mutations.length &&
       adr_0008_record_mutations.all? do |mutation|
         mutation.fetch(:source) != mutation.fetch(:baseline) ||
           mutation.fetch(:metadata) != mutation.fetch(:baseline_metadata, mutation.fetch(:metadata))
       end
  failures << "ADR-0008 record mutations must be independent non-no-op fixtures"
end

adr_0008_record_mutation_survivors = adr_0008_record_mutations.filter_map do |mutation|
  mutation_failures = adr_0008_substantive_source_failures(
    mutation.fetch(:source),
    acceptance_metadata: mutation.fetch(:metadata)
  )
  expected = mutation.fetch(:expected_failure_fragment)
  mutation.fetch(:name) unless mutation_failures.any? { |failure| failure.include?(expected) }
end
unless adr_0008_record_mutation_survivors.empty?
  failures << "ADR-0008 record mutation survivors: #{adr_0008_record_mutation_survivors.join(', ')}"
end

# Prove the future acceptance record binds to a real, exact parent edge without
# embedding this still-Proposed candidate's eventual commit ID. The synthetic
# graph includes a later descendant and a normal merge so acceptance remains
# valid after integration while the original transition edge stays immutable.
adr_0008_approval_record_mutations = []
adr_0008_catalog_source_mutations = []
adr_0008_history_mutations = []
if adr_0008_proposed_fixture_source &&
   adr_0008_proposed_fixture_catalog_source.is_a?(String) &&
   defined?(accepted_fixture) && accepted_fixture
  fixture_revision = adr_0008_future_acceptance_metadata.fetch(:immutable_revision)
  fixture_ancestor = "a" * 40
  fixture_acceptance = "1" * 40
  fixture_later = "2" * 40
  fixture_sibling = "b" * 40
  fixture_head = "3" * 40
  fixture_second_acceptance = "4" * 40
  fixture_nonexistent = "f" * 40
  fixture_commits = {
    fixture_ancestor => [],
    fixture_revision => [fixture_ancestor],
    fixture_acceptance => [fixture_revision],
    fixture_later => [fixture_acceptance],
    fixture_sibling => [fixture_ancestor],
    fixture_head => [fixture_later, fixture_sibling]
  }.freeze

  fixture_gate = adr_0008_accepted_catalog_gate_fixture(adr_0008_future_acceptance_metadata)
  fixture_approval = adr_0008_approval_record_fixture(adr_0008_future_acceptance_metadata)
  fixture_derived_metadata, fixture_metadata_failures = adr_0008_acceptance_metadata_from_gate(fixture_gate)
  unless fixture_metadata_failures.empty? && fixture_derived_metadata == adr_0008_future_acceptance_metadata
    failures << "ADR-0008 future acceptance metadata derivation fixture failed: " \
                "#{fixture_metadata_failures.join('; ')}; derived=#{fixture_derived_metadata.inspect}"
  end
  unless adr_0008_proposed_fixture_gate.is_a?(Hash)
    failures << "ADR-0008 future acceptance fixture Proposed catalog gate is unavailable"
  end
  fixture_parent_catalog_source = adr_0008_proposed_fixture_catalog_source
  fixture_catalog_child_source = lambda do |metadata|
    child_source, child_failures = adr_0008_accepted_catalog_source_fixture(
      fixture_parent_catalog_source,
      metadata
    )
    unless child_failures.empty?
      failures << "ADR-0008 canonical catalog fixture generation failed: #{child_failures.join('; ')}"
    end
    child_source
  end
  fixture_child_catalog_source = fixture_catalog_child_source.call(adr_0008_future_acceptance_metadata)
  fixture_index_paths = [
    ADR_0008_ADR_INDEX_PATH,
    ADR_0008_CHOICE_QUEUE_PATH,
    ADR_0008_CANDIDATE_INDEX_PATH
  ].freeze
  proposed_index_sources = {}
  proposed_index_source_failures = []
  fixture_index_paths.each do |path|
    if adr_0008_acceptance_metadata
      parent_source, parent_error = adr_0008_git_file_at(
        adr_0008_acceptance_metadata.fetch(:immutable_revision),
        path
      )
      proposed_index_source_failures << parent_error if parent_error
      proposed_index_sources[path] = parent_source
    else
      proposed_index_sources[path] = ROOT.join(path).read(encoding: "UTF-8")
    end
  end
  fixture_index_sources = lambda do |metadata|
    index_failures = proposed_index_source_failures.dup
    sources = fixture_index_paths.to_h do |path|
      parent_source = proposed_index_sources[path]
      child_source, child_failures = adr_0008_expected_index_transition(
        path: path,
        parent_source: parent_source,
        metadata: metadata
      )
      index_failures.concat(child_failures)
      [path, { parent: parent_source, child: child_source }]
    end
    [sources, index_failures]
  end
  fixture_indexes, fixture_index_generation_failures =
    fixture_index_sources.call(adr_0008_future_acceptance_metadata)
  positive_surface_failures = adr_0008_acceptance_surface_failures(
    adr_source: accepted_fixture,
    gate: fixture_gate,
    approval_record: fixture_approval,
    metadata: adr_0008_future_acceptance_metadata
  )
  positive_history_failures = adr_0008_acceptance_graph_failures(
    immutable_revision: fixture_revision,
    repository_available: true,
    shallow: false,
    head_revision: fixture_head,
    commits: fixture_commits,
    acceptance_transitions: [fixture_acceptance]
  )
  positive_catalog_failures = adr_0008_catalog_transition_failures(
    parent_source: fixture_parent_catalog_source,
    child_source: fixture_child_catalog_source,
    metadata: adr_0008_future_acceptance_metadata
  )
  positive_change_failures = adr_0008_acceptance_transition_change_failures(
    ADR_0008_ACCEPTANCE_TRANSITION_CHANGES
  )
  positive_index_failures = fixture_index_generation_failures.dup
  fixture_indexes.each do |path, sources|
    positive_index_failures.concat(
      adr_0008_index_transition_failures(
        path: path,
        parent_source: sources.fetch(:parent),
        child_source: sources.fetch(:child),
        metadata: adr_0008_future_acceptance_metadata
      )
    )
  end
  unless positive_surface_failures.empty? && positive_history_failures.empty? &&
         positive_catalog_failures.empty? && positive_change_failures.empty? && positive_index_failures.empty?
    failures << "ADR-0008 exact-parent descendant/merge positive fixture failed: " \
                "#{(positive_surface_failures + positive_history_failures + positive_catalog_failures + positive_change_failures + positive_index_failures).join('; ')}"
  end

  consistent_fixture = lambda do |revision|
    metadata = adr_0008_future_acceptance_metadata.merge(immutable_revision: revision)
    indexes, index_failures = fixture_index_sources.call(metadata)
    failures << "ADR-0008 consistent index fixture generation failed: #{index_failures.join('; ')}" unless index_failures.empty?
    {
      metadata: metadata,
      source: adr_0008_accepted_adr_fixture(adr_0008_proposed_fixture_source, metadata),
      gate: adr_0008_accepted_catalog_gate_fixture(metadata),
      approval: adr_0008_approval_record_fixture(metadata),
      parent_catalog: fixture_parent_catalog_source,
      child_catalog: fixture_catalog_child_source.call(metadata),
      changes: ADR_0008_ACCEPTANCE_TRANSITION_CHANGES,
      indexes: indexes
    }
  end
  canonical_surface = {
    metadata: adr_0008_future_acceptance_metadata,
    source: accepted_fixture,
    gate: fixture_gate,
    approval: fixture_approval,
    parent_catalog: fixture_parent_catalog_source,
    child_catalog: fixture_child_catalog_source,
    changes: ADR_0008_ACCEPTANCE_TRANSITION_CHANGES,
    indexes: fixture_indexes
  }
  catalog_state_line = "    state: ACCEPTED\n"
  catalog_revision_line = "    immutable_revision: #{JSON.generate(fixture_revision)}\n"
  catalog_date_line = "    accepted_at: #{JSON.generate(adr_0008_future_acceptance_metadata.fetch(:accepted_at))}\n"
  if [catalog_state_line, catalog_revision_line, catalog_date_line].all? do |line|
       fixture_child_catalog_source.include?(line)
     end
    catalog_mutation_sources = {
      "duplicate foreign immutable revision before canonical" => fixture_child_catalog_source.sub(
        catalog_revision_line,
        "    immutable_revision: #{JSON.generate(fixture_nonexistent)}\n#{catalog_revision_line}"
      ),
      "alternate acceptance field ordering" => fixture_child_catalog_source.sub(
        catalog_revision_line + catalog_date_line,
        catalog_date_line + catalog_revision_line
      ),
      "alternate immutable revision quoting" => fixture_child_catalog_source.sub(
        catalog_revision_line,
        "    immutable_revision: '#{fixture_revision}'\n"
      ),
      "acceptance inline comment" => fixture_child_catalog_source.sub(
        catalog_date_line,
        catalog_date_line.chomp + " # acceptance date\n"
      ),
      "acceptance trailing whitespace" => fixture_child_catalog_source.sub(
        catalog_revision_line,
        catalog_revision_line.chomp + "  \n"
      ),
      "acceptance blank-line addition" => fixture_child_catalog_source.sub(
        catalog_state_line,
        catalog_state_line + "\n"
      ),
      "mixed canonical revision" => fixture_child_catalog_source.sub(
        catalog_revision_line,
        "    immutable_revision: #{JSON.generate(fixture_nonexistent)}\n"
      ),
      "unrelated top-level raw quoting" => fixture_child_catalog_source.sub(
        "schema_version: \"1.0\"\n",
        "schema_version: '1.0'\n"
      )
    }
    catalog_mutation_sources.each do |name, source|
      adr_0008_catalog_source_mutations << {
        name: name,
        surface: canonical_surface.merge(child_catalog: source),
        baseline: fixture_child_catalog_source,
        expected_failure_fragment: "acceptance catalog child must exactly match the metadata-derived canonical source"
      }
    end
  else
    failures << "ADR-0008 canonical catalog fixture omits required raw-source mutation anchors"
  end
  approval_security_row = fixture_approval.lines.find do |line|
    line.start_with?("| Independent security (WS-13) |")
  end
  approval_qa_row = fixture_approval.lines.find do |line|
    line.start_with?("| Independent QA (WS-13) |")
  end
  if approval_security_row && approval_qa_row
    approval_mutation_sources = {
      "post-table level-three contradictory amendment" =>
        fixture_approval + "\n### Acceptance amendment\n\nIndependent security: REVISE; not approved.\n",
      "post-table prose" => fixture_approval + "Unexpected post-table approval prose.\n",
      "post-table raw HTML" => fixture_approval + "<aside>Unexpected approval text.</aside>\n",
      "post-table HTML comment" => fixture_approval + "<!-- unexpected approval amendment -->\n",
      "post-table blank tail" => fixture_approval + "\n",
      "pre-table addition" => fixture_approval.sub(
        "## Exact-revision dispositions\n",
        "Unexpected pre-table approval prose.\n\n## Exact-revision dispositions\n"
      ),
      "duplicate approval row" => fixture_approval.sub(approval_qa_row, approval_qa_row * 2),
      "foreign approval row" => fixture_approval.sub(
        approval_security_row,
        approval_security_row +
          "| Foreign reviewer | `/root/foreign_review` | `#{fixture_revision}` | APPROVED | Foreign evidence |\n"
      ),
      "missing approval row" => fixture_approval.sub(approval_qa_row, ""),
      "mixed approval-row revision" => fixture_approval.sub(
        approval_security_row,
        approval_security_row.sub(fixture_revision, fixture_nonexistent)
      )
    }
    approval_mutation_sources.each do |name, source|
      adr_0008_approval_record_mutations << {
        name: name,
        surface: canonical_surface.merge(approval: source),
        baseline: fixture_approval,
        expected_failure_fragment: "approval record must exactly match the metadata-derived canonical document"
      }
    end
  else
    failures << "ADR-0008 canonical approval-record fixture omits required adversarial mutation rows"
  end
  canonical_graph = {
    immutable_revision: fixture_revision,
    repository_available: true,
    shallow: false,
    head_revision: fixture_head,
    commits: fixture_commits,
    acceptance_transitions: [fixture_acceptance]
  }

  adr_0008_history_mutations << {
    name: "unavailable Git history",
    surface: canonical_surface,
    graph: canonical_graph.merge(repository_available: false),
    expected_failure_fragment: "repository is unavailable"
  }
  adr_0008_history_mutations << {
    name: "shallow Git history",
    surface: canonical_surface,
    graph: canonical_graph.merge(shallow: true),
    expected_failure_fragment: "history is shallow"
  }
  ambiguous_commits = fixture_commits.merge(
    fixture_second_acceptance => [fixture_revision],
    fixture_head => [fixture_later, fixture_sibling, fixture_second_acceptance]
  )
  adr_0008_history_mutations << {
    name: "ambiguous acceptance transition",
    surface: canonical_surface,
    graph: canonical_graph.merge(
      commits: ambiguous_commits,
      acceptance_transitions: [fixture_acceptance, fixture_second_acceptance]
    ),
    expected_failure_fragment: "exactly one reachable mechanical acceptance transition"
  }

  {
    "consistent nonexistent decision revision" => [fixture_nonexistent, "does not exist"],
    "consistent ancestor decision revision" => [fixture_ancestor, "single-parent immediate child"],
    "consistent sibling decision revision" => [fixture_sibling, "single-parent immediate child"],
    "uppercase decision revision" => [fixture_revision.upcase, "exactly 40 lowercase hexadecimal characters"],
    "malformed decision revision" => [fixture_revision[0, 39], "exactly 40 lowercase hexadecimal characters"]
  }.each do |name, (revision, expected_failure_fragment)|
    adr_0008_history_mutations << {
      name: name,
      surface: consistent_fixture.call(revision),
      graph: canonical_graph.merge(immutable_revision: revision),
      expected_failure_fragment: expected_failure_fragment
    }
  end

  adr_0008_history_mutations << {
    name: "mixed decision revisions",
    surface: canonical_surface.merge(gate: fixture_gate.merge("immutable_revision" => fixture_sibling)),
    graph: canonical_graph,
    expected_failure_fragment: "catalog immutable revision must derive from acceptance metadata"
  }
  unrelated_catalog_source = fixture_child_catalog_source.sub(
    "scope: phase-1-foundation-complete\n",
    "scope: phase-1-foundation-mutated\n"
  )
  adr_0008_history_mutations << {
    name: "unrelated catalog semantics",
    surface: canonical_surface.merge(child_catalog: unrelated_catalog_source),
    graph: canonical_graph,
    expected_failure_fragment: "changes unrelated catalog semantics"
  }
  unrelated_indexes = Marshal.load(Marshal.dump(fixture_indexes))
  choice_queue_child = unrelated_indexes.fetch(ADR_0008_CHOICE_QUEUE_PATH).fetch(:child)
  unrelated_indexes.fetch(ADR_0008_CHOICE_QUEUE_PATH)[:child] = if choice_queue_child
                                                                  choice_queue_child.sub(
                                                                    "| `ADR-CAND-002` PostgreSQL module isolation and cross-module reads |",
                                                                    "| `ADR-CAND-002` MUTATED unrelated decision row |"
                                                                  )
                                                                end
  adr_0008_history_mutations << {
    name: "unrelated index row",
    surface: canonical_surface.merge(indexes: unrelated_indexes),
    graph: canonical_graph,
    expected_failure_fragment: "changes unrelated #{ADR_0008_CHOICE_QUEUE_PATH} content"
  }
  adr_0008_history_mutations << {
    name: "extra implementation path",
    surface: canonical_surface.merge(
      changes: ADR_0008_ACCEPTANCE_TRANSITION_CHANGES.merge("modules/audit/handler.go" => "M")
    ),
    graph: canonical_graph,
    expected_failure_fragment: "outside the closed approval/gate/review allowlist"
  }
  adr_0008_history_mutations << {
    name: "validator self-edit in acceptance transition",
    surface: canonical_surface.merge(
      changes: ADR_0008_ACCEPTANCE_TRANSITION_CHANGES.merge("scripts/validate_adr_records.rb" => "M")
    ),
    graph: canonical_graph,
    expected_failure_fragment: "outside the closed approval/gate/review allowlist"
  }
end

actual_catalog_source_mutation_names = adr_0008_catalog_source_mutations.map do |mutation|
  mutation.fetch(:name)
end
unless actual_catalog_source_mutation_names == ADR_0008_EXPECTED_CATALOG_SOURCE_MUTATION_NAMES
  failures << "ADR-0008 catalog-source mutation inventory changed: expected " \
              "#{ADR_0008_EXPECTED_CATALOG_SOURCE_MUTATION_NAMES.inspect}, found #{actual_catalog_source_mutation_names.inspect}"
end
unless adr_0008_catalog_source_mutations.map { |mutation| mutation.fetch(:surface).fetch(:child_catalog) }.uniq.length ==
       adr_0008_catalog_source_mutations.length &&
       adr_0008_catalog_source_mutations.all? do |mutation|
         mutation.fetch(:surface).fetch(:child_catalog) != mutation.fetch(:baseline)
       end
  failures << "ADR-0008 catalog-source mutations must be independent non-no-op fixtures"
end
adr_0008_catalog_source_mutation_survivors = adr_0008_catalog_source_mutations.filter_map do |mutation|
  surface = mutation.fetch(:surface)
  mutation_failures = adr_0008_catalog_transition_failures(
    parent_source: surface.fetch(:parent_catalog),
    child_source: surface.fetch(:child_catalog),
    metadata: surface.fetch(:metadata)
  )
  expected = mutation.fetch(:expected_failure_fragment)
  mutation.fetch(:name) unless mutation_failures.any? { |failure| failure.include?(expected) }
end
unless adr_0008_catalog_source_mutation_survivors.empty?
  failures << "ADR-0008 catalog-source mutation survivors: " \
              "#{adr_0008_catalog_source_mutation_survivors.join(', ')}"
end

actual_approval_record_mutation_names = adr_0008_approval_record_mutations.map do |mutation|
  mutation.fetch(:name)
end
unless actual_approval_record_mutation_names == ADR_0008_EXPECTED_APPROVAL_RECORD_MUTATION_NAMES
  failures << "ADR-0008 approval-record mutation inventory changed: expected " \
              "#{ADR_0008_EXPECTED_APPROVAL_RECORD_MUTATION_NAMES.inspect}, found #{actual_approval_record_mutation_names.inspect}"
end
unless adr_0008_approval_record_mutations.map { |mutation| mutation.fetch(:surface).fetch(:approval) }.uniq.length ==
       adr_0008_approval_record_mutations.length &&
       adr_0008_approval_record_mutations.all? do |mutation|
         mutation.fetch(:surface).fetch(:approval) != mutation.fetch(:baseline)
       end
  failures << "ADR-0008 approval-record mutations must be independent non-no-op fixtures"
end
adr_0008_approval_record_mutation_survivors = adr_0008_approval_record_mutations.filter_map do |mutation|
  surface = mutation.fetch(:surface)
  mutation_failures = adr_0008_acceptance_surface_failures(
    adr_source: surface.fetch(:source),
    gate: surface.fetch(:gate),
    approval_record: surface.fetch(:approval),
    metadata: surface.fetch(:metadata)
  )
  expected = mutation.fetch(:expected_failure_fragment)
  mutation.fetch(:name) unless mutation_failures.any? { |failure| failure.include?(expected) }
end
unless adr_0008_approval_record_mutation_survivors.empty?
  failures << "ADR-0008 approval-record mutation survivors: " \
              "#{adr_0008_approval_record_mutation_survivors.join(', ')}"
end

actual_history_mutation_names = adr_0008_history_mutations.map { |mutation| mutation.fetch(:name) }
unless actual_history_mutation_names == ADR_0008_EXPECTED_HISTORY_MUTATION_NAMES
  failures << "ADR-0008 acceptance-history mutation inventory changed: expected " \
              "#{ADR_0008_EXPECTED_HISTORY_MUTATION_NAMES.inspect}, found #{actual_history_mutation_names.inspect}"
end
history_mutation_survivors = adr_0008_history_mutations.filter_map do |mutation|
  surface = mutation.fetch(:surface)
  mutation_failures = adr_0008_acceptance_surface_failures(
    adr_source: surface.fetch(:source),
    gate: surface.fetch(:gate),
    approval_record: surface.fetch(:approval),
    metadata: surface.fetch(:metadata)
  )
  mutation_failures.concat(adr_0008_acceptance_graph_failures(**mutation.fetch(:graph)))
  mutation_failures.concat(
    adr_0008_catalog_transition_failures(
      parent_source: surface.fetch(:parent_catalog),
      child_source: surface.fetch(:child_catalog),
      metadata: surface.fetch(:metadata)
    )
  )
  mutation_failures.concat(adr_0008_acceptance_transition_change_failures(surface.fetch(:changes)))
  surface.fetch(:indexes).each do |path, sources|
    mutation_failures.concat(
      adr_0008_index_transition_failures(
        path: path,
        parent_source: sources.fetch(:parent),
        child_source: sources.fetch(:child),
        metadata: surface.fetch(:metadata)
      )
    )
  end
  expected = mutation.fetch(:expected_failure_fragment)
  mutation.fetch(:name) unless mutation_failures.any? { |failure| failure.include?(expected) }
end
unless history_mutation_survivors.empty?
  failures << "ADR-0008 acceptance-history mutation survivors: #{history_mutation_survivors.join(', ')}"
end

adr_0008_probe_environment_token = ENV[ADR_0008_REAL_HISTORY_PROBE_TOKEN_ENV]
adr_0008_probe_config = adr_0008_git_capture(
  "config",
  "--local",
  "--get",
  ADR_0008_REAL_HISTORY_PROBE_CONFIG_KEY
)
adr_0008_probe_config_token = adr_0008_probe_config.fetch(:stdout).strip if adr_0008_probe_config.fetch(:success)
adr_0008_real_history_probe_child = !adr_0008_probe_environment_token.nil? || !adr_0008_probe_config_token.nil?
if adr_0008_real_history_probe_child &&
   (!adr_0008_probe_environment_token&.match?(ADR_0008_REAL_HISTORY_PROBE_TOKEN_PATTERN) ||
    adr_0008_probe_config_token != adr_0008_probe_environment_token)
  failures << "ADR-0008 real-history probe child token/config binding is invalid"
end
adr_0008_real_history_probe_ran = !adr_0008_real_history_probe_child
if adr_0008_real_history_probe_ran
  probe_decision_revision = adr_0008_acceptance_metadata&.fetch(:immutable_revision)
  unless probe_decision_revision
    probe_head = adr_0008_git_capture("rev-parse", "--verify", "HEAD^{commit}")
    probe_decision_revision = probe_head.fetch(:stdout).strip if probe_head.fetch(:success)
  end
  failures.concat(
    adr_0008_real_history_probe_failures(
      decision_revision: probe_decision_revision,
      metadata_template: adr_0008_future_acceptance_metadata
    )
  )
end

# Mutate executable security invariants independently from the record seam.
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
  expected_failure_fragment: "classification bypass inventory source"
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
  expected_failure_fragment: "classification bypass inventory source"
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
    expected_failure_fragment: "classification bypass inventory source"
  }
end

canonical_bypass_row = classification_bypass_source.lines.grep(/\A\| CBI-030 \|/).first
canonical_bypass_lines = classification_bypass_source.lines
canonical_bypass_header_index = canonical_bypass_lines.index(ADR_0008_CBI_TABLE_HEADER)
if canonical_bypass_header_index
  canonical_bypass_end_index = canonical_bypass_lines.each_index.find do |index|
    index > canonical_bypass_header_index + 1 && canonical_bypass_lines[index].strip.empty?
  end || canonical_bypass_lines.length
  canonical_bypass_table = canonical_bypass_lines[
    canonical_bypass_header_index...canonical_bypass_end_index
  ].join

  {
    "HTML-comment-hidden complete inventory table" =>
      "<!--\n#{canonical_bypass_table}-->\n",
    "fenced-code-hidden complete inventory table" =>
      "```text\n#{canonical_bypass_table}```\n",
    "raw-HTML-hidden complete inventory table" =>
      "<div>\n#{canonical_bypass_table}</div>\n\n",
    "type-seven-inline-HTML-hidden complete inventory table" =>
      "<span>\n#{canonical_bypass_table}</span>\n\n",
    "type-seven-custom-HTML-hidden complete inventory table" =>
      "<stead-contract>\n#{canonical_bypass_table}</stead-contract>\n\n",
    "second complete inventory table after a blank line" =>
      "#{canonical_bypass_table}\n#{canonical_bypass_table}",
    "nested formatted duplicate CBI-030 table" =>
      "#{canonical_bypass_table}\n#{canonical_bypass_table.lines.map { |line| "> #{line.sub("CBI-030", "CBI-**030**")}" }.join}",
    "security-control header meaning changed" =>
      canonical_bypass_table.sub(
        ADR_0008_CBI_TABLE_HEADER,
        ADR_0008_CBI_TABLE_HEADER.sub(
          "Required preventive/detective controls",
          "Optional preventive/detective guidance"
        )
      )
  }.each do |name, replacement_table|
    mutated_rendered_bypass = classification_bypass_source.sub(
      canonical_bypass_table,
      replacement_table
    )
    adr_0008_security_mutations << {
      group: :topology,
      name: name,
      adr: adr_0008_source,
      asyncapi: deep_copy_asyncapi.call,
      bypass: mutated_rendered_bypass,
      expected_failure_fragment: "classification bypass inventory source"
    }
  end

  multiline_pre_bypass = classification_bypass_source.sub(
    canonical_bypass_table,
    "<pre\n>\n\n#{canonical_bypass_table}\n</pre>\n"
  )
  adr_0008_security_mutations << {
    group: :topology,
    name: "multiline type-one pre block hides canonical table",
    adr: adr_0008_source,
    asyncapi: deep_copy_asyncapi.call,
    bypass: multiline_pre_bypass,
    expected_failure_fragment: "classification bypass inventory source"
  }
end

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
      expected_failure_fragment: "classification bypass inventory source"
    }
  end
end

if canonical_bypass_table
  post_boundary_duplicate = classification_bypass_source.sub(
    "## Common test fixture and oracle\n",
    "## Common test fixture and oracle\n\n#{canonical_bypass_table}"
  )
  adr_0008_security_mutations << {
    group: :topology,
    name: "post-boundary duplicate CBI-030 table",
    adr: adr_0008_source,
    asyncapi: deep_copy_asyncapi.call,
    bypass: post_boundary_duplicate,
    expected_failure_fragment: "classification bypass inventory source"
  }

  {
    "inline HTML comment splits rendered CBI-030" => "CBI<!-- hidden -->-030",
    "multiline HTML comment splits rendered CBI-030" => "CBI<!--\nhidden\n-->-030",
    "inline link text splits rendered CBI-030" => "[CBI](https://example.invalid/)-030",
    "reference link text splits rendered CBI-030" => "[CBI][split]-030\n\n[split]: https://example.invalid/",
    "entity-escaped angles preserve rendered CBI-030" => "&lt;CBI-030&gt;",
    "numeric entity-escaped angles preserve rendered CBI-030" => "&#60;CBI-030&#62;",
    "raw HTML block exposes rendered CBI-030 text" => "<div>\nCBI-030\n</div>",
    "inline HTML tag splits rendered CBI-030" => "CBI<span data-safe=\"true\"></span>-030",
    "fenced code exposes rendered CBI-030 text" => "```text\nCBI-030\n```",
    "indented paragraph entity exposes rendered CBI-030" =>
      "paragraph continuation\n    CBI-&#48;30",
    "invalid inline link destination exposes rendered CBI-030" =>
      "[safe](not a CBI-030 destination)",
    "Unicode-folded reference link exposes rendered CBI-030" =>
      "[CBI][\u00C4]-030\n\n[\u00E4]: https://example.invalid/",
    "multiline reference destination is a source change" =>
      "[safe][dest]\n\n[dest]:\n  https://example.invalid/CBI-030"
  }.each do |name, rendered_duplicate|
    mutated_rendered_identity = classification_bypass_source.sub(
      "## Common test fixture and oracle\n",
      "#{rendered_duplicate}\n\n## Common test fixture and oracle\n"
    )
    adr_0008_security_mutations << {
      group: :topology,
      name: name,
      adr: adr_0008_source,
      asyncapi: deep_copy_asyncapi.call,
      bypass: mutated_rendered_identity,
      expected_failure_fragment: "classification bypass inventory source"
    }
  end
end

same_length_bypass_change = classification_bypass_source.sub(
  "Positive controls prove an authorized principal still succeeds.",
  "positive controls prove an authorized principal still succeeds."
)
adr_0008_security_mutations << {
  group: :topology,
  name: "same-length non-CBI source byte change",
  adr: adr_0008_source,
  asyncapi: deep_copy_asyncapi.call,
  bypass: same_length_bypass_change,
  expected_failure_fragment: "classification bypass inventory source digest mismatch"
}

actual_cbi_source_mutation_names = adr_0008_security_mutations.filter_map do |mutation|
  mutation.fetch(:name) if ADR_0008_CBI_SOURCE_MUTATION_NAMES.include?(mutation.fetch(:name))
end
unless actual_cbi_source_mutation_names == ADR_0008_CBI_SOURCE_MUTATION_NAMES
  failures << "ADR-0008 pinned CBI source mutation inventory changed: expected #{ADR_0008_CBI_SOURCE_MUTATION_NAMES.inspect}, found #{actual_cbi_source_mutation_names.inspect}"
end

baseline_cbi_rows, baseline_cbi_failures = adr_0008_bypass_inventory_rows(classification_bypass_source)
unless baseline_cbi_failures.empty? && baseline_cbi_rows.length == 47
  failures << "ADR-0008 pinned CBI source baseline failed: #{baseline_cbi_failures.join('; ')}; rows=#{baseline_cbi_rows.length}"
end

adr_0008_security_mutation_survivors = adr_0008_security_mutations.filter_map do |mutation|
  mutation_failures = adr_0008_security_contract_failures(
    adr_source: mutation.fetch(:adr),
    asyncapi: mutation.fetch(:asyncapi),
    bypass_source: mutation.fetch(:bypass),
    acceptance_metadata: adr_0008_acceptance_metadata
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

adr_0009_traceability_failures = adr_requirement_traceability_failures(
  requirements: requirements,
  adr_number: "0009",
  claimed_requirement_ids: requirements_by_number.fetch("0009", []),
  declared_test_ids: tests_by_number.fetch("0009", [])
)
failures.concat(adr_0009_traceability_failures)

adr_0009_expected_edges = expected_adr_requirement_test_edges(EXPECTED_REQUIREMENT_TEST_LINKS.fetch("0009")).freeze
unless adr_0009_expected_edges.length == 53
  failures << "ADR-0009 closed requirement mapping must contain exactly 53 edges, found #{adr_0009_expected_edges.length}"
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
unless adr_0009_adr_mutation_count == ADR_0009_EXPECTED_ADR_MUTATIONS.length
  failures << "ADR-0009 bounded ADR mutation inventory must contain exactly #{ADR_0009_EXPECTED_ADR_MUTATIONS.length} cases"
end
unless adr_0009_adr_mutation_survivors.empty?
  failures << "ADR-0009 bounded ADR mutation survivors: #{adr_0009_adr_mutation_survivors.join(', ')}"
end
unless adr_0009_spec_mutation_count == ADR_0009_SPEC_EXPECTATIONS.length +
       ADR_0009_SPEC_SECTION_DIGESTS.length + ADR_0009_EXPECTED_SPEC_CUSTOM_MUTATIONS
  failures << "ADR-0009 structured-spec mutation inventory count changed"
end
unless adr_0009_spec_mutation_survivors.empty?
  failures << "ADR-0009 structured-spec mutation survivors: #{adr_0009_spec_mutation_survivors.join(', ')}"
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
      if mutation_name == "YAML duplicate acceptance key"
        begin
          parse_yaml(mutated_catalog_source, filename: "#{issue_catalog_relative} (#{mutation_name})")
          failures << "STEAD-P1-006 #{mutation_name} mutant survived global duplicate-key rejection"
        rescue DuplicateYamlMappingKeyError
          # Expected: reject the ambiguous mapping before safe loading.
        rescue Psych::Exception => error
          failures << "STEAD-P1-006 #{mutation_name} fixture failed for the wrong reason: #{error.message}"
        end
      else
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

adr_0009_gate = adr_gates["ADR-CAND-008"]
adr_0009_expected_dependents = %w[
  STEAD-P1-002
  STEAD-P1-003
  STEAD-P1-006
  STEAD-P1-007
  STEAD-P1-011
  STEAD-P1-012
  STEAD-P2-001
].to_set
adr_0009_gate_dependency_failures = lambda do |gate|
  actual = Array(gate&.fetch("dependent_issues", nil)).to_set
  if actual == adr_0009_expected_dependents
    []
  else
    ["implementation issue catalog: ADR-CAND-008 exact dependent issues must be #{adr_0009_expected_dependents.to_a.sort.join(', ')}, found #{actual.to_a.sort.join(', ')}"]
  end
end
failures.concat(adr_0009_gate_dependency_failures.call(adr_0009_gate))

adr_0009_cross_contract_mutation_count += 1
mutated_adr_0009_gate = Marshal.load(Marshal.dump(adr_0009_gate))
removed_p1_007_gate = mutated_adr_0009_gate&.fetch("dependent_issues", [])&.delete("STEAD-P1-007")
if removed_p1_007_gate.nil? || adr_0009_gate_dependency_failures.call(mutated_adr_0009_gate).empty?
  adr_0009_cross_contract_mutation_survivors << "ADR-CAND-008 P1-007 dependent deletion"
end

unless adr_0009_cross_contract_mutation_count == ADR_0009_EXPECTED_CROSS_CONTRACT_MUTATIONS
  failures << "ADR-0009 cross-contract mutation inventory must contain exactly #{ADR_0009_EXPECTED_CROSS_CONTRACT_MUTATIONS} cases"
end
unless adr_0009_cross_contract_mutation_survivors.empty?
  failures << "ADR-0009 cross-contract mutation survivors: #{adr_0009_cross_contract_mutation_survivors.join(', ')}"
end

provider_issue = issues["STEAD-P1-003"]
provider_requirements = Array(provider_issue&.fetch("requirement_ids", nil)).to_set
security_requirements = Array(issues["STEAD-P1-006"]&.fetch("requirement_ids", nil)).to_set
missing_provider_requirements = requirements_by_number.fetch("0009", []).to_set -
                                (provider_requirements | security_requirements)
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

unless operations_acceptance.include?("Own ADR-0009's versioned reconciliation configuration") &&
       operations_acceptance.include?("without selecting reconciliation outcomes or declaring ambiguous effects terminal")
  failures << "STEAD-P1-011 acceptance must preserve WS-12 configuration/operations ownership without moving reconciliation authority"
end

adr_0009_owned_path_requirements = {
  "STEAD-P1-002" => %w[apps/core modules/project modules/work tests/integration/core packages/test-fixtures/core],
  "STEAD-P1-003" => %w[modules/scm providers/gitea tests/contract/gitea],
  "STEAD-P1-007" => %w[apps/worker modules/audit packages/event-schemas specs/asyncapi tests/contract/events],
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
  },
  "0009" => {
    "STEAD-P1-002" => %w[
      T-ADR-0009-DIRECT-CHANGE-ACCEPT
      T-ADR-0009-CONFLICT-QUARANTINE
      T-ADR-0009-AMBIGUOUS-MUTATION
    ],
    "STEAD-P1-003" => tests_by_number.fetch("0009", []),
    "STEAD-P1-006" => %w[
      T-ADR-0009-AMBIGUOUS-MUTATION
      T-ADR-0009-FULL-RECONCILIATION
    ],
    "STEAD-P1-007" => %w[
      T-ADR-0009-FULL-RECONCILIATION
      T-ADR-0009-AUDIT-MINIMIZATION
      T-ADR-0009-UPGRADE-ROLLBACK
    ],
    "STEAD-P1-011" => %w[
      T-ADR-0009-WEBHOOK-IDEMPOTENCY
      T-ADR-0009-PERMISSION-DRIFT
      T-ADR-0009-PROVIDER-OUTAGE
      T-ADR-0009-AMBIGUOUS-MUTATION
      T-ADR-0009-FULL-RECONCILIATION
      T-ADR-0009-AUDIT-MINIMIZATION
      T-ADR-0009-UPGRADE-ROLLBACK
    ],
    "STEAD-P1-012" => tests_by_number.fetch("0009", []),
    "STEAD-P2-001" => %w[
      T-ADR-0009-PRECEDENCE
      T-ADR-0009-PERMISSION-DRIFT
      T-ADR-0009-PROVIDER-OUTAGE
      T-ADR-0009-FULL-RECONCILIATION
      T-ADR-0009-AUDIT-MINIMIZATION
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
  adr_0009_killed_mutations = adr_0009_expected_edges.length - adr_0009_mutation_survivors.length
  adr_0008_killed_mutations = adr_0008_expected_edges.length - adr_0008_mutation_survivors.length
  puts "STEAD-P1-006 strict raw gate mutation guard: PASS (#{p1_006_gate_mutation_count}/#{EXPECTED_P1_006_GATE_MUTATION_COUNT} mutations killed)"
  puts "ADR-0007 exact-mapping mutation guard: PASS (#{adr_0007_killed_mutations}/#{adr_0007_expected_edges.length} required edge deletions killed)"
  puts "ADR-0008 exact-mapping mutation guard: PASS (#{adr_0008_killed_mutations}/#{adr_0008_expected_edges.length} required edge deletions killed)"
  puts "ADR-0008 record-state mutation guard: PASS (#{adr_0008_record_mutations.length}/#{ADR_0008_EXPECTED_RECORD_MUTATION_NAMES.length} mutations killed; proposed and future-accepted controls pass)"
  puts "ADR-0008 approval-record grammar mutation guard: PASS (#{adr_0008_approval_record_mutations.length}/#{ADR_0008_EXPECTED_APPROVAL_RECORD_MUTATION_NAMES.length} mutations killed; canonical metadata-derived document enforced)"
  puts "ADR-0008 catalog-source mutation guard: PASS (#{adr_0008_catalog_source_mutations.length}/#{ADR_0008_EXPECTED_CATALOG_SOURCE_MUTATION_NAMES.length} mutations killed; canonical raw acceptance source enforced)"
  puts "ADR-0008 acceptance-history mutation guard: PASS (#{adr_0008_history_mutations.length}/#{ADR_0008_EXPECTED_HISTORY_MUTATION_NAMES.length} mutations killed; exact-parent descendant/merge fixture passes)"
  puts "ADR-0008 real acceptance-history integration guard: PASS (immediate child, later descendant, normal merge)" if adr_0008_real_history_probe_ran
  puts "ADR-0008 pinned-CBI-source guard: PASS (baseline=#{ADR_0008_CLASSIFICATION_BYPASS_SOURCE_BYTES} bytes, #{ADR_0008_CBI_SOURCE_MUTATION_NAMES.length}/#{ADR_0008_CBI_SOURCE_MUTATION_NAMES.length} adversarial mutations killed)"
  puts "ADR-0008 security-contract mutation guard: PASS (#{adr_0008_security_mutations.length}/#{adr_0008_security_mutations.length} mutations killed across #{adr_0008_security_mutation_groups.length} gap groups)"
  puts "ADR-0009 exact-mapping mutation guard: PASS (#{adr_0009_killed_mutations}/#{adr_0009_expected_edges.length} required edge deletions killed)"
  puts "ADR-0009 bounded ADR mutation guard: PASS (#{adr_0009_adr_mutation_count}/#{ADR_0009_EXPECTED_ADR_MUTATIONS.length} mutations killed)"
  puts "ADR-0009 structured reconciliation mutation guard: PASS (#{adr_0009_spec_mutation_count}/#{adr_0009_spec_mutation_count} mutations killed)"
  puts "ADR-0009 cross-contract mutation guard: PASS (#{adr_0009_cross_contract_mutation_count}/#{ADR_0009_EXPECTED_CROSS_CONTRACT_MUTATIONS} mutations killed)"
  puts "ADR-0009 acceptance-state/history mutation guard: PASS (#{adr_0009_acceptance_mutation_names.length}/#{ADR_0009_EXPECTED_ACCEPTANCE_MUTATION_NAMES.length} mutations killed; later normal merge allowed)"
  puts "ADR traceability validation: PASS (records=#{paths.length}, requirements=#{known_requirement_ids.length}, tests=#{all_test_owners.length})"
else
  warn "ADR traceability validation: FAIL (#{failures.length} issue#{failures.length == 1 ? '' : 's'})"
  failures.each { |failure| warn "- #{failure}" }
  exit 1
end
