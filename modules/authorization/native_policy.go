package authorization

// NativePolicyFacts are trusted evaluator inputs, not request DTOs or permits.
// The Coordinator constructs them from owned state, authenticated identity,
// fresh OpenFGA output, and the signed classification evaluator. Evaluating
// these facts alone cannot construct a sealed Decision or release data.
type NativePolicyFacts struct {
	PrincipalType                                           string
	Operation                                               string // metadata, export, lowering, ci, infrastructure
	RelationshipAllowed, ProviderPathAllowed, FenceCurrent  bool
	ExplicitDeny, HierarchyOnly, ExistenceSensitive         bool
	TrustedAttributesValid, CapabilityActive, ContextValid  bool
	ClassificationReason                                    string // closed denial vocabulary from classification
	DataFlowContextValid, ExternalChannelAllowed            bool
	Lowering                                                LoweringFacts
	CIContextValid, CIPolicyAllowed                         bool
	InfrastructureContextValid, InfrastructurePolicyAllowed bool
	Agent                                                   *AgentPolicyFacts
}

type LoweringFacts struct {
	AuthorityValid, ReasonPresent, SourceValid bool
	ApprovalCount, RequiredApprovalCount       int
	DistinctRequired, DistinctSatisfied        bool
	HumanRequired, HumanSatisfied              bool
	CustodyRequired, CustodySatisfied          bool
}

type AgentPolicyFacts struct {
	DelegationValid, AuthorityValid, TaskScopeAllowed      bool
	RuntimeAllowed, ClassificationAllowed, RuntimeAttested bool
}

type NativePolicyResult struct {
	Allowed        bool
	Suppress       bool
	RuleID, Reason string
	Obligations    []string
}

// NativePolicyDecision implements the signed decision table's complete common
// and agent intersection. A local-development authenticator still does not
// admit Agent sessions; testing the common evaluator is not that product claim.
func NativePolicyDecision(input NativePolicyFacts) NativePolicyResult {
	deny := func(id, reason string) NativePolicyResult {
		if input.ExistenceSensitive {
			return NativePolicyResult{Suppress: true, RuleID: "POLICY-LEAK-001", Reason: "existence_protected"}
		}
		return NativePolicyResult{RuleID: id, Reason: reason}
	}
	if input.PrincipalType != "user" && input.PrincipalType != "agent" && input.PrincipalType != "service_account" {
		return deny("POLICY-010", "context_denied")
	}
	if input.Operation != "metadata" && input.Operation != "export" && input.Operation != "lowering" && input.Operation != "ci" && input.Operation != "infrastructure" {
		return deny("POLICY-010", "context_denied")
	}
	if !input.RelationshipAllowed && input.ExistenceSensitive {
		return NativePolicyResult{Suppress: true, RuleID: "POLICY-LEAK-001", Reason: "existence_protected"}
	}
	if !input.RelationshipAllowed && input.HierarchyOnly {
		return deny("POLICY-HIERARCHY-001", "no_explicit_authorization")
	}
	if !input.RelationshipAllowed {
		return deny("POLICY-001", "relationship_denied")
	}
	if !input.ProviderPathAllowed {
		return deny("POLICY-001A", "provider_enforcement_denied")
	}
	if !input.FenceCurrent {
		return deny("POLICY-001B", "stale_authorization_input")
	}
	if input.ExplicitDeny {
		return deny("POLICY-002", "explicit_policy_deny")
	}
	if input.ClassificationReason == "ceiling_exceeded" {
		return deny("POLICY-003", "ceiling_exceeded")
	}
	if input.ClassificationReason == "compartment_missing" {
		return deny("POLICY-004", "compartment_missing")
	}
	if !input.TrustedAttributesValid || input.ClassificationReason == "trusted_attribute_invalid" {
		return deny("POLICY-005", "trusted_attribute_invalid")
	}
	if !input.CapabilityActive {
		return deny("POLICY-006", "capability_inactive")
	}
	if input.ClassificationReason == "dissemination_denied" {
		return deny("POLICY-007", "dissemination_denied")
	}
	if input.ClassificationReason == "profile_handling_denied" {
		return deny("POLICY-008", "profile_handling_denied")
	}
	if input.ClassificationReason == "affiliation_denied" {
		return deny("POLICY-009", "affiliation_denied")
	}
	if !input.ContextValid || input.ClassificationReason != "" {
		return deny("POLICY-010", "context_denied")
	}
	if input.Operation == "export" {
		if !input.DataFlowContextValid {
			return deny("POLICY-011A", "data_flow_context_invalid")
		}
		if !input.ExternalChannelAllowed {
			return deny("POLICY-011", "export_or_share_denied")
		}
	}
	if input.Operation == "lowering" {
		lowering := input.Lowering
		if !lowering.AuthorityValid || !lowering.ReasonPresent || !lowering.SourceValid {
			return deny("POLICY-012", "lowering_denied")
		}
		if lowering.RequiredApprovalCount < 1 || lowering.ApprovalCount < lowering.RequiredApprovalCount {
			return deny("POLICY-012A", "lowering_approval_threshold_unsatisfied")
		}
		if (lowering.DistinctRequired && !lowering.DistinctSatisfied) || (lowering.HumanRequired && !lowering.HumanSatisfied) || (lowering.CustodyRequired && !lowering.CustodySatisfied) {
			return deny("POLICY-012B", "lowering_approval_separation_unsatisfied")
		}
	}
	if input.Operation == "ci" {
		if !input.CIContextValid {
			return deny("POLICY-013A", "ci_context_invalid")
		}
		if !input.CIPolicyAllowed {
			return deny("POLICY-013", "ci_policy_denied")
		}
	}
	if input.Operation == "infrastructure" {
		if !input.InfrastructureContextValid {
			return deny("POLICY-014A", "infrastructure_context_invalid")
		}
		if !input.InfrastructurePolicyAllowed {
			return deny("POLICY-014", "infrastructure_policy_denied")
		}
	}
	if input.PrincipalType == "agent" {
		agent := input.Agent
		if agent == nil {
			return deny("POLICY-AGENT-001", "agent_context_missing")
		}
		if !agent.DelegationValid {
			return deny("POLICY-AGENT-002", "delegation_invalid")
		}
		if !agent.AuthorityValid {
			return deny("POLICY-AGENT-003", "agent_authority_invalid")
		}
		if !agent.TaskScopeAllowed {
			return deny("POLICY-AGENT-004", "task_scope_denied")
		}
		if !agent.RuntimeAllowed {
			return deny("POLICY-AGENT-005", "runtime_denied")
		}
		if !agent.ClassificationAllowed {
			return deny("POLICY-AGENT-006", "agent_classification_denied")
		}
		if !agent.RuntimeAttested {
			return deny("POLICY-AGENT-008", "runtime_attestation_invalid")
		}
		return NativePolicyResult{Allowed: true, RuleID: "POLICY-AGENT-007", Obligations: []string{"display_marking", "audit_access"}}
	}
	return NativePolicyResult{Allowed: true, RuleID: "POLICY-015", Obligations: []string{"display_marking", "audit_access"}}
}
