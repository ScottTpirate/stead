package authorization

import (
	"encoding/json"
	"reflect"
	"testing"
)

func allowedNativeFacts() NativePolicyFacts {
	return NativePolicyFacts{PrincipalType: "user", Operation: "metadata", RelationshipAllowed: true, ProviderPathAllowed: true, FenceCurrent: true, TrustedAttributesValid: true, CapabilityActive: true, ContextValid: true, DataFlowContextValid: true, ExternalChannelAllowed: true, CIContextValid: true, CIPolicyAllowed: true, InfrastructureContextValid: true, InfrastructurePolicyAllowed: true, Lowering: LoweringFacts{AuthorityValid: true, ReasonPresent: true, SourceValid: true, ApprovalCount: 2, RequiredApprovalCount: 2, DistinctRequired: true, DistinctSatisfied: true, HumanRequired: true, HumanSatisfied: true, CustodyRequired: true, CustodySatisfied: true}, Agent: &AgentPolicyFacts{DelegationValid: true, AuthorityValid: true, TaskScopeAllowed: true, RuntimeAllowed: true, ClassificationAllowed: true, RuntimeAttested: true}}
}

// Each scenario supplies actual facts to the same native function consumed by
// Coordinator. No expected result is supplied to that function. The signed
// table supplies expected outcome/reason/obligations, including agent allow.
func TestNativePolicyRows(t *testing.T) {
	fixtures := map[string]func(*NativePolicyFacts){
		"POLICY-001":           func(f *NativePolicyFacts) { f.RelationshipAllowed = false },
		"POLICY-001A":          func(f *NativePolicyFacts) { f.ProviderPathAllowed = false },
		"POLICY-001B":          func(f *NativePolicyFacts) { f.FenceCurrent = false },
		"POLICY-002":           func(f *NativePolicyFacts) { f.ExplicitDeny = true },
		"POLICY-003":           func(f *NativePolicyFacts) { f.ClassificationReason = "ceiling_exceeded" },
		"POLICY-004":           func(f *NativePolicyFacts) { f.ClassificationReason = "compartment_missing" },
		"POLICY-005":           func(f *NativePolicyFacts) { f.TrustedAttributesValid = false },
		"POLICY-006":           func(f *NativePolicyFacts) { f.CapabilityActive = false },
		"POLICY-007":           func(f *NativePolicyFacts) { f.ClassificationReason = "dissemination_denied" },
		"POLICY-008":           func(f *NativePolicyFacts) { f.ClassificationReason = "profile_handling_denied" },
		"POLICY-009":           func(f *NativePolicyFacts) { f.ClassificationReason = "affiliation_denied" },
		"POLICY-010":           func(f *NativePolicyFacts) { f.ContextValid = false },
		"POLICY-011":           func(f *NativePolicyFacts) { f.Operation = "export"; f.ExternalChannelAllowed = false },
		"POLICY-011A":          func(f *NativePolicyFacts) { f.Operation = "export"; f.DataFlowContextValid = false },
		"POLICY-012":           func(f *NativePolicyFacts) { f.Operation = "lowering"; f.Lowering.AuthorityValid = false },
		"POLICY-012A":          func(f *NativePolicyFacts) { f.Operation = "lowering"; f.Lowering.ApprovalCount = 1 },
		"POLICY-012B":          func(f *NativePolicyFacts) { f.Operation = "lowering"; f.Lowering.DistinctSatisfied = false },
		"POLICY-013":           func(f *NativePolicyFacts) { f.Operation = "ci"; f.CIPolicyAllowed = false },
		"POLICY-013A":          func(f *NativePolicyFacts) { f.Operation = "ci"; f.CIContextValid = false },
		"POLICY-014":           func(f *NativePolicyFacts) { f.Operation = "infrastructure"; f.InfrastructurePolicyAllowed = false },
		"POLICY-014A":          func(f *NativePolicyFacts) { f.Operation = "infrastructure"; f.InfrastructureContextValid = false },
		"POLICY-015":           func(*NativePolicyFacts) {},
		"POLICY-AGENT-001":     func(f *NativePolicyFacts) { f.PrincipalType = "agent"; f.Agent = nil },
		"POLICY-AGENT-002":     func(f *NativePolicyFacts) { f.PrincipalType = "agent"; f.Agent.DelegationValid = false },
		"POLICY-AGENT-003":     func(f *NativePolicyFacts) { f.PrincipalType = "agent"; f.Agent.AuthorityValid = false },
		"POLICY-AGENT-004":     func(f *NativePolicyFacts) { f.PrincipalType = "agent"; f.Agent.TaskScopeAllowed = false },
		"POLICY-AGENT-005":     func(f *NativePolicyFacts) { f.PrincipalType = "agent"; f.Agent.RuntimeAllowed = false },
		"POLICY-AGENT-006":     func(f *NativePolicyFacts) { f.PrincipalType = "agent"; f.Agent.ClassificationAllowed = false },
		"POLICY-AGENT-007":     func(f *NativePolicyFacts) { f.PrincipalType = "agent" },
		"POLICY-AGENT-008":     func(f *NativePolicyFacts) { f.PrincipalType = "agent"; f.Agent.RuntimeAttested = false },
		"POLICY-HIERARCHY-001": func(f *NativePolicyFacts) { f.RelationshipAllowed = false; f.HierarchyOnly = true },
		"POLICY-LEAK-001":      func(f *NativePolicyFacts) { f.RelationshipAllowed = false; f.ExistenceSensitive = true },
	}
	data, err := contracts.ReadFile("contract/decision-table.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Cases []struct {
			ID, Expect, Reason string
			Obligations        []string
		}
	}
	if json.Unmarshal(data, &table) != nil || len(table.Cases) != len(fixtures) {
		t.Fatal("runtime table/fixture coverage mismatch")
	}
	seen := map[string]bool{}
	for _, row := range table.Cases {
		if seen[row.ID] {
			t.Fatal("duplicate runtime row")
		}
		seen[row.ID] = true
		scenario := fixtures[row.ID]
		if scenario == nil {
			t.Fatalf("missing runtime row %s", row.ID)
		}
		t.Run(row.ID, func(t *testing.T) {
			facts := allowedNativeFacts()
			scenario(&facts)
			result := NativePolicyDecision(facts)
			if result.Allowed != (row.Expect == "allow") || result.Suppress != (row.Expect == "deny_and_suppress") || result.Reason != row.Reason || result.RuleID != row.ID || !reflect.DeepEqual(result.Obligations, row.Obligations) {
				t.Fatalf("actual native result %+v does not match signed row %+v", result, row)
			}
			if repeated := NativePolicyDecision(facts); !reflect.DeepEqual(repeated, result) {
				t.Fatal("non-deterministic native policy")
			}
		})
	}
}

func TestNativePolicyUnknownAndPositiveBoundaries(t *testing.T) {
	for _, kind := range []string{"", "directory_group", "USER", "unknown"} {
		facts := allowedNativeFacts()
		facts.PrincipalType = kind
		if NativePolicyDecision(facts).Allowed {
			t.Fatal("unknown acting principal")
		}
	}
	for _, operation := range []string{"", "unknown", "read-lowered"} {
		facts := allowedNativeFacts()
		facts.Operation = operation
		if NativePolicyDecision(facts).Allowed {
			t.Fatal("unknown action class")
		}
	}
	for _, reason := range []string{"unknown", "trusted_attribute_invalid", "context_denied"} {
		facts := allowedNativeFacts()
		facts.ClassificationReason = reason
		if NativePolicyDecision(facts).Allowed {
			t.Fatal("unknown/denied classification")
		}
	}
	for _, operation := range []string{"metadata", "export", "lowering", "ci", "infrastructure"} {
		facts := allowedNativeFacts()
		facts.Operation = operation
		if !NativePolicyDecision(facts).Allowed {
			t.Fatalf("complete trusted %s facts denied", operation)
		}
		facts.ExistenceSensitive = true
		facts.ExplicitDeny = true
		if result := NativePolicyDecision(facts); result.Allowed || !result.Suppress {
			t.Fatal("non-relationship denial leaks existence")
		}
	}
	for _, count := range []int{1, 2, 3, 5} {
		facts := allowedNativeFacts()
		facts.Operation = "lowering"
		facts.Lowering.ApprovalCount = count
		facts.Lowering.RequiredApprovalCount = count
		if !NativePolicyDecision(facts).Allowed {
			t.Fatal("valid configured threshold denied")
		}
		facts.Lowering.ApprovalCount--
		if NativePolicyDecision(facts).Allowed {
			t.Fatal("lowering below threshold")
		}
	}
}
