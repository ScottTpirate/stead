package ci_test

import (
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func installValidProfileRuleFixture(t testing.TB, input *policyrelease.BuildInput) {
	t.Helper()
	mutateSecurityProfile(t, input, func(document map[string]any) {
		semantics := document["semantics"].(map[string]any)
		fixtureTerm := func(dimension, id string) map[string]any {
			return map[string]any{"dimension": dimension, "id": id}
		}
		semantics["implications"] = []any{map[string]any{
			"rule_id": "fixture_implication", "when_all": []any{fixtureTerm("sensitivity", "fixture")},
			"require_all": []any{fixtureTerm("handling_regime", "internal")},
		}}
		semantics["incompatibilities"] = []any{map[string]any{
			"rule_id": "fixture_incompatibility", "all_of": []any{fixtureTerm("category", "alpha"), fixtureTerm("category", "beta")},
		}}
		semantics["sensitivity_constraints"] = []any{map[string]any{
			"rule_id": "fixture_sensitivity", "when_any": []any{fixtureTerm("category", "alpha")},
			"allowed_sensitivity_levels": []any{"fixture"},
		}}
		semantics["dimension_requirements"] = []any{map[string]any{
			"rule_id": "fixture_dimension", "when_all": []any{fixtureTerm("sensitivity", "fixture")},
			"required_nonempty_dimensions": []any{"category"},
		}}
		semantics["context_requirements"] = []any{map[string]any{
			"rule_id": "fixture_context", "when_all": []any{fixtureTerm("sensitivity", "fixture")},
			"requirement_type": "verified_unexpired_presence", "trusted_attribute_names": []any{"fixture_attribute"},
			"authority_classes": []any{"fixture_authority"},
		}}
	})
}

// T-ADR-0002-PROFILE-NEUTRALITY and T-ADR-0006-POLICY-CONFORMANCE: execute
// every rule-family and term-validation branch instead of treating empty test
// profiles as policy-rule coverage.
func TestSecurityProfileRuleFamiliesAndTerms(t *testing.T) {
	valid := fixtureBuildInput(t, "commercial", 1, false)
	installValidProfileRuleFixture(t, &valid)
	if _, err := policyrelease.PrepareUnsigned(valid); err != nil {
		t.Fatalf("valid profile rule fixture rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}

	testCases := []struct {
		name   string
		mutate func(map[string]any)
		code   string
	}{
		{"invalid implication rule ID", func(semantics map[string]any) {
			semantics["implications"].([]any)[0].(map[string]any)["rule_id"] = "bad rule"
		}, "security_profile_rule_mismatch"},
		{"unknown term dimension", func(semantics map[string]any) {
			semantics["implications"].([]any)[0].(map[string]any)["when_all"].([]any)[0].(map[string]any)["dimension"] = "unknown"
		}, "security_profile_rule_mismatch"},
		{"invalid term ID", func(semantics map[string]any) {
			semantics["implications"].([]any)[0].(map[string]any)["when_all"].([]any)[0].(map[string]any)["id"] = "bad id"
		}, "security_profile_rule_mismatch"},
		{"duplicate term", func(semantics map[string]any) {
			rule := semantics["implications"].([]any)[0].(map[string]any)
			rule["when_all"] = append(rule["when_all"].([]any), rule["when_all"].([]any)[0])
		}, "security_profile_rule_mismatch"},
		{"empty implication requirement", func(semantics map[string]any) {
			semantics["implications"].([]any)[0].(map[string]any)["require_all"] = []any{}
		}, "security_profile_rule_mismatch"},
		{"nonmonotone implication", func(semantics map[string]any) {
			semantics["implications"].([]any)[0].(map[string]any)["require_all"].([]any)[0].(map[string]any)["dimension"] = "sensitivity"
		}, "security_profile_rule_mismatch"},
		{"short incompatibility", func(semantics map[string]any) {
			semantics["incompatibilities"].([]any)[0].(map[string]any)["all_of"] = []any{map[string]any{"dimension": "category", "id": "alpha"}}
		}, "security_profile_rule_mismatch"},
		{"empty allowed sensitivity", func(semantics map[string]any) {
			semantics["sensitivity_constraints"].([]any)[0].(map[string]any)["allowed_sensitivity_levels"] = []any{}
		}, "security_profile_rule_mismatch"},
		{"empty required dimension", func(semantics map[string]any) {
			semantics["dimension_requirements"].([]any)[0].(map[string]any)["required_nonempty_dimensions"] = []any{}
		}, "security_profile_rule_mismatch"},
		{"unknown required dimension", func(semantics map[string]any) {
			semantics["dimension_requirements"].([]any)[0].(map[string]any)["required_nonempty_dimensions"] = []any{"unknown"}
		}, "security_profile_rule_mismatch"},
		{"duplicate required dimension", func(semantics map[string]any) {
			semantics["dimension_requirements"].([]any)[0].(map[string]any)["required_nonempty_dimensions"] = []any{"category", "category"}
		}, "schema_duplicate_value"},
		{"unknown context requirement", func(semantics map[string]any) {
			semantics["context_requirements"].([]any)[0].(map[string]any)["requirement_type"] = "unknown"
		}, "security_profile_rule_mismatch"},
		{"empty trusted attributes", func(semantics map[string]any) {
			semantics["context_requirements"].([]any)[0].(map[string]any)["trusted_attribute_names"] = []any{}
		}, "security_profile_rule_mismatch"},
		{"empty authority classes", func(semantics map[string]any) {
			semantics["context_requirements"].([]any)[0].(map[string]any)["authority_classes"] = []any{}
		}, "security_profile_rule_mismatch"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			installValidProfileRuleFixture(t, &input)
			mutateSecurityProfile(t, &input, func(document map[string]any) {
				testCase.mutate(document["semantics"].(map[string]any))
			})
			_, err := policyrelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}
