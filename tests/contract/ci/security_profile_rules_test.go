package ci_test

import (
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func repeatedJSONValue(value any, count int) []any {
	result := make([]any, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func TestSecurityProfileMetadataCollectionsAreStreamingPreflighted(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(map[string]any, int)
	}{
		{"authoritative sources", func(document map[string]any, count int) {
			document["authoritative_sources"] = repeatedJSONValue(map[string]any{}, count)
		}},
		{"allowed categories", func(document map[string]any, count int) {
			document["allowed_categories"] = repeatedJSONValue(map[string]any{}, count)
		}},
		{"export controls", func(document map[string]any, count int) {
			document["export_controls"] = repeatedJSONValue(map[string]any{}, count)
		}},
		{"implication rules", func(document map[string]any, count int) {
			document["semantics"].(map[string]any)["implications"] = repeatedJSONValue(map[string]any{}, count)
		}},
		{"incompatibility rules", func(document map[string]any, count int) {
			document["semantics"].(map[string]any)["incompatibilities"] = repeatedJSONValue(map[string]any{}, count)
		}},
		{"sensitivity constraint rules", func(document map[string]any, count int) {
			document["semantics"].(map[string]any)["sensitivity_constraints"] = repeatedJSONValue(map[string]any{}, count)
		}},
		{"dimension requirement rules", func(document map[string]any, count int) {
			document["semantics"].(map[string]any)["dimension_requirements"] = repeatedJSONValue(map[string]any{}, count)
		}},
		{"context requirement rules", func(document map[string]any, count int) {
			document["semantics"].(map[string]any)["context_requirements"] = repeatedJSONValue(map[string]any{}, count)
		}},
		{"registry mappings", func(document map[string]any, count int) {
			document["semantics"].(map[string]any)["registry_mappings"] = repeatedJSONValue(map[string]any{}, count)
		}},
		{"sensitivity markings", func(document map[string]any, count int) {
			document["presentation"].(map[string]any)["sensitivity_markings"] = repeatedJSONValue(map[string]any{}, count)
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			exact := fixtureBuildInput(t, "commercial", 1, false)
			mutateSecurityProfile(t, &exact, func(document map[string]any) {
				testCase.mutate(document, policyrelease.MaxMetadataEntries)
			})
			if _, err := observedPolicyRelease.PrepareUnsigned(exact); policyrelease.ErrorCode(err) == "metadata_cardinality_limit" {
				t.Fatalf("exact metadata ceiling rejected by preflight: %v", err)
			}

			oneOver := fixtureBuildInput(t, "commercial", 1, false)
			mutateSecurityProfile(t, &oneOver, func(document map[string]any) {
				testCase.mutate(document, policyrelease.MaxMetadataEntries+1)
			})
			result, err := observedPolicyRelease.PrepareUnsigned(oneOver)
			if policyrelease.ErrorCode(err) != "metadata_cardinality_limit" || result.ManifestPayload != nil || result.SigningRequestBytes != nil {
				t.Fatalf("one-over metadata preflight = %v (%s), manifest=%d request=%d", err, policyrelease.ErrorCode(err), len(result.ManifestPayload), len(result.SigningRequestBytes))
			}
		})
	}
}

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
	rebindPolicyContentIndex(t, &valid)
	if _, err := observedPolicyRelease.PrepareUnsigned(valid); err != nil {
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
			_, err := observedPolicyRelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}
