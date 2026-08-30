package ci_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func assertPrepareJSONContractError(t testing.TB, input policyrelease.BuildInput, want string) {
	t.Helper()
	_, err := policyrelease.PrepareUnsigned(input)
	if policyrelease.ErrorCode(err) != want {
		t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), want)
	}
}

func mutateAndRebindTrustSet(t testing.TB, input *policyrelease.BuildInput, mutate func(map[string]any)) {
	t.Helper()
	var trustIndex, envelopeIndex int
	for index := range input.PayloadFiles {
		switch input.PayloadFiles[index].Path {
		case input.Manifest.Trust.TrustSetPath:
			trustIndex = index
		case input.Manifest.Trust.TrustSetEnvelopePath:
			envelopeIndex = index
		}
	}
	var document map[string]any
	if err := json.Unmarshal(input.PayloadFiles[trustIndex].Content, &document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	trustPayload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	trustEnvelope, _ := externallySign(t, policyrelease.TrustSetPayloadType, trustPayload, 1, false)
	input.PayloadFiles[trustIndex].Content = trustPayload
	input.PayloadFiles[envelopeIndex].Content = trustEnvelope
	input.Manifest.Trust.TrustSetID = policyrelease.SHA256Digest(trustPayload)
	input.Manifest.Trust.TrustSetEnvelopeDigest = policyrelease.SHA256Digest(trustEnvelope)
}

func TestSecuritySensitiveZeroValuedEvidenceMembersAreRequiredAndTyped(t *testing.T) {
	testCases := []struct {
		name      string
		path      string
		target    func(map[string]any) map[string]any
		member    string
		wrongType any
	}{
		{"provenance network access", "evidence/provenance.json", func(document map[string]any) map[string]any {
			return document["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["internalParameters"].(map[string]any)
		}, "networkAccess", 0},
		{"license unknown count", "evidence/license-result.json", func(document map[string]any) map[string]any { return document }, "unknown_or_disallowed", false},
		{"vulnerability unknown count", "evidence/vulnerability-result.json", func(document map[string]any) map[string]any { return document }, "unknown_critical_or_high", false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			for _, mutation := range []struct {
				name   string
				value  any
				remove bool
				code   string
			}{
				{"missing", nil, true, "schema_required_field_missing"},
				{"null", nil, false, "signed_payload_contract_error"},
				{"wrong primitive type", testCase.wrongType, false, "signed_payload_contract_error"},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					input := fixtureBuildInput(t, "commercial", 1, false)
					mutateEvidenceReport(t, &input, testCase.path, func(document map[string]any) {
						target := testCase.target(document)
						if mutation.remove {
							delete(target, testCase.member)
							return
						}
						target[testCase.member] = mutation.value
					})
					assertPrepareJSONContractError(t, input, mutation.code)
				})
			}
		})
	}
}

func TestEveryFalseDeploymentAssuranceMemberIsRequiredAndNonNull(t *testing.T) {
	falseMembers := []string{
		"distinct_signing_custodians",
		"distinct_trust_recovery_approvers",
		"human_lowering_approvers_required",
		"validated_cryptographic_module_required",
	}
	for _, member := range falseMembers {
		t.Run(member, func(t *testing.T) {
			for _, mutation := range []struct {
				name   string
				remove bool
				code   string
			}{
				{"missing", true, "schema_required_field_missing"},
				{"null", false, "signed_payload_contract_error"},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					input := fixtureBuildInput(t, "commercial", 1, false)
					mutateBoundJSON(t, &input, "payload/deployment-policy.json", func(document map[string]any) {
						assurance := document["assurance"].(map[string]any)
						if mutation.remove {
							delete(assurance, member)
							return
						}
						assurance[member] = nil
					})
					assertPrepareJSONContractError(t, input, mutation.code)
				})
			}
		})
	}
}

func TestEveryFalsePresentedAssuranceMemberIsRequiredAndNonNull(t *testing.T) {
	falseMembers := []string{
		"distinct_signing_custodians",
		"distinct_trust_recovery_approvers",
		"human_lowering_approvers_required",
		"validated_cryptographic_module_required",
	}
	for _, member := range falseMembers {
		t.Run(member, func(t *testing.T) {
			for _, mutation := range []struct {
				name   string
				remove bool
				code   string
			}{
				{"missing", true, "schema_required_field_missing"},
				{"null", false, "signed_payload_contract_error"},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					input := fixtureBuildInput(t, "commercial", 1, false)
					mutateAssuranceResult(t, &input, func(document map[string]any) {
						if mutation.remove {
							delete(document, member)
							return
						}
						document[member] = nil
					})
					assertPrepareJSONContractError(t, input, mutation.code)
				})
			}
		})
	}
}

func TestDSSEKnownMembersAreRequiredAndExactlyTyped(t *testing.T) {
	payload := []byte("exact-json-contract")
	signature, keyID := fixtureSign(policyrelease.ActivationManifestPayloadType, payload, 0)
	valid := map[string]any{
		"payloadType": policyrelease.ActivationManifestPayloadType,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures": []any{map[string]any{
			"keyid": keyID,
			"sig":   base64.StdEncoding.EncodeToString(signature),
		}},
		"genuineExtension": map[string]any{"version": "extension-v1"},
	}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyrelease.ParseDSSEEnvelope(encoded); err != nil {
		t.Fatalf("genuine extension rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}

	testCases := []struct {
		name   string
		mutate func(map[string]any)
		code   string
	}{
		{"missing payload type", func(document map[string]any) { delete(document, "payloadType") }, "schema_required_field_missing"},
		{"null payload", func(document map[string]any) { document["payload"] = nil }, "signed_payload_contract_error"},
		{"object signatures", func(document map[string]any) { document["signatures"] = map[string]any{} }, "signed_payload_contract_error"},
		{"non-object signature", func(document map[string]any) { document["signatures"] = []any{false} }, "signed_payload_contract_error"},
		{"missing key id", func(document map[string]any) { delete(document["signatures"].([]any)[0].(map[string]any), "keyid") }, "schema_required_field_missing"},
		{"boolean signature", func(document map[string]any) { document["signatures"].([]any)[0].(map[string]any)["sig"] = false }, "signed_payload_contract_error"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(document)
			candidate, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			_, err = policyrelease.ParseDSSEEnvelope(candidate)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func TestExactJSONRejectsInvalidContainerAndIntegerRepresentations(t *testing.T) {
	t.Run("map member encoded as array", func(t *testing.T) {
		input := fixtureBuildInput(t, "commercial", 1, false)
		mutateBoundJSON(t, &input, "payload/deployment-policy.json", func(document map[string]any) {
			document["label_profile_ceilings"] = []any{}
		})
		assertPrepareJSONContractError(t, input, "signed_payload_contract_error")
	})

	t.Run("signed int overflow", func(t *testing.T) {
		input := fixtureBuildInput(t, "commercial", 1, false)
		mutateEvidenceReport(t, &input, "evidence/license-result.json", func(document map[string]any) {
			document["unknown_or_disallowed"] = json.Number("9223372036854775808")
		})
		assertPrepareJSONContractError(t, input, "signed_payload_contract_error")
	})

	t.Run("negative unsigned integer", func(t *testing.T) {
		input := fixtureBuildInput(t, "commercial", 1, false)
		mutateAndRebindTrustSet(t, &input, func(document map[string]any) {
			document["epoch"] = json.Number("-1")
		})
		assertPrepareJSONContractError(t, input, "signed_payload_contract_error")
	})

	t.Run("optional non-pointer member cannot be null", func(t *testing.T) {
		input := externalMappingBuildInput(t)
		mutateBoundJSON(t, &input, "payload/security-profile.json", func(document map[string]any) {
			sources := document["authoritative_sources"].([]any)
			sources[0].(map[string]any)["retrieved_at"] = nil
		})
		assertPrepareJSONContractError(t, input, "signed_payload_contract_error")
	})
}

func TestRequiredNullableTrustMemberAllowsNullButRejectsOmission(t *testing.T) {
	if _, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false)); err != nil {
		t.Fatalf("explicit null previous_trust_set_id rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}

	input := fixtureBuildInput(t, "commercial", 1, false)
	mutateAndRebindTrustSet(t, &input, func(document map[string]any) {
		delete(document, "previous_trust_set_id")
	})
	assertPrepareJSONContractError(t, input, "schema_required_field_missing")

	nonnull := fixtureBuildInput(t, "commercial", 1, false)
	mutateAndRebindTrustSet(t, &nonnull, func(document map[string]any) {
		document["previous_trust_set_id"] = policyrelease.SHA256Digest([]byte("previous-trust-set"))
	})
	rebindPolicyContentIndex(t, &nonnull)
	if _, err := policyrelease.PrepareUnsigned(nonnull); err != nil {
		t.Fatalf("non-null previous_trust_set_id rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}
}
