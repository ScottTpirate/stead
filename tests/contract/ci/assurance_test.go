package ci_test

import (
	"bytes"
	"encoding/json"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func mutateAssuranceResult(t testing.TB, input *policyrelease.BuildInput, mutate func(map[string]any)) {
	t.Helper()
	for index := range input.PayloadFiles {
		if input.PayloadFiles[index].Path != input.Manifest.DeploymentPolicy.PresentedAssuranceResultPath {
			continue
		}
		var document map[string]any
		if err := json.Unmarshal(input.PayloadFiles[index].Content, &document); err != nil {
			t.Fatal(err)
		}
		mutate(document)
		content, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		input.PayloadFiles[index].Content = content
		input.Manifest.DeploymentPolicy.PresentedAssuranceResultDigest = policyrelease.SHA256Digest(content)
		return
	}
	t.Fatal("evaluated assurance result fixture missing")
}

// T-ADR-0006-ASSURANCE-POLICY and T-ADR-0006-CUSTODIAN-SEPARATION.
func TestDeploymentPolicySelectsThresholdAndCustodianSeparation(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		profile   string
		threshold int
		distinct  bool
	}{
		{"starter-threshold-one", "commercial", 1, false},
		{"starter-threshold-two", "commercial", 2, true},
		{"synthetic-non-government-threshold-three", "synthetic_regulated", 3, true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			activation, _, handoff := completeFixtureRelease(t, testCase.profile, testCase.threshold, testCase.distinct)
			if activation.PresentedActivationSignatures.RequestedSignatureThreshold != testCase.threshold || activation.PresentedActivationSignatures.PresentedDistinctKeyIDHints != testCase.threshold || activation.PresentedActivationSignatures.Treatment != policyrelease.PresentedMaterialTreatment {
				t.Fatalf("presented activation signatures = %#v", activation.PresentedActivationSignatures)
			}
			if handoff.PresentedReleaseSignatures.RequestedSignatureThreshold != testCase.threshold || handoff.PresentedReleaseSignatures.PresentedDistinctKeyIDHints != testCase.threshold || handoff.Authority != policyrelease.NonAuthorizingHandoffAuthority {
				t.Fatalf("presented release signatures = %#v", handoff.PresentedReleaseSignatures)
			}
		})
	}
}

func TestProfileIDDoesNotSelectAssuranceOrDisclosureMode(t *testing.T) {
	commercial, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 3, true))
	if err != nil {
		t.Fatal(err)
	}
	synthetic, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "synthetic_regulated", 3, true))
	if err != nil {
		t.Fatal(err)
	}
	if commercial.SigningRequest.RequiredSignatureThreshold != synthetic.SigningRequest.RequiredSignatureThreshold || commercial.SigningRequest.DistinctCustodiansRequired != synthetic.SigningRequest.DistinctCustodiansRequired {
		t.Fatal("profile ID changed signature assurance")
	}
	if commercial.Manifest.DeploymentPolicy.DisclosureRevocationMode != synthetic.Manifest.DeploymentPolicy.DisclosureRevocationMode {
		t.Fatal("profile ID changed disclosure mode")
	}
	if bytes.Equal(commercial.ManifestPayload, synthetic.ManifestPayload) {
		t.Fatal("distinct profile content did not change content identity")
	}
}

func TestDistinctCustodianThresholdFailsClosed(t *testing.T) {
	unsigned, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 2, true))
	if err != nil {
		t.Fatal(err)
	}
	envelope, signing := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 2, true)
	_, err = policyrelease.FinalizeActivationArchive(unsigned, envelope, signing)
	if policyrelease.ErrorCode(err) != "presented_custodian_claim_count_below_policy_request" {
		t.Fatalf("same-custodian error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}

func TestActivationAndReleaseThresholdsAreIndependent(t *testing.T) {
	unsigned, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 2, true))
	if err != nil {
		t.Fatal(err)
	}
	activationEnvelope, activationSigning := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 2, false)
	activation, err := policyrelease.FinalizeActivationArchive(unsigned, activationEnvelope, activationSigning)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := policyrelease.PrepareReleaseAttestation(activation, policyrelease.ReleaseAttestationInput{
		ReleaseWorkflowIdentity: "release-workflow-v1",
		ReviewReceipts:          []policyrelease.ReviewReceipt{{ReviewerID: "reviewer-a", Role: "independent-release", SubjectDigest: activation.ArchiveDigest, RecordDigest: policyrelease.SHA256Digest([]byte("review")), ClaimedDisposition: "accept"}},
		OfflineCheckReceipt:     policyrelease.OfflineCheckReceipt{ClaimedOutcome: "pass", SubjectArchiveDigest: activation.ArchiveDigest, ReportDigest: policyrelease.SHA256Digest([]byte("offline"))},
	})
	if err != nil {
		t.Fatal(err)
	}
	releaseEnvelope, releaseSigning := externallySign(t, policyrelease.ReleaseAttestationPayloadType, attestation.PayloadBytes, 1, false)
	_, err = policyrelease.FinalizeReleaseHandoff(activation, attestation, releaseEnvelope, releaseSigning)
	if policyrelease.ErrorCode(err) != "presented_signature_count_below_policy_request" {
		t.Fatalf("independent release threshold error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}

func TestUnknownMismatchedAndWeakerAssuranceReject(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*policyrelease.BuildInput)
		code   string
	}{
		{"missing-threshold", func(input *policyrelease.BuildInput) { input.Manifest.DeploymentPolicy.PolicySignatureThreshold = 0 }, "invalid_signature_threshold"},
		{"unknown-policy-version", func(input *policyrelease.BuildInput) { input.Manifest.DeploymentPolicy.Version = "2.0.0" }, "unsupported_version"},
		{"mismatched-policy-digest", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.Digest = policyrelease.SHA256Digest([]byte("other"))
		}, "bound_digest_mismatch"},
		{"unknown-mode", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.DisclosureRevocationMode = "profile_selected"
		}, "unsupported_disclosure_mode"},
		{"missing-assurance-result", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.PresentedAssuranceResultDigest = ""
		}, "invalid_digest"},
		{"missing-crypto-boundary", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.ApprovedCryptographicBoundary = ""
		}, "invalid_identifier"},
		{"typed-threshold-does-not-match-deployment-policy", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.PolicySignatureThreshold = 2
		}, "deployment_policy_assurance_binding_mismatch"},
		{"failed-evaluated-result", func(input *policyrelease.BuildInput) {
			mutateAssuranceResult(t, input, func(document map[string]any) { document["claimed_result"] = "fail" })
		}, "presented_assurance_mismatch"},
		{"self-certified-assurance-treatment", func(input *policyrelease.BuildInput) {
			mutateAssuranceResult(t, input, func(document map[string]any) { document["treatment"] = "self-certified" })
		}, "presented_assurance_mismatch"},
		{"unknown-evaluated-result-field", func(input *policyrelease.BuildInput) {
			mutateAssuranceResult(t, input, func(document map[string]any) { document["self_authorized_threshold"] = 1 })
		}, "signed_payload_contract_error"},
		{"stale-evaluated-result-digest", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.PresentedAssuranceResultDigest = policyrelease.SHA256Digest([]byte("stale"))
		}, "bound_digest_mismatch"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			testCase.mutate(&input)
			_, err := policyrelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func mutateBoundJSON(t testing.TB, input *policyrelease.BuildInput, path string, mutate func(map[string]any)) {
	t.Helper()
	for index := range input.PayloadFiles {
		if input.PayloadFiles[index].Path != path {
			continue
		}
		var document map[string]any
		if err := json.Unmarshal(input.PayloadFiles[index].Content, &document); err != nil {
			t.Fatal(err)
		}
		mutate(document)
		content, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		input.PayloadFiles[index].Content = content
		switch path {
		case "payload/security-profile.json":
			input.Manifest.Profiles[0].Digest = policyrelease.SHA256Digest(content)
		case "payload/deployment-policy.json":
			input.Manifest.DeploymentPolicy.Digest = policyrelease.SHA256Digest(content)
		}
		return
	}
	t.Fatalf("bound JSON fixture %s missing", path)
}

func TestExactSecurityProfileSchemaIdentityAndVersionReject(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*policyrelease.BuildInput)
		code   string
	}{
		{"unknown schema id", func(input *policyrelease.BuildInput) {
			input.Manifest.Profiles[0].SchemaID = "https://example.invalid/profile.schema.json"
		}, "unsupported_security_profile_schema"},
		{"document profile id mismatch", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/security-profile.json", func(document map[string]any) { document["profile_id"] = "other_profile" })
		}, "security_profile_identity_mismatch"},
		{"document profile version mismatch", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/security-profile.json", func(document map[string]any) { document["version"] = "2.0.0" })
		}, "security_profile_identity_mismatch"},
		{"unsupported exact profile version", func(input *policyrelease.BuildInput) {
			input.Manifest.Profiles[0].Version = "2.0.0"
			mutateBoundJSON(t, input, "payload/security-profile.json", func(document map[string]any) { document["version"] = "2.0.0" })
		}, "unsupported_version"},
		{"unknown profile schema field", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/security-profile.json", func(document map[string]any) { document["self_certified"] = true })
		}, "signed_payload_contract_error"},
		{"missing required nested profile field", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/security-profile.json", func(document map[string]any) {
				delete(document["presentation"].(map[string]any), "action_warnings")
			})
		}, "schema_required_field_missing"},
		{"invalid nested profile vocabulary", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/security-profile.json", func(document map[string]any) {
				document["allowed_categories"] = []any{map[string]any{"id": "bad id", "subcategories": []any{}}}
			})
		}, "security_profile_vocabulary_mismatch"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			testCase.mutate(&input)
			_, err := policyrelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func TestExactDeploymentPolicySchemaIdentityVersionAndCeilingsReject(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*policyrelease.BuildInput)
		code   string
	}{
		{"unknown schema id", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.SchemaID = "https://example.invalid/deployment.schema.json"
		}, "unsupported_deployment_policy_schema"},
		{"document domain id mismatch", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/deployment-policy.json", func(document map[string]any) { document["domain_id"] = "other-domain" })
		}, "deployment_policy_identity_mismatch"},
		{"document domain version mismatch", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/deployment-policy.json", func(document map[string]any) { document["version"] = "2.0.0" })
		}, "deployment_policy_identity_mismatch"},
		{"unsupported exact deployment version", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.Version = "2.0.0"
			mutateBoundJSON(t, input, "payload/deployment-policy.json", func(document map[string]any) { document["version"] = "2.0.0" })
		}, "unsupported_version"},
		{"profile ceiling version mismatch", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/deployment-policy.json", func(document map[string]any) {
				ceilings := document["label_profile_ceilings"].(map[string]any)
				ceilings["commercial"].(map[string]any)["profile_version"] = "2.0.0"
			})
		}, "deployment_policy_profile_binding_mismatch"},
		{"unknown deployment schema field", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/deployment-policy.json", func(document map[string]any) { document["self_certified"] = true })
		}, "signed_payload_contract_error"},
		{"missing required deployment field", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/deployment-policy.json", func(document map[string]any) { delete(document, "allowed_integrations") })
		}, "schema_required_field_missing"},
		{"duplicate deployment array item", func(input *policyrelease.BuildInput) {
			mutateBoundJSON(t, input, "payload/deployment-policy.json", func(document map[string]any) { document["allowed_integrations"] = []any{"duplicate", "duplicate"} })
		}, "schema_duplicate_value"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			testCase.mutate(&input)
			_, err := policyrelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func TestPresentedAssuranceResultMustBeExactCanonicalHandoff(t *testing.T) {
	input := fixtureBuildInput(t, "commercial", 2, true)
	for index := range input.PayloadFiles {
		if input.PayloadFiles[index].Path != input.Manifest.DeploymentPolicy.PresentedAssuranceResultPath {
			continue
		}
		input.PayloadFiles[index].Content = append(input.PayloadFiles[index].Content, '\n')
		input.Manifest.DeploymentPolicy.PresentedAssuranceResultDigest = policyrelease.SHA256Digest(input.PayloadFiles[index].Content)
		_, err := policyrelease.PrepareUnsigned(input)
		if policyrelease.ErrorCode(err) != "noncanonical_presented_assurance" {
			t.Fatalf("noncanonical result error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
		return
	}
	t.Fatal("evaluated assurance result fixture missing")
}

func TestProvisionalSigstoreProfileRejectsWithoutProfileBranch(t *testing.T) {
	for _, profile := range []string{"commercial", "synthetic_regulated"} {
		t.Run(profile, func(t *testing.T) {
			input := fixtureBuildInput(t, profile, 1, false)
			for index := range input.PayloadFiles {
				if input.PayloadFiles[index].Path == "payload/security-profile.json" {
					input.PayloadFiles[index].Content = bytes.ReplaceAll(input.PayloadFiles[index].Content, []byte(policyrelease.ActivationFormatV1), []byte("sigstore-bundle"))
					input.Manifest.Profiles[0].Digest = policyrelease.SHA256Digest(input.PayloadFiles[index].Content)
				}
			}
			_, err := policyrelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != "unsupported_profile_signing_format" {
				t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
			}
		})
	}
}
