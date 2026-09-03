package ci_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func TestContractErrorsExposeOnlyStableSafeCodes(t *testing.T) {
	input := fixtureBuildInput(t, "commercial", 1, false)
	input.Manifest.DeploymentPolicy.PolicySignatureThreshold = 0
	_, err := observedPolicyRelease.PrepareUnsigned(input)
	if err == nil || err.Error() != "invalid_signature_threshold" || policyrelease.ErrorCode(err) != "invalid_signature_threshold" {
		t.Fatalf("unsafe or unstable contract error: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	var contract *policyrelease.ContractError
	if !errors.As(err, &contract) || contract.Field != "" || contract.Err != nil {
		t.Fatalf("package error retained field or cause: %#v", contract)
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("validation error unexpectedly exposed an underlying payload error")
	}
	if policyrelease.ErrorCode(errors.New("ordinary error")) != "" {
		t.Fatal("ordinary error was assigned a contract code")
	}
}

func appendJSONMember(t testing.TB, data []byte, member string) []byte {
	t.Helper()
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[len(data)-1] != '}' {
		t.Fatal("fixture is not a JSON object")
	}
	result := append([]byte(nil), data[:len(data)-1]...)
	result = append(result, ',')
	result = append(result, member...)
	result = append(result, '}')
	return result
}

func assertParserErrorSanitized(t testing.TB, err error, secret string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected parser error")
	}
	var contract *policyrelease.ContractError
	if !errors.As(err, &contract) {
		t.Fatalf("not a contract error: %T", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(contract.Field, secret) || errors.Unwrap(err) != nil {
		t.Fatalf("parser error leaked attacker-controlled key text: error=%q field=%q", err.Error(), contract.Field)
	}
}

func TestDuplicateAndParserErrorsNeverExposeAttackerKeyText(t *testing.T) {
	const secret = "attacker-secret-json-key"
	_, err := policyrelease.ParseDSSEEnvelope([]byte(`{"` + secret + `":1,"` + secret + `":2}`))
	if policyrelease.ErrorCode(err) != "duplicate_json_key" {
		t.Fatalf("duplicate key error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
	assertParserErrorSanitized(t, err, secret)

	input := fixtureBuildInput(t, "commercial", 1, false)
	input.EvidenceFiles[2].Content = appendJSONMember(t, input.EvidenceFiles[2].Content, `"`+secret+`":"x"`)
	_, err = observedPolicyRelease.PrepareUnsigned(input)
	if policyrelease.ErrorCode(err) != "signed_payload_contract_error" {
		t.Fatalf("unknown key error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
	assertParserErrorSanitized(t, err, secret)
}

func TestEveryDSSESignedPayloadRejectsCaseFoldedAliases(t *testing.T) {
	t.Run("activation manifest", func(t *testing.T) {
		unsigned, err := observedPolicyRelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
		if err != nil {
			t.Fatal(err)
		}
		unsigned.ManifestPayload = appendJSONMember(t, unsigned.ManifestPayload, `"SCHEMA_VERSION":"1.0.0"`)
		unsigned.ActivationSetID = policyrelease.SHA256Digest(unsigned.ManifestPayload)
		envelope, signing := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
		_, err = observedPolicyRelease.FinalizeActivationArchive(unsigned, envelope, signing)
		if policyrelease.ErrorCode(err) != "json_member_name_mismatch" {
			t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("trust set", func(t *testing.T) {
		input := fixtureBuildInput(t, "commercial", 1, false)
		var trustIndex, envelopeIndex int
		for index := range input.PayloadFiles {
			switch input.PayloadFiles[index].Path {
			case input.Manifest.Trust.TrustSetPath:
				trustIndex = index
			case input.Manifest.Trust.TrustSetEnvelopePath:
				envelopeIndex = index
			}
		}
		trustPayload := appendJSONMember(t, input.PayloadFiles[trustIndex].Content, `"SCHEMA_VERSION":"1.0.0"`)
		trustEnvelope, _ := externallySign(t, policyrelease.TrustSetPayloadType, trustPayload, 1, false)
		input.PayloadFiles[trustIndex].Content = trustPayload
		input.PayloadFiles[envelopeIndex].Content = trustEnvelope
		input.Manifest.Trust.TrustSetID = policyrelease.SHA256Digest(trustPayload)
		input.Manifest.Trust.TrustSetEnvelopeDigest = policyrelease.SHA256Digest(trustEnvelope)
		_, err := observedPolicyRelease.PrepareUnsigned(input)
		if policyrelease.ErrorCode(err) != "json_member_name_mismatch" {
			t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("release attestation", func(t *testing.T) {
		activation, attestation, _ := completeFixtureRelease(t, "commercial", 1, false)
		attestation.PayloadBytes = appendJSONMember(t, attestation.PayloadBytes, `"SCHEMA_VERSION":"1.0.0"`)
		attestation.AttestationID = policyrelease.SHA256Digest(attestation.PayloadBytes)
		envelope, signing := externallySign(t, policyrelease.ReleaseAttestationPayloadType, attestation.PayloadBytes, 1, false)
		_, err := observedPolicyRelease.FinalizeReleaseHandoff(activation, attestation, envelope, signing)
		if policyrelease.ErrorCode(err) != "json_member_name_mismatch" {
			t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})
}

func mutateEvidenceReport(t testing.TB, input *policyrelease.BuildInput, path string, mutate func(map[string]any)) {
	t.Helper()
	for index := range input.EvidenceFiles {
		if input.EvidenceFiles[index].Path != path {
			continue
		}
		var document map[string]any
		if err := json.Unmarshal(input.EvidenceFiles[index].Content, &document); err != nil {
			t.Fatal(err)
		}
		mutate(document)
		content, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		input.EvidenceFiles[index].Content = content
		return
	}
	t.Fatalf("evidence report %s missing", path)
}

func mutateSecurityProfile(t testing.TB, input *policyrelease.BuildInput, mutate func(map[string]any)) {
	t.Helper()
	for index := range input.PayloadFiles {
		if input.PayloadFiles[index].Path != input.Manifest.Profiles[0].Path {
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
		input.Manifest.Profiles[0].Digest = policyrelease.SHA256Digest(content)
		return
	}
	t.Fatal("security profile payload missing")
}

func externalMappingBuildInput(t testing.TB) policyrelease.BuildInput {
	t.Helper()
	input := fixtureBuildInput(t, "commercial", 1, false)
	const snapshotPath = "tests/contract/fixtures/security-label-profiles/regulated-example-registry.json"
	const evidencePath = "tests/contract/fixtures/security-label-profiles/regulated-example-rule-evidence.json"
	snapshot := repositoryBytes(t, snapshotPath)
	evidence := repositoryBytes(t, evidencePath)
	mutateSecurityProfile(t, &input, func(document map[string]any) {
		document["profile_purpose"] = "external_regime_mapping"
		document["authoritative_sources"] = []any{map[string]any{
			"source_kind": "authoritative_snapshot", "source_id": "synthetic_registry",
			"title": "Synthetic registry snapshot", "uri": "urn:stead:test:synthetic-registry",
			"source_version_or_date": "fixture-v1", "retrieved_at": "2026-08-29T00:00:00Z",
			"snapshot_digest": policyrelease.SHA256Digest(snapshot), "payload_path": snapshotPath,
			"mapped_scope": "Synthetic category fixture only",
		}}
		semantics := document["semantics"].(map[string]any)
		semantics["registry_mappings"] = []any{map[string]any{
			"mapping_id": "fixture_mapping", "dimension": "sensitivity", "internal_id": "fixture",
			"source_id": "synthetic_registry", "external_id": "SYN-001",
			"mapping_provenance": map[string]any{
				"mapping_version": "1.0.0", "source_revision": "fixture-v1",
				"produced_by": "stead-contract-fixture", "reviewed_at": "2026-08-29T00:00:00Z",
				"tested_coverage": []any{map[string]any{
					"test_id": "T-ADR-0002-PROFILE-NEUTRALITY", "evidence_path": evidencePath,
					"evidence_digest": policyrelease.SHA256Digest(evidence),
				}},
			},
		}}
	})
	input.PayloadFiles = append(input.PayloadFiles, policyrelease.File{
		Path: "payload/" + snapshotPath, MediaType: "application/json", Content: snapshot,
	})
	input.EvidenceFiles = append(input.EvidenceFiles, policyrelease.File{
		Path: "evidence/" + evidencePath, MediaType: "application/vnd.stead.policy-test-result.v1+json", Content: evidence,
	})
	rebindPolicyContentIndex(t, &input)
	return input
}

func removeEvidenceFile(t testing.TB, input *policyrelease.BuildInput, path string) {
	t.Helper()
	for index := range input.EvidenceFiles {
		if input.EvidenceFiles[index].Path == path {
			input.EvidenceFiles = append(input.EvidenceFiles[:index], input.EvidenceFiles[index+1:]...)
			return
		}
	}
	t.Fatalf("evidence report %s missing", path)
}

func replaceExternalMappingEvidence(t testing.TB, input *policyrelease.BuildInput, content []byte) {
	t.Helper()
	const path = "evidence/tests/contract/fixtures/security-label-profiles/regulated-example-rule-evidence.json"
	for index := range input.EvidenceFiles {
		if input.EvidenceFiles[index].Path != path {
			continue
		}
		input.EvidenceFiles[index].Content = append([]byte(nil), content...)
		digest := policyrelease.SHA256Digest(content)
		mutateSecurityProfile(t, input, func(document map[string]any) {
			mapping := document["semantics"].(map[string]any)["registry_mappings"].([]any)[0].(map[string]any)
			coverage := mapping["mapping_provenance"].(map[string]any)["tested_coverage"].([]any)[0].(map[string]any)
			coverage["evidence_digest"] = digest
		})
		rebindPolicyContentIndex(t, input)
		return
	}
	t.Fatalf("evidence report %s missing", path)
}

func TestExternalRegimeMappingBindsSnapshotAndMappingEvidence(t *testing.T) {
	input := externalMappingBuildInput(t)
	unsigned, err := observedPolicyRelease.PrepareUnsigned(input)
	if err != nil {
		t.Fatalf("valid external mapping rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	envelope, signing := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	activation, err := observedPolicyRelease.FinalizeActivationArchive(unsigned, envelope, signing)
	if err != nil {
		t.Fatalf("valid external mapping archive rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	if _, err := observedPolicyRelease.ValidateArchive(activation.ArchiveBytes, envelope, unsigned.Manifest.Files); err != nil {
		t.Fatalf("external mapping archive validation failed: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	want := map[string]bool{
		"payload/tests/contract/fixtures/security-label-profiles/regulated-example-registry.json":       false,
		"evidence/tests/contract/fixtures/security-label-profiles/regulated-example-rule-evidence.json": false,
	}
	for _, file := range unsigned.Manifest.Files {
		if _, tracked := want[file.Path]; tracked {
			want[file.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Fatalf("external mapping artifact not digest-listed: %s", path)
		}
	}

	testCases := []struct {
		name   string
		mutate func(*policyrelease.BuildInput)
		code   string
	}{
		{"reference source forbidden", func(input *policyrelease.BuildInput) {
			mutateSecurityProfile(t, input, func(document map[string]any) {
				source := document["authoritative_sources"].([]any)[0].(map[string]any)
				source["source_kind"] = "reference"
				delete(source, "retrieved_at")
				delete(source, "snapshot_digest")
				delete(source, "payload_path")
			})
		}, "security_profile_external_mapping_requires_snapshots"},
		{"missing snapshot", func(input *policyrelease.BuildInput) {
			input.PayloadFiles = input.PayloadFiles[:len(input.PayloadFiles)-1]
		}, "missing_bound_file"},
		{"snapshot digest mismatch", func(input *policyrelease.BuildInput) {
			input.PayloadFiles[len(input.PayloadFiles)-1].Content = []byte(`{"changed":true}`)
		}, "bound_digest_mismatch"},
		{"missing mapping evidence", func(input *policyrelease.BuildInput) {
			removeEvidenceFile(t, input, "evidence/tests/contract/fixtures/security-label-profiles/regulated-example-rule-evidence.json")
		}, "missing_security_profile_mapping_evidence"},
		{"mapping evidence digest mismatch", func(input *policyrelease.BuildInput) {
			for index := range input.EvidenceFiles {
				if input.EvidenceFiles[index].Path == "evidence/tests/contract/fixtures/security-label-profiles/regulated-example-rule-evidence.json" {
					input.EvidenceFiles[index].Content = []byte(`{"changed":true}`)
				}
			}
		}, "security_profile_artifact_digest_mismatch"},
		{"stale mapping source revision", func(input *policyrelease.BuildInput) {
			mutateSecurityProfile(t, input, func(document map[string]any) {
				mapping := document["semantics"].(map[string]any)["registry_mappings"].([]any)[0].(map[string]any)
				mapping["mapping_provenance"].(map[string]any)["source_revision"] = "stale"
			})
		}, "security_profile_registry_mapping_source_mismatch"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := externalMappingBuildInput(t)
			testCase.mutate(&candidate)
			_, err := observedPolicyRelease.PrepareUnsigned(candidate)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func TestExternalMappingEvidenceUsesClosedTypedAdmission(t *testing.T) {
	t.Run("registered mapping evidence must be profile bound", func(t *testing.T) {
		input := fixtureBuildInput(t, "commercial", 1, false)
		input.EvidenceFiles = append(input.EvidenceFiles, policyrelease.File{
			Path:      "evidence/tests/contract/fixtures/security-label-profiles/regulated-example-rule-evidence.json",
			MediaType: "application/vnd.stead.policy-test-result.v1+json",
			Content:   repositoryBytes(t, "tests/contract/fixtures/security-label-profiles/regulated-example-rule-evidence.json"),
		})
		if _, err := observedPolicyRelease.PrepareUnsigned(input); policyrelease.ErrorCode(err) != "unbound_security_profile_mapping_evidence" {
			t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	for name, path := range map[string]string{
		"outside admitted roots": "mapping-result.json",
		"noncanonical path":      "tests/../private-mapping.json",
	} {
		t.Run(name, func(t *testing.T) {
			input := externalMappingBuildInput(t)
			mutateSecurityProfile(t, &input, func(document map[string]any) {
				mapping := document["semantics"].(map[string]any)["registry_mappings"].([]any)[0].(map[string]any)
				coverage := mapping["mapping_provenance"].(map[string]any)["tested_coverage"].([]any)[0].(map[string]any)
				coverage["evidence_path"] = path
			})
			if _, err := observedPolicyRelease.PrepareUnsigned(input); policyrelease.ErrorCode(err) != "security_profile_artifact_path_mismatch" {
				t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
			}
		})
	}

	t.Run("arbitrary private JSON path", func(t *testing.T) {
		input := externalMappingBuildInput(t)
		content := []byte(`{"private_key":"LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t","credential":"secret"}`)
		mutateSecurityProfile(t, &input, func(document map[string]any) {
			mapping := document["semantics"].(map[string]any)["registry_mappings"].([]any)[0].(map[string]any)
			coverage := mapping["mapping_provenance"].(map[string]any)["tested_coverage"].([]any)[0].(map[string]any)
			coverage["evidence_path"] = "tests/private-mapping.json"
			coverage["evidence_digest"] = policyrelease.SHA256Digest(content)
		})
		input.EvidenceFiles = append(input.EvidenceFiles, policyrelease.File{
			Path: "evidence/tests/private-mapping.json", MediaType: "application/json", Content: content,
		})
		if _, err := observedPolicyRelease.PrepareUnsigned(input); policyrelease.ErrorCode(err) != "unknown_evidence_path" {
			t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("wrong media on typed mapping path", func(t *testing.T) {
		input := externalMappingBuildInput(t)
		for index := range input.EvidenceFiles {
			if input.EvidenceFiles[index].Path == "evidence/tests/contract/fixtures/security-label-profiles/regulated-example-rule-evidence.json" {
				input.EvidenceFiles[index].MediaType = "application/json"
			}
		}
		if _, err := observedPolicyRelease.PrepareUnsigned(input); policyrelease.ErrorCode(err) != "evidence_media_type_mismatch" {
			t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("test identity mismatch", func(t *testing.T) {
		input := externalMappingBuildInput(t)
		mutateSecurityProfile(t, &input, func(document map[string]any) {
			mapping := document["semantics"].(map[string]any)["registry_mappings"].([]any)[0].(map[string]any)
			coverage := mapping["mapping_provenance"].(map[string]any)["tested_coverage"].([]any)[0].(map[string]any)
			coverage["test_id"] = "T-UNRELATED"
		})
		rebindPolicyContentIndex(t, &input)
		if _, err := observedPolicyRelease.PrepareUnsigned(input); policyrelease.ErrorCode(err) != "security_profile_mapping_evidence_binding_mismatch" {
			t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	for name, assertion := range map[string]string{
		"private material in typed assertion": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t",
		"credential in typed assertion":       "credential-token-value",
	} {
		t.Run(name, func(t *testing.T) {
			input := externalMappingBuildInput(t)
			content, err := json.Marshal(map[string]any{
				"test_id": "T-ADR-0002-PROFILE-NEUTRALITY", "assertions": []string{assertion},
			})
			if err != nil {
				t.Fatal(err)
			}
			replaceExternalMappingEvidence(t, &input, content)
			if _, err := observedPolicyRelease.PrepareUnsigned(input); policyrelease.ErrorCode(err) != "policy_test_evidence_schema_mismatch" {
				t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
			}
		})
	}

	for _, field := range []string{"private_key", "credential", "activation_set_id", "archive_digest", "signing_workflow_identity"} {
		t.Run(field, func(t *testing.T) {
			input := externalMappingBuildInput(t)
			var document map[string]any
			for _, file := range input.EvidenceFiles {
				if file.Path == "evidence/tests/contract/fixtures/security-label-profiles/regulated-example-rule-evidence.json" {
					if err := json.Unmarshal(file.Content, &document); err != nil {
						t.Fatal(err)
					}
				}
			}
			document[field] = "impossible-pre-signing-material"
			content, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			replaceExternalMappingEvidence(t, &input, content)
			if _, err := observedPolicyRelease.PrepareUnsigned(input); policyrelease.ErrorCode(err) != "signed_payload_contract_error" {
				t.Fatalf("error = %v (%s)", err, policyrelease.ErrorCode(err))
			}
		})
	}
}

func TestPreSigningEvidenceUsesClosedPathMediaAndSchemaAdmission(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*policyrelease.BuildInput)
		code   string
	}{
		{"renamed private material", func(input *policyrelease.BuildInput) {
			input.EvidenceFiles = append(input.EvidenceFiles, policyrelease.File{Path: "evidence/scan.json", MediaType: "application/json", Content: []byte(`{"data":"LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t"}`)})
		}, "unknown_evidence_path"},
		{"encoded private material in typed report", func(input *policyrelease.BuildInput) {
			mutateEvidenceReport(t, input, "evidence/conformance-result.json", func(document map[string]any) { document["encoded_material"] = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t" })
		}, "signed_payload_contract_error"},
		{"encoded material in nominal SPDX identifier", func(input *policyrelease.BuildInput) {
			mutateEvidenceReport(t, input, "evidence/sbom.spdx.json", func(document map[string]any) {
				graph := document["@graph"].([]any)
				for _, item := range graph {
					element := item.(map[string]any)
					if element["type"] == "software_Package" {
						element["spdxId"] = "SPDXRef-LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t="
					}
				}
			})
		}, "spdx_evidence_schema_mismatch"},
		{"escaped private field", func(input *policyrelease.BuildInput) {
			input.EvidenceFiles[2].Content = []byte(`{"agent_intersection":"pass","critical_mutation_score_percent":93,"decision_rows_covered_percent":100,"deterministic_replay":"pass","explicit_deny":"pass","label_lattice":"pass","provider_bypass":"pass","private\u005fkey":"x"}`)
		}, "signed_payload_contract_error"},
		{"future identity field", func(input *policyrelease.BuildInput) {
			mutateEvidenceReport(t, input, "evidence/license-result.json", func(document map[string]any) {
				document["archive_digest"] = policyrelease.SHA256Digest([]byte("future"))
			})
		}, "signed_payload_contract_error"},
		{"wrong media on closed path", func(input *policyrelease.BuildInput) { input.EvidenceFiles[2].MediaType = "application/json" }, "evidence_media_type_mismatch"},
		{"malformed typed JSON", func(input *policyrelease.BuildInput) { input.EvidenceFiles[2].Content = []byte(`{"result":`) }, "malformed_json"},
		{"duplicate typed JSON", func(input *policyrelease.BuildInput) {
			input.EvidenceFiles[2].Content = []byte(`{"agent_intersection":"pass","agent_intersection":"pass"}`)
		}, "duplicate_json_key"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			testCase.mutate(&input)
			_, err := observedPolicyRelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func TestBuildAdmissionRejectsUnknownMediaCoverageAndUnboundContent(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*policyrelease.BuildInput)
		code   string
	}{
		{"unknown media", func(input *policyrelease.BuildInput) { input.EvidenceFiles[0].MediaType = "application/x-unknown" }, "unknown_media_type"},
		{"decision coverage", func(input *policyrelease.BuildInput) {
			mutateEvidenceReport(t, input, "evidence/conformance-result.json", func(document map[string]any) { document["decision_rows_covered_percent"] = 99 })
		}, "decision_coverage_below_floor"},
		{"mutation floor", func(input *policyrelease.BuildInput) {
			mutateEvidenceReport(t, input, "evidence/conformance-result.json", func(document map[string]any) { document["critical_mutation_score_percent"] = 89 })
		}, "mutation_score_below_floor"},
		{"provider bypass", func(input *policyrelease.BuildInput) {
			mutateEvidenceReport(t, input, "evidence/conformance-result.json", func(document map[string]any) { document["provider_bypass"] = "fail" })
		}, "presented_conformance_claim_not_pass"},
		{"unbound payload", func(input *policyrelease.BuildInput) {
			input.PayloadFiles = append(input.PayloadFiles, policyrelease.File{Path: "payload/unbound", MediaType: "text/plain; charset=utf-8", Content: []byte("x")})
		}, "unbound_payload_file"},
		{"policy index media type", func(input *policyrelease.BuildInput) {
			input.PayloadFiles[0].MediaType = "application/json"
		}, "bound_media_type_mismatch"},
		{"missing security profile", func(input *policyrelease.BuildInput) {
			input.Manifest.Profiles = nil
		}, "missing_security_profile"},
		{"missing contract role", func(input *policyrelease.BuildInput) {
			input.Manifest.ContractBindings = input.Manifest.ContractBindings[1:]
		}, "missing_contract_binding_role"},
		{"duplicate contract role", func(input *policyrelease.BuildInput) {
			duplicate := input.Manifest.ContractBindings[0]
			duplicate.Path = input.Manifest.ContractBindings[1].Path
			duplicate.Digest = input.Manifest.ContractBindings[1].Digest
			duplicate.MediaType = input.Manifest.ContractBindings[1].MediaType
			input.Manifest.ContractBindings[1] = duplicate
		}, "duplicate_contract_binding_role"},
		{"unknown contract role", func(input *policyrelease.BuildInput) {
			input.Manifest.ContractBindings[0].Role = "future_authority"
		}, "unknown_contract_binding_role"},
		{"missing compatibility identifier", func(input *policyrelease.BuildInput) {
			input.Manifest.OpenFGAModel.CompatibilityID = ""
		}, "invalid_identifier"},
		{"missing tuple migration identifier", func(input *policyrelease.BuildInput) {
			input.Manifest.OpenFGAModel.TupleMigrationID = ""
		}, "invalid_identifier"},
		{"duplicate predecessor", func(input *policyrelease.BuildInput) {
			predecessor := policyrelease.SHA256Digest([]byte("predecessor"))
			input.Manifest.CompatiblePredecessorActivationSetIDs = []string{predecessor, predecessor}
		}, "duplicate_value"},
		{"invalid payload UTF-8", func(input *policyrelease.BuildInput) {
			input.PayloadFiles[5].Content = []byte{0xff}
		}, "invalid_artifact_utf8"},
		{"floating JSON number", func(input *policyrelease.BuildInput) {
			input.EvidenceFiles[0].Content = []byte(`{"spdxVersion":"SPDX-3.0","score":1.5}`)
		}, "non_integer_json_number"},
		{"missing required evidence", func(input *policyrelease.BuildInput) {
			input.EvidenceFiles = input.EvidenceFiles[1:]
		}, "missing_required_evidence"},
		{"missing build review", func(input *policyrelease.BuildInput) {
			input.Evidence.ReviewReceipts = nil
		}, "missing_presented_build_review"},
		{"pending build review", func(input *policyrelease.BuildInput) {
			input.Evidence.ReviewReceipts[0].ClaimedDisposition = "pending"
		}, "presented_build_review_not_accept"},
		{"builder self review", func(input *policyrelease.BuildInput) {
			input.Evidence.ReviewReceipts[0].ReviewerID = input.Evidence.BuilderIdentity
		}, "self_presented_build_review"},
		{"duplicate build review", func(input *policyrelease.BuildInput) {
			input.Evidence.ReviewReceipts = append(input.Evidence.ReviewReceipts, input.Evidence.ReviewReceipts[0])
		}, "duplicate_review"},
		{"review subject mismatch", func(input *policyrelease.BuildInput) {
			input.Evidence.ReviewReceipts[0].SubjectDigest = policyrelease.SHA256Digest([]byte("other"))
		}, "presented_review_subject_mismatch"},
		{"rejected build waiver", func(input *policyrelease.BuildInput) {
			input.Evidence.WaiverReceipts = []policyrelease.WaiverReceipt{{WaiverID: "fixture-waiver", SubjectDigest: input.Evidence.ReviewReceipts[0].SubjectDigest, RecordDigest: policyrelease.SHA256Digest([]byte("waiver")), ClaimedDisposition: "rejected"}}
		}, "presented_build_waiver_not_approved"},
		{"invalid build waiver disposition", func(input *policyrelease.BuildInput) {
			input.Evidence.WaiverReceipts = []policyrelease.WaiverReceipt{{WaiverID: "fixture-waiver", SubjectDigest: input.Evidence.ReviewReceipts[0].SubjectDigest, RecordDigest: policyrelease.SHA256Digest([]byte("waiver")), ClaimedDisposition: "pending"}}
		}, "invalid_claimed_waiver_disposition"},
		{"duplicate build waiver", func(input *policyrelease.BuildInput) {
			waiver := policyrelease.WaiverReceipt{WaiverID: "fixture-waiver", SubjectDigest: input.Evidence.ReviewReceipts[0].SubjectDigest, RecordDigest: policyrelease.SHA256Digest([]byte("waiver")), ClaimedDisposition: "approved"}
			input.Evidence.WaiverReceipts = []policyrelease.WaiverReceipt{waiver, waiver}
		}, "duplicate_waiver"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			testCase.mutate(&input)
			_, err := observedPolicyRelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func TestSigningAndReleaseWorkflowsRemainSeparatedFromBuilder(t *testing.T) {
	unsigned, err := observedPolicyRelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	envelope, signing := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	signing, err = policyrelease.NewPresentedSigningResult(unsigned.EvidenceManifest.BuilderIdentity, signing.Receipts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observedPolicyRelease.FinalizeActivationArchive(unsigned, envelope, signing); policyrelease.ErrorCode(err) != "builder_signing_workflow_not_separated" {
		t.Fatalf("builder signing separation error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	activation, attestation, _ := completeFixtureRelease(t, "commercial", 1, false)
	releaseEnvelope, releaseSigning := externallySign(t, policyrelease.ReleaseAttestationPayloadType, attestation.PayloadBytes, 1, false)
	releaseSigning, err = policyrelease.NewPresentedSigningResult(attestation.Payload.ReleaseWorkflowIdentity, releaseSigning.Receipts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observedPolicyRelease.FinalizeReleaseHandoff(activation, attestation, releaseEnvelope, releaseSigning); policyrelease.ErrorCode(err) != "release_signing_workflow_not_separated" {
		t.Fatalf("release signing separation error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}

func TestReleaseAttestationSigningRequestIsExactlyBound(t *testing.T) {
	activation, attestation, _ := completeFixtureRelease(t, "commercial", 1, false)
	releaseEnvelope, releaseSigning := externallySign(t, policyrelease.ReleaseAttestationPayloadType, attestation.PayloadBytes, 1, false)
	testCases := []struct {
		name   string
		mutate func(*policyrelease.UnsignedReleaseAttestation)
	}{
		{"request purpose", func(candidate *policyrelease.UnsignedReleaseAttestation) {
			candidate.SigningRequest.Purpose = "different-purpose"
		}},
		{"request bytes", func(candidate *policyrelease.UnsignedReleaseAttestation) {
			candidate.SigningRequestBytes = append(append([]byte(nil), candidate.SigningRequestBytes...), ' ')
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := attestation
			testCase.mutate(&candidate)
			handoff, err := observedPolicyRelease.FinalizeReleaseHandoff(activation, candidate, releaseEnvelope, releaseSigning)
			if policyrelease.ErrorCode(err) != "signing_request_binding_mismatch" || handoff.ArchiveBytes != nil || handoff.ReleaseAttestationEnvelopeBytes != nil {
				t.Fatalf("signing request binding = %v (%s), archive=%d envelope=%d", err, policyrelease.ErrorCode(err), len(handoff.ArchiveBytes), len(handoff.ReleaseAttestationEnvelopeBytes))
			}
		})
	}
}

func TestReleaseAttestationRejectsSelfReferenceSwapsAndIncompleteEvidence(t *testing.T) {
	activation, attestation, _ := completeFixtureRelease(t, "commercial", 1, false)
	releaseInput := func(reviewer, disposition string) policyrelease.ReleaseAttestationInput {
		return policyrelease.ReleaseAttestationInput{
			ReleaseWorkflowIdentity: "release-workflow-v1",
			ReviewReceipts: []policyrelease.ReviewReceipt{{
				ReviewerID: reviewer, Role: "independent-release", SubjectDigest: activation.ArchiveDigest,
				RecordDigest: policyrelease.SHA256Digest([]byte("review-record")), ClaimedDisposition: disposition,
			}},
			OfflineCheckReceipt: policyrelease.OfflineCheckReceipt{ClaimedOutcome: "pass", SubjectArchiveDigest: activation.ArchiveDigest, ReportDigest: policyrelease.SHA256Digest([]byte("offline-report"))},
		}
	}

	t.Run("unknown self identity", func(t *testing.T) {
		var payload map[string]any
		if err := json.Unmarshal(attestation.PayloadBytes, &payload); err != nil {
			t.Fatal(err)
		}
		payload["release_attestation_id"] = policyrelease.SHA256Digest([]byte("self"))
		mutated, _ := json.Marshal(payload)
		candidate := attestation
		candidate.PayloadBytes = mutated
		candidate.AttestationID = policyrelease.SHA256Digest(mutated)
		envelope, signing := externallySign(t, policyrelease.ReleaseAttestationPayloadType, mutated, 1, false)
		_, err := observedPolicyRelease.FinalizeReleaseHandoff(activation, candidate, envelope, signing)
		if policyrelease.ErrorCode(err) != "signed_payload_contract_error" {
			t.Fatalf("self-reference error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("archive binding swap", func(t *testing.T) {
		candidate := attestation
		candidate.Payload.ArchiveDigest = policyrelease.SHA256Digest([]byte("other-archive"))
		candidate.PayloadBytes, _ = json.Marshal(candidate.Payload)
		candidate.AttestationID = policyrelease.SHA256Digest(candidate.PayloadBytes)
		envelope, signing := externallySign(t, policyrelease.ReleaseAttestationPayloadType, candidate.PayloadBytes, 1, false)
		_, err := observedPolicyRelease.FinalizeReleaseHandoff(activation, candidate, envelope, signing)
		if policyrelease.ErrorCode(err) != "release_attestation_binding_mismatch" {
			t.Fatalf("archive swap error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("mutated archive bytes", func(t *testing.T) {
		candidate := activation
		candidate.ArchiveBytes = append([]byte(nil), candidate.ArchiveBytes...)
		index := bytes.Index(candidate.ArchiveBytes, []byte("fixture-only"))
		if index < 0 {
			t.Fatal("fixture content not found")
		}
		candidate.ArchiveBytes[index] ^= 1
		_, err := observedPolicyRelease.PrepareReleaseAttestation(candidate, policyrelease.ReleaseAttestationInput{})
		if policyrelease.ErrorCode(err) != "digest_mismatch" {
			t.Fatalf("mutated archive error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("offline result for other archive", func(t *testing.T) {
		input := releaseInput("reviewer-a", "accept")
		input.OfflineCheckReceipt.SubjectArchiveDigest = policyrelease.SHA256Digest([]byte("other"))
		_, err := observedPolicyRelease.PrepareReleaseAttestation(activation, input)
		if policyrelease.ErrorCode(err) != "presented_offline_check_not_bound" {
			t.Fatalf("offline binding error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("pending approval", func(t *testing.T) {
		_, err := observedPolicyRelease.PrepareReleaseAttestation(activation, releaseInput("reviewer-a", "pending"))
		if policyrelease.ErrorCode(err) != "presented_release_review_not_accept" {
			t.Fatalf("pending approval error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("rejected waiver", func(t *testing.T) {
		input := releaseInput("reviewer-a", "accept")
		input.WaiverReceipts = []policyrelease.WaiverReceipt{{
			WaiverID:           "fixture-rejected-waiver",
			SubjectDigest:      activation.ArchiveDigest,
			RecordDigest:       policyrelease.SHA256Digest([]byte("fixture-rejected-waiver-record")),
			ClaimedDisposition: "rejected",
		}}
		_, err := observedPolicyRelease.PrepareReleaseAttestation(activation, input)
		if policyrelease.ErrorCode(err) != "presented_release_waiver_not_approved" {
			t.Fatalf("rejected waiver error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("missing approval", func(t *testing.T) {
		input := releaseInput("reviewer-a", "accept")
		input.ReviewReceipts = nil
		_, err := observedPolicyRelease.PrepareReleaseAttestation(activation, input)
		if policyrelease.ErrorCode(err) != "missing_presented_final_review" {
			t.Fatalf("missing approval error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("release workflow is builder", func(t *testing.T) {
		input := releaseInput("reviewer-a", "accept")
		input.ReleaseWorkflowIdentity = activation.Unsigned.EvidenceManifest.BuilderIdentity
		_, err := observedPolicyRelease.PrepareReleaseAttestation(activation, input)
		if policyrelease.ErrorCode(err) != "builder_release_workflow_not_separated" {
			t.Fatalf("builder release workflow error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("release self approval", func(t *testing.T) {
		_, err := observedPolicyRelease.PrepareReleaseAttestation(activation, releaseInput("release-workflow-v1", "accept"))
		if policyrelease.ErrorCode(err) != "self_presented_release_review" {
			t.Fatalf("release self approval error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})
}

func TestSigningReceiptMustBindExactReturnedSignature(t *testing.T) {
	unsigned, err := observedPolicyRelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	envelope, signing := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	signing.Receipts[0].SignatureDigest = policyrelease.SHA256Digest([]byte("other-signature"))
	signing, err = policyrelease.NewPresentedSigningResult(signing.WorkflowIdentity, signing.Receipts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = observedPolicyRelease.FinalizeActivationArchive(unsigned, envelope, signing)
	if policyrelease.ErrorCode(err) != "signing_receipt_mismatch" {
		t.Fatalf("receipt mismatch error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}
