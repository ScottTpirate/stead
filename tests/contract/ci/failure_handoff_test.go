package ci_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func TestContractErrorsExposeOnlyStableSafeCodes(t *testing.T) {
	input := fixtureBuildInput(t, "commercial", 1, false)
	input.Manifest.DeploymentPolicy.PolicySignatureThreshold = 0
	_, err := policyrelease.PrepareUnsigned(input)
	if err == nil || err.Error() != "invalid_signature_threshold: deployment_policy.policy_signature_threshold" || policyrelease.ErrorCode(err) != "invalid_signature_threshold" {
		t.Fatalf("unsafe or unstable contract error: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("validation error unexpectedly exposed an underlying payload error")
	}
	if policyrelease.ErrorCode(errors.New("ordinary error")) != "" {
		t.Fatal("ordinary error was assigned a contract code")
	}
}

func TestPreSigningEvidenceRejectsCircularPrivateAndMalformedInputs(t *testing.T) {
	testCases := []struct {
		name    string
		content []byte
		media   string
		code    string
	}{
		{"future activation identity", []byte(`{"activation_set_id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), "application/json", "circular_or_private_evidence"},
		{"archive identity", []byte(`{"archive_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), "application/json", "circular_or_private_evidence"},
		{"private key", []byte("-----BEGIN PRIVATE KEY-----\nnot-a-key"), "text/plain; charset=utf-8", "circular_or_private_evidence"},
		{"algorithm-specific private key", []byte("-----BEGIN RSA PRIVATE KEY-----\nnot-a-key"), "text/plain; charset=utf-8", "circular_or_private_evidence"},
		{"malformed JSON", []byte(`{"result":`), "application/json", "malformed_json"},
		{"duplicate JSON", []byte(`{"result":"pass","result":"pass"}`), "application/json", "duplicate_json_key"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			input.EvidenceFiles = append(input.EvidenceFiles, policyrelease.File{Path: "evidence/adversarial.json", MediaType: testCase.media, Content: testCase.content})
			_, err := policyrelease.PrepareUnsigned(input)
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
		{"decision coverage", func(input *policyrelease.BuildInput) { input.Evidence.Conformance.DecisionRowsCoveredPercent = 99 }, "decision_coverage_below_floor"},
		{"mutation floor", func(input *policyrelease.BuildInput) { input.Evidence.Conformance.CriticalMutationScorePercent = 89 }, "mutation_score_below_floor"},
		{"provider bypass", func(input *policyrelease.BuildInput) { input.Evidence.Conformance.ProviderBypassPassed = false }, "required_conformance_failed"},
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
			input.Evidence.Reviews = nil
		}, "missing_build_review"},
		{"pending build review", func(input *policyrelease.BuildInput) {
			input.Evidence.Reviews[0].Disposition = "pending"
		}, "build_review_not_accepted"},
		{"builder self review", func(input *policyrelease.BuildInput) {
			input.Evidence.Reviews[0].ReviewerID = input.Evidence.BuilderIdentity
		}, "self_approved_build_evidence"},
		{"duplicate build review", func(input *policyrelease.BuildInput) {
			input.Evidence.Reviews = append(input.Evidence.Reviews, input.Evidence.Reviews[0])
		}, "duplicate_review"},
		{"nonimmutable review revision", func(input *policyrelease.BuildInput) {
			input.Evidence.Reviews[0].Revision = "main"
		}, "nonimmutable_revision"},
		{"rejected build waiver", func(input *policyrelease.BuildInput) {
			input.Evidence.Waivers = []policyrelease.Waiver{{WaiverID: "fixture-waiver", Revision: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Disposition: "rejected"}}
		}, "build_waiver_not_approved"},
		{"invalid build waiver disposition", func(input *policyrelease.BuildInput) {
			input.Evidence.Waivers = []policyrelease.Waiver{{WaiverID: "fixture-waiver", Revision: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Disposition: "pending"}}
		}, "invalid_waiver_disposition"},
		{"duplicate build waiver", func(input *policyrelease.BuildInput) {
			waiver := policyrelease.Waiver{WaiverID: "fixture-waiver", Revision: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Disposition: "approved"}
			input.Evidence.Waivers = []policyrelease.Waiver{waiver, waiver}
		}, "duplicate_waiver"},
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

func TestSigningAndReleaseWorkflowsRemainSeparatedFromBuilder(t *testing.T) {
	unsigned, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	envelope, signing := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	signing, err = policyrelease.NewSigningResult(unsigned.EvidenceManifest.BuilderIdentity, signing.Receipts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyrelease.FinalizeActivationArchive(unsigned, envelope, signing); policyrelease.ErrorCode(err) != "builder_signing_workflow_not_separated" {
		t.Fatalf("builder signing separation error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	activation, attestation, _ := completeFixtureRelease(t, "commercial", 1, false)
	releaseEnvelope, releaseSigning := externallySign(t, policyrelease.ReleaseAttestationPayloadType, attestation.PayloadBytes, 1, false)
	releaseSigning, err = policyrelease.NewSigningResult(attestation.Payload.ReleaseWorkflowIdentity, releaseSigning.Receipts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyrelease.FinalizeReleaseHandoff(activation, attestation, releaseEnvelope, releaseSigning); policyrelease.ErrorCode(err) != "release_signing_workflow_not_separated" {
		t.Fatalf("release signing separation error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}

func TestReleaseAttestationRejectsSelfReferenceSwapsAndIncompleteEvidence(t *testing.T) {
	activation, attestation, _ := completeFixtureRelease(t, "commercial", 1, false)

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
		_, err := policyrelease.FinalizeReleaseHandoff(activation, candidate, envelope, signing)
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
		_, err := policyrelease.FinalizeReleaseHandoff(activation, candidate, envelope, signing)
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
		_, err := policyrelease.PrepareReleaseAttestation(candidate, policyrelease.ReleaseAttestationInput{})
		if policyrelease.ErrorCode(err) != "digest_mismatch" {
			t.Fatalf("mutated archive error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("offline result for other archive", func(t *testing.T) {
		_, err := policyrelease.PrepareReleaseAttestation(activation, policyrelease.ReleaseAttestationInput{
			ReleaseWorkflowIdentity:     "release-workflow-v1",
			FinalApprovals:              []policyrelease.ReviewerDisposition{{ReviewerID: "reviewer-a", Role: "independent-release", Revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Disposition: "accept"}},
			NetworkDisabledVerification: policyrelease.NetworkDisabledVerification{Outcome: "pass", VerifiedArchiveDigest: policyrelease.SHA256Digest([]byte("other")), ResultDigest: policyrelease.SHA256Digest([]byte("result"))},
		})
		if policyrelease.ErrorCode(err) != "offline_verification_not_bound" {
			t.Fatalf("offline binding error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("pending approval", func(t *testing.T) {
		_, err := policyrelease.PrepareReleaseAttestation(activation, policyrelease.ReleaseAttestationInput{
			ReleaseWorkflowIdentity:     "release-workflow-v1",
			FinalApprovals:              []policyrelease.ReviewerDisposition{{ReviewerID: "reviewer-a", Role: "independent-release", Revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Disposition: "pending"}},
			NetworkDisabledVerification: policyrelease.NetworkDisabledVerification{Outcome: "pass", VerifiedArchiveDigest: activation.ArchiveDigest, ResultDigest: policyrelease.SHA256Digest([]byte("result"))},
		})
		if policyrelease.ErrorCode(err) != "release_review_not_accepted" {
			t.Fatalf("pending approval error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("missing approval", func(t *testing.T) {
		_, err := policyrelease.PrepareReleaseAttestation(activation, policyrelease.ReleaseAttestationInput{
			ReleaseWorkflowIdentity:     "release-workflow-v1",
			NetworkDisabledVerification: policyrelease.NetworkDisabledVerification{Outcome: "pass", VerifiedArchiveDigest: activation.ArchiveDigest, ResultDigest: policyrelease.SHA256Digest([]byte("result"))},
		})
		if policyrelease.ErrorCode(err) != "missing_final_approval" {
			t.Fatalf("missing approval error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("release workflow is builder", func(t *testing.T) {
		_, err := policyrelease.PrepareReleaseAttestation(activation, policyrelease.ReleaseAttestationInput{
			ReleaseWorkflowIdentity:     activation.Unsigned.EvidenceManifest.BuilderIdentity,
			FinalApprovals:              []policyrelease.ReviewerDisposition{{ReviewerID: "reviewer-a", Role: "independent-release", Revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Disposition: "accept"}},
			NetworkDisabledVerification: policyrelease.NetworkDisabledVerification{Outcome: "pass", VerifiedArchiveDigest: activation.ArchiveDigest, ResultDigest: policyrelease.SHA256Digest([]byte("result"))},
		})
		if policyrelease.ErrorCode(err) != "builder_release_workflow_not_separated" {
			t.Fatalf("builder release workflow error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("release self approval", func(t *testing.T) {
		_, err := policyrelease.PrepareReleaseAttestation(activation, policyrelease.ReleaseAttestationInput{
			ReleaseWorkflowIdentity:     "release-workflow-v1",
			FinalApprovals:              []policyrelease.ReviewerDisposition{{ReviewerID: "release-workflow-v1", Role: "independent-release", Revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Disposition: "accept"}},
			NetworkDisabledVerification: policyrelease.NetworkDisabledVerification{Outcome: "pass", VerifiedArchiveDigest: activation.ArchiveDigest, ResultDigest: policyrelease.SHA256Digest([]byte("result"))},
		})
		if policyrelease.ErrorCode(err) != "self_approved_release" {
			t.Fatalf("release self approval error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})
}

func TestSigningReceiptMustBindExactReturnedSignature(t *testing.T) {
	unsigned, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	envelope, signing := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	signing.Receipts[0].SignatureDigest = policyrelease.SHA256Digest([]byte("other-signature"))
	signing, err = policyrelease.NewSigningResult(signing.WorkflowIdentity, signing.Receipts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = policyrelease.FinalizeActivationArchive(unsigned, envelope, signing)
	if policyrelease.ErrorCode(err) != "signing_receipt_mismatch" {
		t.Fatalf("receipt mismatch error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}
