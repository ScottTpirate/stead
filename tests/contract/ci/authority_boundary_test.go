package ci_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

var syntacticR1S1 = []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}

func syntacticOnlySigning(t testing.TB, payloadType string, payload []byte, workflow string) ([]byte, policyrelease.PresentedSigningResult) {
	t.Helper()
	keyIDHint := policyrelease.SHA256Digest([]byte("arbitrary-untrusted-key-hint"))
	envelope, err := json.Marshal(fixtureEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []fixtureSignature{{
			KeyID: keyIDHint,
			Sig:   base64.StdEncoding.EncodeToString(syntacticR1S1),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := policyrelease.NewPresentedSigningResult(workflow, []policyrelease.PresentedSignatureReceipt{{
		KeyIDHint:          keyIDHint,
		ClaimedCustodianID: "arbitrary-unverified-custodian",
		ClaimedKeyPurpose:  policyrelease.ReleaseKeyPurpose,
		SignatureDigest:    policyrelease.SHA256Digest(syntacticR1S1),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return envelope, result
}

func assertNoAuthorityClaimFields(t testing.TB, value any) {
	t.Helper()
	forbidden := []string{"verified", "satisfied", "authorized", "trusted"}
	var inspect func(reflect.Type)
	seen := make(map[reflect.Type]bool)
	inspect = func(kind reflect.Type) {
		for kind.Kind() == reflect.Pointer || kind.Kind() == reflect.Slice || kind.Kind() == reflect.Array {
			kind = kind.Elem()
		}
		if kind.Kind() != reflect.Struct || seen[kind] {
			return
		}
		seen[kind] = true
		for index := 0; index < kind.NumField(); index++ {
			field := kind.Field(index)
			lowerName := strings.ToLower(field.Name)
			jsonName := strings.ToLower(strings.Split(field.Tag.Get("json"), ",")[0])
			for _, word := range forbidden {
				if strings.Contains(lowerName, word) || strings.Contains(jsonName, word) {
					t.Fatalf("non-verifier API field %s.%s uses authority word %q", kind.Name(), field.Name, word)
				}
			}
			inspect(field.Type)
		}
	}
	inspect(reflect.TypeOf(value))
}

// Regression for the independent review defect: canonical low-S DER r=1,s=1
// plus arbitrary digest/custodian receipts is shape-valid, but WS-09 must emit
// only unverified presented material and a non-authorizing WS-06 handoff.
func TestSyntacticR1S1AndArbitraryReceiptsNeverClaimAuthority(t *testing.T) {
	unsigned, err := observedPolicyRelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	activationEnvelope, activationSigning := syntacticOnlySigning(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, "unverified-activation-workflow")
	activation, err := observedPolicyRelease.FinalizeActivationArchive(unsigned, activationEnvelope, activationSigning)
	if err != nil {
		t.Fatalf("syntax-only activation handoff: %v (%s)", err, policyrelease.ErrorCode(err))
	}

	publicKey, publicKeyID := testPublicKey(0)
	digest := sha256.Sum256(policyrelease.PAE(policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload))
	if ecdsa.VerifyASN1(publicKey, digest[:], syntacticR1S1) {
		t.Fatal("r=1,s=1 unexpectedly verified against the fixture public key")
	}
	if activation.PresentedActivationSignatures.KeyIDHints[0] == publicKeyID {
		t.Fatal("arbitrary key hint unexpectedly equals the fixture SPKI identity")
	}
	if activation.PresentedActivationSigning.Treatment != policyrelease.PresentedMaterialTreatment || activation.PresentedActivationSignatures.Treatment != policyrelease.PresentedMaterialTreatment {
		t.Fatal("syntax-only activation material was not labeled unverified")
	}

	attestation, err := observedPolicyRelease.PrepareReleaseAttestation(activation, policyrelease.ReleaseAttestationInput{
		ReleaseWorkflowIdentity: "unverified-release-workflow",
		ReviewReceipts: []policyrelease.ReviewReceipt{{
			ReviewerID: "arbitrary-reviewer", Role: "independent-release", SubjectDigest: activation.ArchiveDigest,
			RecordDigest: policyrelease.SHA256Digest([]byte("arbitrary-review-record")), ClaimedDisposition: "accept",
		}},
		OfflineCheckReceipt: policyrelease.OfflineCheckReceipt{
			ClaimedOutcome: "pass", SubjectArchiveDigest: activation.ArchiveDigest,
			ReportDigest: policyrelease.SHA256Digest([]byte("arbitrary-offline-report")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	releaseEnvelope, releaseSigning := syntacticOnlySigning(t, policyrelease.ReleaseAttestationPayloadType, attestation.PayloadBytes, "unverified-attestation-signing-workflow")
	handoff, err := observedPolicyRelease.FinalizeReleaseHandoff(activation, attestation, releaseEnvelope, releaseSigning)
	if err != nil {
		t.Fatalf("syntax-only release handoff: %v (%s)", err, policyrelease.ErrorCode(err))
	}

	if attestation.Payload.Authority != policyrelease.NonAuthorizingHandoffAuthority || handoff.Authority != policyrelease.NonAuthorizingHandoffAuthority {
		t.Fatal("syntax-only artifact claimed authority")
	}
	if handoff.PresentedReleaseSigning.Treatment != policyrelease.PresentedMaterialTreatment || handoff.PresentedReleaseSignatures.Treatment != policyrelease.PresentedMaterialTreatment {
		t.Fatal("syntax-only release material was not labeled unverified")
	}
	if handoff.RequiredConsumerVerification.Owner != policyrelease.RequiredConsumerVerificationOwner || handoff.RequiredConsumerVerification.Status != "required_not_performed_by_ws09" || len(handoff.RequiredConsumerVerification.Checks) == 0 {
		t.Fatal("handoff omitted mandatory downstream WS-06 verification")
	}
	for _, encoded := range [][]byte{attestation.PayloadBytes, mustJSON(t, handoff)} {
		lower := bytes.ToLower(encoded)
		for _, prefix := range []string{`"verified`, `"satisfied`, `"authorized`, `"trusted`} {
			if bytes.Contains(lower, []byte(prefix)) {
				t.Fatalf("non-verifier output contains authority claim %q", prefix)
			}
		}
	}
	assertNoAuthorityClaimFields(t, activation)
	assertNoAuthorityClaimFields(t, attestation)
	assertNoAuthorityClaimFields(t, handoff)
}

func mustJSON(t testing.TB, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func rebindUnsignedEvidence(t testing.TB, unsigned *policyrelease.UnsignedActivation, mutate func(*policyrelease.PreSigningEvidenceManifestV1)) {
	t.Helper()
	mutate(&unsigned.EvidenceManifest)
	unsigned.EvidenceManifestBytes = mustJSON(t, unsigned.EvidenceManifest)
	unsigned.EvidenceManifestDigest = policyrelease.SHA256Digest(unsigned.EvidenceManifestBytes)
	unsigned.Manifest.EvidenceManifestDigest = unsigned.EvidenceManifestDigest
	for index := range unsigned.Files {
		if unsigned.Files[index].Path == "evidence/pre-signing-evidence-manifest.json" {
			unsigned.Files[index].Content = append([]byte(nil), unsigned.EvidenceManifestBytes...)
		}
	}
	for index := range unsigned.Manifest.Files {
		if unsigned.Manifest.Files[index].Path == "evidence/pre-signing-evidence-manifest.json" {
			unsigned.Manifest.Files[index].Size = int64(len(unsigned.EvidenceManifestBytes))
			unsigned.Manifest.Files[index].Digest = unsigned.EvidenceManifestDigest
		}
	}
	unsigned.ManifestPayload = mustJSON(t, unsigned.Manifest)
	unsigned.ActivationSetID = policyrelease.SHA256Digest(unsigned.ManifestPayload)
	unsigned.SigningRequest.PayloadBase64 = base64.StdEncoding.EncodeToString(unsigned.ManifestPayload)
	unsigned.SigningRequest.PAEDigest = policyrelease.SHA256Digest(policyrelease.PAE(policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload))
	unsigned.SigningRequestBytes = mustJSON(t, unsigned.SigningRequest)
}

func TestCanonicalCallerRebindingCannotPromotePresentedEvidence(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*policyrelease.PreSigningEvidenceManifestV1)
		code   string
	}{
		{"authority", func(evidence *policyrelease.PreSigningEvidenceManifestV1) { evidence.Authority = "self-certified" }, "evidence_manifest_authority_mismatch"},
		{"report treatment", func(evidence *policyrelease.PreSigningEvidenceManifestV1) {
			evidence.Reports[0].Treatment = "self-certified"
		}, "presented_evidence_report_mismatch"},
		{"review treatment", func(evidence *policyrelease.PreSigningEvidenceManifestV1) {
			evidence.ReviewReceipts[0].Treatment = "self-certified"
		}, "presented_evidence_treatment_mismatch"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			unsigned, err := observedPolicyRelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
			if err != nil {
				t.Fatal(err)
			}
			rebindUnsignedEvidence(t, &unsigned, testCase.mutate)
			envelope, signing := syntacticOnlySigning(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, "unverified-activation-workflow")
			_, err = observedPolicyRelease.FinalizeActivationArchive(unsigned, envelope, signing)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func TestActivationAndHandoffDeepCopyNestedCollections(t *testing.T) {
	unsigned, err := observedPolicyRelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	activationEnvelope, activationSigning := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	activation, err := observedPolicyRelease.FinalizeActivationArchive(unsigned, activationEnvelope, activationSigning)
	if err != nil {
		t.Fatal(err)
	}

	wantProfile := activation.Unsigned.Manifest.Profiles[0].ProfileID
	wantReport := activation.Unsigned.EvidenceManifest.Reports[0].Digest
	wantReceipt := activation.PresentedActivationSigning.Receipts[0].KeyIDHint
	wantSummary := activation.PresentedActivationSignatures.KeyIDHints[0]
	unsigned.Manifest.Profiles[0].ProfileID = "mutated"
	unsigned.EvidenceManifest.Reports[0].Digest = policyrelease.SHA256Digest([]byte("mutated"))
	activationSigning.Receipts[0].KeyIDHint = policyrelease.SHA256Digest([]byte("mutated"))
	if activation.Unsigned.Manifest.Profiles[0].ProfileID != wantProfile || activation.Unsigned.EvidenceManifest.Reports[0].Digest != wantReport || activation.PresentedActivationSigning.Receipts[0].KeyIDHint != wantReceipt || activation.PresentedActivationSignatures.KeyIDHints[0] != wantSummary {
		t.Fatal("activation aliases unsigned input, signing receipts, or summary slices")
	}

	attestation, err := observedPolicyRelease.PrepareReleaseAttestation(activation, policyrelease.ReleaseAttestationInput{
		ReleaseWorkflowIdentity: "release-workflow-v1",
		ReviewReceipts: []policyrelease.ReviewReceipt{{
			ReviewerID: "reviewer-a", Role: "independent-release", SubjectDigest: activation.ArchiveDigest,
			RecordDigest: policyrelease.SHA256Digest([]byte("review")), ClaimedDisposition: "accept",
		}},
		OfflineCheckReceipt: policyrelease.OfflineCheckReceipt{ClaimedOutcome: "pass", SubjectArchiveDigest: activation.ArchiveDigest, ReportDigest: policyrelease.SHA256Digest([]byte("offline"))},
	})
	if err != nil {
		t.Fatal(err)
	}
	releaseEnvelope, releaseSigning := externallySign(t, policyrelease.ReleaseAttestationPayloadType, attestation.PayloadBytes, 1, false)
	handoff, err := observedPolicyRelease.FinalizeReleaseHandoff(activation, attestation, releaseEnvelope, releaseSigning)
	if err != nil {
		t.Fatal(err)
	}

	wantArchiveByte := handoff.ArchiveBytes[0]
	wantReleaseEnvelopeByte := handoff.ReleaseAttestationEnvelopeBytes[0]
	wantActivationKey := handoff.PresentedActivationSignatures.KeyIDHints[0]
	wantReleaseReceipt := handoff.PresentedReleaseSigning.Receipts[0].KeyIDHint
	wantReleaseKey := handoff.PresentedReleaseSignatures.KeyIDHints[0]
	activation.ArchiveBytes[0] ^= 1
	activation.PresentedActivationSignatures.KeyIDHints[0] = "mutated"
	releaseEnvelope[0] ^= 1
	releaseSigning.Receipts[0].KeyIDHint = "mutated"
	if handoff.ArchiveBytes[0] != wantArchiveByte || handoff.ReleaseAttestationEnvelopeBytes[0] != wantReleaseEnvelopeByte || handoff.PresentedActivationSignatures.KeyIDHints[0] != wantActivationKey || handoff.PresentedReleaseSigning.Receipts[0].KeyIDHint != wantReleaseReceipt || handoff.PresentedReleaseSignatures.KeyIDHints[0] != wantReleaseKey {
		t.Fatal("handoff aliases activation, envelope, signing receipt, or summary collections")
	}

	handoff.ArchiveBytes[0] ^= 2
	handoff.PresentedReleaseSigning.Receipts[0].KeyIDHint = "handoff-mutated"
	if activation.ArchiveBytes[0] == handoff.ArchiveBytes[0] || releaseSigning.Receipts[0].KeyIDHint == handoff.PresentedReleaseSigning.Receipts[0].KeyIDHint {
		t.Fatal("handoff mutation propagated back to source collections")
	}
}
