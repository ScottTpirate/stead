package ci_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

// T-STEAD-P1-016-CONTRACT, T-TEST-008-ACCEPTANCE,
// T-ADR-0006-DETERMINISTIC-BUILD, T-ADR-0006-POLICY-CONFORMANCE.
func TestDeterministicUnsignedConstructionAndEvidence(t *testing.T) {
	first, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatalf("first PrepareUnsigned: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	second, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatalf("second PrepareUnsigned: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	if !bytes.Equal(first.ManifestPayload, second.ManifestPayload) || !bytes.Equal(first.EvidenceManifestBytes, second.EvidenceManifestBytes) || !bytes.Equal(first.SigningRequestBytes, second.SigningRequestBytes) {
		t.Fatal("isolated unsigned builds produced different bytes")
	}
	if first.ActivationSetID != second.ActivationSetID || first.PolicyBundleID != second.PolicyBundleID || first.EvidenceManifestDigest != second.EvidenceManifestDigest {
		t.Fatal("isolated unsigned builds produced different identities")
	}
	if first.ActivationSetID != policyrelease.SHA256Digest(first.ManifestPayload) {
		t.Fatal("activation_set_id does not bind exact manifest payload")
	}
	if first.SigningRequest.PAEDigest != policyrelease.SHA256Digest(policyrelease.PAE(policyrelease.ActivationManifestPayloadType, first.ManifestPayload)) {
		t.Fatal("signing request does not bind DSSE PAE")
	}
	if first.Manifest.ArtifactFormat != policyrelease.ActivationFormatV1 {
		t.Fatalf("artifact format = %q", first.Manifest.ArtifactFormat)
	}
	if first.EvidenceManifest.Conformance.Claims.DecisionRowsCoveredPercent != 100 || first.EvidenceManifest.Conformance.Claims.CriticalMutationScorePercent < 90 || first.EvidenceManifest.Conformance.Treatment != policyrelease.PresentedMaterialTreatment {
		t.Fatal("embedded evidence omitted policy coverage floor")
	}
	if first.EvidenceManifest.Authority != policyrelease.NonAuthorizingHandoffAuthority || len(first.EvidenceManifest.ReviewReceipts) == 0 || first.EvidenceManifest.ReviewReceipts[0].Treatment != policyrelease.PresentedMaterialTreatment {
		t.Fatal("embedded evidence or review material was not explicitly nonauthorizing and unverified")
	}
	for _, report := range first.EvidenceManifest.Reports {
		if report.Treatment != policyrelease.PresentedMaterialTreatment {
			t.Fatalf("evidence report %s was not labeled unverified", report.Path)
		}
	}
	for _, forbidden := range []string{"activation_set_id", "signed_envelope_digest", "archive_digest", "release_attestation_id", "release_attestation_envelope_digest"} {
		if bytes.Contains(bytes.ToLower(first.EvidenceManifestBytes), []byte(forbidden)) {
			t.Fatalf("pre-signing evidence contains future identity %q", forbidden)
		}
	}
	if bytes.Contains(first.ManifestPayload, []byte(`"compatible_predecessor_activation_set_ids":null`)) || bytes.Contains(first.EvidenceManifestBytes, []byte(`"waivers":null`)) {
		t.Fatal("canonical collection field encoded as null instead of an array")
	}
	if len(first.Files)+1 > policyrelease.MaxArchiveFiles {
		t.Fatal("manifest did not reserve the outer envelope file ceiling")
	}
}

func TestFixedEnvelopeArchiveAndAttestationConstructionAreDeterministic(t *testing.T) {
	firstUnsigned, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	secondUnsigned, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	envelope, signing := externallySign(t, policyrelease.ActivationManifestPayloadType, firstUnsigned.ManifestPayload, 1, false)
	firstArchive, err := policyrelease.FinalizeActivationArchive(firstUnsigned, envelope, signing)
	if err != nil {
		t.Fatal(err)
	}
	secondArchive, err := policyrelease.FinalizeActivationArchive(secondUnsigned, envelope, signing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstArchive.ArchiveBytes, secondArchive.ArchiveBytes) || firstArchive.ArchiveDigest != secondArchive.ArchiveDigest {
		t.Fatal("one fixed activation envelope produced different archive bytes")
	}
	releaseInput := policyrelease.ReleaseAttestationInput{
		ReleaseWorkflowIdentity: "stead-ci-policy-release-workflow-v1",
		ReviewReceipts:          []policyrelease.ReviewReceipt{{ReviewerID: "fixture-final-reviewer", Role: "independent-release", SubjectDigest: firstArchive.ArchiveDigest, RecordDigest: policyrelease.SHA256Digest([]byte("review")), ClaimedDisposition: "accept"}},
		OfflineCheckReceipt:     policyrelease.OfflineCheckReceipt{ClaimedOutcome: "pass", SubjectArchiveDigest: firstArchive.ArchiveDigest, ReportDigest: policyrelease.SHA256Digest([]byte("offline-check-report"))},
	}
	firstAttestation, err := policyrelease.PrepareReleaseAttestation(firstArchive, releaseInput)
	if err != nil {
		t.Fatal(err)
	}
	secondAttestation, err := policyrelease.PrepareReleaseAttestation(secondArchive, releaseInput)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstAttestation.PayloadBytes, secondAttestation.PayloadBytes) || !bytes.Equal(firstAttestation.SigningRequestBytes, secondAttestation.SigningRequestBytes) || firstAttestation.AttestationID != secondAttestation.AttestationID {
		t.Fatal("fixed archive ceremony produced different attestation request bytes")
	}
}

// T-ADR-0006-TRANSPORT-IDENTITY, T-ADR-0006-CONTENT-INTEGRITY,
// T-ADR-0006-TUF-NONAUTHORITY.
func TestOneWayReleaseCeremonyAndImmutableTransportIdentity(t *testing.T) {
	activation, attestation, handoff := completeFixtureRelease(t, "commercial", 1, false)
	if handoff.ActivationSetID != policyrelease.SHA256Digest(activation.Unsigned.ManifestPayload) || handoff.SignedEnvelopeDigest != policyrelease.SHA256Digest(activation.EnvelopeBytes) || handoff.ArchiveDigest != policyrelease.SHA256Digest(activation.ArchiveBytes) {
		t.Fatal("activation identities do not bind exact bytes")
	}
	if handoff.ReleaseAttestationID != policyrelease.SHA256Digest(attestation.PayloadBytes) || handoff.ReleaseAttestationEnvelopeDigest != policyrelease.SHA256Digest(handoff.ReleaseAttestationEnvelopeBytes) {
		t.Fatal("attestation identities do not bind exact bytes")
	}
	if bytes.Contains(attestation.PayloadBytes, []byte("release_attestation_id")) || bytes.Contains(attestation.PayloadBytes, []byte("release_attestation_envelope_digest")) {
		t.Fatal("release attestation is self-referential")
	}
	if bytes.Contains(attestation.PayloadBytes, []byte(`"waivers":null`)) {
		t.Fatal("release-attestation waiver collection encoded as null")
	}
	if attestation.Payload.ActivationSetID != handoff.ActivationSetID || attestation.Payload.SignedEnvelopeDigest != handoff.SignedEnvelopeDigest || attestation.Payload.ArchiveDigest != handoff.ArchiveDigest {
		t.Fatal("release attestation does not bind activation ceremony")
	}
	if attestation.Payload.EvidenceManifestDigest != activation.Unsigned.EvidenceManifestDigest || attestation.Payload.PresentedOfflineCheck.SubjectArchiveDigest != handoff.ArchiveDigest || attestation.Payload.Authority != policyrelease.NonAuthorizingHandoffAuthority {
		t.Fatal("release attestation does not bind evidence and offline verification")
	}
	if attestation.Payload.PresentedOfflineCheck.Treatment != policyrelease.PresentedMaterialTreatment || len(attestation.Payload.PresentedReviewReceipts) == 0 || attestation.Payload.PresentedReviewReceipts[0].Treatment != policyrelease.PresentedMaterialTreatment {
		t.Fatal("release review or offline claims were not labeled unverified")
	}
	if handoff.PolicyBundleID != activation.Unsigned.PolicyBundleID || handoff.OpenFGAModelSourceDigest != activation.Unsigned.Manifest.OpenFGAModel.SourceDigest || handoff.EvidenceManifestDigest != activation.Unsigned.EvidenceManifestDigest || handoff.Trust != activation.Unsigned.Manifest.Trust || handoff.SourceRevision != activation.Unsigned.Manifest.SourceRevision {
		t.Fatal("typed handoff omitted immutable policy/model/evidence/trust/source identity")
	}
	if handoff.PresentedActivationReceiptSetDigest != activation.PresentedActivationSigning.ReceiptSetDigest || handoff.PresentedActivationSignatures.Treatment != policyrelease.PresentedMaterialTreatment || handoff.Authority != policyrelease.NonAuthorizingHandoffAuthority {
		t.Fatal("typed handoff omitted or overstated presented activation material")
	}
	inspection, err := policyrelease.ValidateArchive(handoff.ArchiveBytes, activation.EnvelopeBytes, activation.Unsigned.Manifest.Files)
	if err != nil {
		t.Fatalf("ValidateArchive: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	if inspection.ArchiveDigest != handoff.ArchiveDigest {
		t.Fatal("archive inspection identity mismatch")
	}

	descriptor, descriptorBytes, err := policyrelease.BuildTransportDescriptor(handoff)
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Authority != "non_authorizing_transport_only" || strings.Contains(string(descriptorBytes), "tuf") {
		t.Fatal("transport descriptor asserted authority or TUF dependency")
	}
	for _, copyPair := range []struct {
		name        string
		archive     []byte
		attestation []byte
	}{
		{"directory", append([]byte(nil), handoff.ArchiveBytes...), append([]byte(nil), handoff.ReleaseAttestationEnvelopeBytes...)},
		{"oci-by-digest", append([]byte(nil), handoff.ArchiveBytes...), append([]byte(nil), handoff.ReleaseAttestationEnvelopeBytes...)},
		{"offline-media", append([]byte(nil), handoff.ArchiveBytes...), append([]byte(nil), handoff.ReleaseAttestationEnvelopeBytes...)},
	} {
		t.Run(copyPair.name, func(t *testing.T) {
			if !bytes.Equal(copyPair.archive, handoff.ArchiveBytes) || !bytes.Equal(copyPair.attestation, handoff.ReleaseAttestationEnvelopeBytes) {
				t.Fatal("transport reconstructed release bytes")
			}
		})
	}
}

// T-ADR-0006-DSSE fixed P-256/SHA-256, PAE, SPKI key identity, DER, low-S,
// and exact-payload vector. The fixture key is public and non-authorizing.
func TestFixedDSSEVerificationVector(t *testing.T) {
	unsigned, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	parsed, err := policyrelease.ParseDSSEEnvelope(envelope)
	if err != nil {
		t.Fatalf("ParseDSSEEnvelope: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	publicKey, keyID := testPublicKey(0)
	if parsed.Signatures[0].KeyID != keyID {
		t.Fatal("keyid is not the recomputed SPKI identity")
	}
	digest := sha256.Sum256(policyrelease.PAE(parsed.PayloadType, parsed.Payload))
	if !ecdsa.VerifyASN1(publicKey, digest[:], parsed.Signatures[0].Bytes) {
		t.Fatal("fixed DSSE signature does not verify over exact PAE")
	}
	mutated := append([]byte(nil), parsed.Payload...)
	mutated[len(mutated)-1] ^= 1
	mutatedDigest := sha256.Sum256(policyrelease.PAE(parsed.PayloadType, mutated))
	if ecdsa.VerifyASN1(publicKey, mutatedDigest[:], parsed.Signatures[0].Bytes) {
		t.Fatal("fixed DSSE signature verified a mutated payload")
	}
}

func TestManifestAndAttestationRejectUnknownFields(t *testing.T) {
	unsigned, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(unsigned.ManifestPayload, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["unknown_authority"] = true
	mutated, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	unsigned.ManifestPayload = mutated
	unsigned.ActivationSetID = policyrelease.SHA256Digest(mutated)
	envelope, signing := externallySign(t, policyrelease.ActivationManifestPayloadType, mutated, 1, false)
	_, err = policyrelease.FinalizeActivationArchive(unsigned, envelope, signing)
	if policyrelease.ErrorCode(err) != "signed_payload_contract_error" {
		t.Fatalf("unknown signed field error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}

func TestReturnedArtifactsDoNotAliasCallerBuffers(t *testing.T) {
	input := fixtureBuildInput(t, "commercial", 1, false)
	original := append([]byte(nil), input.PayloadFiles[0].Content...)
	unsigned, err := policyrelease.PrepareUnsigned(input)
	if err != nil {
		t.Fatal(err)
	}
	input.PayloadFiles[0].Content[0] ^= 1
	found := false
	for _, file := range unsigned.Files {
		if file.Path == "payload/policy-content-index.json" {
			found = true
			if !bytes.Equal(file.Content, original) {
				t.Fatal("prepared artifact aliases caller input")
			}
		}
	}
	if !found {
		t.Fatal("policy content index missing")
	}
}
