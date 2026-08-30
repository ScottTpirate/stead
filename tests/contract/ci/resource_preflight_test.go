package ci_test

import (
	"fmt"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func boundedReviews(count int, subject, prefix string) []policyrelease.ReviewReceipt {
	reviews := make([]policyrelease.ReviewReceipt, count)
	for index := range reviews {
		reviews[index] = policyrelease.ReviewReceipt{
			ReviewerID:         fmt.Sprintf("%s-reviewer-%03d", prefix, index),
			Role:               "independent-review",
			SubjectDigest:      subject,
			RecordDigest:       policyrelease.SHA256Digest([]byte(fmt.Sprintf("%s-review-%03d", prefix, index))),
			ClaimedDisposition: "accept",
		}
	}
	return reviews
}

func boundedWaivers(count int, subject, prefix string) []policyrelease.WaiverReceipt {
	waivers := make([]policyrelease.WaiverReceipt, count)
	for index := range waivers {
		waivers[index] = policyrelease.WaiverReceipt{
			WaiverID:           fmt.Sprintf("%s-waiver-%03d", prefix, index),
			SubjectDigest:      subject,
			RecordDigest:       policyrelease.SHA256Digest([]byte(fmt.Sprintf("%s-waiver-record-%03d", prefix, index))),
			ClaimedDisposition: "approved",
		}
	}
	return waivers
}

func fixtureActivation(t testing.TB) policyrelease.ActivationArchive {
	t.Helper()
	unsigned, err := policyrelease.PrepareUnsigned(fixtureBuildInput(t, "commercial", 1, false))
	if err != nil {
		t.Fatal(err)
	}
	envelope, signing := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	activation, err := policyrelease.FinalizeActivationArchive(unsigned, envelope, signing)
	if err != nil {
		t.Fatal(err)
	}
	return activation
}

func TestBuildReceiptCardinalityIsPreflighted(t *testing.T) {
	t.Run("exact review ceiling", func(t *testing.T) {
		input := fixtureBuildInput(t, "commercial", 1, false)
		input.Evidence.ReviewReceipts = boundedReviews(policyrelease.MaxReviewReceipts, input.Evidence.ReviewReceipts[0].SubjectDigest, "build")
		if _, err := policyrelease.PrepareUnsigned(input); err != nil {
			t.Fatalf("exact review ceiling rejected: %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("one over review ceiling", func(t *testing.T) {
		input := fixtureBuildInput(t, "commercial", 1, false)
		input.Evidence.ReviewReceipts = make([]policyrelease.ReviewReceipt, policyrelease.MaxReviewReceipts+1)
		result, err := policyrelease.PrepareUnsigned(input)
		if policyrelease.ErrorCode(err) != "review_receipt_count_limit" || result.ManifestPayload != nil || result.SigningRequestBytes != nil {
			t.Fatalf("one-over review preflight = %v (%s), request bytes=%d", err, policyrelease.ErrorCode(err), len(result.SigningRequestBytes))
		}
	})

	t.Run("exact waiver ceiling", func(t *testing.T) {
		input := fixtureBuildInput(t, "commercial", 1, false)
		input.Evidence.WaiverReceipts = boundedWaivers(policyrelease.MaxWaiverReceipts, input.Evidence.ReviewReceipts[0].SubjectDigest, "build")
		if _, err := policyrelease.PrepareUnsigned(input); err != nil {
			t.Fatalf("exact waiver ceiling rejected: %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("one over waiver ceiling", func(t *testing.T) {
		input := fixtureBuildInput(t, "commercial", 1, false)
		input.Evidence.WaiverReceipts = make([]policyrelease.WaiverReceipt, policyrelease.MaxWaiverReceipts+1)
		result, err := policyrelease.PrepareUnsigned(input)
		if policyrelease.ErrorCode(err) != "waiver_receipt_count_limit" || result.ManifestPayload != nil || result.SigningRequestBytes != nil {
			t.Fatalf("one-over waiver preflight = %v (%s), request bytes=%d", err, policyrelease.ErrorCode(err), len(result.SigningRequestBytes))
		}
	})
}

func TestManifestCollectionsArePreflightedBeforeCopy(t *testing.T) {
	input := fixtureBuildInput(t, "commercial", 1, false)
	input.Manifest.RequiredContextIDs = make([]string, policyrelease.MaxMetadataEntries+1)
	result, err := policyrelease.PrepareUnsigned(input)
	if policyrelease.ErrorCode(err) != "metadata_cardinality_limit" || result.ManifestPayload != nil || result.SigningRequestBytes != nil {
		t.Fatalf("manifest preflight = %v (%s), request bytes=%d", err, policyrelease.ErrorCode(err), len(result.SigningRequestBytes))
	}
}

func TestPresentedSigningReceiptCardinalityIsPreflighted(t *testing.T) {
	receipts := make([]policyrelease.PresentedSignatureReceipt, policyrelease.MaxEnvelopeSignatures)
	for index := range receipts {
		receipts[index] = policyrelease.PresentedSignatureReceipt{
			KeyIDHint:          policyrelease.SHA256Digest([]byte(fmt.Sprintf("key-%02d", index))),
			ClaimedCustodianID: fmt.Sprintf("custodian-%02d", index),
			ClaimedKeyPurpose:  policyrelease.ReleaseKeyPurpose,
			SignatureDigest:    policyrelease.SHA256Digest([]byte(fmt.Sprintf("signature-%02d", index))),
		}
	}
	if _, err := policyrelease.NewPresentedSigningResult("fixture-signing-workflow", receipts); err != nil {
		t.Fatalf("exact receipt ceiling rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	receipts = append(receipts, policyrelease.PresentedSignatureReceipt{})
	result, err := policyrelease.NewPresentedSigningResult("fixture-signing-workflow", receipts)
	if policyrelease.ErrorCode(err) != "signing_receipt_count_limit" || result.Receipts != nil {
		t.Fatalf("one-over signing receipt preflight = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}

func TestReleaseAttestationReceiptCardinalityRejectsBeforeSigningRequest(t *testing.T) {
	activation := fixtureActivation(t)
	base := policyrelease.ReleaseAttestationInput{
		ReleaseWorkflowIdentity: "stead-ci-policy-release-workflow-v1",
		OfflineCheckReceipt: policyrelease.OfflineCheckReceipt{
			ClaimedOutcome:       "pass",
			SubjectArchiveDigest: activation.ArchiveDigest,
			ReportDigest:         policyrelease.SHA256Digest([]byte("offline-check-report")),
		},
	}

	t.Run("exact ceilings remain constructible", func(t *testing.T) {
		input := base
		input.ReviewReceipts = boundedReviews(policyrelease.MaxReviewReceipts, activation.ArchiveDigest, "release")
		input.WaiverReceipts = boundedWaivers(policyrelease.MaxWaiverReceipts, activation.ArchiveDigest, "release")
		result, err := policyrelease.PrepareReleaseAttestation(activation, input)
		if err != nil || len(result.PayloadBytes) > policyrelease.MaxDecodedPayloadBytes || len(result.SigningRequestBytes) == 0 {
			t.Fatalf("exact release ceilings: payload=%d request=%d err=%v (%s)", len(result.PayloadBytes), len(result.SigningRequestBytes), err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("one over reviews emits no request", func(t *testing.T) {
		input := base
		input.ReviewReceipts = make([]policyrelease.ReviewReceipt, policyrelease.MaxReviewReceipts+1)
		result, err := policyrelease.PrepareReleaseAttestation(activation, input)
		if policyrelease.ErrorCode(err) != "review_receipt_count_limit" || result.PayloadBytes != nil || result.SigningRequestBytes != nil {
			t.Fatalf("one-over release reviews = %v (%s), payload=%d request=%d", err, policyrelease.ErrorCode(err), len(result.PayloadBytes), len(result.SigningRequestBytes))
		}
	})

	t.Run("one over waivers emits no request", func(t *testing.T) {
		input := base
		input.ReviewReceipts = boundedReviews(1, activation.ArchiveDigest, "release")
		input.WaiverReceipts = make([]policyrelease.WaiverReceipt, policyrelease.MaxWaiverReceipts+1)
		result, err := policyrelease.PrepareReleaseAttestation(activation, input)
		if policyrelease.ErrorCode(err) != "waiver_receipt_count_limit" || result.PayloadBytes != nil || result.SigningRequestBytes != nil {
			t.Fatalf("one-over release waivers = %v (%s), payload=%d request=%d", err, policyrelease.ErrorCode(err), len(result.PayloadBytes), len(result.SigningRequestBytes))
		}
	})
}

func TestArchiveManifestAndTransportCollectionsArePreflighted(t *testing.T) {
	t.Run("archive manifest one over", func(t *testing.T) {
		files := make([]policyrelease.ManifestFile, policyrelease.MaxArchiveFiles)
		_, err := policyrelease.ValidateArchive([]byte("not-inspected"), nil, files)
		if policyrelease.ErrorCode(err) != "archive_content_limit" {
			t.Fatalf("manifest one-over preflight = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("archive manifest exact reaches field validation", func(t *testing.T) {
		files := make([]policyrelease.ManifestFile, policyrelease.MaxArchiveFiles-1)
		_, err := policyrelease.ValidateArchive([]byte("not-inspected"), nil, files)
		if policyrelease.ErrorCode(err) != "invalid_archive_path" {
			t.Fatalf("manifest exact ceiling = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("transport envelope one over", func(t *testing.T) {
		handoff := policyrelease.ImmutableReleaseHandoff{
			ArchiveBytes:                    []byte("archive"),
			ReleaseAttestationEnvelopeBytes: make([]byte, policyrelease.MaxEnvelopeBytes+1),
		}
		descriptor, encoded, err := policyrelease.BuildTransportDescriptor(handoff)
		if policyrelease.ErrorCode(err) != "transport_artifact_size_limit" || encoded != nil || descriptor.ArchiveDigest != "" {
			t.Fatalf("transport preflight = %v (%s), bytes=%d", err, policyrelease.ErrorCode(err), len(encoded))
		}
	})
}
