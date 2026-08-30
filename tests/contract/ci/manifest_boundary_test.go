package ci_test

import (
	"testing"
	"time"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

// T-ADR-0006-ASSURANCE-POLICY: exercise every early manifest/deployment
// validation boundary so a malformed scalar cannot fall through to a later,
// less-specific check.
func TestManifestAndDeploymentInputBoundaries(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*policyrelease.BuildInput)
		code   string
	}{
		{"policy index path", func(input *policyrelease.BuildInput) { input.Manifest.PolicyContentIndexPath = "" }, "invalid_archive_path"},
		{"source revision", func(input *policyrelease.BuildInput) { input.Manifest.SourceRevision = "refs/heads/main" }, "nonimmutable_revision"},
		{"dependency lock digest", func(input *policyrelease.BuildInput) { input.Manifest.DependencyLockDigest = "sha256:00" }, "invalid_digest"},
		{"build recipe", func(input *policyrelease.BuildInput) { input.Manifest.BuildRecipeVersion = "" }, "invalid_identifier"},
		{"evaluator contract", func(input *policyrelease.BuildInput) { input.Manifest.EvaluatorContractVersion = "bad contract" }, "invalid_identifier"},
		{"non-UTC issue time", func(input *policyrelease.BuildInput) {
			input.Manifest.IssuedAt = input.Manifest.IssuedAt.In(time.FixedZone("fixture", -4*60*60))
		}, "invalid_activation_validity"},
		{"fractional expiry", func(input *policyrelease.BuildInput) {
			input.Manifest.ExpiresAt = input.Manifest.ExpiresAt.Add(time.Nanosecond)
		}, "invalid_activation_validity"},
		{"reversed validity", func(input *policyrelease.BuildInput) { input.Manifest.ExpiresAt = input.Manifest.IssuedAt }, "invalid_activation_validity"},
		{"trust-set ID", func(input *policyrelease.BuildInput) { input.Manifest.Trust.TrustSetID = "sha256:00" }, "invalid_digest"},
		{"trust envelope digest", func(input *policyrelease.BuildInput) { input.Manifest.Trust.TrustSetEnvelopeDigest = "sha256:00" }, "invalid_digest"},
		{"zero trust epoch", func(input *policyrelease.BuildInput) { input.Manifest.Trust.TrustEpoch = 0 }, "invalid_trust_epoch"},
		{"OpenFGA path", func(input *policyrelease.BuildInput) { input.Manifest.OpenFGAModel.SourcePath = "" }, "invalid_archive_path"},
		{"OpenFGA schema", func(input *policyrelease.BuildInput) { input.Manifest.OpenFGAModel.SchemaVersion = "1.0" }, "unsupported_openfga_schema"},
		{"OpenFGA digest", func(input *policyrelease.BuildInput) { input.Manifest.OpenFGAModel.SourceDigest = "sha256:00" }, "invalid_digest"},
		{"missing supported versions", func(input *policyrelease.BuildInput) { input.Manifest.SupportedSteadVersions = nil }, "missing_required_list"},
		{"duplicate context", func(input *policyrelease.BuildInput) {
			input.Manifest.RequiredContextIDs = []string{"trusted-principal", "trusted-principal"}
		}, "duplicate_value"},
		{"invalid predecessor", func(input *policyrelease.BuildInput) {
			input.Manifest.CompatiblePredecessorActivationSetIDs = []string{"sha256:00"}
		}, "invalid_digest"},
		{"missing rollback constraint", func(input *policyrelease.BuildInput) { input.Manifest.RollbackConstraints = nil }, "missing_required_list"},
		{"deployment policy ID", func(input *policyrelease.BuildInput) { input.Manifest.DeploymentPolicy.PolicyID = "bad id" }, "invalid_identifier"},
		{"deployment version", func(input *policyrelease.BuildInput) { input.Manifest.DeploymentPolicy.Version = "v1" }, "unsupported_version"},
		{"deployment schema", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.SchemaID = "https://example.invalid/schema"
		}, "unsupported_deployment_policy_schema"},
		{"deployment digest", func(input *policyrelease.BuildInput) { input.Manifest.DeploymentPolicy.Digest = "sha256:00" }, "invalid_digest"},
		{"disclosure mode", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.DisclosureRevocationMode = "eventual"
		}, "unsupported_disclosure_mode"},
		{"signature threshold", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.PolicySignatureThreshold = policyrelease.MaxEnvelopeSignatures + 1
		}, "invalid_signature_threshold"},
		{"recovery threshold", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.TrustRecoveryApprovalThreshold = 0
		}, "invalid_assurance_threshold"},
		{"crypto boundary", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.ApprovedCryptographicBoundary = "bad boundary"
		}, "invalid_identifier"},
		{"evidence profile", func(input *policyrelease.BuildInput) { input.Manifest.DeploymentPolicy.EvidenceProfile = "bad profile" }, "invalid_identifier"},
		{"assurance digest", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.PresentedAssuranceResultDigest = "sha256:00"
		}, "invalid_digest"},
		{"assurance path", func(input *policyrelease.BuildInput) {
			input.Manifest.DeploymentPolicy.PresentedAssuranceResultPath = ""
		}, "invalid_archive_path"},
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

func TestBindingAdmissionBoundaries(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*policyrelease.BuildInput)
		code   string
	}{
		{"role syntax", func(input *policyrelease.BuildInput) { input.Manifest.ContractBindings[0].Role = "bad role" }, "invalid_identifier"},
		{"binding path", func(input *policyrelease.BuildInput) { input.Manifest.ContractBindings[0].Path = "" }, "invalid_archive_path"},
		{"binding digest", func(input *policyrelease.BuildInput) { input.Manifest.ContractBindings[0].Digest = "sha256:00" }, "invalid_digest"},
		{"binding media", func(input *policyrelease.BuildInput) {
			input.Manifest.ContractBindings[0].MediaType = "application/x-unknown"
		}, "unknown_media_type"},
		{"duplicate content path", func(input *policyrelease.BuildInput) {
			input.Manifest.ContractBindings[0].Path = input.Manifest.PolicyContentIndexPath
		}, "duplicate_content_binding"},
		{"missing bound file", func(input *policyrelease.BuildInput) { input.PayloadFiles = input.PayloadFiles[1:] }, "missing_policy_content_index"},
		{"bound media mismatch", func(input *policyrelease.BuildInput) {
			input.Manifest.ContractBindings[0].MediaType = "text/plain; charset=utf-8"
		}, "bound_media_type_mismatch"},
		{"bound digest mismatch", func(input *policyrelease.BuildInput) {
			input.Manifest.ContractBindings[0].Digest = policyrelease.SHA256Digest([]byte("other"))
		}, "bound_digest_mismatch"},
		{"profile ID", func(input *policyrelease.BuildInput) { input.Manifest.Profiles[0].ProfileID = "bad id" }, "invalid_identifier"},
		{"profile version", func(input *policyrelease.BuildInput) { input.Manifest.Profiles[0].Version = "v1" }, "unsupported_version"},
		{"profile schema", func(input *policyrelease.BuildInput) {
			input.Manifest.Profiles[0].SchemaID = "https://example.invalid/schema"
		}, "unsupported_security_profile_schema"},
		{"profile path", func(input *policyrelease.BuildInput) { input.Manifest.Profiles[0].Path = "" }, "invalid_archive_path"},
		{"profile digest", func(input *policyrelease.BuildInput) { input.Manifest.Profiles[0].Digest = "sha256:00" }, "invalid_digest"},
		{"profile signing format", func(input *policyrelease.BuildInput) { input.Manifest.Profiles[0].SigningFormat = "future-format" }, "unsupported_profile_signing_format"},
		{"duplicate profile", func(input *policyrelease.BuildInput) {
			input.Manifest.Profiles = append(input.Manifest.Profiles, input.Manifest.Profiles[0])
		}, "duplicate_profile_binding"},
		{"profile collides with binding", func(input *policyrelease.BuildInput) {
			input.Manifest.Profiles[0].Path = input.Manifest.ContractBindings[0].Path
		}, "duplicate_content_binding"},
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

func TestPresentedReviewAndWaiverInputBoundaries(t *testing.T) {
	reviewCases := []struct {
		name   string
		mutate func(*policyrelease.ReviewReceipt)
		code   string
	}{
		{"reviewer ID", func(review *policyrelease.ReviewReceipt) { review.ReviewerID = "bad reviewer" }, "invalid_identifier"},
		{"review role", func(review *policyrelease.ReviewReceipt) { review.Role = "bad role" }, "invalid_identifier"},
		{"review subject digest", func(review *policyrelease.ReviewReceipt) { review.SubjectDigest = "sha256:00" }, "invalid_digest"},
		{"review subject mismatch", func(review *policyrelease.ReviewReceipt) {
			review.SubjectDigest = policyrelease.SHA256Digest([]byte("other"))
		}, "presented_review_subject_mismatch"},
		{"review record digest", func(review *policyrelease.ReviewReceipt) { review.RecordDigest = "sha256:00" }, "invalid_digest"},
		{"review disposition", func(review *policyrelease.ReviewReceipt) { review.ClaimedDisposition = "unknown" }, "invalid_claimed_review_disposition"},
	}
	for _, testCase := range reviewCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			testCase.mutate(&input.Evidence.ReviewReceipts[0])
			_, err := policyrelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}

	waiverCases := []struct {
		name   string
		mutate func(*policyrelease.WaiverReceipt)
		code   string
	}{
		{"waiver ID", func(waiver *policyrelease.WaiverReceipt) { waiver.WaiverID = "bad waiver" }, "invalid_identifier"},
		{"waiver subject digest", func(waiver *policyrelease.WaiverReceipt) { waiver.SubjectDigest = "sha256:00" }, "invalid_digest"},
		{"waiver subject mismatch", func(waiver *policyrelease.WaiverReceipt) {
			waiver.SubjectDigest = policyrelease.SHA256Digest([]byte("other"))
		}, "presented_waiver_subject_mismatch"},
		{"waiver record digest", func(waiver *policyrelease.WaiverReceipt) { waiver.RecordDigest = "sha256:00" }, "invalid_digest"},
		{"waiver disposition", func(waiver *policyrelease.WaiverReceipt) { waiver.ClaimedDisposition = "unknown" }, "invalid_claimed_waiver_disposition"},
	}
	for _, testCase := range waiverCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := fixtureBuildInput(t, "commercial", 1, false)
			input.Evidence.WaiverReceipts = []policyrelease.WaiverReceipt{{
				WaiverID: "fixture-waiver", SubjectDigest: input.Evidence.ReviewReceipts[0].SubjectDigest,
				RecordDigest: policyrelease.SHA256Digest([]byte("fixture-waiver-record")), ClaimedDisposition: "approved",
			}}
			testCase.mutate(&input.Evidence.WaiverReceipts[0])
			_, err := policyrelease.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}

	t.Run("multiple independent records are canonicalized", func(t *testing.T) {
		input := fixtureBuildInput(t, "commercial", 1, false)
		subject := input.Evidence.ReviewReceipts[0].SubjectDigest
		input.Evidence.ReviewReceipts = append(input.Evidence.ReviewReceipts, policyrelease.ReviewReceipt{
			ReviewerID: "fixture-second-reviewer", Role: "independent-qa", SubjectDigest: subject,
			RecordDigest: policyrelease.SHA256Digest([]byte("second-review")), ClaimedDisposition: "accept",
		})
		input.Evidence.WaiverReceipts = []policyrelease.WaiverReceipt{
			{WaiverID: "fixture-waiver-b", SubjectDigest: subject, RecordDigest: policyrelease.SHA256Digest([]byte("waiver-b")), ClaimedDisposition: "approved"},
			{WaiverID: "fixture-waiver-a", SubjectDigest: subject, RecordDigest: policyrelease.SHA256Digest([]byte("waiver-a")), ClaimedDisposition: "approved"},
		}
		if _, err := policyrelease.PrepareUnsigned(input); err != nil {
			t.Fatalf("valid multiple review/waiver records rejected: %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})
}
