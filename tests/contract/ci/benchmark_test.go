package ci_test

import (
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func BenchmarkPrepareUnsigned(b *testing.B) {
	input := fixtureBuildInput(b, "commercial", 1, false)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := policyrelease.PrepareUnsigned(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFinalizeActivationArchive(b *testing.B) {
	unsigned, err := policyrelease.PrepareUnsigned(fixtureBuildInput(b, "commercial", 1, false))
	if err != nil {
		b.Fatal(err)
	}
	envelope, signing := externallySign(b, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := policyrelease.FinalizeActivationArchive(unsigned, envelope, signing); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInspectArchive(b *testing.B) {
	activation, _, _ := completeFixtureRelease(b, "commercial", 1, false)
	b.SetBytes(int64(len(activation.ArchiveBytes)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := policyrelease.InspectArchive(activation.ArchiveBytes); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrepareReleaseAttestation(b *testing.B) {
	activation, _, _ := completeFixtureRelease(b, "commercial", 1, false)
	input := policyrelease.ReleaseAttestationInput{
		ReleaseWorkflowIdentity: "release-workflow-v1",
		ReviewReceipts:          []policyrelease.ReviewReceipt{{ReviewerID: "reviewer-a", Role: "independent-release", SubjectDigest: activation.ArchiveDigest, RecordDigest: policyrelease.SHA256Digest([]byte("review")), ClaimedDisposition: "accept"}},
		OfflineCheckReceipt:     policyrelease.OfflineCheckReceipt{ClaimedOutcome: "pass", SubjectArchiveDigest: activation.ArchiveDigest, ReportDigest: policyrelease.SHA256Digest([]byte("offline"))},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := policyrelease.PrepareReleaseAttestation(activation, input); err != nil {
			b.Fatal(err)
		}
	}
}
