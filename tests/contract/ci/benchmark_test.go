package ci_test

import (
	"bytes"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func benchmarkEmptyObjectArray(count int) []byte {
	if count == 0 {
		return nil
	}
	items := bytes.Repeat([]byte(`{},`), count)
	return items[:len(items)-1]
}

func benchmarkOversizedSignatureEnvelope() []byte {
	result := []byte(`{"payloadType":"application/vnd.stead.policy-activation-manifest.v1+json","payload":"eA==","signatures":[`)
	result = append(result, benchmarkEmptyObjectArray(1<<16)...)
	return append(result, ']', '}')
}

func BenchmarkPrepareUnsigned(b *testing.B) {
	input := fixtureBuildInput(b, "commercial", 1, false)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := observedPolicyRelease.PrepareUnsigned(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkObservedPrepareUnsigned(b *testing.B) {
	input := fixtureBuildInput(b, "commercial", 1, false)
	workflow, err := policyrelease.NewObservedWorkflow(lifecycleContext("benchmark"), policyrelease.LifecycleObserverFunc(func(event policyrelease.LifecycleEvent) (policyrelease.LifecycleAcknowledgement, error) {
		return policyrelease.AcknowledgeLifecycleEvent(event), nil
	}))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := workflow.PrepareUnsigned(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFinalizeActivationArchive(b *testing.B) {
	unsigned, err := observedPolicyRelease.PrepareUnsigned(fixtureBuildInput(b, "commercial", 1, false))
	if err != nil {
		b.Fatal(err)
	}
	envelope, signing := externallySign(b, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := observedPolicyRelease.FinalizeActivationArchive(unsigned, envelope, signing); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseDSSEEnvelope(b *testing.B) {
	envelope, _ := externallySign(b, policyrelease.ActivationManifestPayloadType, []byte("x"), 1, false)
	b.SetBytes(int64(len(envelope)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := policyrelease.ParseDSSEEnvelope(envelope); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRejectOversizedDSSESignatureArray(b *testing.B) {
	envelope := benchmarkOversizedSignatureEnvelope()
	b.SetBytes(int64(len(envelope)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := policyrelease.ParseDSSEEnvelope(envelope); policyrelease.ErrorCode(err) != "signature_count_limit" {
			b.Fatalf("unexpected error: %v (%s)", err, policyrelease.ErrorCode(err))
		}
	}
}

func BenchmarkInspectArchive(b *testing.B) {
	activation, _, _ := completeFixtureRelease(b, "commercial", 1, false)
	b.SetBytes(int64(len(activation.ArchiveBytes)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := observedPolicyRelease.InspectArchive(activation.ArchiveBytes); err != nil {
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
		if _, err := observedPolicyRelease.PrepareReleaseAttestation(activation, input); err != nil {
			b.Fatal(err)
		}
	}
}
