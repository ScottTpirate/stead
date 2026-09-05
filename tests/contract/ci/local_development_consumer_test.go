package ci_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func localPresentedEvidence(t *testing.T) (policyrelease.BuildInput, policyrelease.LocalDevelopmentEvidenceV1, []byte) {
	t.Helper()
	input := fixtureBuildInput(t, "commercial", 1, false)
	substitutions := []byte(`{"unit_test_only":true}`)
	evidence := policyrelease.LocalDevelopmentEvidenceV1{SchemaVersion: "1.0.0", Kind: "local-development-derivation", TemplateDigest: policyrelease.SHA256Digest([]byte("unit-template")), SubstitutionsDigest: policyrelease.SHA256Digest(substitutions), SourceRevision: input.Manifest.SourceRevision, SourceTree: strings.Repeat("a", 40), DependencyLockDigest: input.Manifest.DependencyLockDigest, InstallerIdentity: "unit-installer", Reports: []policyrelease.LocalDevelopmentCheckEvidence{{CheckID: "policy-conformance"}, {CheckID: "critical-mutations"}, {CheckID: "dependency-review"}}}
	return input, evidence, substitutions
}

func TestLocalDevelopmentArchiveSharesSchemasAndNeverProductionReviews(t *testing.T) {
	input, evidence, substitutions := localPresentedEvidence(t)
	workflow, err := newTestObservedWorkflow()
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := workflow.PrepareLocalDevelopment(input.Manifest, input.PayloadFiles, evidence, substitutions)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	archive, err := workflow.FinalizeLocalDevelopment(unsigned, envelope)
	if err != nil {
		t.Fatal(err)
	}
	got, gotEnvelope, err := workflow.ValidateLocalDevelopmentArchive(archive)
	if err != nil || got.ActivationSetID != unsigned.ActivationSetID || !bytes.Equal(gotEnvelope, envelope) {
		t.Fatal("local archive round trip failed")
	}
	if _, _, err := workflow.ValidateActivationArchive(archive); err == nil {
		t.Fatal("local presented evidence became production review authority")
	}
	if _, err := workflow.PrepareReleaseAttestation(policyrelease.ActivationArchive{Unsigned: unsigned, EnvelopeBytes: envelope, ArchiveBytes: archive}, policyrelease.ReleaseAttestationInput{}); err == nil {
		t.Fatal("local archive reached production release")
	}
	localEnvelope, _ := externallySign(t, policyrelease.LocalDevelopmentDerivationPayloadType, []byte(`{"unit_test_only":true}`), 1, false)
	if _, err := policyrelease.ParseLocalDevelopmentEnvelope(localEnvelope); err != nil {
		t.Fatal(err)
	}
	if _, err := policyrelease.ParseDSSEEnvelope(localEnvelope); err == nil {
		t.Fatal("production DSSE accepted local type")
	}
	if _, err := policyrelease.ParseLocalDevelopmentEnvelope(envelope); err == nil {
		t.Fatal("local attestation parser accepted activation cross-type")
	}
	if _, err := workflow.FinalizeLocalDevelopment(unsigned, localEnvelope); err == nil {
		t.Fatal("cross-type activation signature")
	}
	corrupt := append([]byte{}, archive...)
	corrupt[0] ^= 1
	if _, _, err := workflow.ValidateLocalDevelopmentArchive(corrupt); err == nil {
		t.Fatal("corrupt raw USTAR accepted")
	}
}

func TestLocalDevelopmentEvidenceFailsClosedAtSharedBuilder(t *testing.T) {
	for name, mutate := range map[string]func(*policyrelease.BuildInput, *policyrelease.LocalDevelopmentEvidenceV1, *[]byte){
		"kind": func(_ *policyrelease.BuildInput, e *policyrelease.LocalDevelopmentEvidenceV1, _ *[]byte) {
			e.Kind = "release"
		},
		"source": func(_ *policyrelease.BuildInput, e *policyrelease.LocalDevelopmentEvidenceV1, _ *[]byte) {
			e.SourceRevision = strings.Repeat("c", 40)
		},
		"tree": func(_ *policyrelease.BuildInput, e *policyrelease.LocalDevelopmentEvidenceV1, _ *[]byte) {
			e.SourceTree = "main"
		},
		"digest": func(_ *policyrelease.BuildInput, e *policyrelease.LocalDevelopmentEvidenceV1, _ *[]byte) {
			e.TemplateDigest = "floating"
		},
		"installer": func(_ *policyrelease.BuildInput, e *policyrelease.LocalDevelopmentEvidenceV1, _ *[]byte) {
			e.InstallerIdentity = "bad identity"
		},
		"reports": func(_ *policyrelease.BuildInput, e *policyrelease.LocalDevelopmentEvidenceV1, _ *[]byte) {
			e.Reports = nil
		},
		"substitutions": func(_ *policyrelease.BuildInput, _ *policyrelease.LocalDevelopmentEvidenceV1, s *[]byte) {
			*s = []byte("changed")
		},
		"profile": func(i *policyrelease.BuildInput, _ *policyrelease.LocalDevelopmentEvidenceV1, _ *[]byte) {
			i.Manifest.Profiles[0].Digest = policyrelease.SHA256Digest([]byte("wrong"))
		},
		"duplicate-payload": func(i *policyrelease.BuildInput, _ *policyrelease.LocalDevelopmentEvidenceV1, _ *[]byte) {
			i.PayloadFiles = append(i.PayloadFiles, i.PayloadFiles[0])
		},
		"unsafe-path": func(i *policyrelease.BuildInput, _ *policyrelease.LocalDevelopmentEvidenceV1, _ *[]byte) {
			i.PayloadFiles[0].Path = "../outside"
		},
		"unbound-payload": func(i *policyrelease.BuildInput, _ *policyrelease.LocalDevelopmentEvidenceV1, _ *[]byte) {
			i.PayloadFiles = append(i.PayloadFiles, policyrelease.File{Path: "payload/unbound.json", MediaType: "application/json", Content: []byte(`{}`)})
		},
	} {
		t.Run(name, func(t *testing.T) {
			input, evidence, substitutions := localPresentedEvidence(t)
			mutate(&input, &evidence, &substitutions)
			workflow, err := newTestObservedWorkflow()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := workflow.PrepareLocalDevelopment(input.Manifest, input.PayloadFiles, evidence, substitutions); err == nil {
				t.Fatal("invalid local build accepted")
			}
		})
	}
}
