package ci_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

// observedPolicyRelease is the test-suite caller boundary. Production exposes
// lifecycle construction only through ObservedWorkflow, so all contract tests
// exercise the same mandatory observation path as external callers.
var observedPolicyRelease observedPolicyReleaseAPI

type observedPolicyReleaseAPI struct{}

func newTestObservedWorkflow() (*policyrelease.ObservedWorkflow, error) {
	return policyrelease.NewObservedWorkflow(policyrelease.LifecycleContext{
		OperationID:   "contract-test-operation",
		CorrelationID: "contract-test-correlation",
		CausationID:   "contract-test-causation",
	}, policyrelease.LifecycleObserverFunc(func(event policyrelease.LifecycleEvent) (policyrelease.LifecycleAcknowledgement, error) {
		return policyrelease.AcknowledgeLifecycleEvent(event), nil
	}))
}

func (observedPolicyReleaseAPI) PrepareUnsigned(input policyrelease.BuildInput) (policyrelease.UnsignedActivation, error) {
	workflow, err := newTestObservedWorkflow()
	if err != nil {
		return policyrelease.UnsignedActivation{}, err
	}
	return workflow.PrepareUnsigned(input)
}

func (observedPolicyReleaseAPI) FinalizeActivationArchive(unsigned policyrelease.UnsignedActivation, envelope []byte, signing policyrelease.PresentedSigningResult) (policyrelease.ActivationArchive, error) {
	workflow, err := newTestObservedWorkflow()
	if err != nil {
		return policyrelease.ActivationArchive{}, err
	}
	return workflow.FinalizeActivationArchive(unsigned, envelope, signing)
}

func (observedPolicyReleaseAPI) InspectArchive(archive []byte) (policyrelease.ArchiveInspection, error) {
	workflow, err := newTestObservedWorkflow()
	if err != nil {
		return policyrelease.ArchiveInspection{}, err
	}
	return workflow.InspectArchive(archive)
}

func (observedPolicyReleaseAPI) ValidateArchive(archive, envelope []byte, files []policyrelease.ManifestFile) (policyrelease.ArchiveInspection, error) {
	workflow, err := newTestObservedWorkflow()
	if err != nil {
		return policyrelease.ArchiveInspection{}, err
	}
	return workflow.ValidateArchive(archive, envelope, files)
}

func (observedPolicyReleaseAPI) PrepareReleaseAttestation(activation policyrelease.ActivationArchive, input policyrelease.ReleaseAttestationInput) (policyrelease.UnsignedReleaseAttestation, error) {
	workflow, err := newTestObservedWorkflow()
	if err != nil {
		return policyrelease.UnsignedReleaseAttestation{}, err
	}
	return workflow.PrepareReleaseAttestation(activation, input)
}

func (observedPolicyReleaseAPI) FinalizeReleaseHandoff(activation policyrelease.ActivationArchive, unsigned policyrelease.UnsignedReleaseAttestation, envelope []byte, signing policyrelease.PresentedSigningResult) (policyrelease.ImmutableReleaseHandoff, error) {
	workflow, err := newTestObservedWorkflow()
	if err != nil {
		return policyrelease.ImmutableReleaseHandoff{}, err
	}
	return workflow.FinalizeReleaseHandoff(activation, unsigned, envelope, signing)
}

func (observedPolicyReleaseAPI) BuildTransportDescriptor(handoff policyrelease.ImmutableReleaseHandoff) (policyrelease.TransportDescriptorV1, []byte, error) {
	workflow, err := newTestObservedWorkflow()
	if err != nil {
		return policyrelease.TransportDescriptorV1{}, nil, err
	}
	return workflow.BuildTransportDescriptor(handoff)
}

type fixtureSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type fixtureEnvelope struct {
	PayloadType string             `json:"payloadType"`
	Payload     string             `json:"payload"`
	Signatures  []fixtureSignature `json:"signatures"`
}

type fixtureECDSASignature struct {
	R *big.Int
	S *big.Int
}

func repositoryRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func fixtureBytes(t testing.TB, relative string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "packages/test-fixtures/ci/policy-release/v1", relative))
	if err != nil {
		t.Fatalf("read fixture %s: %v", relative, err)
	}
	return data
}

func repositoryBytes(t testing.TB, relative string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), relative))
	if err != nil {
		t.Fatalf("read repository fixture %s: %v", relative, err)
	}
	return data
}

func testPublicKey(index int) (*ecdsa.PublicKey, string) {
	curve := elliptic.P256()
	d := big.NewInt(int64(index + 1))
	x, y := curve.ScalarBaseMult(d.Bytes())
	publicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	return publicKey, policyrelease.SHA256Digest(spki)
}

// fixtureSign is deliberately test-only. Its scalar and nonce derivation are
// public, non-secret, and categorically ineligible for an installation trust
// store. Production code has no signing function or private-key input.
func fixtureSign(payloadType string, payload []byte, index int) ([]byte, string) {
	curve := elliptic.P256()
	n := curve.Params().N
	d := big.NewInt(int64(index + 1))
	digest := sha256.Sum256(policyrelease.PAE(payloadType, payload))
	nonceSeed := sha256.Sum256(append(append([]byte("stead-public-fixture-nonce-v1:"), byte(index)), digest[:]...))
	k := new(big.Int).SetBytes(nonceSeed[:])
	k.Mod(k, new(big.Int).Sub(n, big.NewInt(1)))
	k.Add(k, big.NewInt(1))
	x, _ := curve.ScalarBaseMult(k.Bytes())
	r := new(big.Int).Mod(x, n)
	z := new(big.Int).SetBytes(digest[:])
	s := new(big.Int).Mul(r, d)
	s.Add(s, z)
	s.Mul(s, new(big.Int).ModInverse(k, n))
	s.Mod(s, n)
	halfN := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(n, s)
	}
	encoded, err := asn1.Marshal(fixtureECDSASignature{R: r, S: s})
	if err != nil {
		panic(err)
	}
	_, keyID := testPublicKey(index)
	return encoded, keyID
}

func externallySign(t testing.TB, payloadType string, payload []byte, signers int, oneCustodian bool) ([]byte, policyrelease.PresentedSigningResult) {
	t.Helper()
	signatures := make([]fixtureSignature, 0, signers)
	receipts := make([]policyrelease.PresentedSignatureReceipt, 0, signers)
	for index := 0; index < signers; index++ {
		signature, keyID := fixtureSign(payloadType, payload, index)
		custodian := "fixture-custodian-" + string(rune('a'+index))
		if oneCustodian {
			custodian = "fixture-custodian-shared"
		}
		signatures = append(signatures, fixtureSignature{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)})
		receipts = append(receipts, policyrelease.PresentedSignatureReceipt{
			KeyIDHint:          keyID,
			ClaimedCustodianID: custodian,
			ClaimedKeyPurpose:  policyrelease.ReleaseKeyPurpose,
			SignatureDigest:    policyrelease.SHA256Digest(signature),
		})
	}
	envelope, err := json.Marshal(fixtureEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  signatures,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := policyrelease.NewPresentedSigningResult("external-fixture-signing-workflow-v1", receipts)
	if err != nil {
		t.Fatal(err)
	}
	return envelope, result
}

func fixtureFile(t testing.TB, path, relative, mediaType string) policyrelease.File {
	t.Helper()
	return policyrelease.File{Path: path, MediaType: mediaType, Content: fixtureBytes(t, relative)}
}

func fixtureBuildInput(t testing.TB, profile string, threshold int, distinctCustodians bool) policyrelease.BuildInput {
	t.Helper()
	sourceRevision := "0123456789abcdef0123456789abcdef01234567"
	dependencyLockDigest := policyrelease.SHA256Digest([]byte("fixture-lock"))
	payloadFiles := []policyrelease.File{
		fixtureFile(t, "payload/policy-content-index.json", "source/payload/policy-content-index.json", "application/vnd.stead.policy-content-index.v1+json"),
		fixtureFile(t, "payload/input-schema.json", "source/payload/input-schema.json", "application/schema+json"),
		fixtureFile(t, "payload/output-schema.json", "source/payload/output-schema.json", "application/schema+json"),
		fixtureFile(t, "payload/decision-table.json", "source/payload/decision-table.json", "application/json"),
		fixtureFile(t, "payload/registries.json", "source/payload/registries.json", "application/json"),
		fixtureFile(t, "payload/openfga-model-source.txt", "source/payload/openfga-model-source.txt", "text/plain; charset=utf-8"),
		fixtureFile(t, "payload/deployment-policy.json", "source/payload/deployment-policy.json", "application/json"),
		fixtureFile(t, "payload/trust-set.json", "source/payload/trust-set.json", "application/json"),
	}
	profileRelative := "source/payload/profile-commercial.json"
	if profile == "synthetic_regulated" {
		profileRelative = "source/payload/profile-synthetic.json"
	}
	payloadFiles = append(payloadFiles, fixtureFile(t, "payload/security-profile.json", profileRelative, "application/vnd.stead.security-profile.v0.1+json"))
	var deploymentDocument map[string]any
	if err := json.Unmarshal(payloadFiles[6].Content, &deploymentDocument); err != nil {
		t.Fatal(err)
	}
	assuranceDocument := deploymentDocument["assurance"].(map[string]any)
	assuranceDocument["policy_signature_threshold"] = threshold
	assuranceDocument["distinct_signing_custodians"] = distinctCustodians
	assuranceDocument["trust_recovery_approval_threshold"] = threshold
	assuranceDocument["distinct_trust_recovery_approvers"] = distinctCustodians
	assuranceDocument["lowering_approval_threshold"] = threshold
	assuranceDocument["distinct_lowering_approvers"] = true
	assuranceDocument["human_lowering_approvers_required"] = threshold > 1
	assuranceDocument["approved_cryptographic_boundary"] = "fixture-boundary"
	assuranceDocument["validated_cryptographic_module_required"] = threshold > 1
	assuranceDocument["evidence_profile"] = "fixture-baseline"
	deploymentDocument["label_profile_ceilings"] = map[string]any{profile: map[string]any{"profile_version": "1.0.0", "classification_ceiling": "fixture-ceiling"}}
	deploymentBytes, err := json.Marshal(deploymentDocument)
	if err != nil {
		t.Fatal(err)
	}
	payloadFiles[6].Content = deploymentBytes
	deploymentPolicy := policyrelease.DeploymentPolicyBinding{
		PolicyID:                       "fixture-domain",
		Version:                        "1.0.0",
		SchemaID:                       policyrelease.DeploymentPolicySchemaID,
		Path:                           "payload/deployment-policy.json",
		Digest:                         policyrelease.SHA256Digest(deploymentBytes),
		DisclosureRevocationMode:       "request_boundary",
		PolicySignatureThreshold:       threshold,
		DistinctSigningCustodians:      distinctCustodians,
		TrustRecoveryApprovalThreshold: threshold,
		DistinctTrustRecoveryApprovers: distinctCustodians,
		LoweringApprovalThreshold:      threshold,
		DistinctLoweringApprovers:      true,
		HumanLoweringApproversRequired: threshold > 1,
		ApprovedCryptographicBoundary:  "fixture-boundary",
		ValidatedCryptoModuleRequired:  threshold > 1,
		EvidenceProfile:                "fixture-baseline",
		PresentedAssuranceResultPath:   "payload/presented-assurance-result.json",
	}
	assuranceResult := policyrelease.PresentedAssuranceEvaluationV1{
		SchemaVersion:                  "1.0.0",
		Treatment:                      policyrelease.PresentedMaterialTreatment,
		DeploymentPolicyID:             deploymentPolicy.PolicyID,
		DeploymentPolicyVersion:        deploymentPolicy.Version,
		DeploymentPolicyDigest:         deploymentPolicy.Digest,
		DisclosureRevocationMode:       deploymentPolicy.DisclosureRevocationMode,
		PolicySignatureThreshold:       deploymentPolicy.PolicySignatureThreshold,
		DistinctSigningCustodians:      deploymentPolicy.DistinctSigningCustodians,
		TrustRecoveryApprovalThreshold: deploymentPolicy.TrustRecoveryApprovalThreshold,
		DistinctTrustRecoveryApprovers: deploymentPolicy.DistinctTrustRecoveryApprovers,
		LoweringApprovalThreshold:      deploymentPolicy.LoweringApprovalThreshold,
		DistinctLoweringApprovers:      deploymentPolicy.DistinctLoweringApprovers,
		HumanLoweringApproversRequired: deploymentPolicy.HumanLoweringApproversRequired,
		ApprovedCryptographicBoundary:  deploymentPolicy.ApprovedCryptographicBoundary,
		ValidatedCryptoModuleRequired:  deploymentPolicy.ValidatedCryptoModuleRequired,
		EvidenceProfile:                deploymentPolicy.EvidenceProfile,
		ClaimedResult:                  "pass",
	}
	assuranceBytes, err := json.Marshal(assuranceResult)
	if err != nil {
		t.Fatal(err)
	}
	deploymentPolicy.PresentedAssuranceResultDigest = policyrelease.SHA256Digest(assuranceBytes)
	payloadFiles = append(payloadFiles, policyrelease.File{Path: deploymentPolicy.PresentedAssuranceResultPath, MediaType: "application/json", Content: assuranceBytes})

	var trustDocument map[string]any
	if err := json.Unmarshal(payloadFiles[7].Content, &trustDocument); err != nil {
		t.Fatal(err)
	}
	trustDocument["deployment_policy_digest"] = deploymentPolicy.Digest
	trustDocument["signature_threshold"] = threshold
	keys := make([]any, 0, threshold)
	for index := 0; index < threshold; index++ {
		publicKey, keyID := testPublicKey(index)
		spki, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, map[string]any{
			"custodian_id":    "fixture-custodian-" + string(rune('a'+index)),
			"key_id":          keyID,
			"not_after":       "2030-01-01T00:00:00Z",
			"not_before":      "2026-01-01T00:00:00Z",
			"purpose":         policyrelease.ReleaseKeyPurpose,
			"spki_der_base64": base64.StdEncoding.EncodeToString(spki),
			"status":          "active",
		})
	}
	trustDocument["keys"] = keys
	trustPayload, err := json.Marshal(trustDocument)
	if err != nil {
		t.Fatal(err)
	}
	payloadFiles[7].Content = trustPayload
	trustEnvelope, _ := externallySign(t, policyrelease.TrustSetPayloadType, trustPayload, threshold, false)
	payloadFiles = append(payloadFiles, policyrelease.File{Path: "payload/trust-set-envelope.json", MediaType: "application/json", Content: trustEnvelope})
	byPath := make(map[string]policyrelease.File, len(payloadFiles))
	for _, file := range payloadFiles {
		byPath[file.Path] = file
	}
	binding := func(role, path string) policyrelease.ContentBinding {
		file := byPath[path]
		return policyrelease.ContentBinding{Role: role, Path: path, MediaType: file.MediaType, Digest: policyrelease.SHA256Digest(file.Content)}
	}
	contractBindings := []policyrelease.ContentBinding{
		binding("decision_table", "payload/decision-table.json"),
		binding("input_schema", "payload/input-schema.json"),
		binding("output_schema", "payload/output-schema.json"),
		binding("registries", "payload/registries.json"),
	}
	sort.Slice(contractBindings, func(i, j int) bool { return contractBindings[i].Role < contractBindings[j].Role })
	indexRoles := map[string]string{
		"payload/decision-table.json":             "decision_table",
		"payload/input-schema.json":               "input_schema",
		"payload/output-schema.json":              "output_schema",
		"payload/registries.json":                 "registries",
		"payload/security-profile.json":           "security_profile",
		"payload/openfga-model-source.txt":        "openfga_model",
		"payload/deployment-policy.json":          "deployment_policy",
		"payload/presented-assurance-result.json": "presented_assurance_result",
		"payload/trust-set.json":                  "trust_set",
		"payload/trust-set-envelope.json":         "trust_set_envelope",
	}
	indexEntries := make([]policyrelease.PolicyContentIndexEntryV1, 0, len(indexRoles))
	for pathValue, role := range indexRoles {
		file := byPath[pathValue]
		indexEntries = append(indexEntries, policyrelease.PolicyContentIndexEntryV1{
			Role: role, Path: pathValue, MediaType: file.MediaType, Digest: policyrelease.SHA256Digest(file.Content),
		})
	}
	sort.Slice(indexEntries, func(i, j int) bool {
		return indexEntries[i].Path+"\x00"+indexEntries[i].Role < indexEntries[j].Path+"\x00"+indexEntries[j].Role
	})
	indexBytes, err := json.Marshal(policyrelease.PolicyContentIndexV1{SchemaVersion: "1.0.0", Entries: indexEntries})
	if err != nil {
		t.Fatal(err)
	}
	for index := range payloadFiles {
		if payloadFiles[index].Path == "payload/policy-content-index.json" {
			payloadFiles[index].Content = indexBytes
			byPath[payloadFiles[index].Path] = payloadFiles[index]
		}
	}
	policyBundleID := policyrelease.SHA256Digest(indexBytes)
	provenanceFile := fixtureFile(t, "evidence/provenance.json", "source/evidence/provenance.json", "application/vnd.in-toto+json")
	var provenanceDocument map[string]any
	if err := json.Unmarshal(provenanceFile.Content, &provenanceDocument); err != nil {
		t.Fatal(err)
	}
	externalParameters := provenanceDocument["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["externalParameters"].(map[string]any)
	externalParameters["sourceRevision"] = sourceRevision
	externalParameters["dependencyLockDigest"] = dependencyLockDigest
	provenanceDocument["subject"].([]any)[0].(map[string]any)["name"] = policyrelease.PolicyIndexSubjectName
	provenanceDocument["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"] = policyBundleID[len("sha256:"):]
	provenanceFile.Content, err = json.Marshal(provenanceDocument)
	if err != nil {
		t.Fatal(err)
	}
	evidenceFiles := []policyrelease.File{
		fixtureFile(t, "evidence/sbom.spdx.json", "source/evidence/sbom.spdx.json", "application/spdx+json"),
		fixtureFile(t, "evidence/license-result.json", "source/evidence/license-result.json", "application/vnd.stead.policy-license-result.v1+json"),
		fixtureFile(t, "evidence/conformance-result.json", "source/evidence/conformance-result.json", "application/vnd.stead.policy-conformance.v1+json"),
		provenanceFile,
		fixtureFile(t, "evidence/vulnerability-result.json", "source/evidence/vulnerability-result.json", "application/vnd.stead.policy-vulnerability.v1+json"),
	}
	return policyrelease.BuildInput{
		PayloadFiles:  payloadFiles,
		EvidenceFiles: evidenceFiles,
		Evidence: policyrelease.EvidenceInput{
			BuilderIdentity:       "stead-ci-policy-builder-v1",
			BuildWorkflowIdentity: "stead-ci-policy-build-workflow-v1",
			ReviewReceipts: []policyrelease.ReviewReceipt{{
				ReviewerID: "fixture-independent-reviewer", Role: "independent-security",
				SubjectDigest: policyBundleID,
				RecordDigest:  policyrelease.SHA256Digest([]byte("fixture-build-review-record")), ClaimedDisposition: "accept",
			}},
			WaiverReceipts: []policyrelease.WaiverReceipt{},
		},
		Manifest: policyrelease.ManifestInput{
			PolicyContentIndexPath: "payload/policy-content-index.json",
			ContractBindings:       contractBindings,
			Profiles: []policyrelease.ProfileBinding{{
				ProfileID:     profile,
				Version:       "1.0.0",
				SchemaID:      policyrelease.SecurityProfileSchemaID,
				Path:          "payload/security-profile.json",
				Digest:        policyrelease.SHA256Digest(byPath["payload/security-profile.json"].Content),
				SigningFormat: policyrelease.ActivationFormatV1,
			}},
			OpenFGAModel: policyrelease.OpenFGAModelBinding{
				SchemaVersion:    "1.1",
				SourcePath:       "payload/openfga-model-source.txt",
				SourceDigest:     policyrelease.SHA256Digest(byPath["payload/openfga-model-source.txt"].Content),
				CompatibilityID:  "fixture-model-compat-v1",
				TupleMigrationID: "fixture-tuple-migration-v1",
			},
			DeploymentPolicy:         deploymentPolicy,
			EvaluatorContractVersion: "evaluator-v1",
			SupportedSteadVersions:   []string{"stead-v0.1"},
			RequiredContextIDs:       []string{"trusted-principal"},
			ReasonCodeIDs:            []string{"denied-by-default"},
			ObligationIDs:            []string{"audit-required"},
			ExplicitDenyIDs:          []string{"explicit-deny-default"},
			SourceRevision:           sourceRevision,
			DependencyLockDigest:     dependencyLockDigest,
			BuildRecipeVersion:       "policy-release-builder-v1",
			IssuedAt:                 time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
			ExpiresAt:                time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
			Trust: policyrelease.TrustBinding{
				TrustSetID:             policyrelease.SHA256Digest(trustPayload),
				TrustSetPath:           "payload/trust-set.json",
				TrustSetEnvelopeDigest: policyrelease.SHA256Digest(trustEnvelope),
				TrustSetEnvelopePath:   "payload/trust-set-envelope.json",
				TrustEpoch:             1,
			},
			CompatiblePredecessorActivationSetIDs: []string{},
			RollbackConstraints:                   []string{"forward-audited-release-only", "no-revoked-evidence-reuse"},
		},
	}
}

// rebindPolicyContentIndex is test-only fixture construction. It models the
// upstream producer updating the canonical content index, review subject, and
// provenance subject after a deliberate semantic payload mutation.
func rebindPolicyContentIndex(t testing.TB, input *policyrelease.BuildInput) {
	t.Helper()
	roles := make(map[string]string)
	for _, binding := range input.Manifest.ContractBindings {
		roles[binding.Path] = binding.Role
	}
	for _, profile := range input.Manifest.Profiles {
		roles[profile.Path] = "security_profile"
		for _, file := range input.PayloadFiles {
			if file.Path != profile.Path {
				continue
			}
			var document map[string]any
			if err := json.Unmarshal(file.Content, &document); err != nil {
				t.Fatal(err)
			}
			for _, rawSource := range document["authoritative_sources"].([]any) {
				source := rawSource.(map[string]any)
				if pathValue, ok := source["payload_path"].(string); ok && pathValue != "" {
					roles["payload/"+pathValue] = "security_profile_authoritative_snapshot"
				}
			}
		}
	}
	roles[input.Manifest.OpenFGAModel.SourcePath] = "openfga_model"
	roles[input.Manifest.DeploymentPolicy.Path] = "deployment_policy"
	roles[input.Manifest.DeploymentPolicy.PresentedAssuranceResultPath] = "presented_assurance_result"
	roles[input.Manifest.Trust.TrustSetPath] = "trust_set"
	roles[input.Manifest.Trust.TrustSetEnvelopePath] = "trust_set_envelope"
	files := make(map[string]policyrelease.File, len(input.PayloadFiles))
	for _, file := range input.PayloadFiles {
		files[file.Path] = file
	}
	entries := make([]policyrelease.PolicyContentIndexEntryV1, 0, len(roles))
	for pathValue, role := range roles {
		file, present := files[pathValue]
		if !present {
			t.Fatalf("cannot rebind missing policy payload %s", pathValue)
		}
		entries = append(entries, policyrelease.PolicyContentIndexEntryV1{
			Role: role, Path: pathValue, MediaType: file.MediaType, Digest: policyrelease.SHA256Digest(file.Content),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path+"\x00"+entries[i].Role < entries[j].Path+"\x00"+entries[j].Role
	})
	indexBytes, err := json.Marshal(policyrelease.PolicyContentIndexV1{SchemaVersion: "1.0.0", Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	for fileIndex := range input.PayloadFiles {
		if input.PayloadFiles[fileIndex].Path == input.Manifest.PolicyContentIndexPath {
			input.PayloadFiles[fileIndex].Content = indexBytes
		}
	}
	bundleID := policyrelease.SHA256Digest(indexBytes)
	for reviewIndex := range input.Evidence.ReviewReceipts {
		input.Evidence.ReviewReceipts[reviewIndex].SubjectDigest = bundleID
	}
	for waiverIndex := range input.Evidence.WaiverReceipts {
		input.Evidence.WaiverReceipts[waiverIndex].SubjectDigest = bundleID
	}
	mutateEvidenceReport(t, input, "evidence/provenance.json", func(document map[string]any) {
		external := document["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["externalParameters"].(map[string]any)
		external["sourceRevision"] = input.Manifest.SourceRevision
		external["dependencyLockDigest"] = input.Manifest.DependencyLockDigest
		document["subject"].([]any)[0].(map[string]any)["name"] = policyrelease.PolicyIndexSubjectName
		document["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"] = bundleID[len("sha256:"):]
	})
}

func completeFixtureRelease(t testing.TB, profile string, threshold int, distinct bool) (policyrelease.ActivationArchive, policyrelease.UnsignedReleaseAttestation, policyrelease.ImmutableReleaseHandoff) {
	t.Helper()
	unsigned, err := observedPolicyRelease.PrepareUnsigned(fixtureBuildInput(t, profile, threshold, distinct))
	if err != nil {
		t.Fatalf("PrepareUnsigned: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	activationEnvelope, activationSigning := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, threshold, false)
	activation, err := observedPolicyRelease.FinalizeActivationArchive(unsigned, activationEnvelope, activationSigning)
	if err != nil {
		t.Fatalf("FinalizeActivationArchive: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	attestation, err := observedPolicyRelease.PrepareReleaseAttestation(activation, policyrelease.ReleaseAttestationInput{
		ReleaseWorkflowIdentity: "stead-ci-policy-release-workflow-v1",
		ReviewReceipts: []policyrelease.ReviewReceipt{{
			ReviewerID:         "fixture-final-reviewer",
			Role:               "independent-release",
			SubjectDigest:      activation.ArchiveDigest,
			RecordDigest:       policyrelease.SHA256Digest([]byte("fixture-final-review-record")),
			ClaimedDisposition: "accept",
		}},
		OfflineCheckReceipt: policyrelease.OfflineCheckReceipt{
			ClaimedOutcome:       "pass",
			SubjectArchiveDigest: activation.ArchiveDigest,
			ReportDigest:         policyrelease.SHA256Digest([]byte("offline-check-report")),
		},
	})
	if err != nil {
		t.Fatalf("PrepareReleaseAttestation: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	releaseEnvelope, releaseSigning := externallySign(t, policyrelease.ReleaseAttestationPayloadType, attestation.PayloadBytes, threshold, false)
	handoff, err := observedPolicyRelease.FinalizeReleaseHandoff(activation, attestation, releaseEnvelope, releaseSigning)
	if err != nil {
		t.Fatalf("FinalizeReleaseHandoff: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	return activation, attestation, handoff
}
