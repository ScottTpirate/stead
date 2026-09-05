package authorization

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
	"github.com/ScottTpirate/stead/modules/identity"
	fixedmodel "github.com/ScottTpirate/stead/policies/openfga"
)

type localSubstitutions struct {
	SchemaVersion       string       `json:"schema_version"`
	InstallationID      string       `json:"installation_id"`
	IssuedAt            string       `json:"issued_at"`
	ExpiresAt           string       `json:"expires_at"`
	Keys                []TrustedKey `json:"instance_keys"`
	TrustEnvelopeDigest string       `json:"trust_envelope_digest"`
	OpenFGAStoreID      string       `json:"openfga_store_id"`
	OpenFGAModelID      string       `json:"openfga_model_id"`
	ModelSourceDigest   string       `json:"model_source_digest"`
}

type localDerivationAttestation struct {
	SchemaVersion       string                                      `json:"schema_version"`
	Kind                string                                      `json:"kind"`
	TemplateDigest      string                                      `json:"template_digest"`
	ReviewSetDigest     string                                      `json:"review_set_digest"`
	InstallationID      string                                      `json:"installation_id"`
	SubstitutionsDigest string                                      `json:"substitutions_digest"`
	ActivationSetID     string                                      `json:"activation_set_id"`
	EnvelopeDigest      string                                      `json:"activation_envelope_digest"`
	ArchiveDigest       string                                      `json:"archive_digest"`
	TrustSetID          string                                      `json:"trust_set_id"`
	TrustEnvelopeDigest string                                      `json:"trust_envelope_digest"`
	OpenFGAStoreID      string                                      `json:"openfga_store_id"`
	OpenFGAModelID      string                                      `json:"openfga_model_id"`
	ModelSourceDigest   string                                      `json:"model_source_digest"`
	ModelReadbackAt     string                                      `json:"model_readback_at"`
	InstallerIdentity   string                                      `json:"installer_identity"`
	EvidenceDigest      string                                      `json:"evidence_digest"`
	OfflineCheck        policyrelease.LocalDevelopmentCheckEvidence `json:"offline_check"`
	IssuedAt            string                                      `json:"issued_at"`
	ExpiresAt           string                                      `json:"expires_at"`
}

// LocalDevelopmentDraft is a single-use in-memory compiler result. A failed
// finalization cannot be retried into a new activation with the same key.
type LocalDevelopmentDraft struct {
	config          LocalDevelopmentConfig
	template        LocalTemplateManifest
	key             *ecdsa.PrivateKey
	keys            []TrustedKey
	client          *OpenFGA
	model           *ModelReceipt
	modelReadbackAt time.Time
	manifest        policyrelease.ManifestInput
	files           []policyrelease.File
	substitutions   []byte
	subject         string
	used            atomic.Bool
}

func jsonDigest(value any) string {
	data, _ := json.Marshal(value)
	return policyrelease.SHA256Digest(data)
}

func localSign(payloadType string, payload []byte, key *ecdsa.PrivateKey, keyID string) ([]byte, error) {
	digest := sha256.Sum256(policyrelease.PAE(payloadType, payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, ErrDenied
	}
	half := new(big.Int).Rsh(new(big.Int).Set(key.Curve.Params().N), 1)
	if s.Cmp(half) > 0 {
		s.Sub(key.Curve.Params().N, s)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, ErrDenied
	}
	return json.Marshal(struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}{payloadType, base64.StdEncoding.EncodeToString(payload), []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}{{keyID, base64.StdEncoding.EncodeToString(der)}}})
}

// PrepareLocalDevelopment never opens a database or writes activation state.
// The composition root must first establish a new isolated, synthetic-only
// installation. Reviewed source and fixed local network checks precede any FGA
// operation. Every returned artifact is non-distributed local evidence.
func PrepareLocalDevelopment(ctx context.Context, config LocalDevelopmentConfig) (*LocalDevelopmentDraft, error) {
	if !config.LocalDevelopment || config.Runner == nil || config.Workflow == nil || !identity.ValidID(config.InstallationID) || config.Now.IsZero() || config.InstallerID != "stead-local-development-installer" || strings.TrimSpace(config.OpenFGAToken) == "" {
		return nil, ErrDenied
	}
	if delta := time.Since(config.Now); delta < -MaxPolicyClockSkew || delta > MaxPolicyClockSkew {
		return nil, ErrDenied
	}
	template, err := loadLocalTemplate(ctx, config.RepositoryRoot)
	if err != nil || config.PublicOrigin != template.Core.PublicOrigin || config.OpenFGAURL != template.Core.OpenFGAURL {
		return nil, ErrDenied
	}
	client, model, err := ProvisionLocalOpenFGA(ctx, config.OpenFGAURL, config.OpenFGAToken)
	if err != nil {
		return nil, err
	}
	draft, err := prepareLocalDraft(config, template, client, model)
	if err == nil {
		draft.modelReadbackAt = time.Now().UTC()
	}
	return draft, err
}

func prepareLocalDraft(config LocalDevelopmentConfig, template LocalTemplateManifest, client *OpenFGA, model *ModelReceipt) (*LocalDevelopmentDraft, error) {
	if validateLocalTemplate(template) != nil || model == nil {
		return nil, ErrDenied
	}
	issued := config.Now.UTC().Truncate(time.Second)
	expires := issued.Add(time.Duration(template.Core.ValiditySeconds) * time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrDenied
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, ErrDenied
	}
	keys := []TrustedKey{{CustodianID: "local-installation-" + config.InstallationID, KeyID: policyrelease.SHA256Digest(spki), NotBefore: issued.Format(time.RFC3339), NotAfter: expires.Format(time.RFC3339), Purpose: "release-policy", SPKIDERBase64: base64.StdEncoding.EncodeToString(spki), Status: "active"}}
	files := RuntimeContractFiles()
	for i := range files {
		if strings.Contains(files[i].Path, "-schema.json") {
			files[i].MediaType = "application/schema+json"
		}
	}
	profile, _ := contracts.ReadFile("contract/profile-commercial.json")
	domain, _ := contracts.ReadFile("contract/deployment-local.json")
	modelJSON, err := fixedmodel.ModelJSON()
	if err != nil || policyrelease.SHA256Digest(modelJSON) != model.sourceDigest {
		return nil, ErrDenied
	}
	files = append(files, policyrelease.File{Path: "payload/profile.json", MediaType: "application/vnd.stead.security-profile.v0.1+json", Content: profile}, policyrelease.File{Path: "payload/deployment-policy.json", MediaType: "application/json", Content: domain}, policyrelease.File{Path: "payload/openfga-model.json", MediaType: "application/json", Content: modelJSON})
	policy := localDeploymentBinding(domain)
	assurance := policyrelease.PresentedAssuranceEvaluationV1{SchemaVersion: "1.0.0", Treatment: policyrelease.PresentedMaterialTreatment, DeploymentPolicyID: policy.PolicyID, DeploymentPolicyVersion: policy.Version, DeploymentPolicyDigest: policy.Digest, DisclosureRevocationMode: policy.DisclosureRevocationMode, PolicySignatureThreshold: policy.PolicySignatureThreshold, DistinctSigningCustodians: policy.DistinctSigningCustodians, TrustRecoveryApprovalThreshold: policy.TrustRecoveryApprovalThreshold, DistinctTrustRecoveryApprovers: policy.DistinctTrustRecoveryApprovers, LoweringApprovalThreshold: policy.LoweringApprovalThreshold, DistinctLoweringApprovers: policy.DistinctLoweringApprovers, HumanLoweringApproversRequired: policy.HumanLoweringApproversRequired, ApprovedCryptographicBoundary: policy.ApprovedCryptographicBoundary, ValidatedCryptoModuleRequired: policy.ValidatedCryptoModuleRequired, EvidenceProfile: policy.EvidenceProfile, ClaimedResult: "pass"}
	// This is the deterministic schema comparison result, not conformance,
	// review, crypto validation, or a fabricated process/test receipt.
	assuranceBytes, _ := json.Marshal(assurance)
	policy.PresentedAssuranceResultDigest = policyrelease.SHA256Digest(assuranceBytes)
	files = append(files, policyrelease.File{Path: policy.PresentedAssuranceResultPath, MediaType: "application/json", Content: assuranceBytes})
	trust := trustDocument{DeploymentPolicyDigest: policy.Digest, DeploymentPolicyID: policy.PolicyID, DeploymentPolicyVersion: policy.Version, Epoch: 1, Keys: keys, PreviousTrustSetID: nil, RecoveryKeyReference: "unsupported-local-development-recovery", SchemaVersion: "1.0.0", SignatureThreshold: 1}
	trustBytes, _ := json.Marshal(trust)
	trustEnvelope, err := localSign(policyrelease.TrustSetPayloadType, trustBytes, key, keys[0].KeyID)
	if err != nil {
		return nil, err
	}
	files = append(files, policyrelease.File{Path: "payload/trust-set.json", MediaType: "application/json", Content: trustBytes}, policyrelease.File{Path: "payload/trust-set.dsse.json", MediaType: "application/json", Content: trustEnvelope})
	bindings := []policyrelease.ContentBinding{}
	for _, pair := range []struct{ role, path string }{{"decision_table", "decision-table.json"}, {"input_schema", "input-schema.json"}, {"output_schema", "output-schema.json"}, {"registries", "registries.json"}} {
		content, _ := contracts.ReadFile("contract/" + pair.path)
		mediaType := "application/json"
		if strings.Contains(pair.path, "-schema.json") {
			mediaType = "application/schema+json"
		}
		bindings = append(bindings, policyrelease.ContentBinding{Role: pair.role, Path: "payload/" + pair.path, MediaType: mediaType, Digest: policyrelease.SHA256Digest(content)})
	}
	manifest := policyrelease.ManifestInput{PolicyContentIndexPath: "payload/policy-content-index.json", ContractBindings: bindings, Profiles: []policyrelease.ProfileBinding{{ProfileID: "commercial", Version: "1.0.0", SchemaID: policyrelease.SecurityProfileSchemaID, Path: "payload/profile.json", Digest: policyrelease.SHA256Digest(profile), SigningFormat: policyrelease.ActivationFormatV1}}, OpenFGAModel: policyrelease.OpenFGAModelBinding{SchemaVersion: "1.1", SourcePath: "payload/openfga-model.json", SourceDigest: model.sourceDigest, CompatibilityID: "stead-openfga-local-metadata-v1", TupleMigrationID: "initial-local-installation"}, DeploymentPolicy: policy, EvaluatorContractVersion: EvaluatorContractVersion, SupportedSteadVersions: []string{"stead-v0.1"}, RequiredContextIDs: []string{"local-metadata", "local-session", "trusted-principal"}, ReasonCodeIDs: []string{"classification_denied", "context_denied", "relationship_denied", "stale_authorization_input"}, ObligationIDs: []string{"audit_access", "display_marking"}, ExplicitDenyIDs: []string{"explicit-deny"}, SourceRevision: template.Core.SourceRevision, DependencyLockDigest: template.Core.DependencyLockDigest, BuildRecipeVersion: "stead-local-development-derivation-v1", IssuedAt: issued, ExpiresAt: expires, Trust: policyrelease.TrustBinding{TrustSetID: policyrelease.SHA256Digest(trustBytes), TrustSetPath: "payload/trust-set.json", TrustSetEnvelopeDigest: policyrelease.SHA256Digest(trustEnvelope), TrustSetEnvelopePath: "payload/trust-set.dsse.json", TrustEpoch: 1}, CompatiblePredecessorActivationSetIDs: []string{}, RollbackConstraints: []string{"initial-local-installation-only", "no-renewal-rotation-recovery-upgrade-or-promotion"}}
	roles := map[string]string{"payload/profile.json": "security_profile", "payload/deployment-policy.json": "deployment_policy", "payload/openfga-model.json": "openfga_model", "payload/assurance.json": "presented_assurance_result", "payload/trust-set.json": "trust_set", "payload/trust-set.dsse.json": "trust_set_envelope"}
	for _, binding := range bindings {
		roles[binding.Path] = binding.Role
	}
	index := policyrelease.PolicyContentIndexV1{SchemaVersion: "1.0.0", Entries: []policyrelease.PolicyContentIndexEntryV1{}}
	for _, file := range files {
		index.Entries = append(index.Entries, policyrelease.PolicyContentIndexEntryV1{Role: roles[file.Path], Path: file.Path, MediaType: file.MediaType, Digest: policyrelease.SHA256Digest(file.Content)})
	}
	sort.Slice(index.Entries, func(i, j int) bool { return index.Entries[i].Path < index.Entries[j].Path })
	indexBytes, _ := json.Marshal(index)
	files = append(files, policyrelease.File{Path: manifest.PolicyContentIndexPath, MediaType: "application/vnd.stead.policy-content-index.v1+json", Content: indexBytes})
	substitutions, _ := json.Marshal(localSubstitutions{SchemaVersion: "1.0.0", InstallationID: config.InstallationID, IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339), Keys: keys, TrustEnvelopeDigest: manifest.Trust.TrustSetEnvelopeDigest, OpenFGAStoreID: model.storeID, OpenFGAModelID: model.modelID, ModelSourceDigest: model.sourceDigest})
	subject := jsonDigest(struct{ TemplateDigest, SubstitutionsDigest, PolicyBundleID string }{jsonDigest(template), policyrelease.SHA256Digest(substitutions), policyrelease.SHA256Digest(indexBytes)})
	return &LocalDevelopmentDraft{config: config, template: template, key: key, keys: keys, client: client, model: model, modelReadbackAt: config.Now.UTC(), manifest: manifest, files: files, substitutions: substitutions, subject: subject}, nil
}

func localDeploymentBinding(domain []byte) policyrelease.DeploymentPolicyBinding {
	return policyrelease.DeploymentPolicyBinding{PolicyID: LocalDevelopmentSecurityDomain, Version: "1.0.0", SchemaID: policyrelease.DeploymentPolicySchemaID, Path: "payload/deployment-policy.json", Digest: policyrelease.SHA256Digest(domain), DisclosureRevocationMode: "request_boundary", PolicySignatureThreshold: 1, TrustRecoveryApprovalThreshold: 1, LoweringApprovalThreshold: 1, DistinctLoweringApprovers: true, ApprovedCryptographicBoundary: "deployment_approved_standard", EvidenceProfile: "baseline", PresentedAssuranceResultPath: "payload/assurance.json"}
}

func validateLocalCheck(template LocalTemplateManifest, spec LocalCheckSpec, subject string, capture policyrelease.LocalDevelopmentCheckEvidence, issued, expires time.Time) error {
	if capture.CheckID != spec.ID || capture.SubjectDigest != subject || capture.ExitCode != 0 || len(capture.Stdout) == 0 || len(capture.Stdout) > 1<<20 || len(capture.Stderr) > 1<<20 {
		return ErrDenied
	}
	started, e1 := time.Parse(time.RFC3339Nano, capture.StartedAt)
	finished, e2 := time.Parse(time.RFC3339Nano, capture.FinishedAt)
	if e1 != nil || e2 != nil || started.Before(issued) || finished.Before(started) || !finished.Before(expires) {
		return ErrDenied
	}
	var report LocalCheckReport
	if decodeClosed([]byte(capture.Stdout), &report) != nil || report.SchemaVersion != "1.0.0" || report.CheckID != spec.ID || report.SubjectDigest != subject || report.SourceRevision != template.Core.SourceRevision || report.SourceTree != template.Core.SourceTree || report.Total != len(spec.Cases) || report.Total <= 0 || len(report.Cases) != report.Total || report.Passed < 0 || report.Failed < 0 || report.Passed+report.Failed != report.Total {
		return ErrDenied
	}
	ids := []string{}
	passed := 0
	for _, item := range report.Cases {
		ids = append(ids, item.ID)
		if item.Passed {
			passed++
		}
	}
	if !slices.Equal(ids, spec.Cases) || passed != report.Passed || passed*100 < report.Total*spec.RequiredRate {
		return ErrDenied
	}
	return nil
}

func (draft *LocalDevelopmentDraft) runCheck(ctx context.Context, spec LocalCheckSpec, subject string, archive []byte) (policyrelease.LocalDevelopmentCheckEvidence, error) {
	files := []policyrelease.File{}
	for _, file := range draft.files {
		files = append(files, policyrelease.File{Path: file.Path, MediaType: file.MediaType, Content: append([]byte{}, file.Content...)})
	}
	files = append(files, policyrelease.File{Path: policyrelease.LocalDevelopmentSubstitutionsPath, MediaType: "application/json", Content: append([]byte{}, draft.substitutions...)})
	request := LocalCheckRequest{ID: spec.ID, SubjectDigest: subject, SourceRevision: draft.template.Core.SourceRevision, SourceTree: draft.template.Core.SourceTree, Files: files, Archive: append([]byte{}, archive...)}
	capture, err := draft.config.Runner.Run(ctx, request)
	if err != nil || !utf8.Valid(capture.Stdout) || !utf8.Valid(capture.Stderr) {
		return policyrelease.LocalDevelopmentCheckEvidence{}, ErrDenied
	}
	receipt := policyrelease.LocalDevelopmentCheckEvidence{CheckID: spec.ID, SubjectDigest: subject, Stdout: string(capture.Stdout), Stderr: string(capture.Stderr), ExitCode: capture.ExitCode, StartedAt: capture.StartedAt.UTC().Format(time.RFC3339Nano), FinishedAt: capture.FinishedAt.UTC().Format(time.RFC3339Nano)}
	if validateLocalCheck(draft.template, spec, subject, receipt, draft.manifest.IssuedAt, draft.manifest.ExpiresAt) != nil {
		return policyrelease.LocalDevelopmentCheckEvidence{}, ErrDenied
	}
	return receipt, nil
}

func (draft *LocalDevelopmentDraft) Finalize(ctx context.Context) (LocalDevelopmentArtifacts, error) {
	if draft == nil || draft.key == nil || !draft.used.CompareAndSwap(false, true) {
		return LocalDevelopmentArtifacts{}, ErrDenied
	}
	defer func() { draft.key = nil }()
	evidence := policyrelease.LocalDevelopmentEvidenceV1{SchemaVersion: "1.0.0", Kind: "local-development-derivation", TemplateDigest: jsonDigest(draft.template), SubstitutionsDigest: policyrelease.SHA256Digest(draft.substitutions), SourceRevision: draft.template.Core.SourceRevision, SourceTree: draft.template.Core.SourceTree, DependencyLockDigest: draft.template.Core.DependencyLockDigest, InstallerIdentity: draft.config.InstallerID, Reports: []policyrelease.LocalDevelopmentCheckEvidence{}}
	for _, spec := range draft.template.Core.Checks[:3] {
		receipt, err := draft.runCheck(ctx, spec, draft.subject, nil)
		if err != nil {
			return LocalDevelopmentArtifacts{}, err
		}
		evidence.Reports = append(evidence.Reports, receipt)
	}
	unsigned, err := draft.config.Workflow.PrepareLocalDevelopment(draft.manifest, draft.files, evidence, draft.substitutions)
	if err != nil {
		return LocalDevelopmentArtifacts{}, err
	}
	envelope, err := localSign(policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, draft.key, draft.keys[0].KeyID)
	if err != nil {
		return LocalDevelopmentArtifacts{}, err
	}
	archive, err := draft.config.Workflow.FinalizeLocalDevelopment(unsigned, envelope)
	if err != nil {
		return LocalDevelopmentArtifacts{}, err
	}
	offline, err := draft.runCheck(ctx, draft.template.Core.Checks[3], policyrelease.SHA256Digest(archive), archive)
	if err != nil {
		return LocalDevelopmentArtifacts{}, err
	}
	attestation := localDerivationAttestation{SchemaVersion: "1.0.0", Kind: "local-development-derivation-v1", TemplateDigest: jsonDigest(draft.template), ReviewSetDigest: jsonDigest(draft.template.Reviews), InstallationID: draft.config.InstallationID, SubstitutionsDigest: policyrelease.SHA256Digest(draft.substitutions), ActivationSetID: unsigned.ActivationSetID, EnvelopeDigest: policyrelease.SHA256Digest(envelope), ArchiveDigest: policyrelease.SHA256Digest(archive), TrustSetID: draft.manifest.Trust.TrustSetID, TrustEnvelopeDigest: draft.manifest.Trust.TrustSetEnvelopeDigest, OpenFGAStoreID: draft.model.storeID, OpenFGAModelID: draft.model.modelID, ModelSourceDigest: draft.model.sourceDigest, ModelReadbackAt: draft.modelReadbackAt.Format(time.RFC3339Nano), InstallerIdentity: draft.config.InstallerID, EvidenceDigest: unsigned.EvidenceManifestDigest, OfflineCheck: offline, IssuedAt: draft.manifest.IssuedAt.Format(time.RFC3339), ExpiresAt: draft.manifest.ExpiresAt.Format(time.RFC3339)}
	attestationBytes, _ := json.Marshal(attestation)
	derivationEnvelope, err := localSign(policyrelease.LocalDevelopmentDerivationPayloadType, attestationBytes, draft.key, draft.keys[0].KeyID)
	if err != nil {
		return LocalDevelopmentArtifacts{}, err
	}
	binding := localActivationBinding(unsigned, attestation, policyrelease.SHA256Digest(attestationBytes), policyrelease.SHA256Digest(derivationEnvelope))
	finalTime := time.Now().UTC()
	anchor := AnchorState{Binding: binding, PolicyTimeHighWater: finalTime, PolicyTimeRevision: 1}
	input := LocalDevelopmentLoadInput{RepositoryRoot: draft.config.RepositoryRoot, PublicOrigin: draft.config.PublicOrigin, OpenFGAURL: draft.config.OpenFGAURL, OpenFGA: draft.client, Archive: archive, DerivationEnvelope: derivationEnvelope, TrustedKeys: draft.keys, Anchor: anchor, Now: finalTime, LocalDevelopment: true, Workflow: draft.config.Workflow}
	activation, err := verifyLocalDevelopment(input, draft.template, draft.model)
	if err != nil {
		return LocalDevelopmentArtifacts{}, err
	}
	return LocalDevelopmentArtifacts{Archive: archive, DerivationEnvelope: derivationEnvelope, TrustedKeys: append([]TrustedKey{}, draft.keys...), EvidenceFiles: []policyrelease.File{{Path: "evidence/local-development-checks.json", MediaType: "application/json", Content: append([]byte{}, unsigned.EvidenceManifestBytes...)}, {Path: policyrelease.LocalDevelopmentSubstitutionsPath, MediaType: "application/json", Content: append([]byte{}, draft.substitutions...)}}, Anchor: anchor, OpenFGA: draft.client, Activation: activation}, nil
}
