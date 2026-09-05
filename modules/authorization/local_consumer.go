package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
	fixedmodel "github.com/ScottTpirate/stead/policies/openfga"
)

type localCandidate struct {
	unsigned        policyrelease.UnsignedActivation
	envelope        []byte
	substitutions   localSubstitutions
	evidence        policyrelease.LocalDevelopmentEvidenceV1
	issued, expires time.Time
}

// CheckLocalDevelopmentArchive performs the actual offline content, signature,
// trust, substitution and pre-signing evidence checks. It confers no runtime
// authority and deliberately cannot produce a VerifiedActivation. Its caller
// records the executed result before the separate derivation attestation is
// created; the final attestation is never an input to its own evidence.
func CheckLocalDevelopmentArchive(ctx context.Context, repositoryRoot string, archive []byte, workflow *policyrelease.ObservedWorkflow, now time.Time) error {
	template, err := loadLocalTemplate(ctx, repositoryRoot)
	if err != nil || workflow == nil || now.IsZero() {
		return ErrDenied
	}
	_, err = checkLocalCandidate(template, archive, workflow, now)
	return err
}

func checkLocalCandidate(template LocalTemplateManifest, archive []byte, workflow *policyrelease.ObservedWorkflow, now time.Time) (localCandidate, error) {
	if validateLocalTemplate(template) != nil || workflow == nil || now.IsZero() {
		return localCandidate{}, ErrDenied
	}
	unsigned, envelope, err := workflow.ValidateLocalDevelopmentArchive(archive)
	if err != nil {
		return localCandidate{}, ErrDenied
	}
	manifest := unsigned.Manifest
	files := map[string][]byte{}
	for _, file := range unsigned.Files {
		files[file.Path] = file.Content
	}
	var substitutions localSubstitutions
	if decodeClosed(files[policyrelease.LocalDevelopmentSubstitutionsPath], &substitutions) != nil || substitutions.SchemaVersion != "1.0.0" || !identity.ValidID(substitutions.InstallationID) || !ulidPattern.MatchString(substitutions.OpenFGAStoreID) || !ulidPattern.MatchString(substitutions.OpenFGAModelID) || len(substitutions.Keys) != 1 {
		return localCandidate{}, ErrDenied
	}
	substitutionBytes, _ := json.Marshal(substitutions)
	if !bytes.Equal(substitutionBytes, files[policyrelease.LocalDevelopmentSubstitutionsPath]) {
		return localCandidate{}, ErrDenied
	}
	issued, e1 := time.Parse(time.RFC3339, substitutions.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339, substitutions.ExpiresAt)
	if e1 != nil || e2 != nil || expires.Sub(issued) != time.Duration(template.Core.ValiditySeconds)*time.Second || now.Before(issued) || !now.Before(expires) || manifest.IssuedAt != substitutions.IssuedAt || manifest.ExpiresAt != substitutions.ExpiresAt {
		return localCandidate{}, ErrDenied
	}
	key := substitutions.Keys[0]
	if key.CustodianID != "local-installation-"+substitutions.InstallationID || key.NotBefore != substitutions.IssuedAt || key.NotAfter != substitutions.ExpiresAt || key.Purpose != "release-policy" || key.Status != "active" {
		return localCandidate{}, ErrDenied
	}
	if manifest.SourceRevision != template.Core.SourceRevision || manifest.DependencyLockDigest != template.Core.DependencyLockDigest || manifest.BuildRecipeVersion != "stead-local-development-derivation-v1" || !supportedContracts(unsigned) || !slices.Equal(manifest.SupportedSteadVersions, []string{"stead-v0.1"}) || len(manifest.CompatiblePredecessorActivationSetIDs) != 0 || !slices.Equal(manifest.RollbackConstraints, []string{"initial-local-installation-only", "no-renewal-rotation-recovery-upgrade-or-promotion"}) {
		return localCandidate{}, ErrDenied
	}
	for _, file := range RuntimeContractFiles() {
		if !bytes.Equal(files[file.Path], file.Content) {
			return localCandidate{}, ErrDenied
		}
	}
	_, profile, profileMetadata, err := localProfileTemplate()
	if err != nil {
		return localCandidate{}, ErrDenied
	}
	domain, _ := contracts.ReadFile("contract/deployment-local.json")
	model, err := fixedmodel.ModelJSON()
	if err != nil || !bytes.Equal(files["payload/profile.json"], profile) || !bytes.Equal(files["payload/deployment-policy.json"], domain) || !bytes.Equal(files["payload/openfga-model.json"], model) {
		return localCandidate{}, ErrDenied
	}
	wantProfile := policyrelease.ProfileBinding{ProfileID: profileMetadata.ProfileID, Version: profileMetadata.Version, SchemaID: policyrelease.SecurityProfileSchemaID, Path: "payload/profile.json", Digest: policyrelease.SHA256Digest(profile), SigningFormat: policyrelease.ActivationFormatV1}
	if len(manifest.Profiles) != 1 || manifest.Profiles[0] != wantProfile || manifest.OpenFGAModel != (policyrelease.OpenFGAModelBinding{SchemaVersion: "1.1", SourcePath: "payload/openfga-model.json", SourceDigest: policyrelease.SHA256Digest(model), CompatibilityID: "stead-openfga-local-metadata-v1", TupleMigrationID: "initial-local-installation"}) || substitutions.ModelSourceDigest != manifest.OpenFGAModel.SourceDigest {
		return localCandidate{}, ErrDenied
	}
	policy := localDeploymentBinding(domain)
	policy.PresentedAssuranceResultDigest = policyrelease.SHA256Digest(files[policy.PresentedAssuranceResultPath])
	if manifest.DeploymentPolicy != policy || manifest.Trust.TrustEpoch != 1 || manifest.Trust.TrustSetPath != "payload/trust-set.json" || manifest.Trust.TrustSetEnvelopePath != "payload/trust-set.dsse.json" || substitutions.TrustEnvelopeDigest != manifest.Trust.TrustSetEnvelopeDigest {
		return localCandidate{}, ErrDenied
	}
	trustEnvelope, err := policyrelease.ParseDSSEEnvelope(files[manifest.Trust.TrustSetEnvelopePath])
	if err != nil || trustEnvelope.PayloadType != policyrelease.TrustSetPayloadType {
		return localCandidate{}, ErrDenied
	}
	var trust trustDocument
	if decodeClosed(trustEnvelope.Payload, &trust) != nil {
		return localCandidate{}, ErrDenied
	}
	expectedTrust := trustDocument{DeploymentPolicyDigest: policy.Digest, DeploymentPolicyID: policy.PolicyID, DeploymentPolicyVersion: policy.Version, Epoch: 1, Keys: substitutions.Keys, PreviousTrustSetID: nil, RecoveryKeyReference: "unsupported-local-development-recovery", SchemaVersion: "1.0.0", SignatureThreshold: 1}
	wantTrust, _ := json.Marshal(expectedTrust)
	if !bytes.Equal(wantTrust, trustEnvelope.Payload) || !bytes.Equal(wantTrust, files[manifest.Trust.TrustSetPath]) {
		return localCandidate{}, ErrDenied
	}
	if _, _, err := verifySignatures(trustEnvelope, substitutions.Keys, 1, false, now); err != nil {
		return localCandidate{}, ErrDenied
	}
	activation, err := policyrelease.ParseDSSEEnvelope(envelope)
	if err != nil || activation.PayloadType != policyrelease.ActivationManifestPayloadType {
		return localCandidate{}, ErrDenied
	}
	if _, _, err := verifySignatures(activation, substitutions.Keys, 1, false, now); err != nil {
		return localCandidate{}, ErrDenied
	}
	var evidence policyrelease.LocalDevelopmentEvidenceV1
	if decodeClosed(unsigned.EvidenceManifestBytes, &evidence) != nil || evidence.TemplateDigest != jsonDigest(template) || evidence.SourceTree != template.Core.SourceTree || evidence.InstallerIdentity != "stead-local-development-installer" || len(evidence.Reports) != 3 {
		return localCandidate{}, ErrDenied
	}
	subject := jsonDigest(struct{ TemplateDigest, SubstitutionsDigest, PolicyBundleID string }{jsonDigest(template), policyrelease.SHA256Digest(substitutionBytes), manifest.PolicyBundleID})
	for i, spec := range template.Core.Checks[:3] {
		if validateLocalCheck(template, spec, subject, evidence.Reports[i], issued, expires) != nil {
			return localCandidate{}, ErrDenied
		}
	}
	return localCandidate{unsigned: unsigned, envelope: envelope, substitutions: substitutions, evidence: evidence, issued: issued, expires: expires}, nil
}

func localActivationBinding(unsigned policyrelease.UnsignedActivation, attestation localDerivationAttestation, attestationID, derivationEnvelopeDigest string) ActivationBinding {
	m := unsigned.Manifest
	return ActivationBinding{EvidenceKind: "local-development-derivation-v1", InstallationID: attestation.InstallationID, ActivationSetID: unsigned.ActivationSetID, SignedEnvelopeDigest: attestation.EnvelopeDigest, ArchiveDigest: attestation.ArchiveDigest, ReleaseAttestationID: attestationID, ReleaseAttestationEnvelopeDigest: derivationEnvelopeDigest, PolicyBundleID: m.PolicyBundleID, OpenFGAModelID: attestation.OpenFGAModelID, OpenFGAStoreID: attestation.OpenFGAStoreID, ModelSourceDigest: m.OpenFGAModel.SourceDigest, DeploymentPolicyID: m.DeploymentPolicy.PolicyID, DeploymentPolicyVersion: m.DeploymentPolicy.Version, DeploymentPolicyDigest: m.DeploymentPolicy.Digest, DisclosureMode: m.DeploymentPolicy.DisclosureRevocationMode, AssuranceResultDigest: m.DeploymentPolicy.PresentedAssuranceResultDigest, EvaluatorContractVersion: m.EvaluatorContractVersion, TrustSetID: m.Trust.TrustSetID, TrustEnvelopeDigest: m.Trust.TrustSetEnvelopeDigest, TrustEpoch: 1, ActivationSequence: 1, ActivationEpoch: 1}
}

// LoadLocalDevelopment re-verifies an existing, unexpired local installation.
// It cannot generate new trust, reset an anchor, renew, rotate, recover, upgrade
// or promote an activation. Database and host-anchor equality is enforced by
// the same Coordinator/final-fence path as every other authorization request.
func LoadLocalDevelopment(ctx context.Context, input LocalDevelopmentLoadInput) (*VerifiedActivation, error) {
	if !input.LocalDevelopment || input.OpenFGA == nil || input.Workflow == nil || input.Now.IsZero() || !validAnchorState(input.Anchor) {
		return nil, ErrDenied
	}
	template, err := loadLocalTemplate(ctx, input.RepositoryRoot)
	if err != nil || input.PublicOrigin != template.Core.PublicOrigin || input.OpenFGAURL != template.Core.OpenFGAURL || input.OpenFGA.endpoint != template.Core.OpenFGAURL {
		return nil, ErrDenied
	}
	model, err := input.OpenFGA.VerifyModel(ctx)
	if err != nil {
		return nil, ErrDenied
	}
	return verifyLocalDevelopment(input, template, model)
}

func verifyLocalDevelopment(input LocalDevelopmentLoadInput, template LocalTemplateManifest, model *ModelReceipt) (*VerifiedActivation, error) {
	if !input.LocalDevelopment || model == nil || input.Workflow == nil || !validAnchorState(input.Anchor) || input.Anchor.Binding.EvidenceKind != "local-development-derivation-v1" {
		return nil, ErrDenied
	}
	now := input.Now.UTC()
	if now.Before(input.Anchor.PolicyTimeHighWater) {
		now = input.Anchor.PolicyTimeHighWater
	}
	candidate, err := checkLocalCandidate(template, input.Archive, input.Workflow, now)
	if err != nil {
		return nil, ErrDenied
	}
	parsed, err := policyrelease.ParseLocalDevelopmentEnvelope(input.DerivationEnvelope)
	if err != nil {
		return nil, ErrDenied
	}
	var attestation localDerivationAttestation
	if decodeClosed(parsed.Payload, &attestation) != nil {
		return nil, ErrDenied
	}
	sub := candidate.substitutions
	m := candidate.unsigned.Manifest
	if len(input.TrustedKeys) != 1 || input.TrustedKeys[0] != sub.Keys[0] || model.storeID != sub.OpenFGAStoreID || model.modelID != sub.OpenFGAModelID || model.sourceDigest != sub.ModelSourceDigest {
		return nil, ErrDenied
	}
	if _, _, err := verifySignatures(parsed, input.TrustedKeys, 1, false, now); err != nil {
		return nil, ErrDenied
	}
	readback, err := time.Parse(time.RFC3339Nano, attestation.ModelReadbackAt)
	if err != nil || readback.Before(candidate.issued) || !readback.Before(candidate.expires) {
		return nil, ErrDenied
	}
	if validateLocalCheck(template, template.Core.Checks[3], policyrelease.SHA256Digest(input.Archive), attestation.OfflineCheck, candidate.issued, candidate.expires) != nil {
		return nil, ErrDenied
	}
	want := localDerivationAttestation{SchemaVersion: "1.0.0", Kind: "local-development-derivation-v1", TemplateDigest: jsonDigest(template), ReviewSetDigest: jsonDigest(template.Reviews), InstallationID: sub.InstallationID, SubstitutionsDigest: policyrelease.SHA256Digest(mustJSON(sub)), ActivationSetID: candidate.unsigned.ActivationSetID, EnvelopeDigest: policyrelease.SHA256Digest(candidate.envelope), ArchiveDigest: policyrelease.SHA256Digest(input.Archive), TrustSetID: m.Trust.TrustSetID, TrustEnvelopeDigest: m.Trust.TrustSetEnvelopeDigest, OpenFGAStoreID: sub.OpenFGAStoreID, OpenFGAModelID: sub.OpenFGAModelID, ModelSourceDigest: sub.ModelSourceDigest, ModelReadbackAt: attestation.ModelReadbackAt, InstallerIdentity: candidate.evidence.InstallerIdentity, EvidenceDigest: candidate.unsigned.EvidenceManifestDigest, OfflineCheck: attestation.OfflineCheck, IssuedAt: sub.IssuedAt, ExpiresAt: sub.ExpiresAt}
	if !bytes.Equal(mustJSON(want), parsed.Payload) {
		return nil, ErrDenied
	}
	binding := localActivationBinding(candidate.unsigned, want, policyrelease.SHA256Digest(parsed.Payload), policyrelease.SHA256Digest(input.DerivationEnvelope))
	if input.Anchor.Binding != binding || input.Anchor.PolicyTimeHighWater.Before(candidate.issued) {
		return nil, ErrDenied
	}
	files := map[string][]byte{}
	for _, file := range candidate.unsigned.Files {
		files[file.Path] = file.Content
	}
	evaluator, err := classification.CompileValidatedProfile(files[m.Profiles[0].Path], files[m.DeploymentPolicy.Path])
	if err != nil {
		return nil, ErrDenied
	}
	return &VerifiedActivation{binding: binding, evaluator: evaluator, issuedAt: candidate.issued, expiresAt: candidate.expires, valid: true}, nil
}

func mustJSON(value any) []byte { data, _ := json.Marshal(value); return data }
