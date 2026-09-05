package authorization

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"slices"
	"time"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
)

// TrustedKey is installation-authenticated trust material, not a key imported
// from an arbitrary envelope. Initial local bootstrap persists these public
// pins separately from application backups. No runtime private key is needed.
type TrustedKey struct {
	CustodianID   string `json:"custodian_id"`
	KeyID         string `json:"key_id"`
	NotAfter      string `json:"not_after"`
	NotBefore     string `json:"not_before"`
	Purpose       string `json:"purpose"`
	SPKIDERBase64 string `json:"spki_der_base64"`
	Status        string `json:"status"`
}
type trustDocument struct {
	DeploymentPolicyDigest  string       `json:"deployment_policy_digest"`
	DeploymentPolicyID      string       `json:"deployment_policy_id"`
	DeploymentPolicyVersion string       `json:"deployment_policy_version"`
	Epoch                   uint64       `json:"epoch"`
	Keys                    []TrustedKey `json:"keys"`
	PreviousTrustSetID      *string      `json:"previous_trust_set_id"`
	RecoveryKeyReference    string       `json:"recovery_key_reference"`
	SchemaVersion           string       `json:"schema_version"`
	SignatureThreshold      int          `json:"signature_threshold"`
}

type ActivationInput struct {
	Archive          []byte
	ReleaseEnvelope  []byte
	TrustedKeys      []TrustedKey
	RootThreshold    int
	Anchor           AnchorState
	Model            *ModelReceipt
	Workflow         *policyrelease.ObservedWorkflow
	Now              time.Time
	LocalDevelopment bool
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validBinding(binding ActivationBinding) bool {
	if binding.EvidenceKind != "" && binding.EvidenceKind != "local-development-derivation-v1" {
		return false
	}
	if !identity.ValidID(binding.InstallationID) {
		return false
	}
	if binding.DisclosureMode != "request_boundary" || binding.EvaluatorContractVersion != EvaluatorContractVersion || binding.DeploymentPolicyID == "" || binding.DeploymentPolicyVersion == "" || !ulidPattern.MatchString(binding.OpenFGAModelID) || !ulidPattern.MatchString(binding.OpenFGAStoreID) || binding.TrustEpoch == 0 || binding.ActivationEpoch == 0 || binding.ActivationSequence == 0 {
		return false
	}
	for _, digest := range []string{binding.ActivationSetID, binding.SignedEnvelopeDigest, binding.ArchiveDigest, binding.ReleaseAttestationID, binding.ReleaseAttestationEnvelopeDigest, binding.PolicyBundleID, binding.ModelSourceDigest, binding.DeploymentPolicyDigest, binding.AssuranceResultDigest, binding.TrustSetID, binding.TrustEnvelopeDigest} {
		if !digestPattern.MatchString(digest) {
			return false
		}
	}
	return true
}

func verifySignatures(parsed policyrelease.ParsedEnvelope, keys []TrustedKey, threshold int, distinct bool, now time.Time) (time.Time, []policyrelease.PresentedSignatureReceipt, error) {
	if threshold < 1 || threshold > 16 || len(keys) < threshold || len(keys) > 16 || len(parsed.Signatures) < threshold {
		return time.Time{}, nil, ErrDenied
	}
	public := map[string]*ecdsa.PublicKey{}
	entries := map[string]TrustedKey{}
	keyExpiry := map[string]time.Time{}
	for _, key := range keys {
		der, err := base64.StdEncoding.DecodeString(key.SPKIDERBase64)
		if err != nil || base64.StdEncoding.EncodeToString(der) != key.SPKIDERBase64 || policyrelease.SHA256Digest(der) != key.KeyID || key.CustodianID == "" || key.Purpose != "release-policy" || key.Status != "active" {
			return time.Time{}, nil, ErrDenied
		}
		if _, duplicate := entries[key.KeyID]; duplicate {
			return time.Time{}, nil, ErrDenied
		}
		decoded, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return time.Time{}, nil, ErrDenied
		}
		candidate, ok := decoded.(*ecdsa.PublicKey)
		if !ok || candidate.Curve != elliptic.P256() {
			return time.Time{}, nil, ErrDenied
		}
		before, err := time.Parse(time.RFC3339, key.NotBefore)
		if err != nil {
			return time.Time{}, nil, ErrDenied
		}
		after, err := time.Parse(time.RFC3339, key.NotAfter)
		if err != nil || !before.Before(after) || now.Before(before) || !now.Before(after) {
			return time.Time{}, nil, ErrDenied
		}
		public[key.KeyID] = candidate
		entries[key.KeyID] = key
		keyExpiry[key.KeyID] = after
	}
	digest := sha256.Sum256(policyrelease.PAE(parsed.PayloadType, parsed.Payload))
	custodians := map[string]bool{}
	receipts := []policyrelease.PresentedSignatureReceipt{}
	var expires time.Time
	for _, signature := range parsed.Signatures {
		key, ok := public[signature.KeyID]
		if !ok || !ecdsa.VerifyASN1(key, digest[:], signature.Bytes) {
			return time.Time{}, nil, ErrDenied
		}
		entry := entries[signature.KeyID]
		if distinct && custodians[entry.CustodianID] {
			return time.Time{}, nil, ErrDenied
		}
		custodians[entry.CustodianID] = true
		if expires.IsZero() || keyExpiry[signature.KeyID].Before(expires) {
			expires = keyExpiry[signature.KeyID]
		}
		receipts = append(receipts, policyrelease.PresentedSignatureReceipt{KeyIDHint: entry.KeyID, ClaimedCustodianID: entry.CustodianID, ClaimedKeyPurpose: entry.Purpose, SignatureDigest: signature.Digest})
	}
	return expires, receipts, nil
}

// VerifyActivation verifies exact archived policy, external release attestation,
// trust signatures, model read-back and an independently supplied current
// anchor. This constructor supports only explicit local-development initial
// trust. Production bootstrap, strict mode, rotation, recovery and unknown ABI
// are rejected, not downshifted to a weaker policy or test-fixture allowance.
func VerifyActivation(input ActivationInput) (*VerifiedActivation, error) {
	if !input.LocalDevelopment || input.Workflow == nil || input.Model == nil || input.Now.IsZero() || !validAnchorState(input.Anchor) || input.Anchor.Binding.EvidenceKind != "" {
		return nil, ErrDenied
	}
	now := input.Now.UTC()
	if now.Before(input.Anchor.PolicyTimeHighWater) {
		now = input.Anchor.PolicyTimeHighWater
	}
	unsigned, envelope, err := input.Workflow.ValidateActivationArchive(input.Archive)
	if err != nil {
		return nil, ErrDenied
	}
	manifest := unsigned.Manifest
	b := input.Anchor.Binding
	if !supportedContracts(unsigned) || len(manifest.Profiles) != 1 || !slices.Contains(manifest.SupportedSteadVersions, "stead-v0.1") || manifest.DeploymentPolicy.DisclosureRevocationMode != "request_boundary" || manifest.DeploymentPolicy.ValidatedCryptoModuleRequired || manifest.Trust.TrustEpoch != b.TrustEpoch || manifest.PolicyBundleID != b.PolicyBundleID || manifest.DeploymentPolicy.PolicyID != b.DeploymentPolicyID || manifest.DeploymentPolicy.Version != b.DeploymentPolicyVersion || manifest.DeploymentPolicy.Digest != b.DeploymentPolicyDigest || manifest.DeploymentPolicy.PresentedAssuranceResultDigest != b.AssuranceResultDigest || manifest.OpenFGAModel.SourceDigest != b.ModelSourceDigest || manifest.EvaluatorContractVersion != b.EvaluatorContractVersion || unsigned.ActivationSetID != b.ActivationSetID || policyrelease.SHA256Digest(envelope) != b.SignedEnvelopeDigest || policyrelease.SHA256Digest(input.Archive) != b.ArchiveDigest || policyrelease.SHA256Digest(input.ReleaseEnvelope) != b.ReleaseAttestationEnvelopeDigest || input.Model.sourceDigest != b.ModelSourceDigest || input.Model.modelID != b.OpenFGAModelID || input.Model.storeID != b.OpenFGAStoreID {
		return nil, ErrDenied
	}
	issued, err := time.Parse(time.RFC3339, manifest.IssuedAt)
	if err != nil {
		return nil, ErrDenied
	}
	expires, err := time.Parse(time.RFC3339, manifest.ExpiresAt)
	if err != nil || now.Before(issued) || !now.Before(expires) {
		return nil, ErrDenied
	}
	files := map[string][]byte{}
	for _, file := range unsigned.Files {
		files[file.Path] = file.Content
	}
	trustEnvelope, err := policyrelease.ParseDSSEEnvelope(files[manifest.Trust.TrustSetEnvelopePath])
	if err != nil || trustEnvelope.PayloadType != policyrelease.TrustSetPayloadType || policyrelease.SHA256Digest(trustEnvelope.Payload) != b.TrustSetID || manifest.Trust.TrustSetID != b.TrustSetID || manifest.Trust.TrustSetEnvelopeDigest != b.TrustEnvelopeDigest || policyrelease.SHA256Digest(files[manifest.Trust.TrustSetEnvelopePath]) != b.TrustEnvelopeDigest {
		return nil, ErrDenied
	}
	var trust trustDocument
	if decodeClosed(trustEnvelope.Payload, &trust) != nil || trust.PreviousTrustSetID != nil || trust.SchemaVersion != "1.0.0" || trust.Epoch != b.TrustEpoch || trust.DeploymentPolicyID != b.DeploymentPolicyID || trust.DeploymentPolicyVersion != b.DeploymentPolicyVersion || trust.DeploymentPolicyDigest != b.DeploymentPolicyDigest || trust.SignatureThreshold != manifest.DeploymentPolicy.PolicySignatureThreshold || input.RootThreshold != trust.SignatureThreshold {
		return nil, ErrDenied
	}
	rootExpiry, _, err := verifySignatures(trustEnvelope, input.TrustedKeys, input.RootThreshold, manifest.DeploymentPolicy.DistinctSigningCustodians, now)
	if err != nil {
		return nil, ErrDenied
	}
	// Initial installation cannot use its own candidate to replace the pinned
	// root keys or alter custody. Key rotation is a separately gated operation.
	rootBytes, _ := json.Marshal(input.TrustedKeys)
	trustBytes, _ := json.Marshal(trust.Keys)
	if !bytes.Equal(rootBytes, trustBytes) {
		return nil, ErrDenied
	}
	activation, err := policyrelease.ParseDSSEEnvelope(envelope)
	if err != nil {
		return nil, ErrDenied
	}
	activationExpiry, receipts, err := verifySignatures(activation, trust.Keys, trust.SignatureThreshold, manifest.DeploymentPolicy.DistinctSigningCustodians, now)
	if err != nil {
		return nil, ErrDenied
	}
	release, err := policyrelease.ParseDSSEEnvelope(input.ReleaseEnvelope)
	if err != nil || release.PayloadType != policyrelease.ReleaseAttestationPayloadType || policyrelease.SHA256Digest(release.Payload) != b.ReleaseAttestationID {
		return nil, ErrDenied
	}
	releaseExpiry, _, err := verifySignatures(release, trust.Keys, trust.SignatureThreshold, manifest.DeploymentPolicy.DistinctSigningCustodians, now)
	if err != nil {
		return nil, ErrDenied
	}
	var attestation policyrelease.ReleaseAttestationV1
	if decodeClosed(release.Payload, &attestation) != nil {
		return nil, ErrDenied
	}
	signing, err := policyrelease.NewPresentedSigningResult(attestation.PresentedActivationWorkflowIdentity, receipts)
	if err != nil || signing.ReceiptSetDigest != attestation.PresentedActivationReceiptSetDigest {
		return nil, ErrDenied
	}
	archive := policyrelease.ActivationArchive{Unsigned: unsigned, EnvelopeBytes: envelope, SignedEnvelopeDigest: b.SignedEnvelopeDigest, ArchiveBytes: input.Archive, ArchiveDigest: b.ArchiveDigest, PresentedActivationSigning: signing, PresentedActivationSignatures: attestation.PresentedActivationSignatures}
	reviewInput := policyrelease.ReleaseAttestationInput{ReleaseWorkflowIdentity: attestation.ReleaseWorkflowIdentity, OfflineCheckReceipt: policyrelease.OfflineCheckReceipt{ClaimedOutcome: attestation.PresentedOfflineCheck.ClaimedOutcome, SubjectArchiveDigest: attestation.PresentedOfflineCheck.SubjectArchiveDigest, ReportDigest: attestation.PresentedOfflineCheck.ReportDigest}}
	for _, review := range attestation.PresentedReviewReceipts {
		reviewInput.ReviewReceipts = append(reviewInput.ReviewReceipts, policyrelease.ReviewReceipt{ReviewerID: review.ReviewerID, Role: review.Role, SubjectDigest: review.SubjectDigest, RecordDigest: review.RecordDigest, ClaimedDisposition: review.ClaimedDisposition})
	}
	for _, waiver := range attestation.PresentedWaiverReceipts {
		reviewInput.WaiverReceipts = append(reviewInput.WaiverReceipts, policyrelease.WaiverReceipt{WaiverID: waiver.WaiverID, SubjectDigest: waiver.SubjectDigest, RecordDigest: waiver.RecordDigest, ClaimedDisposition: waiver.ClaimedDisposition})
	}
	expected, err := input.Workflow.PrepareReleaseAttestation(archive, reviewInput)
	if err != nil || !bytes.Equal(expected.PayloadBytes, release.Payload) {
		return nil, ErrDenied
	}
	evaluator, err := classification.CompileValidatedProfile(files[manifest.Profiles[0].Path], files[manifest.DeploymentPolicy.Path])
	if err != nil {
		return nil, ErrDenied
	}
	for _, bound := range []time.Time{rootExpiry, activationExpiry, releaseExpiry} {
		if bound.Before(expires) {
			expires = bound
		}
	}
	return &VerifiedActivation{binding: b, evaluator: evaluator, issuedAt: issued, expiresAt: expires, valid: true}, nil
}
