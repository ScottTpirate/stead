package policyrelease

import "time"

const (
	ActivationManifestPayloadType = "application/vnd.stead.policy-activation-manifest.v1+json"
	TrustSetPayloadType           = "application/vnd.stead.policy-trust-set.v1+json"
	ReleaseAttestationPayloadType = "application/vnd.stead.policy-release-attestation.v1+json"

	ActivationFormatV1       = "stead-policy-activation-set-dsse-v1"
	ReleaseKeyPurpose        = "release-policy"
	SecurityProfileSchemaID  = "https://stead.example/policies/security-label-profiles/profile-v0.1.schema.json"
	DeploymentPolicySchemaID = "https://stead.example/policies/deployment-domains/domain-profile-v0.1.schema.json"

	PresentedMaterialTreatment        = "unverified_presented_material"
	NonAuthorizingHandoffAuthority    = "none"
	RequiredConsumerVerificationOwner = "WS-06"
)

const (
	MaxEnvelopeBytes         = 4 << 20
	MaxDecodedPayloadBytes   = 2 << 20
	MaxJSONDepth             = 32
	MaxEnvelopeSignatures    = 16
	MaxEncodedSignatureBytes = 256
	MaxDecodedSignatureBytes = 128
	MaxKeyIDBytes            = 80

	MaxArchiveBytes      = 64 << 20
	MaxArchiveEntries    = 512
	MaxArchiveFiles      = 256
	MaxArchiveFileBytes  = 8 << 20
	MaxArchiveContent    = 48 << 20
	MaxArchivePathBytes  = 240
	MaxPathComponents    = 16
	MaxPathComponentByte = 100
)

// File is one immutable payload or pre-signing evidence input. Path is always
// relative and rooted below payload/ or evidence/.
type File struct {
	Path      string
	MediaType string
	Content   []byte
}

// ContentBinding binds a role in the activation manifest to one listed file.
type ContentBinding struct {
	Role      string `json:"role"`
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
}

type ProfileBinding struct {
	ProfileID     string `json:"profile_id"`
	Version       string `json:"version"`
	SchemaID      string `json:"schema_id"`
	Path          string `json:"path"`
	Digest        string `json:"digest"`
	SigningFormat string `json:"signing_format"`
}

type OpenFGAModelBinding struct {
	SchemaVersion    string `json:"schema_version"`
	SourcePath       string `json:"source_path"`
	SourceDigest     string `json:"source_digest"`
	CompatibilityID  string `json:"compatibility_id"`
	TupleMigrationID string `json:"tuple_migration_id"`
}

// DeploymentPolicyBinding is a typed handoff from a separately validated,
// signed deployment policy. The builder binds it but does not reinterpret or
// authorize it.
type DeploymentPolicyBinding struct {
	PolicyID                       string `json:"policy_id"`
	Version                        string `json:"version"`
	SchemaID                       string `json:"schema_id"`
	Path                           string `json:"path"`
	Digest                         string `json:"digest"`
	DisclosureRevocationMode       string `json:"disclosure_revocation_mode"`
	PolicySignatureThreshold       int    `json:"policy_signature_threshold"`
	DistinctSigningCustodians      bool   `json:"distinct_signing_custodians"`
	TrustRecoveryApprovalThreshold int    `json:"trust_recovery_approval_threshold"`
	DistinctTrustRecoveryApprovers bool   `json:"distinct_trust_recovery_approvers"`
	LoweringApprovalThreshold      int    `json:"lowering_approval_threshold"`
	DistinctLoweringApprovers      bool   `json:"distinct_lowering_approvers"`
	HumanLoweringApproversRequired bool   `json:"human_lowering_approvers_required"`
	ApprovedCryptographicBoundary  string `json:"approved_cryptographic_boundary"`
	ValidatedCryptoModuleRequired  bool   `json:"validated_cryptographic_module_required"`
	EvidenceProfile                string `json:"evidence_profile"`
	PresentedAssuranceResultPath   string `json:"presented_assurance_result_path"`
	PresentedAssuranceResultDigest string `json:"presented_assurance_result_digest"`
}

// PresentedAssuranceEvaluationV1 is digest-bound material supplied to WS-09.
// It is deliberately labeled as unverified: only WS-06 may establish whether
// the claimed result is authentic, current, and sufficient for activation.
type PresentedAssuranceEvaluationV1 struct {
	SchemaVersion                  string `json:"schema_version"`
	Treatment                      string `json:"treatment"`
	DeploymentPolicyID             string `json:"deployment_policy_id"`
	DeploymentPolicyVersion        string `json:"deployment_policy_version"`
	DeploymentPolicyDigest         string `json:"deployment_policy_digest"`
	DisclosureRevocationMode       string `json:"disclosure_revocation_mode"`
	PolicySignatureThreshold       int    `json:"policy_signature_threshold"`
	DistinctSigningCustodians      bool   `json:"distinct_signing_custodians"`
	TrustRecoveryApprovalThreshold int    `json:"trust_recovery_approval_threshold"`
	DistinctTrustRecoveryApprovers bool   `json:"distinct_trust_recovery_approvers"`
	LoweringApprovalThreshold      int    `json:"lowering_approval_threshold"`
	DistinctLoweringApprovers      bool   `json:"distinct_lowering_approvers"`
	HumanLoweringApproversRequired bool   `json:"human_lowering_approvers_required"`
	ApprovedCryptographicBoundary  string `json:"approved_cryptographic_boundary"`
	ValidatedCryptoModuleRequired  bool   `json:"validated_cryptographic_module_required"`
	EvidenceProfile                string `json:"evidence_profile"`
	ClaimedResult                  string `json:"claimed_result"`
}

type TrustBinding struct {
	TrustSetID             string `json:"trust_set_id"`
	TrustSetPath           string `json:"trust_set_path"`
	TrustSetEnvelopeDigest string `json:"trust_set_envelope_digest"`
	TrustSetEnvelopePath   string `json:"trust_set_envelope_path"`
	TrustEpoch             uint64 `json:"trust_epoch"`
}

// ReviewReceipt is caller-supplied, digest-addressed review material. The
// builder validates shape and binding only; it does not authenticate reviewers.
type ReviewReceipt struct {
	ReviewerID         string
	Role               string
	SubjectDigest      string
	RecordDigest       string
	ClaimedDisposition string
}

type PresentedReviewReceiptV1 struct {
	Treatment          string `json:"treatment"`
	ReviewerID         string `json:"reviewer_id"`
	Role               string `json:"role"`
	SubjectDigest      string `json:"subject_digest"`
	RecordDigest       string `json:"record_digest"`
	ClaimedDisposition string `json:"claimed_disposition"`
}

type WaiverReceipt struct {
	WaiverID           string
	SubjectDigest      string
	RecordDigest       string
	ClaimedDisposition string
}

type PresentedWaiverReceiptV1 struct {
	Treatment          string `json:"treatment"`
	WaiverID           string `json:"waiver_id"`
	SubjectDigest      string `json:"subject_digest"`
	RecordDigest       string `json:"record_digest"`
	ClaimedDisposition string `json:"claimed_disposition"`
}

// ConformanceClaims are parsed from the one closed, digest-listed conformance
// report. These fields describe what that unverified report claims.
type ConformanceClaims struct {
	DecisionRowsCoveredPercent   int    `json:"decision_rows_covered_percent"`
	CriticalMutationScorePercent int    `json:"critical_mutation_score_percent"`
	ClaimedDeterministicReplay   string `json:"claimed_deterministic_replay"`
	ClaimedLabelLattice          string `json:"claimed_label_lattice"`
	ClaimedExplicitDeny          string `json:"claimed_explicit_deny"`
	ClaimedAgentIntersection     string `json:"claimed_agent_intersection"`
	ClaimedProviderBypass        string `json:"claimed_provider_bypass"`
}

type PresentedConformanceEvidenceV1 struct {
	Treatment    string            `json:"treatment"`
	ReportPath   string            `json:"report_path"`
	ReportDigest string            `json:"report_digest"`
	Claims       ConformanceClaims `json:"claims"`
}

type EvidenceInput struct {
	BuilderIdentity       string
	BuildWorkflowIdentity string
	ReviewReceipts        []ReviewReceipt
	WaiverReceipts        []WaiverReceipt
}

type ManifestInput struct {
	PolicyContentIndexPath                string
	ContractBindings                      []ContentBinding
	Profiles                              []ProfileBinding
	OpenFGAModel                          OpenFGAModelBinding
	DeploymentPolicy                      DeploymentPolicyBinding
	EvaluatorContractVersion              string
	SupportedSteadVersions                []string
	RequiredContextIDs                    []string
	ReasonCodeIDs                         []string
	ObligationIDs                         []string
	ExplicitDenyIDs                       []string
	SourceRevision                        string
	DependencyLockDigest                  string
	BuildRecipeVersion                    string
	IssuedAt                              time.Time
	ExpiresAt                             time.Time
	Trust                                 TrustBinding
	CompatiblePredecessorActivationSetIDs []string
	RollbackConstraints                   []string
}

type BuildInput struct {
	PayloadFiles  []File
	EvidenceFiles []File
	Evidence      EvidenceInput
	Manifest      ManifestInput
}

type ManifestFile struct {
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

type PolicyActivationManifestV1 struct {
	SchemaVersion                         string                  `json:"schema_version"`
	ArtifactFormat                        string                  `json:"artifact_format"`
	PolicyBundleID                        string                  `json:"policy_bundle_id"`
	PolicyContentIndexPath                string                  `json:"policy_content_index_path"`
	ContractBindings                      []ContentBinding        `json:"contract_bindings"`
	Profiles                              []ProfileBinding        `json:"profiles"`
	OpenFGAModel                          OpenFGAModelBinding     `json:"openfga_model"`
	DeploymentPolicy                      DeploymentPolicyBinding `json:"deployment_policy"`
	EvaluatorContractVersion              string                  `json:"evaluator_contract_version"`
	SupportedSteadVersions                []string                `json:"supported_stead_versions"`
	RequiredContextIDs                    []string                `json:"required_context_ids"`
	ReasonCodeIDs                         []string                `json:"reason_code_ids"`
	ObligationIDs                         []string                `json:"obligation_ids"`
	ExplicitDenyIDs                       []string                `json:"explicit_deny_ids"`
	Files                                 []ManifestFile          `json:"files"`
	SourceRevision                        string                  `json:"source_revision"`
	DependencyLockDigest                  string                  `json:"dependency_lock_digest"`
	BuildRecipeVersion                    string                  `json:"build_recipe_version"`
	EvidenceManifestDigest                string                  `json:"evidence_manifest_digest"`
	IssuedAt                              string                  `json:"issued_at"`
	ExpiresAt                             string                  `json:"expires_at"`
	Trust                                 TrustBinding            `json:"trust"`
	CompatiblePredecessorActivationSetIDs []string                `json:"compatible_predecessor_activation_set_ids"`
	RollbackConstraints                   []string                `json:"rollback_constraints"`
}

type PresentedEvidenceReportV1 struct {
	Treatment string `json:"treatment"`
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

type PreSigningEvidenceManifestV1 struct {
	SchemaVersion            string                         `json:"schema_version"`
	Authority                string                         `json:"authority"`
	BuilderIdentity          string                         `json:"builder_identity"`
	BuildWorkflowIdentity    string                         `json:"build_workflow_identity"`
	SourceRevision           string                         `json:"source_revision"`
	DependencyLockDigest     string                         `json:"dependency_lock_digest"`
	PolicyContentIndexDigest string                         `json:"policy_content_index_digest"`
	OpenFGAModelSourceDigest string                         `json:"openfga_model_source_digest"`
	Trust                    TrustBinding                   `json:"trust"`
	DeploymentPolicyID       string                         `json:"deployment_policy_id"`
	DeploymentPolicyVersion  string                         `json:"deployment_policy_version"`
	DeploymentPolicyDigest   string                         `json:"deployment_policy_digest"`
	Reports                  []PresentedEvidenceReportV1    `json:"presented_reports"`
	Conformance              PresentedConformanceEvidenceV1 `json:"presented_conformance"`
	ReviewReceipts           []PresentedReviewReceiptV1     `json:"presented_review_receipts"`
	WaiverReceipts           []PresentedWaiverReceiptV1     `json:"presented_waiver_receipts"`
}

type SigningRequestV1 struct {
	SchemaVersion              string `json:"schema_version"`
	Purpose                    string `json:"purpose"`
	PayloadType                string `json:"payload_type"`
	PayloadBase64              string `json:"payload_base64"`
	PAEDigest                  string `json:"pae_digest"`
	KeyPurpose                 string `json:"key_purpose"`
	DeploymentPolicyID         string `json:"deployment_policy_id"`
	DeploymentPolicyVersion    string `json:"deployment_policy_version"`
	DeploymentPolicyDigest     string `json:"deployment_policy_digest"`
	RequiredSignatureThreshold int    `json:"required_signature_threshold"`
	DistinctCustodiansRequired bool   `json:"distinct_custodians_required"`
	SourceRevision             string `json:"source_revision"`
}

type UnsignedActivation struct {
	Manifest               PolicyActivationManifestV1
	ManifestPayload        []byte
	ActivationSetID        string
	PolicyBundleID         string
	EvidenceManifest       PreSigningEvidenceManifestV1
	EvidenceManifestBytes  []byte
	EvidenceManifestDigest string
	Files                  []File
	SigningRequest         SigningRequestV1
	SigningRequestBytes    []byte
}

type PresentedSignatureReceipt struct {
	KeyIDHint          string `json:"key_id_hint"`
	ClaimedCustodianID string `json:"claimed_custodian_id"`
	ClaimedKeyPurpose  string `json:"claimed_key_purpose"`
	SignatureDigest    string `json:"signature_digest"`
}

type PresentedSigningResult struct {
	Treatment        string                      `json:"treatment"`
	WorkflowIdentity string                      `json:"workflow_identity"`
	ReceiptSetDigest string                      `json:"receipt_set_digest"`
	Receipts         []PresentedSignatureReceipt `json:"presented_receipts"`
}

type PresentedSignatureSummary struct {
	Treatment                        string   `json:"treatment"`
	RequestedSignatureThreshold      int      `json:"requested_signature_threshold"`
	PresentedDistinctKeyIDHints      int      `json:"presented_distinct_key_id_hints"`
	DistinctCustodianClaimsRequested bool     `json:"distinct_custodian_claims_requested"`
	PresentedDistinctCustodianClaims int      `json:"presented_distinct_custodian_claims"`
	KeyIDHints                       []string `json:"key_id_hints"`
	ClaimedCustodianIDs              []string `json:"claimed_custodian_ids"`
}

type ActivationArchive struct {
	Unsigned                      UnsignedActivation
	EnvelopeBytes                 []byte
	SignedEnvelopeDigest          string
	ArchiveBytes                  []byte
	ArchiveDigest                 string
	PresentedActivationSigning    PresentedSigningResult
	PresentedActivationSignatures PresentedSignatureSummary
}

type OfflineCheckReceipt struct {
	ClaimedOutcome       string
	SubjectArchiveDigest string
	ReportDigest         string
}

type PresentedOfflineCheckEvidenceV1 struct {
	Treatment            string `json:"treatment"`
	ClaimedOutcome       string `json:"claimed_outcome"`
	SubjectArchiveDigest string `json:"subject_archive_digest"`
	ReportDigest         string `json:"report_digest"`
}

type ReleaseAttestationInput struct {
	ReleaseWorkflowIdentity string
	ReviewReceipts          []ReviewReceipt
	WaiverReceipts          []WaiverReceipt
	OfflineCheckReceipt     OfflineCheckReceipt
}

type ReleaseAttestationV1 struct {
	SchemaVersion                       string                          `json:"schema_version"`
	Authority                           string                          `json:"authority"`
	ActivationSetID                     string                          `json:"activation_set_id"`
	SignedEnvelopeDigest                string                          `json:"signed_envelope_digest"`
	ArchiveDigest                       string                          `json:"archive_digest"`
	EvidenceManifestDigest              string                          `json:"evidence_manifest_digest"`
	PolicyBundleID                      string                          `json:"policy_bundle_id"`
	OpenFGAModelSourceDigest            string                          `json:"openfga_model_source_digest"`
	Trust                               TrustBinding                    `json:"trust"`
	DeploymentPolicy                    DeploymentPolicyBinding         `json:"deployment_policy"`
	PresentedActivationWorkflowIdentity string                          `json:"presented_activation_workflow_identity"`
	PresentedActivationReceiptSetDigest string                          `json:"presented_activation_receipt_set_digest"`
	PresentedActivationSignatures       PresentedSignatureSummary       `json:"presented_activation_signatures"`
	SourceRevision                      string                          `json:"source_revision"`
	BuilderIdentity                     string                          `json:"builder_identity"`
	ReleaseWorkflowIdentity             string                          `json:"release_workflow_identity"`
	PresentedReviewReceipts             []PresentedReviewReceiptV1      `json:"presented_review_receipts"`
	PresentedWaiverReceipts             []PresentedWaiverReceiptV1      `json:"presented_waiver_receipts"`
	PresentedOfflineCheck               PresentedOfflineCheckEvidenceV1 `json:"presented_offline_check"`
}

type UnsignedReleaseAttestation struct {
	Payload             ReleaseAttestationV1
	PayloadBytes        []byte
	AttestationID       string
	SigningRequest      SigningRequestV1
	SigningRequestBytes []byte
}

// ImmutableReleaseHandoff is the exact archive-plus-attestation pair consumed
// by WS-06. It grants no authority until that owner independently verifies the
// signatures, trust policy, content, and activation prerequisites.
type ImmutableReleaseHandoff struct {
	Authority                           string
	ActivationSetID                     string
	SignedEnvelopeDigest                string
	ArchiveDigest                       string
	ReleaseAttestationID                string
	ReleaseAttestationEnvelopeDigest    string
	PolicyBundleID                      string
	OpenFGAModelSourceDigest            string
	EvidenceManifestDigest              string
	Trust                               TrustBinding
	DeploymentPolicyID                  string
	DeploymentPolicyVersion             string
	DeploymentPolicyDigest              string
	DisclosureRevocationMode            string
	PresentedAssuranceResultDigest      string
	SourceRevision                      string
	PresentedActivationReceiptSetDigest string
	PresentedActivationSignatures       PresentedSignatureSummary
	ArchiveBytes                        []byte
	ReleaseAttestationEnvelopeBytes     []byte
	PresentedReleaseSigning             PresentedSigningResult
	PresentedReleaseSignatures          PresentedSignatureSummary
	RequiredConsumerVerification        ConsumerVerificationRequirementV1
}

type ConsumerVerificationRequirementV1 struct {
	Owner  string
	Status string
	Checks []string
}

type TransportDescriptorV1 struct {
	SchemaVersion                    string `json:"schema_version"`
	Authority                        string `json:"authority"`
	ArchiveDigest                    string `json:"archive_digest"`
	ReleaseAttestationEnvelopeDigest string `json:"release_attestation_envelope_digest"`
}
