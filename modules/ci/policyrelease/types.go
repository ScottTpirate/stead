package policyrelease

import "time"

const (
	ActivationManifestPayloadType = "application/vnd.stead.policy-activation-manifest.v1+json"
	TrustSetPayloadType           = "application/vnd.stead.policy-trust-set.v1+json"
	ReleaseAttestationPayloadType = "application/vnd.stead.policy-release-attestation.v1+json"

	ActivationFormatV1 = "stead-policy-activation-set-dsse-v1"
	ReleaseKeyPurpose  = "release-policy"
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
	EvaluatedAssuranceResultPath   string `json:"evaluated_assurance_result_path"`
	EvaluatedAssuranceResultDigest string `json:"evaluated_assurance_result_digest"`
}

// EvaluatedAssuranceResultV1 is the strict, canonical output of the WS-06/WS-12
// deployment-policy validator. It lets this YAML-independent builder prove that
// signing/custody inputs came from the exact policy bytes it binds.
type EvaluatedAssuranceResultV1 struct {
	SchemaVersion                  string `json:"schema_version"`
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
	Result                         string `json:"result"`
}

type TrustBinding struct {
	TrustSetID             string `json:"trust_set_id"`
	TrustSetPath           string `json:"trust_set_path"`
	TrustSetEnvelopeDigest string `json:"trust_set_envelope_digest"`
	TrustSetEnvelopePath   string `json:"trust_set_envelope_path"`
	TrustEpoch             uint64 `json:"trust_epoch"`
}

type ReviewerDisposition struct {
	ReviewerID  string `json:"reviewer_id"`
	Role        string `json:"role"`
	Revision    string `json:"revision"`
	Disposition string `json:"disposition"`
}

type Waiver struct {
	WaiverID    string `json:"waiver_id"`
	Revision    string `json:"revision"`
	Disposition string `json:"disposition"`
}

// ConformanceSummary contains safe, closed pre-signing results. Source-level
// details remain in digest-listed report files.
type ConformanceSummary struct {
	DecisionRowsCoveredPercent   int  `json:"decision_rows_covered_percent"`
	CriticalMutationScorePercent int  `json:"critical_mutation_score_percent"`
	DeterministicReplayPassed    bool `json:"deterministic_replay_passed"`
	LabelLatticePassed           bool `json:"label_lattice_passed"`
	ExplicitDenyPassed           bool `json:"explicit_deny_passed"`
	AgentIntersectionPassed      bool `json:"agent_intersection_passed"`
	ProviderBypassPassed         bool `json:"provider_bypass_passed"`
}

type EvidenceInput struct {
	BuilderIdentity       string
	BuildWorkflowIdentity string
	Conformance           ConformanceSummary
	Reviews               []ReviewerDisposition
	Waivers               []Waiver
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

type EvidenceReport struct {
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

type PreSigningEvidenceManifestV1 struct {
	SchemaVersion            string                `json:"schema_version"`
	BuilderIdentity          string                `json:"builder_identity"`
	BuildWorkflowIdentity    string                `json:"build_workflow_identity"`
	SourceRevision           string                `json:"source_revision"`
	DependencyLockDigest     string                `json:"dependency_lock_digest"`
	PolicyContentIndexDigest string                `json:"policy_content_index_digest"`
	OpenFGAModelSourceDigest string                `json:"openfga_model_source_digest"`
	Trust                    TrustBinding          `json:"trust"`
	DeploymentPolicyID       string                `json:"deployment_policy_id"`
	DeploymentPolicyVersion  string                `json:"deployment_policy_version"`
	DeploymentPolicyDigest   string                `json:"deployment_policy_digest"`
	Reports                  []EvidenceReport      `json:"reports"`
	Conformance              ConformanceSummary    `json:"conformance"`
	Reviews                  []ReviewerDisposition `json:"reviews"`
	Waivers                  []Waiver              `json:"waivers"`
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

type SignatureReceipt struct {
	KeyID           string `json:"key_id"`
	CustodianID     string `json:"custodian_id"`
	KeyPurpose      string `json:"key_purpose"`
	SignatureDigest string `json:"signature_digest"`
}

type SigningResult struct {
	WorkflowIdentity string             `json:"workflow_identity"`
	ResultDigest     string             `json:"result_digest"`
	Receipts         []SignatureReceipt `json:"receipts"`
}

type ThresholdResult struct {
	RequiredSignatures         int      `json:"required_signatures"`
	VerifiedDistinctKeys       int      `json:"verified_distinct_keys"`
	DistinctCustodiansRequired bool     `json:"distinct_custodians_required"`
	VerifiedDistinctCustodians int      `json:"verified_distinct_custodians"`
	KeyIDs                     []string `json:"key_ids"`
	CustodianIDs               []string `json:"custodian_ids"`
	Satisfied                  bool     `json:"satisfied"`
}

type ActivationArchive struct {
	Unsigned             UnsignedActivation
	EnvelopeBytes        []byte
	SignedEnvelopeDigest string
	ArchiveBytes         []byte
	ArchiveDigest        string
	ActivationSigning    SigningResult
	Threshold            ThresholdResult
}

type NetworkDisabledVerification struct {
	Outcome               string `json:"outcome"`
	VerifiedArchiveDigest string `json:"verified_archive_digest"`
	ResultDigest          string `json:"result_digest"`
}

type ReleaseAttestationInput struct {
	ReleaseWorkflowIdentity     string
	FinalApprovals              []ReviewerDisposition
	Waivers                     []Waiver
	NetworkDisabledVerification NetworkDisabledVerification
}

type ReleaseAttestationV1 struct {
	SchemaVersion                     string                      `json:"schema_version"`
	ActivationSetID                   string                      `json:"activation_set_id"`
	SignedEnvelopeDigest              string                      `json:"signed_envelope_digest"`
	ArchiveDigest                     string                      `json:"archive_digest"`
	EvidenceManifestDigest            string                      `json:"evidence_manifest_digest"`
	PolicyBundleID                    string                      `json:"policy_bundle_id"`
	OpenFGAModelSourceDigest          string                      `json:"openfga_model_source_digest"`
	Trust                             TrustBinding                `json:"trust"`
	DeploymentPolicy                  DeploymentPolicyBinding     `json:"deployment_policy"`
	ActivationSigningWorkflowIdentity string                      `json:"activation_signing_workflow_identity"`
	ActivationSigningResultDigest     string                      `json:"activation_signing_result_digest"`
	ActivationThreshold               ThresholdResult             `json:"activation_threshold"`
	SourceRevision                    string                      `json:"source_revision"`
	BuilderIdentity                   string                      `json:"builder_identity"`
	ReleaseWorkflowIdentity           string                      `json:"release_workflow_identity"`
	FinalApprovals                    []ReviewerDisposition       `json:"final_approvals"`
	Waivers                           []Waiver                    `json:"waivers"`
	NetworkDisabledVerification       NetworkDisabledVerification `json:"network_disabled_verification"`
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
	ActivationSetID                  string
	SignedEnvelopeDigest             string
	ArchiveDigest                    string
	ReleaseAttestationID             string
	ReleaseAttestationEnvelopeDigest string
	PolicyBundleID                   string
	OpenFGAModelSourceDigest         string
	EvidenceManifestDigest           string
	Trust                            TrustBinding
	DeploymentPolicyID               string
	DeploymentPolicyVersion          string
	DeploymentPolicyDigest           string
	DisclosureRevocationMode         string
	EvaluatedAssuranceResultDigest   string
	SourceRevision                   string
	ActivationSigningResultDigest    string
	ActivationThreshold              ThresholdResult
	ArchiveBytes                     []byte
	ReleaseAttestationEnvelopeBytes  []byte
	ReleaseSigning                   SigningResult
	ReleaseThreshold                 ThresholdResult
}

type TransportDescriptorV1 struct {
	SchemaVersion                    string `json:"schema_version"`
	Authority                        string `json:"authority"`
	ArchiveDigest                    string `json:"archive_digest"`
	ReleaseAttestationEnvelopeDigest string `json:"release_attestation_envelope_digest"`
}
