package policyrelease

import (
	"strings"
	"sync/atomic"
)

const (
	LifecycleObservationSchemaVersion   = "1.2.0"
	LifecycleObservationProducerOwner   = "WS-09"
	LifecycleObservationDurableOwner    = "WS-07"
	MaxLifecycleIdentifierBytes         = 128
	MaxLifecycleBuildRecipeVersionBytes = 256
	MinLifecycleApprovalThreshold       = 1
)

type LifecycleWorkflowCode string

const (
	LifecycleWorkflowActivation LifecycleWorkflowCode = "policy_activation"
	LifecycleWorkflowRelease    LifecycleWorkflowCode = "policy_release"
	LifecycleWorkflowTransport  LifecycleWorkflowCode = "policy_transport"
)

type LifecyclePresentedTreatmentCode string

const LifecycleTreatmentPresentedUnverified LifecyclePresentedTreatmentCode = PresentedMaterialTreatment

type LifecycleStageCode string

const (
	LifecycleStagePrepareUnsigned           LifecycleStageCode = "prepare_unsigned_activation"
	LifecycleStageFinalizeActivationArchive LifecycleStageCode = "finalize_activation_archive"
	LifecycleStageInspectArchive            LifecycleStageCode = "inspect_activation_archive"
	LifecycleStageValidateArchive           LifecycleStageCode = "validate_activation_archive"
	LifecycleStagePrepareReleaseAttestation LifecycleStageCode = "prepare_release_attestation"
	LifecycleStageFinalizeReleaseHandoff    LifecycleStageCode = "finalize_release_handoff"
	LifecycleStageBuildTransportDescriptor  LifecycleStageCode = "build_transport_descriptor"
)

type LifecycleOutcomeCode string

const (
	LifecycleOutcomeSuccess LifecycleOutcomeCode = "success"
	LifecycleOutcomeFailure LifecycleOutcomeCode = "failure"
)

type LifecycleThresholdResultCode string

const (
	LifecycleThresholdNotEvaluated       LifecycleThresholdResultCode = "not_evaluated"
	LifecycleThresholdPresentedSatisfied LifecycleThresholdResultCode = "presented_unverified_satisfied"
	LifecycleThresholdPresentedShort     LifecycleThresholdResultCode = "presented_unverified_short"
)

// LifecycleContext is bounded operation metadata supplied by the WS-09
// workflow. It is observation-only and is never passed to an artifact builder.
type LifecycleContext struct {
	OperationID   string `json:"operation_id"`
	CorrelationID string `json:"correlation_id"`
	CausationID   string `json:"causation_id"`
}

// LifecycleFacts contains only closed treatment/result codes, bounded counts,
// booleans, bounded safe identities, and syntactically valid revisions and
// SHA-256 identities already present at the workflow boundary. It cannot carry
// artifact bodies, paths, parser text, signatures, keys, or credentials.
type LifecycleFacts struct {
	BuilderIdentity                  string                          `json:"builder_identity,omitempty"`
	BuildWorkflowIdentity            string                          `json:"build_workflow_identity,omitempty"`
	ReleaseWorkflowIdentity          string                          `json:"release_workflow_identity,omitempty"`
	SigningWorkflowIdentity          string                          `json:"signing_workflow_identity,omitempty"`
	SourceRevision                   string                          `json:"source_revision,omitempty"`
	DependencyLockDigest             string                          `json:"dependency_lock_digest,omitempty"`
	BuildRecipeVersion               string                          `json:"build_recipe_version,omitempty"`
	ActivationSetID                  string                          `json:"activation_set_id,omitempty"`
	PolicyBundleID                   string                          `json:"policy_bundle_id,omitempty"`
	EvidenceManifestDigest           string                          `json:"evidence_manifest_digest,omitempty"`
	SignedEnvelopeDigest             string                          `json:"signed_envelope_digest,omitempty"`
	ArchiveDigest                    string                          `json:"archive_digest,omitempty"`
	ReleaseAttestationID             string                          `json:"release_attestation_id,omitempty"`
	ReleaseAttestationEnvelopeDigest string                          `json:"release_attestation_envelope_digest,omitempty"`
	DeploymentPolicyDigest           string                          `json:"deployment_policy_digest,omitempty"`
	PresentedAssuranceResultDigest   string                          `json:"presented_assurance_result_digest,omitempty"`
	PresentedSigningReceiptSetDigest string                          `json:"presented_signing_receipt_set_digest,omitempty"`
	SigningRequestPAEDigest          string                          `json:"signing_request_pae_digest,omitempty"`
	SigningResultTreatment           LifecyclePresentedTreatmentCode `json:"signing_result_treatment,omitempty"`
	ThresholdResult                  LifecycleThresholdResultCode    `json:"threshold_result"`
	ThresholdTreatment               LifecyclePresentedTreatmentCode `json:"threshold_treatment,omitempty"`
	PresentedOfflineReportDigest     string                          `json:"presented_offline_report_digest,omitempty"`
	PresentedSigningReceiptCount     int                             `json:"presented_signing_receipt_count"`
	RequiredSignatureThreshold       int                             `json:"required_signature_threshold"`
	DistinctCustodiansRequired       bool                            `json:"distinct_custodians_required"`
	PresentedReviewReceiptCount      int                             `json:"presented_review_receipt_count"`
	PresentedAcceptedReviewCount     int                             `json:"presented_accepted_review_count"`
	ReviewApprovalTreatment          LifecyclePresentedTreatmentCode `json:"review_approval_treatment,omitempty"`
	PresentedWaiverReceiptCount      int                             `json:"presented_waiver_receipt_count"`
	PresentedApprovedWaiverCount     int                             `json:"presented_approved_waiver_count"`
	WaiverApprovalTreatment          LifecyclePresentedTreatmentCode `json:"waiver_approval_treatment,omitempty"`
	TrustRecoveryApprovalThreshold   int                             `json:"trust_recovery_approval_threshold"`
	LoweringApprovalThreshold        int                             `json:"lowering_approval_threshold"`
	EntryCount                       int                             `json:"archive_entry_count"`
	FileCount                        int                             `json:"archive_file_count"`
}

// LifecycleAcknowledgement is the bounded receipt for one accepted terminal
// event. The observer port contract requires its WS-07 adapter to retain the
// event atomically with returning the exact receipt. The package validates the
// receipt but cannot enforce persistence behavior inside an adapter; conforming
// adapters retain nothing when they error, panic, or return another receipt.
type LifecycleAcknowledgement struct {
	SchemaVersion     string               `json:"schema_version"`
	ObservationDigest string               `json:"observation_digest"`
	Outcome           LifecycleOutcomeCode `json:"outcome"`
	ErrorCode         string               `json:"error_code,omitempty"`
}

// LifecycleEvent is one terminal, nonauthorizing WS-09 observation for WS-07
// to persist through its separately owned durable audit/outbox boundary.
type LifecycleEvent struct {
	SchemaVersion     string                `json:"schema_version"`
	Authority         string                `json:"authority"`
	ProducerOwner     string                `json:"producer_owner"`
	DurableAuditOwner string                `json:"durable_audit_owner"`
	Workflow          LifecycleWorkflowCode `json:"workflow"`
	Stage             LifecycleStageCode    `json:"stage"`
	Outcome           LifecycleOutcomeCode  `json:"outcome"`
	ErrorCode         string                `json:"error_code,omitempty"`
	Context           LifecycleContext      `json:"context"`
	Facts             LifecycleFacts        `json:"facts"`
}

// LifecycleObserver is an out-of-artifact delivery seam. Implementations may
// hand the value to WS-07, but this package grants them no database, network,
// provider, filesystem, signing, or authorization capability. Implementations
// own the transactional retain-and-acknowledge behavior described by
// LifecycleAcknowledgement.
type LifecycleObserver interface {
	AcknowledgePolicyRelease(LifecycleEvent) (LifecycleAcknowledgement, error)
}

type LifecycleObserverFunc func(LifecycleEvent) (LifecycleAcknowledgement, error)

func (observe LifecycleObserverFunc) AcknowledgePolicyRelease(event LifecycleEvent) (LifecycleAcknowledgement, error) {
	return observe(event)
}

// ObservedWorkflow adds fail-closed terminal observation to deterministic
// package operations. One instance represents one serialized lifecycle flow;
// concurrent or callback-reentrant use fails closed without returning outputs.
type ObservedWorkflow struct {
	context  LifecycleContext
	observer LifecycleObserver
	active   atomic.Bool
}

func NewObservedWorkflow(context LifecycleContext, observer LifecycleObserver) (*ObservedWorkflow, error) {
	if observer == nil {
		return nil, contractError("lifecycle_observer_required", "observer", nil)
	}
	if !validLifecycleIdentifier(context.OperationID) || !validLifecycleIdentifier(context.CorrelationID) || !validLifecycleIdentifier(context.CausationID) {
		return nil, contractError("invalid_lifecycle_context", "context", nil)
	}
	return &ObservedWorkflow{
		context: LifecycleContext{
			OperationID:   strings.Clone(context.OperationID),
			CorrelationID: strings.Clone(context.CorrelationID),
			CausationID:   strings.Clone(context.CausationID),
		},
		observer: observer,
	}, nil
}

func validLifecycleIdentifier(value string) bool {
	return len(value) > 0 && len(value) <= MaxLifecycleIdentifierBytes && opaqueIDPattern.MatchString(value)
}

func boundedLifecycleCount(value, maximum int) int {
	if value > maximum {
		return maximum + 1
	}
	return value
}

func boundedLifecycleSignatureThreshold(value, maximum int) int {
	if value < 1 || value > maximum {
		return 0
	}
	return value
}

func lifecycleApprovalThreshold(value int) int {
	if value < MinLifecycleApprovalThreshold {
		return 0
	}
	return value
}

func lifecycleDigest(value string) string {
	if !digestPattern.MatchString(value) {
		return ""
	}
	return strings.Clone(value)
}

func lifecycleIdentifier(value string) string {
	if !validLifecycleIdentifier(value) {
		return ""
	}
	return strings.Clone(value)
}

func lifecycleBuildRecipeVersion(value string) string {
	if len(value) == 0 || len(value) > MaxLifecycleBuildRecipeVersionBytes || !opaqueIDPattern.MatchString(value) {
		return ""
	}
	return strings.Clone(value)
}

func lifecycleSourceRevision(value string) string {
	if !gitRevisionPattern.MatchString(value) && !digestPattern.MatchString(value) {
		return ""
	}
	return strings.Clone(value)
}

func lifecycleReviewFacts(reviews []ReviewReceipt) (int, int) {
	total := boundedLifecycleCount(len(reviews), MaxReviewReceipts)
	if total > MaxReviewReceipts {
		return total, 0
	}
	accepted := 0
	for _, review := range reviews {
		if review.ClaimedDisposition == "accept" {
			accepted++
		}
	}
	return total, accepted
}

func lifecycleWaiverFacts(waivers []WaiverReceipt) (int, int) {
	total := boundedLifecycleCount(len(waivers), MaxWaiverReceipts)
	if total > MaxWaiverReceipts {
		return total, 0
	}
	approved := 0
	for _, waiver := range waivers {
		if waiver.ClaimedDisposition == "approved" {
			approved++
		}
	}
	return total, approved
}

func lifecyclePresentedReviewFacts(reviews []PresentedReviewReceiptV1) (int, int) {
	total := boundedLifecycleCount(len(reviews), MaxReviewReceipts)
	if total > MaxReviewReceipts {
		return total, 0
	}
	accepted := 0
	for _, review := range reviews {
		if review.ClaimedDisposition == "accept" {
			accepted++
		}
	}
	return total, accepted
}

func lifecyclePresentedWaiverFacts(waivers []PresentedWaiverReceiptV1) (int, int) {
	total := boundedLifecycleCount(len(waivers), MaxWaiverReceipts)
	if total > MaxWaiverReceipts {
		return total, 0
	}
	approved := 0
	for _, waiver := range waivers {
		if waiver.ClaimedDisposition == "approved" {
			approved++
		}
	}
	return total, approved
}

func applyLifecycleThresholdFacts(facts *LifecycleFacts, requested, presented int) {
	facts.RequiredSignatureThreshold = boundedLifecycleSignatureThreshold(requested, MaxEnvelopeSignatures)
	facts.ThresholdResult = LifecycleThresholdNotEvaluated
	if facts.RequiredSignatureThreshold == 0 || presented < 0 || presented > MaxEnvelopeSignatures {
		return
	}
	facts.ThresholdTreatment = LifecycleTreatmentPresentedUnverified
	if presented >= facts.RequiredSignatureThreshold {
		facts.ThresholdResult = LifecycleThresholdPresentedSatisfied
	} else {
		facts.ThresholdResult = LifecycleThresholdPresentedShort
	}
}

func lifecyclePolicyFacts(policy DeploymentPolicyBinding) LifecycleFacts {
	facts := LifecycleFacts{
		DeploymentPolicyDigest:         lifecycleDigest(policy.Digest),
		PresentedAssuranceResultDigest: lifecycleDigest(policy.PresentedAssuranceResultDigest),
		DistinctCustodiansRequired:     policy.DistinctSigningCustodians,
		TrustRecoveryApprovalThreshold: lifecycleApprovalThreshold(policy.TrustRecoveryApprovalThreshold),
		LoweringApprovalThreshold:      lifecycleApprovalThreshold(policy.LoweringApprovalThreshold),
		ThresholdResult:                LifecycleThresholdNotEvaluated,
	}
	applyLifecycleThresholdFacts(&facts, policy.PolicySignatureThreshold, -1)
	return facts
}

func lifecycleUnsignedFacts(unsigned UnsignedActivation) LifecycleFacts {
	facts := lifecyclePolicyFacts(unsigned.Manifest.DeploymentPolicy)
	facts.BuilderIdentity = lifecycleIdentifier(unsigned.EvidenceManifest.BuilderIdentity)
	facts.BuildWorkflowIdentity = lifecycleIdentifier(unsigned.EvidenceManifest.BuildWorkflowIdentity)
	facts.SourceRevision = lifecycleSourceRevision(unsigned.Manifest.SourceRevision)
	facts.DependencyLockDigest = lifecycleDigest(unsigned.Manifest.DependencyLockDigest)
	facts.BuildRecipeVersion = lifecycleBuildRecipeVersion(unsigned.Manifest.BuildRecipeVersion)
	facts.ActivationSetID = lifecycleDigest(unsigned.ActivationSetID)
	facts.PolicyBundleID = lifecycleDigest(unsigned.PolicyBundleID)
	facts.EvidenceManifestDigest = lifecycleDigest(unsigned.EvidenceManifestDigest)
	facts.SigningRequestPAEDigest = lifecycleDigest(unsigned.SigningRequest.PAEDigest)
	facts.PresentedReviewReceiptCount, facts.PresentedAcceptedReviewCount = lifecyclePresentedReviewFacts(unsigned.EvidenceManifest.ReviewReceipts)
	facts.PresentedWaiverReceiptCount, facts.PresentedApprovedWaiverCount = lifecyclePresentedWaiverFacts(unsigned.EvidenceManifest.WaiverReceipts)
	facts.ReviewApprovalTreatment = LifecycleTreatmentPresentedUnverified
	facts.WaiverApprovalTreatment = LifecycleTreatmentPresentedUnverified
	return facts
}

func lifecycleActivationFacts(activation ActivationArchive) LifecycleFacts {
	facts := lifecycleUnsignedFacts(activation.Unsigned)
	facts.SignedEnvelopeDigest = lifecycleDigest(activation.SignedEnvelopeDigest)
	facts.ArchiveDigest = lifecycleDigest(activation.ArchiveDigest)
	facts.PresentedSigningReceiptSetDigest = lifecycleDigest(activation.PresentedActivationSigning.ReceiptSetDigest)
	facts.SigningWorkflowIdentity = lifecycleIdentifier(activation.PresentedActivationSigning.WorkflowIdentity)
	facts.SigningResultTreatment = LifecycleTreatmentPresentedUnverified
	facts.PresentedSigningReceiptCount = boundedLifecycleCount(len(activation.PresentedActivationSigning.Receipts), MaxEnvelopeSignatures)
	applyLifecycleThresholdFacts(&facts, activation.PresentedActivationSignatures.RequestedSignatureThreshold, activation.PresentedActivationSignatures.PresentedDistinctKeyIDHints)
	return facts
}

func lifecycleHandoffFacts(handoff ImmutableReleaseHandoff) LifecycleFacts {
	facts := LifecycleFacts{
		ActivationSetID:                  lifecycleDigest(handoff.ActivationSetID),
		PolicyBundleID:                   lifecycleDigest(handoff.PolicyBundleID),
		EvidenceManifestDigest:           lifecycleDigest(handoff.EvidenceManifestDigest),
		SignedEnvelopeDigest:             lifecycleDigest(handoff.SignedEnvelopeDigest),
		ArchiveDigest:                    lifecycleDigest(handoff.ArchiveDigest),
		ReleaseAttestationID:             lifecycleDigest(handoff.ReleaseAttestationID),
		ReleaseAttestationEnvelopeDigest: lifecycleDigest(handoff.ReleaseAttestationEnvelopeDigest),
		DeploymentPolicyDigest:           lifecycleDigest(handoff.DeploymentPolicyDigest),
		PresentedAssuranceResultDigest:   lifecycleDigest(handoff.PresentedAssuranceResultDigest),
		PresentedSigningReceiptSetDigest: lifecycleDigest(handoff.PresentedReleaseSigning.ReceiptSetDigest),
		SigningWorkflowIdentity:          lifecycleIdentifier(handoff.PresentedReleaseSigning.WorkflowIdentity),
		SigningResultTreatment:           LifecycleTreatmentPresentedUnverified,
		PresentedSigningReceiptCount:     boundedLifecycleCount(len(handoff.PresentedReleaseSigning.Receipts), MaxEnvelopeSignatures),
		DistinctCustodiansRequired:       handoff.PresentedReleaseSignatures.DistinctCustodianClaimsRequested,
		SourceRevision:                   lifecycleSourceRevision(handoff.SourceRevision),
		ThresholdResult:                  LifecycleThresholdNotEvaluated,
	}
	applyLifecycleThresholdFacts(&facts, handoff.PresentedReleaseSignatures.RequestedSignatureThreshold, handoff.PresentedReleaseSignatures.PresentedDistinctKeyIDHints)
	return facts
}

func terminalLifecycleEvent(context LifecycleContext, workflow LifecycleWorkflowCode, stage LifecycleStageCode, facts LifecycleFacts, operationErr error) LifecycleEvent {
	event := LifecycleEvent{
		SchemaVersion:     LifecycleObservationSchemaVersion,
		Authority:         NonAuthorizingHandoffAuthority,
		ProducerOwner:     LifecycleObservationProducerOwner,
		DurableAuditOwner: LifecycleObservationDurableOwner,
		Workflow:          workflow,
		Stage:             stage,
		Outcome:           LifecycleOutcomeSuccess,
		Context:           context,
		Facts:             facts,
	}
	if operationErr != nil {
		event.Outcome = LifecycleOutcomeFailure
		event.ErrorCode = ErrorCode(operationErr)
		if event.ErrorCode == "" {
			event.ErrorCode = "operation_failed"
		}
	}
	return event
}

// AcknowledgeLifecycleEvent constructs the only receipt accepted for event.
// It hashes only the closed, bounded observation schema; artifact bytes and
// protected inputs cannot enter this acknowledgement.
func AcknowledgeLifecycleEvent(event LifecycleEvent) LifecycleAcknowledgement {
	encoded, err := marshalCanonical(event)
	if err != nil {
		return LifecycleAcknowledgement{}
	}
	return LifecycleAcknowledgement{
		SchemaVersion:     LifecycleObservationSchemaVersion,
		ObservationDigest: SHA256Digest(encoded),
		Outcome:           event.Outcome,
		ErrorCode:         strings.Clone(event.ErrorCode),
	}
}

func (workflow *ObservedWorkflow) beginOperation() error {
	if workflow == nil || workflow.observer == nil {
		return contractError("lifecycle_observer_failed", "observer", nil)
	}
	if !workflow.active.CompareAndSwap(false, true) {
		return contractError("lifecycle_operation_in_progress", "workflow", nil)
	}
	return nil
}

func (workflow *ObservedWorkflow) observe(event LifecycleEvent) (err error) {
	want := AcknowledgeLifecycleEvent(event)
	defer func() {
		if recover() != nil {
			err = contractError("lifecycle_observer_failed", "observer", nil)
		}
	}()
	receipt, callbackErr := workflow.observer.AcknowledgePolicyRelease(event)
	if callbackErr != nil || receipt != want {
		return contractError("lifecycle_observer_failed", "observer", nil)
	}
	return nil
}

func (workflow *ObservedWorkflow) PrepareUnsigned(input BuildInput) (UnsignedActivation, error) {
	if err := workflow.beginOperation(); err != nil {
		return UnsignedActivation{}, err
	}
	defer workflow.active.Store(false)
	result, operationErr := prepareUnsigned(input)
	facts := lifecyclePolicyFacts(input.Manifest.DeploymentPolicy)
	facts.BuilderIdentity = lifecycleIdentifier(input.Evidence.BuilderIdentity)
	facts.BuildWorkflowIdentity = lifecycleIdentifier(input.Evidence.BuildWorkflowIdentity)
	facts.SourceRevision = lifecycleSourceRevision(input.Manifest.SourceRevision)
	facts.DependencyLockDigest = lifecycleDigest(input.Manifest.DependencyLockDigest)
	facts.BuildRecipeVersion = lifecycleBuildRecipeVersion(input.Manifest.BuildRecipeVersion)
	facts.PresentedReviewReceiptCount, facts.PresentedAcceptedReviewCount = lifecycleReviewFacts(input.Evidence.ReviewReceipts)
	facts.PresentedWaiverReceiptCount, facts.PresentedApprovedWaiverCount = lifecycleWaiverFacts(input.Evidence.WaiverReceipts)
	facts.ReviewApprovalTreatment = LifecycleTreatmentPresentedUnverified
	facts.WaiverApprovalTreatment = LifecycleTreatmentPresentedUnverified
	if operationErr == nil {
		facts.ActivationSetID = lifecycleDigest(result.ActivationSetID)
		facts.PolicyBundleID = lifecycleDigest(result.PolicyBundleID)
		facts.EvidenceManifestDigest = lifecycleDigest(result.EvidenceManifestDigest)
		facts.SigningRequestPAEDigest = lifecycleDigest(result.SigningRequest.PAEDigest)
	}
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowActivation, LifecycleStagePrepareUnsigned, facts, operationErr)
	if observationErr := workflow.observe(event); observationErr != nil {
		return UnsignedActivation{}, observationErr
	}
	if operationErr != nil {
		return UnsignedActivation{}, operationErr
	}
	return result, nil
}

func (workflow *ObservedWorkflow) FinalizeActivationArchive(unsigned UnsignedActivation, envelope []byte, signing PresentedSigningResult) (ActivationArchive, error) {
	if err := workflow.beginOperation(); err != nil {
		return ActivationArchive{}, err
	}
	defer workflow.active.Store(false)
	result, operationErr := finalizeActivationArchive(unsigned, envelope, signing)
	facts := lifecycleUnsignedFacts(unsigned)
	facts.PresentedSigningReceiptCount = boundedLifecycleCount(len(signing.Receipts), MaxEnvelopeSignatures)
	facts.PresentedSigningReceiptSetDigest = lifecycleDigest(signing.ReceiptSetDigest)
	facts.SigningWorkflowIdentity = lifecycleIdentifier(signing.WorkflowIdentity)
	facts.SigningResultTreatment = LifecycleTreatmentPresentedUnverified
	applyLifecycleThresholdFacts(&facts, unsigned.SigningRequest.RequiredSignatureThreshold, len(signing.Receipts))
	if operationErr == nil {
		facts.SignedEnvelopeDigest = lifecycleDigest(result.SignedEnvelopeDigest)
		facts.ArchiveDigest = lifecycleDigest(result.ArchiveDigest)
	}
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowActivation, LifecycleStageFinalizeActivationArchive, facts, operationErr)
	if observationErr := workflow.observe(event); observationErr != nil {
		return ActivationArchive{}, observationErr
	}
	if operationErr != nil {
		return ActivationArchive{}, operationErr
	}
	return result, nil
}

func (workflow *ObservedWorkflow) InspectArchive(archive []byte) (ArchiveInspection, error) {
	if err := workflow.beginOperation(); err != nil {
		return ArchiveInspection{}, err
	}
	defer workflow.active.Store(false)
	result, operationErr := inspectArchive(archive)
	facts := LifecycleFacts{}
	if operationErr == nil {
		facts.ArchiveDigest = lifecycleDigest(result.ArchiveDigest)
		facts.EntryCount = boundedLifecycleCount(result.EntryCount, MaxArchiveEntries)
		facts.FileCount = boundedLifecycleCount(result.FileCount, MaxArchiveFiles)
	}
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowActivation, LifecycleStageInspectArchive, facts, operationErr)
	if observationErr := workflow.observe(event); observationErr != nil {
		return ArchiveInspection{}, observationErr
	}
	if operationErr != nil {
		return ArchiveInspection{}, operationErr
	}
	return result, nil
}

func (workflow *ObservedWorkflow) ValidateArchive(archive, envelope []byte, files []ManifestFile) (ArchiveInspection, error) {
	if err := workflow.beginOperation(); err != nil {
		return ArchiveInspection{}, err
	}
	defer workflow.active.Store(false)
	result, operationErr := validateArchive(archive, envelope, files)
	facts := LifecycleFacts{}
	if operationErr == nil {
		facts.ArchiveDigest = lifecycleDigest(result.ArchiveDigest)
		facts.EntryCount = boundedLifecycleCount(result.EntryCount, MaxArchiveEntries)
		facts.FileCount = boundedLifecycleCount(result.FileCount, MaxArchiveFiles)
	}
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowActivation, LifecycleStageValidateArchive, facts, operationErr)
	if observationErr := workflow.observe(event); observationErr != nil {
		return ArchiveInspection{}, observationErr
	}
	if operationErr != nil {
		return ArchiveInspection{}, operationErr
	}
	return result, nil
}

func (workflow *ObservedWorkflow) PrepareReleaseAttestation(activation ActivationArchive, input ReleaseAttestationInput) (UnsignedReleaseAttestation, error) {
	if err := workflow.beginOperation(); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	defer workflow.active.Store(false)
	result, operationErr := prepareReleaseAttestation(activation, input)
	facts := lifecycleActivationFacts(activation)
	facts.ReleaseWorkflowIdentity = lifecycleIdentifier(input.ReleaseWorkflowIdentity)
	facts.PresentedReviewReceiptCount, facts.PresentedAcceptedReviewCount = lifecycleReviewFacts(input.ReviewReceipts)
	facts.PresentedWaiverReceiptCount, facts.PresentedApprovedWaiverCount = lifecycleWaiverFacts(input.WaiverReceipts)
	facts.ReviewApprovalTreatment = LifecycleTreatmentPresentedUnverified
	facts.WaiverApprovalTreatment = LifecycleTreatmentPresentedUnverified
	facts.PresentedOfflineReportDigest = lifecycleDigest(input.OfflineCheckReceipt.ReportDigest)
	if operationErr == nil {
		facts.ReleaseAttestationID = lifecycleDigest(result.AttestationID)
		facts.SigningRequestPAEDigest = lifecycleDigest(result.SigningRequest.PAEDigest)
	}
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowRelease, LifecycleStagePrepareReleaseAttestation, facts, operationErr)
	if observationErr := workflow.observe(event); observationErr != nil {
		return UnsignedReleaseAttestation{}, observationErr
	}
	if operationErr != nil {
		return UnsignedReleaseAttestation{}, operationErr
	}
	return result, nil
}

func (workflow *ObservedWorkflow) FinalizeReleaseHandoff(activation ActivationArchive, unsigned UnsignedReleaseAttestation, envelope []byte, signing PresentedSigningResult) (ImmutableReleaseHandoff, error) {
	if err := workflow.beginOperation(); err != nil {
		return ImmutableReleaseHandoff{}, err
	}
	defer workflow.active.Store(false)
	result, operationErr := finalizeReleaseHandoff(activation, unsigned, envelope, signing)
	facts := lifecycleActivationFacts(activation)
	facts.ReleaseAttestationID = lifecycleDigest(unsigned.AttestationID)
	facts.ReleaseWorkflowIdentity = lifecycleIdentifier(unsigned.Payload.ReleaseWorkflowIdentity)
	facts.SigningRequestPAEDigest = lifecycleDigest(unsigned.SigningRequest.PAEDigest)
	facts.SigningWorkflowIdentity = lifecycleIdentifier(signing.WorkflowIdentity)
	facts.SigningResultTreatment = LifecycleTreatmentPresentedUnverified
	facts.PresentedSigningReceiptCount = boundedLifecycleCount(len(signing.Receipts), MaxEnvelopeSignatures)
	facts.PresentedSigningReceiptSetDigest = lifecycleDigest(signing.ReceiptSetDigest)
	facts.PresentedReviewReceiptCount, facts.PresentedAcceptedReviewCount = lifecyclePresentedReviewFacts(unsigned.Payload.PresentedReviewReceipts)
	facts.PresentedWaiverReceiptCount, facts.PresentedApprovedWaiverCount = lifecyclePresentedWaiverFacts(unsigned.Payload.PresentedWaiverReceipts)
	facts.ReviewApprovalTreatment = LifecycleTreatmentPresentedUnverified
	facts.WaiverApprovalTreatment = LifecycleTreatmentPresentedUnverified
	applyLifecycleThresholdFacts(&facts, unsigned.SigningRequest.RequiredSignatureThreshold, len(signing.Receipts))
	facts.PresentedOfflineReportDigest = lifecycleDigest(unsigned.Payload.PresentedOfflineCheck.ReportDigest)
	if operationErr == nil {
		facts.ReleaseAttestationEnvelopeDigest = lifecycleDigest(result.ReleaseAttestationEnvelopeDigest)
	}
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowRelease, LifecycleStageFinalizeReleaseHandoff, facts, operationErr)
	if observationErr := workflow.observe(event); observationErr != nil {
		return ImmutableReleaseHandoff{}, observationErr
	}
	if operationErr != nil {
		return ImmutableReleaseHandoff{}, operationErr
	}
	return result, nil
}

func (workflow *ObservedWorkflow) BuildTransportDescriptor(handoff ImmutableReleaseHandoff) (TransportDescriptorV1, []byte, error) {
	if err := workflow.beginOperation(); err != nil {
		return TransportDescriptorV1{}, nil, err
	}
	defer workflow.active.Store(false)
	descriptor, encoded, operationErr := buildTransportDescriptor(handoff)
	facts := lifecycleHandoffFacts(handoff)
	event := terminalLifecycleEvent(workflow.context, LifecycleWorkflowTransport, LifecycleStageBuildTransportDescriptor, facts, operationErr)
	if observationErr := workflow.observe(event); observationErr != nil {
		return TransportDescriptorV1{}, nil, observationErr
	}
	if operationErr != nil {
		return TransportDescriptorV1{}, nil, operationErr
	}
	return descriptor, encoded, nil
}
