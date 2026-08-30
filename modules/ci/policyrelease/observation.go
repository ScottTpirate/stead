package policyrelease

import (
	"strings"
	"sync/atomic"
)

const (
	LifecycleObservationSchemaVersion = "1.0.0"
	LifecycleObservationProducerOwner = "WS-09"
	LifecycleObservationDurableOwner  = "WS-07"
	MaxLifecycleIdentifierBytes       = 128
)

type LifecycleWorkflowCode string

const (
	LifecycleWorkflowActivation LifecycleWorkflowCode = "policy_activation"
	LifecycleWorkflowRelease    LifecycleWorkflowCode = "policy_release"
	LifecycleWorkflowTransport  LifecycleWorkflowCode = "policy_transport"
)

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

// LifecycleContext is bounded operation metadata supplied by the WS-09
// workflow. It is observation-only and is never passed to an artifact builder.
type LifecycleContext struct {
	OperationID   string `json:"operation_id"`
	CorrelationID string `json:"correlation_id"`
	CausationID   string `json:"causation_id"`
}

// LifecycleFacts contains only bounded counts, booleans, and syntactically
// valid SHA-256 identities already present at the workflow boundary. It cannot
// carry artifact bodies, paths, parser text, signatures, keys, or credentials.
type LifecycleFacts struct {
	ActivationSetID                  string `json:"activation_set_id,omitempty"`
	PolicyBundleID                   string `json:"policy_bundle_id,omitempty"`
	EvidenceManifestDigest           string `json:"evidence_manifest_digest,omitempty"`
	SignedEnvelopeDigest             string `json:"signed_envelope_digest,omitempty"`
	ArchiveDigest                    string `json:"archive_digest,omitempty"`
	ReleaseAttestationID             string `json:"release_attestation_id,omitempty"`
	ReleaseAttestationEnvelopeDigest string `json:"release_attestation_envelope_digest,omitempty"`
	DeploymentPolicyDigest           string `json:"deployment_policy_digest,omitempty"`
	PresentedAssuranceResultDigest   string `json:"presented_assurance_result_digest,omitempty"`
	PresentedSigningReceiptSetDigest string `json:"presented_signing_receipt_set_digest,omitempty"`
	PresentedOfflineReportDigest     string `json:"presented_offline_report_digest,omitempty"`
	PresentedSigningReceiptCount     int    `json:"presented_signing_receipt_count"`
	RequiredSignatureThreshold       int    `json:"required_signature_threshold"`
	DistinctCustodiansRequired       bool   `json:"distinct_custodians_required"`
	PresentedReviewReceiptCount      int    `json:"presented_review_receipt_count"`
	PresentedWaiverReceiptCount      int    `json:"presented_waiver_receipt_count"`
	TrustRecoveryApprovalThreshold   int    `json:"trust_recovery_approval_threshold"`
	LoweringApprovalThreshold        int    `json:"lowering_approval_threshold"`
	EntryCount                       int    `json:"archive_entry_count"`
	FileCount                        int    `json:"archive_file_count"`
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
// provider, filesystem, signing, or authorization capability.
type LifecycleObserver interface {
	ObservePolicyRelease(LifecycleEvent) error
}

type LifecycleObserverFunc func(LifecycleEvent) error

func (observe LifecycleObserverFunc) ObservePolicyRelease(event LifecycleEvent) error {
	return observe(event)
}

// ObservedWorkflow adds fail-closed terminal observation to deterministic
// package operations. One instance represents one serialized lifecycle flow;
// concurrent or callback-reentrant use fails closed without returning outputs.
type ObservedWorkflow struct {
	context            LifecycleContext
	observer           LifecycleObserver
	notifying          atomic.Bool
	reentrancyDetected atomic.Bool
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

func boundedLifecycleThreshold(value, maximum int) int {
	if value < 1 || value > maximum {
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

func lifecyclePolicyFacts(policy DeploymentPolicyBinding) LifecycleFacts {
	return LifecycleFacts{
		DeploymentPolicyDigest:         lifecycleDigest(policy.Digest),
		PresentedAssuranceResultDigest: lifecycleDigest(policy.PresentedAssuranceResultDigest),
		RequiredSignatureThreshold:     boundedLifecycleThreshold(policy.PolicySignatureThreshold, MaxEnvelopeSignatures),
		DistinctCustodiansRequired:     policy.DistinctSigningCustodians,
		TrustRecoveryApprovalThreshold: boundedLifecycleThreshold(policy.TrustRecoveryApprovalThreshold, MaxMetadataEntries),
		LoweringApprovalThreshold:      boundedLifecycleThreshold(policy.LoweringApprovalThreshold, MaxMetadataEntries),
	}
}

func lifecycleActivationFacts(activation ActivationArchive) LifecycleFacts {
	facts := lifecyclePolicyFacts(activation.Unsigned.Manifest.DeploymentPolicy)
	facts.ActivationSetID = lifecycleDigest(activation.Unsigned.ActivationSetID)
	facts.PolicyBundleID = lifecycleDigest(activation.Unsigned.PolicyBundleID)
	facts.EvidenceManifestDigest = lifecycleDigest(activation.Unsigned.EvidenceManifestDigest)
	facts.SignedEnvelopeDigest = lifecycleDigest(activation.SignedEnvelopeDigest)
	facts.ArchiveDigest = lifecycleDigest(activation.ArchiveDigest)
	facts.PresentedSigningReceiptSetDigest = lifecycleDigest(activation.PresentedActivationSigning.ReceiptSetDigest)
	facts.PresentedSigningReceiptCount = boundedLifecycleCount(len(activation.PresentedActivationSigning.Receipts), MaxEnvelopeSignatures)
	facts.PresentedReviewReceiptCount = boundedLifecycleCount(len(activation.Unsigned.EvidenceManifest.ReviewReceipts), MaxReviewReceipts)
	facts.PresentedWaiverReceiptCount = boundedLifecycleCount(len(activation.Unsigned.EvidenceManifest.WaiverReceipts), MaxWaiverReceipts)
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
		PresentedSigningReceiptCount:     boundedLifecycleCount(len(handoff.PresentedReleaseSigning.Receipts), MaxEnvelopeSignatures),
		RequiredSignatureThreshold:       boundedLifecycleThreshold(handoff.PresentedReleaseSignatures.RequestedSignatureThreshold, MaxEnvelopeSignatures),
		DistinctCustodiansRequired:       handoff.PresentedReleaseSignatures.DistinctCustodianClaimsRequested,
	}
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

func (workflow *ObservedWorkflow) observe(event LifecycleEvent) (err error) {
	if workflow == nil || workflow.observer == nil {
		return contractError("lifecycle_observer_failed", "observer", nil)
	}
	if !workflow.notifying.CompareAndSwap(false, true) {
		workflow.reentrancyDetected.Store(true)
		return contractError("lifecycle_observer_failed", "observer", nil)
	}
	workflow.reentrancyDetected.Store(false)
	defer func() {
		if recover() != nil {
			err = contractError("lifecycle_observer_failed", "observer", nil)
		}
		if workflow.reentrancyDetected.Swap(false) {
			err = contractError("lifecycle_observer_failed", "observer", nil)
		}
		workflow.notifying.Store(false)
	}()
	if callbackErr := workflow.observer.ObservePolicyRelease(event); callbackErr != nil {
		return contractError("lifecycle_observer_failed", "observer", nil)
	}
	return nil
}

func (workflow *ObservedWorkflow) PrepareUnsigned(input BuildInput) (UnsignedActivation, error) {
	result, operationErr := PrepareUnsigned(input)
	facts := lifecyclePolicyFacts(input.Manifest.DeploymentPolicy)
	facts.PresentedReviewReceiptCount = boundedLifecycleCount(len(input.Evidence.ReviewReceipts), MaxReviewReceipts)
	facts.PresentedWaiverReceiptCount = boundedLifecycleCount(len(input.Evidence.WaiverReceipts), MaxWaiverReceipts)
	if operationErr == nil {
		facts.ActivationSetID = lifecycleDigest(result.ActivationSetID)
		facts.PolicyBundleID = lifecycleDigest(result.PolicyBundleID)
		facts.EvidenceManifestDigest = lifecycleDigest(result.EvidenceManifestDigest)
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
	result, operationErr := FinalizeActivationArchive(unsigned, envelope, signing)
	facts := lifecyclePolicyFacts(unsigned.Manifest.DeploymentPolicy)
	facts.ActivationSetID = lifecycleDigest(unsigned.ActivationSetID)
	facts.PolicyBundleID = lifecycleDigest(unsigned.PolicyBundleID)
	facts.EvidenceManifestDigest = lifecycleDigest(unsigned.EvidenceManifestDigest)
	facts.PresentedSigningReceiptCount = boundedLifecycleCount(len(signing.Receipts), MaxEnvelopeSignatures)
	facts.PresentedSigningReceiptSetDigest = lifecycleDigest(signing.ReceiptSetDigest)
	facts.PresentedReviewReceiptCount = boundedLifecycleCount(len(unsigned.EvidenceManifest.ReviewReceipts), MaxReviewReceipts)
	facts.PresentedWaiverReceiptCount = boundedLifecycleCount(len(unsigned.EvidenceManifest.WaiverReceipts), MaxWaiverReceipts)
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
	result, operationErr := InspectArchive(archive)
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
	result, operationErr := ValidateArchive(archive, envelope, files)
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
	result, operationErr := PrepareReleaseAttestation(activation, input)
	facts := lifecycleActivationFacts(activation)
	facts.PresentedReviewReceiptCount = boundedLifecycleCount(len(input.ReviewReceipts), MaxReviewReceipts)
	facts.PresentedWaiverReceiptCount = boundedLifecycleCount(len(input.WaiverReceipts), MaxWaiverReceipts)
	facts.PresentedOfflineReportDigest = lifecycleDigest(input.OfflineCheckReceipt.ReportDigest)
	if operationErr == nil {
		facts.ReleaseAttestationID = lifecycleDigest(result.AttestationID)
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
	result, operationErr := FinalizeReleaseHandoff(activation, unsigned, envelope, signing)
	facts := lifecycleActivationFacts(activation)
	facts.ReleaseAttestationID = lifecycleDigest(unsigned.AttestationID)
	facts.PresentedSigningReceiptCount = boundedLifecycleCount(len(signing.Receipts), MaxEnvelopeSignatures)
	facts.PresentedSigningReceiptSetDigest = lifecycleDigest(signing.ReceiptSetDigest)
	facts.PresentedReviewReceiptCount = boundedLifecycleCount(len(unsigned.Payload.PresentedReviewReceipts), MaxReviewReceipts)
	facts.PresentedWaiverReceiptCount = boundedLifecycleCount(len(unsigned.Payload.PresentedWaiverReceipts), MaxWaiverReceipts)
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
	descriptor, encoded, operationErr := BuildTransportDescriptor(handoff)
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
