package policyrelease

import (
	"bytes"
	"reflect"
)

func validateFinalReviewState(reviews []ReviewerDisposition, waivers []Waiver) error {
	if len(reviews) == 0 {
		return contractError("missing_final_approval", "final_approvals", nil)
	}
	if err := validateReviewsAndWaivers(reviews, waivers); err != nil {
		return err
	}
	for _, review := range reviews {
		if review.Disposition != "accept" {
			return contractError("release_review_not_accepted", "final_approvals", nil)
		}
	}
	for _, waiver := range waivers {
		if waiver.Disposition != "approved" {
			return contractError("release_waiver_not_approved", "waivers", nil)
		}
	}
	return nil
}

// PrepareReleaseAttestation constructs the post-signing payload only after the
// exact activation envelope and archive identities exist.
func PrepareReleaseAttestation(activation ActivationArchive, input ReleaseAttestationInput) (UnsignedReleaseAttestation, error) {
	if err := validateUnsignedActivation(activation.Unsigned); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if err := requireDigestMatches("signed_envelope_digest", activation.SignedEnvelopeDigest, activation.EnvelopeBytes); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if err := requireDigestMatches("archive_digest", activation.ArchiveDigest, activation.ArchiveBytes); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if _, err := ValidateArchive(activation.ArchiveBytes, activation.EnvelopeBytes, activation.Unsigned.Manifest.Files); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	parsedActivation, err := validateExpectedEnvelope(activation.EnvelopeBytes, activation.Unsigned.ManifestPayload, ActivationManifestPayloadType)
	if err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	activationThreshold, err := validateSigningResult(parsedActivation, activation.ActivationSigning, activation.Unsigned.Manifest.DeploymentPolicy)
	if err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if !reflect.DeepEqual(activationThreshold, activation.Threshold) {
		return UnsignedReleaseAttestation{}, contractError("activation_threshold_result_mismatch", "activation.threshold", nil)
	}
	if err := validateIdentifier("release_workflow_identity", input.ReleaseWorkflowIdentity); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if err := validateFinalReviewState(input.FinalApprovals, input.Waivers); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if input.ReleaseWorkflowIdentity == activation.Unsigned.EvidenceManifest.BuilderIdentity || input.ReleaseWorkflowIdentity == activation.Unsigned.EvidenceManifest.BuildWorkflowIdentity {
		return UnsignedReleaseAttestation{}, contractError("builder_release_workflow_not_separated", "release_workflow_identity", nil)
	}
	for _, review := range input.FinalApprovals {
		if review.ReviewerID == activation.Unsigned.EvidenceManifest.BuilderIdentity || review.ReviewerID == activation.Unsigned.EvidenceManifest.BuildWorkflowIdentity || review.ReviewerID == input.ReleaseWorkflowIdentity || review.ReviewerID == activation.ActivationSigning.WorkflowIdentity {
			return UnsignedReleaseAttestation{}, contractError("self_approved_release", "final_approvals", nil)
		}
	}
	if input.NetworkDisabledVerification.Outcome != "pass" || input.NetworkDisabledVerification.VerifiedArchiveDigest != activation.ArchiveDigest {
		return UnsignedReleaseAttestation{}, contractError("offline_verification_not_bound", "network_disabled_verification", nil)
	}
	if err := validateDigest("network_disabled_verification.result_digest", input.NetworkDisabledVerification.ResultDigest); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	payload := ReleaseAttestationV1{
		SchemaVersion:                     "1.0.0",
		ActivationSetID:                   activation.Unsigned.ActivationSetID,
		SignedEnvelopeDigest:              activation.SignedEnvelopeDigest,
		ArchiveDigest:                     activation.ArchiveDigest,
		EvidenceManifestDigest:            activation.Unsigned.EvidenceManifestDigest,
		PolicyBundleID:                    activation.Unsigned.PolicyBundleID,
		OpenFGAModelSourceDigest:          activation.Unsigned.Manifest.OpenFGAModel.SourceDigest,
		Trust:                             activation.Unsigned.Manifest.Trust,
		DeploymentPolicy:                  activation.Unsigned.Manifest.DeploymentPolicy,
		ActivationSigningWorkflowIdentity: activation.ActivationSigning.WorkflowIdentity,
		ActivationSigningResultDigest:     activation.ActivationSigning.ResultDigest,
		ActivationThreshold:               activation.Threshold,
		SourceRevision:                    activation.Unsigned.Manifest.SourceRevision,
		BuilderIdentity:                   activation.Unsigned.EvidenceManifest.BuilderIdentity,
		ReleaseWorkflowIdentity:           input.ReleaseWorkflowIdentity,
		FinalApprovals:                    sortReviews(input.FinalApprovals),
		Waivers:                           sortWaivers(input.Waivers),
		NetworkDisabledVerification:       input.NetworkDisabledVerification,
	}
	encoded, err := marshalCanonical(payload)
	if err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if bytes.Contains(encoded, []byte("release_attestation_id")) || bytes.Contains(encoded, []byte("release_attestation_envelope_digest")) {
		return UnsignedReleaseAttestation{}, contractError("self_referential_attestation", "release_attestation", nil)
	}
	request, requestBytes, err := makeSigningRequest("policy_release_attestation", ReleaseAttestationPayloadType, encoded, manifestInputFromActivation(activation))
	if err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	return UnsignedReleaseAttestation{
		Payload:             payload,
		PayloadBytes:        encoded,
		AttestationID:       SHA256Digest(encoded),
		SigningRequest:      request,
		SigningRequestBytes: requestBytes,
	}, nil
}

func manifestInputFromActivation(activation ActivationArchive) ManifestInput {
	return ManifestInput{
		DeploymentPolicy: activation.Unsigned.Manifest.DeploymentPolicy,
		SourceRevision:   activation.Unsigned.Manifest.SourceRevision,
	}
}

func validateUnsignedAttestation(activation ActivationArchive, unsigned UnsignedReleaseAttestation) error {
	if SHA256Digest(unsigned.PayloadBytes) != unsigned.AttestationID {
		return contractError("release_attestation_identity_mismatch", "release_attestation_id", nil)
	}
	var decoded ReleaseAttestationV1
	if err := decodeStrict(unsigned.PayloadBytes, &decoded); err != nil {
		return err
	}
	if !reflect.DeepEqual(decoded, unsigned.Payload) {
		return contractError("release_attestation_struct_mismatch", "release_attestation", nil)
	}
	canonical, err := marshalCanonical(unsigned.Payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, unsigned.PayloadBytes) {
		return contractError("noncanonical_release_attestation", "release_attestation", nil)
	}
	want, err := PrepareReleaseAttestation(activation, ReleaseAttestationInput{
		ReleaseWorkflowIdentity:     unsigned.Payload.ReleaseWorkflowIdentity,
		FinalApprovals:              unsigned.Payload.FinalApprovals,
		Waivers:                     unsigned.Payload.Waivers,
		NetworkDisabledVerification: unsigned.Payload.NetworkDisabledVerification,
	})
	if err != nil {
		return err
	}
	if !bytes.Equal(want.PayloadBytes, unsigned.PayloadBytes) {
		return contractError("release_attestation_binding_mismatch", "release_attestation", nil)
	}
	return nil
}

// FinalizeReleaseHandoff accepts the separately signed release attestation and
// returns the exact immutable pair for independent WS-06 verification.
func FinalizeReleaseHandoff(activation ActivationArchive, unsigned UnsignedReleaseAttestation, envelope []byte, signing SigningResult) (ImmutableReleaseHandoff, error) {
	if err := validateUnsignedAttestation(activation, unsigned); err != nil {
		return ImmutableReleaseHandoff{}, err
	}
	parsed, err := validateExpectedEnvelope(envelope, unsigned.PayloadBytes, ReleaseAttestationPayloadType)
	if err != nil {
		return ImmutableReleaseHandoff{}, err
	}
	threshold, err := validateSigningResult(parsed, signing, activation.Unsigned.Manifest.DeploymentPolicy)
	if err != nil {
		return ImmutableReleaseHandoff{}, err
	}
	if signing.WorkflowIdentity == activation.Unsigned.EvidenceManifest.BuilderIdentity || signing.WorkflowIdentity == activation.Unsigned.EvidenceManifest.BuildWorkflowIdentity || signing.WorkflowIdentity == unsigned.Payload.ReleaseWorkflowIdentity {
		return ImmutableReleaseHandoff{}, contractError("release_signing_workflow_not_separated", "signing_result.workflow_identity", nil)
	}
	policy := activation.Unsigned.Manifest.DeploymentPolicy
	return ImmutableReleaseHandoff{
		ActivationSetID:                  activation.Unsigned.ActivationSetID,
		SignedEnvelopeDigest:             activation.SignedEnvelopeDigest,
		ArchiveDigest:                    activation.ArchiveDigest,
		ReleaseAttestationID:             unsigned.AttestationID,
		ReleaseAttestationEnvelopeDigest: SHA256Digest(envelope),
		PolicyBundleID:                   activation.Unsigned.PolicyBundleID,
		OpenFGAModelSourceDigest:         activation.Unsigned.Manifest.OpenFGAModel.SourceDigest,
		EvidenceManifestDigest:           activation.Unsigned.EvidenceManifestDigest,
		Trust:                            activation.Unsigned.Manifest.Trust,
		DeploymentPolicyID:               policy.PolicyID,
		DeploymentPolicyVersion:          policy.Version,
		DeploymentPolicyDigest:           policy.Digest,
		DisclosureRevocationMode:         policy.DisclosureRevocationMode,
		EvaluatedAssuranceResultDigest:   policy.EvaluatedAssuranceResultDigest,
		SourceRevision:                   activation.Unsigned.Manifest.SourceRevision,
		ActivationSigningResultDigest:    activation.ActivationSigning.ResultDigest,
		ActivationThreshold:              activation.Threshold,
		ArchiveBytes:                     append([]byte(nil), activation.ArchiveBytes...),
		ReleaseAttestationEnvelopeBytes:  append([]byte(nil), envelope...),
		ReleaseSigning:                   copySigningResult(signing),
		ReleaseThreshold:                 threshold,
	}, nil
}

func copySigningResult(signing SigningResult) SigningResult {
	return SigningResult{
		WorkflowIdentity: signing.WorkflowIdentity,
		ResultDigest:     signing.ResultDigest,
		Receipts:         append([]SignatureReceipt(nil), signing.Receipts...),
	}
}

// BuildTransportDescriptor names exact completed bytes but is explicitly
// non-authorizing. It may be embedded by a future approved TUF transport layer;
// it cannot replace either DSSE envelope or the deployment assurance result.
func BuildTransportDescriptor(handoff ImmutableReleaseHandoff) (TransportDescriptorV1, []byte, error) {
	if err := requireDigestMatches("archive_digest", handoff.ArchiveDigest, handoff.ArchiveBytes); err != nil {
		return TransportDescriptorV1{}, nil, err
	}
	if err := requireDigestMatches("release_attestation_envelope_digest", handoff.ReleaseAttestationEnvelopeDigest, handoff.ReleaseAttestationEnvelopeBytes); err != nil {
		return TransportDescriptorV1{}, nil, err
	}
	descriptor := TransportDescriptorV1{
		SchemaVersion:                    "1.0.0",
		Authority:                        "non_authorizing_transport_only",
		ArchiveDigest:                    handoff.ArchiveDigest,
		ReleaseAttestationEnvelopeDigest: handoff.ReleaseAttestationEnvelopeDigest,
	}
	encoded, err := marshalCanonical(descriptor)
	if err != nil {
		return TransportDescriptorV1{}, nil, err
	}
	return descriptor, encoded, nil
}
