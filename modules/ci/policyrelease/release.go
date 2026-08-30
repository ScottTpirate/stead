package policyrelease

import (
	"bytes"
	"reflect"
)

func validateFinalReviewState(reviews []ReviewReceipt, waivers []WaiverReceipt, subjectDigest string) error {
	if len(reviews) == 0 {
		return contractError("missing_presented_final_review", "review_receipts", nil)
	}
	if err := validateReviewsAndWaivers(reviews, waivers, subjectDigest); err != nil {
		return err
	}
	for _, review := range reviews {
		if review.ClaimedDisposition != "accept" {
			return contractError("presented_release_review_not_accept", "review_receipts", nil)
		}
	}
	for _, waiver := range waivers {
		if waiver.ClaimedDisposition != "approved" {
			return contractError("presented_release_waiver_not_approved", "waiver_receipts", nil)
		}
	}
	return nil
}

// PrepareReleaseAttestation constructs the post-signing payload only after the
// exact activation envelope and archive identities exist.
func PrepareReleaseAttestation(activation ActivationArchive, input ReleaseAttestationInput) (UnsignedReleaseAttestation, error) {
	if err := preflightActivationArtifacts(activation); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if err := preflightReviewAndWaiverCounts(input.ReviewReceipts, input.WaiverReceipts); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
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
	presentedActivationSignatures, err := validatePresentedSigningResult(parsedActivation, activation.PresentedActivationSigning, activation.Unsigned.Manifest.DeploymentPolicy)
	if err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if !reflect.DeepEqual(presentedActivationSignatures, activation.PresentedActivationSignatures) {
		return UnsignedReleaseAttestation{}, contractError("presented_activation_signature_summary_mismatch", "activation.presented_signatures", nil)
	}
	if err := validateIdentifier("release_workflow_identity", input.ReleaseWorkflowIdentity); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if err := validateFinalReviewState(input.ReviewReceipts, input.WaiverReceipts, activation.ArchiveDigest); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if input.ReleaseWorkflowIdentity == activation.Unsigned.EvidenceManifest.BuilderIdentity || input.ReleaseWorkflowIdentity == activation.Unsigned.EvidenceManifest.BuildWorkflowIdentity {
		return UnsignedReleaseAttestation{}, contractError("builder_release_workflow_not_separated", "release_workflow_identity", nil)
	}
	for _, review := range input.ReviewReceipts {
		if review.ReviewerID == activation.Unsigned.EvidenceManifest.BuilderIdentity || review.ReviewerID == activation.Unsigned.EvidenceManifest.BuildWorkflowIdentity || review.ReviewerID == input.ReleaseWorkflowIdentity || review.ReviewerID == activation.PresentedActivationSigning.WorkflowIdentity {
			return UnsignedReleaseAttestation{}, contractError("self_presented_release_review", "review_receipts", nil)
		}
	}
	if input.OfflineCheckReceipt.ClaimedOutcome != "pass" || input.OfflineCheckReceipt.SubjectArchiveDigest != activation.ArchiveDigest {
		return UnsignedReleaseAttestation{}, contractError("presented_offline_check_not_bound", "offline_check_receipt", nil)
	}
	if err := validateDigest("offline_check_receipt.report_digest", input.OfflineCheckReceipt.ReportDigest); err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	payload := ReleaseAttestationV1{
		SchemaVersion:                       "1.0.0",
		Authority:                           NonAuthorizingHandoffAuthority,
		ActivationSetID:                     activation.Unsigned.ActivationSetID,
		SignedEnvelopeDigest:                activation.SignedEnvelopeDigest,
		ArchiveDigest:                       activation.ArchiveDigest,
		EvidenceManifestDigest:              activation.Unsigned.EvidenceManifestDigest,
		PolicyBundleID:                      activation.Unsigned.PolicyBundleID,
		OpenFGAModelSourceDigest:            activation.Unsigned.Manifest.OpenFGAModel.SourceDigest,
		Trust:                               activation.Unsigned.Manifest.Trust,
		DeploymentPolicy:                    activation.Unsigned.Manifest.DeploymentPolicy,
		PresentedActivationWorkflowIdentity: activation.PresentedActivationSigning.WorkflowIdentity,
		PresentedActivationReceiptSetDigest: activation.PresentedActivationSigning.ReceiptSetDigest,
		PresentedActivationSignatures:       copyPresentedSignatureSummary(activation.PresentedActivationSignatures),
		SourceRevision:                      activation.Unsigned.Manifest.SourceRevision,
		BuilderIdentity:                     activation.Unsigned.EvidenceManifest.BuilderIdentity,
		ReleaseWorkflowIdentity:             input.ReleaseWorkflowIdentity,
		PresentedReviewReceipts:             presentReviews(input.ReviewReceipts),
		PresentedWaiverReceipts:             presentWaivers(input.WaiverReceipts),
		PresentedOfflineCheck: PresentedOfflineCheckEvidenceV1{
			Treatment:            PresentedMaterialTreatment,
			ClaimedOutcome:       input.OfflineCheckReceipt.ClaimedOutcome,
			SubjectArchiveDigest: input.OfflineCheckReceipt.SubjectArchiveDigest,
			ReportDigest:         input.OfflineCheckReceipt.ReportDigest,
		},
	}
	encoded, err := marshalCanonical(payload)
	if err != nil {
		return UnsignedReleaseAttestation{}, err
	}
	if bytes.Contains(encoded, []byte("release_attestation_id")) || bytes.Contains(encoded, []byte("release_attestation_envelope_digest")) {
		return UnsignedReleaseAttestation{}, contractError("self_referential_attestation", "release_attestation", nil)
	}
	if len(encoded) > MaxDecodedPayloadBytes {
		return UnsignedReleaseAttestation{}, contractError("release_attestation_payload_size_limit", "release_attestation", nil)
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

// preflightActivationArtifacts bounds caller-controlled activation bytes before
// any identity hashing, archive inspection, or defensive copying occurs.
func preflightActivationArtifacts(activation ActivationArchive) error {
	if len(activation.EnvelopeBytes) == 0 || len(activation.EnvelopeBytes) > MaxEnvelopeBytes ||
		len(activation.ArchiveBytes) == 0 || len(activation.ArchiveBytes) > MaxArchiveBytes {
		return contractError("activation_artifact_size_limit", "activation", nil)
	}
	return nil
}

func manifestInputFromActivation(activation ActivationArchive) ManifestInput {
	return ManifestInput{
		DeploymentPolicy: activation.Unsigned.Manifest.DeploymentPolicy,
		SourceRevision:   activation.Unsigned.Manifest.SourceRevision,
	}
}

func validateUnsignedAttestation(activation ActivationArchive, unsigned UnsignedReleaseAttestation) error {
	if err := preflightActivationArtifacts(activation); err != nil {
		return err
	}
	if len(unsigned.PayloadBytes) > MaxDecodedPayloadBytes {
		return contractError("release_attestation_payload_size_limit", "release_attestation", nil)
	}
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
		ReleaseWorkflowIdentity: unsigned.Payload.ReleaseWorkflowIdentity,
		ReviewReceipts:          reviewReceiptInputs(unsigned.Payload.PresentedReviewReceipts),
		WaiverReceipts:          waiverReceiptInputs(unsigned.Payload.PresentedWaiverReceipts),
		OfflineCheckReceipt: OfflineCheckReceipt{
			ClaimedOutcome:       unsigned.Payload.PresentedOfflineCheck.ClaimedOutcome,
			SubjectArchiveDigest: unsigned.Payload.PresentedOfflineCheck.SubjectArchiveDigest,
			ReportDigest:         unsigned.Payload.PresentedOfflineCheck.ReportDigest,
		},
	})
	if err != nil {
		return err
	}
	if !bytes.Equal(want.PayloadBytes, unsigned.PayloadBytes) {
		return contractError("release_attestation_binding_mismatch", "release_attestation", nil)
	}
	if !reflect.DeepEqual(unsigned.SigningRequest, want.SigningRequest) || !bytes.Equal(unsigned.SigningRequestBytes, want.SigningRequestBytes) {
		return contractError("signing_request_binding_mismatch", "signing_request", nil)
	}
	return nil
}

// FinalizeReleaseHandoff accepts the separately signed release attestation and
// returns the exact immutable pair for independent WS-06 verification.
func FinalizeReleaseHandoff(activation ActivationArchive, unsigned UnsignedReleaseAttestation, envelope []byte, signing PresentedSigningResult) (ImmutableReleaseHandoff, error) {
	if err := preflightActivationArtifacts(activation); err != nil {
		return ImmutableReleaseHandoff{}, err
	}
	if err := validateUnsignedAttestation(activation, unsigned); err != nil {
		return ImmutableReleaseHandoff{}, err
	}
	parsed, err := validateExpectedEnvelope(envelope, unsigned.PayloadBytes, ReleaseAttestationPayloadType)
	if err != nil {
		return ImmutableReleaseHandoff{}, err
	}
	presentedReleaseSignatures, err := validatePresentedSigningResult(parsed, signing, activation.Unsigned.Manifest.DeploymentPolicy)
	if err != nil {
		return ImmutableReleaseHandoff{}, err
	}
	if signing.WorkflowIdentity == activation.Unsigned.EvidenceManifest.BuilderIdentity || signing.WorkflowIdentity == activation.Unsigned.EvidenceManifest.BuildWorkflowIdentity || signing.WorkflowIdentity == unsigned.Payload.ReleaseWorkflowIdentity {
		return ImmutableReleaseHandoff{}, contractError("release_signing_workflow_not_separated", "presented_signing_result.workflow_identity", nil)
	}
	policy := activation.Unsigned.Manifest.DeploymentPolicy
	return ImmutableReleaseHandoff{
		Authority:                           NonAuthorizingHandoffAuthority,
		ActivationSetID:                     activation.Unsigned.ActivationSetID,
		SignedEnvelopeDigest:                activation.SignedEnvelopeDigest,
		ArchiveDigest:                       activation.ArchiveDigest,
		ReleaseAttestationID:                unsigned.AttestationID,
		ReleaseAttestationEnvelopeDigest:    SHA256Digest(envelope),
		PolicyBundleID:                      activation.Unsigned.PolicyBundleID,
		OpenFGAModelSourceDigest:            activation.Unsigned.Manifest.OpenFGAModel.SourceDigest,
		EvidenceManifestDigest:              activation.Unsigned.EvidenceManifestDigest,
		Trust:                               activation.Unsigned.Manifest.Trust,
		DeploymentPolicyID:                  policy.PolicyID,
		DeploymentPolicyVersion:             policy.Version,
		DeploymentPolicyDigest:              policy.Digest,
		DisclosureRevocationMode:            policy.DisclosureRevocationMode,
		PresentedAssuranceResultDigest:      policy.PresentedAssuranceResultDigest,
		SourceRevision:                      activation.Unsigned.Manifest.SourceRevision,
		PresentedActivationReceiptSetDigest: activation.PresentedActivationSigning.ReceiptSetDigest,
		PresentedActivationSignatures:       copyPresentedSignatureSummary(activation.PresentedActivationSignatures),
		ArchiveBytes:                        cloneSlice(activation.ArchiveBytes),
		ReleaseAttestationEnvelopeBytes:     cloneSlice(envelope),
		PresentedReleaseSigning:             copyPresentedSigningResult(signing),
		PresentedReleaseSignatures:          copyPresentedSignatureSummary(presentedReleaseSignatures),
		RequiredConsumerVerification: ConsumerVerificationRequirementV1{
			Owner:  RequiredConsumerVerificationOwner,
			Status: "required_not_performed_by_ws09",
			Checks: []string{
				"exact_archive_and_attestation_pair",
				"dsse_cryptographic_signatures",
				"spki_identity_and_trust_state",
				"key_purpose_status_validity_and_revocation",
				"signature_threshold_and_distinct_custodians",
				"evidence_review_waiver_and_offline_claims",
				"deployment_assurance_and_activation_prerequisites",
			},
		},
	}, nil
}

func copyPresentedSigningResult(signing PresentedSigningResult) PresentedSigningResult {
	return PresentedSigningResult{
		Treatment:        signing.Treatment,
		WorkflowIdentity: signing.WorkflowIdentity,
		ReceiptSetDigest: signing.ReceiptSetDigest,
		Receipts:         cloneSlice(signing.Receipts),
	}
}

func copyPresentedSignatureSummary(summary PresentedSignatureSummary) PresentedSignatureSummary {
	result := summary
	result.KeyIDHints = cloneSlice(summary.KeyIDHints)
	result.ClaimedCustodianIDs = cloneSlice(summary.ClaimedCustodianIDs)
	return result
}

// BuildTransportDescriptor names exact completed bytes but is explicitly
// non-authorizing. It may be embedded by a future approved TUF transport layer;
// it cannot replace either DSSE envelope or the deployment assurance result.
func BuildTransportDescriptor(handoff ImmutableReleaseHandoff) (TransportDescriptorV1, []byte, error) {
	if len(handoff.ArchiveBytes) == 0 || len(handoff.ArchiveBytes) > MaxArchiveBytes || len(handoff.ReleaseAttestationEnvelopeBytes) == 0 || len(handoff.ReleaseAttestationEnvelopeBytes) > MaxEnvelopeBytes {
		return TransportDescriptorV1{}, nil, contractError("transport_artifact_size_limit", "handoff", nil)
	}
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
