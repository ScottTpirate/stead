package policyrelease

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

const evidenceManifestPath = "evidence/pre-signing-evidence-manifest.json"

var requiredContractRoles = map[string]struct{}{
	"decision_table": {},
	"input_schema":   {},
	"output_schema":  {},
	"registries":     {},
}

func copyFile(file File) File {
	return File{Path: file.Path, MediaType: file.MediaType, Content: cloneSlice(file.Content)}
}

// cloneSlice preserves the distinction between nil and a non-nil empty slice.
// That distinction is material for the canonical JSON structures in this
// package: collection fields are encoded as arrays, never null.
func cloneSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	result := make([]T, len(values))
	copy(result, values)
	return result
}

func presentReviews(reviews []ReviewReceipt) []PresentedReviewReceiptV1 {
	result := make([]PresentedReviewReceiptV1, 0, len(reviews))
	for _, review := range reviews {
		result = append(result, PresentedReviewReceiptV1{
			Treatment:          PresentedMaterialTreatment,
			ReviewerID:         review.ReviewerID,
			Role:               review.Role,
			SubjectDigest:      review.SubjectDigest,
			RecordDigest:       review.RecordDigest,
			ClaimedDisposition: review.ClaimedDisposition,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i].Role + "\x00" + result[i].ReviewerID + "\x00" + result[i].SubjectDigest + "\x00" + result[i].RecordDigest + "\x00" + result[i].ClaimedDisposition
		right := result[j].Role + "\x00" + result[j].ReviewerID + "\x00" + result[j].SubjectDigest + "\x00" + result[j].RecordDigest + "\x00" + result[j].ClaimedDisposition
		return left < right
	})
	return result
}

func presentWaivers(waivers []WaiverReceipt) []PresentedWaiverReceiptV1 {
	result := make([]PresentedWaiverReceiptV1, 0, len(waivers))
	for _, waiver := range waivers {
		result = append(result, PresentedWaiverReceiptV1{
			Treatment:          PresentedMaterialTreatment,
			WaiverID:           waiver.WaiverID,
			SubjectDigest:      waiver.SubjectDigest,
			RecordDigest:       waiver.RecordDigest,
			ClaimedDisposition: waiver.ClaimedDisposition,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].WaiverID+"\x00"+result[i].SubjectDigest+"\x00"+result[i].RecordDigest < result[j].WaiverID+"\x00"+result[j].SubjectDigest+"\x00"+result[j].RecordDigest
	})
	return result
}

func reviewReceiptInputs(reviews []PresentedReviewReceiptV1) []ReviewReceipt {
	result := make([]ReviewReceipt, 0, len(reviews))
	for _, review := range reviews {
		result = append(result, ReviewReceipt{ReviewerID: review.ReviewerID, Role: review.Role, SubjectDigest: review.SubjectDigest, RecordDigest: review.RecordDigest, ClaimedDisposition: review.ClaimedDisposition})
	}
	return result
}

func waiverReceiptInputs(waivers []PresentedWaiverReceiptV1) []WaiverReceipt {
	result := make([]WaiverReceipt, 0, len(waivers))
	for _, waiver := range waivers {
		result = append(result, WaiverReceipt{WaiverID: waiver.WaiverID, SubjectDigest: waiver.SubjectDigest, RecordDigest: waiver.RecordDigest, ClaimedDisposition: waiver.ClaimedDisposition})
	}
	return result
}

func validateReviewsAndWaivers(reviews []ReviewReceipt, waivers []WaiverReceipt, subjectDigest string) error {
	seenReviews := make(map[string]struct{}, len(reviews))
	for _, review := range reviews {
		if err := validateReview(review, subjectDigest); err != nil {
			return err
		}
		key := review.Role + "\x00" + review.ReviewerID
		if _, exists := seenReviews[key]; exists {
			return contractError("duplicate_review", "reviews", nil)
		}
		seenReviews[key] = struct{}{}
	}
	seenWaivers := make(map[string]struct{}, len(waivers))
	for _, waiver := range waivers {
		if err := validateWaiver(waiver, subjectDigest); err != nil {
			return err
		}
		if _, exists := seenWaivers[waiver.WaiverID]; exists {
			return contractError("duplicate_waiver", "waivers", nil)
		}
		seenWaivers[waiver.WaiverID] = struct{}{}
	}
	return nil
}

func validateManifestInput(input ManifestInput) error {
	if err := validateDeploymentPolicy(input.DeploymentPolicy); err != nil {
		return err
	}
	if err := validatePath(input.PolicyContentIndexPath, false); err != nil {
		return err
	}
	if err := validateImmutableRevision("manifest.source_revision", input.SourceRevision); err != nil {
		return err
	}
	if err := validateDigest("manifest.dependency_lock_digest", input.DependencyLockDigest); err != nil {
		return err
	}
	if err := validateOpaqueID("manifest.build_recipe_version", input.BuildRecipeVersion); err != nil {
		return err
	}
	if err := validateIdentifier("manifest.evaluator_contract_version", input.EvaluatorContractVersion); err != nil {
		return err
	}
	if input.IssuedAt.Location() != time.UTC || input.ExpiresAt.Location() != time.UTC || input.IssuedAt.Nanosecond() != 0 || input.ExpiresAt.Nanosecond() != 0 || !input.ExpiresAt.After(input.IssuedAt) {
		return contractError("invalid_activation_validity", "manifest.issued_at/expires_at", nil)
	}
	if err := validateDigest("manifest.trust.trust_set_id", input.Trust.TrustSetID); err != nil {
		return err
	}
	if err := validateDigest("manifest.trust.trust_set_envelope_digest", input.Trust.TrustSetEnvelopeDigest); err != nil {
		return err
	}
	if input.Trust.TrustEpoch == 0 {
		return contractError("invalid_trust_epoch", "manifest.trust.trust_epoch", nil)
	}
	for _, pathValue := range []string{input.OpenFGAModel.SourcePath, input.DeploymentPolicy.Path, input.DeploymentPolicy.PresentedAssuranceResultPath, input.Trust.TrustSetPath, input.Trust.TrustSetEnvelopePath} {
		if err := validatePath(pathValue, false); err != nil {
			return err
		}
	}
	if input.OpenFGAModel.SchemaVersion != "1.1" {
		return contractError("unsupported_openfga_schema", "manifest.openfga_model.schema_version", nil)
	}
	if err := validateDigest("manifest.openfga_model.source_digest", input.OpenFGAModel.SourceDigest); err != nil {
		return err
	}
	if err := validateOpaqueID("manifest.openfga_model.compatibility_id", input.OpenFGAModel.CompatibilityID); err != nil {
		return err
	}
	if err := validateOpaqueID("manifest.openfga_model.tuple_migration_id", input.OpenFGAModel.TupleMigrationID); err != nil {
		return err
	}
	for field, values := range map[string][]string{
		"supported_stead_versions": input.SupportedSteadVersions,
		"required_context_ids":     input.RequiredContextIDs,
		"reason_code_ids":          input.ReasonCodeIDs,
		"obligation_ids":           input.ObligationIDs,
		"explicit_deny_ids":        input.ExplicitDenyIDs,
	} {
		if _, err := sortedUniqueStrings(field, values, false); err != nil {
			return err
		}
	}
	seenPredecessors := make(map[string]struct{}, len(input.CompatiblePredecessorActivationSetIDs))
	for _, value := range input.CompatiblePredecessorActivationSetIDs {
		if err := validateDigest("compatible_predecessor_activation_set_ids", value); err != nil {
			return err
		}
		if _, duplicate := seenPredecessors[value]; duplicate {
			return contractError("duplicate_value", "compatible_predecessor_activation_set_ids", nil)
		}
		seenPredecessors[value] = struct{}{}
	}
	if _, err := sortedUniqueStrings("rollback_constraints", input.RollbackConstraints, false); err != nil {
		return err
	}
	return nil
}

func findBoundFile(files map[string]File, pathValue, digest, mediaType string) error {
	file, ok := files[pathValue]
	if !ok {
		return contractError("missing_bound_file", pathValue, nil)
	}
	if mediaType != "" && file.MediaType != mediaType {
		return contractError("bound_media_type_mismatch", pathValue, nil)
	}
	if SHA256Digest(file.Content) != digest {
		return contractError("bound_digest_mismatch", pathValue, nil)
	}
	return nil
}

func validateAndSortBindings(input ManifestInput, payload map[string]File, profileEvidenceRequirements map[string]string) ([]ContentBinding, []ProfileBinding, error) {
	referenced := map[string]string{input.PolicyContentIndexPath: "policy_content_index"}
	bindings := append([]ContentBinding(nil), input.ContractBindings...)
	seenRoles := make(map[string]struct{}, len(bindings))
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].Role+"\x00"+bindings[i].Path < bindings[j].Role+"\x00"+bindings[j].Path
	})
	for _, binding := range bindings {
		if err := validateIdentifier("contract_binding.role", binding.Role); err != nil {
			return nil, nil, err
		}
		if _, required := requiredContractRoles[binding.Role]; !required {
			return nil, nil, contractError("unknown_contract_binding_role", binding.Role, nil)
		}
		if _, duplicate := seenRoles[binding.Role]; duplicate {
			return nil, nil, contractError("duplicate_contract_binding_role", binding.Role, nil)
		}
		seenRoles[binding.Role] = struct{}{}
		if err := validatePath(binding.Path, false); err != nil {
			return nil, nil, err
		}
		if err := validateDigest("contract_binding.digest", binding.Digest); err != nil {
			return nil, nil, err
		}
		if err := validateMediaType("contract_binding.media_type", binding.MediaType); err != nil {
			return nil, nil, err
		}
		if _, exists := referenced[binding.Path]; exists {
			return nil, nil, contractError("duplicate_content_binding", binding.Path, nil)
		}
		referenced[binding.Path] = binding.Role
		if err := findBoundFile(payload, binding.Path, binding.Digest, binding.MediaType); err != nil {
			return nil, nil, err
		}
	}
	for role := range requiredContractRoles {
		if _, present := seenRoles[role]; !present {
			return nil, nil, contractError("missing_contract_binding_role", role, nil)
		}
	}
	profiles := append([]ProfileBinding(nil), input.Profiles...)
	if len(profiles) == 0 {
		return nil, nil, contractError("missing_security_profile", "profiles", nil)
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].ProfileID+"\x00"+profiles[i].Version < profiles[j].ProfileID+"\x00"+profiles[j].Version
	})
	seenProfiles := make(map[string]struct{}, len(profiles))
	profileSnapshotRequirements := make(map[string]string)
	for _, profile := range profiles {
		if err := validateIdentifier("profile.profile_id", profile.ProfileID); err != nil {
			return nil, nil, err
		}
		if err := validateVersion("profile.version", profile.Version); err != nil {
			return nil, nil, err
		}
		if profile.SchemaID != SecurityProfileSchemaID {
			return nil, nil, contractError("unsupported_security_profile_schema", profile.Path, nil)
		}
		if err := validatePath(profile.Path, false); err != nil {
			return nil, nil, err
		}
		if err := validateDigest("profile.digest", profile.Digest); err != nil {
			return nil, nil, err
		}
		if profile.SigningFormat != ActivationFormatV1 {
			return nil, nil, contractError("unsupported_profile_signing_format", profile.Path, nil)
		}
		if _, duplicate := seenProfiles[profile.ProfileID+"@"+profile.Version]; duplicate {
			return nil, nil, contractError("duplicate_profile_binding", profile.ProfileID, nil)
		}
		seenProfiles[profile.ProfileID+"@"+profile.Version] = struct{}{}
		if _, exists := referenced[profile.Path]; exists {
			return nil, nil, contractError("duplicate_content_binding", profile.Path, nil)
		}
		referenced[profile.Path] = "security_profile"
		if err := findBoundFile(payload, profile.Path, profile.Digest, ""); err != nil {
			return nil, nil, err
		}
		if err := validateSecurityProfileDocument(payload[profile.Path], profile); err != nil {
			return nil, nil, err
		}
		snapshots, evidence, err := profileArtifactRequirements(payload[profile.Path])
		if err != nil {
			return nil, nil, err
		}
		for artifactPath, digest := range snapshots {
			if prior, exists := profileSnapshotRequirements[artifactPath]; exists {
				if prior != digest {
					return nil, nil, contractError("security_profile_artifact_digest_conflict", "profile.authoritative_sources", nil)
				}
				continue
			}
			if _, exists := referenced[artifactPath]; exists {
				return nil, nil, contractError("duplicate_content_binding", "profile.authoritative_sources", nil)
			}
			profileSnapshotRequirements[artifactPath] = digest
			referenced[artifactPath] = "security_profile_authoritative_snapshot"
			if err := findBoundFile(payload, artifactPath, digest, ""); err != nil {
				return nil, nil, err
			}
		}
		for artifactPath, digest := range evidence {
			if prior, exists := profileEvidenceRequirements[artifactPath]; exists && prior != digest {
				return nil, nil, contractError("security_profile_artifact_digest_conflict", "profile.semantics.registry_mappings", nil)
			}
			profileEvidenceRequirements[artifactPath] = digest
		}
	}
	special := []struct {
		path   string
		digest string
		role   string
	}{
		{input.OpenFGAModel.SourcePath, input.OpenFGAModel.SourceDigest, "openfga_model"},
		{input.DeploymentPolicy.Path, input.DeploymentPolicy.Digest, "deployment_policy"},
		{input.DeploymentPolicy.PresentedAssuranceResultPath, input.DeploymentPolicy.PresentedAssuranceResultDigest, "presented_assurance_result"},
		{input.Trust.TrustSetPath, input.Trust.TrustSetID, "trust_set"},
		{input.Trust.TrustSetEnvelopePath, input.Trust.TrustSetEnvelopeDigest, "trust_set_envelope"},
	}
	for _, item := range special {
		if _, exists := referenced[item.path]; exists {
			return nil, nil, contractError("duplicate_content_binding", item.path, nil)
		}
		referenced[item.path] = item.role
		if err := findBoundFile(payload, item.path, item.digest, ""); err != nil {
			return nil, nil, err
		}
	}
	if err := validateDeploymentPolicyDocument(payload[input.DeploymentPolicy.Path], input.DeploymentPolicy, profiles); err != nil {
		return nil, nil, err
	}
	if err := validateTrustSetDocument(payload[input.Trust.TrustSetPath], payload[input.Trust.TrustSetEnvelopePath], input.Trust, input.DeploymentPolicy); err != nil {
		return nil, nil, err
	}
	var assurance PresentedAssuranceEvaluationV1
	assuranceFile := payload[input.DeploymentPolicy.PresentedAssuranceResultPath]
	if assuranceFile.MediaType != "application/json" {
		return nil, nil, contractError("bound_media_type_mismatch", input.DeploymentPolicy.PresentedAssuranceResultPath, nil)
	}
	if err := decodeStrict(assuranceFile.Content, &assurance); err != nil {
		return nil, nil, err
	}
	expectedAssurance := PresentedAssuranceEvaluationV1{
		SchemaVersion:                  "1.0.0",
		Treatment:                      PresentedMaterialTreatment,
		DeploymentPolicyID:             input.DeploymentPolicy.PolicyID,
		DeploymentPolicyVersion:        input.DeploymentPolicy.Version,
		DeploymentPolicyDigest:         input.DeploymentPolicy.Digest,
		DisclosureRevocationMode:       input.DeploymentPolicy.DisclosureRevocationMode,
		PolicySignatureThreshold:       input.DeploymentPolicy.PolicySignatureThreshold,
		DistinctSigningCustodians:      input.DeploymentPolicy.DistinctSigningCustodians,
		TrustRecoveryApprovalThreshold: input.DeploymentPolicy.TrustRecoveryApprovalThreshold,
		DistinctTrustRecoveryApprovers: input.DeploymentPolicy.DistinctTrustRecoveryApprovers,
		LoweringApprovalThreshold:      input.DeploymentPolicy.LoweringApprovalThreshold,
		DistinctLoweringApprovers:      input.DeploymentPolicy.DistinctLoweringApprovers,
		HumanLoweringApproversRequired: input.DeploymentPolicy.HumanLoweringApproversRequired,
		ApprovedCryptographicBoundary:  input.DeploymentPolicy.ApprovedCryptographicBoundary,
		ValidatedCryptoModuleRequired:  input.DeploymentPolicy.ValidatedCryptoModuleRequired,
		EvidenceProfile:                input.DeploymentPolicy.EvidenceProfile,
		ClaimedResult:                  "pass",
	}
	if !reflect.DeepEqual(assurance, expectedAssurance) {
		return nil, nil, contractError("presented_assurance_mismatch", input.DeploymentPolicy.PresentedAssuranceResultPath, nil)
	}
	canonicalAssurance, err := marshalCanonical(assurance)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(canonicalAssurance, assuranceFile.Content) {
		return nil, nil, contractError("noncanonical_presented_assurance", input.DeploymentPolicy.PresentedAssuranceResultPath, nil)
	}
	for pathValue := range payload {
		if _, ok := referenced[pathValue]; !ok {
			return nil, nil, contractError("unbound_payload_file", pathValue, nil)
		}
	}
	return bindings, profiles, nil
}

// PrepareUnsigned constructs deterministic pre-signing content and an external
// signing request. Calling it twice with byte-identical inputs yields identical
// output bytes and identities.
func PrepareUnsigned(input BuildInput) (UnsignedActivation, error) {
	if len(input.PayloadFiles) > MaxArchiveFiles-2 || len(input.EvidenceFiles) > MaxArchiveFiles-2-len(input.PayloadFiles) {
		return UnsignedActivation{}, contractError("archive_content_limit", "files", nil)
	}
	if err := validateManifestInput(input.Manifest); err != nil {
		return UnsignedActivation{}, err
	}
	if err := validateIdentifier("evidence.builder_identity", input.Evidence.BuilderIdentity); err != nil {
		return UnsignedActivation{}, err
	}
	if err := validateIdentifier("evidence.build_workflow_identity", input.Evidence.BuildWorkflowIdentity); err != nil {
		return UnsignedActivation{}, err
	}
	allFiles := make([]File, 0, len(input.PayloadFiles)+len(input.EvidenceFiles)+1)
	payload := make(map[string]File, len(input.PayloadFiles))
	seen := make(map[string]struct{}, cap(allFiles))
	var totalContent uint64
	for _, original := range input.PayloadFiles {
		file := copyFile(original)
		if err := validateArtifactFile(file, "payload"); err != nil {
			return UnsignedActivation{}, err
		}
		if _, duplicate := seen[file.Path]; duplicate {
			return UnsignedActivation{}, contractError("duplicate_archive_path", file.Path, nil)
		}
		if strings.Contains(file.MediaType, "json") {
			if err := validateJSON(file.Content, MaxJSONDepth, true); err != nil {
				return UnsignedActivation{}, err
			}
		}
		seen[file.Path] = struct{}{}
		payload[file.Path] = file
		allFiles = append(allFiles, file)
		totalContent += uint64(len(file.Content))
	}
	policyIndex, ok := payload[input.Manifest.PolicyContentIndexPath]
	if !ok {
		return UnsignedActivation{}, contractError("missing_policy_content_index", input.Manifest.PolicyContentIndexPath, nil)
	}
	if policyIndex.MediaType != "application/vnd.stead.policy-content-index.v1+json" {
		return UnsignedActivation{}, contractError("bound_media_type_mismatch", input.Manifest.PolicyContentIndexPath, nil)
	}
	policyBundleID := SHA256Digest(policyIndex.Content)
	if err := validateReviewsAndWaivers(input.Evidence.ReviewReceipts, input.Evidence.WaiverReceipts, policyBundleID); err != nil {
		return UnsignedActivation{}, err
	}
	for _, review := range input.Evidence.ReviewReceipts {
		if review.ClaimedDisposition != "accept" {
			return UnsignedActivation{}, contractError("presented_build_review_not_accept", "evidence.review_receipts", nil)
		}
		if review.ReviewerID == input.Evidence.BuilderIdentity || review.ReviewerID == input.Evidence.BuildWorkflowIdentity {
			return UnsignedActivation{}, contractError("self_presented_build_review", "evidence.review_receipts", nil)
		}
	}
	if len(input.Evidence.ReviewReceipts) == 0 {
		return UnsignedActivation{}, contractError("missing_presented_build_review", "evidence.review_receipts", nil)
	}
	for _, waiver := range input.Evidence.WaiverReceipts {
		if waiver.ClaimedDisposition != "approved" {
			return UnsignedActivation{}, contractError("presented_build_waiver_not_approved", "evidence.waiver_receipts", nil)
		}
	}
	profileEvidenceRequirements := make(map[string]string)
	bindings, profiles, err := validateAndSortBindings(input.Manifest, payload, profileEvidenceRequirements)
	if err != nil {
		return UnsignedActivation{}, err
	}

	reports := make([]PresentedEvidenceReportV1, 0, len(input.EvidenceFiles))
	seenEvidencePaths := make(map[string]struct{}, len(input.EvidenceFiles))
	var conformance ConformanceClaims
	var conformanceDigest string
	for _, original := range input.EvidenceFiles {
		file := copyFile(original)
		if file.Path == evidenceManifestPath {
			return UnsignedActivation{}, contractError("reserved_evidence_path", file.Path, nil)
		}
		if err := validateArtifactFile(file, "evidence"); err != nil {
			return UnsignedActivation{}, err
		}
		if strings.Contains(file.MediaType, "json") {
			if err := validateJSON(file.Content, MaxJSONDepth, true); err != nil {
				return UnsignedActivation{}, err
			}
		}
		if _, duplicate := seen[file.Path]; duplicate {
			return UnsignedActivation{}, contractError("duplicate_archive_path", file.Path, nil)
		}
		var claims ConformanceClaims
		if expectedDigest, profileEvidence := profileEvidenceRequirements[file.Path]; profileEvidence {
			if SHA256Digest(file.Content) != expectedDigest {
				return UnsignedActivation{}, contractError("security_profile_artifact_digest_mismatch", "profile.semantics.registry_mappings", nil)
			}
		} else {
			var err error
			claims, err = validateTypedEvidenceFile(file)
			if err != nil {
				return UnsignedActivation{}, err
			}
		}
		seenEvidencePaths[file.Path] = struct{}{}
		if file.Path == conformanceEvidencePath {
			conformance = claims
			conformanceDigest = SHA256Digest(file.Content)
		}
		seen[file.Path] = struct{}{}
		allFiles = append(allFiles, file)
		totalContent += uint64(len(file.Content))
		reports = append(reports, PresentedEvidenceReportV1{Treatment: PresentedMaterialTreatment, Path: file.Path, MediaType: file.MediaType, Size: int64(len(file.Content)), Digest: SHA256Digest(file.Content)})
	}
	for requiredPath := range profileEvidenceRequirements {
		if _, present := seenEvidencePaths[requiredPath]; !present {
			return UnsignedActivation{}, contractError("missing_security_profile_mapping_evidence", "profile.semantics.registry_mappings", nil)
		}
	}
	for _, pathValue := range sortedEvidencePaths() {
		if _, ok := seenEvidencePaths[pathValue]; !ok {
			return UnsignedActivation{}, contractError("missing_required_evidence", pathValue, nil)
		}
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Path < reports[j].Path })

	evidenceManifest := PreSigningEvidenceManifestV1{
		SchemaVersion:            "1.0.0",
		Authority:                NonAuthorizingHandoffAuthority,
		BuilderIdentity:          input.Evidence.BuilderIdentity,
		BuildWorkflowIdentity:    input.Evidence.BuildWorkflowIdentity,
		SourceRevision:           input.Manifest.SourceRevision,
		DependencyLockDigest:     input.Manifest.DependencyLockDigest,
		PolicyContentIndexDigest: policyBundleID,
		OpenFGAModelSourceDigest: input.Manifest.OpenFGAModel.SourceDigest,
		Trust:                    input.Manifest.Trust,
		DeploymentPolicyID:       input.Manifest.DeploymentPolicy.PolicyID,
		DeploymentPolicyVersion:  input.Manifest.DeploymentPolicy.Version,
		DeploymentPolicyDigest:   input.Manifest.DeploymentPolicy.Digest,
		Reports:                  reports,
		Conformance: PresentedConformanceEvidenceV1{
			Treatment:    PresentedMaterialTreatment,
			ReportPath:   conformanceEvidencePath,
			ReportDigest: conformanceDigest,
			Claims:       conformance,
		},
		ReviewReceipts: presentReviews(input.Evidence.ReviewReceipts),
		WaiverReceipts: presentWaivers(input.Evidence.WaiverReceipts),
	}
	evidenceBytes, err := marshalCanonical(evidenceManifest)
	if err != nil {
		return UnsignedActivation{}, err
	}
	evidenceFile := File{Path: evidenceManifestPath, MediaType: "application/vnd.stead.policy-evidence.v1+json", Content: evidenceBytes}
	if err := validateArtifactFile(evidenceFile, "evidence"); err != nil {
		return UnsignedActivation{}, err
	}
	allFiles = append(allFiles, evidenceFile)
	totalContent += uint64(len(evidenceBytes))
	if len(allFiles)+1 > MaxArchiveFiles || totalContent > MaxArchiveContent {
		return UnsignedActivation{}, contractError("archive_content_limit", "files", nil)
	}
	sort.Slice(allFiles, func(i, j int) bool { return allFiles[i].Path < allFiles[j].Path })
	manifestFiles := make([]ManifestFile, 0, len(allFiles))
	for _, file := range allFiles {
		manifestFiles = append(manifestFiles, ManifestFile{Path: file.Path, MediaType: file.MediaType, Size: int64(len(file.Content)), Digest: SHA256Digest(file.Content)})
	}

	manifest := PolicyActivationManifestV1{
		SchemaVersion:                         "1.0.0",
		ArtifactFormat:                        ActivationFormatV1,
		PolicyBundleID:                        policyBundleID,
		PolicyContentIndexPath:                input.Manifest.PolicyContentIndexPath,
		ContractBindings:                      bindings,
		Profiles:                              profiles,
		OpenFGAModel:                          input.Manifest.OpenFGAModel,
		DeploymentPolicy:                      input.Manifest.DeploymentPolicy,
		EvaluatorContractVersion:              input.Manifest.EvaluatorContractVersion,
		SupportedSteadVersions:                mustSorted(input.Manifest.SupportedSteadVersions),
		RequiredContextIDs:                    mustSorted(input.Manifest.RequiredContextIDs),
		ReasonCodeIDs:                         mustSorted(input.Manifest.ReasonCodeIDs),
		ObligationIDs:                         mustSorted(input.Manifest.ObligationIDs),
		ExplicitDenyIDs:                       mustSorted(input.Manifest.ExplicitDenyIDs),
		Files:                                 manifestFiles,
		SourceRevision:                        input.Manifest.SourceRevision,
		DependencyLockDigest:                  input.Manifest.DependencyLockDigest,
		BuildRecipeVersion:                    input.Manifest.BuildRecipeVersion,
		EvidenceManifestDigest:                SHA256Digest(evidenceBytes),
		IssuedAt:                              input.Manifest.IssuedAt.Format(time.RFC3339),
		ExpiresAt:                             input.Manifest.ExpiresAt.Format(time.RFC3339),
		Trust:                                 input.Manifest.Trust,
		CompatiblePredecessorActivationSetIDs: sortedDigests(input.Manifest.CompatiblePredecessorActivationSetIDs),
		RollbackConstraints:                   mustSorted(input.Manifest.RollbackConstraints),
	}
	manifestBytes, err := marshalCanonical(manifest)
	if err != nil {
		return UnsignedActivation{}, err
	}
	if len(manifestBytes) > MaxDecodedPayloadBytes {
		return UnsignedActivation{}, contractError("manifest_payload_size_limit", "manifest", nil)
	}
	request, requestBytes, err := makeSigningRequest("policy_activation_manifest", ActivationManifestPayloadType, manifestBytes, input.Manifest)
	if err != nil {
		return UnsignedActivation{}, err
	}
	return UnsignedActivation{
		Manifest:               manifest,
		ManifestPayload:        manifestBytes,
		ActivationSetID:        SHA256Digest(manifestBytes),
		PolicyBundleID:         policyBundleID,
		EvidenceManifest:       evidenceManifest,
		EvidenceManifestBytes:  evidenceBytes,
		EvidenceManifestDigest: SHA256Digest(evidenceBytes),
		Files:                  allFiles,
		SigningRequest:         request,
		SigningRequestBytes:    requestBytes,
	}, nil
}

func mustSorted(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	sort.Strings(result)
	return result
}

func sortedDigests(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	sort.Strings(result)
	return result
}

func copyUnsignedActivation(unsigned UnsignedActivation) UnsignedActivation {
	result := unsigned
	result.ManifestPayload = cloneSlice(unsigned.ManifestPayload)
	result.EvidenceManifestBytes = cloneSlice(unsigned.EvidenceManifestBytes)
	result.SigningRequestBytes = cloneSlice(unsigned.SigningRequestBytes)
	result.Files = make([]File, len(unsigned.Files))
	for index, file := range unsigned.Files {
		result.Files[index] = copyFile(file)
	}
	result.Manifest.ContractBindings = cloneSlice(unsigned.Manifest.ContractBindings)
	result.Manifest.Profiles = cloneSlice(unsigned.Manifest.Profiles)
	result.Manifest.SupportedSteadVersions = cloneSlice(unsigned.Manifest.SupportedSteadVersions)
	result.Manifest.RequiredContextIDs = cloneSlice(unsigned.Manifest.RequiredContextIDs)
	result.Manifest.ReasonCodeIDs = cloneSlice(unsigned.Manifest.ReasonCodeIDs)
	result.Manifest.ObligationIDs = cloneSlice(unsigned.Manifest.ObligationIDs)
	result.Manifest.ExplicitDenyIDs = cloneSlice(unsigned.Manifest.ExplicitDenyIDs)
	result.Manifest.Files = cloneSlice(unsigned.Manifest.Files)
	result.Manifest.CompatiblePredecessorActivationSetIDs = cloneSlice(unsigned.Manifest.CompatiblePredecessorActivationSetIDs)
	result.Manifest.RollbackConstraints = cloneSlice(unsigned.Manifest.RollbackConstraints)
	result.EvidenceManifest.Reports = cloneSlice(unsigned.EvidenceManifest.Reports)
	result.EvidenceManifest.ReviewReceipts = cloneSlice(unsigned.EvidenceManifest.ReviewReceipts)
	result.EvidenceManifest.WaiverReceipts = cloneSlice(unsigned.EvidenceManifest.WaiverReceipts)
	return result
}

func requireDigestMatches(field, expected string, data []byte) error {
	if got := SHA256Digest(data); got != expected {
		return contractError("digest_mismatch", field, fmt.Errorf("digest mismatch"))
	}
	return nil
}

func validatePreparedEvidence(unsigned UnsignedActivation, profileEvidenceRequirements map[string]string) error {
	evidence := unsigned.EvidenceManifest
	manifest := unsigned.Manifest
	if evidence.SchemaVersion != "1.0.0" || evidence.Authority != NonAuthorizingHandoffAuthority {
		return contractError("evidence_manifest_authority_mismatch", "evidence_manifest", nil)
	}
	if err := validateIdentifier("evidence.builder_identity", evidence.BuilderIdentity); err != nil {
		return err
	}
	if err := validateIdentifier("evidence.build_workflow_identity", evidence.BuildWorkflowIdentity); err != nil {
		return err
	}
	if evidence.SourceRevision != manifest.SourceRevision || evidence.DependencyLockDigest != manifest.DependencyLockDigest || evidence.PolicyContentIndexDigest != manifest.PolicyBundleID || evidence.OpenFGAModelSourceDigest != manifest.OpenFGAModel.SourceDigest || evidence.Trust != manifest.Trust || evidence.DeploymentPolicyID != manifest.DeploymentPolicy.PolicyID || evidence.DeploymentPolicyVersion != manifest.DeploymentPolicy.Version || evidence.DeploymentPolicyDigest != manifest.DeploymentPolicy.Digest {
		return contractError("evidence_manifest_binding_mismatch", "evidence_manifest", nil)
	}
	reviewInputs := reviewReceiptInputs(evidence.ReviewReceipts)
	waiverInputs := waiverReceiptInputs(evidence.WaiverReceipts)
	if !reflect.DeepEqual(evidence.ReviewReceipts, presentReviews(reviewInputs)) || !reflect.DeepEqual(evidence.WaiverReceipts, presentWaivers(waiverInputs)) {
		return contractError("presented_evidence_treatment_mismatch", "evidence_manifest", nil)
	}
	if err := validateReviewsAndWaivers(reviewInputs, waiverInputs, manifest.PolicyBundleID); err != nil {
		return err
	}
	if len(reviewInputs) == 0 {
		return contractError("missing_presented_build_review", "evidence_manifest.presented_review_receipts", nil)
	}
	for _, review := range reviewInputs {
		if review.ClaimedDisposition != "accept" || review.ReviewerID == evidence.BuilderIdentity || review.ReviewerID == evidence.BuildWorkflowIdentity {
			return contractError("presented_build_review_mismatch", "evidence_manifest.presented_review_receipts", nil)
		}
	}
	for _, waiver := range waiverInputs {
		if waiver.ClaimedDisposition != "approved" {
			return contractError("presented_build_waiver_mismatch", "evidence_manifest.presented_waiver_receipts", nil)
		}
	}

	reports := make([]PresentedEvidenceReportV1, 0, len(evidence.Reports))
	seenPaths := make(map[string]struct{}, len(evidence.Reports))
	var conformance ConformanceClaims
	var conformanceDigest string
	for _, file := range unsigned.Files {
		if !strings.HasPrefix(file.Path, "evidence/") || file.Path == evidenceManifestPath {
			continue
		}
		var claims ConformanceClaims
		if expectedDigest, profileEvidence := profileEvidenceRequirements[file.Path]; profileEvidence {
			if SHA256Digest(file.Content) != expectedDigest {
				return contractError("security_profile_artifact_digest_mismatch", "profile.semantics.registry_mappings", nil)
			}
		} else {
			var err error
			claims, err = validateTypedEvidenceFile(file)
			if err != nil {
				return err
			}
		}
		seenPaths[file.Path] = struct{}{}
		if file.Path == conformanceEvidencePath {
			conformance = claims
			conformanceDigest = SHA256Digest(file.Content)
		}
		reports = append(reports, PresentedEvidenceReportV1{Treatment: PresentedMaterialTreatment, Path: file.Path, MediaType: file.MediaType, Size: int64(len(file.Content)), Digest: SHA256Digest(file.Content)})
	}
	for _, requiredPath := range sortedEvidencePaths() {
		if _, present := seenPaths[requiredPath]; !present {
			return contractError("missing_required_evidence", requiredPath, nil)
		}
	}
	for requiredPath := range profileEvidenceRequirements {
		if _, present := seenPaths[requiredPath]; !present {
			return contractError("missing_security_profile_mapping_evidence", "profile.semantics.registry_mappings", nil)
		}
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Path < reports[j].Path })
	if !reflect.DeepEqual(reports, evidence.Reports) {
		return contractError("presented_evidence_report_mismatch", "evidence_manifest.presented_reports", nil)
	}
	wantConformance := PresentedConformanceEvidenceV1{Treatment: PresentedMaterialTreatment, ReportPath: conformanceEvidencePath, ReportDigest: conformanceDigest, Claims: conformance}
	if !reflect.DeepEqual(evidence.Conformance, wantConformance) {
		return contractError("presented_conformance_mismatch", "evidence_manifest.presented_conformance", nil)
	}
	return nil
}

func validateUnsignedActivation(unsigned UnsignedActivation) error {
	if SHA256Digest(unsigned.ManifestPayload) != unsigned.ActivationSetID {
		return contractError("activation_set_identity_mismatch", "activation_set_id", nil)
	}
	if unsigned.PolicyBundleID != unsigned.Manifest.PolicyBundleID {
		return contractError("policy_bundle_identity_mismatch", "policy_bundle_id", nil)
	}
	var decoded PolicyActivationManifestV1
	if err := decodeStrict(unsigned.ManifestPayload, &decoded); err != nil {
		return err
	}
	if !reflect.DeepEqual(decoded, unsigned.Manifest) {
		return contractError("manifest_struct_mismatch", "manifest", nil)
	}
	canonical, err := marshalCanonical(unsigned.Manifest)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, unsigned.ManifestPayload) {
		return contractError("noncanonical_manifest_payload", "manifest", nil)
	}
	issuedAt, err := time.Parse(time.RFC3339, unsigned.Manifest.IssuedAt)
	if err != nil {
		return contractError("invalid_activation_validity", "manifest.issued_at", nil)
	}
	expiresAt, err := time.Parse(time.RFC3339, unsigned.Manifest.ExpiresAt)
	if err != nil {
		return contractError("invalid_activation_validity", "manifest.expires_at", nil)
	}
	manifestInput := ManifestInput{
		PolicyContentIndexPath:                unsigned.Manifest.PolicyContentIndexPath,
		ContractBindings:                      cloneSlice(unsigned.Manifest.ContractBindings),
		Profiles:                              cloneSlice(unsigned.Manifest.Profiles),
		OpenFGAModel:                          unsigned.Manifest.OpenFGAModel,
		DeploymentPolicy:                      unsigned.Manifest.DeploymentPolicy,
		EvaluatorContractVersion:              unsigned.Manifest.EvaluatorContractVersion,
		SupportedSteadVersions:                cloneSlice(unsigned.Manifest.SupportedSteadVersions),
		RequiredContextIDs:                    cloneSlice(unsigned.Manifest.RequiredContextIDs),
		ReasonCodeIDs:                         cloneSlice(unsigned.Manifest.ReasonCodeIDs),
		ObligationIDs:                         cloneSlice(unsigned.Manifest.ObligationIDs),
		ExplicitDenyIDs:                       cloneSlice(unsigned.Manifest.ExplicitDenyIDs),
		SourceRevision:                        unsigned.Manifest.SourceRevision,
		DependencyLockDigest:                  unsigned.Manifest.DependencyLockDigest,
		BuildRecipeVersion:                    unsigned.Manifest.BuildRecipeVersion,
		IssuedAt:                              issuedAt,
		ExpiresAt:                             expiresAt,
		Trust:                                 unsigned.Manifest.Trust,
		CompatiblePredecessorActivationSetIDs: cloneSlice(unsigned.Manifest.CompatiblePredecessorActivationSetIDs),
		RollbackConstraints:                   cloneSlice(unsigned.Manifest.RollbackConstraints),
	}
	if unsigned.Manifest.SchemaVersion != "1.0.0" || unsigned.Manifest.ArtifactFormat != ActivationFormatV1 {
		return contractError("unsupported_activation_manifest", "manifest", nil)
	}
	if err := validateManifestInput(manifestInput); err != nil {
		return err
	}
	payload := make(map[string]File)
	for _, file := range unsigned.Files {
		if strings.HasPrefix(file.Path, "payload/") {
			payload[file.Path] = file
		}
	}
	profileEvidenceRequirements := make(map[string]string)
	bindings, profiles, err := validateAndSortBindings(manifestInput, payload, profileEvidenceRequirements)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(bindings, unsigned.Manifest.ContractBindings) || !reflect.DeepEqual(profiles, unsigned.Manifest.Profiles) {
		return contractError("manifest_binding_order_mismatch", "manifest", nil)
	}
	policyIndex, present := payload[unsigned.Manifest.PolicyContentIndexPath]
	if !present || SHA256Digest(policyIndex.Content) != unsigned.Manifest.PolicyBundleID {
		return contractError("policy_bundle_identity_mismatch", "policy_bundle_id", nil)
	}
	wantSigningRequest, wantSigningRequestBytes, err := makeSigningRequest("policy_activation_manifest", ActivationManifestPayloadType, unsigned.ManifestPayload, manifestInput)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(unsigned.SigningRequest, wantSigningRequest) || !bytes.Equal(unsigned.SigningRequestBytes, wantSigningRequestBytes) {
		return contractError("signing_request_binding_mismatch", "signing_request", nil)
	}
	if SHA256Digest(unsigned.EvidenceManifestBytes) != unsigned.EvidenceManifestDigest || unsigned.Manifest.EvidenceManifestDigest != unsigned.EvidenceManifestDigest {
		return contractError("evidence_manifest_identity_mismatch", "evidence_manifest", nil)
	}
	var evidence PreSigningEvidenceManifestV1
	if err := decodeStrict(unsigned.EvidenceManifestBytes, &evidence); err != nil {
		return err
	}
	if !reflect.DeepEqual(evidence, unsigned.EvidenceManifest) {
		return contractError("evidence_manifest_struct_mismatch", "evidence_manifest", nil)
	}
	canonicalEvidence, err := marshalCanonical(unsigned.EvidenceManifest)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonicalEvidence, unsigned.EvidenceManifestBytes) {
		return contractError("noncanonical_evidence_manifest", "evidence_manifest", nil)
	}
	if err := validatePreparedEvidence(unsigned, profileEvidenceRequirements); err != nil {
		return err
	}
	actualFiles := manifestFileList(unsigned.Files)
	if !reflect.DeepEqual(actualFiles, unsigned.Manifest.Files) {
		return contractError("manifest_file_list_mismatch", "manifest.files", nil)
	}
	foundEvidenceManifest := false
	for _, file := range unsigned.Files {
		if file.Path == evidenceManifestPath && !bytes.Equal(file.Content, unsigned.EvidenceManifestBytes) {
			return contractError("evidence_manifest_content_mismatch", file.Path, nil)
		}
		if file.Path == evidenceManifestPath {
			foundEvidenceManifest = true
			if file.MediaType != "application/vnd.stead.policy-evidence.v1+json" {
				return contractError("bound_media_type_mismatch", file.Path, nil)
			}
		}
	}
	if !foundEvidenceManifest {
		return contractError("missing_evidence_manifest", evidenceManifestPath, nil)
	}
	return nil
}
