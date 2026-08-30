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
	return File{Path: file.Path, MediaType: file.MediaType, Content: append([]byte(nil), file.Content...)}
}

func sortReviews(reviews []ReviewerDisposition) []ReviewerDisposition {
	result := make([]ReviewerDisposition, len(reviews))
	copy(result, reviews)
	sort.Slice(result, func(i, j int) bool {
		left := result[i].Role + "\x00" + result[i].ReviewerID + "\x00" + result[i].Revision + "\x00" + result[i].Disposition
		right := result[j].Role + "\x00" + result[j].ReviewerID + "\x00" + result[j].Revision + "\x00" + result[j].Disposition
		return left < right
	})
	return result
}

func sortWaivers(waivers []Waiver) []Waiver {
	result := make([]Waiver, len(waivers))
	copy(result, waivers)
	sort.Slice(result, func(i, j int) bool {
		return result[i].WaiverID+"\x00"+result[i].Revision < result[j].WaiverID+"\x00"+result[j].Revision
	})
	return result
}

func validateReviewsAndWaivers(reviews []ReviewerDisposition, waivers []Waiver) error {
	seenReviews := make(map[string]struct{}, len(reviews))
	for _, review := range reviews {
		if err := validateReview(review); err != nil {
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
		if err := validateWaiver(waiver); err != nil {
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
	for _, pathValue := range []string{input.OpenFGAModel.SourcePath, input.DeploymentPolicy.Path, input.DeploymentPolicy.EvaluatedAssuranceResultPath, input.Trust.TrustSetPath, input.Trust.TrustSetEnvelopePath} {
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

func validateAndSortBindings(input ManifestInput, payload map[string]File) ([]ContentBinding, []ProfileBinding, error) {
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
	for _, profile := range profiles {
		if err := validateIdentifier("profile.profile_id", profile.ProfileID); err != nil {
			return nil, nil, err
		}
		if err := validateVersion("profile.version", profile.Version); err != nil {
			return nil, nil, err
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
		profileBytes := bytes.ToLower(payload[profile.Path].Content)
		if !bytes.Contains(profileBytes, []byte(ActivationFormatV1)) || bytes.Contains(profileBytes, []byte("sigstore-bundle")) {
			return nil, nil, contractError("unsupported_profile_signing_format", profile.Path, nil)
		}
	}
	special := []struct {
		path   string
		digest string
		role   string
	}{
		{input.OpenFGAModel.SourcePath, input.OpenFGAModel.SourceDigest, "openfga_model"},
		{input.DeploymentPolicy.Path, input.DeploymentPolicy.Digest, "deployment_policy"},
		{input.DeploymentPolicy.EvaluatedAssuranceResultPath, input.DeploymentPolicy.EvaluatedAssuranceResultDigest, "evaluated_assurance_result"},
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
	var assurance EvaluatedAssuranceResultV1
	assuranceFile := payload[input.DeploymentPolicy.EvaluatedAssuranceResultPath]
	if assuranceFile.MediaType != "application/json" {
		return nil, nil, contractError("bound_media_type_mismatch", input.DeploymentPolicy.EvaluatedAssuranceResultPath, nil)
	}
	if err := decodeStrict(assuranceFile.Content, &assurance); err != nil {
		return nil, nil, err
	}
	expectedAssurance := EvaluatedAssuranceResultV1{
		SchemaVersion:                  "1.0.0",
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
		Result:                         "pass",
	}
	if !reflect.DeepEqual(assurance, expectedAssurance) {
		return nil, nil, contractError("evaluated_assurance_mismatch", input.DeploymentPolicy.EvaluatedAssuranceResultPath, nil)
	}
	canonicalAssurance, err := marshalCanonical(assurance)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(canonicalAssurance, assuranceFile.Content) {
		return nil, nil, contractError("noncanonical_evaluated_assurance", input.DeploymentPolicy.EvaluatedAssuranceResultPath, nil)
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
	if err := validateConformance(input.Evidence.Conformance); err != nil {
		return UnsignedActivation{}, err
	}
	if err := validateReviewsAndWaivers(input.Evidence.Reviews, input.Evidence.Waivers); err != nil {
		return UnsignedActivation{}, err
	}
	for _, review := range input.Evidence.Reviews {
		if review.Disposition != "accept" {
			return UnsignedActivation{}, contractError("build_review_not_accepted", "evidence.reviews", nil)
		}
		if review.ReviewerID == input.Evidence.BuilderIdentity || review.ReviewerID == input.Evidence.BuildWorkflowIdentity {
			return UnsignedActivation{}, contractError("self_approved_build_evidence", "evidence.reviews", nil)
		}
	}
	if len(input.Evidence.Reviews) == 0 {
		return UnsignedActivation{}, contractError("missing_build_review", "evidence.reviews", nil)
	}
	for _, waiver := range input.Evidence.Waivers {
		if waiver.Disposition != "approved" {
			return UnsignedActivation{}, contractError("build_waiver_not_approved", "evidence.waivers", nil)
		}
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
	bindings, profiles, err := validateAndSortBindings(input.Manifest, payload)
	if err != nil {
		return UnsignedActivation{}, err
	}

	reports := make([]EvidenceReport, 0, len(input.EvidenceFiles))
	requiredEvidenceMediaTypes := []string{
		"application/spdx+json",
		"application/vnd.in-toto+json",
		"application/vnd.stead.policy-conformance.v1+json",
		"application/vnd.stead.policy-license-result.v1+json",
		"application/vnd.stead.policy-vulnerability.v1+json",
	}
	requiredEvidenceTypes := make(map[string]bool, len(requiredEvidenceMediaTypes))
	for _, mediaType := range requiredEvidenceMediaTypes {
		requiredEvidenceTypes[mediaType] = false
	}
	for _, original := range input.EvidenceFiles {
		file := copyFile(original)
		if file.Path == evidenceManifestPath {
			return UnsignedActivation{}, contractError("reserved_evidence_path", file.Path, nil)
		}
		if err := validateArtifactFile(file, "evidence"); err != nil {
			return UnsignedActivation{}, err
		}
		if err := validatePreSigningEvidence(file); err != nil {
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
		seen[file.Path] = struct{}{}
		allFiles = append(allFiles, file)
		totalContent += uint64(len(file.Content))
		reports = append(reports, EvidenceReport{Path: file.Path, MediaType: file.MediaType, Size: int64(len(file.Content)), Digest: SHA256Digest(file.Content)})
		if _, required := requiredEvidenceTypes[file.MediaType]; required {
			requiredEvidenceTypes[file.MediaType] = true
		}
	}
	for _, mediaType := range requiredEvidenceMediaTypes {
		if !requiredEvidenceTypes[mediaType] {
			return UnsignedActivation{}, contractError("missing_required_evidence", mediaType, nil)
		}
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Path < reports[j].Path })

	evidenceManifest := PreSigningEvidenceManifestV1{
		SchemaVersion:            "1.0.0",
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
		Conformance:              input.Evidence.Conformance,
		Reviews:                  sortReviews(input.Evidence.Reviews),
		Waivers:                  sortWaivers(input.Evidence.Waivers),
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

func requireDigestMatches(field, expected string, data []byte) error {
	if got := SHA256Digest(data); got != expected {
		return contractError("digest_mismatch", field, fmt.Errorf("digest mismatch"))
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
