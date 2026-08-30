package policyrelease

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var (
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identifierPattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:/-]{0,127}$`)
	opaqueIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,255}$`)
	gitRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionPattern     = regexp.MustCompile(`^1\.[0-9]+\.[0-9]+$`)
)

var allowedMediaTypes = map[string]struct{}{
	"application/json":                                    {},
	"application/schema+json":                             {},
	"application/spdx+json":                               {},
	"application/vnd.in-toto+json":                        {},
	"application/vnd.openfga.model+text":                  {},
	"application/vnd.stead.policy-conformance.v1+json":    {},
	"application/vnd.stead.policy-content-index.v1+json":  {},
	"application/vnd.stead.policy-evidence.v1+json":       {},
	"application/vnd.stead.policy-license-result.v1+json": {},
	"application/vnd.stead.policy-review-result.v1+json":  {},
	"application/vnd.stead.security-profile.v0.1+json":    {},
	"application/vnd.stead.policy-sbom.v1+json":           {},
	"application/vnd.stead.policy-test-result.v1+json":    {},
	"application/vnd.stead.policy-vulnerability.v1+json":  {},
	"application/yaml":                                    {},
	"text/plain; charset=utf-8":                           {},
}

// ContractError supplies a stable, safe failure code without embedding input
// payloads or signature bytes in logs.
type ContractError struct {
	Code  string
	Field string
	Err   error
}

func (e *ContractError) Error() string {
	if e.Field == "" {
		return e.Code
	}
	return e.Code + ": " + e.Field
}

func (e *ContractError) Unwrap() error { return e.Err }

func contractError(code, field string, err error) error {
	return &ContractError{Code: code, Field: field, Err: err}
}

func ErrorCode(err error) string {
	var target *ContractError
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}

func SHA256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateDigest(field, value string) error {
	if !digestPattern.MatchString(value) {
		return contractError("invalid_digest", field, nil)
	}
	return nil
}

func validateIdentifier(field, value string) error {
	if !identifierPattern.MatchString(value) {
		return contractError("invalid_identifier", field, nil)
	}
	return nil
}

func validateOpaqueID(field, value string) error {
	if !opaqueIDPattern.MatchString(value) {
		return contractError("invalid_identifier", field, nil)
	}
	return nil
}

func validateImmutableRevision(field, value string) error {
	if !gitRevisionPattern.MatchString(value) && !digestPattern.MatchString(value) {
		return contractError("nonimmutable_revision", field, nil)
	}
	return nil
}

func validateVersion(field, value string) error {
	if !versionPattern.MatchString(value) {
		return contractError("unsupported_version", field, nil)
	}
	return nil
}

func validateMediaType(field, value string) error {
	if _, ok := allowedMediaTypes[value]; !ok {
		return contractError("unknown_media_type", field, nil)
	}
	return nil
}

func validatePath(value string, directory bool) error {
	if value == "" || !utf8.ValidString(value) || len(value) > MaxArchivePathBytes {
		return contractError("invalid_archive_path", "path", nil)
	}
	if strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || path.Clean(value) != strings.TrimSuffix(value, "/") {
		return contractError("invalid_archive_path", "path", nil)
	}
	if directory != strings.HasSuffix(value, "/") {
		return contractError("invalid_archive_path", "path", nil)
	}
	trimmed := strings.TrimSuffix(value, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 || len(parts) > MaxPathComponents {
		return contractError("archive_path_component_limit", "path", nil)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > MaxPathComponentByte || !utf8.ValidString(part) {
			return contractError("invalid_archive_path_component", "path", nil)
		}
	}
	return nil
}

func validateArtifactFile(file File, root string) error {
	if err := validatePath(file.Path, false); err != nil {
		return err
	}
	if !strings.HasPrefix(file.Path, root+"/") {
		return contractError("wrong_archive_root", file.Path, nil)
	}
	if len(file.Content) > MaxArchiveFileBytes {
		return contractError("archive_file_size_limit", file.Path, nil)
	}
	if err := validateMediaType(file.Path, file.MediaType); err != nil {
		return err
	}
	if !utf8.Valid(file.Content) {
		return contractError("invalid_artifact_utf8", file.Path, nil)
	}
	return nil
}

func sortedUniqueStrings(field string, values []string, allowEmpty bool) ([]string, error) {
	if len(values) == 0 && !allowEmpty {
		return nil, contractError("missing_required_list", field, nil)
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for i, value := range result {
		if err := validateIdentifier(field, value); err != nil {
			return nil, err
		}
		if i > 0 && value == result[i-1] {
			return nil, contractError("duplicate_value", field, nil)
		}
	}
	return result, nil
}

func validateDeploymentPolicy(policy DeploymentPolicyBinding) error {
	if err := validateIdentifier("deployment_policy.policy_id", policy.PolicyID); err != nil {
		return err
	}
	if err := validateVersion("deployment_policy.version", policy.Version); err != nil {
		return err
	}
	if policy.SchemaID != DeploymentPolicySchemaID {
		return contractError("unsupported_deployment_policy_schema", "deployment_policy.schema_id", nil)
	}
	if err := validateDigest("deployment_policy.digest", policy.Digest); err != nil {
		return err
	}
	if policy.DisclosureRevocationMode != "request_boundary" && policy.DisclosureRevocationMode != "commit_boundary" {
		return contractError("unsupported_disclosure_mode", "deployment_policy.disclosure_revocation_mode", nil)
	}
	if policy.PolicySignatureThreshold < 1 || policy.PolicySignatureThreshold > MaxEnvelopeSignatures {
		return contractError("invalid_signature_threshold", "deployment_policy.policy_signature_threshold", nil)
	}
	if policy.TrustRecoveryApprovalThreshold < 1 || policy.LoweringApprovalThreshold < 1 {
		return contractError("invalid_assurance_threshold", "deployment_policy", nil)
	}
	if err := validateIdentifier("deployment_policy.approved_cryptographic_boundary", policy.ApprovedCryptographicBoundary); err != nil {
		return err
	}
	if err := validateIdentifier("deployment_policy.evidence_profile", policy.EvidenceProfile); err != nil {
		return err
	}
	if err := validateDigest("deployment_policy.presented_assurance_result_digest", policy.PresentedAssuranceResultDigest); err != nil {
		return err
	}
	if err := validatePath(policy.PresentedAssuranceResultPath, false); err != nil {
		return err
	}
	return nil
}

func validateReview(review ReviewReceipt, subjectDigest string) error {
	if err := validateIdentifier("review.reviewer_id", review.ReviewerID); err != nil {
		return err
	}
	if err := validateIdentifier("review.role", review.Role); err != nil {
		return err
	}
	if err := validateDigest("review.subject_digest", review.SubjectDigest); err != nil {
		return err
	}
	if review.SubjectDigest != subjectDigest {
		return contractError("presented_review_subject_mismatch", "review.subject_digest", nil)
	}
	if err := validateDigest("review.record_digest", review.RecordDigest); err != nil {
		return err
	}
	if review.ClaimedDisposition != "accept" && review.ClaimedDisposition != "reject" && review.ClaimedDisposition != "pending" {
		return contractError("invalid_claimed_review_disposition", "review.claimed_disposition", nil)
	}
	return nil
}

func validateWaiver(waiver WaiverReceipt, subjectDigest string) error {
	if err := validateIdentifier("waiver.waiver_id", waiver.WaiverID); err != nil {
		return err
	}
	if err := validateDigest("waiver.subject_digest", waiver.SubjectDigest); err != nil {
		return err
	}
	if waiver.SubjectDigest != subjectDigest {
		return contractError("presented_waiver_subject_mismatch", "waiver.subject_digest", nil)
	}
	if err := validateDigest("waiver.record_digest", waiver.RecordDigest); err != nil {
		return err
	}
	if waiver.ClaimedDisposition != "approved" && waiver.ClaimedDisposition != "rejected" {
		return contractError("invalid_claimed_waiver_disposition", "waiver.claimed_disposition", nil)
	}
	return nil
}

func validateConformance(summary ConformanceClaims) error {
	if summary.DecisionRowsCoveredPercent != 100 {
		return contractError("decision_coverage_below_floor", "evidence.conformance", nil)
	}
	if summary.CriticalMutationScorePercent < 90 || summary.CriticalMutationScorePercent > 100 {
		return contractError("mutation_score_below_floor", "evidence.conformance", nil)
	}
	for _, claim := range []string{summary.ClaimedDeterministicReplay, summary.ClaimedLabelLattice, summary.ClaimedExplicitDeny, summary.ClaimedAgentIntersection, summary.ClaimedProviderBypass} {
		if claim != "pass" {
			return contractError("presented_conformance_claim_not_pass", "evidence.presented_conformance", nil)
		}
	}
	return nil
}
