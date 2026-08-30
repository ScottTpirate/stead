package policyrelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	if err := validateDigest("deployment_policy.evaluated_assurance_result_digest", policy.EvaluatedAssuranceResultDigest); err != nil {
		return err
	}
	if err := validatePath(policy.EvaluatedAssuranceResultPath, false); err != nil {
		return err
	}
	return nil
}

func validateReview(review ReviewerDisposition) error {
	if err := validateIdentifier("review.reviewer_id", review.ReviewerID); err != nil {
		return err
	}
	if err := validateIdentifier("review.role", review.Role); err != nil {
		return err
	}
	if err := validateImmutableRevision("review.revision", review.Revision); err != nil {
		return err
	}
	if review.Disposition != "accept" && review.Disposition != "reject" && review.Disposition != "pending" {
		return contractError("invalid_review_disposition", "review.disposition", nil)
	}
	return nil
}

func validateWaiver(waiver Waiver) error {
	if err := validateIdentifier("waiver.waiver_id", waiver.WaiverID); err != nil {
		return err
	}
	if err := validateImmutableRevision("waiver.revision", waiver.Revision); err != nil {
		return err
	}
	if waiver.Disposition != "approved" && waiver.Disposition != "rejected" {
		return contractError("invalid_waiver_disposition", "waiver.disposition", nil)
	}
	return nil
}

func validateConformance(summary ConformanceSummary) error {
	if summary.DecisionRowsCoveredPercent != 100 {
		return contractError("decision_coverage_below_floor", "evidence.conformance", nil)
	}
	if summary.CriticalMutationScorePercent < 90 || summary.CriticalMutationScorePercent > 100 {
		return contractError("mutation_score_below_floor", "evidence.conformance", nil)
	}
	if !summary.DeterministicReplayPassed || !summary.LabelLatticePassed || !summary.ExplicitDenyPassed || !summary.AgentIntersectionPassed || !summary.ProviderBypassPassed {
		return contractError("required_conformance_failed", "evidence.conformance", nil)
	}
	return nil
}

var prohibitedPreSigningMarkers = [][]byte{
	[]byte("activation_set_id"),
	[]byte("signed_envelope_digest"),
	[]byte("archive_digest"),
	[]byte("release_attestation_id"),
	[]byte("release_attestation_envelope_digest"),
	[]byte("-----begin private key-----"),
	[]byte("private key-----"),
}

func validatePreSigningEvidence(file File) error {
	lower := bytes.ToLower(file.Content)
	for _, marker := range prohibitedPreSigningMarkers {
		if bytes.Contains(lower, marker) {
			return contractError("circular_or_private_evidence", file.Path, fmt.Errorf("prohibited marker"))
		}
	}
	return nil
}
