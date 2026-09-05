package authorization

import (
	"context"
	"time"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

const LocalDevelopmentSecurityDomain = "stead-local-development"

// LocalCheckRequest identifies a fixed, reviewed check, not a caller-selected
// executable. SubjectDigest is the pre-signing derivation input digest, except
// for offline-verification where it is the completed archive digest.
type LocalCheckRequest struct {
	ID             string
	SubjectDigest  string
	SourceRevision string
	SourceTree     string
	Files          []policyrelease.File
	Archive        []byte
}

// LocalCheckCapture is actual process output captured by the reviewed local
// installer. A supplied success assertion is not accepted in place of output.
type LocalCheckCapture struct {
	Stdout, Stderr        []byte
	ExitCode              int
	StartedAt, FinishedAt time.Time
}

type LocalCheckRunner interface {
	Run(context.Context, LocalCheckRequest) (LocalCheckCapture, error)
}

// LocalCheckReport is the closed stdout format produced by an actual check.
// Cases must exactly match the names frozen in the reviewed template. For the
// critical-mutations check, Passed means a real mutant was killed.
type LocalCheckReport struct {
	SchemaVersion  string           `json:"schema_version"`
	CheckID        string           `json:"check_id"`
	SubjectDigest  string           `json:"subject_digest"`
	SourceRevision string           `json:"source_revision"`
	SourceTree     string           `json:"source_tree"`
	Total          int              `json:"total"`
	Passed         int              `json:"passed"`
	Failed         int              `json:"failed"`
	Cases          []LocalCheckCase `json:"cases"`
}

type LocalCheckCase struct {
	ID     string `json:"id"`
	Passed bool   `json:"passed"`
}

type LocalCheckSpec struct {
	ID           string   `json:"id"`
	Cases        []string `json:"cases"`
	RequiredRate int      `json:"required_rate"`
}

type LocalTemplateFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// LocalTemplateCore is reviewed before review records and the final template
// manifest are added as a metadata-only descendant. This avoids a hash cycle.
type LocalTemplateCore struct {
	SourceRevision       string              `json:"source_revision"`
	SourceTree           string              `json:"source_tree"`
	GoVersion            string              `json:"go_version"`
	GoBinaryDigest       string              `json:"go_binary_digest"`
	GoCompilerDigest     string              `json:"go_compiler_digest"`
	GoToolchainDigest    string              `json:"go_toolchain_digest"`
	DependencyLockDigest string              `json:"dependency_lock_digest"`
	Files                []LocalTemplateFile `json:"files"`
	PublicOrigin         string              `json:"public_origin"`
	OpenFGAURL           string              `json:"openfga_url"`
	SecurityDomain       string              `json:"security_domain"`
	ValiditySeconds      int                 `json:"validity_seconds"`
	AllowedSubstitutions []string            `json:"allowed_substitutions"`
	Checks               []LocalCheckSpec    `json:"checks"`
}

type LocalTemplateReview struct {
	Role           string `json:"role"`
	ReviewerID     string `json:"reviewer_id"`
	SourceRevision string `json:"source_revision"`
	CoreDigest     string `json:"core_digest"`
	RecordPath     string `json:"record_path"`
	RecordDigest   string `json:"record_digest"`
	Disposition    string `json:"disposition"`
}

type LocalTemplateManifest struct {
	SchemaVersion string                `json:"schema_version"`
	Status        string                `json:"status"`
	Core          LocalTemplateCore     `json:"core"`
	Reviews       []LocalTemplateReview `json:"reviews"`
}

type LocalDevelopmentConfig struct {
	RepositoryRoot   string
	InstallationID   string
	PublicOrigin     string
	OpenFGAURL       string
	OpenFGAToken     string
	InstallerID      string
	Now              time.Time
	LocalDevelopment bool
	Runner           LocalCheckRunner
	Workflow         *policyrelease.ObservedWorkflow
}

// LocalDevelopmentArtifacts contains no private signing key. The initial key
// is generated in memory and discarded after finalization; restart verifies
// these exact retained artifacts and cannot renew, rotate, or promote them.
// The composition root persists every byte with no-overwrite private writes,
// establishes the fresh database, and creates the independent anchor.
type LocalDevelopmentArtifacts struct {
	Archive            []byte
	DerivationEnvelope []byte
	TrustedKeys        []TrustedKey
	EvidenceFiles      []policyrelease.File
	Anchor             AnchorState
	OpenFGA            *OpenFGA
	Activation         *VerifiedActivation
}

type LocalDevelopmentLoadInput struct {
	RepositoryRoot     string
	PublicOrigin       string
	OpenFGAURL         string
	OpenFGA            *OpenFGA
	Archive            []byte
	DerivationEnvelope []byte
	TrustedKeys        []TrustedKey
	Anchor             AnchorState
	Now                time.Time
	LocalDevelopment   bool
	Workflow           *policyrelease.ObservedWorkflow
}
