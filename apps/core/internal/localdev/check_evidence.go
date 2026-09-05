package localdev

import (
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

// Diagnostic capture only, not a PASS assertion or substitute for policy
// evidence verification. No request payload, archive, credential, or raw error
// text is included. Captures remain private and durable even when signing stops.
type retainedCheckCapture struct {
	SchemaVersion  string    `json:"schema_version"`
	CheckID        string    `json:"check_id"`
	SubjectDigest  string    `json:"subject_digest"`
	SourceRevision string    `json:"source_revision"`
	SourceTree     string    `json:"source_tree"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	ExitCode       int       `json:"exit_code"`
	ErrorCode      string    `json:"error_code"`
	Stdout         []byte    `json:"stdout_base64"`
	Stderr         []byte    `json:"stderr_base64"`
	StdoutDigest   string    `json:"stdout_digest"`
	StderrDigest   string    `json:"stderr_digest"`
}

func retainCheckCapture(directory string, request authorization.LocalCheckRequest, capture authorization.LocalCheckCapture, processErr error) error {
	if !validCheckID(request.ID) || !validCheckRequest(request) || len(capture.Stdout) > 256<<10 || len(capture.Stderr) > 256<<10 || PrivateDirectory(directory) != nil {
		return ErrConfiguration
	}
	code := "none"
	if processErr != nil {
		code = "check_execution_failed"
	} else if capture.ExitCode != 0 {
		code = "check_exit_nonzero"
	}
	record := retainedCheckCapture{SchemaVersion: "1.0.0", CheckID: request.ID, SubjectDigest: request.SubjectDigest, SourceRevision: request.SourceRevision, SourceTree: request.SourceTree, StartedAt: capture.StartedAt, FinishedAt: capture.FinishedAt, ExitCode: capture.ExitCode, ErrorCode: code, Stdout: capture.Stdout, Stderr: capture.Stderr, StdoutDigest: policyrelease.SHA256Digest(capture.Stdout), StderrDigest: policyrelease.SHA256Digest(capture.Stderr)}
	encoded, err := json.Marshal(record)
	if err != nil {
		return ErrConfiguration
	}
	id, err := checkIdentifier()
	if err != nil {
		return ErrConfiguration
	}
	return WriteExclusive(filepath.Join(directory, id+".json"), encoded)
}
