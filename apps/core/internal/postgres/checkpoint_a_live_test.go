//go:build linux && stead_checkpoint_a_live

package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/localdev"
)

// This test does not exist in ordinary unit selection. Explicit tag + exact
// test invocation requires every private prerequisite; none are skipped.
func TestCheckpointADenialEvidenceLive(t *testing.T) {
	mode := os.Getenv("STEAD_CHECKPOINT_A_SQL_MODE")
	if mode != "" && mode != "organization-list-denial" {
		t.Fatal("live denial collector mode rejected")
	}
	collection := mode == "organization-list-denial"
	admissionFile, admissionHash := os.Getenv("STEAD_CHECKPOINT_A_ADMISSION"), os.Getenv("STEAD_CHECKPOINT_A_ADMISSION_SHA256")
	reportFile, reportHash := os.Getenv("STEAD_CHECKPOINT_A_FOLLOWON"), os.Getenv("STEAD_CHECKPOINT_A_FOLLOWON_SHA256")
	collectionFile, collectionHash := os.Getenv("STEAD_CHECKPOINT_A_COLLECTION"), os.Getenv("STEAD_CHECKPOINT_A_COLLECTION_SHA256")
	if collection {
		if reportFile != "" || reportHash != "" {
			t.Fatal("live denial collector mixed proof modes rejected")
		}
		reportFile, reportHash = collectionFile, collectionHash
	} else if collectionFile != "" || collectionHash != "" {
		t.Fatal("live denial collector mixed proof modes rejected")
	}
	output := os.Getenv("STEAD_CHECKPOINT_A_SQL_PROOF")
	for _, value := range []string{admissionFile, admissionHash, reportFile, reportHash, output} {
		if value == "" {
			t.Fatal("live denial collector requires explicit private prerequisites")
		}
	}
	if !checkpointHex.MatchString(admissionHash) || !checkpointHex.MatchString(reportHash) {
		t.Fatal("live denial collector requires exact evidence hashes")
	}
	limits, err := os.ReadFile("/proc/self/limits")
	if err != nil || len(limits) > 16384 || !regexp.MustCompile(`(?m)^Max core file size[ \t]+0[ \t]+0[ \t]+bytes[ \t]*$`).Match(limits) {
		t.Fatal("live denial collector requires disabled inherited core dumps")
	}
	if localdev.PrivateDirectory(filepath.Dir(output)) != nil {
		t.Fatal("live denial collector private output rejected")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("live denial collector requires a new proof path")
	}
	result := struct {
		Scope             string   `json:"scope"`
		Passed            bool     `json:"passed"`
		Stage             string   `json:"stage"`
		AdmissionHash     string   `json:"admission_sha256"`
		ReportHash        string   `json:"followon_sha256"`
		CollectionHash    string   `json:"collection_sha256,omitempty"`
		Instance          string   `json:"instance_id"`
		Source            string   `json:"source_revision"`
		CollectorBinary   string   `json:"collector_binary_sha256"`
		Correlations      []string `json:"denial_correlations"`
		Known             int      `json:"known_canonical_resources"`
		Unknown           int      `json:"unknown_absent_resources"`
		Snapshot          bool     `json:"repeatable_read_read_only_rolled_back"`
		Runtime           bool     `json:"runtime_identity_reverified"`
		BrowserProvenance bool     `json:"browser_created_provenance_proven"`
		Timing            bool     `json:"timing_nondisclosure_proven"`
	}{Scope: "current-denial-audit-correlation-and-canonical-existence-only", Stage: "inputs", AdmissionHash: admissionHash, ReportHash: reportHash}
	if collection {
		result.Scope, result.CollectionHash, result.ReportHash = "current-organization-list-denial-audit-correlation-only", reportHash, ""
	}
	defer func() {
		data, err := json.Marshal(result)
		if err != nil || localdev.WriteExclusive(output, append(data, '\n')) != nil {
			t.Error("live denial collector could not preserve exclusive proof")
		}
	}()
	admission, err := checkpointPrivate(admissionFile, admissionHash, 32768)
	if err != nil {
		t.Fatal("live denial collector admission rejected")
	}
	data, err := checkpointPrivate(reportFile, reportHash, 1<<20)
	if err != nil {
		t.Fatal("live denial collector follow-on rejected")
	}
	cwd, err := os.Getwd()
	if err != nil || !strings.HasSuffix(cwd, "/apps/core/internal/postgres") {
		t.Fatal("live denial collector checkout rejected")
	}
	repo := strings.TrimSuffix(cwd, "/apps/core/internal/postgres")
	// The integrator separately records the reviewed immutable build revision.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("live denial collector executable identity unavailable")
	}
	binary, err := checkpointPublic(executable, 512<<20)
	if err != nil {
		t.Fatal("live denial collector executable identity rejected")
	}
	result.CollectorBinary = checkpointHash(binary)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result.Stage = "identity_before"
	before, err := checkpointCurrentIdentity(ctx, repo, admissionFile, admissionHash, admission)
	if err != nil {
		t.Fatal("live denial collector identity rejected")
	}
	result.Instance, result.Source = before.InstanceID, before.SourceRevision
	var report checkpointReport
	var expected map[string]checkpointExpected
	if collection {
		expected, err = checkpointParseCollection(data, before, admissionHash)
	} else {
		report, expected, err = checkpointParseReport(data, before, admissionHash)
	}
	if err != nil {
		t.Fatal("live denial collector report contract rejected")
	}
	// The only secret file this collector reads. Never Load() or an admin DSN.
	result.Stage = "runtime_database_boundary"
	secret, err := localdev.ReadPrivate(filepath.Join(before.State, "database-url"), 8192)
	if err != nil {
		t.Fatal("live denial collector runtime connection input rejected")
	}
	secretHash := checkpointHash(secret) // In memory only; never output credential derivatives.
	config, err := checkpointDSN(secret, before.InstanceID, os.Environ())
	clear(secret)
	if err != nil {
		t.Fatal("live denial collector runtime connection boundary rejected")
	}
	defer func() { config.Password = "" }()
	result.Stage = "readonly_snapshot"
	var matches []string
	if collection {
		matches, err = checkpointCollectCollection(ctx, config, before, expected)
	} else {
		matches, err = checkpointCollect(ctx, config, before, report, expected)
	}
	if err != nil {
		t.Fatal("live denial collector read-only verification failed")
	}
	result.Correlations, result.Snapshot = matches, true
	if !collection {
		result.Known, result.Unknown = 3, 3
	}
	result.Stage = "identity_after"
	secret, err = localdev.ReadPrivate(filepath.Join(before.State, "database-url"), 8192)
	unchangedSecret := err == nil && checkpointHash(secret) == secretHash
	clear(secret)
	if !unchangedSecret {
		t.Fatal("live denial collector runtime connection input changed")
	}
	again, err := checkpointPrivate(admissionFile, admissionHash, 32768)
	if err != nil || !bytes.Equal(again, admission) {
		t.Fatal("live denial collector admission changed")
	}
	again, err = checkpointPrivate(reportFile, reportHash, 1<<20)
	if err != nil || !bytes.Equal(again, data) {
		t.Fatal("live denial collector follow-on changed")
	}
	after, err := checkpointCurrentIdentity(ctx, repo, admissionFile, admissionHash, admission)
	if err != nil || !reflectCheckpointIdentity(before, after) {
		t.Fatal("live denial collector runtime identity changed")
	}
	result.Passed, result.Runtime, result.Stage = true, true, "complete"
}
func reflectCheckpointIdentity(a, b checkpointIdentity) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
