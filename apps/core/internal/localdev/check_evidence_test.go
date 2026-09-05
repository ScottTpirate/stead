package localdev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func TestPinnedNPMUsesDistinctPrivateEmptyConfiguration(t *testing.T) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("npm_config_userconfig", "/outside/user-with-credentials")
	t.Setenv("npm_config_globalconfig", "/outside/global-with-credentials")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	capture, err := captureCheck(ctx, root, filepath.Join(root, "scripts/run_pinned_node.sh"), []string{"npm", "config", "list", "--json"}, nil)
	if err != nil || capture.ExitCode != 0 {
		t.Fatal("actual pinned npm cannot resolve closed configuration")
	}
	var config map[string]any
	if json.Unmarshal(capture.Stdout, &config) != nil {
		t.Fatal("actual npm did not emit configuration")
	}
	user, userOK := config["userconfig"].(string)
	global, globalOK := config["globalconfig"].(string)
	if !userOK || !globalOK || user == global || filepath.Base(user) != "user.npmrc" || filepath.Base(global) != "global.npmrc" {
		t.Fatal("npm did not consume distinct fixed configuration paths")
	}
	for _, path := range []string{user, global} {
		contents, err := ReadPrivate(path, 1024)
		if err != nil || !bytes.Equal(contents, []byte("\n")) {
			t.Fatal("npm configuration was not privately empty")
		}
	}
}

func checkEvidenceRequest() authorization.LocalCheckRequest {
	return authorization.LocalCheckRequest{ID: "policy-conformance", SubjectDigest: "sha256:" + strings.Repeat("a", 64), SourceRevision: strings.Repeat("b", 40), SourceTree: strings.Repeat("c", 40), Archive: []byte("never-retain-archive"), Files: []policyrelease.File{{Content: []byte("never-retain-file")}}}
}

func TestFailedCheckCaptureIsPrivateBoundedAndDoesNotOverwrite(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	capture := authorization.LocalCheckCapture{Stdout: []byte("actual stdout"), Stderr: []byte{0xff, 0x00, '\n'}, ExitCode: 1, StartedAt: now, FinishedAt: now.Add(time.Millisecond)}
	request := checkEvidenceRequest()
	if retainCheckCapture(directory, request, capture, errors.New("never-retain-error-secret")) != nil {
		t.Fatal("failed check evidence was dropped")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("private capture absent")
	}
	name := filepath.Join(directory, entries[0].Name())
	data, err := ReadPrivate(name, 1<<20)
	if err != nil {
		t.Fatal("capture is not owner-only regular file")
	}
	var record retainedCheckCapture
	if json.Unmarshal(data, &record) != nil || !bytes.Equal(record.Stdout, capture.Stdout) || !bytes.Equal(record.Stderr, capture.Stderr) || record.ErrorCode != "check_execution_failed" || record.StdoutDigest != policyrelease.SHA256Digest(capture.Stdout) || record.StderrDigest != policyrelease.SHA256Digest(capture.Stderr) || record.CheckID != request.ID || record.SourceRevision != request.SourceRevision || record.ExitCode != 1 {
		t.Fatal("actual failed output/identity was changed")
	}
	if bytes.Contains(data, []byte("never-retain")) {
		t.Fatal("request/archive/raw error leaked into capture")
	}
	if retainCheckCapture(directory, request, capture, nil) != nil {
		t.Fatal("subsequent capture failed")
	}
	entries, _ = os.ReadDir(directory)
	original, err := ReadPrivate(name, 1<<20)
	if err != nil || len(entries) != 2 || !bytes.Equal(original, data) || WriteExclusive(name, []byte("overwrite")) == nil {
		t.Fatal("existing diagnostic capture was overwritten")
	}
	capture.Stdout = make([]byte, (256<<10)+1)
	if retainCheckCapture(directory, request, capture, nil) == nil {
		t.Fatal("unbounded output persisted")
	}
	capture.Stdout = nil
	if os.Chmod(directory, 0755) != nil || retainCheckCapture(directory, request, capture, nil) == nil {
		t.Fatal("shared diagnostic directory admitted")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "evidence")
	if os.Symlink(directory, link) != nil || retainCheckCapture(link, request, capture, nil) == nil {
		t.Fatal("aliased diagnostic directory admitted")
	}
}

func TestCheckRunnerRejectsMissingRetentionBeforeExecution(t *testing.T) {
	root, _ := filepath.Abs("../../../..")
	runner := CheckRunner{RepositoryRoot: root, EvidenceDirectory: filepath.Join(t.TempDir(), "missing")}
	if _, err := runner.Run(context.Background(), checkEvidenceRequest()); err == nil {
		t.Fatal("check executed without durable private capture destination")
	}
}

func TestCheckRunnerRetainsActualPartialProcessFailure(t *testing.T) {
	root := t.TempDir()
	evidence := t.TempDir()
	if os.Chmod(evidence, 0700) != nil {
		t.Fatal("private evidence setup")
	}
	request := checkEvidenceRequest()
	request.ID = "dependency-review"
	runner := CheckRunner{RepositoryRoot: root, EvidenceDirectory: evidence}
	if _, err := runner.Run(context.Background(), request); err == nil {
		t.Fatal("missing actual dependency scripts were accepted")
	}
	files, err := os.ReadDir(evidence)
	if err != nil || len(files) != 1 {
		t.Fatal("execution failure capture missing")
	}
	data, err := ReadPrivate(filepath.Join(evidence, files[0].Name()), 1<<20)
	var record retainedCheckCapture
	if err != nil || json.Unmarshal(data, &record) != nil || record.ErrorCode != "check_execution_failed" || record.StartedAt.IsZero() || record.FinishedAt.Before(record.StartedAt) || !bytes.Contains(record.Stderr, []byte("go-module-integrity")) || !bytes.Contains(record.Stderr, []byte("approved-dependency-locks")) {
		t.Fatal("partial dependency execution diagnostics were discarded")
	}
}

// Executes the actual approval/lock validator, Go module verification and
// pinned npm audit through the same constructor used by bootstrap. It is a
// nonauthorizing integration probe, never installation evidence to be reused.
func TestLiveCheckRunnerDependencySliceAndRetention(t *testing.T) {
	if os.Getenv("STEAD_LIVE_LOCAL_CHECKS") != "1" {
		t.Skip("explicit dependency runner integration gate")
	}
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	core, err := authorization.InspectLocalTemplateSource(ctx, root)
	if err != nil {
		t.Fatal("integration gate requires clean immutable source")
	}
	evidence, err := os.MkdirTemp("", "stead-local-dependency-capture-proof-")
	if err != nil {
		t.Fatal(err)
	}
	request := authorization.LocalCheckRequest{ID: "dependency-review", SubjectDigest: policyrelease.SHA256Digest([]byte("non-authorizing dependency runner integration probe")), SourceRevision: core.SourceRevision, SourceTree: core.SourceTree}
	runner := CheckRunner{RepositoryRoot: root, EvidenceDirectory: evidence}
	capture, err := runner.Run(ctx, request)
	var report authorization.LocalCheckReport
	if err != nil || capture.ExitCode != 0 || json.Unmarshal(capture.Stdout, &report) != nil || report.CheckID != request.ID || report.SubjectDigest != request.SubjectDigest || report.SourceRevision != core.SourceRevision || report.SourceTree != core.SourceTree || report.Total != 3 || report.Passed != 3 || report.Failed != 0 {
		t.Fatalf("actual dependency runner failed; private capture retained at %s", evidence)
	}
	files, err := os.ReadDir(evidence)
	if err != nil || len(files) != 1 {
		t.Fatal("actual check did not retain its capture")
	}
	data, err := ReadPrivate(filepath.Join(evidence, files[0].Name()), 1<<20)
	var retained retainedCheckCapture
	if err != nil || json.Unmarshal(data, &retained) != nil || !bytes.Equal(retained.Stdout, capture.Stdout) || !bytes.Equal(retained.Stderr, capture.Stderr) || retained.ErrorCode != "none" {
		t.Fatal("actual successful capture differs from returned process result")
	}
	t.Logf("actual approval/lock + Go module integrity + pinned npm advisory checks PASS3/3; exact raw capture retained at %s", evidence)
}
