package localdev

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
)

func TestCheckOutputAndExecutionCaptureAreActualAndBounded(t *testing.T) {
	output := &boundedOutput{limit: 3}
	if _, err := output.Write([]byte("123")); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("4")); err == nil || !output.overflow || output.String() != "123" {
		t.Fatal("unbounded output")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := captureCheck(ctx, t.TempDir(), "/usr/bin/true", nil, nil)
	if err != nil || result.ExitCode != 0 || result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		t.Fatal("missing actual successful execution")
	}
	result, err = captureCheck(ctx, t.TempDir(), "/usr/bin/false", nil, nil)
	if err != nil || result.ExitCode != 1 {
		t.Fatal("actual failure was converted to success")
	}
	if _, err = captureCheck(ctx, t.TempDir(), "/nonexistent/stead-check", nil, nil); err == nil {
		t.Fatal("missing executable succeeded")
	}
	cancel()
	if _, err = captureCheck(ctx, t.TempDir(), "/usr/bin/true", nil, nil); err == nil {
		t.Fatal("cancelled check succeeded")
	}
}

func TestCheckEnvironmentCannotInheritServiceSecretsOrCompilerOverrides(t *testing.T) {
	t.Setenv("STEAD_DATABASE_PASSWORD", "must-not-leak")
	t.Setenv("GOFLAGS", "-tags=unsafe")
	for _, entry := range checkEnvironment() {
		if strings.Contains(entry, "must-not-leak") || strings.HasPrefix(entry, "STEAD_") || strings.HasPrefix(entry, "GOFLAGS=") || strings.HasPrefix(entry, "HOME=") {
			t.Fatal("untrusted check environment")
		}
	}
}

func TestCheckRequestClosureAndUnapprovedInput(t *testing.T) {
	request := authorization.LocalCheckRequest{ID: "offline-verification", SubjectDigest: "sha256:" + strings.Repeat("a", 64), SourceRevision: strings.Repeat("b", 40), SourceTree: strings.Repeat("c", 40), Archive: []byte("actual")}
	data, _ := json.Marshal(request)
	var decoded authorization.LocalCheckRequest
	if decodeCheckInput(data, &decoded) != nil || !validCheckRequest(decoded) {
		t.Fatal("closed request rejected")
	}
	for _, bad := range []string{`{}`, string(data) + `{}`, strings.Replace(string(data), `"ID":`, `"ID":"other","ID":`, 1), strings.Replace(string(data), `"ID":`, `"id":`, 1), strings.Replace(string(data), `"ID":`, `"Unknown":`, 1)} {
		if decodeCheckInput([]byte(bad), &decoded) == nil {
			t.Fatal("ambiguous request admitted")
		}
	}
	root := t.TempDir()
	runner := CheckRunner{RepositoryRoot: root}
	for _, id := range []string{"caller-script", "offline-verification"} {
		request.ID = id
		if _, err := runner.Run(context.Background(), request); err == nil {
			t.Fatal("unknown executable or wrong archive subject admitted")
		}
	}
	request.ID = "policy-conformance"
	request.SourceRevision = "HEAD"
	if _, err := runner.Run(context.Background(), request); err == nil {
		t.Fatal("floating source identity admitted")
	}
	if _, err := os.Stat(filepath.Join(root, "created")); !os.IsNotExist(err) {
		t.Fatal("unexpected request side effect")
	}
}

func TestReportCountsOnlyExecutedCases(t *testing.T) {
	report := actualReport(authorization.LocalCheckRequest{ID: "dependency-review"}, []authorization.LocalCheckCase{{ID: "one", Passed: true}, {ID: "two", Passed: false}})
	if report.Total != 2 || report.Passed != 1 || report.Failed != 1 {
		t.Fatal("fabricated check rate")
	}
}
