package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func rowEvents(action string) []event {
	return []event{
		{Action: "run", Package: authorizationPackage, Test: "TestNativePolicyRows"},
		{Action: "run", Package: authorizationPackage, Test: "TestNativePolicyRows/POLICY-001"},
		{Action: action, Package: authorizationPackage, Test: "TestNativePolicyRows/POLICY-001"},
		{Action: action, Package: authorizationPackage, Test: "TestNativePolicyRows"},
		{Action: action, Package: authorizationPackage},
	}
}

func TestCaptureRowsRequiresActualExactExecution(t *testing.T) {
	for _, action := range []string{"pass", "fail"} {
		code := 0
		if action == "fail" {
			code = 1
		}
		rows, err := captureRows([]string{"POLICY-001"}, rowEvents(action), code)
		if err != nil || len(rows) != 1 || rows[0].Passed != (action == "pass") {
			t.Fatal("actual row outcome lost", err)
		}
	}
	for _, tc := range []struct {
		name   string
		events []event
		code   int
		ids    []string
	}{
		{"missing", nil, 0, []string{"POLICY-001"}},
		{"skipped", rowEvents("skip"), 0, []string{"POLICY-001"}},
		{"missing-row", rowEvents("pass"), 0, []string{"POLICY-001", "POLICY-002"}},
		{"unexpected-row", rowEvents("pass"), 0, []string{"POLICY-002"}},
		{"duplicate-inventory", rowEvents("pass"), 0, []string{"POLICY-001", "POLICY-001"}},
		{"exit-mismatch", rowEvents("pass"), 1, []string{"POLICY-001"}},
		{"exit-hidden-fail", rowEvents("fail"), 0, []string{"POLICY-001"}},
		{"duplicate-terminal", append(rowEvents("pass"), rowEvents("pass")[2]), 0, []string{"POLICY-001"}},
		{"no-start", rowEvents("pass")[2:], 0, []string{"POLICY-001"}},
		{"incomplete", rowEvents("pass")[:2], 1, []string{"POLICY-001"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := captureRows(tc.ids, tc.events, tc.code); err == nil {
				t.Fatal("invalid process capture accepted")
			}
		})
	}
}

func TestCaptureRowsPreservesContractOrderNotExecutionOrLexicalOrder(t *testing.T) {
	ids := []string{"POLICY-Z", "POLICY-A"}
	events := []event{{Action: "run", Package: authorizationPackage, Test: "TestNativePolicyRows"}}
	for _, id := range []string{"POLICY-A", "POLICY-Z"} {
		events = append(events,
			event{Action: "run", Package: authorizationPackage, Test: "TestNativePolicyRows/" + id},
			event{Action: "pass", Package: authorizationPackage, Test: "TestNativePolicyRows/" + id})
	}
	events = append(events,
		event{Action: "pass", Package: authorizationPackage, Test: "TestNativePolicyRows"},
		event{Action: "pass", Package: authorizationPackage})
	rows, err := captureRows(ids, events, 0)
	if err != nil || len(rows) != len(ids) || rows[0].ID != ids[0] || rows[1].ID != ids[1] {
		t.Fatal("contract row order changed", err)
	}
}

func TestProcessResultCannotCreditCompilerOrPackageFailures(t *testing.T) {
	good := rowEvents("fail")
	for _, tc := range []struct {
		name   string
		events []event
		code   int
	}{
		{"compiler", append(good, event{Action: "build-fail", Package: authorizationPackage}), 1},
		{"build-output", append(good, event{Action: "output", Package: authorizationPackage, Output: "FAIL [build failed]"}), 1},
		{"package-only", []event{{Action: "fail", Package: authorizationPackage}}, 1},
		{"interrupted", good, 137},
		{"unrelated-package", append(good, event{Action: "pass", Package: "unrelated"}), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if killed, err := processResult(tc.events, tc.code, []string{authorizationPackage}); err == nil || killed {
				t.Fatal("invalid mutation kill credited")
			}
		})
	}
	if _, err := processResult(good, 1, []string{authorizationPackage, classificationPackage}); err == nil {
		t.Fatal("omitted package credited")
	}
}

type diagnostic struct {
	Reason               string `json:"reason"`
	ExitCode             int    `json:"exit_code"`
	Event                *event `json:"event"`
	FollowingBuildOutput string `json:"following_build_output"`
	Truncated            bool   `json:"truncated"`
}

func readDiagnostic(t *testing.T, data string) diagnostic {
	t.Helper()
	// Five bounded names, two output fields, JSON syntax.
	if len(data) > 6*(5*diagnosticNameBytes+2*diagnosticOutputBytes)+1024 || !utf8.ValidString(data) || strings.ContainsAny(data, "\r\n\x00") {
		t.Fatal("diagnostic is unbounded or not escaped UTF-8")
	}
	var result diagnostic
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		t.Fatal("diagnostic is not JSON", err)
	}
	return result
}

func TestInvalidEvidenceRetainsFirstOffendingEventAndExit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry event
	}{
		{"build-output-import-path", event{Action: "build-output", ImportPath: authorizationPackage, Output: "file.go:12: undefined: missing\n"}},
		{"build-fail-import-path", event{Action: "build-fail", ImportPath: authorizationPackage}},
		{"foreign-package", event{Action: "output", Package: "unexpected/package", Test: "TestOther", Output: "foreign output"}},
		{"empty-package", event{Action: "output", Output: "no package"}},
		{"utf8-and-controls", event{Action: "output", Package: "外部/é", Output: "quote \" slash \\ tab\t line\n nul\x00"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A legitimate failing test before the offending event and a later
			// build-fail cannot make invalid compiler/package evidence a kill.
			events := append(rowEvents("fail"), tc.entry, event{Action: "build-fail", ImportPath: "later/package"})
			killed, err := processResult(events, 1, []string{authorizationPackage})
			if err == nil || killed {
				t.Fatal("invalid evidence credited")
			}
			got := readDiagnostic(t, err.Error())
			if got.ExitCode != 1 || got.Truncated || got.Event == nil || *got.Event != tc.entry {
				t.Fatalf("first offending event lost: %#v", got)
			}
			compiler := strings.HasPrefix(tc.entry.Action, "build-")
			if compiler != strings.Contains(got.Reason, "compiler") {
				t.Fatal("build event misclassified", got.Reason)
			}
		})
	}
	// A build-output is invalid even without a subsequent build-fail, and
	// even if all otherwise valid events and the child exit claim success.
	for _, code := range []int{0, 1} {
		entry := event{Action: "build-output", Package: authorizationPackage, ImportPath: authorizationPackage}
		if killed, err := processResult(append(rowEvents("pass"), entry), code, []string{authorizationPackage}); err == nil || killed {
			t.Fatal("build output accepted without terminal build failure")
		}
	}
}

func TestCompilerDiagnosticRetainsBoundedFollowingErrorNotUnrelatedOutput(t *testing.T) {
	first := event{Action: "build-output", ImportPath: authorizationPackage, Output: "# package\n"}
	events := []event{first,
		{Action: "output", Package: authorizationPackage, Output: "not compiler output"},
		{Action: "build-output", ImportPath: "foreign/build", Output: "not this compiler"},
		{Action: "build-output", ImportPath: authorizationPackage, Output: "file.go:12: undefined: missing\n"},
		{Action: "build-output", ImportPath: authorizationPackage, Output: strings.Repeat("\x00", diagnosticOutputBytes)},
		{Action: "build-fail", ImportPath: authorizationPackage}}
	killed, err := processResult(events, 1, []string{authorizationPackage})
	if err == nil || killed {
		t.Fatal("compiler evidence credited")
	}
	got := readDiagnostic(t, err.Error())
	if got.Event == nil || *got.Event != first || !got.Truncated || len(got.FollowingBuildOutput) != diagnosticOutputBytes || !strings.HasPrefix(got.FollowingBuildOutput, "file.go:12: undefined: missing\n") || strings.Contains(got.FollowingBuildOutput, "not ") {
		t.Fatal("following compiler detail lost, unbounded, or mixed with other output")
	}
}

func TestInvalidEvidenceDiagnosticTruncatesOnlyAfterValidation(t *testing.T) {
	entry := event{Action: "output", Package: authorizationPackage, Output: strings.Repeat("x", diagnosticOutputBytes*3) + "[build failed]"}
	killed, err := processResult(append(rowEvents("fail"), entry), 1, []string{authorizationPackage})
	if err == nil || killed {
		t.Fatal("compiler failure beyond retained prefix credited")
	}
	got := readDiagnostic(t, err.Error())
	if !got.Truncated || !strings.Contains(got.Reason, "compiler") || got.Event.Output != strings.Repeat("x", diagnosticOutputBytes) {
		t.Fatal("oversize compiler diagnostic lost its explicit truncation")
	}
	entry = event{Action: strings.Repeat("\x00", diagnosticNameBytes*2), Test: strings.Repeat("\x01", diagnosticNameBytes*2),
		Package: strings.Repeat("\x02", diagnosticNameBytes*2), ImportPath: strings.Repeat("\x03", diagnosticNameBytes*2),
		Output: strings.Repeat("\x04", diagnosticOutputBytes*2)}
	next := event{Action: "build-output", ImportPath: entry.ImportPath, Output: strings.Repeat("\x06", diagnosticOutputBytes*2)}
	got = readDiagnostic(t, evidenceError(strings.Repeat("\x05", diagnosticNameBytes*2), -1, &entry, next).Error())
	if !got.Truncated || got.ExitCode != -1 || len(got.Event.Output) != diagnosticOutputBytes {
		t.Fatal("worst-case escaped diagnostic not bounded")
	}
	// A byte limit can split a multibyte rune. encoding/json must still emit
	// valid, escaped UTF-8 and disclose truncation, never an invalid JSON line.
	entry.Output = strings.Repeat("x", diagnosticOutputBytes-1) + "界"
	got = readDiagnostic(t, evidenceError("boundary", 1, &entry).Error())
	if !got.Truncated || !utf8.ValidString(got.Event.Output) {
		t.Fatal("multibyte truncation produced invalid JSON")
	}
}

func TestExecuteRetainsBoundedChildFailureAndBuildEvent(t *testing.T) {
	directory := t.TempDir()
	// A private synthetic executable exercises the actual child/decode path;
	// it does not invoke a service or substitute for a real compiler campaign.
	script := "#!/bin/sh\n[ -z \"${STEAD_LOCALCHECK_TEST_SECRET+x}\" ] || exit 99\nprintf '%s\\n' '{\"ImportPath\":\"" + authorizationPackage + "\",\"Action\":\"build-output\",\"Output\":\"file.go:12: undefined: missing\\n\"}' '{\"ImportPath\":\"" + authorizationPackage + "\",\"Action\":\"build-fail\"}'\nprintf '%s' '" + strings.Repeat("x", diagnosticOutputBytes*2) + "' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(directory, "go"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("STEAD_LOCALCHECK_TEST_SECRET", "synthetic-not-a-service-credential")
	stderr, err := os.CreateTemp(directory, "stderr-")
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = stderr
	t.Cleanup(func() { os.Stderr = original; stderr.Close() })
	events, code, err := execute(context.Background(), "test", "-json")
	os.Stderr = original
	if err != nil || code != 1 || len(events) != 2 || events[0].ImportPath != authorizationPackage {
		t.Fatal("child exit or build event lost", code, err)
	}
	data, err := os.ReadFile(stderr.Name())
	if err != nil {
		t.Fatal(err)
	}
	got := readDiagnostic(t, strings.TrimSuffix(string(data), "\n"))
	if got.ExitCode != 1 || got.Reason != "test process stderr" || !got.Truncated || len(got.Event.Output) != diagnosticOutputBytes {
		t.Fatal("child stderr diagnostic lost", got)
	}
	if killed, err := processResult(events, code, []string{authorizationPackage}); err == nil || killed {
		t.Fatal("decoded compiler failure credited")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	if cases, err := critical(context.Background()); err == nil || cases != nil || !strings.Contains(err.Error(), "unmutated positive control") || !strings.Contains(err.Error(), `"ImportPath":"`+authorizationPackage+`"`) || !strings.Contains(err.Error(), `"exit_code":1`) {
		t.Fatal("positive-control compiler detail discarded", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "go"), []byte("#!/bin/sh\nprintf '%s' 'not-json'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	events, code, err = execute(context.Background(), "test", "-json")
	if err == nil || code != 1 || events != nil {
		t.Fatal("malformed child JSON accepted")
	}
	got = readDiagnostic(t, err.Error())
	if got.ExitCode != 1 || got.Event.Output != "not-json" || !strings.Contains(got.Reason, "invalid test JSON") {
		t.Fatal("malformed child output or exit lost", got)
	}
}

func TestTestEnvironmentDoesNotInheritCredentialsOrBuildOverrides(t *testing.T) {
	for _, name := range []string{"PGPASSWORD", "STEAD_BOOTSTRAP_TOKEN", "AWS_SECRET_ACCESS_KEY", "GOFLAGS", "GOENV", "GOWORK", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "CC", "LD_PRELOAD"} {
		t.Setenv(name, "untrusted-test-value")
	}
	t.Setenv("GOCACHE", "/private/test-build-cache")
	joined := strings.Join(testEnvironment(), "\n")
	if strings.Contains(joined, "untrusted-test-value") || !strings.Contains(joined, "GOCACHE=/private/test-build-cache\n") || !strings.Contains(joined, "GOFLAGS=-mod=readonly\n") {
		t.Fatal("nested check inherited credentials/overrides or lost approved build paths")
	}
}
