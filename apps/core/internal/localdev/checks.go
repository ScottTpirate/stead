package localdev

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

// CheckRunner invokes only fixed reviewed checks, never an executable supplied
// by policy input. No service/password/signing environment reaches a check.
type CheckRunner struct{ RepositoryRoot string }

type boundedOutput struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	if output.Len()+len(data) > output.limit {
		output.overflow = true
		return 0, errors.New("bounded check output exceeded")
	}
	return output.Buffer.Write(data)
}

func checkEnvironment() []string {
	// Deliberately do not inherit GOFLAGS, GOENV, compiler overrides, credentials,
	// shell startup files, proxy settings or npm configuration from the caller.
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "CGO_ENABLED=0", "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOEXPERIMENT=", "GOCACHE=/tmp/stead-go-build-cache", "GOPATH=/tmp/stead-go-path", "npm_config_cache=/tmp/stead-local-npm-cache", "npm_config_userconfig=/dev/null", "npm_config_globalconfig=/dev/null"}
}

func captureCheck(ctx context.Context, root, executable string, args []string, input []byte) (authorization.LocalCheckCapture, error) {
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = root
	command.Env = checkEnvironment()
	if filepath.Base(executable) == "run_pinned_go.sh" && len(args) > 1 && args[0] == "go" && args[1] == "run" {
		// Compiler evidence may not be satisfied from a shared compiled-object
		// cache. Only exact go.sum-verified module ZIP inputs are reused; source
		// extraction and every compilation happen in this fresh private cache.
		cache, err := os.MkdirTemp("", "stead-local-check-build-")
		if err != nil {
			return authorization.LocalCheckCapture{}, ErrConfiguration
		}
		defer os.RemoveAll(cache)
		filtered := []string{}
		for _, entry := range command.Env {
			if !strings.HasPrefix(entry, "GOCACHE=") {
				filtered = append(filtered, entry)
			}
		}
		command.Env = append(filtered, "GOCACHE="+filepath.Join(cache, "build"), "GOMODCACHE="+filepath.Join(cache, "modules"), "GOPROXY=file:///tmp/stead-go-path/pkg/mod/cache/download", "GOSUMDB=off")
	}
	command.Stdin = bytes.NewReader(input)
	stdout, stderr := &boundedOutput{limit: 256 << 10}, &boundedOutput{limit: 256 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = 2 * time.Second
	capture := authorization.LocalCheckCapture{StartedAt: time.Now().UTC()}
	err := command.Run()
	capture.FinishedAt = time.Now().UTC()
	capture.Stdout = append([]byte(nil), stdout.Bytes()...)
	capture.Stderr = append([]byte(nil), stderr.Bytes()...)
	if stdout.overflow || stderr.overflow || ctx.Err() != nil {
		return capture, ErrConfiguration
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return capture, ErrConfiguration
		}
		capture.ExitCode = exit.ExitCode()
	}
	return capture, nil
}

var checkRevision = regexp.MustCompile(`^[a-f0-9]{40}$`)
var checkDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func validCheckRequest(request authorization.LocalCheckRequest) bool {
	return checkRevision.MatchString(request.SourceRevision) && checkRevision.MatchString(request.SourceTree) && checkDigest.MatchString(request.SubjectDigest)
}

func (runner CheckRunner) Run(ctx context.Context, request authorization.LocalCheckRequest) (authorization.LocalCheckCapture, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(runner.RepositoryRoot) || !validCheckRequest(request) {
		return authorization.LocalCheckCapture{}, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	switch request.ID {
	case "policy-conformance", "critical-mutations":
		args := []string{"go", "run", "-mod=readonly", "./tests/contract/localcheck", "--check-id", request.ID, "--subject-digest", request.SubjectDigest, "--source-revision", request.SourceRevision, "--source-tree", request.SourceTree}
		return captureCheck(ctx, runner.RepositoryRoot, filepath.Join(runner.RepositoryRoot, "scripts/run_pinned_go.sh"), args, nil)
	case "dependency-review":
		return runner.dependencies(ctx, request)
	case "offline-verification":
		if len(request.Archive) == 0 || len(request.Archive) > 8<<20 || policyrelease.SHA256Digest(request.Archive) != request.SubjectDigest {
			return authorization.LocalCheckCapture{}, ErrConfiguration
		}
		executable, err := os.Executable()
		if err != nil {
			return authorization.LocalCheckCapture{}, ErrConfiguration
		}
		// Events are retained even on failure for diagnosis, never silently erased.
		events, err := os.MkdirTemp("", "stead-local-offline-events-")
		if err != nil {
			return authorization.LocalCheckCapture{}, ErrConfiguration
		}
		request.Files = nil // The completed archive contains the actual files checked.
		input, err := json.Marshal(request)
		if err != nil {
			return authorization.LocalCheckCapture{}, ErrConfiguration
		}
		return captureCheck(ctx, runner.RepositoryRoot, executable, []string{"dev-policy-check", "--repository", runner.RepositoryRoot, "--events", events}, input)
	default:
		return authorization.LocalCheckCapture{}, ErrConfiguration
	}
}

func actualReport(request authorization.LocalCheckRequest, cases []authorization.LocalCheckCase) authorization.LocalCheckReport {
	report := authorization.LocalCheckReport{SchemaVersion: "1.0.0", CheckID: request.ID, SubjectDigest: request.SubjectDigest, SourceRevision: request.SourceRevision, SourceTree: request.SourceTree, Total: len(cases), Cases: cases}
	for _, entry := range cases {
		if entry.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
	}
	return report
}

func checkIdentifier() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", ErrConfiguration
	}
	return hex.EncodeToString(material[:]), nil
}

func decodeCheckInput(data []byte, request *authorization.LocalCheckRequest) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ErrConfiguration
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return ErrConfiguration
		}
		switch key {
		case "ID", "SubjectDigest", "SourceRevision", "SourceTree", "Files", "Archive":
		default:
			return ErrConfiguration
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return ErrConfiguration
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(seen) != 6 {
		return ErrConfiguration
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrConfiguration
	}
	if json.Unmarshal(data, request) != nil {
		return ErrConfiguration
	}
	return nil
}

// Dependency checks re-execute approval/lock consistency, exact module cache
// integrity and the npm advisory review. They do not relabel prior govulncheck
// results as a new scan; actual runtime binary scans remain an integration gate.
func (runner CheckRunner) dependencies(ctx context.Context, request authorization.LocalCheckRequest) (authorization.LocalCheckCapture, error) {
	capture := authorization.LocalCheckCapture{StartedAt: time.Now().UTC()}
	cases := []authorization.LocalCheckCase{}
	raw := &boundedOutput{limit: 256 << 10}
	for _, check := range []struct {
		id, executable string
		args           []string
	}{
		{"approved-dependency-locks", "/usr/bin/ruby", []string{"scripts/validate_dependencies.rb", "--release"}},
		{"go-module-integrity", filepath.Join(runner.RepositoryRoot, "scripts/run_pinned_go.sh"), []string{"go", "mod", "verify"}},
		{"npm-vulnerability-review", filepath.Join(runner.RepositoryRoot, "scripts/run_pinned_node.sh"), []string{"npm", "audit", "--json", "--audit-level=high"}},
	} {
		result, err := captureCheck(ctx, runner.RepositoryRoot, check.executable, check.args, nil)
		if err != nil {
			return capture, err
		}
		cases = append(cases, authorization.LocalCheckCase{ID: check.id, Passed: result.ExitCode == 0})
		// Quoted process output is evidence, not an interpreted PASS string.
		encoded, _ := json.Marshal(struct {
			Check          string
			ExitCode       int
			Stdout, Stderr string
		}{check.id, result.ExitCode, string(result.Stdout), string(result.Stderr)})
		if _, err := raw.Write(append(encoded, '\n')); err != nil {
			return capture, ErrConfiguration
		}
	}
	report := actualReport(request, cases)
	capture.Stdout, _ = json.Marshal(report)
	capture.Stderr = append([]byte(nil), raw.Bytes()...)
	capture.FinishedAt = time.Now().UTC()
	if report.Failed != 0 {
		capture.ExitCode = 1
	}
	return capture, nil
}

// RunOfflineCommand is an internal, nonauthorizing CLI. Only its real archive
// verification result is emitted; it never creates a VerifiedActivation or key.
func RunOfflineCommand(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("dev-policy-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("repository", "", "reviewed checkout")
	events := flags.String("events", "", "private retained event directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !filepath.IsAbs(*root) || PrivateDirectory(*events) != nil {
		return ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(input, 12<<20+1))
	if err != nil || len(data) > 12<<20 {
		return ErrConfiguration
	}
	var request authorization.LocalCheckRequest
	if decodeCheckInput(data, &request) != nil || !validCheckRequest(request) || request.ID != "offline-verification" || len(request.Files) != 0 || policyrelease.SHA256Digest(request.Archive) != request.SubjectDigest {
		return ErrConfiguration
	}
	id, err := checkIdentifier()
	if err != nil {
		return ErrConfiguration
	}
	workflow, err := policyrelease.NewObservedWorkflow(policyrelease.LifecycleContext{OperationID: id, CorrelationID: id, CausationID: id}, policyrelease.LifecycleObserverFunc(func(event policyrelease.LifecycleEvent) (policyrelease.LifecycleAcknowledgement, error) {
		encoded, err := json.Marshal(event)
		if err != nil {
			return policyrelease.LifecycleAcknowledgement{}, ErrConfiguration
		}
		name, err := checkIdentifier()
		if err != nil {
			return policyrelease.LifecycleAcknowledgement{}, ErrConfiguration
		}
		if WriteExclusive(filepath.Join(*events, name+".json"), encoded) != nil {
			return policyrelease.LifecycleAcknowledgement{}, ErrConfiguration
		}
		return policyrelease.AcknowledgeLifecycleEvent(event), nil
	}))
	if err != nil {
		return ErrConfiguration
	}
	err = authorization.CheckLocalDevelopmentArchive(ctx, *root, request.Archive, workflow, time.Now().UTC())
	report := actualReport(request, []authorization.LocalCheckCase{{ID: "actual-archive-signatures-trust-policy-and-evidence", Passed: err == nil}})
	if json.NewEncoder(output).Encode(report) != nil {
		return ErrConfiguration
	}
	if err != nil {
		return fmt.Errorf("offline archive verification failed: %w", ErrConfiguration)
	}
	return nil
}
