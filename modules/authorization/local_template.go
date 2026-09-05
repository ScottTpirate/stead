package authorization

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

const localTemplatePath = "modules/authorization/localdata/approved-template.json"
const localReviewPath = "docs/governance/local-development-template-review.json"

// This placeholder is intentionally ineligible until distinct reviewers have
// accepted the exact preceding compiler/source/test revision. No environment
// variable or external manifest path can replace this compiled-in trust input.
//
//go:embed localdata/approved-template.json
var approvedLocalTemplate []byte

var gitObjectPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

var localSubstitutionFields = []string{"installation_id", "issued_at", "expires_at", "instance_keys", "trust_envelope", "openfga_store_id", "openfga_model_id", "derived_digests"}

var localSourceFiles = []string{
	"go.mod", "go.sum", ".tool-versions",
	"modules/authorization/contract/decision-table.json", "modules/authorization/contract/deployment-local.json",
	"modules/authorization/contract/input-schema.json", "modules/authorization/contract/output-schema.json",
	"modules/authorization/" + localProfileContractPath(), "modules/authorization/contract/registries.json",
	"policies/openfga/model-v0.2.fga",
}

type localGitOutput struct{ bytes.Buffer }

func (output *localGitOutput) Write(data []byte) (int, error) {
	if output.Len()+len(data) > 1<<20 {
		return 0, ErrDenied
	}
	return output.Buffer.Write(data)
}

func gitLocal(ctx context.Context, root string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "/usr/bin/git", append([]string{"--no-pager", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-C", root}, args...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1", "LC_ALL=C"}
	var stdout localGitOutput
	command.Stdout = &stdout
	if err := command.Run(); err != nil || stdout.Len() > 1<<20 {
		return nil, ErrDenied
	}
	return bytes.TrimSpace(stdout.Bytes()), nil
}

func LocalTemplateCoreDigest(core LocalTemplateCore) string {
	data, _ := json.Marshal(core)
	return policyrelease.SHA256Digest(data)
}

// LocalPolicyDecisionCaseIDs returns the exact ordered row inventory embedded
// in this native evaluator's signed decision-table contract.
func LocalPolicyDecisionCaseIDs() []string {
	data, _ := contracts.ReadFile("contract/decision-table.json")
	var table struct {
		Cases []struct {
			ID string `json:"id"`
		} `json:"cases"`
	}
	if json.Unmarshal(data, &table) != nil {
		return nil
	}
	ids := []string{}
	for _, row := range table.Cases {
		ids = append(ids, row.ID)
	}
	return ids
}

// InspectLocalTemplateSource reports actual immutable source inputs for review
// assembly. It confers no approval and cannot enable the runtime constructor.
func InspectLocalTemplateSource(ctx context.Context, root string) (LocalTemplateCore, error) {
	core := LocalTemplateCore{GoVersion: runtime.Version(), PublicOrigin: "https://localhost:18443", OpenFGAURL: "http://127.0.0.1:18080", SecurityDomain: LocalDevelopmentSecurityDomain, ValiditySeconds: 86400, AllowedSubstitutions: append([]string{}, localSubstitutionFields...)}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return LocalTemplateCore{}, ErrDenied
	}
	for _, item := range []struct {
		field *string
		path  string
	}{{&core.GoBinaryDigest, filepath.Join(runtime.GOROOT(), "bin/go")}, {&core.GoCompilerDigest, filepath.Join(runtime.GOROOT(), "pkg/tool/linux_amd64/compile")}} {
		digest, err := localToolDigest(item.path)
		if err != nil {
			return LocalTemplateCore{}, err
		}
		*item.field = digest
	}
	status, err := gitLocal(ctx, root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil || len(status) != 0 {
		return LocalTemplateCore{}, ErrDenied
	}
	// Index hints must not hide edited compiler inputs from a clean-tree check.
	indexed, err := gitLocal(ctx, root, "ls-files", "-v", "-z")
	if err != nil {
		return LocalTemplateCore{}, ErrDenied
	}
	for _, entry := range bytes.Split(indexed, []byte{0}) {
		if len(entry) > 0 && entry[0] != 'H' {
			return LocalTemplateCore{}, ErrDenied
		}
	}
	// An ignored source file can still be compiled. Reject such hidden inputs;
	// generated/cache directories are not permission to add reviewed Go code.
	ignored, err := gitLocal(ctx, root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", ":(glob)**/*.go", ":(exclude).cache/**", ":(exclude)**/node_modules/**")
	if err != nil {
		return LocalTemplateCore{}, ErrDenied
	}
	for _, entry := range bytes.Split(ignored, []byte{0}) {
		path := string(entry)
		if strings.HasSuffix(path, ".go") && !strings.HasPrefix(path, ".cache/") && !strings.Contains(path, "/node_modules/") && !strings.HasPrefix(path, "node_modules/") {
			return LocalTemplateCore{}, ErrDenied
		}
	}
	for _, item := range []struct {
		field *string
		ref   string
	}{{&core.SourceRevision, "HEAD"}, {&core.SourceTree, "HEAD^{tree}"}} {
		value, err := gitLocal(ctx, root, "rev-parse", "--verify", item.ref)
		if err != nil || !gitObjectPattern.Match(value) {
			return LocalTemplateCore{}, ErrDenied
		}
		*item.field = string(value)
	}
	for _, path := range localSourceFiles {
		info, err := os.Lstat(filepath.Join(root, path))
		if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return LocalTemplateCore{}, ErrDenied
		}
		content, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return LocalTemplateCore{}, ErrDenied
		}
		digest := policyrelease.SHA256Digest(content)
		core.Files = append(core.Files, LocalTemplateFile{Path: path, Digest: digest})
		if path == "go.sum" {
			core.DependencyLockDigest = digest
		}
	}
	return core, nil
}

func localToolDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
		return "", ErrDenied
	}
	file, err := os.Open(path)
	if err != nil {
		return "", ErrDenied
	}
	defer file.Close()
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, 128<<20+1))
	if err != nil || count != info.Size() {
		return "", ErrDenied
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func validateLocalTemplate(manifest LocalTemplateManifest) error {
	core := manifest.Core
	if !digestPattern.MatchString(core.GoBinaryDigest) || !digestPattern.MatchString(core.GoCompilerDigest) {
		return ErrDenied
	}
	if manifest.SchemaVersion != "1.0.0" || manifest.Status != "approved" || !gitObjectPattern.MatchString(core.SourceRevision) || !gitObjectPattern.MatchString(core.SourceTree) || core.GoVersion == "" || core.SecurityDomain != LocalDevelopmentSecurityDomain || core.PublicOrigin != "https://localhost:18443" || core.OpenFGAURL != "http://127.0.0.1:18080" || core.ValiditySeconds != 86400 || !slices.Equal(core.AllowedSubstitutions, localSubstitutionFields) || len(core.Files) != len(localSourceFiles) || len(core.Checks) != 4 || len(manifest.Reviews) != 3 || !digestPattern.MatchString(core.DependencyLockDigest) {
		return ErrDenied
	}
	for i, file := range core.Files {
		if file.Path != localSourceFiles[i] || !digestPattern.MatchString(file.Digest) || (file.Path == "go.sum" && file.Digest != core.DependencyLockDigest) {
			return ErrDenied
		}
	}
	for i, id := range []string{"policy-conformance", "critical-mutations", "dependency-review", "offline-verification"} {
		check := core.Checks[i]
		rate := 100
		if id == "critical-mutations" {
			rate = 90
		}
		if check.ID != id || check.RequiredRate != rate || len(check.Cases) == 0 || len(check.Cases) > 512 {
			return ErrDenied
		}
		if id == "policy-conformance" && !slices.Equal(check.Cases, LocalPolicyDecisionCaseIDs()) {
			return ErrDenied
		}
		seen := map[string]bool{}
		for _, name := range check.Cases {
			if name == "" || len(name) > 160 || seen[name] {
				return ErrDenied
			}
			seen[name] = true
		}
	}
	coreDigest := LocalTemplateCoreDigest(core)
	seen := map[string]bool{}
	for i, role := range []string{"architecture-contract-owner", "qa", "security"} {
		review := manifest.Reviews[i]
		if review.Role != role || review.SourceRevision != core.SourceRevision || review.CoreDigest != coreDigest || review.RecordPath != localReviewPath || !digestPattern.MatchString(review.RecordDigest) || review.Disposition != "accept" || review.ReviewerID == "" || seen[review.ReviewerID] {
			return ErrDenied
		}
		seen[review.ReviewerID] = true
	}
	return nil
}

func loadLocalTemplate(ctx context.Context, root string) (LocalTemplateManifest, error) {
	var manifest LocalTemplateManifest
	if decodeClosed(approvedLocalTemplate, &manifest) != nil || validateLocalTemplate(manifest) != nil {
		return LocalTemplateManifest{}, ErrDenied
	}
	core := manifest.Core
	actual, err := InspectLocalTemplateSource(ctx, root)
	if err != nil || actual.GoVersion != core.GoVersion || actual.GoBinaryDigest != core.GoBinaryDigest || actual.GoCompilerDigest != core.GoCompilerDigest || actual.DependencyLockDigest != core.DependencyLockDigest || !slices.Equal(actual.Files, core.Files) {
		return LocalTemplateManifest{}, ErrDenied
	}
	tree, err := gitLocal(ctx, root, "rev-parse", "--verify", core.SourceRevision+"^{tree}")
	if err != nil || string(tree) != core.SourceTree {
		return LocalTemplateManifest{}, ErrDenied
	}
	if _, err := gitLocal(ctx, root, "merge-base", "--is-ancestor", core.SourceRevision, actual.SourceRevision); err != nil {
		return LocalTemplateManifest{}, ErrDenied
	}
	changed, err := gitLocal(ctx, root, "diff", "--no-ext-diff", "--name-only", core.SourceRevision, actual.SourceRevision, "--")
	if err != nil {
		return LocalTemplateManifest{}, ErrDenied
	}
	for _, path := range strings.Split(string(changed), "\n") {
		if path != "" && path != localTemplatePath && path != localReviewPath {
			return LocalTemplateManifest{}, ErrDenied
		}
	}
	templateBytes, err := os.ReadFile(filepath.Join(root, localTemplatePath))
	if err != nil || !bytes.Equal(templateBytes, approvedLocalTemplate) {
		return LocalTemplateManifest{}, ErrDenied
	}
	for _, review := range manifest.Reviews {
		record, err := os.ReadFile(filepath.Join(root, review.RecordPath))
		if err != nil || policyrelease.SHA256Digest(record) != review.RecordDigest {
			return LocalTemplateManifest{}, ErrDenied
		}
	}
	// The running installer must itself have been built from this clean reviewed
	// source or its exact metadata-only acceptance descendant, not an old binary
	// pointed at a newer checkout. No -ldflags or environment receipt bypass.
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return LocalTemplateManifest{}, ErrDenied
	}
	settings := map[string]string{}
	for _, setting := range build.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["vcs.revision"] != actual.SourceRevision || settings["vcs.modified"] != "false" {
		return LocalTemplateManifest{}, ErrDenied
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != "amd64" || settings["GOAMD64"] != "v1" || settings["CGO_ENABLED"] != "0" || settings["-buildmode"] != "exe" || settings["-compiler"] != "gc" || settings["-tags"] != "" || settings["GOEXPERIMENT"] != "" || settings["-ldflags"] != "" {
		return LocalTemplateManifest{}, ErrDenied
	}
	return manifest, nil
}
