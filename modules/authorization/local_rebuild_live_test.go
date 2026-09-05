package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This focused security gate builds and executes real stead-api binaries; it
// does not supply an approved template or mint a local activation. Run after
// committing the candidate source, with STEAD_LIVE_LOCAL_REBUILD=1.
func TestLiveLocalExecutableFixedRecipeAndOverlayRejection(t *testing.T) {
	if os.Getenv("STEAD_LIVE_LOCAL_REBUILD") != "1" {
		t.Skip("explicit clean-source executable provenance gate")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	actual, err := InspectLocalTemplateSource(ctx, root)
	if err != nil {
		t.Fatal("gate requires clean immutable source")
	}
	stage, err := os.MkdirTemp("", "stead-local-rebuild-proof-")
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the actual compiler/module-cache evidence. Go intentionally makes
	// unpacked module sources read-only; do not relax that boundary for cleanup.
	t.Logf("private executable provenance proof retained at %s", stage)
	checkout := filepath.Join(stage, "checkout")
	clone := exec.CommandContext(ctx, "/usr/bin/git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", root, checkout)
	clone.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1", "LC_ALL=C"}
	if output, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("isolated source clone: %s %v", output, err)
	}
	check := exec.CommandContext(ctx, "/usr/bin/git", "-C", checkout, "checkout", "--quiet", "--detach", actual.SourceRevision)
	check.Env = clone.Env
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("immutable checkout: %s %v", output, err)
	}
	// Automatic ancestor workspaces would break or redirect this build unless
	// the actual controlled build and independent rebuild both use GOWORK=off.
	if err := os.WriteFile(filepath.Join(stage, "go.work"), []byte("invalid unreviewed ancestor workspace\n"), 0600); err != nil {
		t.Fatal(err)
	}
	environment := localBuildEnvironment(stage, runtime.GOROOT())
	build := func(name, overlay string) string {
		t.Helper()
		executable := filepath.Join(stage, name)
		args := []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-pgo=off", "-o", executable}
		if overlay != "" {
			args = append(args, "-overlay", overlay)
		}
		args = append(args, "./apps/core")
		command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin/go"), args...)
		command.Dir, command.Env = checkout, environment
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("actual candidate build: %s %v", output, err)
		}
		return executable
	}
	baseline := build("reviewed-stead-api", "")
	command := exec.CommandContext(ctx, baseline, "dev-template-inspect")
	command.Dir, command.Env = checkout, environment
	start := time.Now()
	output, err := command.CombinedOutput()
	var observed LocalTemplateCore
	if err != nil || json.Unmarshal(output, &observed) != nil || observed.SourceRevision != actual.SourceRevision || observed.SourceTree != actual.SourceTree || observed.GoToolchainDigest != actual.GoToolchainDigest {
		t.Fatalf("fixed recipe/ancestor workspace isolation failed: %s %v", output, err)
	}
	t.Logf("real fixed-recipe binary self-comparison and ancestor go.work isolation PASS (%s)", time.Since(start).Round(time.Millisecond))
	main := filepath.Join(checkout, "apps/core/main.go")
	data, err := os.ReadFile(main)
	if err != nil || !bytes.Contains(data, []byte(`component.Run("stead-api"`)) {
		t.Fatal("overlay fixture source absent")
	}
	replacement := bytes.Replace(data, []byte(`component.Run("stead-api"`), []byte(`component.Run("unreviewed-binary"`), 1)
	overlaySource := filepath.Join(stage, "main-overlay.go")
	if err := os.WriteFile(overlaySource, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(stage, "overlay.json")
	encoded, _ := json.Marshal(struct{ Replace map[string]string }{map[string]string{main: overlaySource}})
	if err := os.WriteFile(overlay, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	changed := build("overlay-stead-api", overlay)
	command = exec.CommandContext(ctx, changed, "dev-template-inspect")
	command.Dir, command.Env = checkout, environment
	output, err = command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "clean immutable template source inspection failed") {
		t.Fatalf("unrecorded build overlay admitted: %s %v", output, err)
	}
	t.Log("real compiled overlay differs from independently rebuilt reviewed source: denied before activation PASS")
}
