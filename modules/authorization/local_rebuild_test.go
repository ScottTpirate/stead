package authorization

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestLocalToolchainDigestCoversSourceLinkerModesAndRejectsLinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "link"), []byte("reviewed linker"), 0700); err != nil {
		t.Fatal(err)
	}
	before, err := localToolchainDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "link"), []byte("changed linker"), 0700); err != nil {
		t.Fatal(err)
	}
	after, err := localToolchainDigest(root)
	if err != nil || before == after {
		t.Fatal("linker drift was not detected")
	}
	if err = os.Chmod(filepath.Join(root, "link"), 0600); err != nil {
		t.Fatal(err)
	}
	changedMode, err := localToolchainDigest(root)
	if err != nil || changedMode == after {
		t.Fatal("toolchain executable mode drift was not detected")
	}
	if err := os.Symlink("/usr/bin/go", filepath.Join(root, "go")); err != nil {
		t.Fatal(err)
	}
	if _, err = localToolchainDigest(root); err == nil {
		t.Fatal("toolchain symlink accepted")
	}
}

func TestLocalSourceExportUsesExactTrackedBytesAndRejectsArchiveOverrides(t *testing.T) {
	root := localSourceFixture(t)
	export := t.TempDir()
	if err := exportLocalSource(context.Background(), root, "HEAD", export); err != nil {
		t.Fatal("exact tracked source export denied", err)
	}
	for _, name := range localSourceFiles {
		got, err := os.ReadFile(filepath.Join(export, name))
		if err != nil || !bytes.Equal(got, []byte("unit source\n")) {
			t.Fatal("export differs from tracked source", name)
		}
	}
	for _, name := range []string{"../outside", "/absolute", ".git/config", "a/../b", "a\\b", "newline\n.go"} {
		if localExportPath(name) {
			t.Fatal("unsafe export path accepted")
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".gitattributes"), []byte("go.mod export-ignore\n"), 0600); err != nil {
		t.Fatal(err)
	}
	commitLocalRebuildFixture(t, root)
	if exportLocalSource(context.Background(), root, "HEAD", t.TempDir()) == nil {
		t.Fatal("export-ignore changed reviewed compiler closure")
	}
}

func TestLocalSourceExportRejectsTrackedSymlink(t *testing.T) {
	root := localSourceFixture(t)
	if err := os.Symlink("/tmp/outside-review.go", filepath.Join(root, "unreviewed.go")); err != nil {
		t.Fatal(err)
	}
	commitLocalRebuildFixture(t, root)
	if exportLocalSource(context.Background(), root, "HEAD", t.TempDir()) == nil {
		t.Fatal("tracked symlink escaped review-bound export")
	}
}

func commitLocalRebuildFixture(t *testing.T, root string) {
	t.Helper()
	for _, args := range [][]string{{"add", "."}, {"-c", "user.name=Unit Test", "-c", "user.email=unit@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "negative fixture"}} {
		command := exec.Command("/usr/bin/git", append([]string{"-C", root}, args...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %s %v", output, err)
		}
	}
}

func TestLocalBuildEnvironmentIgnoresInheritedOverridesAndNetwork(t *testing.T) {
	t.Setenv("GOFLAGS", "-overlay=unreviewed.json")
	t.Setenv("GOWORK", "/tmp/unreviewed.work")
	t.Setenv("GOPROXY", "https://unreviewed.invalid")
	environment := localBuildEnvironment("/private/rebuild", "/approved/toolchain")
	for _, required := range []string{"GOFLAGS=", "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOEXPERIMENT=", "GOPROXY=" + localModuleProxy, "GOSUMDB=off", "GOCACHE=/private/rebuild/build-cache", "GOMODCACHE=/private/rebuild/module-cache"} {
		if !slices.Contains(environment, required) {
			t.Fatal("closed build input missing", required)
		}
	}
	for _, value := range environment {
		if bytes.Contains([]byte(value), []byte("unreviewed")) {
			t.Fatal("unreviewed compiler input inherited")
		}
	}
}
