package authorization

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func localSourceFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, path := range localSourceFiles {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("unit source\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "--quiet"}, {"add", "."}, {"-c", "user.name=Unit Test", "-c", "user.email=unit@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "unit fixture"}} {
		command := exec.Command("/usr/bin/git", append([]string{"-C", root}, args...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %s %v", output, err)
		}
	}
	return root
}

func TestLocalSourceInspectionDetectsDirtyAndIndexHiddenInputs(t *testing.T) {
	root := localSourceFixture(t)
	if _, err := InspectLocalTemplateSource(context.Background(), root); err != nil {
		t.Fatal("clean source denied")
	}
	if output, err := exec.Command("/usr/bin/git", "-C", root, "update-index", "--assume-unchanged", "go.mod").CombinedOutput(); err != nil {
		t.Fatalf("test index: %s %v", output, err)
	}
	if _, err := InspectLocalTemplateSource(context.Background(), root); err != ErrDenied {
		t.Fatal("index-hidden compiler input accepted")
	}
	if output, err := exec.Command("/usr/bin/git", "-C", root, "update-index", "--no-assume-unchanged", "go.mod").CombinedOutput(); err != nil {
		t.Fatalf("test index: %s %v", output, err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("changed source\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectLocalTemplateSource(context.Background(), root); err != ErrDenied {
		t.Fatal("dirty source admitted")
	}
}

func TestLocalSourceInspectionRejectsIgnoredCompilerSource(t *testing.T) {
	root := localSourceFixture(t)
	if err := os.WriteFile(filepath.Join(root, ".git/info/exclude"), []byte("hidden.go\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hidden.go"), []byte("package unauthorized\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectLocalTemplateSource(context.Background(), root); err != ErrDenied {
		t.Fatal("ignored unreviewed code admitted")
	}
}
