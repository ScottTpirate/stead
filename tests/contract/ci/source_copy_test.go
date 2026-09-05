package ci_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBranchCoverageCopyExcludesLocalServiceState(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	cache := filepath.Join(source, ".cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "private-state"), []byte("synthetic-private-state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "source.go"), []byte("package fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyBranchCoverageTree(source, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, ".cache")); !os.IsNotExist(err) {
		t.Fatal("private local state copied into instrumentation tree")
	}
	if _, err := os.Stat(filepath.Join(destination, "source.go")); err != nil {
		t.Fatal("actual source omitted")
	}
}
