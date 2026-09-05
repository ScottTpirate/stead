//go:build linux

package authorization

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHostAnchorTimeSurvivesDatabaseRollbackAndRejectsReplacement(t *testing.T) {
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private test directory")
	}
	path := filepath.Join(directory, "policy-anchor.json")
	now := time.Now().UTC()
	binding := bindingFixture()
	anchor, err := CreateLocalAnchor(path, AnchorState{Binding: binding, PolicyTimeHighWater: now, PolicyTimeRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	advanced, err := anchor.CompareMax(context.Background(), binding, now.Add(time.Second))
	if err != nil || advanced.PolicyTimeRevision != 2 {
		t.Fatal("anchor did not advance")
	}
	// Simulate application state rollback by reopening the independent file
	// with the old observed DB time. Equal/lower time cannot reset it.
	reopened, err := OpenLocalAnchor(path)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := reopened.CompareMax(context.Background(), binding, now)
	if err != nil || latest != advanced {
		t.Fatal("time rolled back with application")
	}
	if _, err := CreateLocalAnchor(path, AnchorState{Binding: binding, PolicyTimeHighWater: now, PolicyTimeRevision: 1}); err != ErrDenied {
		t.Fatal("existing anchor reset")
	}
	binding.ActivationSequence++
	if _, err := anchor.CompareMax(context.Background(), binding, now); err != ErrDenied {
		t.Fatal("mismatched activation selection")
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("change test mode")
	}
	if _, err := anchor.Read(context.Background()); err != ErrDenied {
		t.Fatal("public anchor accepted")
	}
}

func TestHostAnchorRejectsSymlinkAndPublicParent(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "policy-anchor.json")
	state := AnchorState{Binding: bindingFixture(), PolicyTimeHighWater: time.Now().UTC(), PolicyTimeRevision: 1}
	os.Chmod(directory, 0755)
	if _, err := CreateLocalAnchor(path, state); err != ErrDenied {
		t.Fatal("public directory")
	}
	os.Chmod(directory, 0700)
	if _, err := CreateLocalAnchor(path, state); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if os.Symlink(path, link) != nil {
		t.Fatal("test symlink")
	}
	if _, err := OpenLocalAnchor(link); err != ErrDenied {
		t.Fatal("symlink anchor")
	}
}
