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

func TestHostAnchorWaitsForBriefActualFileLockContention(t *testing.T) {
	for _, operation := range []string{"read", "compare-max"} {
		t.Run(operation, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			binding := bindingFixture()
			anchor, err := CreateLocalAnchor(filepath.Join(directory, "anchor.json"), AnchorState{Binding: binding, PolicyTimeHighWater: now, PolicyTimeRevision: 1})
			if err != nil {
				t.Fatal(err)
			}
			held, release, holderDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				holderDone <- anchor.locked(context.Background(), func() error { close(held); <-release; return nil })
			}()
			<-held
			result := make(chan error, 1)
			go func() {
				var err error
				if operation == "read" {
					_, err = anchor.Read(context.Background())
				} else {
					_, err = anchor.CompareMax(context.Background(), binding, now.Add(time.Second))
				}
				result <- err
			}()
			select {
			case err := <-result:
				close(release)
				<-holderDone
				t.Fatal("brief contention returned before lock release", err)
			case <-time.After(10 * time.Millisecond):
			}
			close(release)
			if err := <-holderDone; err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal("valid independent anchor denied after lock release", err)
			}
			current, err := anchor.Read(context.Background())
			if err != nil || current.Binding != binding || current.PolicyTimeHighWater.Before(now) {
				t.Fatal("contention changed or rolled back authority")
			}
			if operation == "compare-max" && (!current.PolicyTimeHighWater.Equal(now.Add(time.Second)) || current.PolicyTimeRevision != 2) {
				t.Fatal("compare-max did not persist its monotonic advance")
			}
		})
	}
}

func TestHostAnchorLockWaitRemainsBoundedAndCancellationAware(t *testing.T) {
	for _, name := range []string{"hard-cap", "deadline", "cancellation"} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			anchor, err := CreateLocalAnchor(filepath.Join(directory, "anchor.json"), AnchorState{Binding: bindingFixture(), PolicyTimeHighWater: time.Now().UTC(), PolicyTimeRevision: 1})
			if err != nil {
				t.Fatal(err)
			}
			held, release, holderDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				holderDone <- anchor.locked(context.Background(), func() error { close(held); <-release; return nil })
			}()
			<-held
			defer func() { close(release); <-holderDone }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "deadline" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer deadlineCancel()
			}
			if name == "cancellation" {
				timer := time.AfterFunc(10*time.Millisecond, cancel)
				defer timer.Stop()
			}
			started := time.Now()
			if _, err := anchor.Read(ctx); err != ErrDenied {
				t.Fatal("held anchor admitted")
			}
			elapsed := time.Since(started)
			if elapsed > time.Second || (name == "hard-cap" && elapsed < localAnchorLockWait) {
				t.Fatal("anchor lock wait escaped fixed bound", elapsed)
			}
			if name != "hard-cap" && ctx.Err() == nil {
				t.Fatal("context did not govern waiting")
			}
		})
	}
}
