//go:build linux

package authorization

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// LocalAnchor is independently retained protected host state, outside the
// application database and its backups. This first implementation is for one
// local-development host only; no production HA, restore or rotation claim.
type LocalAnchor struct{ path string }

func safeAnchorPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}
func safeAnchorFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 64<<10 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid()) && stat.Nlink == 1
}

func OpenLocalAnchor(path string) (*LocalAnchor, error) {
	if !safeAnchorPath(path) || !safeAnchorFile(path) {
		return nil, ErrDenied
	}
	return &LocalAnchor{path: path}, nil
}

// CreateLocalAnchor is explicit first-install bootstrap, not a restore/reset
// command. An existing file is never overwritten, even when unreadable.
func CreateLocalAnchor(path string, state AnchorState) (*LocalAnchor, error) {
	if !safeAnchorPath(path) || !validAnchorState(state) {
		return nil, ErrDenied
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, ErrDenied
	}
	data, err := json.Marshal(state)
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, ErrDenied
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, ErrDenied
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		return nil, ErrDenied
	}
	return OpenLocalAnchor(path)
}

func validAnchorState(state AnchorState) bool {
	return validBinding(state.Binding) && !state.PolicyTimeHighWater.IsZero() && state.PolicyTimeRevision > 0
}

func (anchor *LocalAnchor) locked(ctx context.Context, action func() error) error {
	if anchor == nil || ctx.Err() != nil || !safeAnchorPath(anchor.path) {
		return ErrDenied
	}
	lockPath := anchor.path + ".lock"
	file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrDenied
	}
	defer file.Close()
	if !safeAnchorFile(lockPath) {
		return ErrDenied
	}
	// Non-blocking flock avoids waiting past a request's disclosure deadline.
	if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return ErrDenied
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if ctx.Err() != nil {
		return ErrDenied
	}
	return action()
}

func (anchor *LocalAnchor) readUnlocked() (AnchorState, error) {
	if !safeAnchorFile(anchor.path) {
		return AnchorState{}, ErrDenied
	}
	data, err := os.ReadFile(anchor.path)
	var state AnchorState
	if err != nil || decodeClosed(data, &state) != nil || !validAnchorState(state) {
		return AnchorState{}, ErrDenied
	}
	return state, nil
}
func (anchor *LocalAnchor) Read(ctx context.Context) (AnchorState, error) {
	var state AnchorState
	err := anchor.locked(ctx, func() error { var err error; state, err = anchor.readUnlocked(); return err })
	if err != nil {
		return AnchorState{}, ErrDenied
	}
	return state, nil
}

func (anchor *LocalAnchor) CompareMax(ctx context.Context, binding ActivationBinding, proposed time.Time) (AnchorState, error) {
	var state AnchorState
	err := anchor.locked(ctx, func() error {
		var err error
		state, err = anchor.readUnlocked()
		if err != nil || state.Binding != binding || proposed.IsZero() {
			return ErrDenied
		}
		if !proposed.After(state.PolicyTimeHighWater) {
			return nil
		}
		if state.PolicyTimeRevision == ^uint64(0) {
			return ErrDenied
		}
		state.PolicyTimeHighWater = proposed.UTC()
		state.PolicyTimeRevision++
		data, err := json.Marshal(state)
		if err != nil {
			return ErrDenied
		}
		file, err := os.CreateTemp(filepath.Dir(anchor.path), ".policy-time-")
		if err != nil {
			return ErrDenied
		}
		name := file.Name()
		defer os.Remove(name)
		if _, err = file.Write(data); err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return ErrDenied
		}
		if err = os.Rename(name, anchor.path); err != nil {
			return ErrDenied
		}
		directory, err := os.Open(filepath.Dir(anchor.path))
		if err != nil {
			return ErrDenied
		}
		defer directory.Close()
		if directory.Sync() != nil {
			return ErrDenied
		}
		return nil
	})
	if err != nil {
		return AnchorState{}, ErrDenied
	}
	return state, nil
}
