package component

import (
	"bytes"
	"testing"
)

func TestVersionIdentity(t *testing.T) {
	for _, name := range []string{"stead-api", "stead-worker", "steadctl"} {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if code := Run(name, []string{"--version"}, &stdout, &stderr); code != 0 {
				t.Fatalf("Run() code = %d, want 0", code)
			}
			if got, want := stdout.String(), name+" "+Version+"\n"; got != want {
				t.Fatalf("stdout = %q, want %q", got, want)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestUnconfiguredRuntimeFailsExplicitly(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run("stead-api", nil, &stdout, &stderr); code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if got, want := stderr.String(), "stead-api: Phase 1 runtime is not configured; use --version\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}
