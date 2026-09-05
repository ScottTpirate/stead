package authorization

import (
	"testing"
	"time"
)

func TestSealedActivationReadinessCannotExtendValidity(t *testing.T) {
	coordinator, _, _, now := coordinatorFixture(t, true)
	activation := coordinator.config.Activation
	if !activation.ValidAt(*now) || activation.ValidAt(activation.issuedAt.Add(-time.Nanosecond)) || activation.ValidAt(activation.expiresAt) || (*VerifiedActivation)(nil).ValidAt(*now) {
		t.Fatal("invalid activation readiness window")
	}
	if _, _, err := activation.LocalBootstrapDefaults(); err != ErrDenied {
		t.Fatal("nonlocal evidence acquired development defaults")
	}
	draft, _ := localUnitDraft(t)
	artifacts, err := draft.Finalize(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	label, ceilings, err := artifacts.Activation.LocalBootstrapDefaults()
	if err != nil || label.ProfileID == "" || ceilings[label.ProfileID] == "" {
		t.Fatal("signed local metadata unavailable")
	}
	ceilings[label.ProfileID] = "wrong"
	_, fresh, err := artifacts.Activation.LocalBootstrapDefaults()
	if err != nil || fresh[label.ProfileID] == "wrong" {
		t.Fatal("mutable signed defaults")
	}
}
