package app

import (
	"context"
	"github.com/ScottTpirate/stead/modules/identity"
	"testing"
)

func TestCreatorActivatorCannotAuthorizeAnUnconfiguredOrUnsealedCall(t *testing.T) {
	if _, err := NewCreatorActivator(nil, nil, nil); err == nil {
		t.Fatal("missing owned ports accepted")
	}
	var activator *CreatorActivator
	if err := activator.Activate(context.Background(), identity.Authenticated{}, "019ed5bf-0000-7000-8000-000000000001"); err == nil {
		t.Fatal("unconfigured activation accepted")
	}
	activator = &CreatorActivator{}
	if err := activator.Activate(context.Background(), identity.Authenticated{}, "019ed5bf-0000-7000-8000-000000000001"); err == nil {
		t.Fatal("unsealed session reached provider or repository")
	}
}
