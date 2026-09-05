package postgres

import (
	"context"
	"testing"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/jackc/pgx/v5"
)

func TestInvalidStateSetsNeverReachSQL(t *testing.T) {
	id := "019ed5bf-0000-7000-8000-000000000001"
	valid := authorization.ResourceRef{Kind: "team", ID: id}
	for _, refs := range [][]authorization.ResourceRef{nil, {valid, valid}, {{Kind: "provider", ID: id}}, {{Kind: "team", ID: "invalid"}}, make([]authorization.ResourceRef, maxStateSet+1)} {
		store := &Store{}
		_, err := store.readStates(context.Background(), identity.Principal{Type: "user", ID: id}, id, refs, false, func(string, func(pgx.Tx) error) error {
			t.Fatal("invalid state set reached SQL")
			return nil
		})
		if err == nil {
			t.Fatal("invalid state set accepted")
		}
	}
}

func TestUnsealedResourceSetsNeverReachSQL(t *testing.T) {
	store := &Store{}
	for _, decisions := range [][]*authorization.Decision{nil, {nil}, {{}}, make([]*authorization.Decision, maxStateSet+1)} {
		if _, err := store.GetOrganizations(context.Background(), decisions); err == nil {
			t.Fatal("unsealed organization set accepted")
		}
		if _, err := store.GetTeams(context.Background(), decisions); err == nil {
			t.Fatal("unsealed team set accepted")
		}
		if _, err := store.GetProjects(context.Background(), decisions); err == nil {
			t.Fatal("unsealed project set accepted")
		}
	}
}
