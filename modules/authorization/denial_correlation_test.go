package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ScottTpirate/stead/internal/telemetry"
)

func TestCoordinatorDenialRetainsOnlyBoundedRequestCorrelation(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	for _, set := range []bool{false, true} {
		path := "single"
		if set {
			path = "set"
		}
		for _, tc := range []struct {
			name, input, want string
		}{
			{"trusted", id, id},
			{"absent", "", ""},
			{"invalid", "untrusted-resource-or-credential", ""},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				coordinator, repo, session, _ := coordinatorFixture(t, false)
				ctx := context.Background()
				if tc.name != "absent" {
					ctx = telemetry.WithCorrelationID(ctx, tc.input)
				}
				ctx, _ = telemetry.Begin(ctx)
				ctx = WithoutDecisions(ctx)
				var err error
				if set {
					// A whole-set repository failure emits a reason-safe denial.
					// Missing individual rows remain aligned nil slots as before.
					coordinator.config.Repository = &setTestRepo{testRepo: repo, err: ErrDenied}
					_, err = coordinator.AuthorizeSet(ctx, session, []ReadAuthorization{{Action: OrganizationRead, Target: repo.state.Resource}})
				} else {
					_, err = coordinator.Authorize(ctx, session, OrganizationRead, repo.state.Resource)
				}
				if !errors.Is(err, ErrDenied) || len(repo.denials) != 1 {
					t.Fatalf("denial missing: %v, %d records", err, len(repo.denials))
				}
				denial := repo.denials[0]
				if denial.RequestID != tc.want || len(denial.DecisionID) != 32 || denial.DecisionID == id || denial.Actor != session.Principal() || denial.Action != OrganizationRead || denial.OccurredAt.IsZero() {
					t.Fatal("durable denial lost its request/decision/actor binding")
				}
				encoded, err := json.Marshal(denial)
				if err != nil || !strings.Contains(string(encoded), `"RequestID":"`+tc.want+`"`) || strings.Contains(string(encoded), repo.state.Resource.ID) || strings.Contains(string(encoded), "untrusted-resource-or-credential") {
					t.Fatal("durable evidence omitted safe correlation or included unsafe request/resource metadata")
				}
			})
		}
	}
}

func TestCollectionRequiredDenialSanitizesRequestCorrelation(t *testing.T) {
	for _, input := range []string{"0123456789abcdef0123456789abcdef", "", "untrusted-resource-or-credential"} {
		t.Run(input, func(t *testing.T) {
			coordinator, repo, session, _ := coordinatorFixture(t, false)
			coordinator.config.Repository = &setTestRepo{testRepo: repo, states: []State{{Resource: repo.state.Resource}}}
			ctx := WithoutDecisions(telemetry.WithCorrelationID(context.Background(), input))
			decisions, err := coordinator.AuthorizeCollection(ctx, session, []ReadAuthorization{{OrganizationRead, repo.state.Resource}}, true)
			if err != nil || len(decisions) != 1 || decisions[0] != nil || len(repo.denials) != 1 {
				t.Fatal("required missing parent was not one aligned audited denial")
			}
			want := ""
			if input == "0123456789abcdef0123456789abcdef" {
				want = input
			}
			if repo.denials[0].RequestID != want {
				t.Fatal("untrusted request metadata entered the denial")
			}
		})
	}
}
