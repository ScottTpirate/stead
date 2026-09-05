package authorization

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
)

func TestCoordinatorSetTemporalAndClassificationBounds(t *testing.T) {
	for _, name := range []string{"anchor-time", "short-session", "short-context", "short-activation", "future-activation", "expired-activation", "rollback", "finished-expired", "all-classified-denied", "all-missing", "database-time-ahead"} {
		t.Run(name, func(t *testing.T) {
			coordinator, repo, session, now := coordinatorFixture(t, true)
			set := &setTestRepo{testRepo: repo, states: []State{repo.state}}
			coordinator.config.Repository = set
			coordinator.config.OpenFGA = batchServer(t, func(tuples []Tuple) []bool { return []bool{true} })
			wantEvaluation, wantExpiry := *now, now.Add(2*time.Second)
			wantDenied, wantMissing := false, false
			switch name {
			case "anchor-time":
				wantEvaluation = now.Add(time.Millisecond)
				wantExpiry = wantEvaluation.Add(2 * time.Second)
				coordinator.config.Anchor.(*testAnchor).state.PolicyTimeHighWater = wantEvaluation
			case "short-session":
				wantExpiry = now.Add(time.Second)
				repo.session.ExpiresAt = wantExpiry
				session = refreshedGuardSession(t, repo, now)
			case "short-context":
				wantExpiry = now.Add(time.Second)
				set.states[0].ContextExpiresAt = wantExpiry
			case "short-activation":
				wantExpiry = now.Add(time.Second)
				coordinator.config.Activation.expiresAt = wantExpiry
			case "future-activation":
				coordinator.config.Activation.issuedAt = now.Add(time.Second)
				wantDenied = true
			case "expired-activation":
				coordinator.config.Activation.expiresAt = *now
				wantDenied = true
			case "rollback":
				coordinator.config.Anchor.(*testAnchor).state.PolicyTimeHighWater = now.Add(MaxPolicyClockSkew + time.Second)
				wantDenied = true
			case "finished-expired":
				initial := *now
				calls := 0
				coordinator.config.Clock = func() time.Time {
					calls++
					if calls > 1 {
						return initial.Add(3 * time.Second)
					}
					return initial
				}
				wantDenied = true
			case "all-classified-denied":
				set.states[0].Label.SensitivityLevel = "restricted"
				wantMissing = true
			case "all-missing":
				set.states[0] = State{Resource: repo.state.Resource}
				wantMissing = true
			case "database-time-ahead":
				set.states[0].PolicyTimeHighWater = now.Add(time.Millisecond)
				wantMissing = true
			}
			ctx, counters := telemetry.Begin(context.Background())
			decisions, err := coordinator.AuthorizeSet(ctx, session, []ReadAuthorization{{OrganizationRead, repo.state.Resource}})
			if wantDenied {
				if err != ErrDenied || decisions != nil {
					t.Fatal("invalid set time/authority admitted")
				}
				return
			}
			if err != nil || len(decisions) != 1 {
				t.Fatal("aligned set outcome lost", err)
			}
			if wantMissing {
				if decisions[0] != nil || counters.Snapshot().OpenFGACalls != 0 || len(repo.denials) != 0 {
					t.Fatal("denied row leaked or reached provider")
				}
				return
			}
			if decisions[0] == nil || !decisions[0].Evidence().EvaluatedAt.Equal(wantEvaluation) || !decisions[0].Evidence().ExpiresAt.Equal(wantExpiry) {
				t.Fatal("shared set time bound lost")
			}
		})
	}
}

func TestOpenFGABatchInvalidTuplesNeverReachTransport(t *testing.T) {
	client := batchServer(t, func([]Tuple) []bool { t.Fatal("invalid tuple reached transport"); return nil })
	valid := Tuple{"user:" + userID, "viewer", "organization:" + orgID}
	for _, tuples := range [][]Tuple{nil, {valid, valid}, {{"user:invalid", "viewer", valid.Object}}, {{valid.User, "unknown relation", valid.Object}}} {
		if result, err := client.BatchCheck(context.Background(), tuples); err != ErrDenied || result != nil {
			t.Fatal("invalid batch tuple accepted")
		}
	}
}

func TestCoordinatorSetInvalidShapeStopsBeforeRepository(t *testing.T) {
	for _, name := range []string{"nil-coordinator", "nil-context", "empty", "duplicate", "wrong-kind"} {
		t.Run(name, func(t *testing.T) {
			coordinator, repo, session, _ := coordinatorFixture(t, true)
			set := &setTestRepo{testRepo: repo, states: []State{repo.state}}
			coordinator.config.Repository = set
			ctx := context.Background()
			reads := []ReadAuthorization{{OrganizationRead, repo.state.Resource}}
			switch name {
			case "nil-coordinator":
				coordinator = nil
			case "nil-context":
				ctx = nil
			case "empty":
				reads = nil
			case "duplicate":
				reads = append(reads, reads[0])
				set.states = append(set.states, set.states[0])
			case "wrong-kind":
				reads[0].Target.Kind = "team"
				set.states[0].Resource = reads[0].Target
			}
			decisions, err := coordinator.AuthorizeSet(ctx, session, reads)
			if err != ErrDenied || decisions != nil || set.batchReads != 0 {
				t.Fatal("invalid set shape reached state repository")
			}
		})
	}
}

func TestCoordinatorSetProviderFailureDeniesWholeSet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	client, err := NewOpenFGA(OpenFGAConfig{URL: server.URL, StoreID: modelID, ModelID: modelID, LocalDevelopment: true})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, repo, session, _ := coordinatorFixture(t, true)
	set := &setTestRepo{testRepo: repo, states: []State{repo.state}}
	coordinator.config.Repository, coordinator.config.OpenFGA = set, client
	ctx, counters := telemetry.Begin(context.Background())
	decisions, err := coordinator.AuthorizeSet(ctx, session, []ReadAuthorization{{OrganizationRead, repo.state.Resource}})
	if err != ErrDenied || decisions != nil || set.batchReads != 1 || counters.Snapshot().OpenFGACalls != 1 {
		t.Fatal("failed provider result was not a whole-set denial")
	}
}
