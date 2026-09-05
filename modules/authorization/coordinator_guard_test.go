package authorization

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/ScottTpirate/stead/modules/identity"
)

func refreshedGuardSession(t *testing.T, repo *testRepo, now *time.Time) identity.Authenticated {
	t.Helper()
	authenticator, err := identity.NewLocalAuthenticator(repo, instanceID, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := identity.NewLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := authenticator.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestCoordinatorCanonicalStateBindings(t *testing.T) {
	coordinator, repo, session, now := coordinatorFixture(t, true)
	binding := coordinator.config.Activation.binding
	if !validState(repo.state, session.Context(), repo.state.Resource, binding, *now) {
		t.Fatal("valid canonical state denied")
	}
	otherSession := session.Context()
	otherSession.InstanceID = orgID
	otherState := repo.state
	otherState.InstanceID = orgID
	if validState(otherState, otherSession, otherState.Resource, binding, *now) {
		t.Fatal("foreign installation bound to local activation")
	}
	instance := repo.state
	instance.Resource = ResourceRef{"instance", instanceID}
	instance.OrganizationID = ""
	if !validState(instance, session.Context(), instance.Resource, binding, *now) {
		t.Fatal("instance scope lost")
	}
	team := repo.state
	team.Resource.Kind = "team"
	team.OrganizationID = "invalid"
	if validState(team, session.Context(), team.Resource, binding, *now) {
		t.Fatal("invalid team container admitted")
	}
}

func TestCoordinatorTemporalAuthorityGuards(t *testing.T) {
	for _, name := range []string{"nil", "cancelled", "anchor-binding", "anchor-revision", "rollback", "future-activation", "expired-activation", "database-time-ahead", "database-revision-ahead", "finished-expired"} {
		t.Run(name, func(t *testing.T) {
			coordinator, repo, session, now := coordinatorFixture(t, true)
			ctx, counters := telemetry.Begin(context.Background())
			anchor := coordinator.config.Anchor.(*testAnchor)
			expectedReads := 0
			switch name {
			case "nil":
				coordinator = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "anchor-binding":
				anchor.state.Binding.TrustEpoch++
			case "anchor-revision":
				anchor.state.PolicyTimeRevision = 0
			case "rollback":
				anchor.state.PolicyTimeHighWater = now.Add(MaxPolicyClockSkew + time.Second)
			case "future-activation":
				coordinator.config.Activation.issuedAt = now.Add(time.Second)
			case "expired-activation":
				coordinator.config.Activation.expiresAt = *now
			case "database-time-ahead":
				repo.state.PolicyTimeHighWater = now.Add(time.Millisecond)
				expectedReads = 1
			case "database-revision-ahead":
				repo.state.PolicyTimeRevision++
				expectedReads = 1
			case "finished-expired":
				calls := 0
				initial := *now
				coordinator.config.Clock = func() time.Time {
					calls++
					if calls > 1 {
						return initial.Add(3 * time.Second)
					}
					return initial
				}
				expectedReads = 1
			}
			if decision, err := coordinator.Authorize(ctx, session, OrganizationRead, repo.state.Resource); err != ErrDenied || decision != nil {
				t.Fatal("unsafe authority/time admitted")
			}
			if repo.reads != expectedReads {
				t.Fatal("denied prerequisite reached later storage", repo.reads, expectedReads)
			}
			if name != "finished-expired" && counters.Snapshot().OpenFGACalls != 0 {
				t.Fatal("denied prerequisite reached relationship service")
			}
		})
	}
}

func TestCoordinatorExactClockAndExpiryBounds(t *testing.T) {
	for _, bound := range []string{"anchor", "session", "context", "activation"} {
		t.Run(bound, func(t *testing.T) {
			coordinator, repo, session, now := coordinatorFixture(t, true)
			wantEvaluation, wantExpiry := *now, now.Add(2*time.Second)
			switch bound {
			case "anchor":
				wantEvaluation = now.Add(time.Millisecond)
				wantExpiry = wantEvaluation.Add(2 * time.Second)
				coordinator.config.Anchor.(*testAnchor).state.PolicyTimeHighWater = wantEvaluation
			case "context":
				wantExpiry = now.Add(time.Second)
				repo.state.ContextExpiresAt = wantExpiry
			case "activation":
				wantExpiry = now.Add(time.Second)
				coordinator.config.Activation.expiresAt = wantExpiry
			case "session":
				// The authenticated session is sealed; construct a fresh valid one
				// through its real authenticator rather than altering its seal.
				wantExpiry = now.Add(time.Second)
				repo.session.ExpiresAt = wantExpiry
				session = refreshedGuardSession(t, repo, now)
			}
			decision, err := coordinator.Authorize(context.Background(), session, OrganizationRead, repo.state.Resource)
			if err != nil || !decision.Evidence().EvaluatedAt.Equal(wantEvaluation) || !decision.Evidence().ExpiresAt.Equal(wantExpiry) {
				t.Fatal("authorization timing bound lost", err)
			}
		})
	}
}

func TestCoordinatorFinalAnchorAndSealGuards(t *testing.T) {
	coordinator, repo, session, now := coordinatorFixture(t, true)
	decision, err := coordinator.Authorize(context.Background(), session, OrganizationRead, repo.state.Resource)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unsealed", "time-regression", "revision-regression", "excessive-rollback", "anchored-expiry"} {
		t.Run(name, func(t *testing.T) {
			current := repo.state
			candidate := decision
			checkTime := *now
			switch name {
			case "unsealed":
				copy := *decision
				copy.valid = false
				candidate = &copy
			case "time-regression":
				current.PolicyTimeHighWater = now.Add(-time.Millisecond)
			case "revision-regression":
				current.PolicyTimeRevision = 0
			case "excessive-rollback":
				copy := *decision
				copy.evidence.ExpiresAt = now.Add(time.Minute)
				candidate = &copy
				current.PolicyTimeHighWater = now.Add(MaxPolicyClockSkew + time.Second)
			case "anchored-expiry":
				current.PolicyTimeHighWater = now.Add(2 * time.Second)
				current.PolicyTimeRevision++
			}
			if candidate.ValidateFinal(current, checkTime) != ErrDenied {
				t.Fatal("invalid final seal accepted")
			}
		})
	}
	if !reflect.DeepEqual(decision.state, repo.state) {
		t.Fatal("final guard checks mutated sealed state")
	}
}
