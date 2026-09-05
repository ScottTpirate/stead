package authorization

import (
	"context"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/ScottTpirate/stead/modules/identity"
)

type advancingReadRepo struct {
	*testRepo
	duringRead func()
}

type firstReadErrorAnchor struct {
	*testAnchor
	reads int
}

func (anchor *firstReadErrorAnchor) Read(context.Context) (AnchorState, error) {
	anchor.reads++
	if anchor.reads == 1 {
		return anchor.state, ErrDenied
	}
	return anchor.state, nil
}

func (repo *advancingReadRepo) ReadState(context.Context, identity.Principal, string, ResourceRef) (State, error) {
	repo.duringRead()
	return repo.state, nil
}
func (repo *advancingReadRepo) ReadStates(context.Context, identity.Principal, string, []ResourceRef) ([]State, error) {
	repo.duringRead()
	return []State{repo.state}, nil
}

func TestCoordinatorBracketsStateReadsWithCurrentHostAnchor(t *testing.T) {
	for _, mode := range []string{"single", "set"} {
		for _, name := range []string{"concurrent-advance", "first-anchor-error", "first-clock-rollback", "anchor-time-regression", "anchor-revision-regression", "binding-change", "database-time-ahead", "database-revision-ahead", "clock-rollback", "original-expiry", "session-expiry", "context-expiry", "activation-expiry", "finished-expiry", "finished-clock-rollback"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				coordinator, repo, session, now := coordinatorFixture(t, true)
				initial := *now
				anchor := coordinator.config.Anchor.(*testAnchor)
				if mode == "set" {
					coordinator.config.OpenFGA = batchServer(t, func(tuples []Tuple) []bool { return []bool{true} })
				}
				switch name {
				case "first-anchor-error":
					coordinator.config.Anchor = &firstReadErrorAnchor{testAnchor: anchor}
				case "first-clock-rollback":
					calls := 0
					coordinator.config.Clock = func() time.Time {
						calls++
						if calls == 1 {
							return initial.Add(-MaxPolicyClockSkew - time.Second)
						}
						return initial
					}
				case "session-expiry":
					repo.session.ExpiresAt = initial.Add(time.Millisecond)
					session = refreshedGuardSession(t, repo, now)
				case "context-expiry":
					repo.state.ContextExpiresAt = initial.Add(time.Millisecond)
				case "activation-expiry":
					coordinator.config.Activation.expiresAt = initial.Add(time.Millisecond)
				case "finished-clock-rollback", "finished-expiry":
					calls := 0
					coordinator.config.Clock = func() time.Time {
						calls++
						if calls > 2 {
							if name == "finished-expiry" {
								return initial.Add(2 * time.Second)
							}
							return initial.Add(-MaxPolicyClockSkew - time.Second)
						}
						return initial
					}
				}
				coordinator.config.Repository = &advancingReadRepo{testRepo: repo, duringRead: func() {
					// Another request persists its independent host advance before
					// committing the same DB copy while our state read is in flight.
					anchor.state.PolicyTimeHighWater = initial.Add(time.Millisecond)
					anchor.state.PolicyTimeRevision++
					repo.state.PolicyTimeHighWater = anchor.state.PolicyTimeHighWater
					repo.state.PolicyTimeRevision = anchor.state.PolicyTimeRevision
					switch name {
					case "anchor-time-regression":
						anchor.state.PolicyTimeHighWater = initial.Add(-time.Millisecond)
					case "anchor-revision-regression":
						anchor.state.PolicyTimeRevision = 0
					case "binding-change":
						anchor.state.Binding.ActivationSequence++
					case "database-time-ahead":
						repo.state.PolicyTimeHighWater = initial.Add(2 * time.Millisecond)
					case "database-revision-ahead":
						repo.state.PolicyTimeRevision++
					case "clock-rollback":
						*now = initial.Add(-MaxPolicyClockSkew - time.Second)
					case "original-expiry":
						*now = initial.Add(2 * time.Second)
					}
				}}
				ctx, counters := telemetry.Begin(context.Background())
				var decision *Decision
				var err error
				if mode == "single" {
					decision, err = coordinator.Authorize(ctx, session, OrganizationRead, repo.state.Resource)
				} else {
					var decisions []*Decision
					decisions, err = coordinator.AuthorizeSet(ctx, session, []ReadAuthorization{{OrganizationRead, repo.state.Resource}})
					if len(decisions) == 1 {
						decision = decisions[0]
					}
				}
				if name != "concurrent-advance" {
					alignedDenial := mode == "set" && (name == "database-time-ahead" || name == "database-revision-ahead" || name == "context-expiry")
					if decision != nil || (alignedDenial && err != nil) || (!alignedDenial && err != ErrDenied) {
						t.Fatal("unsafe post-read authority admitted", err)
					}
					if name != "finished-clock-rollback" && name != "finished-expiry" && counters.Snapshot().OpenFGACalls != 0 {
						t.Fatal("unsafe refreshed inputs reached provider")
					}
					return
				}
				if err != nil || decision == nil || counters.Snapshot().OpenFGACalls != 1 {
					t.Fatal("valid concurrent time-only advance denied", err)
				}
				evidence := decision.Evidence()
				if evidence.PolicyTimeRevision != 2 || !evidence.PolicyTimeHighWater.Equal(initial.Add(time.Millisecond)) || !evidence.EvaluatedAt.Equal(initial.Add(time.Millisecond)) || !evidence.ExpiresAt.Equal(initial.Add(2*time.Second)) {
					t.Fatal("refresh failed to bind latest host state or extended original expiry")
				}
				if err := decision.ValidateFinal(repo.state, evidence.EvaluatedAt); err != nil {
					t.Fatal("refreshed decision lost final fence", err)
				}
				stale := repo.state
				stale.Revisions.Revocation++
				if decision.ValidateFinal(stale, evidence.EvaluatedAt) != ErrDenied || decision.ValidateFinal(repo.state, initial.Add(2*time.Second)) != ErrDenied {
					t.Fatal("revocation or original expiry fence weakened")
				}
			})
		}
	}
}
