package postgres

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/identity"
)

type responseSequenceAnchor struct {
	states []authorization.AnchorState
	reads  int
	events *[]string
	onRead func(int)
}

func (anchor *responseSequenceAnchor) Read(context.Context) (authorization.AnchorState, error) {
	*anchor.events = append(*anchor.events, "host")
	anchor.reads++
	if anchor.onRead != nil {
		anchor.onRead(anchor.reads)
	}
	if anchor.reads > len(anchor.states) {
		return authorization.AnchorState{}, authorization.ErrDenied
	}
	return anchor.states[anchor.reads-1], nil
}

type responseSnapshotRepo struct {
	states []authorization.State
	events *[]string
}

func (repo *responseSnapshotRepo) ReadStates(context.Context, identity.Principal, string, []authorization.ResourceRef) ([]authorization.State, error) {
	*repo.events = append(*repo.events, "database")
	return repo.states, nil
}

// This exercises the actual recheck predicate and owner/host read ordering. It
// does not mint a bound revision, a RecheckReceipt, or new authorization.
func TestResponseRecheckBracketsConcurrentDatabaseAdvanceAndRetainsTerminalFence(t *testing.T) {
	for _, name := range []string{"concurrent-advance", "terminal-time-advance", "database-time-ahead", "database-revision-ahead", "initial-host-rollback", "post-host-time-rollback", "post-host-revision-rollback", "post-binding-change", "revocation", "resource-change", "truncated-states", "terminal-host-time-rollback", "terminal-host-revision-rollback", "terminal-binding-change", "terminal-anchor-expiry", "finished-expiry", "finished-clock-rollback", "terminal-cancellation"} {
		t.Run(name, func(t *testing.T) {
			initial := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
			binding := authorization.ActivationBinding{InstallationID: "test-only", ActivationSequence: 1}
			prior := authorization.State{Resource: authorization.ResourceRef{Kind: "organization", ID: "test-only"}, Principal: identity.Principal{Type: "user", ID: "test-only"}, SessionID: "test-only", PolicyTimeHighWater: initial, PolicyTimeRevision: 1, Revisions: authorization.Revisions{Resource: 1, Revocation: 1}}
			proof := responseProof{States: []authorization.State{prior}, Binding: binding, ExpiresAt: initial.Add(2 * time.Second)}
			first := authorization.AnchorState{Binding: binding, PolicyTimeHighWater: initial, PolicyTimeRevision: 1}
			latest := first
			latest.PolicyTimeHighWater = initial.Add(time.Millisecond)
			latest.PolicyTimeRevision = 2
			events := []string{}
			host := &responseSequenceAnchor{states: []authorization.AnchorState{first, latest, latest}, events: &events}
			current := prior
			current.PolicyTimeHighWater, current.PolicyTimeRevision = latest.PolicyTimeHighWater, latest.PolicyTimeRevision
			repo := &responseSnapshotRepo{states: []authorization.State{current}, events: &events}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clockCalls := 0
			clock := func() time.Time {
				clockCalls++
				if clockCalls > 1 {
					if name == "finished-expiry" {
						return proof.ExpiresAt
					}
					if name == "finished-clock-rollback" {
						return initial.Add(-authorization.MaxPolicyClockSkew - time.Second)
					}
				}
				return initial
			}
			switch name {
			case "terminal-time-advance":
				host.states[2].PolicyTimeHighWater = initial.Add(2 * time.Millisecond)
				host.states[2].PolicyTimeRevision = 3
			case "database-time-ahead":
				repo.states[0].PolicyTimeHighWater = initial.Add(2 * time.Millisecond)
			case "database-revision-ahead":
				repo.states[0].PolicyTimeRevision++
			case "initial-host-rollback":
				host.states[0].PolicyTimeHighWater = initial.Add(-time.Millisecond)
			case "post-host-time-rollback":
				host.states[1].PolicyTimeHighWater = initial.Add(-time.Millisecond)
			case "post-host-revision-rollback":
				host.states[1].PolicyTimeRevision = 0
			case "post-binding-change":
				host.states[1].Binding.ActivationSequence++
			case "revocation":
				repo.states[0].Revisions.Revocation++
			case "resource-change":
				repo.states[0].Revisions.Resource++
			case "truncated-states":
				repo.states = nil
			case "terminal-host-time-rollback":
				host.states[2].PolicyTimeHighWater = initial
			case "terminal-host-revision-rollback":
				host.states[2].PolicyTimeRevision = 1
			case "terminal-binding-change":
				host.states[2].Binding.ActivationSequence++
			case "terminal-anchor-expiry":
				host.states[2].PolicyTimeHighWater = proof.ExpiresAt
			case "terminal-cancellation":
				host.onRead = func(index int) {
					if index == 3 {
						cancel()
					}
				}
			}
			err := recheckResponseStates(ctx, proof, host, repo, clock)
			if name == "concurrent-advance" || name == "terminal-time-advance" {
				if err != nil || !reflect.DeepEqual(events, []string{"host", "database", "host", "host"}) {
					t.Fatal("legitimate snapshot advance denied or terminal fence omitted", err, events)
				}
			} else if err != authorization.ErrDenied {
				t.Fatal("unsafe response snapshot admitted", err)
			}
		})
	}
}
