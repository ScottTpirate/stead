package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ScottTpirate/stead/internal/telemetry"
)

func TestCollectionRequiredDenialIsOneSafeCorrelatedDecision(t *testing.T) {
	for _, name := range []string{"parent-fga", "parent-missing", "parent-classified", "all-missing", "required-missing", "required-fga", "required-revoked", "required-foreign", "optional-missing", "optional-fga", "optional-foreign", "allowed", "instance-parent"} {
		t.Run(name, func(t *testing.T) {
			coordinator, repo, session, now := coordinatorFixture(t, true)
			parent := repo.state
			row := parent
			row.Resource = ResourceRef{Kind: "team", ID: "019ec4e0-0000-7000-8000-000000000005"}
			reads := []ReadAuthorization{{OrganizationRead, parent.Resource}, {TeamRead, row.Resource}}
			set := &setTestRepo{testRepo: repo, states: []State{parent, row}}
			coordinator.config.Repository = set
			required := !strings.HasPrefix(name, "optional-")
			wantAudit, wantNil := 1, 0
			switch name {
			case "parent-missing":
				set.states[0] = State{Resource: parent.Resource}
			case "parent-classified":
				set.states[0].Label.SensitivityLevel = "restricted"
			case "all-missing":
				set.states = []State{{Resource: parent.Resource}, {Resource: row.Resource}}
			case "required-missing", "optional-missing":
				set.states[1] = State{Resource: row.Resource}
				wantNil = 1
			case "required-fga", "optional-fga":
				wantNil = 1
			case "required-revoked":
				set.states[1].TuplePending = true
				wantNil = 1
			case "required-foreign", "optional-foreign":
				set.states[1].OrganizationID = "019ec4e0-0000-7000-8000-000000000006"
				wantNil = 1
			case "instance-parent":
				set.states[0].Resource = ResourceRef{Kind: "instance", ID: instanceID}
				set.states[0].OrganizationID = ""
				set.states[1] = parent
				reads = []ReadAuthorization{{OrganizationsList, set.states[0].Resource}, {OrganizationRead, parent.Resource}}
			case "allowed":
				wantAudit, wantNil = 0, -1
			}
			if !required {
				wantAudit = 0
			}
			coordinator.config.OpenFGA = batchServer(t, func(tuples []Tuple) []bool {
				allowed := make([]bool, len(tuples))
				for i, tuple := range tuples {
					allowed[i] = !(name == "parent-fga" && tuple.Object == "organization:"+orgID) && !(strings.HasSuffix(name, "-fga") && name != "parent-fga" && tuple.Object == "team:"+row.Resource.ID) && !(name == "instance-parent" && tuple.Object == "instance:"+instanceID)
				}
				return allowed
			})
			const correlation = "0123456789abcdef0123456789abcdef"
			ctx, counters := telemetry.Begin(telemetry.WithCorrelationID(context.Background(), correlation))
			decisions, err := coordinator.AuthorizeCollection(ctx, session, reads, required)
			if err != nil || len(decisions) != 2 || (wantNil >= 0 && decisions[wantNil] != nil) || len(repo.denials) != wantAudit {
				t.Fatalf("aligned outcome or aggregate audit lost: %v, %d denials", err, len(repo.denials))
			}
			if set.batchReads != 1 || repo.reads != 0 || counters.Snapshot().OpenFGACalls > 1 {
				t.Fatal("required denial reauthorized or caused per-row work")
			}
			for _, decision := range decisions {
				if decision != nil && wantAudit > 0 && decision.Evidence().DecisionID != repo.denials[0].DecisionID {
					t.Fatal("denial belongs to a different logical decision")
				}
			}
			if wantAudit > 0 {
				denial := repo.denials[0]
				raw, err := json.Marshal(denial)
				if err != nil || denial.RequestID != correlation || len(denial.DecisionID) != 32 || denial.DecisionID == correlation || denial.Actor != session.Principal() || denial.Action != reads[0].Action || denial.Reason != "context_denied" || !denial.OccurredAt.Equal(*now) || strings.Contains(string(raw), row.Resource.ID) || strings.Contains(string(raw), orgID) || strings.Contains(string(raw), instanceID) {
					t.Fatal("aggregate denial lost its safe request/decision binding")
				}
			} else if name == "allowed" {
				for i, decision := range decisions {
					if decision == nil || decision.ValidateFinal(set.states[i], *now) != nil {
						t.Fatal("allowed collection lost its final fence")
					}
					changed := set.states[i]
					changed.Revisions.Revocation++
					if decision.ValidateFinal(changed, *now) != ErrDenied {
						t.Fatal("stale response admitted")
					}
				}
			}
		})
	}
}

func TestCollectionClosedShapeAndFailuresDoNotDoubleAudit(t *testing.T) {
	for _, name := range []string{"empty", "no-parent", "mutation", "wrong-kind", "mixed-rows", "repository", "duplicate", "oversize"} {
		t.Run(name, func(t *testing.T) {
			coordinator, repo, session, _ := coordinatorFixture(t, true)
			set := &setTestRepo{testRepo: repo, states: []State{repo.state}}
			coordinator.config.Repository = set
			reads := []ReadAuthorization{{OrganizationRead, repo.state.Resource}}
			wantReads, wantAudit := 0, 1
			switch name {
			case "empty":
				reads, wantAudit = nil, 0
			case "no-parent":
				reads[0] = ReadAuthorization{TeamRead, ResourceRef{Kind: "team", ID: orgID}}
			case "mutation":
				reads[0].Action = OrganizationCreate
			case "wrong-kind":
				reads = append(reads, ReadAuthorization{TeamRead, ResourceRef{Kind: "project", ID: instanceID}})
			case "mixed-rows":
				reads = append(reads, ReadAuthorization{TeamRead, ResourceRef{Kind: "team", ID: instanceID}}, ReadAuthorization{ProjectRead, ResourceRef{Kind: "project", ID: userID}})
			case "repository":
				set.err, wantReads = ErrDenied, 1
			case "duplicate":
				reads = append(reads, reads[0])
			case "oversize":
				reads, wantAudit = make([]ReadAuthorization, MaxReadSet+1), 0
			}
			coordinator.config.OpenFGA = batchServer(t, func([]Tuple) []bool { t.Fatal("invalid collection reached provider"); return nil })
			decisions, err := coordinator.AuthorizeCollection(context.Background(), session, reads, true)
			if decisions != nil || err != ErrDenied || set.batchReads != wantReads || len(repo.denials) != wantAudit {
				t.Fatal("invalid collection changed fail-closed/error/audit behavior")
			}
		})
	}
}

func TestCollectionManyHiddenCandidatesDoNotWritePerRow(t *testing.T) {
	for _, required := range []bool{false, true} {
		coordinator, repo, session, _ := coordinatorFixture(t, true)
		set := &setTestRepo{testRepo: repo, states: []State{repo.state}}
		reads := []ReadAuthorization{{OrganizationRead, repo.state.Resource}}
		for i := 1; i < MaxReadSet; i++ {
			ref := ResourceRef{Kind: "project", ID: fmt.Sprintf("019ec4e0-0000-7000-8000-%012x", 100+i)}
			reads = append(reads, ReadAuthorization{ProjectRead, ref})
			set.states = append(set.states, State{Resource: ref})
		}
		coordinator.config.Repository = set
		coordinator.config.OpenFGA = batchServer(t, func(tuples []Tuple) []bool {
			if len(tuples) != 1 {
				t.Fatal("hidden rows reached provider")
			}
			return []bool{true}
		})
		decisions, err := coordinator.AuthorizeCollection(context.Background(), session, reads, required)
		wantAudit := 0
		if required {
			wantAudit = 1
		}
		if err != nil || len(decisions) != MaxReadSet || decisions[0] == nil || len(repo.denials) != wantAudit || set.batchReads != 1 {
			t.Fatal("required response rows and optional discovery candidates confused")
		}
	}
}
