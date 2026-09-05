package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/ScottTpirate/stead/modules/identity"
)

type setTestRepo struct {
	*testRepo
	states     []State
	batchReads int
	err        error
}

func (repo *setTestRepo) ReadStates(_ context.Context, principal identity.Principal, session string, refs []ResourceRef) ([]State, error) {
	repo.batchReads++
	if principal != repo.session.Principal || session != sessionID {
		return nil, ErrDenied
	}
	return append([]State(nil), repo.states...), repo.err
}

func batchServer(t *testing.T, reply func([]Tuple) []bool) *OpenFGA {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Model       string `json:"authorization_model_id"`
			Consistency string `json:"consistency"`
			Checks      []struct {
				Tuple Tuple  `json:"tuple_key"`
				ID    string `json:"correlation_id"`
			} `json:"checks"`
		}
		if r.URL.Path != "/stores/"+modelID+"/batch-check" || json.NewDecoder(r.Body).Decode(&request) != nil || request.Model != modelID || request.Consistency != "HIGHER_CONSISTENCY" || len(request.Checks) == 0 || len(request.Checks) > 50 {
			t.Error("unbounded batch request")
			w.WriteHeader(400)
			return
		}
		tuples := make([]Tuple, len(request.Checks))
		for i, c := range request.Checks {
			tuples[i] = c.Tuple
		}
		allowed := reply(tuples)
		result := map[string]any{}
		for i, c := range request.Checks {
			result[c.ID] = map[string]bool{"allowed": allowed[i]}
		}
		json.NewEncoder(w).Encode(map[string]any{"result": result})
	}))
	t.Cleanup(server.Close)
	client, err := NewOpenFGA(OpenFGAConfig{URL: server.URL, StoreID: modelID, ModelID: modelID, LocalDevelopment: true})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestCoordinatorSetActualBatchAndSharedFinalFence(t *testing.T) {
	coordinator, repo, session, now := coordinatorFixture(t, true)
	set := &setTestRepo{testRepo: repo}
	reads := make([]ReadAuthorization, 101)
	for i := range reads {
		state := repo.state
		state.Resource.ID = fmt.Sprintf("019ec4e0-0000-7000-8000-%012d", 100+i)
		state.OrganizationID = state.Resource.ID
		reads[i] = ReadAuthorization{OrganizationRead, state.Resource}
		set.states = append(set.states, state)
	}
	// Missing input is an aligned denial and never causes a per-row audit write.
	set.states[5] = State{Resource: reads[5].Target}
	coordinator.config.Repository = set
	coordinator.config.OpenFGA = batchServer(t, func(tuples []Tuple) []bool {
		result := make([]bool, len(tuples))
		for i, tuple := range tuples {
			result[i] = !strings.HasSuffix(tuple.Object, "000000000107")
		}
		return result
	})
	ctx, counters := telemetry.Begin(context.Background())
	decisions, err := coordinator.AuthorizeSet(ctx, session, reads)
	if err != nil || len(decisions) != 101 || decisions[5] != nil || decisions[7] != nil {
		t.Fatalf("set result: %v", err)
	}
	if set.batchReads != 1 || repo.reads != 0 || len(repo.denials) != 0 || counters.Snapshot().OpenFGACalls != 2 {
		t.Fatal("per-row repository/network/audit work")
	}
	first := decisions[0].Evidence()
	for i, decision := range decisions {
		if decision == nil {
			continue
		}
		e := decision.Evidence()
		if e.DecisionID != first.DecisionID || e.EvaluatedAt != first.EvaluatedAt || e.ExpiresAt != first.ExpiresAt || e.OpenFGACalls != 2 || decision.ValidateFinal(set.states[i], *now) != nil {
			t.Fatal("unshared or invalid final fence")
		}
		changed := set.states[i]
		changed.Revisions.Revocation++
		if decision.ValidateFinal(changed, *now) != ErrDenied || decision.ValidateFinal(set.states[i], now.Add(2*time.Second)) != ErrDenied {
			t.Fatal("stale set seal admitted")
		}
	}
	if _, err := coordinator.AuthorizeSet(ctx, session, reads); err != nil || counters.Snapshot().OpenFGACalls != 4 {
		t.Fatal("set reused an authorization cache")
	}
}

func TestCoordinatorSetFailsWholeForUntrustedShapeOrInfrastructure(t *testing.T) {
	for _, test := range []string{"no-set-port", "duplicate", "mutation", "oversize", "wrong-kind", "misaligned", "truncated", "repository", "expired", "bad-anchor", "cancelled"} {
		t.Run(test, func(t *testing.T) {
			coordinator, repo, session, now := coordinatorFixture(t, true)
			set := &setTestRepo{testRepo: repo, states: []State{repo.state}}
			coordinator.config.Repository = set
			reads := []ReadAuthorization{{OrganizationRead, repo.state.Resource}}
			ctx, counters := telemetry.Begin(context.Background())
			switch test {
			case "no-set-port":
				coordinator.config.Repository = repo
			case "duplicate":
				reads = append(reads, reads[0])
			case "mutation":
				reads[0].Action = OrganizationCreate
			case "oversize":
				reads = make([]ReadAuthorization, 102)
			case "wrong-kind":
				reads[0].Target.Kind = "team"
			case "misaligned":
				set.states[0].Resource.ID = instanceID
			case "truncated":
				set.states = nil
			case "repository":
				set.err = ErrDenied
			case "expired":
				*now = now.Add(2 * time.Hour)
			case "bad-anchor":
				coordinator.config.Anchor = &testAnchor{}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if decisions, err := coordinator.AuthorizeSet(ctx, session, reads); err != ErrDenied || decisions != nil {
				t.Fatal("unsafe set admitted")
			}
			if counters.Snapshot().OpenFGACalls != 0 || len(repo.denials) > 1 {
				t.Fatal("unsafe input reached provider or per-row denial writes")
			}
		})
	}
}

func TestOpenFGABatchClosedCorrelationAndBoundedCalls(t *testing.T) {
	for name, body := range map[string]string{
		"missing": `{"result":{}}`, "wrong": `{"result":{"2":{"allowed":true}}}`,
		"duplicate": `{"result":{"1":{"allowed":true},"1":{"allowed":true}}}`,
		"unknown":   `{"result":{"1":{"allowed":true,"error":{}}}}`,
		"type":      `{"result":{"1":{"allowed":"true"}}}`, "absent": `{"result":{"1":{}}}`,
		"null": `{"result":{"1":{"allowed":null}}}`, "case": `{"result":{"1":{"Allowed":true}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer server.Close()
			client, _ := NewOpenFGA(OpenFGAConfig{URL: server.URL, StoreID: modelID, ModelID: modelID, LocalDevelopment: true})
			if results, err := client.BatchCheck(context.Background(), []Tuple{{"user:" + userID, "viewer", "organization:" + orgID}}); err != ErrDenied || results != nil {
				t.Fatal("ambiguous batch accepted")
			}
		})
	}
	client := batchServer(t, func(tuples []Tuple) []bool { return make([]bool, len(tuples)) })
	tuples := make([]Tuple, 101)
	for i := range tuples {
		tuples[i] = Tuple{"user:" + userID, "viewer", fmt.Sprintf("organization:019ec4e0-0000-7000-8000-%012d", 100+i)}
	}
	ctx, counters := telemetry.Begin(context.Background())
	if results, err := client.BatchCheck(ctx, tuples); err != nil || len(results) != 101 || counters.Snapshot().OpenFGACalls != 3 {
		t.Fatal("actual stock default batch bounds")
	}
	if _, err := client.BatchCheck(ctx, append(tuples, tuples[0])); err != ErrDenied || counters.Snapshot().OpenFGACalls != 3 {
		t.Fatal("oversize batch reached network")
	}
}
