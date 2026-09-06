package authorization_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/providers/gitea"
)

// Source-only cross-owner tests: real WS-06 issue/consume/dispatch code and
// actual adapter HTTP against owned synthetic handlers, fake SQL owner store,
// synthetic inactive activation. No live Gitea, real PostgreSQL or product pass.
const trackerInstallation = "019ec4e0-0000-7000-8000-000000000009"

func trackerFixture(t *testing.T, handler http.HandlerFunc) (*gitea.HiddenTrackerAdapter, *gitea.HiddenTrackerPlan, *authorization.EffectExecution, func() authorization.EffectRecord, func(), *atomic.Int32) {
	t.Helper()
	ctx, project, consume, snapshot, cancel := authorization.NewEffectConsumerUnitFixture(t)
	count := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.Method != "POST" || r.URL.RequestURI() != "/api/v1/user/repos" ||
			r.Header.Get("Authorization") != "token "+strings.Repeat("a", 40) || r.Header.Get("Cookie") != "" || r.Header.Get("Idempotency-Key") != "" {
			t.Error("call plan/credential confinement mismatch")
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		want := `{"name":"stead-tracker-` + project.ID + `","private":true,"auto_init":true,"default_branch":"main","readme":"Default"}`
		if err != nil || string(raw) != want {
			t.Error("dispatched bytes differ from fixed tracker input")
		}
		w.Header().Set("Content-Type", "application/json")
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		name := "stead-tracker-" + project.ID
		fmt.Fprintf(w, `{"id":9007199254740993,"name":%q,"full_name":%q,"owner":{"login":"probe-admin"},"private":true,"empty":false,"default_branch":"main"}`, name, "probe-admin/"+name)
	}))
	t.Cleanup(server.Close)
	adapter, err := gitea.NewHiddenTrackerAdapter(server.URL, "probe-admin", strings.Repeat("a", 40), trackerInstallation)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	plan, err := adapter.PlanHiddenTracker(gitea.HiddenTrackerIntent{EffectID: "019ec4e0-0000-7000-8000-000000000006",
		OperationID: "019ec4e0-0000-7000-8000-000000000007", PlanID: "019ec4e0-0000-7000-8000-000000000008", RequestID: strings.Repeat("a", 32),
		Project: project, ProviderRevision: 1, OriginalDeadline: deadline, ProviderNotAfter: deadline.Add(-time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	execution, err := consume(plan.Binding())
	if err != nil {
		t.Fatal(err)
	}
	return adapter, plan, execution, snapshot, cancel, count
}

func TestGiteaConsumedTrackerSingleExactCallAndPrivatePending(t *testing.T) {
	a, plan, execution, snapshot, _, calls := trackerFixture(t, nil)
	if snapshot().State != authorization.EffectConsumed || calls.Load() != 0 {
		t.Fatal("dispatch before durable consume acknowledgment")
	}
	// Mutating the returned non-authorizing record cannot mutate the sealed plan.
	b := plan.Binding()
	b.PlanDigest = "sha256:" + strings.Repeat("f", 64)
	result, err := a.CreateHiddenTracker(plan, execution)
	if err != nil || result == nil || calls.Load() != 1 || snapshot().State != authorization.EffectConsumed {
		t.Fatal("single dispatch failed or fabricated terminal state")
	}
	for _, v := range []any{a, plan, result} {
		data, err := json.Marshal(v)
		if err != nil || string(data) != "{}" || !strings.Contains(fmt.Sprintf("%#v", v), "[private]") {
			t.Fatal("opaque provider value serialized protected state")
		}
	}
	copyExecution, copyPlan, copyAdapter := *execution, *plan, *a
	if result, err := copyAdapter.CreateHiddenTracker(&copyPlan, &copyExecution); result != nil || err == nil || calls.Load() != 1 {
		t.Fatal("copied consumed capability dispatched twice")
	}
}

func TestGiteaConsumedTrackerConcurrentCopiesDispatchOnce(t *testing.T) {
	a, p, execution, _, _, calls := trackerFixture(t, nil)
	var wg sync.WaitGroup
	var winners atomic.Int32
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			copyExecution, copyPlan := *execution, *p
			if result, err := a.CreateHiddenTracker(&copyPlan, &copyExecution); err == nil && result != nil {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 || winners.Load() != 1 {
		t.Fatal("concurrent dispatch cloned authority")
	}
}

func TestGiteaConsumedTrackerRejectsZeroAndForeignPlansBeforeIO(t *testing.T) {
	a, p, execution, _, _, calls := trackerFixture(t, nil)
	foreign, err := gitea.NewHiddenTrackerAdapter("http://127.0.0.1:1", "probe-admin", strings.Repeat("a", 40), trackerInstallation)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range []func() (*gitea.HiddenTrackerPending, error){
		func() (*gitea.HiddenTrackerPending, error) { return a.CreateHiddenTracker(p, nil) },
		func() (*gitea.HiddenTrackerPending, error) {
			return a.CreateHiddenTracker(p, &authorization.EffectExecution{})
		},
		func() (*gitea.HiddenTrackerPending, error) { return a.CreateHiddenTracker(nil, execution) },
		func() (*gitea.HiddenTrackerPending, error) {
			return a.CreateHiddenTracker(&gitea.HiddenTrackerPlan{}, execution)
		},
		func() (*gitea.HiddenTrackerPending, error) { return foreign.CreateHiddenTracker(p, execution) },
	} {
		if result, err := run(); result != nil || err == nil || calls.Load() != 0 {
			t.Fatal("invalid plan/handle reached provider")
		}
	}
	if result, err := a.CreateHiddenTracker(p, execution); result == nil || err != nil || calls.Load() != 1 {
		t.Fatal("denied foreign attempt altered original plan")
	}
}

func TestGiteaConsumedTrackerSuppressionBeforeDispatch(t *testing.T) {
	for _, suppress := range []string{"execution", "request"} {
		t.Run(suppress, func(t *testing.T) {
			a, p, e, _, cancel, calls := trackerFixture(t, nil)
			if suppress == "execution" {
				e.Suppress()
			} else {
				cancel()
			}
			if result, err := a.CreateHiddenTracker(p, e); result != nil || err == nil || calls.Load() != 0 {
				t.Fatal("suppressed execution dispatched")
			}
		})
	}
}

func TestGiteaConsumedTrackerAmbiguityNeverRetriesOrTerminalizes(t *testing.T) {
	for _, kind := range []string{"lost_response", "rejected", "malformed", "foreign_repository", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			a, p, e, snapshot, _, calls := trackerFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "lost_response":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error("fixture hijack failed")
						return
					}
					conn.Close()
				case "rejected":
					w.WriteHeader(http.StatusForbidden)
				case "malformed":
					w.WriteHeader(http.StatusCreated)
					io.WriteString(w, `{"id":`)
				case "foreign_repository":
					w.WriteHeader(http.StatusCreated)
					io.WriteString(w, `{"id":1,"name":"other"}`)
				case "redirect":
					w.Header().Set("Location", "/forbidden")
					w.WriteHeader(http.StatusTemporaryRedirect)
				}
			})
			if result, err := a.CreateHiddenTracker(p, e); result != nil || err == nil || calls.Load() != 1 || snapshot().State != authorization.EffectReconciling || !e.SuppressionRequired() {
				t.Fatal("failed call did not preserve ambiguity/suppression")
			}
			if result, err := a.CreateHiddenTracker(p, e); result != nil || err == nil || calls.Load() != 1 {
				t.Fatal("ambiguous mutation replayed")
			}
		})
	}
}

func TestGiteaConsumedTrackerCancellationDuringCallRetainsAmbiguity(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	a, p, e, snapshot, cancel, calls := trackerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{}`)
	})
	t.Cleanup(func() { close(release) })
	done := make(chan bool, 1)
	go func() { result, err := a.CreateHiddenTracker(p, e); done <- result == nil && err != nil }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture dispatch did not start")
	}
	cancel()
	select {
	case denied := <-done:
		if !denied {
			t.Fatal("canceled output released")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled transport did not stop")
	}
	if calls.Load() != 1 || snapshot().State != authorization.EffectReconciling {
		t.Fatal("cancellation falsely proved no effect")
	}
}

func TestGiteaConsumedTrackerRejectsCallerSubstitutedBindings(t *testing.T) {
	for _, field := range []string{"digest", "profile", "profile_digest", "installation", "plan_id", "operation_id", "effect_id", "request_id", "project", "revision", "deadline", "provider_expiry"} {
		t.Run(field, func(t *testing.T) {
			ctx, project, consume, _, _ := authorization.NewEffectConsumerUnitFixture(t)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusForbidden) }))
			t.Cleanup(server.Close)
			a, err := gitea.NewHiddenTrackerAdapter(server.URL, "probe-admin", strings.Repeat("a", 40), trackerInstallation)
			if err != nil {
				t.Fatal(err)
			}
			deadline, _ := ctx.Deadline()
			p, err := a.PlanHiddenTracker(gitea.HiddenTrackerIntent{EffectID: "019ec4e0-0000-7000-8000-000000000006", OperationID: "019ec4e0-0000-7000-8000-000000000007",
				PlanID: "019ec4e0-0000-7000-8000-000000000008", RequestID: strings.Repeat("a", 32), Project: project, ProviderRevision: 1,
				OriginalDeadline: deadline, ProviderNotAfter: deadline.Add(-time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			b := p.Binding()
			other := "019ec4e0-0000-7000-8000-000000000010"
			switch field {
			case "digest":
				b.PlanDigest = "sha256:" + strings.Repeat("f", 64)
			case "profile":
				b.CompatibilityProfileID = "caller-selected"
			case "profile_digest":
				b.CompatibilityProfileDigest = "sha256:" + strings.Repeat("f", 64)
			case "installation":
				b.ProviderInstallationID = other
			case "plan_id":
				b.PlanID = other
			case "operation_id":
				b.OperationID = other
			case "effect_id":
				b.EffectID = other
			case "request_id":
				b.RequestID = strings.Repeat("b", 32)
			case "project":
				b.Project.ID = other
			case "revision":
				b.ProviderRevision++
			case "deadline":
				b.OriginalDeadline = b.OriginalDeadline.Add(time.Second)
			case "provider_expiry":
				b.ProviderNotAfter = b.ProviderNotAfter.Add(time.Second)
			}
			e, err := consume(b)
			if err == nil {
				if result, err := a.CreateHiddenTracker(p, e); result != nil || err == nil {
					t.Fatal("caller binding substituted sealed plan")
				}
			}
			if calls.Load() != 0 {
				t.Fatal("caller binding reached provider")
			}
		})
	}
}
