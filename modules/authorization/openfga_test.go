package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
)

func TestOpenFGAFailsClosedAndNeverRedirects(t *testing.T) {
	for name, body := range map[string]string{"missing": `{}`, "wrongtype": `{"allowed":"true"}`, "duplicate": `{"allowed":true,"allowed":false}`, "case": `{"Allowed":true}`, "oversize": strings.Repeat(" ", 65537)} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer server.Close()
			client, _ := NewOpenFGA(OpenFGAConfig{URL: server.URL, StoreID: modelID, ModelID: modelID, LocalDevelopment: true})
			if _, err := client.Check(context.Background(), Tuple{User: "user:" + userID, Relation: "viewer", Object: "organization:" + orgID}); err != ErrDenied {
				t.Fatal("ambiguous FGA allow")
			}
		})
	}
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer source.Close()
	client, _ := NewOpenFGA(OpenFGAConfig{URL: source.URL, StoreID: modelID, ModelID: modelID, LocalDevelopment: true})
	if _, err := client.Check(context.Background(), Tuple{User: "user:" + userID, Relation: "viewer", Object: "organization:" + orgID}); err != ErrDenied || redirected {
		t.Fatal("followed FGA redirect")
	}
	for _, endpoint := range []string{"http://example.com", "http://localhost:8080", "https://user:password@example.com", "https://example.com/other", "https://example.com?target=evil"} {
		if _, err := NewOpenFGA(OpenFGAConfig{URL: endpoint, StoreID: modelID, ModelID: modelID, LocalDevelopment: true}); err != ErrDenied {
			t.Fatal("unsafe endpoint accepted")
		}
	}
}

func TestTupleReceiptRequiresActualDirectReadback(t *testing.T) {
	for _, direct := range []bool{true, false} {
		t.Run(map[bool]string{true: "direct", false: "computed-only"}[direct], func(t *testing.T) {
			tuple := Tuple{User: "user:" + userID, Relation: "viewer", Object: "organization:" + orgID}
			writes, reads := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/write") {
					writes++
					var body struct {
						Model  string `json:"authorization_model_id"`
						Writes struct {
							Tuples    []Tuple `json:"tuple_keys"`
							Duplicate string  `json:"on_duplicate"`
						} `json:"writes"`
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil || body.Model != modelID || body.Writes.Duplicate != "ignore" {
						t.Error("unbound write")
					}
					w.Write([]byte(`{}`))
					return
				}
				reads++
				if direct {
					json.NewEncoder(w).Encode(map[string]any{"tuples": []any{map[string]any{"key": tuple}}, "continuation_token": ""})
				} else {
					w.Write([]byte(`{"tuples":[],"continuation_token":""}`))
				}
			}))
			defer server.Close()
			client, _ := NewOpenFGA(OpenFGAConfig{URL: server.URL, StoreID: modelID, ModelID: modelID, LocalDevelopment: true})
			receipt, err := client.WriteVerified(context.Background(), []Tuple{tuple})
			if direct && (err != nil || !receipt.Match([]Tuple{tuple})) {
				t.Fatal("direct acknowledgement absent")
			}
			if !direct && (err != ErrDenied || receipt != nil) {
				t.Fatal("computed permission substituted for stored tuple")
			}
			if reads != 1 || writes != 1 {
				t.Fatal("unexpected provider fanout")
			}
		})
	}
}

// TestLiveOpenFGALocalProtocol uses only an explicitly provided isolated,
// synthetic service. Unit doubles above are not product-path evidence.
func TestLiveOpenFGALocalProtocol(t *testing.T) {
	endpoint, keyFile := os.Getenv("STEAD_AUTH_TEST_OPENFGA_URL"), os.Getenv("STEAD_AUTH_TEST_OPENFGA_TOKEN_FILE")
	if endpoint == "" || keyFile == "" {
		t.Skip("explicit isolated OpenFGA required")
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal("read test service credential")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctx, counters := telemetry.Begin(ctx)
	client, receipt, err := ProvisionLocalOpenFGA(ctx, endpoint, strings.TrimSpace(string(key)))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ModelID() == "" || receipt.SourceDigest() == "" {
		t.Fatal("missing model receipt")
	}
	parent := "team:019ec4e0-0000-7000-8000-000000000010"
	child := "team:019ec4e0-0000-7000-8000-000000000011"
	project := "project:019ec4e0-0000-7000-8000-000000000012"
	alice := "user:" + userID
	bob := "user:019ec4e0-0000-7000-8000-000000000020"
	contributor := "user:019ec4e0-0000-7000-8000-000000000021"
	org := "organization:" + orgID
	tuples := []Tuple{{alice, "lead", parent}, {bob, "lead", child}, {parent, "parent", child}, {org, "organization", parent}, {org, "organization", child}, {contributor, "contributor", child}}
	if grant, err := client.WriteVerified(ctx, tuples); err != nil || !grant.Match(tuples) {
		t.Fatal("direct tuple write/readback failed")
	}
	if _, err := client.WriteVerified(ctx, tuples); err != nil {
		t.Fatal("idempotent grant retry failed")
	}
	if _, err := client.WriteVerified(ctx, []Tuple{{parent, "owning_team", project}, {org, "organization", project}, {bob, "viewer", project}}); err != nil {
		t.Fatal("explicit project tuple write failed")
	}
	checks := []struct {
		user, relation, object string
		want                   bool
	}{{alice, "viewer", parent, true}, {alice, "role_manager", parent, true}, {alice, "viewer", child, false}, {bob, "viewer", parent, false}, {contributor, "viewer", child, true}, {contributor, "editor", child, false}, {alice, "viewer", project, false}, {bob, "viewer", project, true}}
	for _, check := range checks {
		allowed, err := client.Check(ctx, Tuple{check.user, check.relation, check.object})
		if err != nil || allowed != check.want {
			t.Fatal("stock role or noninheritance behavior mismatch")
		}
	}
	batch := make([]Tuple, len(checks))
	for index, check := range checks {
		batch[index] = Tuple{check.user, check.relation, check.object}
	}
	before := counters.Snapshot().OpenFGACalls
	allowed, err := client.BatchCheck(ctx, batch)
	if err != nil || len(allowed) != len(checks) || counters.Snapshot().OpenFGACalls != before+1 {
		t.Fatal("stock eight-role BatchCheck did not use exactly one bounded call", err)
	}
	for index, check := range checks {
		if allowed[index] != check.want {
			t.Fatal("stock BatchCheck role/noninheritance differs from direct Check")
		}
	}
	large := make([]Tuple, MaxReadSet)
	for index := range large {
		large[index] = Tuple{alice, "viewer", fmt.Sprintf("team:019ec4e0-0000-7000-8000-%012d", 100+index)}
	}
	before = counters.Snapshot().OpenFGACalls
	allowed, err = client.BatchCheck(ctx, large)
	if err != nil || len(allowed) != MaxReadSet || counters.Snapshot().OpenFGACalls != before+3 {
		t.Fatal("stock 101-result BatchCheck did not honor three max50 chunks", err)
	}
	for _, value := range allowed {
		if value {
			t.Fatal("ungranted synthetic resource allowed by stock batch")
		}
	}
	before = counters.Snapshot().OpenFGACalls
	if _, err = client.BatchCheck(ctx, append(large, large[0])); err != ErrDenied || counters.Snapshot().OpenFGACalls != before {
		t.Fatal("oversized live batch reached provider")
	}
	if _, err := client.WriteVerified(ctx, []Tuple{{"service_account:019ec4e0-0000-7000-8000-000000000030", "lead", child}}); err != ErrDenied {
		t.Fatal("stock model admitted non-User lead")
	}
	t.Logf("stock model, direct grants, idempotency, hierarchy/accountability noninheritance, eight-role batch and 101-result max50 batch PASS; actual OpenFGA HTTP calls=%d", counters.Snapshot().OpenFGACalls)
}
