package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
)

func TestClosedBoundedJSONRequest(t *testing.T) {
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"key":"ORG","name":"People"}`, true},
		{`{"key":"ORG","name":"People","parent_team_id":"x"}`, true},
		{`{"key":"ORG","name":"People","name":"Shadow"}`, false},
		{`{"key":"ORG","name":"People","\u006eame":"Shadow"}`, false},
		{`{"KEY":"ORG","name":"People"}`, false},
		{`{"key":"ORG","name":"People","authority":"admin"}`, false},
		{`{"key":"ORG","name":null}`, false},
		{`{"key":"ORG","name":{}}`, false},
		{`{"key":"ORG","name":"\ud800"}`, false},
		{`{"key":"ORG","name":"People"}{}`, false},
		{`{"key":"ORG"}`, false},
		{"{\"key\":\"ORG\",\"name\":\"\xff\"}", false},
		{`{"key":"ORG","name":"` + strings.Repeat("a", maxRequestBytes) + `"}`, false},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		_, err := readStrings(httptest.NewRecorder(), r, []string{"key", "name"}, []string{"parent_team_id"})
		if (err == nil) != tc.valid {
			t.Errorf("valid=%v expected=%v", err == nil, tc.valid)
		}
	}
}

func TestCookieAmbiguityAndIdempotency(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	if _, err := tokenFromCookie(r); err == nil {
		t.Fatal("missing cookie")
	}
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "first"})
	if token, err := tokenFromCookie(r); err != nil || token != "first" {
		t.Fatal("single cookie")
	}
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "second"})
	if _, err := tokenFromCookie(r); err == nil {
		t.Fatal("ambiguous cookie")
	}
	r.Header.Add("Idempotency-Key", "request-0001")
	if idempotencyKey(r) != "request-0001" {
		t.Fatal("valid key")
	}
	r.Header.Add("Idempotency-Key", "request-0002")
	if idempotencyKey(r) != "" {
		t.Fatal("ambiguous key")
	}
}

type denyRecheck struct{}

func (denyRecheck) Recheck(context.Context, transaction.BoundRevision, transaction.RecheckIssuer) (transaction.RecheckReceipt, error) {
	panic("zero proof must deny before rechecking")
}
func TestZeroProofCannotReleaseProtectedBytes(t *testing.T) {
	boundary, err := transaction.NewRequestBoundaryAdapter(denyRecheck{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	response := &protectedResponse{writer: w, body: []byte("protected"), status: 200, etag: `"protected-tag"`}
	if _, err := boundary.ReleaseProtected(context.Background(), transaction.BoundRevision{}, response); err == nil {
		t.Fatal("zero proof")
	}
	if response.body != nil || response.released || w.Body.Len() != 0 || w.Header().Get("ETag") != "" {
		t.Fatal("protected response leaked before final fence")
	}
}

func TestUnknownAndCrossOriginRequestsStayGeneric(t *testing.T) {
	server := &Server{config: Config{Origin: "https://localhost:7443"}, host: "localhost:7443", mux: http.NewServeMux()}
	server.mux.HandleFunc("POST /api/v1/session", func(http.ResponseWriter, *http.Request) { t.Fatal("cross-origin request reached handler") })
	for _, tc := range []struct {
		method, path, origin, host string
		status                     int
	}{
		{"POST", "/api/v1/session", "https://evil.invalid", "localhost:7443", 403},
		{"POST", "/api/v1/session", "", "localhost:7443", 403},
		{"POST", "/api/v1/session", "https://localhost:7443", "evil.invalid", 400},
		{"GET", "/api/v1/unknown", "", "localhost:7443", 404},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Host = tc.host
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "evil") || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("unsafe response: %d", w.Code)
		}
	}
}
