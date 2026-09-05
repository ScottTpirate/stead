// Package httpapi is the same-origin Platform BFF. It translates transport
// contracts into owned commands and never exposes provider or SQL interfaces.
package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
	"github.com/ScottTpirate/stead/modules/project"
)

const cookieName = "__Host-stead_session"
const maxRequestBytes = 16 << 10
const maxResponseBytes = 1 << 20

type Repository interface {
	organization.Repository
	project.Repository
	transaction.RevisionRechecker
	RotateSessionToken(context.Context, string, [sha256.Size]byte, [sha256.Size]byte) (bool, error)
	RevokeSession(context.Context, string) error
	ListOrganizationIDs(context.Context, string, int) ([]string, error)
	ListTeamIDs(context.Context, string, int) ([]string, error)
	ListProjectIDs(context.Context, string, int) ([]string, error)
	FinalizeResponse(context.Context, []*authorization.Decision) (transaction.BoundRevision, error)
}

type Observation struct {
	Operation            string  `json:"operation"`
	Status               int     `json:"status"`
	DurationMilliseconds float64 `json:"duration_ms"`
	ResponseBytes        int     `json:"response_bytes"`
	telemetry.Snapshot
}
type Config struct {
	Origin, InstanceID string
	Repository         Repository
	Identity           *identity.LocalAuthenticator
	Authorization      *authorization.Coordinator
	ActivateCreated    func(context.Context, identity.Authenticated, string) error
	Ready              func(context.Context) error
	Observe            func(Observation)
}
type Server struct {
	config   Config
	host     string
	boundary *transaction.RequestBoundaryAdapter
	mux      *http.ServeMux
}

func New(config Config) (*Server, error) {
	u, err := url.Parse(config.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !identity.ValidID(config.InstanceID) || config.Repository == nil || config.Identity == nil || config.Authorization == nil || config.Ready == nil || config.ActivateCreated == nil {
		return nil, errors.New("invalid Platform API configuration")
	}
	boundary, err := transaction.NewRequestBoundaryAdapter(config.Repository)
	if err != nil {
		return nil, err
	}
	server := &Server{config: config, host: u.Host, boundary: boundary, mux: http.NewServeMux()}
	server.mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"healthy": true}) })
	server.mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if config.Ready(r.Context()) != nil {
			writeJSON(w, 503, map[string]bool{"healthy": false})
			return
		}
		writeJSON(w, 200, map[string]bool{"healthy": true})
	})
	server.mux.HandleFunc("GET /api/v1/session", server.session)
	server.mux.HandleFunc("POST /api/v1/session", server.login)
	server.mux.HandleFunc("DELETE /api/v1/session", server.logout)
	server.mux.HandleFunc("GET /api/v1/organizations", server.listOrganizations)
	server.mux.HandleFunc("POST /api/v1/organizations", server.createOrganization)
	server.mux.HandleFunc("GET /api/v1/organizations/{organization_id}", server.getOrganization)
	server.mux.HandleFunc("GET /api/v1/organizations/{organization_id}/teams", server.listTeams)
	server.mux.HandleFunc("POST /api/v1/organizations/{organization_id}/teams", server.createTeam)
	server.mux.HandleFunc("GET /api/v1/teams/{team_id}", server.getTeam)
	server.mux.HandleFunc("GET /api/v1/organizations/{organization_id}/projects", server.listProjects)
	server.mux.HandleFunc("POST /api/v1/organizations/{organization_id}/projects", server.createProject)
	server.mux.HandleFunc("GET /api/v1/projects/{project_id}", server.getProject)
	return server, nil
}

type observedWriter struct {
	http.ResponseWriter
	status, bytes int
}

func (w *observedWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *observedWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(body)
	w.bytes += n
	return n, err
}

func (server *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	ctx, counters := telemetry.Begin(r.Context())
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	output := &observedWriter{ResponseWriter: w}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		http.Error(output, "Unavailable", 503)
		return
	}
	output.Header().Set("X-Correlation-ID", hex.EncodeToString(id[:]))
	output.Header().Set("Cache-Control", "no-store")
	output.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		if server.config.Observe != nil {
			server.config.Observe(Observation{Operation: r.Pattern, Status: output.status, DurationMilliseconds: float64(time.Since(started).Microseconds()) / 1000, ResponseBytes: output.bytes, Snapshot: counters.Snapshot()})
		}
	}()
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Host != server.host || r.URL.IsAbs() || r.URL.RawPath != "" || r.URL.RawQuery != "" || strings.ContainsAny(r.URL.Path, "\\\x00") || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			problem(output, 400)
			return
		}
		if len(r.Header.Values("Origin")) > 1 || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != server.config.Origin) {
			problem(output, 403)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("Origin") != server.config.Origin {
			problem(output, 403)
			return
		}
		// Bearer/provider tokens, method overrides, and browser-supplied authority
		// never enter the local cookie boundary.
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-HTTP-Method-Override") != "" {
			problem(output, 400)
			return
		}
	}
	_, pattern := server.mux.Handler(r)
	if pattern == "" {
		problem(output, 404)
		return
	}
	server.mux.ServeHTTP(output, r)
}

func problem(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": "The request could not be completed.", "status": status, "correlation_id": w.Header().Get("X-Correlation-ID")})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func readStrings(w http.ResponseWriter, r *http.Request, required, optional []string) (map[string]string, error) {
	media, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(parameters) > 1 || (len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8")) {
		return nil, organization.ErrInvalid
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err != nil || !utf8.Valid(raw) {
		return nil, organization.ErrInvalid
	}
	allowed := map[string]bool{}
	for _, key := range append(append([]string{}, required...), optional...) {
		allowed[key] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, organization.ErrInvalid
	}
	result := map[string]string{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, organization.ErrInvalid
		}
		key, ok := keyToken.(string)
		if !ok || !allowed[key] {
			return nil, organization.ErrInvalid
		}
		if _, exists := result[key]; exists {
			return nil, organization.ErrInvalid
		}
		valueToken, err := decoder.Token()
		value, ok := valueToken.(string)
		if err != nil || !ok || strings.ContainsRune(value, '\ufffd') {
			return nil, organization.ErrInvalid
		}
		result[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, organization.ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, organization.ErrInvalid
	}
	for _, key := range required {
		if _, ok := result[key]; !ok {
			return nil, organization.ErrInvalid
		}
	}
	return result, nil
}

func tokenFromCookie(r *http.Request) (string, error) {
	values := r.CookiesNamed(cookieName)
	if len(values) != 1 {
		return "", identity.ErrUnauthenticated
	}
	return values[0].Value, nil
}
func (server *Server) authenticated(w http.ResponseWriter, r *http.Request) (identity.Authenticated, bool) {
	token, err := tokenFromCookie(r)
	if err != nil {
		problem(w, 401)
		return identity.Authenticated{}, false
	}
	session, err := server.config.Identity.Authenticate(r.Context(), token)
	if err != nil {
		problem(w, 401)
		return identity.Authenticated{}, false
	}
	return session, true
}
func sessionView(session identity.Authenticated) any {
	return struct {
		Principal  identity.Principal `json:"principal"`
		InstanceID string             `json:"instance_id"`
		ExpiresAt  time.Time          `json:"expires_at"`
		Revision   uint64             `json:"session_revision"`
	}{session.Principal(), session.Context().InstanceID, session.ExpiresAt(), session.Context().Revision}
}
func (server *Server) session(w http.ResponseWriter, r *http.Request) {
	session, ok := server.authenticated(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, sessionView(session))
}
func (server *Server) login(w http.ResponseWriter, r *http.Request) {
	body, err := readStrings(w, r, []string{"token"}, nil)
	if err != nil {
		problem(w, 400)
		return
	}
	session, err := server.config.Identity.Authenticate(r.Context(), body["token"])
	if err != nil {
		problem(w, 401)
		return
	}
	newToken, digest, err := identity.NewLocalToken()
	if err != nil {
		problem(w, 503)
		return
	}
	rotated, err := server.config.Repository.RotateSessionToken(r.Context(), session.SessionID(), sha256.Sum256([]byte(body["token"])), digest)
	if err != nil || !rotated {
		problem(w, 401)
		return
	}
	session, err = server.config.Identity.Authenticate(r.Context(), newToken)
	if err != nil {
		problem(w, 401)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: newToken, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt()})
	writeJSON(w, 200, sessionView(session))
}
func (server *Server) logout(w http.ResponseWriter, r *http.Request) {
	session, ok := server.authenticated(w, r)
	if !ok {
		return
	}
	if server.config.Repository.RevokeSession(r.Context(), session.SessionID()) != nil {
		problem(w, 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"signed_out": true})
}

func (server *Server) authorize(w http.ResponseWriter, r *http.Request, session identity.Authenticated, action authorization.Action, kind, id string) (*authorization.Decision, bool) {
	decision, err := server.config.Authorization.Authorize(r.Context(), session, action, authorization.ResourceRef{Kind: kind, ID: id})
	if err != nil {
		problem(w, 404)
		return nil, false
	}
	return decision, true
}
func domainError(w http.ResponseWriter, err error) {
	var pending *organization.PendingError
	switch {
	case errors.Is(err, organization.ErrInvalid):
		problem(w, 400)
	case errors.Is(err, organization.ErrConflict):
		problem(w, 409)
	case errors.As(err, &pending):
		w.Header().Set("Retry-After", "1")
		problem(w, 503)
	default:
		problem(w, 404)
	}
}

type protectedResponse struct {
	writer   http.ResponseWriter
	body     []byte
	status   int
	etag     string
	released bool
}

func (response *protectedResponse) Release(ctx context.Context) error {
	if ctx.Err() != nil || response.released || response.body == nil {
		return authorization.ErrDenied
	}
	response.released = true
	response.writer.Header().Set("Content-Type", "application/json")
	response.writer.Header().Set("Stead-Schema-Version", "1.0")
	if response.etag != "" {
		response.writer.Header().Set("ETag", response.etag)
	}
	response.writer.WriteHeader(response.status)
	_, err := response.writer.Write(response.body)
	response.body = nil
	return err
}
func (response *protectedResponse) Suppress() { response.body = nil }
func (server *Server) release(w http.ResponseWriter, r *http.Request, status int, value any, decisions []*authorization.Decision) {
	body, err := json.Marshal(value)
	if err != nil || len(body) > maxResponseBytes {
		problem(w, 503)
		return
	}
	revision, err := server.config.Repository.FinalizeResponse(r.Context(), decisions)
	if err != nil {
		problem(w, 404)
		return
	}
	digest := sha256.Sum256(body)
	response := &protectedResponse{writer: w, body: body, status: status, etag: `"` + hex.EncodeToString(digest[:]) + `"`}
	if _, err = server.boundary.ReleaseProtected(r.Context(), revision, response); err != nil && !response.released {
		problem(w, 404)
	}
}
