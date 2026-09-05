package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/identity"
)

const maxPageSize = 20
const candidateChunk = 100
const maxCandidateScan = 1000

var errCollectionUnavailable = errors.New("collection unavailable")

type resourcePage struct {
	Items     []map[string]any `json:"items"`
	NextAfter string           `json:"next_after,omitempty"`
}

func listPattern(pattern string) bool {
	switch pattern {
	case "GET /api/v1/organizations", "GET /api/v1/organizations/{organization_id}/teams", "GET /api/v1/organizations/{organization_id}/projects":
		return true
	}
	return false
}
func pageParameters(raw string) (int, string, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return 0, "", errCollectionUnavailable
	}
	size := maxPageSize
	after := ""
	for key, entries := range values {
		if len(entries) != 1 {
			return 0, "", errCollectionUnavailable
		}
		switch key {
		case "page_size":
			value, err := strconv.Atoi(entries[0])
			if err != nil || value < 1 || value > maxPageSize || strconv.Itoa(value) != entries[0] {
				return 0, "", errCollectionUnavailable
			}
			size = value
		case "after":
			if !identity.ValidID(entries[0]) {
				return 0, "", errCollectionUnavailable
			}
			after = entries[0]
		default:
			return 0, "", errCollectionUnavailable
		}
	}
	return size, after, nil
}

// discoverPage never returns raw-candidate continuation metadata. The extra
// eligible ID is a private lookahead; only an authorized returned row can later
// become next_after, and only after fresh complete response authorization.
func discoverPage(ctx context.Context, after string, size int, fetch func(context.Context, string, int) ([]string, error), eligible func(context.Context, string) error) ([]string, error) {
	selected := []string{}
	cursor := after
	for scanned := 0; scanned < maxCandidateScan; {
		if ctx.Err() != nil {
			return nil, errCollectionUnavailable
		}
		ids, err := fetch(ctx, cursor, candidateChunk)
		if err != nil || len(ids) > candidateChunk {
			return nil, errCollectionUnavailable
		}
		for _, id := range ids {
			if !identity.ValidID(id) || id <= cursor {
				return nil, errCollectionUnavailable
			}
			cursor = id
			scanned++
			if err = eligible(ctx, id); err == nil {
				selected = append(selected, id)
				if len(selected) > size {
					return selected, nil
				}
			} else if !errors.Is(err, authorization.ErrDenied) {
				return nil, errCollectionUnavailable
			}
			if ctx.Err() != nil {
				return nil, errCollectionUnavailable
			}
		}
		if len(ids) < candidateChunk {
			return selected, nil
		}
	}
	// Reaching the scan budget is not an empty/end page and cannot mint a cursor.
	return nil, errCollectionUnavailable
}

func readAction(kind string) authorization.Action {
	switch kind {
	case "organization":
		return authorization.OrganizationRead
	case "team":
		return authorization.TeamRead
	case "project":
		return authorization.ProjectRead
	}
	return ""
}
func (server *Server) list(w http.ResponseWriter, r *http.Request, kind string) {
	size, after, err := pageParameters(r.URL.RawQuery)
	if err != nil {
		problem(w, 400)
		return
	}
	session, ok := server.authenticated(w, r)
	if !ok {
		return
	}
	base := authorization.WithoutDecisions(r.Context())
	parentKind, parentID, parentAction := "organization", r.PathValue("organization_id"), authorization.OrganizationRead
	if kind == "organization" {
		parentKind, parentID, parentAction = "instance", server.config.InstanceID, authorization.OrganizationCreate
	}
	if _, err = server.config.Authorization.Authorize(base, session, parentAction, authorization.ResourceRef{Kind: parentKind, ID: parentID}); err != nil {
		problem(w, 404)
		return
	}
	eligible := func(ctx context.Context, id string) error {
		decision, err := server.config.Authorization.Authorize(ctx, session, readAction(kind), authorization.ResourceRef{Kind: kind, ID: id})
		if err != nil {
			return err
		}
		if kind != "organization" && decision.Evidence().OrganizationID != parentID {
			return authorization.ErrDenied
		}
		return nil
	}
	// A cursor is only a previously visible resource coordinate, not authority.
	// A revoked, cross-kind, deleted or cross-Organization cursor denies alike.
	if after != "" {
		if err = eligible(base, after); err != nil {
			problem(w, 404)
			return
		}
	}
	fetch := func(ctx context.Context, cursor string, limit int) ([]string, error) {
		switch kind {
		case "organization":
			return server.config.Repository.ListOrganizationPageIDs(ctx, parentID, cursor, limit)
		case "team":
			return server.config.Repository.ListTeamPageIDs(ctx, parentID, cursor, limit)
		default:
			return server.config.Repository.ListProjectPageIDs(ctx, parentID, cursor, limit)
		}
	}
	ids, err := discoverPage(base, after, size, fetch, eligible)
	if err != nil {
		problem(w, 503)
		return
	}
	freshIDs := ids
	if after != "" {
		freshIDs = append([]string{after}, ids...)
	}
	values, decisions, err := server.freshPage(base, session, kind, parentID, freshIDs)
	if err != nil {
		domainError(w, err)
		return
	}
	if after != "" {
		// Keep the freshly authorized cursor in the aggregate final fence, but
		// never duplicate its representation in the new page.
		values = values[1:]
	}
	// Discovery may have lasted longer than a decision lease. Renew the parent
	// too; no discovery decision is reused for disclosure.
	parent, err := server.config.Authorization.Authorize(base, session, parentAction, authorization.ResourceRef{Kind: parentKind, ID: parentID})
	if err != nil {
		problem(w, 404)
		return
	}
	decisions = append([]*authorization.Decision{parent}, decisions...)
	page := resourcePage{Items: values}
	if len(values) > size {
		page.Items = values[:size]
		page.NextAfter = ids[size-1]
	}
	server.release(w, r, 200, page, decisions)
}

// freshPage uses bounded parallel central decisions and canonical reads. All
// buffered bytes are regenerated from those reads, not an earlier discovery
// snapshot. Failure returns no partial page; finalization rechecks every row,
// including the authorized lookahead that justifies continuation.
func (server *Server) freshPage(ctx context.Context, session identity.Authenticated, kind, organization string, ids []string) ([]map[string]any, []*authorization.Decision, error) {
	values := make([]map[string]any, len(ids))
	decisions := make([]*authorization.Decision, len(ids))
	failures := make([]error, len(ids))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	var workers sync.WaitGroup
	for worker := 0; worker < min(4, len(ids)); worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				value, decision, err := server.readResource(ctx, session, kind, ids[index])
				if err == nil && kind != "organization" && decision.Evidence().OrganizationID != organization {
					err = authorization.ErrDenied
				}
				values[index], decisions[index], failures[index] = value, decision, err
				if err != nil {
					cancel()
				}
			}
		}()
	}
	for index := range ids {
		jobs <- index
	}
	close(jobs)
	workers.Wait()
	for _, err := range failures {
		if err != nil {
			return nil, nil, authorization.ErrDenied
		}
	}
	return values, decisions, nil
}
func (server *Server) listOrganizations(w http.ResponseWriter, r *http.Request) {
	server.list(w, r, "organization")
}
func (server *Server) listTeams(w http.ResponseWriter, r *http.Request) { server.list(w, r, "team") }
func (server *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	server.list(w, r, "project")
}
