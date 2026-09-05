package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

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
func discoverPage(ctx context.Context, after string, size int, fetch func(context.Context, string, int) ([]string, error), eligible func(context.Context, []string) ([]bool, error)) ([]string, error) {
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
		}
		allowed, err := eligible(ctx, ids)
		if err != nil || len(allowed) != len(ids) {
			return nil, errCollectionUnavailable
		}
		scanned += len(ids)
		for index, id := range ids {
			if allowed[index] {
				selected = append(selected, id)
				if len(selected) > size {
					return selected, nil
				}
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
		parentKind, parentID, parentAction = "instance", server.config.InstanceID, authorization.OrganizationsList
	}
	parent := authorization.ReadAuthorization{Action: parentAction, Target: authorization.ResourceRef{Kind: parentKind, ID: parentID}}
	inputs := func(ids []string) []authorization.ReadAuthorization {
		result := make([]authorization.ReadAuthorization, 1, len(ids)+1)
		result[0] = parent
		for _, id := range ids {
			result = append(result, authorization.ReadAuthorization{Action: readAction(kind), Target: authorization.ResourceRef{Kind: kind, ID: id}})
		}
		return result
	}
	// A cursor is only a previously visible resource coordinate, not authority.
	// A revoked, cross-kind, deleted or cross-Organization cursor denies alike.
	initialIDs := []string{}
	if after != "" {
		initialIDs = append(initialIDs, after)
	}
	initial, err := server.config.Authorization.AuthorizeSet(base, session, inputs(initialIDs))
	if err != nil {
		problem(w, 503)
		return
	}
	if !allowedPageSet(initial, kind, parentID, len(initialIDs)) {
		problem(w, 404)
		return
	}
	eligible := func(ctx context.Context, ids []string) ([]bool, error) {
		if len(ids) == 0 {
			return []bool{}, nil
		}
		decisions, err := server.config.Authorization.AuthorizeSet(ctx, session, inputs(ids))
		if err != nil || len(decisions) != len(ids)+1 || decisions[0] == nil {
			return nil, errCollectionUnavailable
		}
		allowed := make([]bool, len(ids))
		for index, decision := range decisions[1:] {
			allowed[index] = decision != nil && (kind == "organization" || decision.Evidence().OrganizationID == parentID)
		}
		return allowed, nil
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
	decisions, err := server.config.Authorization.AuthorizeSet(base, session, inputs(freshIDs))
	if err != nil {
		problem(w, 503)
		return
	}
	if !allowedPageSet(decisions, kind, parentID, len(freshIDs)) {
		problem(w, 404)
		return
	}
	values, err := server.readPage(base, kind, decisions[1:])
	if err != nil {
		domainError(w, err)
		return
	}
	if after != "" {
		// Keep the freshly authorized cursor in the aggregate final fence, but
		// never duplicate its representation in the new page.
		values = values[1:]
	}
	page := resourcePage{Items: values}
	if len(values) > size {
		page.Items = values[:size]
		page.NextAfter = ids[size-1]
	}
	server.release(w, r, 200, page, decisions)
}

func allowedPageSet(decisions []*authorization.Decision, kind, organization string, rows int) bool {
	if len(decisions) != rows+1 || decisions[0] == nil {
		return false
	}
	for _, decision := range decisions[1:] {
		if decision == nil || (kind != "organization" && decision.Evidence().OrganizationID != organization) {
			return false
		}
	}
	return true
}

// readPage reads one owner set using the fresh shared logical authorization
// decision. Cursor and authorized lookahead remain part of the final proof;
// neither discovery snapshots nor individual per-row policy calls are reused.
func (server *Server) readPage(ctx context.Context, kind string, decisions []*authorization.Decision) ([]map[string]any, error) {
	values := make([]map[string]any, len(decisions))
	if len(decisions) == 0 {
		return values, nil
	}
	switch kind {
	case "organization":
		rows, err := server.config.Repository.GetOrganizations(ctx, decisions)
		if err != nil || len(rows) != len(decisions) {
			return nil, authorization.ErrDenied
		}
		for index, row := range rows {
			values[index] = server.organizationView(row, decisions[index])
		}
	case "team":
		rows, err := server.config.Repository.GetTeams(ctx, decisions)
		if err != nil || len(rows) != len(decisions) {
			return nil, authorization.ErrDenied
		}
		for index, row := range rows {
			values[index] = server.teamView(row, decisions[index])
		}
	case "project":
		rows, err := server.config.Repository.GetProjects(ctx, decisions)
		if err != nil || len(rows) != len(decisions) {
			return nil, authorization.ErrDenied
		}
		for index, row := range rows {
			values[index] = server.projectView(row, decisions[index])
		}
	default:
		return nil, authorization.ErrDenied
	}
	return values, nil
}
func (server *Server) listOrganizations(w http.ResponseWriter, r *http.Request) {
	server.list(w, r, "organization")
}
func (server *Server) listTeams(w http.ResponseWriter, r *http.Request) { server.list(w, r, "team") }
func (server *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	server.list(w, r, "project")
}
