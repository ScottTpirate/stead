package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
	"github.com/ScottTpirate/stead/modules/project"
)

func (server *Server) envelope(value organization.Resource, decision *authorization.Decision) map[string]any {
	containerID := value.OrganizationID
	uri := "urn:uuid:" + value.ID
	return map[string]any{
		"kind": value.Kind, "id": value.ID, "uri": uri, "browser_url": server.config.Origin + "/r/" + value.Kind + "/" + value.ID,
		"schema_version": "1.0", "version": value.Version, "instance_id": value.InstanceID, "scope_kind": "organization", "scope_id": value.OrganizationID, "organization_id": value.OrganizationID,
		"container": map[string]string{"kind": "organization", "id": containerID, "uri": "urn:uuid:" + containerID},
		"title":     value.Title, "created_at": value.CreatedAt, "created_by": value.CreatedBy, "updated_at": value.CreatedAt, "updated_by": value.CreatedBy,
		"security_label_id": value.SecurityLabelID, "effective_security_label": value.Label, "security_presentation": decision.Presentation(),
		"provenance": map[string]any{"created_at": value.CreatedAt, "created_by": value.CreatedBy}, "external_references": []any{}, "relationships": []any{},
	}
}
func (server *Server) organizationView(value organization.Organization, decision *authorization.Decision) map[string]any {
	result := server.envelope(value.Resource, decision)
	result["key"] = value.Key
	result["name"] = value.Name
	return result
}
func (server *Server) teamView(value organization.Team, decision *authorization.Decision) map[string]any {
	result := server.envelope(value.Resource, decision)
	result["key"] = value.Key
	result["name"] = value.Name
	result["hierarchy_depth"] = value.HierarchyDepth
	if value.ParentTeamID != "" {
		result["parent_team_id"] = value.ParentTeamID
	}
	return result
}
func (server *Server) projectView(value project.Project, decision *authorization.Decision) map[string]any {
	// A general Project exposes only its authorized Work/Docs summary. Provider
	// tracker IDs and software-only surfaces do not cross this response boundary.
	return map[string]any{"kind": "project", "id": value.ID, "uri": "urn:uuid:" + value.ID, "browser_url": server.config.Origin + "/r/project/" + value.ID, "schema_version": "1.0", "instance_id": value.InstanceID, "scope_kind": "organization", "scope_id": value.OrganizationID, "organization_id": value.OrganizationID, "title": value.Title, "purpose": value.Purpose, "lifecycle_state": value.LifecycleState, "owning_team_id": value.OwningTeamID, "authorized_capabilities": []string{"work", "docs"}, "visible_areas": []string{"overview", "work", "docs"}, "effective_security_label": value.Label, "security_presentation": decision.Presentation(), "version": value.Version}
}

func (server *Server) readResource(ctx context.Context, session identity.Authenticated, kind, id string) (map[string]any, *authorization.Decision, error) {
	action := authorization.OrganizationRead
	switch kind {
	case "team":
		action = authorization.TeamRead
	case "project":
		action = authorization.ProjectRead
	case "organization":
	default:
		return nil, nil, authorization.ErrDenied
	}
	decision, err := server.config.Authorization.Authorize(ctx, session, action, authorization.ResourceRef{Kind: kind, ID: id})
	if err != nil {
		return nil, nil, err
	}
	ctx = decision.WithContext(ctx)
	switch kind {
	case "organization":
		value, err := server.config.Repository.GetOrganization(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		return server.organizationView(value, decision), decision, nil
	case "team":
		value, err := server.config.Repository.GetTeam(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		return server.teamView(value, decision), decision, nil
	default:
		value, err := server.config.Repository.GetProject(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		return server.projectView(value, decision), decision, nil
	}
}
func (server *Server) get(w http.ResponseWriter, r *http.Request, kind, id string, status int) {
	session, ok := server.authenticated(w, r)
	if !ok {
		return
	}
	value, decision, err := server.readResource(r.Context(), session, kind, id)
	if err != nil {
		domainError(w, err)
		return
	}
	server.release(w, r, status, value, []*authorization.Decision{decision})
}
func (server *Server) getOrganization(w http.ResponseWriter, r *http.Request) {
	server.get(w, r, "organization", r.PathValue("organization_id"), 200)
}
func (server *Server) getTeam(w http.ResponseWriter, r *http.Request) {
	server.get(w, r, "team", r.PathValue("team_id"), 200)
}
func (server *Server) getProject(w http.ResponseWriter, r *http.Request) {
	server.get(w, r, "project", r.PathValue("project_id"), 200)
}

func idempotencyKey(r *http.Request) string {
	values := r.Header.Values("Idempotency-Key")
	if len(values) != 1 || !organization.ValidIdempotencyKey(values[0]) {
		return ""
	}
	return values[0]
}

func (server *Server) created(w http.ResponseWriter, r *http.Request, session identity.Authenticated, ctx context.Context, kind, id string, err error) {
	var pending *organization.PendingError
	if errors.As(err, &pending) {
		id = pending.ResourceID
		if err = server.config.ActivateCreated(ctx, session, id); err != nil {
			domainError(w, &organization.PendingError{ResourceID: id})
			return
		}
	} else if err != nil {
		domainError(w, err)
		return
	}
	// Parent create permission is not read permission on the new object.
	value, decision, err := server.readResource(r.Context(), session, kind, id)
	if err != nil {
		domainError(w, err)
		return
	}
	server.release(w, r, 201, value, []*authorization.Decision{decision})
}
func (server *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	session, ok := server.authenticated(w, r)
	if !ok {
		return
	}
	body, err := readStrings(w, r, []string{"key", "name"}, nil)
	if err != nil {
		problem(w, 400)
		return
	}
	command := organization.Create{Key: body["key"], Name: body["name"], IdempotencyKey: idempotencyKey(r)}
	if command.Validate() != nil {
		problem(w, 400)
		return
	}
	decision, ok := server.authorize(w, r, session, authorization.OrganizationCreate, "instance", server.config.InstanceID)
	if !ok {
		return
	}
	ctx := decision.WithContext(r.Context())
	value, err := server.config.Repository.CreateOrganization(ctx, command)
	server.created(w, r, session, ctx, "organization", value.ID, err)
}
func (server *Server) createTeam(w http.ResponseWriter, r *http.Request) {
	session, ok := server.authenticated(w, r)
	if !ok {
		return
	}
	body, err := readStrings(w, r, []string{"key", "name"}, []string{"parent_team_id"})
	if err != nil {
		problem(w, 400)
		return
	}
	command := organization.CreateTeam{OrganizationID: r.PathValue("organization_id"), Key: body["key"], Name: body["name"], ParentTeamID: body["parent_team_id"], IdempotencyKey: idempotencyKey(r)}
	if command.Validate() != nil {
		problem(w, 400)
		return
	}
	decision, ok := server.authorize(w, r, session, authorization.TeamCreate, "organization", command.OrganizationID)
	if !ok {
		return
	}
	ctx := decision.WithContext(r.Context())
	if command.ParentTeamID != "" {
		parent, ok := server.authorize(w, r, session, authorization.TeamHierarchyManage, "team", command.ParentTeamID)
		if !ok {
			return
		}
		if parent.Evidence().OrganizationID != command.OrganizationID {
			problem(w, 404)
			return
		}
		ctx = parent.WithContext(ctx)
	}
	value, err := server.config.Repository.CreateTeam(ctx, command)
	server.created(w, r, session, ctx, "team", value.ID, err)
}
func (server *Server) createProject(w http.ResponseWriter, r *http.Request) {
	session, ok := server.authenticated(w, r)
	if !ok {
		return
	}
	body, err := readStrings(w, r, []string{"key", "title", "purpose", "owning_team_id"}, nil)
	if err != nil {
		problem(w, 400)
		return
	}
	command := project.Create{OrganizationID: r.PathValue("organization_id"), Key: body["key"], Title: body["title"], Purpose: body["purpose"], OwningTeamID: body["owning_team_id"], IdempotencyKey: idempotencyKey(r)}
	if command.Validate() != nil {
		problem(w, 400)
		return
	}
	decision, ok := server.authorize(w, r, session, authorization.ProjectCreate, "organization", command.OrganizationID)
	if !ok {
		return
	}
	ctx := decision.WithContext(r.Context())
	owner, ok := server.authorize(w, r, session, authorization.TeamRead, "team", command.OwningTeamID)
	if !ok {
		return
	}
	if owner.Evidence().OrganizationID != command.OrganizationID {
		problem(w, 404)
		return
	}
	ctx = owner.WithContext(ctx)
	value, err := server.config.Repository.CreateProject(ctx, command)
	server.created(w, r, session, ctx, "project", value.ID, err)
}
