package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/organization"
	"github.com/ScottTpirate/stead/modules/project"
	"github.com/jackc/pgx/v5"
)

func (store *Store) GetOrganizations(ctx context.Context, decisions []*authorization.Decision) ([]organization.Organization, error) {
	return readResourceSet[organization.Organization](ctx, store, "organization", decisions, func(value *organization.Organization) *organization.Resource { return &value.Resource })
}
func (store *Store) GetTeams(ctx context.Context, decisions []*authorization.Decision) ([]organization.Team, error) {
	return readResourceSet[organization.Team](ctx, store, "team", decisions, func(value *organization.Team) *organization.Resource { return &value.Resource })
}
func (store *Store) GetProjects(ctx context.Context, decisions []*authorization.Decision) ([]project.Project, error) {
	return readResourceSet[project.Project](ctx, store, "project", decisions, func(value *project.Project) *organization.Resource { return &value.Resource })
}

// readResourceSet loads one owner payload set and validates the complete fresh
// decision set without per-row transactions/audits. This is a buffered internal
// result, not a disclosure: the caller must still FinalizeResponse and release
// via RequestBoundaryAdapter after constructing the whole finite response.
func readResourceSet[T any](ctx context.Context, store *Store, kind string, decisions []*authorization.Decision, resource func(*T) *organization.Resource) ([]T, error) {
	if len(decisions) == 0 || len(decisions) > maxStateSet {
		return nil, authorization.ErrDenied
	}
	first := decisions[0].Evidence()
	refs := make([]authorization.ResourceRef, len(decisions))
	ids := make([]string, len(decisions))
	for index, decision := range decisions {
		e := decision.Evidence()
		if first.DecisionID == "" || e.DecisionID != first.DecisionID || e.EvaluatedAt != first.EvaluatedAt || e.ExpiresAt != first.ExpiresAt || e.Target.Kind != kind || e.Action != authorization.Action(kind+".read") || e.Actor != first.Actor || e.SessionID != first.SessionID || e.InstanceID != store.config.InstanceID || e.ActivationDigest != first.ActivationDigest {
			return nil, authorization.ErrDenied
		}
		refs[index], ids[index] = e.Target, e.Target.ID
	}
	owner, table := "organization", "organizations"
	if kind == "team" {
		table = "teams"
	} else if kind == "project" {
		owner, table = "project", "projects"
	}
	values := map[string]T{}
	if err := store.owned(ctx, owner, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text,record FROM `+pgx.Identifier{owner, table}.Sanitize()+` WHERE active AND id=ANY($1::uuid[]) ORDER BY id`, ids)
		count(ctx, 1, 0, 0, 0)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var raw []byte
			var value T
			if err = rows.Scan(&id, &raw); err != nil || json.Unmarshal(raw, &value) != nil || resource(&value).ID != id {
				return authorization.ErrDenied
			}
			values[id] = value
		}
		return rows.Err()
	}); err != nil || len(values) != len(decisions) {
		return nil, authorization.ErrDenied
	}
	states, err := store.ReadStates(ctx, first.Actor, first.SessionID, refs)
	if err != nil {
		return nil, authorization.ErrDenied
	}
	anchor, err := store.config.Anchor.Read(ctx)
	if err != nil || anchor.Binding != decisions[0].Binding() {
		return nil, authorization.ErrDenied
	}
	now := time.Now().UTC()
	if now.Before(anchor.PolicyTimeHighWater) {
		now = anchor.PolicyTimeHighWater
	}
	result := make([]T, len(decisions))
	for index, decision := range decisions {
		state := states[index]
		if state.PolicyTimeHighWater.After(anchor.PolicyTimeHighWater) || state.PolicyTimeRevision > anchor.PolicyTimeRevision {
			return nil, authorization.ErrDenied
		}
		state.PolicyTimeHighWater, state.PolicyTimeRevision = anchor.PolicyTimeHighWater, anchor.PolicyTimeRevision
		if decision.ValidateFinal(state, now) != nil {
			return nil, authorization.ErrDenied
		}
		value := values[ids[index]]
		base := resource(&value)
		if base.InstanceID != state.InstanceID || base.OrganizationID != state.OrganizationID || base.Kind != kind || base.Version == 0 {
			return nil, authorization.ErrDenied
		}
		base.Label = state.Label.Copy()
		result[index] = value
	}
	return result, nil
}
