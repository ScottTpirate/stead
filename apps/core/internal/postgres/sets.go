package postgres

import (
	"context"
	"encoding/json"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/jackc/pgx/v5"
)

const maxStateSet = 101

type ownerRead func(string, func(pgx.Tx) error) error

// ReadStates is a bounded set-oriented authorization input. It preserves input
// order, loads each shared namespace/session/label once, and exposes no content.
// Missing resources have only Resource populated and cannot pass central auth.
// Query/integrity failure aborts the complete set rather than omitting rows.
func (store *Store) ReadStates(ctx context.Context, principal identity.Principal, sessionID string, refs []authorization.ResourceRef) ([]authorization.State, error) {
	return store.readStates(ctx, principal, sessionID, refs, false, func(owner string, read func(pgx.Tx) error) error {
		return store.owned(ctx, owner, false, read)
	})
}

func (store *Store) readStates(ctx context.Context, principal identity.Principal, sessionID string, refs []authorization.ResourceRef, lock bool, owned ownerRead) ([]authorization.State, error) {
	if !principal.Valid() || !identity.ValidID(sessionID) || len(refs) == 0 || len(refs) > maxStateSet {
		return nil, authorization.ErrDenied
	}
	positions := map[authorization.ResourceRef]int{}
	ids := make([]string, len(refs))
	byKind := map[string][]string{}
	for index, ref := range refs {
		if !identity.ValidID(ref.ID) || (ref.Kind != "instance" && ref.Kind != "organization" && ref.Kind != "team" && ref.Kind != "project") {
			return nil, authorization.ErrDenied
		}
		if _, duplicate := positions[ref]; duplicate {
			return nil, authorization.ErrDenied
		}
		positions[ref], ids[index] = index, ref.ID
		byKind[ref.Kind] = append(byKind[ref.Kind], ref.ID)
	}
	var session identity.SessionRecord
	if err := owned("identity", func(tx pgx.Tx) error {
		var err error
		session, err = loadSession(ctx, tx, "s.id=$1", sessionID, lock)
		return err
	}); err != nil || session.Principal != principal || session.InstanceID != store.config.InstanceID || session.SecurityDomain != store.config.SecurityDomain {
		return nil, authorization.ErrDenied
	}
	security := make([]resourceSecurity, len(refs))
	found := make([]bool, len(refs))
	labelSet := map[string]bool{}
	if err := owned("authorization", func(tx pgx.Tx) error {
		namespace, err := loadNamespace(ctx, tx, lock)
		if err != nil || namespace.InstanceID != store.config.InstanceID || namespace.SecurityDomain != store.config.SecurityDomain {
			return authorization.ErrDenied
		}
		query := `SELECT r.id::text,r.kind,COALESCE(r.organization_id::text,''),r.label_id::text,r.pending,r.explicit_deny,r.provider_allowed,r.capability_active,r.revision,r.tuple_revision,f.pending FROM "authorization".resources r CROSS JOIN "authorization".session_fences f WHERE r.id=ANY($1::uuid[]) AND f.session_id=$2 ORDER BY r.id`
		if lock {
			query += ` FOR SHARE`
		}
		rows, err := tx.Query(ctx, query, ids, sessionID)
		count(ctx, 1, 0, 0, 0)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			current := resourceSecurity{state: namespace}
			state := &current.state
			if err = rows.Scan(&state.Resource.ID, &state.Resource.Kind, &state.OrganizationID, &current.labelID, &state.TuplePending, &state.ExplicitDeny, &state.ProviderPathAllowed, &state.CapabilityActive, &state.Revisions.Resource, &state.Revisions.Tuples, &state.SessionPending); err != nil {
				return err
			}
			index, requested := positions[state.Resource]
			if !requested {
				continue
			}
			state.Principal, state.SessionID = principal, sessionID
			applyIdentity(state, session)
			security[index], found[index] = current, true
			labelSet[current.labelID] = true
		}
		return rows.Err()
	}); err != nil {
		return nil, authorization.ErrDenied
	}
	labels := map[string]classification.Label{}
	if len(labelSet) > 0 {
		labelIDs := make([]string, 0, len(labelSet))
		for id := range labelSet {
			labelIDs = append(labelIDs, id)
		}
		if err := owned("classification", func(tx pgx.Tx) error {
			query := `SELECT id::text,value,revision FROM classification.labels WHERE id=ANY($1::uuid[]) ORDER BY id`
			if lock {
				query += ` FOR SHARE`
			}
			rows, err := tx.Query(ctx, query, labelIDs)
			count(ctx, 1, 0, 0, 0)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				var raw []byte
				var revision uint64
				var label classification.Label
				if err = rows.Scan(&id, &raw, &revision); err != nil || json.Unmarshal(raw, &label) != nil || label.Version != revision {
					return authorization.ErrDenied
				}
				labels[id] = label
			}
			return rows.Err()
		}); err != nil || len(labels) != len(labelSet) {
			return nil, authorization.ErrDenied
		}
	}
	canonical := map[authorization.ResourceRef]string{}
	// A role never reads a foreign schema. Organization and Team share one
	// owner transaction but remain separately indexed, bounded set queries.
	for _, owner := range []string{"organization", "project"} {
		kinds := []string{"organization", "team"}
		if owner == "project" {
			kinds = []string{"project"}
		}
		needed := false
		for _, kind := range kinds {
			needed = needed || len(byKind[kind]) > 0
		}
		if !needed {
			continue
		}
		if err := owned(owner, func(tx pgx.Tx) error {
			for _, kind := range kinds {
				if len(byKind[kind]) == 0 {
					continue
				}
				query := `SELECT id::text,organization_id::text FROM organization.teams WHERE active AND id=ANY($1::uuid[]) ORDER BY id`
				if kind == "organization" {
					query = `SELECT id::text,id::text FROM organization.organizations WHERE active AND id=ANY($1::uuid[]) ORDER BY id`
				} else if kind == "project" {
					query = `SELECT id::text,organization_id::text FROM project.projects WHERE active AND id=ANY($1::uuid[]) ORDER BY id`
				}
				if lock {
					query += ` FOR SHARE`
				}
				rows, err := tx.Query(ctx, query, byKind[kind])
				count(ctx, 1, 0, 0, 0)
				if err != nil {
					return err
				}
				for rows.Next() {
					var id, org string
					if err = rows.Scan(&id, &org); err != nil {
						rows.Close()
						return err
					}
					canonical[authorization.ResourceRef{Kind: kind, ID: id}] = org
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, authorization.ErrDenied
		}
	}
	states := make([]authorization.State, len(refs))
	for index, ref := range refs {
		states[index].Resource = ref
		if !found[index] {
			continue
		}
		state := security[index].state
		if ref.Kind == "instance" {
			if ref.ID != state.InstanceID || state.OrganizationID != "" {
				return nil, authorization.ErrDenied
			}
		} else if org, exists := canonical[ref]; !exists {
			continue
		} else if org != state.OrganizationID {
			return nil, authorization.ErrDenied
		}
		state.Label = labels[security[index].labelID].Copy()
		state.Revisions.Label = state.Label.Version
		states[index] = state
	}
	return states, nil
}
