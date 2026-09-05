package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
	"github.com/jackc/pgx/v5"
)

func count(ctx context.Context, queries, writes, audits, outbox uint64) {
	telemetry.AddSQL(ctx, queries, writes)
	telemetry.AddAudit(ctx, audits)
	telemetry.AddOutbox(ctx, outbox)
}

func loadSession(ctx context.Context, tx pgx.Tx, clause string, value any, lock bool) (identity.SessionRecord, error) {
	query := `SELECT s.record,s.active,s.revision,p.active,p.revision,s.id::text,p.id::text,p.kind FROM identity.sessions s JOIN identity.principals p ON p.id=s.principal_id WHERE ` + clause
	if lock {
		query += ` FOR SHARE OF s,p`
	}
	var data []byte
	var session identity.SessionRecord
	var canonicalSessionID, canonicalPrincipalID, canonicalPrincipalKind string
	err := tx.QueryRow(ctx, query, value).Scan(&data, &session.Active, &session.Revision, &session.PrincipalActive, &session.PrincipalRevision, &canonicalSessionID, &canonicalPrincipalID, &canonicalPrincipalKind)
	count(ctx, 1, 0, 0, 0)
	if err != nil {
		return identity.SessionRecord{}, identity.ErrUnauthenticated
	}
	var stored identity.SessionRecord
	if json.Unmarshal(data, &stored) != nil || stored.ID != canonicalSessionID || stored.Principal.ID != canonicalPrincipalID || stored.Principal.Type != canonicalPrincipalKind {
		return identity.SessionRecord{}, identity.ErrUnauthenticated
	}
	stored.Active = session.Active
	stored.Revision = session.Revision
	stored.PrincipalActive = session.PrincipalActive
	stored.PrincipalRevision = session.PrincipalRevision
	return stored, nil
}
func (store *Store) LookupSession(ctx context.Context, digest [sha256.Size]byte) (identity.SessionRecord, error) {
	var result identity.SessionRecord
	err := store.owned(ctx, "identity", false, func(tx pgx.Tx) error {
		var err error
		result, err = loadSession(ctx, tx, "s.token_digest=$1", digest[:], false)
		return err
	})
	if err != nil {
		return identity.SessionRecord{}, identity.ErrUnauthenticated
	}
	return result, nil
}
func (store *Store) RotateSessionToken(ctx context.Context, id string, oldDigest, newDigest [sha256.Size]byte) (bool, error) {
	if !identity.ValidID(id) || oldDigest == newDigest || newDigest == ([32]byte{}) {
		return false, identity.ErrUnauthenticated
	}
	changed := false
	err := store.owned(ctx, "identity", true, func(tx pgx.Tx) error {
		session, err := loadSession(ctx, tx, "s.id=$1", id, true)
		if err != nil || !session.Active || !session.PrincipalActive || session.AuthenticationStrength != "local_bootstrap" || session.Authority != "stead_local_identity" || !time.Now().Before(session.ExpiresAt) {
			return identity.ErrUnauthenticated
		}
		tag, err := tx.Exec(ctx, `UPDATE identity.sessions SET token_digest=$1,revision=revision+1,bootstrap_consumed=true WHERE id=$2 AND token_digest=$3 AND active AND NOT bootstrap_consumed`, newDigest[:], id, oldDigest[:])
		count(ctx, 1, uint64(tag.RowsAffected()), 0, 0)
		changed = tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		return false, identity.ErrUnauthenticated
	}
	return changed, nil
}
func (store *Store) RevokeSession(ctx context.Context, id string) error {
	if !identity.ValidID(id) {
		return identity.ErrUnauthenticated
	}
	return store.owned(ctx, "identity", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE identity.sessions SET active=false,revision=revision+1 WHERE id=$1 AND active`, id)
		count(ctx, 1, uint64(tag.RowsAffected()), 0, 0)
		return err
	})
}

type resourceSecurity struct {
	state   authorization.State
	labelID string
}

func loadSecurity(ctx context.Context, tx pgx.Tx, principal identity.Principal, sessionID string, ref authorization.ResourceRef, lock bool) (resourceSecurity, error) {
	var result resourceSecurity
	result.state.Resource = ref
	result.state.Principal = principal
	result.state.SessionID = sessionID
	var revisions, bindingJSON []byte
	var storeID string
	query := `SELECT instance_id::text,security_domain,store_id,activation_id,activation_sequence,model_id,activation_digest,activation_binding,revisions,policy_time,policy_revision FROM "authorization".namespace WHERE id`
	if lock {
		query += ` FOR UPDATE`
	}
	state := &result.state
	err := tx.QueryRow(ctx, query).Scan(&state.InstanceID, &state.SecurityDomain, &storeID, &state.ActivationSetID, &state.ActivationSequence, &state.OpenFGAModelID, &state.ActivationDigest, &bindingJSON, &revisions, &state.PolicyTimeHighWater, &state.PolicyTimeRevision)
	count(ctx, 1, 0, 0, 0)
	var binding authorization.ActivationBinding
	if err != nil || json.Unmarshal(revisions, &state.Revisions) != nil || json.Unmarshal(bindingJSON, &binding) != nil || binding.Digest() != state.ActivationDigest || binding.OpenFGAStoreID != storeID || binding.OpenFGAModelID != state.OpenFGAModelID || binding.DeploymentPolicyID != state.SecurityDomain || binding.ActivationSetID != state.ActivationSetID || binding.ActivationSequence != state.ActivationSequence {
		return resourceSecurity{}, authorization.ErrDenied
	}
	query = `SELECT COALESCE(organization_id::text,''),label_id::text,pending,explicit_deny,provider_allowed,capability_active,revision,tuple_revision FROM "authorization".resources WHERE id=$1 AND kind=$2`
	if lock {
		query += ` FOR SHARE`
	}
	err = tx.QueryRow(ctx, query, ref.ID, ref.Kind).Scan(&state.OrganizationID, &result.labelID, &state.TuplePending, &state.ExplicitDeny, &state.ProviderPathAllowed, &state.CapabilityActive, &state.Revisions.Resource, &state.Revisions.Tuples)
	count(ctx, 1, 0, 0, 0)
	if err != nil {
		return resourceSecurity{}, authorization.ErrDenied
	}
	return result, nil
}
func loadLabel(ctx context.Context, tx pgx.Tx, id string, lock bool) (classification.Label, error) {
	var data []byte
	var revision uint64
	query := `SELECT value,revision FROM classification.labels WHERE id=$1`
	if lock {
		query += ` FOR SHARE`
	}
	err := tx.QueryRow(ctx, query, id).Scan(&data, &revision)
	count(ctx, 1, 0, 0, 0)
	var label classification.Label
	if err != nil || json.Unmarshal(data, &label) != nil || revision != label.Version {
		return classification.Label{}, authorization.ErrDenied
	}
	return label, nil
}
func applyIdentity(state *authorization.State, session identity.SessionRecord) {
	state.PrincipalActive = session.PrincipalActive
	state.SessionActive = session.Active
	state.Revisions.Principal = session.PrincipalRevision
	state.Revisions.Session = session.Revision
	state.ContextExpiresAt = session.ExpiresAt
}

func (store *Store) ReadState(ctx context.Context, principal identity.Principal, sessionID string, ref authorization.ResourceRef) (authorization.State, error) {
	if !principal.Valid() || !identity.ValidID(sessionID) || !identity.ValidID(ref.ID) {
		return authorization.State{}, authorization.ErrDenied
	}
	var session identity.SessionRecord
	if err := store.owned(ctx, "identity", false, func(tx pgx.Tx) error {
		var err error
		session, err = loadSession(ctx, tx, "s.id=$1", sessionID, false)
		return err
	}); err != nil || session.Principal != principal || session.InstanceID != store.config.InstanceID || session.SecurityDomain != store.config.SecurityDomain {
		return authorization.State{}, authorization.ErrDenied
	}
	var security resourceSecurity
	if err := store.owned(ctx, "authorization", false, func(tx pgx.Tx) error {
		var err error
		security, err = loadSecurity(ctx, tx, principal, sessionID, ref, false)
		return err
	}); err != nil {
		return authorization.State{}, authorization.ErrDenied
	}
	if err := store.owned(ctx, "classification", false, func(tx pgx.Tx) error {
		var err error
		security.state.Label, err = loadLabel(ctx, tx, security.labelID, false)
		return err
	}); err != nil {
		return authorization.State{}, authorization.ErrDenied
	}
	applyIdentity(&security.state, session)
	security.state.Revisions.Label = security.state.Label.Version
	if ref.Kind != "instance" {
		if err := store.canonicalExists(ctx, ref, security.state.OrganizationID); err != nil {
			return authorization.State{}, authorization.ErrDenied
		}
	}
	return security.state, nil
}

func canonicalQuery(kind string) (string, string) {
	switch kind {
	case "organization":
		return "organization", `SELECT id::text FROM organization.organizations WHERE id=$1 AND active`
	case "team":
		return "organization", `SELECT organization_id::text FROM organization.teams WHERE id=$1 AND active`
	case "project":
		return "project", `SELECT organization_id::text FROM project.projects WHERE id=$1 AND active`
	}
	return "", ""
}
func (store *Store) canonicalExists(ctx context.Context, ref authorization.ResourceRef, org string) error {
	owner, query := canonicalQuery(ref.Kind)
	if owner == "" {
		return authorization.ErrDenied
	}
	return store.owned(ctx, owner, false, func(tx pgx.Tx) error {
		var actual string
		err := tx.QueryRow(ctx, query, ref.ID).Scan(&actual)
		count(ctx, 1, 0, 0, 0)
		if err != nil || actual != org {
			return authorization.ErrDenied
		}
		return nil
	})
}

func (store *Store) ListOrganizationIDs(ctx context.Context, instanceID string, limit int) ([]string, error) {
	return store.ListOrganizationPageIDs(ctx, instanceID, "", limit)
}
func (store *Store) ListOrganizationPageIDs(ctx context.Context, instanceID, after string, limit int) ([]string, error) {
	if instanceID != store.config.InstanceID {
		return nil, organization.ErrUnavailable
	}
	return store.listIDs(ctx, "organization", `SELECT id::text FROM organization.organizations WHERE active AND ($2::uuid IS NULL OR id>$2::uuid) ORDER BY id LIMIT $1`, nil, after, limit)
}
func (store *Store) ListTeamIDs(ctx context.Context, organizationID string, limit int) ([]string, error) {
	return store.ListTeamPageIDs(ctx, organizationID, "", limit)
}
func (store *Store) ListTeamPageIDs(ctx context.Context, organizationID, after string, limit int) ([]string, error) {
	return store.listIDs(ctx, "organization", `SELECT id::text FROM organization.teams WHERE organization_id=$3 AND active AND ($2::uuid IS NULL OR id>$2::uuid) ORDER BY id LIMIT $1`, &organizationID, after, limit)
}
func (store *Store) ListProjectIDs(ctx context.Context, organizationID string, limit int) ([]string, error) {
	return store.ListProjectPageIDs(ctx, organizationID, "", limit)
}
func (store *Store) ListProjectPageIDs(ctx context.Context, organizationID, after string, limit int) ([]string, error) {
	return store.listIDs(ctx, "project", `SELECT id::text FROM project.projects WHERE organization_id=$3 AND active AND ($2::uuid IS NULL OR id>$2::uuid) ORDER BY id LIMIT $1`, &organizationID, after, limit)
}
func (store *Store) listIDs(ctx context.Context, owner, query string, org *string, after string, limit int) ([]string, error) {
	if limit < 1 || limit > 100 || (after != "" && !identity.ValidID(after)) || (org != nil && !identity.ValidID(*org)) {
		return nil, organization.ErrInvalid
	}
	ids := []string{}
	err := store.owned(ctx, owner, false, func(tx pgx.Tx) error {
		var cursor any
		if after != "" {
			cursor = after
		}
		args := []any{limit, cursor}
		if org != nil {
			args = append(args, *org)
		}
		rows, err := tx.Query(ctx, query, args...)
		count(ctx, 1, 0, 0, 0)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return ids, nil
}

func (store *Store) RecordDenial(ctx context.Context, denial authorization.Denial) error {
	if !denial.Actor.Valid() || denial.DecisionID == "" || denial.Reason == "" || denial.OccurredAt.IsZero() {
		return errors.New("invalid denial evidence")
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	return store.owned(ctx, "audit", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO audit.records(id,actor,action,decision,evidence,occurred_at) VALUES($1,$2,$3,'deny',$4,$5)`, id, denial.Actor.Type+":"+denial.Actor.ID, string(denial.Action), encode(denial), denial.OccurredAt)
		count(ctx, 1, 1, 1, 0)
		return err
	})
}
