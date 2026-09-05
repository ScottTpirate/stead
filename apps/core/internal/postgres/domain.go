package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
	"github.com/ScottTpirate/stead/modules/audit"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
	"github.com/ScottTpirate/stead/modules/project"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"time"
)

func (store *Store) CreateOrganization(ctx context.Context, value organization.Create) (organization.Organization, error) {
	if err := value.Validate(); err != nil {
		return organization.Organization{}, err
	}
	var result organization.Organization
	err := store.create(ctx, command{Kind: "organization", Key: value.Key, Title: value.Name, IdempotencyKey: value.IdempotencyKey}, &result)
	return result, err
}
func (store *Store) CreateTeam(ctx context.Context, value organization.CreateTeam) (organization.Team, error) {
	if err := value.Validate(); err != nil {
		return organization.Team{}, err
	}
	var result organization.Team
	err := store.create(ctx, command{Kind: "team", Org: value.OrganizationID, Key: value.Key, Title: value.Name, Related: value.ParentTeamID, IdempotencyKey: value.IdempotencyKey}, &result)
	return result, err
}
func (store *Store) CreateProject(ctx context.Context, value project.Create) (project.Project, error) {
	if err := value.Validate(); err != nil {
		return project.Project{}, err
	}
	var result project.Project
	err := store.create(ctx, command{Kind: "project", Org: value.OrganizationID, Key: value.Key, Title: value.Title, Purpose: value.Purpose, Related: value.OwningTeamID, IdempotencyKey: value.IdempotencyKey}, &result)
	return result, err
}

func (store *Store) create(ctx context.Context, input command, destination any) error {
	input.Mode = "create"
	decisions, err := checkDecisions(ctx, input, store.config.InstanceID)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(encode(input))
	input.InputHash = string(hash[:])
	input.ID, err = NewID()
	if err != nil {
		return err
	}
	input.EventID, err = NewID()
	if err != nil {
		return err
	}
	input.CreatedNanos = time.Now().UnixNano()
	evidence := decisions[0].Evidence()
	state, err := store.ReadState(ctx, evidence.Actor, evidence.SessionID, evidence.Target)
	if err != nil {
		return authorization.ErrDenied
	}
	org := input.Org
	if input.Kind == "organization" {
		org = input.ID
	}
	record := organization.Resource{ID: input.ID, Kind: input.Kind, OrganizationID: org, InstanceID: store.config.InstanceID, Key: input.Key, Title: input.Title, CreatedAt: time.Unix(0, input.CreatedNanos).UTC(), CreatedBy: evidence.Actor, Label: state.Label, Version: 1}
	payload, err := audit.CreatedEvent(input.EventID, record, input.IdempotencyKey, store.config.SecurityDomain, evidence.DecisionID)
	if err != nil {
		return err
	}
	intent, err := outbox.NewValidationAuthority().WrapValidated(outbox.ValidatedIntentHandoffV1, payload)
	if err != nil {
		return err
	}
	plan, err := store.createPlan.Bind(store.registry, input, &intent)
	if err != nil {
		return err
	}
	result := &executionResult{}
	ctx = context.WithValue(ctx, resultKey{}, result)
	_, err = store.coordinator.Execute(ctx, plan)
	if err != nil {
		return commandError(result.failure)
	}
	if err = json.Unmarshal(result.raw, destination); err != nil {
		return organization.ErrUnavailable
	}
	if result.pending {
		var resource organization.Resource
		if json.Unmarshal(result.raw, &resource) != nil {
			return organization.ErrUnavailable
		}
		return &organization.PendingError{ResourceID: resource.ID}
	}
	return nil
}
func commandError(err error) error {
	if errors.Is(err, organization.ErrConflict) {
		return organization.ErrConflict
	}
	if errors.Is(err, organization.ErrInvalid) {
		return organization.ErrInvalid
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "23505" {
		return organization.ErrConflict
	}
	return authorization.ErrDenied
}

func (store *Store) GetOrganization(ctx context.Context, id string) (organization.Organization, error) {
	var result organization.Organization
	err := store.read(ctx, "organization", id, &result)
	return result, err
}
func (store *Store) GetTeam(ctx context.Context, id string) (organization.Team, error) {
	var result organization.Team
	err := store.read(ctx, "team", id, &result)
	return result, err
}
func (store *Store) GetProject(ctx context.Context, id string) (project.Project, error) {
	var result project.Project
	err := store.read(ctx, "project", id, &result)
	return result, err
}
func (store *Store) read(ctx context.Context, kind, id string, destination any) error {
	if !identity.ValidID(id) {
		return organization.ErrUnavailable
	}
	input := command{Mode: "read", Kind: kind, ID: id}
	if _, err := checkDecisions(ctx, input, store.config.InstanceID); err != nil {
		return err
	}
	plan, err := store.readPlan.Bind(store.registry, input, nil)
	if err != nil {
		return err
	}
	result := &executionResult{}
	ctx = context.WithValue(ctx, resultKey{}, result)
	if _, err = store.coordinator.Execute(ctx, plan); err != nil {
		return authorization.ErrDenied
	}
	if json.Unmarshal(result.raw, destination) != nil {
		return organization.ErrUnavailable
	}
	return nil
}

type CreatorGrant struct {
	ResourceID      string
	Action          authorization.Action
	Target, Related authorization.ResourceRef
	Tuples          []authorization.Tuple
	Pending         bool
}

func (store *Store) PendingCreatorGrant(ctx context.Context, id string) (CreatorGrant, error) {
	if !identity.ValidID(id) {
		return CreatorGrant{}, authorization.ErrDenied
	}
	var result CreatorGrant
	var actor, action string
	var tuples []byte
	result.ResourceID = id
	err := store.owned(ctx, "authorization", false, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT actor,action,target_kind,target_id::text,related_kind,related_id,tuples,pending FROM "authorization".creator_grants WHERE resource_id=$1`, id).Scan(&actor, &action, &result.Target.Kind, &result.Target.ID, &result.Related.Kind, &result.Related.ID, &tuples, &result.Pending)
		count(ctx, 1, 0, 0, 0)
		return err
	})
	decision, ok := authorization.DecisionFromContext(ctx)
	if err != nil || !ok || actor != decision.Evidence().Actor.Type+":"+decision.Evidence().Actor.ID || action != string(decision.Evidence().Action) || result.Target != decision.Evidence().Target || json.Unmarshal(tuples, &result.Tuples) != nil {
		return CreatorGrant{}, authorization.ErrDenied
	}
	result.Action = authorization.Action(action)
	return result, nil
}
func (store *Store) ActivateCreatorGrant(ctx context.Context, id string, receipt *authorization.TupleReceipt) error {
	grant, err := store.PendingCreatorGrant(ctx, id)
	if err != nil || len(grant.Tuples) == 0 {
		return authorization.ErrDenied
	}
	kind := strings.SplitN(grant.Tuples[0].Object, ":", 2)[0]
	org := grant.Target.ID
	if kind == "organization" {
		org = ""
	}
	input := command{Mode: "activate", Kind: kind, ID: id, Org: org, Related: grant.Related.ID}
	if _, err = checkDecisions(ctx, input, store.config.InstanceID); err != nil {
		return err
	}
	plan, err := store.activatePlan.Bind(store.registry, input, nil)
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, receiptKey{}, receipt)
	if _, err = store.coordinator.Execute(ctx, plan); err != nil {
		return authorization.ErrDenied
	}
	return nil
}
