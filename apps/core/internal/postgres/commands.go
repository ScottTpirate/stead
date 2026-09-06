package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/modules/audit"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
	"github.com/ScottTpirate/stead/modules/project"
	"github.com/jackc/pgx/v5"
)

// command has only value fields; the transaction registry snapshots it once.
// Mutable storage results and sealed decisions remain private to the root.
type command struct {
	Mode, Kind, ID, Org, Key, Title, Purpose, Related, IdempotencyKey, InputHash, EventID string
	CreatedNanos                                                                          int64
}
type receiptKey struct{}

func (store *Store) register() error {
	contract, err := transaction.NewBackendContract(store)
	if err != nil {
		return err
	}
	store.contract = contract
	participants := []transaction.TypedParticipant[command]{}
	for index, entry := range []struct {
		key, owner string
		write      bool
		run        func(context.Context, *runtimeSession, command) error
	}{
		{"identity_snapshot", "identity", false, store.identityParticipant},
		{"authorization_snapshot", "authorization", true, store.securityParticipant},
		{"classification_snapshot", "classification", false, store.classificationParticipant},
		{"organization_snapshot", "organization", false, store.organizationSnapshot},
		{"project_snapshot", "project", false, store.projectSnapshot},
		{"authorization_final", "authorization", true, store.finalParticipant},
		{"organization_write", "organization", true, store.organizationWrite},
		{"project_write", "project", true, store.projectWrite},
		{"audit_write", "audit", true, store.auditParticipant},
	} {
		owner, run := entry.owner, entry.run
		operation, err := transaction.NewBackendOperation(contract, owner, func(ctx context.Context, binding transaction.ExecutorBinding, input command) error {
			session, err := store.session(binding)
			if err != nil {
				return err
			}
			if err = session.role(ctx, owner); err == nil {
				err = run(ctx, session, input)
			}
			if err != nil {
				if result, ok := ctx.Value(resultKey{}).(*executionResult); ok {
					result.failure = err
				}
			}
			return err
		})
		if err != nil {
			return err
		}
		registered, err := transaction.NewRegisteredOperation(operation, func(ctx context.Context, port transaction.OperationPort[command], _ command) error {
			return port.Execute(ctx)
		})
		if err != nil {
			return err
		}
		after := []string{}
		if index > 0 {
			after = []string{participants[index-1].Key}
		}
		participants = append(participants, transaction.TypedParticipant[command]{Key: entry.key, After: after, DeclaresWrite: entry.write, Operation: registered})
	}
	template, plan, err := transaction.NewPlanContract(transaction.ContractVersionV1, "checkpoint_a.create.v1", participants, transaction.OutboxRequired)
	if err != nil {
		return err
	}
	store.createPlan = plan
	readTemplate, readPlan, err := transaction.NewPlanContract(transaction.ContractVersionV1, "checkpoint_a.read.v1", participants, transaction.OutboxOptional)
	if err != nil {
		return err
	}
	store.readPlan = readPlan
	activateTemplate, activatePlan, err := transaction.NewPlanContract(transaction.ContractVersionV1, "checkpoint_a.activate.v1", participants, transaction.OutboxOptional)
	if err != nil {
		return err
	}
	store.activatePlan = activatePlan
	registry, err := transaction.NewRegistry([]transaction.PlanTemplate{template, readTemplate, activateTemplate})
	if err != nil {
		return err
	}
	store.registry = registry
	appender, err := transaction.NewStorageOutbox(contract, store.appendOutbox)
	if err != nil {
		return err
	}
	finalOperation, err := transaction.NewBackendOperation(contract, transaction.FinalAuthorizationOwner, store.finalResponseOperation)
	if err != nil {
		return err
	}
	durableOperation, err := transaction.NewBackendOperation(contract, transaction.DurableEffectOwner, store.effectOperation)
	if err != nil {
		return err
	}
	store.coordinator, err = transaction.NewCoordinator(transaction.Configuration{Backend: contract, Registry: registry, Outbox: appender, FinalAuthorizationAudit: store, FinalAuthorizationOperation: finalOperation, DurableEffectPreparation: store, DurableEffectOperation: durableOperation})
	return err
}

func expected(input command, instance string) (authorization.Action, authorization.ResourceRef, authorization.Action, authorization.ResourceRef) {
	target := authorization.ResourceRef{Kind: "organization", ID: input.Org}
	action := authorization.TeamCreate
	if input.Kind == "organization" {
		target = authorization.ResourceRef{Kind: "instance", ID: instance}
		action = authorization.OrganizationCreate
	}
	if input.Kind == "project" {
		action = authorization.ProjectCreate
	}
	if input.Mode == "read" {
		target = authorization.ResourceRef{Kind: input.Kind, ID: input.ID}
		switch input.Kind {
		case "organization":
			action = authorization.OrganizationRead
		case "team":
			action = authorization.TeamRead
		case "project":
			action = authorization.ProjectRead
		}
		return action, target, "", authorization.ResourceRef{}
	}
	relatedAction := authorization.TeamHierarchyManage
	if input.Kind == "project" {
		relatedAction = authorization.TeamRead
	}
	related := authorization.ResourceRef{}
	if input.Related != "" {
		related = authorization.ResourceRef{Kind: "team", ID: input.Related}
	}
	return action, target, relatedAction, related
}
func checkDecisions(ctx context.Context, input command, instance string) ([]*authorization.Decision, error) {
	decisions := authorization.DecisionsFromContext(ctx)
	action, target, relatedAction, related := expected(input, instance)
	length := 1
	if related.ID != "" {
		length = 2
	}
	if len(decisions) != length {
		return nil, authorization.ErrDenied
	}
	primary := decisions[0].Evidence()
	if primary.Action != action || primary.Target != target || primary.InstanceID != instance {
		return nil, authorization.ErrDenied
	}
	if length == 2 {
		second := decisions[1].Evidence()
		if second.Action != relatedAction || second.Target != related || second.Actor != primary.Actor || second.SessionID != primary.SessionID || second.OrganizationID != input.Org || second.ActivationDigest != primary.ActivationDigest {
			return nil, authorization.ErrDenied
		}
	}
	return decisions, nil
}
func (store *Store) identityParticipant(ctx context.Context, session *runtimeSession, input command) error {
	decisions, err := checkDecisions(ctx, input, store.config.InstanceID)
	if err != nil {
		return err
	}
	evidence := decisions[0].Evidence()
	session.identity, err = loadSession(ctx, session.tx, "s.id=$1", evidence.SessionID, true)
	if err != nil || session.identity.Principal != evidence.Actor || session.identity.InstanceID != store.config.InstanceID || session.identity.SecurityDomain != store.config.SecurityDomain {
		return authorization.ErrDenied
	}
	return nil
}
func (store *Store) securityParticipant(ctx context.Context, session *runtimeSession, input command) error {
	decisions, _ := checkDecisions(ctx, input, store.config.InstanceID)
	for _, decision := range decisions {
		e := decision.Evidence()
		security, err := loadSecurity(ctx, session.tx, e.Actor, e.SessionID, e.Target, true)
		if err != nil {
			return err
		}
		applyIdentity(&security.state, session.identity)
		session.states = append(session.states, security.state)
		if len(session.states) == 1 {
			session.result.SecurityLabelID = security.labelID
		} else if security.labelID != session.result.SecurityLabelID {
			return authorization.ErrDenied
		}
	}
	if input.Mode == "create" {
		e := decisions[0].Evidence()
		actor := e.Actor.Type + ":" + e.Actor.ID
		var hash []byte
		var id string
		err := session.tx.QueryRow(ctx, `SELECT input_hash,resource_id::text FROM "authorization".requests WHERE actor=$1 AND action=$2 AND key=$3`, actor, string(e.Action), input.IdempotencyKey).Scan(&hash, &id)
		count(ctx, 1, 0, 0, 0)
		if err == nil {
			if string(hash) != input.InputHash {
				return organization.ErrConflict
			}
			session.replay = true
			session.result.ID = id
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		} else {
			session.result.ID = input.ID
		}
	}
	if input.Mode == "activate" {
		var actor, action, targetKind, targetID, relatedKind, relatedID string
		var raw []byte
		err := session.tx.QueryRow(ctx, `SELECT actor,action,target_kind,target_id::text,related_kind,related_id,tuples,pending FROM "authorization".creator_grants WHERE resource_id=$1 FOR UPDATE`, input.ID).Scan(&actor, &action, &targetKind, &targetID, &relatedKind, &relatedID, &raw, &session.pending)
		count(ctx, 1, 0, 0, 0)
		e := decisions[0].Evidence()
		if err != nil || actor != e.Actor.Type+":"+e.Actor.ID || action != string(e.Action) || targetKind != e.Target.Kind || targetID != e.Target.ID || relatedID != input.Related || json.Unmarshal(raw, &session.grant) != nil {
			return authorization.ErrDenied
		}
		receipt, ok := ctx.Value(receiptKey{}).(*authorization.TupleReceipt)
		if !ok || receipt == nil || !receipt.Match(session.grant) || receipt.ModelID() != e.OpenFGAModelID || receipt.StoreID() != store.config.OpenFGAStoreID || time.Since(receipt.VerifiedAt()) < 0 || time.Since(receipt.VerifiedAt()) > 2*time.Second {
			return authorization.ErrDenied
		}
	}
	return nil
}
func (store *Store) classificationParticipant(ctx context.Context, session *runtimeSession, _ command) error {
	label, err := loadLabel(ctx, session.tx, session.result.SecurityLabelID, true)
	if err != nil {
		return err
	}
	session.label = label
	for index := range session.states {
		session.states[index].Label = label.Copy()
		session.states[index].Revisions.Label = label.Version
	}
	return nil
}
func (store *Store) organizationSnapshot(ctx context.Context, session *runtimeSession, input command) error {
	for _, state := range session.states {
		if state.Resource.Kind == "organization" || state.Resource.Kind == "team" {
			_, query := canonicalQuery(state.Resource.Kind)
			var org string
			err := session.tx.QueryRow(ctx, query+` FOR SHARE`, state.Resource.ID).Scan(&org)
			count(ctx, 1, 0, 0, 0)
			if err != nil || org != state.OrganizationID {
				return authorization.ErrDenied
			}
		}
	}
	if input.Mode != "read" && input.Related != "" {
		var org string
		err := session.tx.QueryRow(ctx, `SELECT organization_id::text,depth FROM organization.teams WHERE id=$1 AND active FOR SHARE`, input.Related).Scan(&org, &session.depth)
		count(ctx, 1, 0, 0, 0)
		if err != nil || org != input.Org {
			return authorization.ErrDenied
		}
		if input.Kind == "team" {
			session.depth++
			if session.depth > 11 {
				return organization.ErrInvalid
			}
		}
	}
	if (input.Mode == "read" || session.replay) && input.Kind != "project" {
		id := input.ID
		if session.replay {
			id = session.result.ID
		}
		table := "organizations"
		if input.Kind == "team" {
			table = "teams"
		}
		err := session.tx.QueryRow(ctx, `SELECT record FROM organization.`+table+` WHERE id=$1 AND active FOR SHARE`, id).Scan(&session.raw)
		count(ctx, 1, 0, 0, 0)
		if err != nil {
			return organization.ErrUnavailable
		}
	}
	return nil
}
func (store *Store) projectSnapshot(ctx context.Context, session *runtimeSession, input command) error {
	for _, state := range session.states {
		if state.Resource.Kind == "project" {
			var org string
			_, query := canonicalQuery("project")
			err := session.tx.QueryRow(ctx, query+` FOR SHARE`, state.Resource.ID).Scan(&org)
			count(ctx, 1, 0, 0, 0)
			if err != nil || org != state.OrganizationID {
				return authorization.ErrDenied
			}
		}
	}
	if (input.Mode == "read" || session.replay) && input.Kind == "project" {
		id := input.ID
		if session.replay {
			id = session.result.ID
		}
		err := session.tx.QueryRow(ctx, `SELECT record FROM project.projects WHERE id=$1 AND active FOR SHARE`, id).Scan(&session.raw)
		count(ctx, 1, 0, 0, 0)
		if err != nil {
			return organization.ErrUnavailable
		}
	}
	return nil
}
func (store *Store) finalParticipant(ctx context.Context, session *runtimeSession, input command) error {
	decisions, err := checkDecisions(ctx, input, store.config.InstanceID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	anchor, err := store.config.Anchor.CompareMax(ctx, decisions[0].Binding(), now)
	if err != nil {
		return authorization.ErrDenied
	}
	// Lock acquisition and durable compare-max may have consumed the remaining
	// decision lifetime. Never validate using the pre-wait clock sample.
	now = time.Now().UTC()
	for index, decision := range decisions {
		session.states[index].PolicyTimeHighWater = anchor.PolicyTimeHighWater
		session.states[index].PolicyTimeRevision = anchor.PolicyTimeRevision
		if err = decision.ValidateFinal(session.states[index], now); err != nil {
			return err
		}
	}
	_, err = session.tx.Exec(ctx, `UPDATE "authorization".namespace SET policy_time=GREATEST(policy_time,$1),policy_revision=GREATEST(policy_revision,$2) WHERE id`, anchor.PolicyTimeHighWater, anchor.PolicyTimeRevision)
	count(ctx, 1, 1, 0, 0)
	if err != nil {
		return err
	}
	if input.Mode == "read" {
		return nil
	}
	if input.Mode == "activate" {
		if !session.pending {
			return nil
		}
		tag, err := session.tx.Exec(ctx, `UPDATE "authorization".resources SET pending=false,tuple_revision=tuple_revision+1,revision=revision+1 WHERE id=$1 AND pending`, input.ID)
		count(ctx, 1, uint64(tag.RowsAffected()), 0, 0)
		if err != nil || tag.RowsAffected() != 1 {
			return authorization.ErrDenied
		}
		_, err = session.tx.Exec(ctx, `UPDATE "authorization".creator_grants SET pending=false WHERE resource_id=$1`, input.ID)
		count(ctx, 1, 1, 0, 0)
		session.pending = false
		return err
	}
	if session.replay {
		err := session.tx.QueryRow(ctx, `SELECT pending FROM "authorization".resources WHERE id=$1`, session.result.ID).Scan(&session.pending)
		count(ctx, 1, 0, 0, 0)
		return err
	}
	e := decisions[0].Evidence()
	org := input.Org
	if input.Kind == "organization" {
		org = input.ID
	}
	session.result = organization.Resource{ID: input.ID, Kind: input.Kind, InstanceID: store.config.InstanceID, OrganizationID: org, Key: input.Key, Title: input.Title, SecurityLabelID: session.result.SecurityLabelID, Label: session.label.Copy(), Version: 1, CreatedAt: time.Unix(0, input.CreatedNanos).UTC(), CreatedBy: e.Actor}
	session.pending = true
	actor := e.Actor.Type + ":" + e.Actor.ID
	object := input.Kind + ":" + input.ID
	session.grant = []authorization.Tuple{{User: actor, Relation: "viewer", Object: object}, {User: actor, Relation: "editor", Object: object}}
	if input.Kind == "team" {
		session.grant = []authorization.Tuple{{User: actor, Relation: "lead", Object: object}, {User: "organization:" + org, Relation: "organization", Object: object}}
		if input.Related != "" {
			session.grant = append(session.grant, authorization.Tuple{User: "team:" + input.Related, Relation: "parent", Object: object})
		}
	}
	if input.Kind == "project" {
		session.grant = append(session.grant, authorization.Tuple{User: actor, Relation: "manager", Object: object}, authorization.Tuple{User: "organization:" + org, Relation: "organization", Object: object}, authorization.Tuple{User: "team:" + input.Related, Relation: "owning_team", Object: object})
	}
	if _, err = session.tx.Exec(ctx, `INSERT INTO "authorization".resources(id,kind,organization_id,label_id,pending,revision,tuple_revision) VALUES($1,$2,$3,$4,true,1,1)`, input.ID, input.Kind, org, session.result.SecurityLabelID); err != nil {
		return err
	}
	count(ctx, 1, 1, 0, 0)
	if _, err = session.tx.Exec(ctx, `INSERT INTO "authorization".requests VALUES($1,$2,$3,$4,$5)`, actor, string(e.Action), input.IdempotencyKey, []byte(input.InputHash), input.ID); err != nil {
		return err
	}
	count(ctx, 1, 1, 0, 0)
	_, target, _, related := expected(input, store.config.InstanceID)
	_, err = session.tx.Exec(ctx, `INSERT INTO "authorization".creator_grants VALUES($1,$2,$3,$4,$5,$6,$7,$8,true,$9)`, input.ID, actor, string(e.Action), target.Kind, target.ID, related.Kind, related.ID, encode(session.grant), session.result.CreatedAt)
	count(ctx, 1, 1, 0, 0)
	return err
}
func (store *Store) organizationWrite(ctx context.Context, session *runtimeSession, input command) error {
	if input.Mode != "create" || session.replay || input.Kind == "project" {
		return nil
	}
	if input.Kind == "organization" {
		session.raw = encode(organization.Organization{Resource: session.result, Name: input.Title})
		_, err := session.tx.Exec(ctx, `INSERT INTO organization.organizations(id,key,record) VALUES($1,$2,$3)`, input.ID, input.Key, session.raw)
		count(ctx, 1, 1, 0, 0)
		return err
	}
	session.raw = encode(organization.Team{Resource: session.result, Name: input.Title, ParentTeamID: input.Related, HierarchyDepth: session.depth})
	var parent any
	if input.Related != "" {
		parent = input.Related
	}
	_, err := session.tx.Exec(ctx, `INSERT INTO organization.teams(id,organization_id,key,parent_id,depth,record) VALUES($1,$2,$3,$4,$5,$6)`, input.ID, input.Org, input.Key, parent, session.depth, session.raw)
	count(ctx, 1, 1, 0, 0)
	return err
}
func (store *Store) projectWrite(ctx context.Context, session *runtimeSession, input command) error {
	if input.Mode != "create" || session.replay || input.Kind != "project" {
		return nil
	}
	session.raw = encode(project.Project{Resource: session.result, Purpose: input.Purpose, OwningTeamID: input.Related, ContributingTeamIDs: []string{}, Capabilities: project.Capabilities{Preset: "general", Active: []string{"work", "docs"}}, LifecycleState: "active"})
	_, err := session.tx.Exec(ctx, `INSERT INTO project.projects(id,organization_id,key,owning_team_id,record) VALUES($1,$2,$3,$4,$5)`, input.ID, input.Org, input.Key, input.Related, session.raw)
	count(ctx, 1, 1, 0, 0)
	return err
}
func (store *Store) auditParticipant(ctx context.Context, session *runtimeSession, input command) error {
	if input.Mode == "read" || session.replay {
		return nil
	} // finite read has one aggregate audit at FinalizeResponse.
	decision, _ := authorization.DecisionFromContext(ctx)
	e := decision.Evidence()
	id, err := NewID()
	if err != nil {
		return err
	}
	action := string(e.Action)
	if input.Mode == "activate" {
		action = "authorization.creator_grant.activate"
	}
	after := sha256.Sum256(session.raw)
	evidence := struct {
		Authorization authorization.Evidence
		AfterHash     [32]byte
		Pending       bool
	}{e, after, session.pending}
	_, err = session.tx.Exec(ctx, `INSERT INTO audit.records VALUES($1,$2,$3,$4,'allow',$5,$6)`, id, input.ID, e.Actor.Type+":"+e.Actor.ID, action, encode(evidence), time.Now().UTC())
	count(ctx, 1, 1, 1, 0)
	return err
}
func (store *Store) appendOutbox(ctx context.Context, binding transaction.ExecutorBinding, intent outbox.ValidatedIntent) error {
	session, err := store.session(binding)
	if err != nil {
		return err
	}
	if session.replay {
		return nil
	}
	if err = session.role(ctx, "core_outbox"); err != nil {
		return err
	}
	eventID, resourceID, subject, err := outboxRoute(intent.PayloadCopy())
	if err != nil || resourceID != session.result.ID {
		return authorization.ErrDenied
	}
	digest := intent.Digest()
	_, err = session.tx.Exec(ctx, `INSERT INTO core_outbox.intents(id,resource_id,subject,payload,digest,created_at) VALUES($1,$2,$3,$4,$5,$6)`, eventID, session.result.ID, subject, intent.PayloadCopy(), digest[:], time.Now().UTC())
	count(ctx, 1, 1, 0, 1)
	return err
}

// WS-07 owns payload validity. Routing additionally binds the closed producer
// source/type/resource combination; a Project resource is not a project event.
func outboxRoute(payload []byte) (id, resourceID, subject string, err error) {
	var event struct {
		ID, Source, Type string
		Data             struct{ Resource authorization.ResourceRef }
	}
	if json.Unmarshal(payload, &event) != nil || !identity.ValidID(event.ID) || !identity.ValidID(event.Data.Resource.ID) {
		return "", "", "", authorization.ErrDenied
	}
	if event.Type == audit.EffectEventType {
		id, resourceID, err = audit.DecodeEffectEvent(payload)
		return id, resourceID, audit.EffectEventSubject, err
	}
	switch {
	case event.Source == "urn:stead:producer:organization" && ((event.Type == "stead.organization.created.v1" && event.Data.Resource.Kind == "organization") || (event.Type == "stead.team.created.v1" && event.Data.Resource.Kind == "team")):
		subject = "stead.organization.changed.v1"
	case event.Source == "urn:stead:producer:project" && event.Type == "stead.project.created.v1" && event.Data.Resource.Kind == "project":
		subject = "stead.project.changed.v1"
	default:
		return "", "", "", authorization.ErrDenied
	}
	return event.ID, event.Data.Resource.ID, subject, nil
}
