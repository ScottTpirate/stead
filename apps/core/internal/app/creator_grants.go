// Package app composes owned repositories and authorization at the executable
// boundary. It contains no signer, bootstrap authority, or SQL executor.
package app

import (
	"context"
	"reflect"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/postgres"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/identity"
)

type CreatorGrantRepository interface {
	PendingCreatorGrant(context.Context, string) (postgres.CreatorGrant, error)
	ActivateCreatorGrant(context.Context, string, *authorization.TupleReceipt) error
}

type CreatorActivator struct {
	repository CreatorGrantRepository
	authorizer *authorization.Coordinator
	openfga    *authorization.OpenFGA
}

func NewCreatorActivator(repository CreatorGrantRepository, authorizer *authorization.Coordinator, openfga *authorization.OpenFGA) (*CreatorActivator, error) {
	if repository == nil || authorizer == nil || openfga == nil {
		return nil, authorization.ErrDenied
	}
	return &CreatorActivator{repository: repository, authorizer: authorizer, openfga: openfga}, nil
}

// Activate is suitable for httpapi.Config.ActivateCreated. The canonical
// resource/audit/outbox transaction has already committed pending state. This
// method performs network I/O only between transactions. Any failure leaves the
// same durable intent recoverable by a same-key retry, with the object hidden.
func (activator *CreatorActivator) Activate(ctx context.Context, session identity.Authenticated, id string) error {
	if activator == nil || activator.repository == nil || activator.authorizer == nil || activator.openfga == nil || !identity.ValidID(id) || !session.ValidAt(time.Now().UTC()) {
		return authorization.ErrDenied
	}
	grant, err := activator.repository.PendingCreatorGrant(ctx, id)
	if err != nil || grant.ResourceID != id {
		return authorization.ErrDenied
	}
	fresh, err := activator.fresh(ctx, session, grant)
	if err != nil {
		return err
	}
	current, err := activator.repository.PendingCreatorGrant(fresh, id)
	if err != nil || !reflect.DeepEqual(grant, current) {
		return authorization.ErrDenied
	}
	if !current.Pending {
		return nil
	} // Never recreate a previously retired grant.
	receipt, err := activator.openfga.WriteVerified(fresh, current.Tuples)
	if err != nil {
		return authorization.ErrDenied
	}
	// Network time consumed the earlier decisions. Reauthorize both the primary
	// target and the exact structural dependency; never prolong an old decision.
	final, err := activator.fresh(ctx, session, current)
	if err != nil {
		return err
	}
	return activator.repository.ActivateCreatorGrant(final, id, receipt)
}

func (activator *CreatorActivator) fresh(ctx context.Context, session identity.Authenticated, grant postgres.CreatorGrant) (context.Context, error) {
	base := authorization.WithoutDecisions(ctx)
	if grant.ResourceID == "" || len(grant.Tuples) == 0 || len(grant.Tuples) > 8 {
		return nil, authorization.ErrDenied
	}
	var related authorization.Action
	switch grant.Action {
	case authorization.OrganizationCreate:
		if grant.Target.Kind != "instance" || grant.Target.ID != session.Context().InstanceID || grant.Related.ID != "" || grant.Related.Kind != "" {
			return nil, authorization.ErrDenied
		}
	case authorization.TeamCreate:
		if grant.Target.Kind != "organization" {
			return nil, authorization.ErrDenied
		}
		related = authorization.TeamHierarchyManage
	case authorization.ProjectCreate:
		if grant.Target.Kind != "organization" || grant.Related.Kind != "team" || !identity.ValidID(grant.Related.ID) {
			return nil, authorization.ErrDenied
		}
		related = authorization.TeamRead
	default:
		return nil, authorization.ErrDenied
	}
	primary, err := activator.authorizer.Authorize(base, session, grant.Action, grant.Target)
	if err != nil {
		return nil, err
	}
	result := primary.WithContext(base)
	if grant.Related.ID != "" {
		if grant.Related.Kind != "team" || !identity.ValidID(grant.Related.ID) {
			return nil, authorization.ErrDenied
		}
		decision, err := activator.authorizer.Authorize(base, session, related, grant.Related)
		if err != nil || decision.Evidence().OrganizationID != grant.Target.ID {
			return nil, authorization.ErrDenied
		}
		result = decision.WithContext(result)
	} else if grant.Related.Kind != "" {
		return nil, authorization.ErrDenied
	}
	return result, nil
}
