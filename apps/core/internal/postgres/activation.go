package postgres

import (
	"context"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/jackc/pgx/v5"
)

// CheckActivation is an owner-scoped readiness input. It verifies the database
// copy only; the executable separately verifies the signed artifact, retained
// host anchor and actual OpenFGA model. No login/session is needed for health.
func (store *Store) CheckActivation(ctx context.Context, expected authorization.ActivationBinding) error {
	if expected.InstallationID != store.config.InstanceID || expected.DeploymentPolicyID != store.config.SecurityDomain || expected.OpenFGAStoreID != store.config.OpenFGAStoreID {
		return authorization.ErrDenied
	}
	return store.owned(ctx, "authorization", false, func(tx pgx.Tx) error {
		state, err := loadNamespace(ctx, tx, false)
		if err != nil || state.ActivationDigest != expected.Digest() || state.InstanceID != expected.InstallationID || state.SecurityDomain != expected.DeploymentPolicyID || state.OpenFGAModelID != expected.OpenFGAModelID || state.ActivationSetID != expected.ActivationSetID || state.ActivationSequence != expected.ActivationSequence || state.PolicyTimeHighWater.IsZero() || state.PolicyTimeRevision == 0 {
			return authorization.ErrDenied
		}
		r := state.Revisions
		for _, value := range []uint64{r.Principal, r.Authority, r.Attributes, r.Groups, r.TeamBindings, r.Tuples, r.Session, r.Delegation, r.Task, r.Runtime, r.Capability, r.Resource, r.Label, r.ExplicitDeny, r.Provider, r.Revocation} {
			if value == 0 {
				return authorization.ErrDenied
			}
		}
		return nil
	})
}
