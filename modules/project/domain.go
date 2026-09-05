package project

import (
	"context"

	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
)

type Capabilities struct {
	Preset string
	Active []string
}
type Project struct {
	organization.Resource
	Purpose             string
	OwningTeamID        string
	ContributingTeamIDs []string
	Capabilities        Capabilities
	LifecycleState      string
}
type Create struct {
	OrganizationID string
	Key            string
	Title          string
	Purpose        string
	OwningTeamID   string
	IdempotencyKey string
}

func (command Create) Validate() error {
	if !organization.ValidIdempotencyKey(command.IdempotencyKey) || !identity.ValidID(command.OrganizationID) || !identity.ValidID(command.OwningTeamID) || !organization.ValidKey(command.Key) || !organization.ValidText(command.Title, 160) || !organization.ValidText(command.Purpose, 2000) {
		return organization.ErrInvalid
	}
	return nil
}

type Repository interface {
	CreateProject(context.Context, Create) (Project, error)
	GetProject(context.Context, string) (Project, error)
}
