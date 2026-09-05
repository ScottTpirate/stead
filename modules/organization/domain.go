package organization

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
)

var ErrInvalid = errors.New("invalid domain command")
var ErrUnavailable = errors.New("resource unavailable")
var ErrConflict = errors.New("command conflicts with existing state")
var keyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}$`)
var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)

// Resource is the canonical owner record. The BFF adds server-derived OWGP
// presentation; this record grants no permission and contains no provider ID.
type Resource struct {
	ID              string
	Kind            string
	InstanceID      string
	OrganizationID  string
	Key             string
	Title           string
	SecurityLabelID string
	Label           classification.Label
	Version         uint64
	CreatedAt       time.Time
	CreatedBy       identity.Principal
}

type Organization struct {
	Resource
	Name string
}
type Team struct {
	Resource
	Name           string
	ParentTeamID   string
	HierarchyDepth int
}
type Create struct {
	Key            string
	Name           string
	IdempotencyKey string
}
type CreateTeam struct {
	OrganizationID string
	Key            string
	Name           string
	ParentTeamID   string
	IdempotencyKey string
}

func ValidText(value string, max int) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) || len(value) == 0 || len(value) > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func ValidKey(value string) bool            { return keyPattern.MatchString(value) }
func ValidIdempotencyKey(value string) bool { return idempotencyPattern.MatchString(value) }
func (command Create) Validate() error {
	if !ValidIdempotencyKey(command.IdempotencyKey) || !ValidKey(command.Key) || !ValidText(command.Name, 160) {
		return ErrInvalid
	}
	return nil
}
func (command CreateTeam) Validate() error {
	if !ValidIdempotencyKey(command.IdempotencyKey) || !identity.ValidID(command.OrganizationID) || !ValidKey(command.Key) || !ValidText(command.Name, 160) || (command.ParentTeamID != "" && !identity.ValidID(command.ParentTeamID)) {
		return ErrInvalid
	}
	return nil
}

// Repository is implemented by the trusted composition adapter. Commands
// consume sealed central decisions attached to ctx; they accept no pool, SQL,
// role, callback, authorization boolean, or caller-supplied identity.
type Repository interface {
	CreateOrganization(context.Context, Create) (Organization, error)
	CreateTeam(context.Context, CreateTeam) (Team, error)
	GetOrganization(context.Context, string) (Organization, error)
	GetTeam(context.Context, string) (Team, error)
}

// PendingError reports only the operation resource identity. A pending object
// remains unreadable until the exact explicit creator grant is acknowledged.
type PendingError struct{ ResourceID string }

func (*PendingError) Error() string { return "authorization provisioning pending" }
