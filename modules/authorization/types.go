// Package authorization is the central, fail-closed Platform authorization
// boundary. Domain modules consume its decisions and never combine permissions.
package authorization

import (
	"context"
	"errors"
	"time"

	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
)

var ErrDenied = errors.New("operation not permitted")

type Action string

const (
	OrganizationCreate      Action = "organization.create"
	OrganizationRead        Action = "organization.read"
	OrganizationsList       Action = "organization.list"
	TeamCreate              Action = "team.create"
	TeamRead                Action = "team.read"
	ProjectCreate           Action = "project.create"
	ProjectRead             Action = "project.read"
	ProjectBackingProvision Action = "project.backing.provision"
	TeamProfileManage       Action = "team.profile.manage"
	TeamRoleManage          Action = "team.role.manage"
	TeamHierarchyManage     Action = "team.hierarchy.manage"
)

type ResourceRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Revisions are authoritative WS-06 consistency components. Components that
// are not applicable to the local User path still carry their current namespace
// revision; zero is never a fresh or unknown-as-safe revision.
type Revisions struct {
	Principal    uint64
	Authority    uint64
	Attributes   uint64
	Groups       uint64
	TeamBindings uint64
	Tuples       uint64
	Session      uint64
	Delegation   uint64
	Task         uint64
	Runtime      uint64
	Capability   uint64
	Resource     uint64
	Label        uint64
	ExplicitDeny uint64
	Provider     uint64
	Revocation   uint64
}

// State is loaded from owning repository ports, never request JSON. The root
// storage adapter loads the canonical resource through its owner and the
// security vector through WS-06-owned state. Pending tuples deny until an
// acknowledged, verified OpenFGA mutation advances the stable revision.
type State struct {
	Resource            ResourceRef
	InstanceID          string
	OrganizationID      string
	SecurityDomain      string
	Principal           identity.Principal
	SessionID           string
	PrincipalActive     bool
	SessionActive       bool
	SessionPending      bool
	TuplePending        bool
	ExplicitDeny        bool
	ProviderPathAllowed bool
	ActivationSetID     string
	ActivationSequence  uint64
	ActivationDigest    string
	OpenFGAModelID      string
	Revisions           Revisions
	Label               classification.Label
	CapabilityActive    bool
	PolicyTimeHighWater time.Time
	PolicyTimeRevision  uint64
	ContextExpiresAt    time.Time
}

type Repository interface {
	ReadState(context.Context, identity.Principal, string, ResourceRef) (State, error)
}

// SetRepository reads one bounded logical set through authoritative owner
// ports. Results preserve input order; an absent resource is represented only
// by its ResourceRef. Infrastructure or malformed stored state fails the set.
type SetRepository interface {
	ReadStates(context.Context, identity.Principal, string, []ResourceRef) ([]State, error)
}

type ReadAuthorization struct {
	Action Action
	Target ResourceRef
}

// DenialRecorder owns durable reason-safe denial evidence. It may not include
// resource existence, credentials, raw policy inputs, or dependency errors in
// external logs or messages. Successful evidence is committed by the root's
// registered final authorization/domain/outbox transaction.
type DenialRecorder interface {
	RecordDenial(context.Context, Denial) error
}

type Denial struct {
	DecisionID string
	RequestID  string
	Actor      identity.Principal
	Action     Action
	Reason     string
	OccurredAt time.Time
}

// Evidence is a safe copy for the registered final-fence/audit participant. It
// is evidence, never a permit; only its originating Decision can authorize a
// final check. The root must not accept this structure from request bodies.
type Evidence struct {
	DecisionID                       string
	Actor                            identity.Principal
	SessionID                        string
	Action                           Action
	Target                           ResourceRef
	InstanceID                       string
	OrganizationID                   string
	SecurityDomain                   string
	Relation                         string
	OpenFGAModelID                   string
	PolicyBundleID                   string
	ActivationSetID                  string
	ActivationSequence               uint64
	ActivationDigest                 string
	ActivationEpoch                  uint64
	TrustEpoch                       uint64
	DeploymentPolicyID               string
	DeploymentPolicyVersion          string
	DeploymentPolicyDigest           string
	SignedEnvelopeDigest             string
	ArchiveDigest                    string
	ReleaseAttestationID             string
	ReleaseAttestationEnvelopeDigest string
	TrustSetID                       string
	TrustEnvelopeDigest              string
	ModelSourceDigest                string
	EvaluatorContractVersion         string
	Revisions                        Revisions
	PolicyTimeHighWater              time.Time
	PolicyTimeRevision               uint64
	EvaluatedAt                      time.Time
	ExpiresAt                        time.Time
	DisclosureMode                   string
	OpenFGACalls                     uint64
}
