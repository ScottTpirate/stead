package gitea

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/identity"
)

// This is an inactive, operation-specific compatibility contract, not approval
// of a deployed provider or a release dependency. The composition root must
// verify its installation against the exact reviewed upstream before use.
const hiddenTrackerProfile = "gitea-private-loopback-hidden-tracker-v1"
const hiddenTrackerContract = `{"version":1,"upstream":"cf0f4dce72a8799e8afe5307be7470caf6936dba","backend_sha256":"baa9f7f8d3acd4e92e9e009d4e1356377a4371074a16d207a92b309f907eec68","operation":"create_hidden_tracker","method":"POST","path":"/api/v1/user/repos","private":true,"auto_init":true,"default_branch":"main","readme":"Default","response":201,"redirects":0,"retries":0,"verification_reads":0}`

// HiddenTrackerAdapter has one exported I/O operation, which requires a real
// WS-06 consumed execution and this adapter's sealed plan. It does not load
// credentials, expose the raw client, select policy, or activate provider use.
type HiddenTrackerAdapter struct{ state *hiddenTrackerAdapter }
type hiddenTrackerAdapter struct {
	client         *client
	installationID string
}

func (HiddenTrackerAdapter) String() string     { return "gitea.hidden-tracker-adapter[private]" }
func (a HiddenTrackerAdapter) GoString() string { return a.String() }

// NewHiddenTrackerAdapter performs no I/O. The trusted composition root supplies
// protected installation configuration, never values decoded from a BFF request.
// It admits only the existing bounded private-loopback transport profile.
func NewHiddenTrackerAdapter(origin, owner, token, installationID string) (*HiddenTrackerAdapter, error) {
	if !identity.ValidID(installationID) {
		return nil, failure(NotDispatched)
	}
	c, err := newClient(origin, owner, token)
	if err != nil {
		return nil, err
	}
	return &HiddenTrackerAdapter{&hiddenTrackerAdapter{c, installationID}}, nil
}

// HiddenTrackerIntent is a canonical owner input, not authorization. There is no
// caller-selected repository name, provider path, body, operation or profile.
// WS-06 separately binds these IDs/lifetimes to its fresh Project decision.
type HiddenTrackerIntent struct {
	EffectID, OperationID, PlanID, RequestID string
	Project                                  authorization.ResourceRef
	ProviderRevision                         uint64
	OriginalDeadline, ProviderNotAfter       time.Time
}

func (HiddenTrackerIntent) String() string     { return "gitea.hidden-tracker-intent[private]" }
func (i HiddenTrackerIntent) GoString() string { return i.String() }

// HiddenTrackerPlan is protected WS-03 state. A copy preserves the same sealed
// plan. Its Binding is persistence/authorization input, never a permit. There
// is deliberately no unmarshal, restore-as-authority, raw payload or locator API.
type HiddenTrackerPlan struct{ state *hiddenTrackerPlan }
type hiddenTrackerPlan struct {
	adapter *hiddenTrackerAdapter
	binding authorization.EffectBinding
	name    string
}

func (HiddenTrackerPlan) String() string     { return "gitea.hidden-tracker-plan[private]" }
func (p HiddenTrackerPlan) GoString() string { return p.String() }
func (p HiddenTrackerPlan) Binding() authorization.EffectBinding {
	if p.state == nil {
		return authorization.EffectBinding{}
	}
	return p.state.binding
}

func trackerDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// PlanHiddenTracker constructs the exact protected plan without any provider
// call. The owner must durably store it with the operation before dispatch; a
// digest alone is not a recoverable plan or a provider idempotency guarantee.
func (a *HiddenTrackerAdapter) PlanHiddenTracker(intent HiddenTrackerIntent) (*HiddenTrackerPlan, error) {
	if a == nil || a.state == nil || a.state.client == nil || !identity.ValidID(intent.EffectID) ||
		!identity.ValidID(intent.OperationID) || !identity.ValidID(intent.PlanID) || !hexOK(intent.RequestID, 32) ||
		intent.Project.Kind != "project" || !identity.ValidID(intent.Project.ID) || intent.ProviderRevision == 0 ||
		intent.OriginalDeadline.IsZero() || intent.ProviderNotAfter.IsZero() {
		return nil, failure(NotDispatched)
	}
	name := "stead-tracker-" + intent.Project.ID
	binding := authorization.EffectBinding{EffectID: intent.EffectID, OperationID: intent.OperationID, PlanID: intent.PlanID,
		RequestID: intent.RequestID, Project: intent.Project, ProviderInstallationID: a.state.installationID,
		CompatibilityProfileID: hiddenTrackerProfile, CompatibilityProfileDigest: trackerDigest([]byte(hiddenTrackerContract)),
		ProviderRevision: intent.ProviderRevision, OriginalDeadline: intent.OriginalDeadline.UTC(), ProviderNotAfter: intent.ProviderNotAfter.UTC()}
	// JSON of a closed struct supplies an unambiguous length/framing boundary.
	// Include the exact serialized input, target, operation, all identity/revision
	// bindings and profile, but never a credential or content-derived log field.
	payload, err := json.Marshal(repositoryCreateInput(name))
	if err != nil {
		return nil, failure(NotDispatched)
	}
	encoded, err := json.Marshal(struct {
		Version   uint8
		Operation string
		Origin    string
		Owner     string
		Method    string
		Path      string
		Input     string
		Binding   authorization.EffectBinding
	}{1, authorization.CreateHiddenTracker, a.state.client.origin, a.state.client.owner, "POST", "/api/v1/user/repos", string(payload), binding})
	if err != nil {
		return nil, failure(NotDispatched)
	}
	binding.PlanDigest = trackerDigest(encoded)
	return &HiddenTrackerPlan{&hiddenTrackerPlan{a.state, binding, name}}, nil
}

// HiddenTrackerPending keeps a successful adapter response private. It is NOT
// terminal proof, a disclosed/canonical Repository, or a ready Project backing.
// There is intentionally no exported success/proof/getter/persistence receipt:
// the next owner integration must verify exact provider proof and final fences
// before its atomic protected mapping plus WS-02 canonical/outbox transaction.
type HiddenTrackerPending struct{ state *hiddenTrackerPending }
type hiddenTrackerPending struct {
	plan       *hiddenTrackerPlan
	execution  *authorization.EffectExecution
	repository Repository
}

func (HiddenTrackerPending) String() string     { return "gitea.hidden-tracker-pending[private]" }
func (p HiddenTrackerPending) GoString() string { return p.String() }

// CreateHiddenTracker invokes exactly one existing repository mutation inside
// the consumed handle. No caller binding/receipt/callback is accepted. A failed
// or canceled attempt remains reconciling through WS-06; this method never
// retries or spends the mutation handle on a verification GET. A deterministic
// name is NOT provider-authenticated immutable uniqueness or safe replay proof.
func (a *HiddenTrackerAdapter) CreateHiddenTracker(plan *HiddenTrackerPlan, execution *authorization.EffectExecution) (*HiddenTrackerPending, error) {
	if a == nil || a.state == nil || plan == nil || plan.state == nil || plan.state.adapter != a.state || execution == nil {
		return nil, failure(NotDispatched)
	}
	var result Repository
	attempted := false
	err := execution.Run(plan.state.binding, func(ctx context.Context) error {
		attempted = true
		var err error
		result, err = a.state.client.createRepository(ctx, plan.state.name)
		return err
	})
	if err != nil || execution.SuppressionRequired() {
		if attempted {
			return nil, failure(Uncertain)
		}
		return nil, failure(NotDispatched)
	}
	return &HiddenTrackerPending{&hiddenTrackerPending{plan.state, execution, result}}, nil
}
