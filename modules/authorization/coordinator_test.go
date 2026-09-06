package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
)

const userID = "019ec4e0-0000-7000-8000-000000000002"
const instanceID = "019ec4e0-0000-7000-8000-000000000003"
const orgID = "019ec4e0-0000-7000-8000-000000000004"
const sessionID = "019ec4e0-0000-7000-8000-000000000001"
const modelID = "01ABCDEFGHJKMNPQRSTVWXYZ01"

type testRepo struct {
	session identity.SessionRecord
	state   State
	denials []Denial
	reads   int
}

func (repo *testRepo) LookupSession(context.Context, [sha256.Size]byte) (identity.SessionRecord, error) {
	return repo.session, nil
}
func (repo *testRepo) ReadState(context.Context, identity.Principal, string, ResourceRef) (State, error) {
	repo.reads++
	return repo.state, nil
}
func (repo *testRepo) RecordDenial(_ context.Context, denial Denial) error {
	repo.denials = append(repo.denials, denial)
	return nil
}

type testAnchor struct{ state AnchorState }

func (anchor *testAnchor) Read(context.Context) (AnchorState, error) { return anchor.state, nil }

func bindingFixture() ActivationBinding {
	digest := "sha256:" + strings.Repeat("1", 64)
	return ActivationBinding{InstallationID: instanceID, ActivationSetID: digest, SignedEnvelopeDigest: digest, ArchiveDigest: digest, ReleaseAttestationID: digest, ReleaseAttestationEnvelopeDigest: digest, PolicyBundleID: digest, OpenFGAModelID: modelID, OpenFGAStoreID: modelID, ModelSourceDigest: digest, DeploymentPolicyID: "stead-local-development", DeploymentPolicyVersion: "1.0.0", DeploymentPolicyDigest: digest, DisclosureMode: "request_boundary", AssuranceResultDigest: digest, EvaluatorContractVersion: EvaluatorContractVersion, TrustSetID: digest, TrustEnvelopeDigest: digest, TrustEpoch: 1, ActivationSequence: 1, ActivationEpoch: 1}
}
func coordinatorFixture(t *testing.T, allowed bool) (*Coordinator, *testRepo, identity.Authenticated, *time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	binding := bindingFixture()
	repo := &testRepo{session: identity.SessionRecord{ID: sessionID, Principal: identity.Principal{Type: "user", ID: userID}, InstanceID: instanceID, SecurityDomain: binding.DeploymentPolicyID, Authority: "stead_local_identity", AuthenticationStrength: "local_bootstrap", NetworkZone: "loopback", DeviceTrust: "local", Environment: "local-development", ClassificationCeilings: map[string]string{"commercial": "internal"}, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1, PrincipalRevision: 1, Active: true, PrincipalActive: true}}
	revisions := Revisions{}
	value := reflect.ValueOf(&revisions).Elem()
	for i := 0; i < value.NumField(); i++ {
		value.Field(i).SetUint(1)
	}
	repo.state = State{Resource: ResourceRef{Kind: "organization", ID: orgID}, InstanceID: instanceID, OrganizationID: orgID, SecurityDomain: binding.DeploymentPolicyID, Principal: repo.session.Principal, SessionID: sessionID, PrincipalActive: true, SessionActive: true, ProviderPathAllowed: true, ActivationSetID: binding.ActivationSetID, ActivationSequence: 1, ActivationDigest: binding.Digest(), OpenFGAModelID: modelID, Revisions: revisions, Label: classification.Label{ProfileID: "commercial", SensitivityLevel: "internal", Version: 1}, CapabilityActive: true, PolicyTimeHighWater: now, PolicyTimeRevision: 1, ContextExpiresAt: now.Add(time.Hour)}
	profile, _ := contracts.ReadFile("contract/profile-commercial.json")
	domain, _ := contracts.ReadFile("contract/deployment-local.json")
	evaluator, err := classification.CompileValidatedProfile(profile, domain)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Model       string `json:"authorization_model_id"`
			Tuple       Tuple  `json:"tuple_key"`
			Consistency string `json:"consistency"`
		}
		if json.NewDecoder(request.Body).Decode(&body) != nil || body.Model != modelID || body.Consistency != "HIGHER_CONSISTENCY" || body.Tuple.Relation == "" {
			t.Error("unbounded or missing actual OpenFGA request binding")
			writer.WriteHeader(400)
			return
		}
		json.NewEncoder(writer).Encode(map[string]bool{"allowed": allowed})
	}))
	t.Cleanup(server.Close)
	fga, err := NewOpenFGA(OpenFGAConfig{URL: server.URL, StoreID: modelID, ModelID: modelID, LocalDevelopment: true})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, _ := identity.NewLocalAuthenticator(repo, instanceID, func() time.Time { return now })
	token, _, _ := identity.NewLocalToken()
	session, err := authenticator.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(Config{Repository: repo, Denials: repo, OpenFGA: fga, Activation: &VerifiedActivation{binding: binding, evaluator: evaluator, issuedAt: now.Add(-time.Hour), expiresAt: now.Add(time.Hour), valid: true}, Anchor: &testAnchor{AnchorState{Binding: binding, PolicyTimeHighWater: now, PolicyTimeRevision: 1}}, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, repo, session, &now
}

func TestCoordinatorActualFreshCallAndFinalFence(t *testing.T) {
	coordinator, repo, session, now := coordinatorFixture(t, true)
	ctx, counters := telemetry.Begin(context.Background())
	decision, err := coordinator.Authorize(ctx, session, OrganizationRead, repo.state.Resource)
	if err != nil {
		t.Fatal(err)
	}
	if counters.Snapshot().OpenFGACalls != 1 || decision.Evidence().DisclosureMode != "request_boundary" {
		t.Fatal("no actual check")
	}
	if err := decision.ValidateFinal(repo.state, *now); err != nil {
		t.Fatal(err)
	}
	presentation := decision.Presentation()
	if presentation.PolicyBundleID != decision.Evidence().PolicyBundleID || presentation.ProfileVersion != "1.0.0" || presentation.Markings[0].Text != "Internal" || !presentation.TextAuthoritative || !presentation.ColorSupplementalOnly {
		t.Fatal("unbound presentation")
	}
	presentation.Markings[0].Text = "unmarked"
	if decision.Presentation().Markings[0].Text != "Internal" {
		t.Fatal("mutable presentation")
	}
	if _, err := coordinator.Authorize(ctx, session, OrganizationRead, repo.state.Resource); err != nil || counters.Snapshot().OpenFGACalls != 2 {
		t.Fatal("decision cache")
	}
	advanced := repo.state
	advanced.PolicyTimeHighWater = now.Add(time.Millisecond)
	advanced.PolicyTimeRevision++
	if decision.ValidateFinal(advanced, *now) != nil {
		t.Fatal("safe time-only advance invalidated activation")
	}
	for i := 0; i < reflect.TypeOf(Revisions{}).NumField(); i++ {
		t.Run(reflect.TypeOf(Revisions{}).Field(i).Name, func(t *testing.T) {
			changed := repo.state
			reflect.ValueOf(&changed.Revisions).Elem().Field(i).SetUint(2)
			if decision.ValidateFinal(changed, *now) != ErrDenied {
				t.Fatal("changed security namespace admitted")
			}
		})
	}
	if decision.ValidateFinal(repo.state, now.Add(2*time.Second)) != ErrDenied {
		t.Fatal("expired response decision accepted")
	}
	changed := repo.state
	changed.TuplePending = true
	if decision.ValidateFinal(changed, *now) != ErrDenied {
		t.Fatal("pending tuple accepted")
	}
	changed = repo.state
	changed.ActivationDigest = "sha256:" + strings.Repeat("2", 64)
	if decision.ValidateFinal(changed, *now) != ErrDenied {
		t.Fatal("mixed activation tuple accepted")
	}
}

func TestCoordinatorNegativeStateAndNoProviderCalls(t *testing.T) {
	mutations := map[string]func(*State){"pending": func(s *State) { s.TuplePending = true }, "inactive": func(s *State) { s.PrincipalActive = false }, "session": func(s *State) { s.SessionActive = false }, "deny": func(s *State) { s.ExplicitDeny = true }, "path": func(s *State) { s.ProviderPathAllowed = false }, "capability": func(s *State) { s.CapabilityActive = false }, "foreign-org": func(s *State) { s.OrganizationID = instanceID }, "model": func(s *State) { s.OpenFGAModelID = "" }, "revision": func(s *State) { s.Revisions.Tuples = 0 }, "policytime": func(s *State) { s.PolicyTimeRevision = 0 }, "expired": func(s *State) { s.ContextExpiresAt = time.Time{} }, "classification": func(s *State) { s.Label.SensitivityLevel = "restricted" }, "compartment": func(s *State) { s.Label.Compartments = []string{"need_to_know"} }}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			coordinator, repo, session, _ := coordinatorFixture(t, true)
			mutate(&repo.state)
			ctx, counters := telemetry.Begin(context.Background())
			if _, err := coordinator.Authorize(ctx, session, OrganizationRead, repo.state.Resource); err != ErrDenied {
				t.Fatal("unsafe state admitted")
			}
			if len(repo.denials) != 1 || counters.Snapshot().ProviderCalls != 0 {
				t.Fatal("denial evidence or provider boundary")
			}
		})
	}
	coordinator, repo, session, _ := coordinatorFixture(t, false)
	if _, err := coordinator.Authorize(context.Background(), session, OrganizationRead, repo.state.Resource); err != ErrDenied || repo.denials[0].Reason != "relationship_denied" {
		t.Fatal("relationship deny ignored")
	}
	if _, err := coordinator.Authorize(context.Background(), session, Action("document.download"), repo.state.Resource); err != ErrDenied {
		t.Fatal("unregistered effect class")
	}
	if _, err := coordinator.Authorize(context.Background(), identity.Authenticated{}, OrganizationRead, repo.state.Resource); err != ErrDenied {
		t.Fatal("bootstrap bypass")
	}
}

func TestClosedJSONRejectsSecurityAmbiguity(t *testing.T) {
	for _, source := range []string{`{"allowed":true,"allowed":false}`, `{"Allowed":true}`, `{"allowed":true,"extra":false}`, `{"allowed":1}`, `{"allowed":true} {}`, "{\"allowed\":true,\"x\":\"\xff\"}"} {
		var result struct {
			Allowed bool `json:"allowed"`
		}
		if decodeClosed([]byte(source), &result) == nil {
			t.Fatalf("accepted %q", source)
		}
	}
}
