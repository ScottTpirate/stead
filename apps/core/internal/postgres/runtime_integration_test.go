package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
	"github.com/jackc/pgx/v5"
)

// This fixture is deliberately not an activation verifier or an authorizing
// Coordinator. It exercises PostgreSQL lifecycle/role/atomicity only; product
// authorization tests must use the signed activation consumer and real FGA.
type databaseTestAnchor struct {
	mutex sync.Mutex
	state authorization.AnchorState
}

func (anchor *databaseTestAnchor) Read(context.Context) (authorization.AnchorState, error) {
	anchor.mutex.Lock()
	defer anchor.mutex.Unlock()
	return anchor.state, nil
}
func (anchor *databaseTestAnchor) CompareMax(_ context.Context, binding authorization.ActivationBinding, now time.Time) (authorization.AnchorState, error) {
	anchor.mutex.Lock()
	defer anchor.mutex.Unlock()
	if binding != anchor.state.Binding {
		return authorization.AnchorState{}, authorization.ErrDenied
	}
	if now.After(anchor.state.PolicyTimeHighWater) {
		anchor.state.PolicyTimeHighWater = now
		anchor.state.PolicyTimeRevision++
	}
	return anchor.state, nil
}

func TestLivePostgresBootstrapRolesSessionAndAtomicity(t *testing.T) {
	if os.Getenv("STEAD_POSTGRES_TEST") != "1" {
		t.Skip("requires isolated approved PostgreSQL; run dev integration harness")
	}
	ctx := context.Background()
	adminPassword := os.Getenv("POSTGRES_PASSWORD")
	if adminPassword == "" {
		t.Fatal("missing disposable test password")
	}
	config, err := pgx.ParseConfig("host=/tmp user=probe_admin dbname=probe_db sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.Password = adminPassword
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("admin connect failed")
	}
	defer conn.Close(ctx)
	instance, _ := NewID()
	principal, _ := NewID()
	sessionID, _ := NewID()
	labelID, _ := NewID()
	database := "stead_" + DeploymentKey(instance)
	if _, err = conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	config.Database = database
	adminDSN := testDSN(config.User, config.Password, database)
	runtimePassword := strings.Repeat("a7", 32)
	token, digest, err := identity.NewLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	binding := authorization.ActivationBinding{ActivationSetID: "test-only-activation", OpenFGAModelID: "test-only-model", OpenFGAStoreID: "test-only-store", ActivationSequence: 1, DeploymentPolicyID: "test-only-domain"}
	anchor := &databaseTestAnchor{state: authorization.AnchorState{Binding: binding, PolicyTimeHighWater: now, PolicyTimeRevision: 1}}
	session := identity.SessionRecord{ID: sessionID, Principal: identity.Principal{Type: "user", ID: principal}, InstanceID: instance, SecurityDomain: binding.DeploymentPolicyID, Authority: "stead_local_identity", AuthenticationStrength: "local_bootstrap", NetworkZone: "loopback", DeviceTrust: "local", Environment: "local-development", ClassificationCeilings: map[string]string{"local": "internal"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Revision: 1, PrincipalRevision: 1, Active: true, PrincipalActive: true}
	bootstrap := BootstrapConfig{AdminDSN: adminDSN, AppPassword: runtimePassword, InstanceID: instance, SecurityDomain: binding.DeploymentPolicyID, OpenFGAStoreID: binding.OpenFGAStoreID, ActivationBinding: binding, PolicyTimeHighWater: now, PolicyTimeRevision: 1, LabelID: labelID, Label: classification.Label{ProfileID: "local", SensitivityLevel: "internal", Version: 1}, Session: session, TokenDigest: digest}
	result, err := Bootstrap(ctx, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if result.RuntimeRole != RuntimeRole(instance) {
		t.Fatal("runtime role mismatch")
	}
	if _, err = Bootstrap(ctx, bootstrap); err == nil {
		t.Fatal("bootstrap overwrote existing state")
	}
	runtimeConfig := config.Copy()
	runtimeConfig.User = result.RuntimeRole
	runtimeConfig.Password = runtimePassword
	store, err := Open(ctx, Config{DSN: testDSN(runtimeConfig.User, runtimeConfig.Password, database), InstanceID: instance, SecurityDomain: binding.DeploymentPolicyID, OpenFGAStoreID: binding.OpenFGAStoreID, Anchor: anchor})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authentication, err := identity.NewLocalAuthenticator(store, instance, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authentication.Authenticate(ctx, token); err != nil {
		t.Fatal("real SQL bootstrap authentication failed", err)
	}
	_, newDigest, _ := identity.NewLocalToken()
	changed, err := store.RotateSessionToken(ctx, sessionID, digest, newDigest)
	if err != nil || !changed {
		t.Fatal("token exchange failed")
	}
	if changed, err = store.RotateSessionToken(ctx, sessionID, digest, newDigest); err != nil || changed {
		t.Fatal("bootstrap token replay accepted")
	}
	if _, err = authentication.Authenticate(ctx, token); err == nil {
		t.Fatal("old bootstrap token still valid")
	}
	if err = store.RevokeSession(ctx, sessionID); err != nil {
		t.Fatal(err)
	}
	record, err := store.LookupSession(ctx, newDigest)
	if err != nil || record.Active || record.Revision != 3 {
		t.Fatal("revoke did not advance canonical session revision")
	}
	// Runtime cannot use a schema-owner role or cross-owner tables, even if an
	// owning repository accidentally submits such a query.
	for _, query := range []string{`SELECT * FROM identity.sessions`, "SET ROLE " + pgx.Identifier{store.prefix + "identity_owner"}.Sanitize(), `SELECT * FROM pg_catalog.pg_authid`} {
		if _, err = store.pool.Exec(ctx, query); err == nil {
			t.Fatal("runtime escaped role boundary")
		}
	}
	err = store.owned(ctx, "organization", false, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, `SELECT * FROM identity.sessions`); return err })
	if err == nil {
		t.Fatal("organization executor read identity owner table")
	}
	if _, err = store.CreateOrganization(ctx, organization.Create{Key: "NO", Name: "No bypass", IdempotencyKey: "no-bypass-001"}); err == nil {
		t.Fatal("unsealed create accepted")
	}
	t.Run("real_transaction_commit_rollback_outbox", func(t *testing.T) { testAtomicBackend(t, store) })
	var serverVersion int
	var grantor string
	db, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	if err = db.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer,current_user`).Scan(&serverVersion, &grantor); err != nil {
		t.Fatal(err)
	}
	manifest := RuntimeManifest(instance, database, grantor, serverVersion)
	if err = ValidateManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if err = CheckBootstrapCatalog(ctx, adminDSN, manifest); err != nil {
		if conformance, ok := err.(*ConformanceError); ok {
			t.Logf("catalog violations: %+v", conformance.Violations())
		}
		t.Fatal(err)
	}
	t.Logf("LIVE PostgreSQL %d: SCRAM, runtime NOINHERIT owner isolation, token one-use/revocation, commit+rollback+outbox and complete catalog PASS", serverVersion)
}

func testDSN(user, password, database string) string {
	value := url.URL{Scheme: "postgresql", User: url.UserPassword(user, password), Path: "/" + database, RawQuery: url.Values{"host": []string{"/tmp"}, "sslmode": []string{"disable"}}.Encode()}
	return value.String()
}

func testAtomicBackend(t *testing.T, store *Store) {
	ctx := context.Background()
	contract, _ := transaction.NewBackendContract(store)
	type input struct {
		ID   string
		Fail bool
	}
	operation, err := transaction.NewBackendOperation(contract, "organization", func(ctx context.Context, binding transaction.ExecutorBinding, value input) error {
		session, err := store.session(binding)
		if err != nil {
			return err
		}
		if err = session.role(ctx, "organization"); err != nil {
			return err
		}
		_, err = session.tx.Exec(ctx, `INSERT INTO organization.organizations(id,key,record) VALUES($1,$2,'{}')`, value.ID, value.ID)
		if err != nil {
			return err
		}
		session.result.ID = value.ID
		if value.Fail {
			return errors.New("injected owner failure")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	registered, _ := transaction.NewRegisteredOperation(operation, func(ctx context.Context, port transaction.OperationPort[input], _ input) error {
		return port.Execute(ctx)
	})
	template, planContract, err := transaction.NewPlanContract(transaction.ContractVersionV1, "postgres.live.atomic.v1", []transaction.TypedParticipant[input]{{Key: "organization", DeclaresWrite: true, Operation: registered}}, transaction.OutboxRequired)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := transaction.NewRegistry([]transaction.PlanTemplate{template})
	appender, _ := transaction.NewStorageOutbox(contract, func(ctx context.Context, binding transaction.ExecutorBinding, intent outbox.ValidatedIntent) error {
		session, err := store.session(binding)
		if err != nil {
			return err
		}
		if err = session.role(ctx, "core_outbox"); err != nil {
			return err
		}
		digest := sha256.Sum256(intent.PayloadCopy())
		_, err = session.tx.Exec(ctx, `INSERT INTO core_outbox.intents(id,resource_id,subject,payload,digest,created_at) VALUES($1,$1,'test-only',$2,$3,now())`, session.result.ID, intent.PayloadCopy(), digest[:])
		return err
	})
	coordinator, err := transaction.NewCoordinator(transaction.Configuration{Backend: contract, Registry: registry, Outbox: appender})
	if err != nil {
		t.Fatal(err)
	}
	for _, fail := range []bool{false, true} {
		id, _ := NewID()
		intent, _ := outbox.NewValidationAuthority().WrapValidated(outbox.ValidatedIntentHandoffV1, []byte(`{"test_only":true}`))
		plan, err := planContract.Bind(registry, input{ID: id, Fail: fail}, &intent)
		if err != nil {
			t.Fatal(err)
		}
		_, err = coordinator.Execute(ctx, plan)
		if (err != nil) != fail {
			t.Fatal("unexpected atomic result", err)
		}
		for _, owner := range []string{"organization", "core_outbox"} {
			var count int
			err := store.owned(ctx, owner, false, func(tx pgx.Tx) error {
				table := "organization.organizations"
				if owner == "core_outbox" {
					table = "core_outbox.intents"
				}
				return tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE id=$1`, id).Scan(&count)
			})
			want := 1
			if fail {
				want = 0
			}
			if err != nil || count != want {
				t.Fatal("transaction/outbox atomicity failed", owner, count, err)
			}
		}
	}
}
