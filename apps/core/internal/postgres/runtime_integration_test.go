package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/internal/telemetry"
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
	// The opt-in harness owns a fresh isolated cluster. The fixed database also
	// exercises the actual startup catalog diagnostic; an existing DB fails the
	// CREATE below rather than being overwritten or removed.
	database := "stead"
	if _, err = conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	config.Database = database
	adminDSN := testDSN(config.User, config.Password, database)
	if err = CheckFreshBootstrapDatabase(ctx, adminDSN, database); err != nil {
		t.Fatal("pristine isolated database rejected", err)
	}
	t.Run("fresh_bootstrap_preflight", func(t *testing.T) { testFreshBootstrap(t, adminDSN, database) })
	runtimePassword := strings.Repeat("a7", 32)
	token, digest, err := identity.NewLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	binding := authorization.ActivationBinding{InstallationID: instance, ActivationSetID: "test-only-activation", OpenFGAModelID: "test-only-model", OpenFGAStoreID: "test-only-store", ActivationSequence: 1, DeploymentPolicyID: "test-only-domain"}
	anchor := &databaseTestAnchor{state: authorization.AnchorState{Binding: binding, PolicyTimeHighWater: now, PolicyTimeRevision: 1}}
	session := identity.SessionRecord{ID: sessionID, Principal: identity.Principal{Type: "user", ID: principal}, InstanceID: instance, SecurityDomain: binding.DeploymentPolicyID, Authority: "stead_local_identity", AuthenticationStrength: "local_bootstrap", NetworkZone: "loopback", DeviceTrust: "local", Environment: "local-development", ClassificationCeilings: map[string]string{"local": "internal"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Revision: 1, PrincipalRevision: 1, Active: true, PrincipalActive: true}
	unprivileged := session
	unprivileged.ID, _ = NewID()
	unprivileged.Principal.ID, _ = NewID()
	unprivilegedToken, unprivilegedDigest, err := identity.NewLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := BootstrapConfig{AdminDSN: adminDSN, AppPassword: runtimePassword, InstanceID: instance, SecurityDomain: binding.DeploymentPolicyID, OpenFGAStoreID: binding.OpenFGAStoreID, ActivationBinding: binding, PolicyTimeHighWater: now, PolicyTimeRevision: 1, LabelID: labelID, Label: classification.Label{ProfileID: "local", SensitivityLevel: "internal", Version: 1}, Session: session, TokenDigest: digest, UnprivilegedSession: unprivileged, UnprivilegedTokenDigest: unprivilegedDigest}
	t.Run("two_user_bootstrap_rollback", func(t *testing.T) {
		// This is a storage failure fixture, not policy authority: PostgreSQL's
		// signed bigint cannot encode this value in the namespace INSERT, which
		// follows both User/session inserts in the same initializer transaction.
		failed := bootstrap
		failed.PolicyTimeRevision = ^uint64(0)
		if _, err := Bootstrap(ctx, failed); err == nil {
			t.Fatal("late namespace storage failure accepted")
		}
		if err := CheckFreshBootstrapDatabase(ctx, adminDSN, database); err != nil {
			t.Fatal("failed two-user initializer left database material", err)
		}
		var roles int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_roles WHERE left(rolname,length($1))=$1`, "sd_"+DeploymentKey(instance)+"_").Scan(&roles); err != nil || roles != 0 {
			t.Fatal("failed two-user initializer retained roles")
		}
	})
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
	if err = store.CheckActivation(ctx, binding); err != nil {
		t.Fatal("initial activation readiness rejected", err)
	}
	wrongBinding := binding
	wrongBinding.ActivationSequence++
	if err = store.CheckActivation(ctx, wrongBinding); err == nil {
		t.Fatal("stale/mismatched activation passed readiness")
	}
	if err = store.owned(ctx, "authorization", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE "authorization".namespace SET revisions=jsonb_set(revisions,'{Authority}','0') WHERE id`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.CheckActivation(ctx, binding); err == nil {
		t.Fatal("zero unknown namespace revision passed readiness")
	}
	if err = store.owned(ctx, "authorization", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE "authorization".namespace SET revisions=jsonb_set(revisions,'{Authority}','1') WHERE id`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = CheckFreshBootstrapDatabase(ctx, adminDSN, database); err == nil {
		t.Fatal("initialized database passed fresh preflight")
	}
	if err = store.owned(ctx, "audit", false, func(tx pgx.Tx) error {
		var records int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit.records WHERE action='identity.bootstrap' AND resource_id=$1 AND evidence->'unprivileged_principal'->>'id'=$2 AND evidence->>'unprivileged_session_id'=$3 AND evidence->>'session_id'=$4`, instance, unprivileged.Principal.ID, unprivileged.ID, session.ID).Scan(&records); err != nil || records != 1 {
			return errors.New("atomic bootstrap audit absent or duplicated")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.owned(ctx, "identity", false, func(tx pgx.Tx) error {
		var principals, sessions int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity.principals WHERE kind='user' AND active`).Scan(&principals); err != nil || principals != 2 {
			return errors.New("fixed two-user bootstrap absent or duplicated")
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity.sessions WHERE active AND NOT bootstrap_consumed`).Scan(&sessions); err != nil || sessions != 2 {
			return errors.New("fixed two-session bootstrap absent or already consumed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	authentication, err := identity.NewLocalAuthenticator(store, instance, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authentication.Authenticate(ctx, token); err != nil {
		t.Fatal("real SQL bootstrap authentication failed", err)
	}
	unprivilegedAuthenticated, err := authentication.Authenticate(ctx, unprivilegedToken)
	if err != nil || unprivilegedAuthenticated.Principal() != unprivileged.Principal || unprivilegedAuthenticated.SessionID() != unprivileged.ID {
		t.Fatal("real second-user authentication failed")
	}
	if changed, err := store.RotateSessionToken(ctx, unprivileged.ID, unprivilegedDigest, digest); err == nil || changed {
		t.Fatal("second-user exchange collided with primary credential")
	}
	if _, err := authentication.Authenticate(ctx, unprivilegedToken); err != nil {
		t.Fatal("rejected credential collision changed second-user session")
	}
	unprivilegedReplacement, unprivilegedReplacementDigest, _ := identity.NewLocalToken()
	if changed, err := store.RotateSessionToken(ctx, unprivileged.ID, unprivilegedDigest, unprivilegedReplacementDigest); err != nil || !changed {
		t.Fatal("second-user one-time exchange failed")
	}
	if changed, err := store.RotateSessionToken(ctx, unprivileged.ID, unprivilegedDigest, unprivilegedReplacementDigest); err != nil || changed {
		t.Fatal("second-user bootstrap credential replay accepted")
	}
	if _, err := authentication.Authenticate(ctx, unprivilegedToken); err == nil {
		t.Fatal("consumed second-user bootstrap token authenticated")
	}
	if replacement, err := authentication.Authenticate(ctx, unprivilegedReplacement); err != nil || replacement.Principal() != unprivileged.Principal {
		t.Fatal("second-user rotated session did not retain its own identity")
	}
	if primary, err := authentication.Authenticate(ctx, token); err != nil || primary.Principal() != session.Principal {
		t.Fatal("second-user exchange changed the primary credential")
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
	t.Run("real_keyset_candidate_pages", func(t *testing.T) { testCandidatePages(t, store) })
	t.Run("bounded_set_security_reads", func(t *testing.T) { testStateSets(t, store, session, labelID) })
	t.Run("real_effect_storage_not_provider_authorization", func(t *testing.T) { testEffectStorage(t, store, unprivileged) })
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
	if err = CheckExistingBootstrapCatalog(ctx, adminDSN, instance); err != nil {
		t.Fatal("actual startup catalog rejected unchanged owned database", err)
	}
	otherInstallation, _ := NewID()
	if err = CheckExistingBootstrapCatalog(ctx, adminDSN, otherInstallation); err == nil {
		t.Fatal("startup catalog accepted different installation")
	}
	if _, err = db.Exec(ctx, `GRANT SELECT ON audit.records TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if err = CheckExistingBootstrapCatalog(ctx, adminDSN, instance); err == nil {
		t.Fatal("startup catalog accepted actual public ACL drift")
	}
	if _, err = db.Exec(ctx, `REVOKE SELECT ON audit.records FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if err = CheckExistingBootstrapCatalog(ctx, adminDSN, instance); err != nil {
		t.Fatal("startup catalog failed after restoring exact ACL", err)
	}
	t.Log("transient-admin startup catalog: unchanged exact database accepted; wrong installation and actual public ACL drift denied; restored ACL accepted")
	t.Logf("LIVE PostgreSQL %d: SCRAM, runtime NOINHERIT owner isolation, token one-use/revocation, commit+rollback+outbox and complete catalog PASS", serverVersion)
}

func testFreshBootstrap(t *testing.T, adminDSN, database string) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if err = CheckFreshBootstrapDatabase(ctx, adminDSN, database); err == nil {
		t.Fatal("another live client did not block bootstrap preflight")
	}
	if err = checkFreshDatabase(ctx, conn, database); err != nil {
		t.Fatal("sole client pristine database rejected", err)
	}
	for _, query := range []string{
		`CREATE SCHEMA used`, `CREATE TABLE public.used(id integer)`,
		`CREATE SEQUENCE public.used`, `CREATE TYPE public.used AS ENUM ('existing')`,
		`CREATE FUNCTION public.used() RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT 1'`,
		`ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC`,
		`SELECT lo_create(0)`, `DROP EXTENSION plpgsql`,
	} {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, query); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("freshness fixture failed", err)
		}
		if err = checkFreshDatabase(ctx, tx, database); err == nil {
			_ = tx.Rollback(ctx)
			t.Fatal("existing database material accepted", query)
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err = checkFreshDatabase(ctx, conn, database); err != nil {
			t.Fatal("fixture rollback did not restore freshness", err)
		}
	}
	t.Log("pristine database accepted; existing schema/table/sequence/type/function/default ACL/large object/extension changes and other clients denied")
}

func testStateSets(t *testing.T, store *Store, session identity.SessionRecord, labelID string) {
	ctx := context.Background()
	org, _ := NewID()
	refs := make([]authorization.ResourceRef, 100)
	for index := range refs {
		id, _ := NewID()
		refs[index] = authorization.ResourceRef{Kind: "team", ID: id}
	}
	if err := store.owned(ctx, "organization", true, func(tx pgx.Tx) error {
		for _, ref := range refs {
			if _, err := tx.Exec(ctx, `INSERT INTO organization.teams(id,organization_id,key,depth,record) VALUES($1,$2,$3,0,'{}')`, ref.ID, org, ref.ID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.owned(ctx, "authorization", true, func(tx pgx.Tx) error {
		for _, ref := range refs {
			if _, err := tx.Exec(ctx, `INSERT INTO "authorization".resources(id,kind,organization_id,label_id,pending,revision,tuple_revision) VALUES($1,'team',$2,$3,false,1,1)`, ref.ID, org, labelID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	measured, counters := telemetry.Begin(ctx)
	states, err := store.ReadStates(measured, session.Principal, session.ID, refs)
	if err != nil || len(states) != len(refs) {
		t.Fatal("real set state read failed", err)
	}
	if queries := counters.Snapshot().SQLQueries; queries != 17 {
		t.Fatal("100-resource security set did not use fixed 17 statements including transaction/role controls", queries)
	}
	for index, state := range states {
		if state.Resource != refs[index] || state.OrganizationID != org || state.SessionActive || state.Revisions.Session != 3 || state.Label.Version != 1 {
			t.Fatal("batch reordered, omitted or changed authoritative state", index)
		}
	}
	one, err := store.ReadState(ctx, session.Principal, session.ID, refs[0])
	if err != nil || !reflect.DeepEqual(one, states[0]) {
		t.Fatal("set and single authoritative state disagree", err)
	}
	missing, _ := NewID()
	withMissing := append(append([]authorization.ResourceRef(nil), refs...), authorization.ResourceRef{Kind: "team", ID: missing})
	read, err := store.ReadStates(ctx, session.Principal, session.ID, withMissing)
	if err != nil || len(read) != 101 || !reflect.DeepEqual(read[100], authorization.State{Resource: withMissing[100]}) {
		t.Fatal("missing resource was not an aligned closed denial", err)
	}
	// The same set loader is exercised under one actual locked final-fence
	// transaction, without minting fake central decisions or response permits.
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	locked, err := store.readStates(ctx, session.Principal, session.ID, refs, true, func(owner string, read func(pgx.Tx) error) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{store.prefix + owner + "_execute"}.Sanitize()); err != nil {
			return err
		}
		return read(tx)
	})
	if err != nil || !reflect.DeepEqual(locked, states) {
		t.Fatal("locked aggregate state differs", err)
	}
	t.Log("100 resources: 17 actual SQL statements; aligned missing-resource denial and locked aggregate state PASS")
}

func testCandidatePages(t *testing.T, store *Store) {
	ctx := context.Background()
	org, _ := NewID()
	teamIDs := []string{}
	for index := 0; index < 105; index++ {
		id, _ := NewID()
		teamIDs = append(teamIDs, id)
	}
	slices.Sort(teamIDs)
	if err := store.owned(ctx, "organization", true, func(tx pgx.Tx) error {
		for _, id := range teamIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO organization.teams(id,organization_id,key,depth,record) VALUES($1,$2,$3,0,'{}')`, id, org, id); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	first, err := store.ListTeamPageIDs(ctx, org, "", 100)
	if err != nil || !slices.Equal(first, teamIDs[:100]) {
		t.Fatal("first real keyset chunk differs", err)
	}
	second, err := store.ListTeamPageIDs(ctx, org, first[99], 100)
	if err != nil || !slices.Equal(second, teamIDs[100:]) {
		t.Fatal("later real keyset rows were starved", err)
	}
	empty, err := store.ListTeamPageIDs(ctx, store.config.InstanceID, "", 100)
	if err != nil || len(empty) != 0 {
		t.Fatal("candidate scope crossed Organizations")
	}
	if _, err = store.ListTeamPageIDs(ctx, org, "malformed", 100); err == nil {
		t.Fatal("malformed cursor reached SQL")
	}
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
