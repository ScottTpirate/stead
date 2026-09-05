package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/jackc/pgx/v5"
)

// BootstrapConfig is exclusively for the dev-bootstrap executable. AdminDSN
// must never be passed to the long-running application. ActivationBinding is
// the complete independently verified ADR-0006 binding supplied by WS-06.
type BootstrapConfig struct {
	AdminDSN, AppPassword, InstanceID, SecurityDomain, OpenFGAStoreID string
	ActivationBinding                                                 authorization.ActivationBinding
	PolicyTimeHighWater                                               time.Time
	PolicyTimeRevision                                                uint64
	LabelID                                                           string
	Label                                                             classification.Label
	Session                                                           identity.SessionRecord
	TokenDigest                                                       [sha256.Size]byte
}
type BootstrapResult struct {
	RuntimeRole, DatabaseName, ActivationDigest string
	Manifest                                    Manifest
}

var schemaTables = map[string]map[string]string{
	"identity": {
		"principals": `id uuid PRIMARY KEY, kind text NOT NULL CHECK(kind='user'), active boolean NOT NULL, revision bigint NOT NULL CHECK(revision>0)`,
		"sessions":   `id uuid PRIMARY KEY, token_digest bytea NOT NULL UNIQUE CHECK(octet_length(token_digest)=32), principal_id uuid NOT NULL, record jsonb NOT NULL, active boolean NOT NULL, revision bigint NOT NULL CHECK(revision>0), bootstrap_consumed boolean NOT NULL DEFAULT false`,
	},
	"classification": {"labels": `id uuid PRIMARY KEY, value jsonb NOT NULL, revision bigint NOT NULL CHECK(revision>0)`},
	"authorization": {
		"namespace":      `id boolean PRIMARY KEY CHECK(id), instance_id uuid NOT NULL, security_domain text NOT NULL, store_id text NOT NULL, activation_id text NOT NULL, activation_sequence bigint NOT NULL CHECK(activation_sequence>0), model_id text NOT NULL, activation_binding jsonb NOT NULL, activation_digest text NOT NULL, revisions jsonb NOT NULL, policy_time timestamptz NOT NULL, policy_revision bigint NOT NULL CHECK(policy_revision>0)`,
		"resources":      `id uuid PRIMARY KEY, kind text NOT NULL, organization_id uuid, label_id uuid NOT NULL, pending boolean NOT NULL, explicit_deny boolean NOT NULL DEFAULT false, provider_allowed boolean NOT NULL DEFAULT true, capability_active boolean NOT NULL DEFAULT true, revision bigint NOT NULL CHECK(revision>0), tuple_revision bigint NOT NULL CHECK(tuple_revision>0)`,
		"requests":       `actor text NOT NULL, action text NOT NULL, key text NOT NULL, input_hash bytea NOT NULL, resource_id uuid NOT NULL, PRIMARY KEY(actor,action,key)`,
		"creator_grants": `resource_id uuid PRIMARY KEY, actor text NOT NULL, action text NOT NULL, target_kind text NOT NULL, target_id uuid NOT NULL, related_kind text NOT NULL, related_id text NOT NULL, tuples jsonb NOT NULL, pending boolean NOT NULL, created_at timestamptz NOT NULL`,
	},
	"organization": {
		"organizations": `id uuid PRIMARY KEY, key text NOT NULL UNIQUE, record jsonb NOT NULL, active boolean NOT NULL DEFAULT true`,
		"teams":         `id uuid PRIMARY KEY, organization_id uuid NOT NULL, key text NOT NULL, parent_id uuid, depth integer NOT NULL CHECK(depth BETWEEN 0 AND 11), record jsonb NOT NULL, active boolean NOT NULL DEFAULT true, UNIQUE(organization_id,key)`,
	},
	"project":     {"projects": `id uuid PRIMARY KEY, organization_id uuid NOT NULL, key text NOT NULL, owning_team_id uuid NOT NULL, record jsonb NOT NULL, active boolean NOT NULL DEFAULT true, UNIQUE(organization_id,key)`},
	"audit":       {"records": `id uuid PRIMARY KEY, resource_id uuid, actor text NOT NULL, action text NOT NULL, decision text NOT NULL, evidence jsonb NOT NULL, occurred_at timestamptz NOT NULL`},
	"core_outbox": {"intents": `id uuid PRIMARY KEY, resource_id uuid NOT NULL, subject text NOT NULL, payload bytea NOT NULL, digest bytea NOT NULL CHECK(octet_length(digest)=32), created_at timestamptz NOT NULL, published_at timestamptz`},
}

func Bootstrap(ctx context.Context, config BootstrapConfig) (BootstrapResult, error) {
	binding := config.ActivationBinding
	if binding.InstallationID != config.InstanceID {
		return BootstrapResult{}, errors.New("bootstrap installation binding mismatch")
	}
	digest := binding.Digest()
	if !identity.ValidID(config.InstanceID) || !identity.ValidID(config.LabelID) || !identity.ValidID(config.Session.ID) || !config.Session.Principal.Valid() || config.Session.Principal.Type != "user" || config.Session.InstanceID != config.InstanceID || config.Session.SecurityDomain != config.SecurityDomain || config.SecurityDomain == "" || config.OpenFGAStoreID == "" || binding.OpenFGAStoreID != config.OpenFGAStoreID || binding.DeploymentPolicyID != config.SecurityDomain || binding.ActivationSetID == "" || binding.ActivationSequence == 0 || binding.OpenFGAModelID == "" || config.PolicyTimeHighWater.IsZero() || config.PolicyTimeRevision == 0 || len(config.AppPassword) < 24 || config.TokenDigest == ([32]byte{}) || config.Label.Version == 0 || config.Label.ProfileID == "" || config.Session.Revision != 1 || config.Session.PrincipalRevision != 1 || !config.Session.Active || !config.Session.PrincipalActive || !config.Session.ExpiresAt.After(time.Now()) {
		return BootstrapResult{}, errors.New("invalid bootstrap configuration")
	}
	conn, err := pgx.Connect(ctx, config.AdminDSN)
	if err != nil {
		return BootstrapResult{}, errors.New("bootstrap database unavailable")
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return BootstrapResult{}, err
	}
	defer tx.Rollback(ctx)
	var database, admin string
	var version int
	if err = tx.QueryRow(ctx, `SELECT current_database(),current_user,current_setting('server_version_num')::integer`).Scan(&database, &admin, &version); err != nil || version < MinimumServerVersion {
		return BootstrapResult{}, errors.New("unsupported bootstrap database")
	}
	prefix := "sd_" + DeploymentKey(config.InstanceID) + "_"
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='authorization')`).Scan(&exists); err != nil {
		return BootstrapResult{}, err
	}
	if exists {
		return BootstrapResult{}, errors.New("database already initialized; bootstrap does not overwrite state")
	}
	execute := func(sql string, args ...any) error { _, err := tx.Exec(ctx, sql, args...); return err }
	role := func(id string, login, inherit bool) error {
		options := " NOLOGIN NOINHERIT"
		if login {
			options = " LOGIN NOINHERIT"
		}
		if inherit {
			options = " NOLOGIN INHERIT"
		}
		if err := execute("CREATE ROLE " + pgx.Identifier{prefix + id}.Sanitize() + options + " NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
			return err
		}
		binding := "stead-role:v1:" + config.InstanceID + ":" + id
		return execute("COMMENT ON ROLE " + pgx.Identifier{prefix + id}.Sanitize() + " IS " + literal(binding))
	}
	if err = role("database_owner", false, false); err != nil {
		return BootstrapResult{}, err
	}
	if err = role("api", true, false); err != nil {
		return BootstrapResult{}, err
	}
	if err = execute("ALTER ROLE " + pgx.Identifier{prefix + "api"}.Sanitize() + " PASSWORD " + literal(config.AppPassword)); err != nil {
		return BootstrapResult{}, errors.New("runtime credential setup failed")
	}
	if err = execute("ALTER ROLE " + pgx.Identifier{prefix + "api"}.Sanitize() + " SET search_path = pg_catalog, pg_temp"); err != nil {
		return BootstrapResult{}, err
	}
	if err = execute("REVOKE ALL ON DATABASE " + pgx.Identifier{database}.Sanitize() + " FROM PUBLIC"); err != nil {
		return BootstrapResult{}, err
	}
	if err = execute("ALTER DATABASE " + pgx.Identifier{database}.Sanitize() + " OWNER TO " + pgx.Identifier{prefix + "database_owner"}.Sanitize()); err != nil {
		return BootstrapResult{}, err
	}
	if err = execute("GRANT CONNECT ON DATABASE " + pgx.Identifier{database}.Sanitize() + " TO " + pgx.Identifier{prefix + "api"}.Sanitize()); err != nil {
		return BootstrapResult{}, err
	}
	if err = execute("REVOKE ALL ON SCHEMA public FROM PUBLIC"); err != nil {
		return BootstrapResult{}, err
	}
	for _, owner := range []string{"identity", "classification", "authorization", "organization", "project", "audit", "core_outbox"} {
		for _, suffix := range []string{"_owner", "_rw", "_execute"} {
			if err = role(owner+suffix, false, suffix == "_execute"); err != nil {
				return BootstrapResult{}, err
			}
		}
		ownerRole, rwRole, execRole := pgx.Identifier{prefix + owner + "_owner"}.Sanitize(), pgx.Identifier{prefix + owner + "_rw"}.Sanitize(), pgx.Identifier{prefix + owner + "_execute"}.Sanitize()
		if err = execute("CREATE SCHEMA " + pgx.Identifier{owner}.Sanitize() + " AUTHORIZATION " + ownerRole); err != nil {
			return BootstrapResult{}, err
		}
		if err = execute("SET LOCAL ROLE " + ownerRole); err != nil {
			return BootstrapResult{}, err
		}
		for _, kind := range []string{"TABLES", "SEQUENCES", "FUNCTIONS", "TYPES"} {
			if err = execute("ALTER DEFAULT PRIVILEGES REVOKE ALL ON " + kind + " FROM PUBLIC"); err != nil {
				return BootstrapResult{}, err
			}
		}
		if err = execute("REVOKE ALL ON SCHEMA " + pgx.Identifier{owner}.Sanitize() + " FROM PUBLIC"); err != nil {
			return BootstrapResult{}, err
		}
		if err = execute("GRANT USAGE ON SCHEMA " + pgx.Identifier{owner}.Sanitize() + " TO " + rwRole); err != nil {
			return BootstrapResult{}, err
		}
		for table, definition := range schemaTables[owner] {
			qualified := pgx.Identifier{owner, table}.Sanitize()
			if err = execute("CREATE TABLE " + qualified + " (" + definition + ")"); err != nil {
				return BootstrapResult{}, err
			}
			privileges := "SELECT, INSERT, UPDATE"
			if owner == "audit" {
				privileges = "SELECT, INSERT"
			}
			if err = execute("GRANT " + privileges + " ON " + qualified + " TO " + rwRole); err != nil {
				return BootstrapResult{}, err
			}
		}
		if err = execute("RESET ROLE"); err != nil {
			return BootstrapResult{}, err
		}
		if err = execute("GRANT " + rwRole + " TO " + execRole + " WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"); err != nil {
			return BootstrapResult{}, err
		}
		if err = execute("GRANT " + execRole + " TO " + pgx.Identifier{prefix + "api"}.Sanitize() + " WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"); err != nil {
			return BootstrapResult{}, err
		}
	}
	// No cross-owner foreign key or trigger: typed participant validation is the
	// only cross-module operation, and every initial row is one atomic bootstrap.
	if err = execute(`INSERT INTO identity.principals VALUES($1,'user',true,1)`, config.Session.Principal.ID); err != nil {
		return BootstrapResult{}, err
	}
	if err = execute(`INSERT INTO identity.sessions(id,token_digest,principal_id,record,active,revision) VALUES($1,$2,$3,$4,true,1)`, config.Session.ID, config.TokenDigest[:], config.Session.Principal.ID, encode(config.Session)); err != nil {
		return BootstrapResult{}, err
	}
	if err = execute(`INSERT INTO classification.labels VALUES($1,$2,1)`, config.LabelID, encode(config.Label)); err != nil {
		return BootstrapResult{}, err
	}
	revisions := `{"Principal":1,"Authority":1,"Attributes":1,"Groups":1,"TeamBindings":1,"Tuples":1,"Session":1,"Delegation":1,"Task":1,"Runtime":1,"Capability":1,"Resource":1,"Label":1,"ExplicitDeny":1,"Provider":1,"Revocation":1}`
	if err = execute(`INSERT INTO "authorization".namespace VALUES(true,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, config.InstanceID, config.SecurityDomain, config.OpenFGAStoreID, binding.ActivationSetID, binding.ActivationSequence, binding.OpenFGAModelID, encode(binding), digest, revisions, config.PolicyTimeHighWater, config.PolicyTimeRevision); err != nil {
		return BootstrapResult{}, err
	}
	if err = execute(`INSERT INTO "authorization".resources(id,kind,label_id,pending,revision,tuple_revision) VALUES($1,'instance',$2,false,1,1)`, config.InstanceID, config.LabelID); err != nil {
		return BootstrapResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return BootstrapResult{}, fmt.Errorf("bootstrap commit failed: %w", err)
	}
	manifest := RuntimeManifest(config.InstanceID, database, admin, version)
	if err = CheckBootstrapCatalog(ctx, config.AdminDSN, manifest); err != nil {
		return BootstrapResult{}, err
	}
	return BootstrapResult{RuntimeRole: prefix + "api", DatabaseName: database, ActivationDigest: digest, Manifest: manifest}, nil
}
func literal(value string) string { return "'" + replaceQuotes(value) + "'" }
func replaceQuotes(value string) string {
	result := ""
	for _, r := range value {
		if r == '\'' {
			result += "''"
		} else {
			result += string(r)
		}
	}
	return result
}
