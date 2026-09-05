package postgres

import (
	"context"
	"database/sql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// RuntimeManifest renders only actual Checkpoint A producers/consumers. It
// does not create or reserve future modules or infer expectations from the DB.
func RuntimeManifest(instance, database, bootstrapGrantor string, serverVersion int) Manifest {
	key := DeploymentKey(instance)
	prefix := "sd_" + key + "_"
	m := Manifest{DeploymentKey: key, InstallationUUID: instance, Databases: []DatabaseSpec{{Name: database, Owner: "database_owner"}}, Principals: []PrincipalSpec{{SemanticID: "bootstrap_grantor", Name: bootstrapGrantor}, {SemanticID: "public_schema_owner", Name: "pg_database_owner"}}, Schemas: []SchemaSpec{{Name: "public", Owner: "public_schema_owner"}}}
	role := func(id string, login, inherit bool) {
		properties := RoleProperties{Login: login, Inherit: inherit, ConnectionLimit: -1, PasswordPresent: login, Configuration: []string{}}
		if login {
			properties.Configuration = []string{"search_path=pg_catalog, pg_temp"}
		}
		m.Roles = append(m.Roles, RoleSpec{SemanticID: id, Name: prefix + id, Binding: "stead-role:v1:" + instance + ":" + id, Properties: properties})
	}
	role("database_owner", false, false)
	role("api", true, false)
	for _, privilege := range []string{"CONNECT", "CREATE", "TEMPORARY"} {
		m.DatabaseACLs = append(m.DatabaseACLs, ACLSpec{Database: database, Grantor: "database_owner", Grantee: "database_owner", Privilege: privilege})
	}
	m.DatabaseACLs = append(m.DatabaseACLs, ACLSpec{Database: database, Grantor: "database_owner", Grantee: "api", Privilege: "CONNECT"})
	for _, privilege := range []string{"CREATE", "USAGE"} {
		m.SchemaACLs = append(m.SchemaACLs, ACLSpec{Schema: "public", Grantor: "public_schema_owner", Grantee: "public_schema_owner", Privilege: privilege})
	}
	tablePrivileges := []string{"DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"}
	if serverVersion >= 170000 {
		tablePrivileges = append(tablePrivileges, "MAINTAIN")
	}
	for _, owner := range []string{"identity", "classification", "authorization", "organization", "project", "audit", "core_outbox"} {
		o, r, x := owner+"_owner", owner+"_rw", owner+"_execute"
		role(o, false, false)
		role(r, false, false)
		role(x, false, true)
		m.Memberships = append(m.Memberships, MembershipSpec{Role: r, Member: x, Grantor: "bootstrap_grantor", InheritOption: true}, MembershipSpec{Role: x, Member: "api", Grantor: "bootstrap_grantor", SetOption: true})
		m.Schemas = append(m.Schemas, SchemaSpec{Name: owner, Owner: o})
		for _, privilege := range []string{"CREATE", "USAGE"} {
			m.SchemaACLs = append(m.SchemaACLs, ACLSpec{Schema: owner, Grantor: o, Grantee: o, Privilege: privilege})
		}
		m.SchemaACLs = append(m.SchemaACLs, ACLSpec{Schema: owner, Grantor: o, Grantee: r, Privilege: "USAGE"})
		for table := range schemaTables[owner] {
			m.Objects = append(m.Objects, ObjectSpec{Schema: owner, Name: table, Kind: "table", Owner: o})
			for _, privilege := range tablePrivileges {
				m.ObjectACLs = append(m.ObjectACLs, ACLSpec{Schema: owner, Object: table, ObjectKind: "table", Grantor: o, Grantee: o, Privilege: privilege})
			}
			for _, privilege := range []string{"SELECT", "INSERT", "UPDATE"} {
				if owner == "audit" && privilege == "UPDATE" {
					continue
				}
				m.ObjectACLs = append(m.ObjectACLs, ACLSpec{Schema: owner, Object: table, ObjectKind: "table", Grantor: o, Grantee: r, Privilege: privilege})
			}
		}
		for kind, privileges := range map[string][]string{"table": tablePrivileges, "sequence": {"SELECT", "UPDATE", "USAGE"}, "routine": {"EXECUTE"}, "type": {"USAGE"}} {
			for _, privilege := range privileges {
				m.DefaultACLs = append(m.DefaultACLs, DefaultACLSpec{Owner: o, ObjectKind: kind, Grantor: o, Grantee: o, Privilege: privilege})
			}
		}
	}
	return m
}

// CheckBootstrapCatalog runs only with the transient bootstrap identity. The
// full registered-password-presence catalog is intentionally unavailable to
// the runtime API role; no security-definer function or broad read grant exists.
func CheckBootstrapCatalog(ctx context.Context, adminDSN string, manifest Manifest) error {
	config, err := pgx.ParseConfig(adminDSN)
	if err != nil {
		return err
	}
	db := sql.OpenDB(stdlib.GetConnector(*config))
	defer db.Close()
	snapshot, err := NewSQLCollector(db).Collect(ctx, manifest)
	if err != nil {
		return err
	}
	return Compare(manifest, snapshot)
}
