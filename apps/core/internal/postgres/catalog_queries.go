package postgres

// QueryContract is a PostgreSQL 16+ catalog projection. Columns and ordering
// are part of the adapter contract. Queries return identifiers as data only;
// callers must never interpolate them into SQL.
type QueryContract struct {
	Name    string
	SQL     string
	Columns []string
	Args    []string
}

// CatalogQueryContracts returns a copy of the complete catalog read plan.
// $1 is the deployment-qualified role prefix (for example sd_<key>_) where
// present. All queries run against the target database in one repeatable-read,
// read-only transaction so the Snapshot represents one catalog point.
func CatalogQueryContracts() []QueryContract {
	contracts := []QueryContract{
		{
			Name:    "server_version",
			SQL:     `SELECT current_setting('server_version_num')::integer AS server_version_num`,
			Columns: []string{"server_version_num"},
		},
		{
			Name: "roles",
			SQL: `SELECT r.rolname,
       COALESCE(shobj_description(r.oid, 'pg_authid'), '') AS identity_binding,
       r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
       r.rolreplication, r.rolbypassrls, r.rolconnlimit,
       r.rolpassword IS NOT NULL AS password_present,
       COALESCE(to_char(r.rolvaliduntil AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '') AS valid_until_utc,
       COALESCE((SELECT json_agg(setting ORDER BY setting COLLATE "C")::text
                 FROM unnest(r.rolconfig) AS configured(setting)), '[]') AS configuration_json
FROM pg_catalog.pg_roles AS r
WHERE left(r.rolname, length($1)) = $1
ORDER BY r.rolname`,
			Columns: []string{"rolname", "identity_binding", "rolsuper", "rolinherit", "rolcreaterole", "rolcreatedb", "rolcanlogin", "rolreplication", "rolbypassrls", "rolconnlimit", "password_present", "valid_until_utc", "configuration_json"},
			Args:    []string{"deployment_role_prefix"},
		},
		{
			Name: "memberships",
			SQL: `SELECT role_role.rolname AS role_name,
       member_role.rolname AS member_name,
       grantor_role.rolname AS grantor_name,
       membership.admin_option,
       membership.inherit_option,
       membership.set_option
FROM pg_catalog.pg_auth_members AS membership
JOIN pg_catalog.pg_roles AS role_role ON role_role.oid = membership.roleid
JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member
JOIN pg_catalog.pg_roles AS grantor_role ON grantor_role.oid = membership.grantor
WHERE left(role_role.rolname, length($1)) = $1
   OR left(member_role.rolname, length($1)) = $1
ORDER BY role_name, member_name, grantor_name, admin_option, inherit_option, set_option`,
			Columns: []string{"role_name", "member_name", "grantor_name", "admin_option", "inherit_option", "set_option"},
			Args:    []string{"deployment_role_prefix"},
		},
		{
			Name: "databases",
			SQL: `SELECT d.datname, owner_role.rolname AS owner_name
FROM pg_catalog.pg_database AS d
JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = d.datdba
WHERE d.datname = current_database()
ORDER BY d.datname`,
			Columns: []string{"datname", "owner_name"},
		},
		{
			Name: "database_acls",
			SQL: `SELECT d.datname,
       grantor_role.rolname AS grantor_name,
       CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee_role.rolname END AS grantee_name,
       acl.privilege_type,
       acl.is_grantable
FROM pg_catalog.pg_database AS d
CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(d.datacl, pg_catalog.acldefault('d', d.datdba))) AS acl
JOIN pg_catalog.pg_roles AS grantor_role ON grantor_role.oid = acl.grantor
LEFT JOIN pg_catalog.pg_roles AS grantee_role ON grantee_role.oid = acl.grantee
WHERE d.datname = current_database()
ORDER BY d.datname, grantor_name, grantee_name, acl.privilege_type, acl.is_grantable`,
			Columns: []string{"datname", "grantor_name", "grantee_name", "privilege_type", "is_grantable"},
		},
		{
			Name: "schemas",
			SQL: `SELECT n.nspname, owner_role.rolname AS owner_name
FROM pg_catalog.pg_namespace AS n
JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = n.nspowner
WHERE n.nspname <> 'information_schema'
  AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY n.nspname`,
			Columns: []string{"nspname", "owner_name"},
		},
		{
			Name: "schema_acls",
			SQL: `SELECT n.nspname,
       grantor_role.rolname AS grantor_name,
       CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee_role.rolname END AS grantee_name,
       acl.privilege_type,
       acl.is_grantable
FROM pg_catalog.pg_namespace AS n
CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) AS acl
JOIN pg_catalog.pg_roles AS grantor_role ON grantor_role.oid = acl.grantor
LEFT JOIN pg_catalog.pg_roles AS grantee_role ON grantee_role.oid = acl.grantee
WHERE n.nspname <> 'information_schema'
  AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY n.nspname, grantor_name, grantee_name, acl.privilege_type, acl.is_grantable`,
			Columns: []string{"nspname", "grantor_name", "grantee_name", "privilege_type", "is_grantable"},
		},
		{
			Name: "objects",
			SQL: `WITH objects AS (
  SELECT n.nspname AS schema_name, c.relname AS object_name,
         CASE c.relkind
           WHEN 'r' THEN 'table' WHEN 'p' THEN 'table' WHEN 'S' THEN 'sequence'
           WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized_view' WHEN 'f' THEN 'foreign_table'
         END AS object_kind,
         c.relowner AS owner_oid
  FROM pg_catalog.pg_class AS c
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
    AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  UNION ALL
  SELECT n.nspname, p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')',
         CASE p.prokind WHEN 'p' THEN 'procedure' WHEN 'a' THEN 'aggregate' ELSE 'function' END,
         p.proowner
  FROM pg_catalog.pg_proc AS p
  JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
  WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  UNION ALL
  SELECT n.nspname, t.typname,
         CASE t.typtype WHEN 'd' THEN 'domain' ELSE 'type' END,
         t.typowner
  FROM pg_catalog.pg_type AS t
  JOIN pg_catalog.pg_namespace AS n ON n.oid = t.typnamespace
  LEFT JOIN pg_catalog.pg_class AS c ON c.oid = t.typrelid
  WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
    AND t.typelem = 0
    AND (t.typtype <> 'c' OR c.relkind = 'c')
)
SELECT objects.schema_name, objects.object_name, objects.object_kind, owner_role.rolname AS owner_name
FROM objects
JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = objects.owner_oid
ORDER BY objects.schema_name, objects.object_kind, objects.object_name`,
			Columns: []string{"schema_name", "object_name", "object_kind", "owner_name"},
		},
		{
			Name: "object_acls",
			SQL: `WITH object_acls AS (
  SELECT n.nspname AS schema_name, c.relname AS object_name,
         CASE c.relkind
           WHEN 'r' THEN 'table' WHEN 'p' THEN 'table' WHEN 'S' THEN 'sequence'
           WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized_view' WHEN 'f' THEN 'foreign_table'
         END AS object_kind,
         c.relowner AS owner_oid,
         COALESCE(c.relacl, pg_catalog.acldefault(CASE WHEN c.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END, c.relowner)) AS object_acl
  FROM pg_catalog.pg_class AS c
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
    AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  UNION ALL
  SELECT n.nspname, p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')',
         CASE p.prokind WHEN 'p' THEN 'procedure' WHEN 'a' THEN 'aggregate' ELSE 'function' END,
         p.proowner, COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
  FROM pg_catalog.pg_proc AS p
  JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
  WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  UNION ALL
  SELECT n.nspname, t.typname, CASE t.typtype WHEN 'd' THEN 'domain' ELSE 'type' END,
         t.typowner, COALESCE(t.typacl, pg_catalog.acldefault('T', t.typowner))
  FROM pg_catalog.pg_type AS t
  JOIN pg_catalog.pg_namespace AS n ON n.oid = t.typnamespace
  LEFT JOIN pg_catalog.pg_class AS c ON c.oid = t.typrelid
  WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
    AND t.typelem = 0
    AND (t.typtype <> 'c' OR c.relkind = 'c')
)
SELECT object_acls.schema_name, object_acls.object_name, object_acls.object_kind,
       grantor_role.rolname AS grantor_name,
       CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee_role.rolname END AS grantee_name,
       acl.privilege_type, acl.is_grantable
FROM object_acls
CROSS JOIN LATERAL pg_catalog.aclexplode(object_acls.object_acl) AS acl
JOIN pg_catalog.pg_roles AS grantor_role ON grantor_role.oid = acl.grantor
LEFT JOIN pg_catalog.pg_roles AS grantee_role ON grantee_role.oid = acl.grantee
ORDER BY object_acls.schema_name, object_acls.object_kind, object_acls.object_name,
         grantor_name, grantee_name, acl.privilege_type, acl.is_grantable`,
			Columns: []string{"schema_name", "object_name", "object_kind", "grantor_name", "grantee_name", "privilege_type", "is_grantable"},
		},
		{
			Name: "default_acls",
			SQL: `WITH deployment_schema_owners AS (
  SELECT DISTINCT owner_role.oid AS owner_oid, owner_role.rolname AS owner_name
  FROM pg_catalog.pg_namespace AS owned_schema
  JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = owned_schema.nspowner
  WHERE left(owner_role.rolname, length($1)) = $1
    AND owned_schema.nspname <> 'information_schema'
    AND owned_schema.nspname NOT LIKE 'pg\_%' ESCAPE '\'
), effective_defaults AS (
  SELECT owners.owner_oid, owners.owner_name, ''::name AS schema_name, kinds.object_kind,
         COALESCE(defaults.defaclacl, pg_catalog.acldefault(kinds.object_code, owners.owner_oid)) AS default_acl
  FROM deployment_schema_owners AS owners
  CROSS JOIN (VALUES
    ('r'::"char", 'table'), ('S'::"char", 'sequence'),
    ('f'::"char", 'routine'), ('T'::"char", 'type')
  ) AS kinds(object_code, object_kind)
  LEFT JOIN pg_catalog.pg_default_acl AS defaults
    ON defaults.defaclrole = owners.owner_oid
   AND defaults.defaclnamespace = 0
   AND defaults.defaclobjtype = kinds.object_code
  UNION ALL
  SELECT owner_role.oid, owner_role.rolname, ''::name,
         CASE defaults.defaclobjtype WHEN 'n' THEN 'schema' ELSE defaults.defaclobjtype::text END,
         defaults.defaclacl
  FROM pg_catalog.pg_default_acl AS defaults
  JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = defaults.defaclrole
  WHERE defaults.defaclnamespace = 0
    AND defaults.defaclobjtype NOT IN ('r', 'S', 'f', 'T')
    AND left(owner_role.rolname, length($1)) = $1
  UNION ALL
  SELECT owner_role.oid, owner_role.rolname, ''::name,
         CASE defaults.defaclobjtype WHEN 'r' THEN 'table' WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'routine' WHEN 'T' THEN 'type' END,
         defaults.defaclacl
  FROM pg_catalog.pg_default_acl AS defaults
  JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = defaults.defaclrole
  WHERE defaults.defaclnamespace = 0
    AND defaults.defaclobjtype IN ('r', 'S', 'f', 'T')
    AND left(owner_role.rolname, length($1)) = $1
    AND NOT EXISTS (SELECT 1 FROM deployment_schema_owners AS owners WHERE owners.owner_oid = owner_role.oid)
  UNION ALL
  SELECT owner_role.oid, owner_role.rolname, namespace.nspname,
         CASE defaults.defaclobjtype WHEN 'r' THEN 'table' WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'routine' WHEN 'T' THEN 'type' WHEN 'n' THEN 'schema' END,
         defaults.defaclacl
  FROM pg_catalog.pg_default_acl AS defaults
  JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = defaults.defaclrole
  JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = defaults.defaclnamespace
  WHERE namespace.nspname <> 'information_schema'
    AND namespace.nspname NOT LIKE 'pg\_%' ESCAPE '\'
)
SELECT defaults.owner_name,
       defaults.schema_name,
       defaults.object_kind,
       grantor_role.rolname AS grantor_name,
       CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee_role.rolname END AS grantee_name,
       acl.privilege_type, acl.is_grantable
FROM effective_defaults AS defaults
CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.default_acl) AS acl
JOIN pg_catalog.pg_roles AS grantor_role ON grantor_role.oid = acl.grantor
LEFT JOIN pg_catalog.pg_roles AS grantee_role ON grantee_role.oid = acl.grantee
ORDER BY owner_name, schema_name, object_kind, grantor_name, grantee_name, acl.privilege_type, acl.is_grantable`,
			Columns: []string{"owner_name", "schema_name", "object_kind", "grantor_name", "grantee_name", "privilege_type", "is_grantable"},
			Args:    []string{"deployment_role_prefix"},
		},
		{
			Name: "column_acls",
			SQL: `SELECT n.nspname AS schema_name, c.relname AS relation_name, a.attname AS column_name,
       owner_role.rolname AS owner_name,
       grantor_role.rolname AS grantor_name,
       CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE grantee_role.rolname END AS grantee_name,
       acl.privilege_type, acl.is_grantable
FROM pg_catalog.pg_attribute AS a
JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = c.relowner
CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) AS acl
JOIN pg_catalog.pg_roles AS grantor_role ON grantor_role.oid = acl.grantor
LEFT JOIN pg_catalog.pg_roles AS grantee_role ON grantee_role.oid = acl.grantee
WHERE a.attnum > 0 AND NOT a.attisdropped
  AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY schema_name, relation_name, column_name, grantor_name, grantee_name, acl.privilege_type, acl.is_grantable`,
			Columns: []string{"schema_name", "relation_name", "column_name", "owner_name", "grantor_name", "grantee_name", "privilege_type", "is_grantable"},
		},
	}

	result := make([]QueryContract, len(contracts))
	for i, contract := range contracts {
		result[i] = contract
		result[i].Columns = append([]string(nil), contract.Columns...)
		result[i].Args = append([]string(nil), contract.Args...)
	}
	return result
}
