package postgres

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const fixtureRoot = "../../../../packages/test-fixtures/core/"
const integrationRoot = "../../../../tests/integration/core/"

func TestCoreOutboxManifestMatchesExactCatalogSnapshot(t *testing.T) {
	manifest := loadCoreOutboxManifest(t)
	snapshot := snapshotForManifest(manifest)
	if err := Compare(manifest, snapshot); err != nil {
		t.Fatalf("Compare() error = %v", err)
	}
}

func TestSeededCatalogMutationsFailClosed(t *testing.T) {
	manifest := loadCoreOutboxManifest(t)
	data, err := os.ReadFile(integrationRoot + "postgres_catalog_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	type mutationCase struct {
		Mutation     string `json:"mutation"`
		Edge         int    `json:"edge"`
		ExpectedCode Code   `json:"expected_code"`
	}
	var inventory struct {
		Scope string         `json:"scope"`
		Cases []mutationCase `json:"cases"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("mutation inventory contains trailing data")
	}
	if inventory.Scope != "STEAD-P1-015 core_outbox-only catalog conformance contribution" {
		t.Fatal("mutation inventory scope drifted")
	}
	wantInventory := make([]mutationCase, 0, len(manifest.Memberships)*5+2)
	for edge := range manifest.Memberships {
		wantInventory = append(wantInventory,
			mutationCase{"membership_inherit_inversion", edge, CodeMissingState},
			mutationCase{"membership_set_inversion", edge, CodeMissingState},
			mutationCase{"membership_admin_true", edge, CodeMembershipAdminEnabled},
			mutationCase{"membership_reversal", edge, CodeMissingState},
			mutationCase{"membership_unknown_grantor", edge, CodeUnknownPrincipal},
		)
	}
	wantInventory = append(wantInventory,
		mutationCase{"extra_schema_grant", -1, CodeExtraState},
		mutationCase{"persistent_column_acl", -1, CodeColumnACLPresent},
	)
	if !reflect.DeepEqual(inventory.Cases, wantInventory) {
		t.Fatalf("mutation inventory is not the exact generated per-edge inventory\ngot:  %#v\nwant: %#v", inventory.Cases, wantInventory)
	}
	seen := make(map[string]struct{}, len(inventory.Cases))
	for _, testCase := range inventory.Cases {
		key := testCase.Mutation + ":" + strconv.Itoa(testCase.Edge)
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate seeded mutation %s edge %d", testCase.Mutation, testCase.Edge)
		}
		seen[key] = struct{}{}
	}

	for _, testCase := range inventory.Cases {
		t.Run(testCase.Mutation+"_edge_"+strconv.Itoa(testCase.Edge), func(t *testing.T) {
			snapshot := snapshotForManifest(manifest)
			switch testCase.Mutation {
			case "membership_inherit_inversion":
				snapshot.Memberships[testCase.Edge].InheritOption = !snapshot.Memberships[testCase.Edge].InheritOption
			case "membership_set_inversion":
				snapshot.Memberships[testCase.Edge].SetOption = !snapshot.Memberships[testCase.Edge].SetOption
			case "membership_reversal":
				snapshot.Memberships[testCase.Edge].Role, snapshot.Memberships[testCase.Edge].Member = snapshot.Memberships[testCase.Edge].Member, snapshot.Memberships[testCase.Edge].Role
			case "membership_admin_true":
				snapshot.Memberships[testCase.Edge].AdminOption = true
			case "membership_unknown_grantor":
				snapshot.Memberships[testCase.Edge].Grantor = "protected_unknown_grantor"
			case "extra_schema_grant":
				snapshot.SchemaACLs = append(snapshot.SchemaACLs, ACLState{Schema: "core_outbox", Grantor: snapshot.Roles[1].Name, Grantee: PublicPrincipal, Privilege: "USAGE"})
			case "persistent_column_acl":
				snapshot.ColumnACLs = append(snapshot.ColumnACLs, ColumnACLState{Schema: "core_outbox", Relation: "event_intents", Column: "payload", Owner: snapshot.Roles[1].Name, Grantor: snapshot.Roles[1].Name, Grantee: PublicPrincipal, Privilege: "SELECT"})
			default:
				t.Fatalf("unimplemented seeded mutation %q", testCase.Mutation)
			}

			err := Compare(manifest, snapshot)
			assertViolationCode(t, err, testCase.ExpectedCode)
			assertSafeError(t, err, manifest)
		})
	}
}

func TestExactComparisonRejectsUnknownDuplicateMissingExtraAndDrift(t *testing.T) {
	manifest := loadCoreOutboxManifest(t)
	tests := []struct {
		name   string
		code   Code
		mutate func(*Snapshot)
	}{
		{"duplicate actual", CodeDuplicateActual, func(snapshot *Snapshot) { snapshot.Roles = append(snapshot.Roles, snapshot.Roles[0]) }},
		{"missing actual", CodeMissingState, func(snapshot *Snapshot) { snapshot.Roles = snapshot.Roles[1:] }},
		{"extra actual", CodeExtraState, func(snapshot *Snapshot) {
			snapshot.Roles = append(snapshot.Roles, RoleState{Name: "sd_0123456789abcdef_unknown", Binding: "unknown", Properties: RoleProperties{ConnectionLimit: -1}})
		}},
		{"role property drift", CodePropertyDrift, func(snapshot *Snapshot) { snapshot.Roles[0].Properties.CreateRole = true }},
		{"schema owner drift", CodePropertyDrift, func(snapshot *Snapshot) { snapshot.Schemas[0].Owner = snapshot.Roles[0].Name }},
		{"missing default acl", CodeMissingState, func(snapshot *Snapshot) { snapshot.DefaultACLs = snapshot.DefaultACLs[1:] }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			snapshot := snapshotForManifest(manifest)
			testCase.mutate(&snapshot)
			err := Compare(manifest, snapshot)
			assertViolationCode(t, err, testCase.code)
		})
	}
}

func TestLockstepManifestAndCatalogCannotAuthorizeProhibitedState(t *testing.T) {
	base := loadCoreOutboxManifest(t)
	roleMutations := []struct {
		name   string
		mutate func(*RoleProperties)
	}{
		{"superuser", func(value *RoleProperties) { value.Superuser = true }},
		{"create_role", func(value *RoleProperties) { value.CreateRole = true }},
		{"create_database", func(value *RoleProperties) { value.CreateDatabase = true }},
		{"replication", func(value *RoleProperties) { value.Replication = true }},
		{"bypass_rls", func(value *RoleProperties) { value.BypassRLS = true }},
	}
	for _, testCase := range roleMutations {
		t.Run("role_"+testCase.name, func(t *testing.T) {
			manifest := cloneManifest(t, base)
			testCase.mutate(&manifest.Roles[0].Properties)
			assertViolationCode(t, Compare(manifest, snapshotForManifest(manifest)), CodeProhibitedRoleCapability)
		})
	}

	t.Run("membership_admin", func(t *testing.T) {
		manifest := cloneManifest(t, base)
		manifest.Memberships[0].AdminOption = true
		assertViolationCode(t, Compare(manifest, snapshotForManifest(manifest)), CodeMembershipAdminEnabled)
	})

	objectBase := cloneManifest(t, base)
	objectBase.Objects = append(objectBase.Objects, ObjectSpec{Schema: "core_outbox", Name: "event_intents", Kind: "table", Owner: "core_outbox_owner"})
	objectBase.ObjectACLs = append(objectBase.ObjectACLs, ACLSpec{Schema: "core_outbox", Object: "event_intents", ObjectKind: "table", Grantor: "core_outbox_owner", Grantee: "core_outbox_owner", Privilege: "SELECT"})
	aclMutations := []struct {
		name   string
		base   Manifest
		code   Code
		mutate func(*Manifest)
	}{
		{"database_public", base, CodePublicPrivilege, func(value *Manifest) { value.DatabaseACLs[0].Grantee = PublicPrincipal }},
		{"schema_public", base, CodePublicPrivilege, func(value *Manifest) { value.SchemaACLs[0].Grantee = PublicPrincipal }},
		{"object_public", objectBase, CodePublicPrivilege, func(value *Manifest) { value.ObjectACLs[0].Grantee = PublicPrincipal }},
		{"default_public", base, CodePublicPrivilege, func(value *Manifest) { value.DefaultACLs[0].Grantee = PublicPrincipal }},
		{"database_grant_option", base, CodeGrantOptionEnabled, func(value *Manifest) { value.DatabaseACLs[0].GrantOption = true }},
		{"schema_grant_option", base, CodeGrantOptionEnabled, func(value *Manifest) { value.SchemaACLs[0].GrantOption = true }},
		{"object_grant_option", objectBase, CodeGrantOptionEnabled, func(value *Manifest) { value.ObjectACLs[0].GrantOption = true }},
		{"default_grant_option", base, CodeGrantOptionEnabled, func(value *Manifest) { value.DefaultACLs[0].GrantOption = true }},
	}
	for _, testCase := range aclMutations {
		t.Run(testCase.name, func(t *testing.T) {
			manifest := cloneManifest(t, testCase.base)
			testCase.mutate(&manifest)
			assertViolationCode(t, Compare(manifest, snapshotForManifest(manifest)), testCase.code)
		})
	}
}

func TestRoleEqualityIsStructuredAndConfigurationIsCollisionSafe(t *testing.T) {
	manifest := loadCoreOutboxManifest(t)
	manifest.Roles[0].Properties.Configuration = []string{"a\x1fb", "c"}
	snapshot := snapshotForManifest(manifest)
	if err := Compare(manifest, snapshot); err != nil {
		t.Fatalf("exact control-character configuration failed: %v", err)
	}
	snapshot.Roles[0].Properties.Configuration = []string{"a", "b\x1fc"}
	assertViolationCode(t, Compare(manifest, snapshot), CodePropertyDrift)
}

func TestManifestIdentityAndDuplicateValidation(t *testing.T) {
	manifest := loadCoreOutboxManifest(t)

	invalidKey := manifest
	invalidKey.DeploymentKey = "ABC"
	assertViolationCode(t, ValidateManifest(invalidKey), CodeInvalidDeploymentIdentity)

	invalidRoleName := manifest
	invalidRoleName.Roles = append([]RoleSpec(nil), manifest.Roles...)
	invalidRoleName.Roles[0].Name = "foreign_owner"
	assertViolationCode(t, ValidateManifest(invalidRoleName), CodeInvalidRegisteredIdentity)

	wrongBindingUUID := cloneManifest(t, manifest)
	wrongBindingUUID.Roles[0].Binding = "stead-role:v1:00000000-0000-4000-8000-000000000002:database-owner"
	assertViolationCode(t, ValidateManifest(wrongBindingUUID), CodeInvalidRegisteredIdentity)

	wrongBindingVersion := cloneManifest(t, manifest)
	wrongBindingVersion.Roles[0].Binding = strings.Replace(wrongBindingVersion.Roles[0].Binding, "stead-role:v1:", "stead-role:v2:", 1)
	assertViolationCode(t, ValidateManifest(wrongBindingVersion), CodeInvalidRegisteredIdentity)

	duplicate := manifest
	duplicate.Memberships = append(append([]MembershipSpec(nil), manifest.Memberships...), manifest.Memberships[0])
	assertViolationCode(t, ValidateManifest(duplicate), CodeDuplicateExpected)

	unknown := manifest
	unknown.Memberships = append([]MembershipSpec(nil), manifest.Memberships...)
	unknown.Memberships[0].Grantor = "not_registered"
	assertViolationCode(t, ValidateManifest(unknown), CodeUnknownPrincipal)
}

func TestLegitimateLoginAndInheritRolePropertiesRemainValid(t *testing.T) {
	manifest := loadCoreOutboxManifest(t)
	if !manifest.Roles[3].Properties.Inherit || !manifest.Roles[4].Properties.Login {
		t.Fatal("fixture no longer exercises legitimate INHERIT and LOGIN properties")
	}
	if err := Compare(manifest, snapshotForManifest(manifest)); err != nil {
		t.Fatalf("legitimate role properties rejected: %v", err)
	}
}

func TestPostgreSQL16MinimumIsEnforced(t *testing.T) {
	manifest := loadCoreOutboxManifest(t)
	snapshot := snapshotForManifest(manifest)
	snapshot.ServerVersion = MinimumServerVersion - 1
	assertViolationCode(t, Compare(manifest, snapshot), CodeServerVersionUnsupported)
}

func TestCatalogQueryContractsCoverExactACLInputs(t *testing.T) {
	contracts := CatalogQueryContracts()
	byName := make(map[string]QueryContract, len(contracts))
	for _, contract := range contracts {
		if _, duplicate := byName[contract.Name]; duplicate {
			t.Fatalf("duplicate query contract %q", contract.Name)
		}
		byName[contract.Name] = contract
	}
	for _, name := range []string{"server_version", "roles", "memberships", "databases", "database_acls", "schemas", "schema_acls", "objects", "object_acls", "default_acls", "column_acls"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("missing query contract %q", name)
		}
	}
	for name, fragments := range map[string][]string{
		"roles":         {"pg_roles", "rolinherit", "rolbypassrls", "rolpassword", "rolvaliduntil", "rolconfig", "shobj_description", "json_agg", "configuration_json"},
		"memberships":   {"pg_auth_members", "admin_option", "inherit_option", "set_option", "grantor"},
		"database_acls": {"pg_database", "aclexplode", "acldefault"},
		"schema_acls":   {"pg_namespace", "aclexplode", "acldefault"},
		"object_acls":   {"relacl", "proacl", "typacl", "aclexplode", "acldefault"},
		"default_acls":  {"pg_default_acl", "defaclnamespace", "aclexplode"},
		"column_acls":   {"pg_attribute", "attacl", "attnum > 0", "NOT a.attisdropped", "aclexplode"},
	} {
		for _, fragment := range fragments {
			if !strings.Contains(byName[name].SQL, fragment) {
				t.Errorf("query %s does not contain required catalog fragment %s", name, fragment)
			}
		}
	}
	if strings.Contains(byName["roles"].SQL, `E'\x1f'`) {
		t.Fatal("role query still uses a lossy unit-separator encoding")
	}

	copyOfContracts := CatalogQueryContracts()
	copyOfContracts[0].Columns[0] = "mutated"
	if reflect.DeepEqual(copyOfContracts, CatalogQueryContracts()) {
		t.Fatal("CatalogQueryContracts returned shared mutable storage")
	}
}

func TestDecodeManifestRejectsUnknownAndTrailingData(t *testing.T) {
	manifest := loadCoreOutboxManifest(t)
	if manifest.DeploymentKey == "" {
		t.Fatal("decoded manifest is empty")
	}
	if _, err := DecodeManifest(strings.NewReader(`{"unknown":true}`)); err == nil {
		t.Fatal("DecodeManifest accepted an unknown field")
	}
	data, err := os.ReadFile(fixtureRoot + "core_outbox_catalog_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManifest(strings.NewReader(string(data) + `{}`)); err == nil {
		t.Fatal("DecodeManifest accepted trailing data")
	}
}

func loadCoreOutboxManifest(t *testing.T) Manifest {
	t.Helper()
	file, err := os.Open(fixtureRoot + "core_outbox_catalog_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	manifest, err := DecodeManifest(file)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func cloneManifest(t *testing.T, manifest Manifest) Manifest {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var cloned Manifest
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func snapshotForManifest(manifest Manifest) Snapshot {
	principalName := make(map[string]string, len(manifest.Roles)+len(manifest.Principals)+1)
	principalName[PublicPrincipal] = PublicPrincipal
	for _, role := range manifest.Roles {
		principalName[role.SemanticID] = role.Name
	}
	for _, principal := range manifest.Principals {
		principalName[principal.SemanticID] = principal.Name
	}
	snapshot := Snapshot{ServerVersion: MinimumServerVersion}
	for _, role := range manifest.Roles {
		properties := role.Properties
		properties.Configuration = append([]string(nil), properties.Configuration...)
		snapshot.Roles = append(snapshot.Roles, RoleState{Name: role.Name, Binding: role.Binding, Properties: properties})
	}
	for _, edge := range manifest.Memberships {
		snapshot.Memberships = append(snapshot.Memberships, MembershipState{Role: principalName[edge.Role], Member: principalName[edge.Member], Grantor: principalName[edge.Grantor], AdminOption: edge.AdminOption, InheritOption: edge.InheritOption, SetOption: edge.SetOption})
	}
	for _, database := range manifest.Databases {
		snapshot.Databases = append(snapshot.Databases, DatabaseState{Name: database.Name, Owner: principalName[database.Owner]})
	}
	for _, schema := range manifest.Schemas {
		snapshot.Schemas = append(snapshot.Schemas, SchemaState{Name: schema.Name, Owner: principalName[schema.Owner]})
	}
	for _, object := range manifest.Objects {
		snapshot.Objects = append(snapshot.Objects, ObjectState{Schema: object.Schema, Name: object.Name, Kind: object.Kind, Owner: principalName[object.Owner]})
	}
	toACL := func(spec ACLSpec) ACLState {
		return ACLState{Database: spec.Database, Schema: spec.Schema, Object: spec.Object, ObjectKind: spec.ObjectKind, Grantor: principalName[spec.Grantor], Grantee: principalName[spec.Grantee], Privilege: spec.Privilege, GrantOption: spec.GrantOption}
	}
	for _, acl := range manifest.DatabaseACLs {
		snapshot.DatabaseACLs = append(snapshot.DatabaseACLs, toACL(acl))
	}
	for _, acl := range manifest.SchemaACLs {
		snapshot.SchemaACLs = append(snapshot.SchemaACLs, toACL(acl))
	}
	for _, acl := range manifest.ObjectACLs {
		snapshot.ObjectACLs = append(snapshot.ObjectACLs, toACL(acl))
	}
	for _, acl := range manifest.DefaultACLs {
		snapshot.DefaultACLs = append(snapshot.DefaultACLs, DefaultACLState{Owner: principalName[acl.Owner], Schema: acl.Schema, ObjectKind: acl.ObjectKind, Grantor: principalName[acl.Grantor], Grantee: principalName[acl.Grantee], Privilege: acl.Privilege, GrantOption: acl.GrantOption})
	}
	return snapshot
}

func assertViolationCode(t *testing.T, err error, want Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want violation %s", want)
	}
	var conformanceErr *ConformanceError
	if !errors.As(err, &conformanceErr) {
		t.Fatalf("error type = %T, want *ConformanceError", err)
	}
	for _, violation := range conformanceErr.Violations() {
		if violation.Code == want {
			return
		}
	}
	t.Fatalf("violations = %#v, want code %s", conformanceErr.Violations(), want)
}

func assertSafeError(t *testing.T, err error, manifest Manifest) {
	t.Helper()
	message := err.Error()
	protected := []string{manifest.DeploymentKey, manifest.InstallationUUID, "core_outbox", "protected_unknown_grantor", "event_intents", "payload"}
	for _, value := range protected {
		if strings.Contains(message, value) {
			t.Errorf("Error() exposed a protected identifier")
		}
	}
	for _, role := range manifest.Roles {
		if strings.Contains(message, role.Name) || strings.Contains(message, role.SemanticID) {
			t.Errorf("Error() exposed a registered role identifier")
		}
	}
}
