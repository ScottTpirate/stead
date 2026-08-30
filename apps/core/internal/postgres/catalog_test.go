package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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
		for roleIndex := range base.Roles {
			t.Run("role_"+strconv.Itoa(roleIndex)+"_"+testCase.name, func(t *testing.T) {
				manifest := cloneManifest(t, base)
				testCase.mutate(&manifest.Roles[roleIndex].Properties)
				assertViolationCode(t, Compare(manifest, snapshotForManifest(manifest)), CodeProhibitedRoleCapability)
			})
		}
	}

	for edge := range base.Memberships {
		t.Run("membership_"+strconv.Itoa(edge)+"_admin", func(t *testing.T) {
			manifest := cloneManifest(t, base)
			manifest.Memberships[edge].AdminOption = true
			assertViolationCode(t, Compare(manifest, snapshotForManifest(manifest)), CodeMembershipAdminEnabled)
		})
	}

	objectBase := cloneManifest(t, base)
	objectBase.Objects = append(objectBase.Objects, ObjectSpec{Schema: "core_outbox", Name: "event_intents", Kind: "table", Owner: "core_outbox_owner"})
	objectBase.ObjectACLs = append(objectBase.ObjectACLs, ACLSpec{Schema: "core_outbox", Object: "event_intents", ObjectKind: "table", Grantor: "core_outbox_owner", Grantee: "core_outbox_owner", Privilege: "SELECT"})
	aclGroups := []struct {
		name        string
		base        Manifest
		length      func(Manifest) int
		makePublic  func(*Manifest, int)
		grantOption func(*Manifest, int)
	}{
		{"database", base, func(value Manifest) int { return len(value.DatabaseACLs) }, func(value *Manifest, index int) { value.DatabaseACLs[index].Grantee = PublicPrincipal }, func(value *Manifest, index int) { value.DatabaseACLs[index].GrantOption = true }},
		{"schema", base, func(value Manifest) int { return len(value.SchemaACLs) }, func(value *Manifest, index int) { value.SchemaACLs[index].Grantee = PublicPrincipal }, func(value *Manifest, index int) { value.SchemaACLs[index].GrantOption = true }},
		{"object", objectBase, func(value Manifest) int { return len(value.ObjectACLs) }, func(value *Manifest, index int) { value.ObjectACLs[index].Grantee = PublicPrincipal }, func(value *Manifest, index int) { value.ObjectACLs[index].GrantOption = true }},
		{"default", base, func(value Manifest) int { return len(value.DefaultACLs) }, func(value *Manifest, index int) { value.DefaultACLs[index].Grantee = PublicPrincipal }, func(value *Manifest, index int) { value.DefaultACLs[index].GrantOption = true }},
	}
	for _, group := range aclGroups {
		for entry := 0; entry < group.length(group.base); entry++ {
			t.Run(group.name+"_"+strconv.Itoa(entry)+"_public", func(t *testing.T) {
				manifest := cloneManifest(t, group.base)
				group.makePublic(&manifest, entry)
				assertViolationCode(t, Compare(manifest, snapshotForManifest(manifest)), CodePublicPrivilege)
			})
			t.Run(group.name+"_"+strconv.Itoa(entry)+"_grant_option", func(t *testing.T) {
				manifest := cloneManifest(t, group.base)
				group.grantOption(&manifest, entry)
				assertViolationCode(t, Compare(manifest, snapshotForManifest(manifest)), CodeGrantOptionEnabled)
			})
		}
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
	wrongBindingUUID.Roles[0].Binding = strings.Replace(wrongBindingUUID.Roles[0].Binding, manifest.InstallationUUID, "00000000-0000-4000-8000-000000000002", 1)
	if !strings.HasSuffix(wrongBindingUUID.Roles[0].Binding, ":"+manifest.Roles[0].SemanticID) {
		t.Fatal("wrong-UUID mutation changed the semantic role suffix")
	}
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
		"roles":         {"pg_roles", "rolinherit", "rolbypassrls", "rolpassword", "rolvaliduntil", "rolconfig", "shobj_description", "json_agg", `ORDER BY setting COLLATE "C"`, "configuration_json"},
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

func TestCatalogACLObjectCodeMappingsAreClosedAndCaseSensitive(t *testing.T) {
	byName := make(map[string]string)
	for _, contract := range CatalogQueryContracts() {
		byName[contract.Name] = contract.SQL
	}
	objectACLs, defaultACLs := byName["object_acls"], byName["default_acls"]
	if err := validateACLObjectCodeMappings(objectACLs, defaultACLs); err != nil {
		t.Fatalf("catalog ACL object-code mapping rejected: %v", err)
	}
	objectSequenceUpper := replaceOnce(t, objectACLs, `THEN 's'::"char"`, `THEN 'S'::"char"`)
	defaultSequenceUpper := replaceOnce(t, defaultACLs, `('S'::"char", 's'::"char", 'sequence')`, `('S'::"char", 'S'::"char", 'sequence')`)
	defaultFallbackUsesCatalogCode := replaceOnce(t, defaultACLs, `acldefault(kinds.acldefault_code,`, `acldefault(kinds.defaclobjtype_code,`)
	defaultCatalogMatchUsesFallbackCode := replaceOnce(t, defaultACLs, `defaclobjtype = kinds.defaclobjtype_code`, `defaclobjtype = kinds.acldefault_code`)
	objectDeadBranchDecoy := replaceOnce(t, objectSequenceUpper,
		`WHERE c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')`,
		`WHERE c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
    AND (true OR `+sequenceObjectFallbackSQL+` IS NULL)`)
	defaultAllWrong := replaceOnce(t, defaultSequenceUpper, `acldefault(kinds.acldefault_code,`, `acldefault(kinds.defaclobjtype_code,`)
	defaultAllWrong = replaceOnce(t, defaultAllWrong, `defaclobjtype = kinds.defaclobjtype_code`, `defaclobjtype = kinds.acldefault_code`)
	defaultUnusedCTEDecoy := replaceOnce(t, defaultAllWrong, `), effective_defaults AS (`, `), expected_mapping_decoy AS (
  SELECT owners.owner_oid
  FROM deployment_schema_owners AS owners
  `+defaultObjectPairsSQL+`
  LEFT JOIN pg_catalog.pg_default_acl AS defaults
    ON defaults.defaclrole = owners.owner_oid
   AND `+defaultACLCatalogUseSQL+`
  WHERE `+defaultACLFallbackUseSQL+` IS NOT NULL
), effective_defaults AS (`)
	assertLocalizedACLSequencesPresent(t, objectDeadBranchDecoy, defaultUnusedCTEDecoy)

	mutations := []struct {
		name        string
		objectACLs  string
		defaultACLs string
	}{
		{"object_sequence_fallback_S_to_S", objectSequenceUpper, defaultACLs},
		{"default_table_fallback_r_to_s", objectACLs, replaceOnce(t, defaultACLs, `('r'::"char", 'r'::"char", 'table')`, `('r'::"char", 's'::"char", 'table')`)},
		{"default_sequence_fallback_s_to_S", objectACLs, defaultSequenceUpper},
		{"default_routine_fallback_f_to_r", objectACLs, replaceOnce(t, defaultACLs, `('f'::"char", 'f'::"char", 'routine')`, `('f'::"char", 'r'::"char", 'routine')`)},
		{"default_type_fallback_T_to_r", objectACLs, replaceOnce(t, defaultACLs, `('T'::"char", 'T'::"char", 'type')`, `('T'::"char", 'r'::"char", 'type')`)},
		{"default_pair_split_typecast", objectACLs, replaceOnce(t, defaultACLs, `'r'::"char"`, `'r':/**/:"char"`)},
		{"fallback_uses_catalog_code", objectACLs, defaultFallbackUsesCatalogCode},
		{"catalog_match_uses_fallback_code", objectACLs, defaultCatalogMatchUsesFallbackCode},
		{"object_sequence_line_comment_decoy", objectSequenceUpper + "\n" + lineCommentSQL(sequenceObjectFallbackSQL), defaultACLs},
		{"object_sequence_block_comment_decoy", objectSequenceUpper + "\n" + blockCommentSQL(sequenceObjectFallbackSQL), defaultACLs},
		{"default_sequence_line_comment_decoy", objectACLs, defaultSequenceUpper + "\n" + lineCommentSQL(defaultObjectPairsSQL)},
		{"default_sequence_block_comment_decoy", objectACLs, defaultSequenceUpper + "\n" + blockCommentSQL(defaultObjectPairsSQL)},
		{"fallback_use_line_comment_decoy", objectACLs, defaultFallbackUsesCatalogCode + "\n" + lineCommentSQL(defaultACLFallbackUseSQL)},
		{"fallback_use_block_comment_decoy", objectACLs, defaultFallbackUsesCatalogCode + "\n" + blockCommentSQL(defaultACLFallbackUseSQL)},
		{"catalog_use_line_comment_decoy", objectACLs, defaultCatalogMatchUsesFallbackCode + "\n" + lineCommentSQL(defaultACLCatalogUseSQL)},
		{"catalog_use_block_comment_decoy", objectACLs, defaultCatalogMatchUsesFallbackCode + "\n" + blockCommentSQL(defaultACLCatalogUseSQL)},
		{"object_active_dead_branch_decoy", objectDeadBranchDecoy, defaultACLs},
		{"default_active_unused_cte_decoy", objectACLs, defaultUnusedCTEDecoy},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if err := validateACLObjectCodeMappings(mutation.objectACLs, mutation.defaultACLs); err == nil {
				t.Fatal("object-code mutation survived the structural guard")
			}
		})
	}
}

const maximumCatalogGuardSQLBytes = 1 << 20

const sequenceObjectFallbackSQL = `pg_catalog.acldefault(CASE WHEN c.relkind = 'S' THEN 's'::"char" ELSE 'r'::"char" END, c.relowner)`

const defaultObjectPairsSQL = `CROSS JOIN (VALUES
    ('r'::"char", 'r'::"char", 'table'),
    ('S'::"char", 's'::"char", 'sequence'),
    ('f'::"char", 'f'::"char", 'routine'),
    ('T'::"char", 'T'::"char", 'type')
  ) AS kinds(defaclobjtype_code, acldefault_code, object_kind)`

const defaultACLFallbackUseSQL = `pg_catalog.acldefault(kinds.acldefault_code, owners.owner_oid)`
const defaultACLCatalogUseSQL = `defaults.defaclobjtype = kinds.defaclobjtype_code`

// These digests bind each complete comment-free token stream. The readable
// localized sequences above separately identify the PostgreSQL code distinction.
const objectACLActiveSQLDigest = "7f910fb8267b15ec8aefe3543220862353a60c33364551d732caac2fe182b8d3"
const defaultACLActiveSQLDigest = "292840d38b0658a67249c06962eb22bf4a218eec381a843cfc061ecae80ae6fb"

func validateACLObjectCodeMappings(objectACLs, defaultACLs string) error {
	objectTokens, err := tokenizeActiveCatalogSQL(objectACLs)
	if err != nil {
		return errors.New("object ACL SQL is malformed")
	}
	defaultTokens, err := tokenizeActiveCatalogSQL(defaultACLs)
	if err != nil {
		return errors.New("default ACL SQL is malformed")
	}
	if digest := activeSQLTokenDigest(objectTokens); digest != objectACLActiveSQLDigest {
		return fmt.Errorf("object ACL active SQL digest = %s, want %s", digest, objectACLActiveSQLDigest)
	}
	if digest := activeSQLTokenDigest(defaultTokens); digest != defaultACLActiveSQLDigest {
		return fmt.Errorf("default ACL active SQL digest = %s, want %s", digest, defaultACLActiveSQLDigest)
	}
	if err := requireOneActiveSQLSequence(objectTokens, sequenceObjectFallbackSQL); err != nil {
		return errors.New("object ACL fallback codes drifted")
	}
	for _, required := range []string{defaultObjectPairsSQL, defaultACLFallbackUseSQL, defaultACLCatalogUseSQL} {
		if err := requireOneActiveSQLSequence(defaultTokens, required); err != nil {
			return errors.New("default ACL catalog/fallback object-code pairs drifted")
		}
	}
	return nil
}

func activeSQLTokenDigest(tokens []string) string {
	hasher := sha256.New()
	var size [8]byte
	for _, token := range tokens {
		binary.BigEndian.PutUint64(size[:], uint64(len(token)))
		_, _ = hasher.Write(size[:])
		_, _ = hasher.Write([]byte(token))
	}
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func assertLocalizedACLSequencesPresent(t *testing.T, objectACLs, defaultACLs string) {
	t.Helper()
	objectTokens, err := tokenizeActiveCatalogSQL(objectACLs)
	if err != nil || requireOneActiveSQLSequence(objectTokens, sequenceObjectFallbackSQL) != nil {
		t.Fatal("object active-decoy mutant does not isolate whole-query binding")
	}
	defaultTokens, err := tokenizeActiveCatalogSQL(defaultACLs)
	if err != nil {
		t.Fatal("default active-decoy mutant is malformed")
	}
	for _, required := range []string{defaultObjectPairsSQL, defaultACLFallbackUseSQL, defaultACLCatalogUseSQL} {
		if requireOneActiveSQLSequence(defaultTokens, required) != nil {
			t.Fatal("default active-decoy mutant does not isolate whole-query binding")
		}
	}
}

func requireOneActiveSQLSequence(active []string, requiredSQL string) error {
	required, err := tokenizeActiveCatalogSQL(requiredSQL)
	if err != nil || len(required) == 0 {
		return errors.New("invalid required SQL sequence")
	}
	count := 0
	for start := 0; start+len(required) <= len(active); start++ {
		matched := true
		for offset := range required {
			if active[start+offset] != required[offset] {
				matched = false
				break
			}
		}
		if matched {
			count++
		}
	}
	if count != 1 {
		return errors.New("required SQL sequence count drifted")
	}
	return nil
}

func tokenizeActiveCatalogSQL(input string) ([]string, error) {
	if len(input) > maximumCatalogGuardSQLBytes {
		return nil, errors.New("catalog SQL exceeds structural-guard bound")
	}
	if strings.IndexByte(input, 0) >= 0 {
		return nil, errors.New("catalog SQL contains a NUL byte")
	}
	tokens := make([]string, 0, len(input)/4)
	for index := 0; index < len(input); {
		switch {
		case isSQLWhitespace(input[index]):
			index++
		case index+1 < len(input) && input[index] == '-' && input[index+1] == '-':
			index += 2
			for index < len(input) && input[index] != '\n' && input[index] != '\r' {
				index++
			}
		case index+1 < len(input) && input[index] == '/' && input[index+1] == '*':
			depth := 1
			index += 2
			for depth > 0 {
				if index >= len(input) {
					return nil, errors.New("unterminated SQL block comment")
				}
				switch {
				case index+1 < len(input) && input[index] == '/' && input[index+1] == '*':
					depth++
					index += 2
				case index+1 < len(input) && input[index] == '*' && input[index+1] == '/':
					depth--
					index += 2
				default:
					index++
				}
			}
		case (input[index] == 'E' || input[index] == 'e') && index+1 < len(input) && input[index+1] == '\'':
			end, err := scanSQLSingleQuoted(input, index+1, true)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, input[index:end])
			index = end
		case input[index] == '\'':
			end, err := scanSQLSingleQuoted(input, index, false)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, input[index:end])
			index = end
		case input[index] == '"':
			end, err := scanSQLDoubleQuoted(input, index)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, input[index:end])
			index = end
		case input[index] == '$':
			if index+1 < len(input) && input[index+1] >= '0' && input[index+1] <= '9' {
				start := index
				index += 2
				for index < len(input) && input[index] >= '0' && input[index] <= '9' {
					index++
				}
				if index < len(input) && isSQLIdentifierContinuation(input[index]) {
					return nil, errors.New("SQL parameter has identifier junk")
				}
				tokens = append(tokens, input[start:index])
				continue
			}
			delimiter, ok := sqlDollarQuoteDelimiter(input, index)
			if !ok {
				tokens = append(tokens, "$")
				index++
				continue
			}
			contentStart := index + len(delimiter)
			closingOffset := strings.Index(input[contentStart:], delimiter)
			if closingOffset < 0 {
				return nil, errors.New("unterminated SQL dollar quote")
			}
			end := contentStart + closingOffset + len(delimiter)
			tokens = append(tokens, input[index:end])
			index = end
		case input[index] == ':' && index+1 < len(input) && (input[index+1] == ':' || input[index+1] == '='):
			tokens = append(tokens, input[index:index+2])
			index += 2
		case isSQLOperatorByte(input[index]):
			start := index
			index++
			for index < len(input) && isSQLOperatorByte(input[index]) {
				if index+1 < len(input) && (input[index] == '-' && input[index+1] == '-' || input[index] == '/' && input[index+1] == '*') {
					break
				}
				index++
			}
			tokens = append(tokens, input[start:index])
		case input[index] >= '0' && input[index] <= '9':
			start := index
			index++
			for index < len(input) && input[index] >= '0' && input[index] <= '9' {
				index++
			}
			if index < len(input) && isSQLIdentifierContinuation(input[index]) {
				return nil, errors.New("SQL integer has identifier junk")
			}
			tokens = append(tokens, input[start:index])
		case isSQLIdentifierStart(input[index]):
			start := index
			index++
			for index < len(input) && isSQLIdentifierContinuation(input[index]) {
				index++
			}
			tokens = append(tokens, input[start:index])
		default:
			tokens = append(tokens, input[index:index+1])
			index++
		}
	}
	return tokens, nil
}

func scanSQLSingleQuoted(input string, start int, backslashEscapes bool) (int, error) {
	for index := start + 1; index < len(input); index++ {
		if backslashEscapes && input[index] == '\\' {
			if index+1 >= len(input) {
				return 0, errors.New("unterminated SQL escape string")
			}
			index++
			continue
		}
		if input[index] != '\'' {
			continue
		}
		if index+1 < len(input) && input[index+1] == '\'' {
			index++
			continue
		}
		return index + 1, nil
	}
	return 0, errors.New("unterminated SQL string")
}

func scanSQLDoubleQuoted(input string, start int) (int, error) {
	for index := start + 1; index < len(input); index++ {
		if input[index] != '"' {
			continue
		}
		if index+1 < len(input) && input[index+1] == '"' {
			index++
			continue
		}
		return index + 1, nil
	}
	return 0, errors.New("unterminated SQL quoted identifier")
}

func sqlDollarQuoteDelimiter(input string, start int) (string, bool) {
	if start+1 >= len(input) {
		return "", false
	}
	if input[start+1] == '$' {
		return "$$", true
	}
	if !isSQLIdentifierStart(input[start+1]) {
		return "", false
	}
	end := start + 2
	for end < len(input) && isSQLIdentifierContinuation(input[end]) && input[end] != '$' {
		end++
	}
	if end >= len(input) || input[end] != '$' {
		return "", false
	}
	return input[start : end+1], true
}

func isSQLWhitespace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r' || value == '\f'
}

func isSQLIdentifierStart(value byte) bool {
	return value == '_' || value >= 0x80 || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isSQLIdentifierContinuation(value byte) bool {
	return isSQLIdentifierStart(value) || value >= '0' && value <= '9' || value == '$'
}

func isSQLOperatorByte(value byte) bool {
	return strings.ContainsRune("+-*/<>=~!@#%^&|`?", rune(value))
}

func lineCommentSQL(value string) string {
	return "-- " + strings.ReplaceAll(value, "\n", "\n-- ")
}

func blockCommentSQL(value string) string { return "/* " + value + " */" }

func TestCatalogSQLTokenizerRespectsQuotesAndRejectsMalformedInput(t *testing.T) {
	input := `SELECT '--', "/*", $tag$-- /*$tag$, E'quote\'--still' -- removed
FROM x /* outer /* nested */ comment */ WHERE y = '/*still*/'`
	want := []string{"SELECT", "'--'", ",", `"/*"`, ",", "$tag$-- /*$tag$", ",", `E'quote\'--still'`, "FROM", "x", "WHERE", "y", "=", "'/*still*/'"}
	got, err := tokenizeActiveCatalogSQL(input)
	if err != nil {
		t.Fatalf("tokenizeActiveCatalogSQL() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens = %#v, want %#v", got, want)
	}
	operatorTokens, err := tokenizeActiveCatalogSQL(`SELECT 'r'::"char", $1, a<>b, a||b, a*/b`)
	if err != nil {
		t.Fatalf("operator tokenization failed: %v", err)
	}
	wantOperatorTokens := []string{"SELECT", "'r'", "::", `"char"`, ",", "$1", ",", "a", "<>", "b", ",", "a", "||", "b", ",", "a", "*/", "b"}
	if !reflect.DeepEqual(operatorTokens, wantOperatorTokens) {
		t.Fatalf("operator tokens = %#v, want %#v", operatorTokens, wantOperatorTokens)
	}
	for _, testCase := range []struct {
		canonical string
		split     string
	}{
		{`SELECT 'r'::"char"`, `SELECT 'r':/**/:"char"`},
		{`SELECT $1`, `SELECT $ 1`},
		{`SELECT a<>b`, `SELECT a</**/>b`},
		{`SELECT a||b`, `SELECT a|/**/|b`},
		{"SELECT a b", "SELECT a\vb"},
	} {
		canonical, err := tokenizeActiveCatalogSQL(testCase.canonical)
		if err != nil {
			t.Fatalf("canonical operator was not lexable: %v", err)
		}
		split, err := tokenizeActiveCatalogSQL(testCase.split)
		if err != nil {
			t.Fatalf("split-token mutation was not lexable: %v", err)
		}
		if reflect.DeepEqual(canonical, split) {
			t.Fatal("split-token mutation retained the canonical token boundary")
		}
	}
	for _, testCase := range []struct {
		canonical string
		junk      string
	}{
		{`SELECT 0 THEN`, `SELECT 0THEN`},
		{`SELECT $1 AND`, `SELECT $1AND`},
	} {
		if _, err := tokenizeActiveCatalogSQL(testCase.canonical); err != nil {
			t.Fatalf("canonical literal or parameter was not lexable: %v", err)
		}
		if _, err := tokenizeActiveCatalogSQL(testCase.junk); err == nil {
			t.Fatal("tokenizer accepted PostgreSQL identifier junk")
		}
	}

	for _, malformed := range []string{
		`SELECT 'unterminated`,
		`SELECT "unterminated`,
		`SELECT E'unterminated\`,
		`SELECT /* unterminated`,
		`SELECT $tag$unterminated`,
		strings.Repeat("x", maximumCatalogGuardSQLBytes+1),
	} {
		if _, err := tokenizeActiveCatalogSQL(malformed); err == nil {
			t.Fatal("tokenizer accepted malformed or over-bound SQL")
		}
	}
}

func TestDecodeManifestRejectsNonCanonicalJSONBeforeTypedDecode(t *testing.T) {
	data, err := os.ReadFile(fixtureRoot + "core_outbox_catalog_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManifest(bytes.NewReader(data)); err != nil {
		t.Fatalf("canonical fixture rejected: %v", err)
	}
	canonicalZero := []byte(replaceOnce(t, string(data), `"connection_limit": -1`, `"connection_limit": 0`))
	if _, err := DecodeManifest(bytes.NewReader(canonicalZero)); err != nil {
		t.Fatalf("canonical zero integer rejected: %v", err)
	}

	augmented := loadCoreOutboxManifest(t)
	augmented.Objects = append(augmented.Objects, ObjectSpec{Schema: "core_outbox", Name: "event_intents", Kind: "table", Owner: "core_outbox_owner"})
	augmented.ObjectACLs = append(augmented.ObjectACLs, ACLSpec{Schema: "core_outbox", Object: "event_intents", ObjectKind: "table", Grantor: "core_outbox_owner", Grantee: "core_outbox_owner", Privilege: "SELECT"})
	augmentedData, err := json.Marshal(augmented)
	if err != nil {
		t.Fatal(err)
	}

	fixture := string(data)
	augmentedFixture := string(augmentedData)
	mutations := []struct {
		name string
		data []byte
	}{
		{"duplicate_root", []byte(replaceOnce(t, fixture, `"roles": [`, `"roles": [], "roles": [`))},
		{"escaped_duplicate_root", []byte(replaceOnce(t, fixture, `"roles": [`, `"roles": [], "\u0072oles": [`))},
		{"escaped_known_key", []byte(replaceOnce(t, fixture, `"roles": [`, `"\u0072oles": [`))},
		{"lone_surrogate", []byte(replaceOnce(t, fixture, `"deployment_key": "0123456789abcdef"`, `"deployment_key": "\ud800"`))},
		{"duplicate_role", []byte(replaceOnce(t, fixture, `"semantic_id": "database_owner",`, `"semantic_id": "database_owner", "semantic_id": "database_owner",`))},
		{"duplicate_role_properties", []byte(replaceOnce(t, fixture, `"superuser": false,`, `"superuser": false, "superuser": false,`))},
		{"duplicate_principal", []byte(replaceOnce(t, fixture, `"semantic_id": "bootstrap_grantor",`, `"semantic_id": "bootstrap_grantor", "semantic_id": "bootstrap_grantor",`))},
		{"duplicate_membership", []byte(replaceOnce(t, fixture, `{"role": "core_outbox_read_write",`, `{"role": "core_outbox_read_write", "role": "core_outbox_read_write",`))},
		{"duplicate_database", []byte(replaceOnce(t, fixture, `{"name": "stead_0123456789abcdef",`, `{"name": "stead_0123456789abcdef", "name": "stead_0123456789abcdef",`))},
		{"duplicate_schema", []byte(replaceOnce(t, fixture, `{"name": "core_outbox",`, `{"name": "core_outbox", "name": "core_outbox",`))},
		{"duplicate_database_acl", []byte(replaceOnce(t, fixture, `{"database": "stead_0123456789abcdef",`, `{"database": "stead_0123456789abcdef", "database": "stead_0123456789abcdef",`))},
		{"duplicate_schema_acl", []byte(replaceOnce(t, fixture, `{"schema": "core_outbox", "grantor":`, `{"schema": "core_outbox", "schema": "core_outbox", "grantor":`))},
		{"duplicate_default_acl", []byte(replaceOnce(t, fixture, `{"owner": "core_outbox_owner", "object_kind":`, `{"owner": "core_outbox_owner", "owner": "core_outbox_owner", "object_kind":`))},
		{"duplicate_object", []byte(replaceOnce(t, augmentedFixture, `{"schema":"core_outbox","name":"event_intents",`, `{"schema":"core_outbox","schema":"core_outbox","name":"event_intents",`))},
		{"duplicate_object_acl", []byte(replaceOnce(t, augmentedFixture, `{"schema":"core_outbox","object":"event_intents",`, `{"schema":"core_outbox","schema":"core_outbox","object":"event_intents",`))},
		{"case_variant_root", []byte(replaceOnce(t, fixture, `"roles": [`, `"Roles": [`))},
		{"case_variant_nested", []byte(replaceOnce(t, fixture, `"semantic_id": "database_owner"`, `"Semantic_ID": "database_owner"`))},
		{"unknown_root", []byte(replaceOnce(t, fixture, `{`, `{"unknown": false,`))},
		{"unknown_nested", []byte(replaceOnce(t, fixture, `"superuser": false,`, `"unknown": false, "superuser": false,`))},
		{"null_array", []byte(replaceOnce(t, fixture, `"configuration": []`, `"configuration": null`))},
		{"noncanonical_integer", []byte(replaceOnce(t, fixture, `"connection_limit": -1`, `"connection_limit": -1.0`))},
		{"negative_zero_integer", []byte(replaceOnce(t, fixture, `"connection_limit": -1`, `"connection_limit": -0`))},
		{"missing_required", []byte(replaceOnce(t, fixture, `"superuser": false, `, ``))},
		{"trailing_value", append(append([]byte(nil), data...), []byte(`{}`)...)},
		{"invalid_utf8", []byte("{\"deployment_key\":\"\xff\"}")},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if _, err := DecodeManifest(bytes.NewReader(mutation.data)); err == nil {
				t.Fatal("DecodeManifest accepted non-canonical JSON")
			}
		})
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

func replaceOnce(t *testing.T, input, old, replacement string) string {
	t.Helper()
	if !strings.Contains(input, old) {
		t.Fatalf("test mutation target %q not found", old)
	}
	return strings.Replace(input, old, replacement, 1)
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
