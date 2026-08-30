// Package postgres contains the PostgreSQL boundary owned by the core
// composition root. This file deliberately models catalog state without a
// database-driver dependency so deployment adapters can use the approved
// driver without changing the conformance contract.
package postgres

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	MinimumServerVersion = 160000
	PublicPrincipal      = "PUBLIC"
)

var (
	deploymentKeyPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
	identifierPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	uuidPattern          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// RoleProperties is the complete non-secret PostgreSQL role-property surface
// registered by this release. Password bytes are never read; only their
// presence is compared.
type RoleProperties struct {
	Superuser       bool     `json:"superuser"`
	Inherit         bool     `json:"inherit"`
	CreateRole      bool     `json:"create_role"`
	CreateDatabase  bool     `json:"create_database"`
	Login           bool     `json:"login"`
	Replication     bool     `json:"replication"`
	BypassRLS       bool     `json:"bypass_rls"`
	ConnectionLimit int      `json:"connection_limit"`
	PasswordPresent bool     `json:"password_present"`
	ValidUntilUTC   string   `json:"valid_until_utc"`
	Configuration   []string `json:"configuration"`
}

type RoleSpec struct {
	SemanticID string         `json:"semantic_id"`
	Name       string         `json:"name"`
	Binding    string         `json:"binding"`
	Properties RoleProperties `json:"properties"`
}

type RoleState struct {
	Name       string
	Binding    string
	Properties RoleProperties
}

// PrincipalSpec binds a controlled cluster or built-in identity referenced by
// catalog tuples. It is not a deployment role and its provider-owned role
// properties are intentionally outside the release registry.
type PrincipalSpec struct {
	SemanticID string `json:"semantic_id"`
	Name       string `json:"name"`
}

type MembershipSpec struct {
	Role          string `json:"role"`
	Member        string `json:"member"`
	Grantor       string `json:"grantor"`
	AdminOption   bool   `json:"admin_option"`
	InheritOption bool   `json:"inherit_option"`
	SetOption     bool   `json:"set_option"`
}

type MembershipState struct {
	Role          string
	Member        string
	Grantor       string
	AdminOption   bool
	InheritOption bool
	SetOption     bool
}

type DatabaseSpec struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

type DatabaseState struct {
	Name  string
	Owner string
}

type SchemaSpec struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

type SchemaState struct {
	Name  string
	Owner string
}

// ObjectKind uses the stable values table, sequence, view, materialized_view,
// foreign_table, function, procedure, aggregate, type, and domain.
type ObjectSpec struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Owner  string `json:"owner"`
}

type ObjectState struct {
	Schema string
	Name   string
	Kind   string
	Owner  string
}

type ACLSpec struct {
	Database    string `json:"database,omitempty"`
	Schema      string `json:"schema,omitempty"`
	Object      string `json:"object,omitempty"`
	ObjectKind  string `json:"object_kind,omitempty"`
	Grantor     string `json:"grantor"`
	Grantee     string `json:"grantee"`
	Privilege   string `json:"privilege"`
	GrantOption bool   `json:"grant_option"`
}

type ACLState struct {
	Database    string
	Schema      string
	Object      string
	ObjectKind  string
	Grantor     string
	Grantee     string
	Privilege   string
	GrantOption bool
}

type DefaultACLSpec struct {
	Owner       string `json:"owner"`
	Schema      string `json:"schema,omitempty"`
	ObjectKind  string `json:"object_kind"`
	Grantor     string `json:"grantor"`
	Grantee     string `json:"grantee"`
	Privilege   string `json:"privilege"`
	GrantOption bool   `json:"grant_option"`
}

type DefaultACLState struct {
	Owner       string
	Schema      string
	ObjectKind  string
	Grantor     string
	Grantee     string
	Privilege   string
	GrantOption bool
}

type ColumnACLState struct {
	Schema      string
	Relation    string
	Column      string
	Owner       string
	Grantor     string
	Grantee     string
	Privilege   string
	GrantOption bool
}

// Manifest is the complete rendered state for one harness invocation. Other
// owners extend this value with their own namespace cases; core does not infer
// or render their effective configuration.
type Manifest struct {
	DeploymentKey    string           `json:"deployment_key"`
	InstallationUUID string           `json:"installation_uuid"`
	Databases        []DatabaseSpec   `json:"databases"`
	Roles            []RoleSpec       `json:"roles"`
	Principals       []PrincipalSpec  `json:"principals"`
	Memberships      []MembershipSpec `json:"memberships"`
	Schemas          []SchemaSpec     `json:"schemas"`
	Objects          []ObjectSpec     `json:"objects"`
	DatabaseACLs     []ACLSpec        `json:"database_acls"`
	SchemaACLs       []ACLSpec        `json:"schema_acls"`
	ObjectACLs       []ACLSpec        `json:"object_acls"`
	DefaultACLs      []DefaultACLSpec `json:"default_acls"`
}

type Snapshot struct {
	ServerVersion int
	Databases     []DatabaseState
	Roles         []RoleState
	Memberships   []MembershipState
	Schemas       []SchemaState
	Objects       []ObjectState
	DatabaseACLs  []ACLState
	SchemaACLs    []ACLState
	ObjectACLs    []ACLState
	DefaultACLs   []DefaultACLState
	ColumnACLs    []ColumnACLState
}

type Collector interface {
	Collect(context.Context, Manifest) (Snapshot, error)
}

// Verify validates the rendered identity contract and then compares a freshly
// collected catalog snapshot in both directions.
func Verify(ctx context.Context, manifest Manifest, collector Collector) error {
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	if collector == nil {
		return &ConformanceError{violations: []Violation{{Code: CodeCatalogQueryFailed, Section: "catalog"}}}
	}
	snapshot, err := collector.Collect(ctx, manifest)
	if err != nil {
		return &ConformanceError{violations: []Violation{{Code: CodeCatalogQueryFailed, Section: "catalog"}}}
	}
	return Compare(manifest, snapshot)
}

type Code string

const (
	CodeInvalidDeploymentIdentity Code = "invalid_deployment_identity"
	CodeInvalidRegisteredIdentity Code = "invalid_registered_identity"
	CodeUnknownPrincipal          Code = "unknown_principal"
	CodeDuplicateExpected         Code = "duplicate_expected"
	CodeDuplicateActual           Code = "duplicate_actual"
	CodeMissingState              Code = "missing_state"
	CodeExtraState                Code = "extra_state"
	CodePropertyDrift             Code = "property_drift"
	CodeMembershipAdminEnabled    Code = "membership_admin_enabled"
	CodeColumnACLPresent          Code = "column_acl_present"
	CodeServerVersionUnsupported  Code = "server_version_unsupported"
	CodeCatalogQueryFailed        Code = "catalog_query_failed"
)

// Violation contains only normalized classifications and ordinals. It never
// includes deployment, installation, role, schema, object, or column names.
type Violation struct {
	Code            Code
	Section         string
	Field           string
	ExpectedOrdinal int
	ActualOrdinal   int
}

type ConformanceError struct {
	violations []Violation
}

func (e *ConformanceError) Error() string {
	if e == nil || len(e.violations) == 0 {
		return "postgres catalog conformance failed"
	}
	return fmt.Sprintf("postgres catalog conformance failed: %s (%d violation(s))", e.violations[0].Code, len(e.violations))
}

func (e *ConformanceError) Violations() []Violation {
	if e == nil {
		return nil
	}
	return append([]Violation(nil), e.violations...)
}

func ValidateManifest(manifest Manifest) error {
	v := make([]Violation, 0)
	if !deploymentKeyPattern.MatchString(manifest.DeploymentKey) || !uuidPattern.MatchString(manifest.InstallationUUID) {
		v = append(v, Violation{Code: CodeInvalidDeploymentIdentity, Section: "deployment"})
	}

	prefix := "sd_" + manifest.DeploymentKey + "_"
	semanticIDs := map[string]int{}
	roleNames := map[string]int{}
	roleBindings := map[string]int{}
	for i, role := range manifest.Roles {
		if role.SemanticID == "" || role.Binding == "" || !identifierPattern.MatchString(role.Name) || !strings.HasPrefix(role.Name, prefix) || len(role.Name) > 63 {
			v = append(v, Violation{Code: CodeInvalidRegisteredIdentity, Section: "roles", ExpectedOrdinal: i})
		}
		if previous, ok := semanticIDs[role.SemanticID]; ok {
			v = append(v, Violation{Code: CodeDuplicateExpected, Section: "roles.semantic_id", ExpectedOrdinal: previous, ActualOrdinal: i})
		} else {
			semanticIDs[role.SemanticID] = i
		}
		if previous, ok := roleNames[role.Name]; ok {
			v = append(v, Violation{Code: CodeDuplicateExpected, Section: "roles.name", ExpectedOrdinal: previous, ActualOrdinal: i})
		} else {
			roleNames[role.Name] = i
		}
		if previous, ok := roleBindings[role.Binding]; ok {
			v = append(v, Violation{Code: CodeDuplicateExpected, Section: "roles.binding", ExpectedOrdinal: previous, ActualOrdinal: i})
		} else {
			roleBindings[role.Binding] = i
		}
		if !sort.StringsAreSorted(role.Properties.Configuration) || hasAdjacentDuplicate(role.Properties.Configuration) {
			v = append(v, Violation{Code: CodeInvalidRegisteredIdentity, Section: "roles.configuration", ExpectedOrdinal: i})
		}
	}
	principalIDs := map[string]int{}
	principalNames := map[string]int{}
	for i, principal := range manifest.Principals {
		if principal.SemanticID == "" || !identifierPattern.MatchString(principal.Name) || len(principal.Name) > 63 {
			v = append(v, Violation{Code: CodeInvalidRegisteredIdentity, Section: "principals", ExpectedOrdinal: i})
		}
		if _, roleConflict := semanticIDs[principal.SemanticID]; roleConflict {
			v = append(v, Violation{Code: CodeDuplicateExpected, Section: "principals.semantic_id", ExpectedOrdinal: i})
		}
		if previous, ok := principalIDs[principal.SemanticID]; ok {
			v = append(v, Violation{Code: CodeDuplicateExpected, Section: "principals.semantic_id", ExpectedOrdinal: previous, ActualOrdinal: i})
		} else {
			principalIDs[principal.SemanticID] = i
		}
		if _, roleConflict := roleNames[principal.Name]; roleConflict {
			v = append(v, Violation{Code: CodeDuplicateExpected, Section: "principals.name", ExpectedOrdinal: i})
		}
		if previous, ok := principalNames[principal.Name]; ok {
			v = append(v, Violation{Code: CodeDuplicateExpected, Section: "principals.name", ExpectedOrdinal: previous, ActualOrdinal: i})
		} else {
			principalNames[principal.Name] = i
		}
	}

	roleExists := func(id string) bool { _, ok := semanticIDs[id]; return ok }
	externalPrincipalExists := func(id string) bool { _, ok := principalIDs[id]; return ok }
	principalExists := func(id string) bool { return id == PublicPrincipal || roleExists(id) || externalPrincipalExists(id) }
	databaseNames := make(map[string]struct{}, len(manifest.Databases))
	for _, database := range manifest.Databases {
		databaseNames[database.Name] = struct{}{}
	}
	schemaNames := make(map[string]struct{}, len(manifest.Schemas))
	for _, schema := range manifest.Schemas {
		schemaNames[schema.Name] = struct{}{}
	}
	objectNames := make(map[string]struct{}, len(manifest.Objects))
	for _, object := range manifest.Objects {
		objectNames[objectStateIdentityKey(ObjectState{Schema: object.Schema, Name: object.Name, Kind: object.Kind})] = struct{}{}
	}
	for i, membership := range manifest.Memberships {
		if !roleExists(membership.Role) || !roleExists(membership.Member) || !principalExists(membership.Grantor) || membership.Grantor == PublicPrincipal {
			v = append(v, Violation{Code: CodeUnknownPrincipal, Section: "memberships", ExpectedOrdinal: i})
		}
		if membership.AdminOption {
			v = append(v, Violation{Code: CodeMembershipAdminEnabled, Section: "memberships", ExpectedOrdinal: i})
		}
	}
	for i, database := range manifest.Databases {
		sharedName := "stead_" + manifest.DeploymentKey
		if (database.Name != "stead" && database.Name != sharedName) || !roleExists(database.Owner) {
			v = append(v, Violation{Code: CodeInvalidRegisteredIdentity, Section: "databases", ExpectedOrdinal: i})
		}
	}
	for i, schema := range manifest.Schemas {
		if !identifierPattern.MatchString(schema.Name) || !principalExists(schema.Owner) || schema.Owner == PublicPrincipal {
			v = append(v, Violation{Code: CodeInvalidRegisteredIdentity, Section: "schemas", ExpectedOrdinal: i})
		}
	}
	for i, object := range manifest.Objects {
		_, knownSchema := schemaNames[object.Schema]
		if !knownSchema || !identifierPattern.MatchString(object.Schema) || !validObjectIdentity(object.Kind, object.Name) || !roleExists(object.Owner) {
			v = append(v, Violation{Code: CodeInvalidRegisteredIdentity, Section: "objects", ExpectedOrdinal: i})
		}
	}
	for section, entries := range map[string][]ACLSpec{"database_acls": manifest.DatabaseACLs, "schema_acls": manifest.SchemaACLs, "object_acls": manifest.ObjectACLs} {
		for i, acl := range entries {
			if !principalExists(acl.Grantor) || acl.Grantor == PublicPrincipal || !principalExists(acl.Grantee) {
				v = append(v, Violation{Code: CodeUnknownPrincipal, Section: section, ExpectedOrdinal: i})
			}
			if acl.Privilege == "" {
				v = append(v, Violation{Code: CodeInvalidRegisteredIdentity, Section: section, ExpectedOrdinal: i})
			}
			validResource := false
			switch section {
			case "database_acls":
				_, validResource = databaseNames[acl.Database]
				validResource = validResource && acl.Schema == "" && acl.Object == "" && acl.ObjectKind == ""
			case "schema_acls":
				_, validResource = schemaNames[acl.Schema]
				validResource = validResource && acl.Database == "" && acl.Object == "" && acl.ObjectKind == ""
			case "object_acls":
				_, validResource = objectNames[objectStateIdentityKey(ObjectState{Schema: acl.Schema, Name: acl.Object, Kind: acl.ObjectKind})]
				validResource = validResource && acl.Database == ""
			}
			if !validResource {
				v = append(v, Violation{Code: CodeInvalidRegisteredIdentity, Section: section, ExpectedOrdinal: i})
			}
		}
	}
	for i, acl := range manifest.DefaultACLs {
		_, knownSchema := schemaNames[acl.Schema]
		if acl.Schema == "" {
			knownSchema = true
		}
		if !roleExists(acl.Owner) || !principalExists(acl.Grantor) || acl.Grantor == PublicPrincipal || !principalExists(acl.Grantee) {
			v = append(v, Violation{Code: CodeUnknownPrincipal, Section: "default_acls", ExpectedOrdinal: i})
		}
		if !knownSchema || acl.ObjectKind == "" || acl.Privilege == "" {
			v = append(v, Violation{Code: CodeInvalidRegisteredIdentity, Section: "default_acls", ExpectedOrdinal: i})
		}
	}

	appendExpectedDuplicateViolations(&v, "memberships", manifest.Memberships, membershipSpecKey)
	appendExpectedDuplicateViolations(&v, "memberships.identity", manifest.Memberships, func(value MembershipSpec) string { return joinKey(value.Role, "\x00", value.Member) })
	appendExpectedDuplicateViolations(&v, "principals", manifest.Principals, principalSpecKey)
	appendExpectedDuplicateViolations(&v, "databases", manifest.Databases, databaseSpecKey)
	appendExpectedDuplicateViolations(&v, "databases.identity", manifest.Databases, func(value DatabaseSpec) string { return value.Name })
	appendExpectedDuplicateViolations(&v, "schemas", manifest.Schemas, schemaSpecKey)
	appendExpectedDuplicateViolations(&v, "schemas.identity", manifest.Schemas, func(value SchemaSpec) string { return value.Name })
	appendExpectedDuplicateViolations(&v, "objects", manifest.Objects, objectSpecKey)
	appendExpectedDuplicateViolations(&v, "objects.identity", manifest.Objects, func(value ObjectSpec) string {
		return objectStateIdentityKey(ObjectState{Schema: value.Schema, Name: value.Name, Kind: value.Kind})
	})
	appendExpectedDuplicateViolations(&v, "database_acls", manifest.DatabaseACLs, aclSpecKey)
	appendExpectedDuplicateViolations(&v, "schema_acls", manifest.SchemaACLs, aclSpecKey)
	appendExpectedDuplicateViolations(&v, "object_acls", manifest.ObjectACLs, aclSpecKey)
	appendExpectedDuplicateViolations(&v, "default_acls", manifest.DefaultACLs, defaultACLSpecKey)
	return violationsError(v)
}

func Compare(manifest Manifest, snapshot Snapshot) error {
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	v := make([]Violation, 0)
	if snapshot.ServerVersion < MinimumServerVersion {
		v = append(v, Violation{Code: CodeServerVersionUnsupported, Section: "server"})
	}

	roleByID := make(map[string]string, len(manifest.Roles))
	knownNames := make(map[string]struct{}, len(manifest.Roles)+len(manifest.Principals))
	for _, role := range manifest.Roles {
		roleByID[role.SemanticID] = role.Name
		knownNames[role.Name] = struct{}{}
	}
	for _, principal := range manifest.Principals {
		roleByID[principal.SemanticID] = principal.Name
		knownNames[principal.Name] = struct{}{}
	}
	principalName := func(id string) string {
		if id == PublicPrincipal {
			return PublicPrincipal
		}
		return roleByID[id]
	}
	checkActualPrincipal := func(section string, ordinal int, names ...string) {
		for _, name := range names {
			if name == PublicPrincipal {
				continue
			}
			if _, ok := knownNames[name]; !ok {
				v = append(v, Violation{Code: CodeUnknownPrincipal, Section: section, ActualOrdinal: ordinal})
				return
			}
		}
	}

	expectedRoles := make([]RoleState, 0, len(manifest.Roles))
	for _, role := range manifest.Roles {
		expectedRoles = append(expectedRoles, RoleState{Name: role.Name, Binding: role.Binding, Properties: role.Properties})
	}
	compareKeyed(&v, "roles", expectedRoles, snapshot.Roles, roleStateIdentityKey, roleStateFullKey)

	expectedMemberships := make([]MembershipState, 0, len(manifest.Memberships))
	for _, edge := range manifest.Memberships {
		expectedMemberships = append(expectedMemberships, MembershipState{
			Role: principalName(edge.Role), Member: principalName(edge.Member), Grantor: principalName(edge.Grantor),
			AdminOption: edge.AdminOption, InheritOption: edge.InheritOption, SetOption: edge.SetOption,
		})
	}
	for i, edge := range snapshot.Memberships {
		checkActualPrincipal("memberships", i, edge.Role, edge.Member, edge.Grantor)
		if edge.AdminOption {
			v = append(v, Violation{Code: CodeMembershipAdminEnabled, Section: "memberships", ActualOrdinal: i})
		}
	}
	compareSet(&v, "memberships", expectedMemberships, snapshot.Memberships, membershipStateKey)

	expectedDatabases := make([]DatabaseState, 0, len(manifest.Databases))
	for _, database := range manifest.Databases {
		expectedDatabases = append(expectedDatabases, DatabaseState{Name: database.Name, Owner: principalName(database.Owner)})
	}
	for i, database := range snapshot.Databases {
		checkActualPrincipal("databases", i, database.Owner)
	}
	compareKeyed(&v, "databases", expectedDatabases, snapshot.Databases, func(value DatabaseState) string { return value.Name }, databaseStateKey)

	expectedSchemas := make([]SchemaState, 0, len(manifest.Schemas))
	for _, schema := range manifest.Schemas {
		expectedSchemas = append(expectedSchemas, SchemaState{Name: schema.Name, Owner: principalName(schema.Owner)})
	}
	for i, schema := range snapshot.Schemas {
		checkActualPrincipal("schemas", i, schema.Owner)
	}
	compareKeyed(&v, "schemas", expectedSchemas, snapshot.Schemas, func(value SchemaState) string { return value.Name }, schemaStateKey)

	expectedObjects := make([]ObjectState, 0, len(manifest.Objects))
	for _, object := range manifest.Objects {
		expectedObjects = append(expectedObjects, ObjectState{Schema: object.Schema, Name: object.Name, Kind: object.Kind, Owner: principalName(object.Owner)})
	}
	for i, object := range snapshot.Objects {
		checkActualPrincipal("objects", i, object.Owner)
	}
	compareKeyed(&v, "objects", expectedObjects, snapshot.Objects, objectStateIdentityKey, objectStateKey)

	convertACLs := func(specs []ACLSpec) []ACLState {
		states := make([]ACLState, 0, len(specs))
		for _, acl := range specs {
			states = append(states, ACLState{Database: acl.Database, Schema: acl.Schema, Object: acl.Object, ObjectKind: acl.ObjectKind, Grantor: principalName(acl.Grantor), Grantee: principalName(acl.Grantee), Privilege: acl.Privilege, GrantOption: acl.GrantOption})
		}
		return states
	}
	for _, group := range []struct {
		section  string
		expected []ACLState
		actual   []ACLState
	}{
		{"database_acls", convertACLs(manifest.DatabaseACLs), snapshot.DatabaseACLs},
		{"schema_acls", convertACLs(manifest.SchemaACLs), snapshot.SchemaACLs},
		{"object_acls", convertACLs(manifest.ObjectACLs), snapshot.ObjectACLs},
	} {
		for i, acl := range group.actual {
			checkActualPrincipal(group.section, i, acl.Grantor, acl.Grantee)
		}
		compareSet(&v, group.section, group.expected, group.actual, aclStateKey)
	}

	expectedDefaults := make([]DefaultACLState, 0, len(manifest.DefaultACLs))
	for _, acl := range manifest.DefaultACLs {
		expectedDefaults = append(expectedDefaults, DefaultACLState{Owner: principalName(acl.Owner), Schema: acl.Schema, ObjectKind: acl.ObjectKind, Grantor: principalName(acl.Grantor), Grantee: principalName(acl.Grantee), Privilege: acl.Privilege, GrantOption: acl.GrantOption})
	}
	for i, acl := range snapshot.DefaultACLs {
		checkActualPrincipal("default_acls", i, acl.Owner, acl.Grantor, acl.Grantee)
	}
	compareSet(&v, "default_acls", expectedDefaults, snapshot.DefaultACLs, defaultACLStateKey)

	for i, acl := range snapshot.ColumnACLs {
		checkActualPrincipal("column_acls", i, acl.Owner, acl.Grantor, acl.Grantee)
		v = append(v, Violation{Code: CodeColumnACLPresent, Section: "column_acls", ActualOrdinal: i})
	}
	return violationsError(v)
}

func compareKeyed[T any](violations *[]Violation, section string, expected, actual []T, identityKey, fullKey func(T) string) {
	expectedIdentity := indexKeys(violations, section, expected, identityKey, true)
	actualIdentity := indexKeys(violations, section, actual, identityKey, false)
	for identity, expectedOrdinal := range expectedIdentity {
		actualOrdinal, ok := actualIdentity[identity]
		if !ok {
			*violations = append(*violations, Violation{Code: CodeMissingState, Section: section, ExpectedOrdinal: expectedOrdinal})
			continue
		}
		if fullKey(expected[expectedOrdinal]) != fullKey(actual[actualOrdinal]) {
			*violations = append(*violations, Violation{Code: CodePropertyDrift, Section: section, ExpectedOrdinal: expectedOrdinal, ActualOrdinal: actualOrdinal})
		}
	}
	for identity, actualOrdinal := range actualIdentity {
		if _, ok := expectedIdentity[identity]; !ok {
			*violations = append(*violations, Violation{Code: CodeExtraState, Section: section, ActualOrdinal: actualOrdinal})
		}
	}
}

func compareSet[T any](violations *[]Violation, section string, expected, actual []T, key func(T) string) {
	expectedKeys := indexKeys(violations, section, expected, key, true)
	actualKeys := indexKeys(violations, section, actual, key, false)
	for value, ordinal := range expectedKeys {
		if _, ok := actualKeys[value]; !ok {
			*violations = append(*violations, Violation{Code: CodeMissingState, Section: section, ExpectedOrdinal: ordinal})
		}
	}
	for value, ordinal := range actualKeys {
		if _, ok := expectedKeys[value]; !ok {
			*violations = append(*violations, Violation{Code: CodeExtraState, Section: section, ActualOrdinal: ordinal})
		}
	}
}

func indexKeys[T any](violations *[]Violation, section string, values []T, key func(T) string, expected bool) map[string]int {
	result := make(map[string]int, len(values))
	for i, value := range values {
		valueKey := key(value)
		if previous, ok := result[valueKey]; ok {
			code := CodeDuplicateActual
			if expected {
				code = CodeDuplicateExpected
			}
			*violations = append(*violations, Violation{Code: code, Section: section, ExpectedOrdinal: previous, ActualOrdinal: i})
			continue
		}
		result[valueKey] = i
	}
	return result
}

func appendExpectedDuplicateViolations[T any](violations *[]Violation, section string, values []T, key func(T) string) {
	indexKeys(violations, section, values, key, true)
}

func violationsError(violations []Violation) error {
	if len(violations) == 0 {
		return nil
	}
	sort.SliceStable(violations, func(i, j int) bool {
		left, right := violations[i], violations[j]
		if left.Section != right.Section {
			return left.Section < right.Section
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if left.ExpectedOrdinal != right.ExpectedOrdinal {
			return left.ExpectedOrdinal < right.ExpectedOrdinal
		}
		return left.ActualOrdinal < right.ActualOrdinal
	})
	return &ConformanceError{violations: violations}
}

func hasAdjacentDuplicate(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i] == values[i-1] {
			return true
		}
	}
	return false
}

func validObjectIdentity(kind, name string) bool {
	validKinds := map[string]struct{}{
		"table": {}, "sequence": {}, "view": {}, "materialized_view": {}, "foreign_table": {},
		"function": {}, "procedure": {}, "aggregate": {}, "type": {}, "domain": {},
	}
	if _, ok := validKinds[kind]; !ok || name == "" || len(name) > 1024 || strings.IndexFunc(name, func(value rune) bool { return value < ' ' }) >= 0 {
		return false
	}
	if kind != "function" && kind != "procedure" && kind != "aggregate" {
		return identifierPattern.MatchString(name)
	}
	open := strings.IndexByte(name, '(')
	return open > 0 && strings.HasSuffix(name, ")") && identifierPattern.MatchString(name[:open])
}

func joinKey(values ...any) string { return fmt.Sprint(values...) }

func roleStateIdentityKey(value RoleState) string { return value.Name }
func roleStateFullKey(value RoleState) string {
	properties := value.Properties
	configuration := append([]string(nil), properties.Configuration...)
	sort.Strings(configuration)
	return joinKey(value.Name, "\x00", value.Binding, "\x00", properties.Superuser, properties.Inherit, properties.CreateRole, properties.CreateDatabase, properties.Login, properties.Replication, properties.BypassRLS, properties.ConnectionLimit, properties.PasswordPresent, properties.ValidUntilUTC, strings.Join(configuration, "\x1f"))
}
func membershipSpecKey(value MembershipSpec) string {
	return joinKey(value.Role, "\x00", value.Member, "\x00", value.Grantor, "\x00", value.AdminOption, value.InheritOption, value.SetOption)
}
func membershipStateKey(value MembershipState) string {
	return joinKey(value.Role, "\x00", value.Member, "\x00", value.Grantor, "\x00", value.AdminOption, value.InheritOption, value.SetOption)
}
func databaseSpecKey(value DatabaseSpec) string { return joinKey(value.Name, "\x00", value.Owner) }
func principalSpecKey(value PrincipalSpec) string {
	return joinKey(value.SemanticID, "\x00", value.Name)
}
func databaseStateKey(value DatabaseState) string { return joinKey(value.Name, "\x00", value.Owner) }
func schemaSpecKey(value SchemaSpec) string       { return joinKey(value.Name, "\x00", value.Owner) }
func schemaStateKey(value SchemaState) string     { return joinKey(value.Name, "\x00", value.Owner) }
func objectSpecKey(value ObjectSpec) string {
	return joinKey(value.Schema, "\x00", value.Name, "\x00", value.Kind, "\x00", value.Owner)
}
func objectStateIdentityKey(value ObjectState) string {
	return joinKey(value.Schema, "\x00", value.Name, "\x00", value.Kind)
}
func objectStateKey(value ObjectState) string {
	return joinKey(value.Schema, "\x00", value.Name, "\x00", value.Kind, "\x00", value.Owner)
}
func aclSpecKey(value ACLSpec) string {
	return joinKey(value.Database, "\x00", value.Schema, "\x00", value.Object, "\x00", value.ObjectKind, "\x00", value.Grantor, "\x00", value.Grantee, "\x00", value.Privilege, "\x00", value.GrantOption)
}
func aclStateKey(value ACLState) string {
	return joinKey(value.Database, "\x00", value.Schema, "\x00", value.Object, "\x00", value.ObjectKind, "\x00", value.Grantor, "\x00", value.Grantee, "\x00", value.Privilege, "\x00", value.GrantOption)
}
func defaultACLSpecKey(value DefaultACLSpec) string {
	return joinKey(value.Owner, "\x00", value.Schema, "\x00", value.ObjectKind, "\x00", value.Grantor, "\x00", value.Grantee, "\x00", value.Privilege, "\x00", value.GrantOption)
}
func defaultACLStateKey(value DefaultACLState) string {
	return joinKey(value.Owner, "\x00", value.Schema, "\x00", value.ObjectKind, "\x00", value.Grantor, "\x00", value.Grantee, "\x00", value.Privilege, "\x00", value.GrantOption)
}
