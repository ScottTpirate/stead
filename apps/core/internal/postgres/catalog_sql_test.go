package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

var catalogDriverSequence atomic.Uint64

func TestSQLCollectorReadsOneExactSnapshot(t *testing.T) {
	manifest := loadCoreOutboxManifest(t)
	manifest.Objects = append(manifest.Objects, ObjectSpec{Schema: "core_outbox", Name: "event_intents", Kind: "table", Owner: "core_outbox_owner"})
	manifest.ObjectACLs = append(manifest.ObjectACLs,
		ACLSpec{Schema: "core_outbox", Object: "event_intents", ObjectKind: "table", Grantor: "core_outbox_owner", Grantee: "core_outbox_owner", Privilege: "SELECT"},
		ACLSpec{Schema: "core_outbox", Object: "event_intents", ObjectKind: "table", Grantor: "core_outbox_owner", Grantee: "core_outbox_read_write", Privilege: "SELECT"},
	)
	want := snapshotForManifest(manifest)
	database := openCatalogTestDatabase(t, catalogTestDriver{snapshot: want})

	collector := NewSQLCollector(database)
	got, err := collector.Collect(context.Background(), manifest)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if err := Compare(manifest, got); err != nil {
		t.Fatalf("collected snapshot mismatch: %v", err)
	}
	if err := Verify(context.Background(), manifest, collector); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestSQLCollectorAndVerifyFailWithoutLeakingDriverError(t *testing.T) {
	manifest := loadCoreOutboxManifest(t)
	database := openCatalogTestDatabase(t, catalogTestDriver{snapshot: snapshotForManifest(manifest), failQuery: "memberships"})
	err := Verify(context.Background(), manifest, NewSQLCollector(database))
	assertViolationCode(t, err, CodeCatalogQueryFailed)
	if strings.Contains(err.Error(), "protected driver detail") {
		t.Fatal("Verify exposed collector detail")
	}

	if _, err := NewSQLCollector(nil).Collect(context.Background(), manifest); err == nil {
		t.Fatal("nil SQLCollector database did not fail")
	}
	assertViolationCode(t, Verify(context.Background(), manifest, nil), CodeCatalogQueryFailed)
}

type catalogTestDriver struct {
	snapshot  Snapshot
	failQuery string
}

func (value catalogTestDriver) Open(string) (driver.Conn, error) {
	return &catalogTestConnection{driver: value}, nil
}

type catalogTestConnection struct {
	driver catalogTestDriver
}

func (connection *catalogTestConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}
func (connection *catalogTestConnection) Close() error { return nil }
func (connection *catalogTestConnection) Begin() (driver.Tx, error) {
	return catalogTestTransaction{}, nil
}
func (connection *catalogTestConnection) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	if !options.ReadOnly || options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("unexpected catalog transaction options")
	}
	return catalogTestTransaction{}, nil
}
func (connection *catalogTestConnection) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	var contract QueryContract
	found := false
	for _, candidate := range CatalogQueryContracts() {
		if candidate.SQL == query {
			contract = candidate
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("unknown query")
	}
	if contract.Name == connection.driver.failQuery {
		return nil, errors.New("protected driver detail")
	}
	if len(args) != len(contract.Args) {
		return nil, errors.New("wrong argument count")
	}
	if len(args) == 1 {
		prefix, ok := args[0].Value.(string)
		if !ok || !strings.HasPrefix(prefix, "sd_") || !strings.HasSuffix(prefix, "_") {
			return nil, errors.New("wrong deployment prefix")
		}
	}
	return catalogRows(contract, connection.driver.snapshot), nil
}

type catalogTestTransaction struct{}

func (catalogTestTransaction) Commit() error   { return nil }
func (catalogTestTransaction) Rollback() error { return nil }

type catalogTestRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (rows *catalogTestRows) Columns() []string { return append([]string(nil), rows.columns...) }
func (rows *catalogTestRows) Close() error      { return nil }
func (rows *catalogTestRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}

func catalogRows(contract QueryContract, snapshot Snapshot) driver.Rows {
	rows := &catalogTestRows{columns: contract.Columns}
	appendRow := func(values ...driver.Value) { rows.values = append(rows.values, values) }
	switch contract.Name {
	case "server_version":
		appendRow(int64(snapshot.ServerVersion))
	case "roles":
		for _, value := range snapshot.Roles {
			properties := value.Properties
			appendRow(value.Name, value.Binding, properties.Superuser, properties.Inherit, properties.CreateRole, properties.CreateDatabase, properties.Login, properties.Replication, properties.BypassRLS, int64(properties.ConnectionLimit), properties.PasswordPresent, properties.ValidUntilUTC, strings.Join(properties.Configuration, "\x1f"))
		}
	case "memberships":
		for _, value := range snapshot.Memberships {
			appendRow(value.Role, value.Member, value.Grantor, value.AdminOption, value.InheritOption, value.SetOption)
		}
	case "databases":
		for _, value := range snapshot.Databases {
			appendRow(value.Name, value.Owner)
		}
	case "database_acls":
		for _, value := range snapshot.DatabaseACLs {
			appendRow(value.Database, value.Grantor, value.Grantee, value.Privilege, value.GrantOption)
		}
	case "schemas":
		for _, value := range snapshot.Schemas {
			appendRow(value.Name, value.Owner)
		}
	case "schema_acls":
		for _, value := range snapshot.SchemaACLs {
			appendRow(value.Schema, value.Grantor, value.Grantee, value.Privilege, value.GrantOption)
		}
	case "objects":
		for _, value := range snapshot.Objects {
			appendRow(value.Schema, value.Name, value.Kind, value.Owner)
		}
	case "object_acls":
		for _, value := range snapshot.ObjectACLs {
			appendRow(value.Schema, value.Object, value.ObjectKind, value.Grantor, value.Grantee, value.Privilege, value.GrantOption)
		}
	case "default_acls":
		for _, value := range snapshot.DefaultACLs {
			appendRow(value.Owner, value.Schema, value.ObjectKind, value.Grantor, value.Grantee, value.Privilege, value.GrantOption)
		}
	case "column_acls":
		for _, value := range snapshot.ColumnACLs {
			appendRow(value.Schema, value.Relation, value.Column, value.Owner, value.Grantor, value.Grantee, value.Privilege, value.GrantOption)
		}
	default:
		panic(fmt.Sprintf("unimplemented query contract %s", contract.Name))
	}
	return rows
}

func openCatalogTestDatabase(t *testing.T, value catalogTestDriver) *sql.DB {
	t.Helper()
	name := fmt.Sprintf("stead_catalog_test_%d", catalogDriverSequence.Add(1))
	sql.Register(name, value)
	database, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}
