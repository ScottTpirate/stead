package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	catalogSearchPathSQL             = `SET LOCAL search_path = pg_catalog, pg_temp`
	catalogSearchPathVerificationSQL = `SELECT pg_catalog.current_setting('search_path')`
	catalogSearchPath                = "pg_catalog, pg_temp"
)

// SQLCollector executes CatalogQueryContracts through database/sql. The
// application supplies its approved PostgreSQL driver elsewhere; this package
// intentionally registers none.
type SQLCollector struct {
	db *sql.DB
}

func NewSQLCollector(db *sql.DB) *SQLCollector { return &SQLCollector{db: db} }

func (collector *SQLCollector) Collect(ctx context.Context, manifest Manifest) (snapshot Snapshot, err error) {
	if collector == nil || collector.db == nil {
		return Snapshot{}, errors.New("postgres catalog collector is not configured")
	}
	tx, err := collector.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Snapshot{}, errors.New("postgres catalog snapshot transaction failed")
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, execErr := tx.ExecContext(ctx, catalogSearchPathSQL); execErr != nil {
		return Snapshot{}, errors.New("postgres catalog search path setup failed")
	}
	var observedSearchPath string
	if queryErr := tx.QueryRowContext(ctx, catalogSearchPathVerificationSQL).Scan(&observedSearchPath); queryErr != nil || observedSearchPath != catalogSearchPath {
		return Snapshot{}, errors.New("postgres catalog search path verification failed")
	}

	prefix := "sd_" + manifest.DeploymentKey + "_"
	for _, contract := range CatalogQueryContracts() {
		args := make([]any, 0, len(contract.Args))
		for _, name := range contract.Args {
			switch name {
			case "deployment_role_prefix":
				args = append(args, prefix)
			default:
				return Snapshot{}, errors.New("postgres catalog query argument contract failed")
			}
		}
		rows, queryErr := tx.QueryContext(ctx, contract.SQL, args...)
		if queryErr != nil {
			return Snapshot{}, fmt.Errorf("postgres catalog query failed: %s", contract.Name)
		}
		if scanErr := scanContract(contract.Name, rows, &snapshot); scanErr != nil {
			_ = rows.Close()
			return Snapshot{}, fmt.Errorf("postgres catalog scan failed: %s", contract.Name)
		}
		if closeErr := rows.Close(); closeErr != nil {
			return Snapshot{}, fmt.Errorf("postgres catalog close failed: %s", contract.Name)
		}
	}
	if err = tx.Commit(); err != nil {
		return Snapshot{}, errors.New("postgres catalog snapshot commit failed")
	}
	return snapshot, nil
}

func scanContract(name string, rows *sql.Rows, snapshot *Snapshot) error {
	for rows.Next() {
		switch name {
		case "server_version":
			if err := rows.Scan(&snapshot.ServerVersion); err != nil {
				return err
			}
		case "roles":
			var value RoleState
			var configurationJSON string
			properties := &value.Properties
			if err := rows.Scan(&value.Name, &value.Binding, &properties.Superuser, &properties.Inherit, &properties.CreateRole, &properties.CreateDatabase, &properties.Login, &properties.Replication, &properties.BypassRLS, &properties.ConnectionLimit, &properties.PasswordPresent, &properties.ValidUntilUTC, &configurationJSON); err != nil {
				return err
			}
			configuration, err := decodeRoleConfiguration(configurationJSON)
			if err != nil {
				return err
			}
			properties.Configuration = configuration
			snapshot.Roles = append(snapshot.Roles, value)
		case "memberships":
			var value MembershipState
			if err := rows.Scan(&value.Role, &value.Member, &value.Grantor, &value.AdminOption, &value.InheritOption, &value.SetOption); err != nil {
				return err
			}
			snapshot.Memberships = append(snapshot.Memberships, value)
		case "databases":
			var value DatabaseState
			if err := rows.Scan(&value.Name, &value.Owner); err != nil {
				return err
			}
			snapshot.Databases = append(snapshot.Databases, value)
		case "database_acls":
			var value ACLState
			if err := rows.Scan(&value.Database, &value.Grantor, &value.Grantee, &value.Privilege, &value.GrantOption); err != nil {
				return err
			}
			snapshot.DatabaseACLs = append(snapshot.DatabaseACLs, value)
		case "schemas":
			var value SchemaState
			if err := rows.Scan(&value.Name, &value.Owner); err != nil {
				return err
			}
			snapshot.Schemas = append(snapshot.Schemas, value)
		case "schema_acls":
			var value ACLState
			if err := rows.Scan(&value.Schema, &value.Grantor, &value.Grantee, &value.Privilege, &value.GrantOption); err != nil {
				return err
			}
			snapshot.SchemaACLs = append(snapshot.SchemaACLs, value)
		case "objects":
			var value ObjectState
			if err := rows.Scan(&value.Schema, &value.Name, &value.Kind, &value.Owner); err != nil {
				return err
			}
			snapshot.Objects = append(snapshot.Objects, value)
		case "object_acls":
			var value ACLState
			if err := rows.Scan(&value.Schema, &value.Object, &value.ObjectKind, &value.Grantor, &value.Grantee, &value.Privilege, &value.GrantOption); err != nil {
				return err
			}
			snapshot.ObjectACLs = append(snapshot.ObjectACLs, value)
		case "default_acls":
			var value DefaultACLState
			if err := rows.Scan(&value.Owner, &value.Schema, &value.ObjectKind, &value.Grantor, &value.Grantee, &value.Privilege, &value.GrantOption); err != nil {
				return err
			}
			snapshot.DefaultACLs = append(snapshot.DefaultACLs, value)
		case "column_acls":
			var value ColumnACLState
			if err := rows.Scan(&value.Schema, &value.Relation, &value.Column, &value.Owner, &value.Grantor, &value.Grantee, &value.Privilege, &value.GrantOption); err != nil {
				return err
			}
			snapshot.ColumnACLs = append(snapshot.ColumnACLs, value)
		default:
			return errors.New("unknown postgres catalog query contract")
		}
	}
	return rows.Err()
}

func decodeRoleConfiguration(encoded string) ([]string, error) {
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var configuration []string
	if err := decoder.Decode(&configuration); err != nil || configuration == nil {
		return nil, errors.New("postgres role configuration decode failed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("postgres role configuration has trailing data")
	}
	if !sort.StringsAreSorted(configuration) || hasAdjacentDuplicate(configuration) {
		return nil, errors.New("postgres role configuration is not canonical")
	}
	return configuration, nil
}
