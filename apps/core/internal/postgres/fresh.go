package postgres

import (
	"context"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"
)

var databaseName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

func bootstrapDatabaseName(value string) bool {
	return databaseName.MatchString(value) && value != "postgres" && value != "template0" && value != "template1" && value != "gitea" && value != "openfga"
}

// CheckFreshBootstrapDatabase is a read-only preflight before local signing or
// provider preparation. The executable supplies its fixed expected database
// name separately from the DSN. ACL isolation of the pristine database is
// permitted; existing application objects, extensions or clients are not.
func CheckFreshBootstrapDatabase(ctx context.Context, adminDSN, expectedDatabase string) error {
	config, err := pgx.ParseConfig(adminDSN)
	if err != nil || !bootstrapDatabaseName(expectedDatabase) || config.Database != expectedDatabase {
		return errors.New("bootstrap database identity rejected")
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return errors.New("bootstrap database unavailable")
	}
	defer conn.Close(ctx)
	return checkFreshDatabase(ctx, conn, expectedDatabase)
}

type freshDatabaseQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func checkFreshDatabase(ctx context.Context, db freshDatabaseQuery, expected string) error {
	if !bootstrapDatabaseName(expected) {
		return errors.New("bootstrap database identity rejected")
	}
	var database string
	var version int
	var template, utf8, occupied, dirty bool
	err := db.QueryRow(ctx, `SELECT current_database(),current_setting('server_version_num')::integer,d.datistemplate,pg_encoding_to_char(d.encoding)='UTF8',
 EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity a WHERE a.datid=d.oid AND a.pid<>pg_backend_pid() AND a.backend_type='client backend'),
 EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname NOT IN ('pg_catalog','pg_toast','information_schema','public'))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='public')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relnamespace NOT IN ('pg_catalog'::regnamespace,'pg_toast'::regnamespace,'information_schema'::regnamespace))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc WHERE pronamespace NOT IN ('pg_catalog'::regnamespace,'information_schema'::regnamespace))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_type WHERE typnamespace NOT IN ('pg_catalog'::regnamespace,'pg_toast'::regnamespace,'information_schema'::regnamespace))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_operator WHERE oprnamespace<>'pg_catalog'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_opclass WHERE opcnamespace<>'pg_catalog'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_opfamily WHERE opfnamespace<>'pg_catalog'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_collation WHERE collnamespace<>'pg_catalog'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_conversion WHERE connamespace<>'pg_catalog'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_ts_config WHERE cfgnamespace<>'pg_catalog'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_ts_dict WHERE dictnamespace<>'pg_catalog'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_ts_parser WHERE prsnamespace<>'pg_catalog'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_ts_template WHERE tmplnamespace<>'pg_catalog'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_extension WHERE extname<>'plpgsql' OR extnamespace<>'pg_catalog'::regnamespace OR extversion<>'1.0')
 OR (SELECT count(*) FROM pg_catalog.pg_extension WHERE extname='plpgsql')<>1
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_event_trigger)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_foreign_data_wrapper)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_foreign_server)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_publication)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_subscription WHERE subdbid=d.oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_largeobject_metadata)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_db_role_setting WHERE setdatabase=d.oid)
 FROM pg_catalog.pg_database d WHERE d.datname=current_database()`).Scan(&database, &version, &template, &utf8, &occupied, &dirty)
	if err != nil || database != expected || version < MinimumServerVersion || template || !utf8 || occupied || dirty {
		return errors.New("bootstrap requires a fresh isolated database")
	}
	return nil
}
