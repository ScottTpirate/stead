package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Config is trusted process configuration, never a request DTO. The runtime
// connection must use this installation's NOINHERIT API login, not an owner.
type Config struct {
	DSN, InstanceID, SecurityDomain, OpenFGAStoreID string
	Anchor                                          authorization.PolicyTimeAnchor
}
type Store struct {
	pool         *pgxpool.Pool
	config       Config
	prefix       string
	mutex        sync.Mutex
	sessions     map[transaction.ExecutorBinding]*runtimeSession
	contract     transaction.BackendContract
	coordinator  *transaction.Coordinator
	registry     transaction.Registry
	createPlan   transaction.PlanContract[command]
	readPlan     transaction.PlanContract[command]
	activatePlan transaction.PlanContract[command]
	// Committed local operation provenance, never drain/terminal authority.
	// A new Store after restart cannot attribute recovery to the old User.
	effectOrigins map[string]authorization.EffectRecord
}

func DeploymentKey(instance string) string {
	sum := sha256.Sum256([]byte(instance))
	return hex.EncodeToString(sum[:8])
}
func RuntimeRole(instance string) string { return "sd_" + DeploymentKey(instance) + "_api" }

func Open(ctx context.Context, config Config) (*Store, error) {
	if !identity.ValidID(config.InstanceID) || config.SecurityDomain == "" || config.OpenFGAStoreID == "" || config.Anchor == nil {
		return nil, errors.New("invalid database configuration")
	}
	parsed, err := pgxpool.ParseConfig(config.DSN)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	if parsed.ConnConfig.User != RuntimeRole(config.InstanceID) {
		return nil, errors.New("database runtime identity mismatch")
	}
	parsed.MaxConns = 8
	parsed.MinConns = 0
	parsed.ConnConfig.RuntimeParams["search_path"] = "pg_catalog, pg_temp"
	parsed.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	parsed.ConnConfig.RuntimeParams["lock_timeout"] = "2000"
	parsed.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "5000"
	pool, err := pgxpool.NewWithConfig(ctx, parsed)
	if err != nil {
		return nil, errors.New("database unavailable")
	}
	store := &Store{pool: pool, config: config, prefix: "sd_" + DeploymentKey(config.InstanceID) + "_", sessions: make(map[transaction.ExecutorBinding]*runtimeSession)}
	if err = store.Health(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err = store.register(); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}
func (store *Store) Close() {
	if store != nil && store.pool != nil {
		store.pool.Close()
	}
}
func (store *Store) Health(ctx context.Context) error {
	var version int
	var user string
	var unsafe bool
	err := store.pool.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer,current_user,rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR rolinherit FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&version, &user, &unsafe)
	if err != nil || version < MinimumServerVersion || user != RuntimeRole(store.config.InstanceID) || unsafe {
		return errors.New("database runtime readiness denied")
	}
	return nil
}

// UUIDv7 is generated only at the trusted owner boundary; no client can select
// a canonical ID, timestamp, actor, or initial security label.
func NewID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	ms := uint64(time.Now().UnixMilli())
	for index := 5; index >= 0; index-- {
		value[index] = byte(ms)
		ms >>= 8
	}
	value[6] = (value[6] & 15) | 0x70
	value[8] = (value[8] & 63) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[:4], value[4:6], value[6:8], value[8:10], value[10:]), nil
}

type runtimeSession struct {
	store           *Store
	tx              pgx.Tx
	binding         transaction.ExecutorBinding
	states          []authorization.State
	identity        identity.SessionRecord
	label           classification.Label
	result          organization.Resource
	raw             []byte
	replay          bool
	pending         bool
	grant           []authorization.Tuple
	depth           int
	queries, writes uint64
}

func (store *Store) Begin(ctx context.Context) (transaction.BeginResult, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	count(ctx, 1, 0, 0, 0)
	if err != nil {
		return transaction.BeginResult{}, err
	}
	session := &runtimeSession{store: store, tx: tx}
	result, binding, err := transaction.NewBeginResult(session)
	if err != nil {
		_ = tx.Rollback(ctx)
		return transaction.BeginResult{}, err
	}
	session.binding = binding
	store.mutex.Lock()
	store.sessions[binding] = session
	store.mutex.Unlock()
	return result, nil
}
func (session *runtimeSession) finish() {
	session.store.mutex.Lock()
	delete(session.store.sessions, session.binding)
	session.store.mutex.Unlock()
}
func (session *runtimeSession) Commit(ctx context.Context) error {
	defer session.finish()
	err := session.tx.Commit(ctx)
	count(ctx, 1, 0, 0, 0)
	if err == nil {
		if result, ok := ctx.Value(resultKey{}).(*executionResult); ok {
			result.raw = append([]byte(nil), session.raw...)
			result.pending = session.pending
			result.queries = session.queries
			result.writes = session.writes
		}
	}
	return err
}
func (session *runtimeSession) Rollback(ctx context.Context) error {
	defer session.finish()
	err := session.tx.Rollback(ctx)
	if !errors.Is(err, pgx.ErrTxClosed) {
		count(ctx, 1, 0, 0, 0)
	}
	return err
}
func (store *Store) session(binding transaction.ExecutorBinding) (*runtimeSession, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	session := store.sessions[binding]
	if session == nil {
		return nil, authorization.ErrDenied
	}
	return session, nil
}
func (session *runtimeSession) role(ctx context.Context, owner string) error {
	_, err := session.tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{session.store.prefix + owner + "_execute"}.Sanitize())
	session.queries++
	count(ctx, 1, 0, 0, 0)
	return err
}

func (store *Store) owned(ctx context.Context, owner string, write bool, fn func(pgx.Tx) error) error {
	mode := pgx.ReadOnly
	if write {
		mode = pgx.ReadWrite
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: mode})
	count(ctx, 1, 0, 0, 0)
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(ctx); !errors.Is(err, pgx.ErrTxClosed) {
			count(ctx, 1, 0, 0, 0)
		}
	}()
	_, err = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{store.prefix + owner + "_execute"}.Sanitize())
	count(ctx, 1, 0, 0, 0)
	if err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	err = tx.Commit(ctx)
	count(ctx, 1, 0, 0, 0)
	return err
}

func encode(value any) []byte { data, _ := json.Marshal(value); return data }

type resultKey struct{}
type executionResult struct {
	raw             []byte
	pending         bool
	queries, writes uint64
	failure         error
}
