//go:build linux

package postgres

// Test-only parsing and fixed read-only evidence queries. No product endpoint,
// schema, privilege, fixture initializer or bootstrap authority is introduced.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ScottTpirate/stead/apps/core/internal/localdev"
	"github.com/jackc/pgx/v5"
)

var checkpointEvidenceRejected = errors.New("checkpoint A SQL evidence rejected")
var checkpointHex = regexp.MustCompile(`^[0-9a-f]{64}$`)
var checkpointCorrelation = regexp.MustCompile(`^[0-9a-f]{32}$`)
var checkpointUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const checkpointNode = "/tmp/stead-node-toolchain-26.8.1/toolchain/node-v26.8.1-linux-x64/bin/node"
const checkpointNodeHash = "19235a9b678f84729464c52623f92de130a165452747c6826d3fdc13df3abcc3"

var checkpointSources = []string{"scripts/checkpoint_a_followon.mjs", "scripts/checkpoint_a_smoke.mjs", "scripts/checkpoint_a_denial.mjs", "scripts/checkpoint_a_browser.mjs", "scripts/checkpoint_a_browser_boundary.mjs", "packages/api-client/src/client.ts", "packages/api-client/src/generated/platform-v1.ts"}
var checkpointTimingFields = strings.Fields("sql_client_calls sql_client_ns sql_client_failures pool_acquire_calls pool_acquire_ns pool_acquire_failures anchor_lock_attempts anchor_lock_wait_ns anchor_lock_contentions anchor_lock_failures anchor_lock_held_ns anchor_sync_calls anchor_sync_ns anchor_sync_failures")

type checkpointReport struct {
	Scope           string            `json:"scope"`
	Passed          bool              `json:"passed"`
	FailedStage     *string           `json:"failed_stage"`
	AdmissionHash   string            `json:"admissionSHA256"`
	InstanceID      string            `json:"instanceID"`
	SourceRevision  string            `json:"sourceRevision"`
	Resources       map[string]string `json:"resources"`
	NodeVersion     string            `json:"node_version"`
	Source          map[string]string `json:"source"`
	HarnessRevision string            `json:"prior_browser_harness_revision"`
	RuntimeVerified bool              `json:"runtime_process_identity_reverified"`
	AuditProven     bool              `json:"database_audit_persistence_proven"`
	ExistenceProven bool              `json:"resource_existence_independently_proven"`
	RestartProven   bool              `json:"restart_proven"`
	TimingProven    bool              `json:"timing_nondisclosure_proven"`
	Readers         struct {
		Passed      bool             `json:"passed"`
		FailedStage *string          `json:"failed_stage"`
		Records     []checkpointRead `json:"records"`
		Maximum     int              `json:"client_max_in_flight"`
		Attempts    int              `json:"dispatch_attempts"`
		Validated   int              `json:"sdk_validated_responses"`
		Unobserved  int              `json:"unobserved_dispatch_attempts"`
	} `json:"readers"`
}
type checkpointRead struct {
	Worker    int      `json:"worker"`
	Principal string   `json:"principal"`
	Sequence  int      `json:"sequence"`
	Sample    string   `json:"sample"`
	Operation string   `json:"operation"`
	RequestID string   `json:"correlation_id"`
	Status    int      `json:"status"`
	Bytes     int      `json:"response_bytes"`
	Duration  *float64 `json:"duration_ms"`
	API       struct {
		Queries  uint64            `json:"sql_queries"`
		Writes   uint64            `json:"sql_writes"`
		Audits   uint64            `json:"audit_writes"`
		Outbox   uint64            `json:"outbox_writes"`
		FGA      uint64            `json:"openfga_calls"`
		Provider uint64            `json:"provider_calls"`
		Bytes    int               `json:"response_bytes"`
		Status   int               `json:"status"`
		Duration float64           `json:"duration_ms"`
		Timing   map[string]uint64 `json:"timing"`
	} `json:"api"`
}
type checkpointIdentity struct {
	InstanceID      string          `json:"instance_id"`
	SourceRevision  string          `json:"source_revision"`
	HarnessRevision string          `json:"harness_revision"`
	State           string          `json:"state"`
	Activation      string          `json:"activation"`
	Store           string          `json:"store"`
	Model           string          `json:"model"`
	Primary         string          `json:"primary"`
	Denied          string          `json:"denied"`
	Snapshot        json.RawMessage `json:"snapshot"`
}
type checkpointExpected struct{ Actor, Action string }

// Bounded test JSON: duplicate/escaped/case-variant keys, unknown/missing fields,
// null-for-scalar values and unsafe UTF-8 do not acquire evidence authority.
func checkpointDecode(data []byte, target any) error {
	if len(data) == 0 || len(data) > 1<<20 || !utf8.Valid(data) || hasEscapedObjectKey(data) {
		return checkpointEvidenceRejected
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if checkpointUnique(d, 0) != nil {
		return checkpointEvidenceRejected
	}
	if _, err := d.Token(); err != io.EOF {
		return checkpointEvidenceRejected
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return checkpointEvidenceRejected
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return checkpointEvidenceRejected
	}
	var original, normalized any
	d = json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	_ = d.Decode(&original)
	d = json.NewDecoder(bytes.NewReader(canonical))
	d.UseNumber()
	_ = d.Decode(&normalized)
	if !checkpointShape(original, normalized) {
		return checkpointEvidenceRejected
	}
	return nil
}
func checkpointUnique(d *json.Decoder, depth int) error {
	if depth > 16 {
		return checkpointEvidenceRejected
	}
	token, err := d.Token()
	if err != nil {
		return checkpointEvidenceRejected
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter != '{' && delimiter != '[' {
		return checkpointEvidenceRejected
	}
	seen := map[string]bool{}
	for d.More() {
		if delimiter == '{' {
			token, err = d.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return checkpointEvidenceRejected
			}
			seen[key] = true
		}
		if checkpointUnique(d, depth+1) != nil {
			return checkpointEvidenceRejected
		}
	}
	token, err = d.Token()
	if err != nil || (delimiter == '{' && token != json.Delim('}')) || (delimiter == '[' && token != json.Delim(']')) {
		return checkpointEvidenceRejected
	}
	return nil
}
func checkpointShape(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !checkpointShape(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !checkpointShape(x[i], y[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.TypeOf(a) == reflect.TypeOf(b)
	}
}
func checkpointHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func checkpointPrivate(file, digest string, max int64) ([]byte, error) {
	if !checkpointHex.MatchString(digest) {
		return nil, checkpointEvidenceRejected
	}
	data, err := localdev.ReadPrivate(file, max)
	if err != nil || checkpointHash(data) != digest {
		return nil, checkpointEvidenceRejected
	}
	return data, nil
}
func checkpointPublic(file string, max int64) ([]byte, error) {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return nil, checkpointEvidenceRejected
	}
	resolved, err := filepath.EvalSymlinks(file)
	if err != nil || resolved != file {
		return nil, checkpointEvidenceRejected
	}
	fd, err := syscall.Open(file, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, checkpointEvidenceRejected
	}
	f := os.NewFile(uintptr(fd), file)
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0022 != 0 || stat.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || stat.Size() < 1 || stat.Size() > max {
		return nil, checkpointEvidenceRejected
	}
	system, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || system.Uid != uint32(os.Getuid()) || system.Nlink != 1 {
		return nil, checkpointEvidenceRejected
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) != stat.Size() {
		return nil, checkpointEvidenceRejected
	}
	return data, nil
}

// The only JS execution is this fixed, previously reviewed public-identity
// export. No main/verifyInputs/native/browser/credential code path is called.
const checkpointIdentityScript = `
import {pathToFileURL} from 'node:url';
const base=process.argv[1], file=process.argv[2], digest=process.argv[3];
const b=await import(pathToFileURL(base+'/scripts/checkpoint_a_browser_boundary.mjs'));
const c=await import(pathToFileURL(base+'/scripts/checkpoint_a_browser.mjs'));
const bytes=b.readBounded(file,32768,{privateMode:true}); b.check(b.sha256(bytes)===digest);
const a=b.validateAdmission(JSON.parse(bytes));
for(const review of a.reviews)b.check(b.sha256(b.readBounded(review.path,1048576))===review.sha256);
const current=c.verifyIdentity(a);
const p=JSON.parse(b.readBounded(a.instance.state+'/bootstrap.json',16384,{privateMode:true}));
process.stdout.write(JSON.stringify({instance_id:a.instance.instanceID,source_revision:a.source.head,
 harness_revision:a.harness.head,state:a.instance.state,activation:a.instance.activationDigest,
 store:p.openfga_store_id,model:p.openfga_model_id,primary:p.principal_id,denied:p.unprivileged_principal_id,
 snapshot:{distribution:current.distribution,runtime:current.runtime}}));`

type checkpointOutput struct{ bytes.Buffer }

func (output *checkpointOutput) Write(data []byte) (int, error) {
	if output.Len()+len(data) > 16384 {
		return 0, checkpointEvidenceRejected
	}
	return output.Buffer.Write(data)
}
func checkpointCurrentIdentity(ctx context.Context, repo, file, digest string, data []byte) (checkpointIdentity, error) {
	var raw map[string]json.RawMessage
	if checkpointDecode(data, &raw) != nil {
		return checkpointIdentity{}, checkpointEvidenceRejected
	}
	var files map[string]string
	if json.Unmarshal(raw["files"], &files) != nil {
		return checkpointIdentity{}, checkpointEvidenceRejected
	}
	for _, relative := range []string{"scripts/checkpoint_a_browser.mjs", "scripts/checkpoint_a_browser_boundary.mjs"} {
		actual, err := checkpointPublic(filepath.Join(repo, relative), 1<<20)
		if err != nil || !checkpointHex.MatchString(files[relative]) || checkpointHash(actual) != files[relative] {
			return checkpointIdentity{}, checkpointEvidenceRejected
		}
	}
	node, err := checkpointPublic(checkpointNode, 512<<20)
	if err != nil || checkpointHash(node) != checkpointNodeHash {
		return checkpointIdentity{}, checkpointEvidenceRejected
	}
	command := exec.CommandContext(ctx, checkpointNode, "--input-type=module", "-e", checkpointIdentityScript, repo, file, digest)
	command.Env = []string{"PATH=/usr/bin", "LANG=C.UTF-8", "TZ=UTC"}
	// Output is fixed public metadata, not Node errors or arbitrary child output.
	var output checkpointOutput
	command.Stdout = &output
	if command.Run() != nil || output.Len() > 16384 {
		return checkpointIdentity{}, checkpointEvidenceRejected
	}
	var result checkpointIdentity
	if checkpointDecode(output.Bytes(), &result) != nil || !checkpointUUID.MatchString(result.InstanceID) || !checkpointUUID.MatchString(result.Primary) || !checkpointUUID.MatchString(result.Denied) || result.Primary == result.Denied {
		return checkpointIdentity{}, checkpointEvidenceRejected
	}
	return result, nil
}

func checkpointParseReport(data []byte, identity checkpointIdentity, admissionHash string) (checkpointReport, map[string]checkpointExpected, error) {
	var report checkpointReport
	if checkpointDecode(data, &report) != nil || !report.Passed || report.FailedStage != nil || !report.Readers.Passed || report.Readers.FailedStage != nil ||
		report.Scope != "established-session-tls-sdk-reads-not-browser-sql-or-release" || report.AdmissionHash != admissionHash || report.InstanceID != identity.InstanceID || report.SourceRevision != identity.SourceRevision || report.HarnessRevision != identity.HarnessRevision || report.NodeVersion != "v26.8.1" || !report.RuntimeVerified || report.AuditProven || report.ExistenceProven || report.RestartProven || report.TimingProven ||
		len(report.Readers.Records) != 80 || report.Readers.Maximum != 4 || report.Readers.Attempts != 80 || report.Readers.Validated != 80 || report.Readers.Unobserved != 0 {
		return checkpointReport{}, nil, checkpointEvidenceRejected
	}
	if len(report.Source) != len(checkpointSources) || len(report.Resources) != 6 {
		return checkpointReport{}, nil, checkpointEvidenceRejected
	}
	for _, file := range checkpointSources {
		if !checkpointHex.MatchString(report.Source[file]) {
			return checkpointReport{}, nil, checkpointEvidenceRejected
		}
	}
	ids := map[string]bool{}
	for _, kind := range []string{"organization", "team", "project"} {
		for _, which := range []string{"known", "unknown"} {
			id := report.Resources[which+"_"+kind]
			if !checkpointUUID.MatchString(id) || ids[id] {
				return checkpointReport{}, nil, checkpointEvidenceRejected
			}
			ids[id] = true
		}
	}
	seen := map[string]bool{}
	sequence := [4]int{}
	expected := map[string]checkpointExpected{}
	for _, r := range report.Readers.Records {
		if r.Worker < 0 || r.Worker > 3 || r.Sequence != sequence[r.Worker] || r.Sequence > 19 || !checkpointCorrelation.MatchString(r.RequestID) || seen[r.RequestID] || r.Duration == nil || math.IsNaN(*r.Duration) || math.IsInf(*r.Duration, 0) || *r.Duration < 0 || *r.Duration > 120000 || r.Bytes < 1 || r.Bytes > 1<<20 || r.API.Status != r.Status || r.API.Bytes != r.Bytes || r.API.Provider != 0 || r.API.Duration < 0 || math.IsNaN(r.API.Duration) || math.IsInf(r.API.Duration, 0) {
			return checkpointReport{}, nil, checkpointEvidenceRejected
		}
		if len(r.API.Timing) != len(checkpointTimingFields) {
			return checkpointReport{}, nil, checkpointEvidenceRejected
		}
		for _, key := range checkpointTimingFields {
			n, ok := r.API.Timing[key]
			if !ok || n > 9007199254740991 {
				return checkpointReport{}, nil, checkpointEvidenceRejected
			}
		}
		for _, n := range []uint64{r.API.Queries, r.API.Writes, r.API.Audits, r.API.Outbox, r.API.FGA} {
			if n > 9007199254740991 {
				return checkpointReport{}, nil, checkpointEvidenceRejected
			}
		}
		role, actor := "primary", identity.Primary
		if r.Worker%2 == 1 {
			role, actor = "denied", identity.Denied
		}
		if r.Principal != role {
			return checkpointReport{}, nil, checkpointEvidenceRejected
		}
		operation, sample, status := "getSession", "session_before", 200
		if r.Sequence == 19 {
			sample = "session_after"
		} else if r.Sequence > 0 {
			position := r.Sequence - 1
			round := position / 6
			kind := []string{"organization", "team", "project"}[(position%6)/2]
			operation = map[string]string{"organization": "getOrganization", "team": "getTeam", "project": "getProject"}[kind]
			which := "known"
			if position%2 != round%2 {
				which = "unknown"
			}
			sample = which + "_" + kind
			if role == "denied" || which == "unknown" {
				status = 404
				expected[r.RequestID] = checkpointExpected{Actor: "user:" + actor, Action: kind + ".read"}
			}
		}
		if r.Operation != operation || r.Sample != sample || r.Status != status {
			return checkpointReport{}, nil, checkpointEvidenceRejected
		}
		seen[r.RequestID] = true
		sequence[r.Worker]++
	}
	if sequence != [4]int{20, 20, 20, 20} || len(expected) != 54 {
		return checkpointReport{}, nil, checkpointEvidenceRejected
	}
	return report, expected, nil
}

func checkpointDSN(data []byte, instance string, environment []string) (*pgx.ConnConfig, error) {
	for _, entry := range environment {
		if strings.HasPrefix(entry, "PG") {
			return nil, checkpointEvidenceRejected
		}
	}
	if !checkpointUUID.MatchString(instance) || len(data) == 0 || len(data) > 8192 || bytes.ContainsAny(data, "\x00\r\n") {
		return nil, checkpointEvidenceRejected
	}
	u, err := url.Parse(string(data))
	if err != nil || u.Scheme != "postgresql" || u.Host != "127.0.0.1:15432" || u.Path != "/stead" || u.RawPath != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" || u.User == nil || u.User.Username() != RuntimeRole(instance) {
		return nil, checkpointEvidenceRejected
	}
	password, ok := u.User.Password()
	if !ok || len(password) < 24 || len(password) > 256 || strings.ContainsAny(password, "\x00\r\n") {
		return nil, checkpointEvidenceRejected
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(query) < 1 || len(query) > 2 || len(query["sslmode"]) != 1 || query.Get("sslmode") != "disable" || (len(query) == 2 && (len(query["connect_timeout"]) != 1 || query.Get("connect_timeout") != "5")) {
		return nil, checkpointEvidenceRejected
	}
	config, err := pgx.ParseConfig(string(data))
	if err != nil || config.User != RuntimeRole(instance) || config.Host != "127.0.0.1" || config.Port != 15432 || config.Database != "stead" || config.TLSConfig != nil || len(config.Fallbacks) != 0 {
		return nil, checkpointEvidenceRejected
	}
	config.ConnectTimeout = 5 * time.Second
	config.RuntimeParams = map[string]string{"search_path": "pg_catalog, pg_temp", "statement_timeout": "5000", "lock_timeout": "2000", "idle_in_transaction_session_timeout": "5000"}
	return config, nil
}
func checkpointSetRole(ctx context.Context, tx pgx.Tx, instance, owner string) error {
	if !checkpointUUID.MatchString(instance) || !slices.Contains([]string{"authorization", "organization", "project", "audit"}, owner) {
		return checkpointEvidenceRejected
	}
	_, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{"sd_" + DeploymentKey(instance) + "_" + owner + "_execute"}.Sanitize())
	if err != nil {
		return checkpointEvidenceRejected
	}
	return nil
}

const checkpointAuditSQL = `SELECT id::text,evidence->>'RequestID',actor,action,decision,resource_id IS NULL,
 evidence->'Actor'->>'type',evidence->'Actor'->>'id',evidence->>'Action',evidence->>'DecisionID',occurred_at,evidence->>'OccurredAt',
 CASE WHEN jsonb_typeof(evidence)='object' AND jsonb_typeof(evidence->'Actor')='object' THEN
 evidence ?& ARRAY['DecisionID','RequestID','Actor','Action','Reason','OccurredAt'] AND
 evidence-ARRAY['DecisionID','RequestID','Actor','Action','Reason','OccurredAt']='{}'::jsonb AND
 (evidence->'Actor') ?& ARRAY['type','id'] AND (evidence->'Actor')-ARRAY['type','id']='{}'::jsonb AND
 jsonb_typeof(evidence->'DecisionID')='string' AND jsonb_typeof(evidence->'RequestID')='string' AND
 jsonb_typeof(evidence->'Action')='string' AND jsonb_typeof(evidence->'Reason')='string' AND
 jsonb_typeof(evidence->'OccurredAt')='string' AND jsonb_typeof(evidence->'Actor'->'id')='string' AND
 jsonb_typeof(evidence->'Actor'->'type')='string' AND
 evidence->>'Reason' IN ('relationship_denied','stale_authorization_input','context_denied','existence_protected','no_explicit_authorization','provider_enforcement_denied','explicit_policy_deny','ceiling_exceeded','compartment_missing','trusted_attribute_invalid','capability_inactive','dissemination_denied','profile_handling_denied','affiliation_denied')
 ELSE false END
 FROM audit.records WHERE evidence->>'RequestID'=ANY($1::text[]) LIMIT 55`

var checkpointResourceSQL = []struct{ owner, kind, query string }{
	{"authorization", "authorization", `SELECT id::text,kind,''::text,NOT pending FROM "authorization".resources WHERE id=ANY($1::uuid[]) LIMIT 7`},
	{"organization", "organization", `SELECT id::text,'organization'::text,''::text,active FROM organization.organizations WHERE id=ANY($1::uuid[]) LIMIT 7`},
	{"organization", "team", `SELECT id::text,'team'::text,organization_id::text,active FROM organization.teams WHERE id=ANY($1::uuid[]) LIMIT 7`},
	{"project", "project", `SELECT id::text,'project'::text,organization_id::text,active FROM project.projects WHERE id=ANY($1::uuid[]) LIMIT 7`},
}

type checkpointResourceRow struct {
	ID, Kind, Organization string
	Ready                  bool
}

func checkpointCheckResources(rows []checkpointResourceRow, kind string, ids map[string]string) error {
	expected := map[string]string{}
	for _, k := range []string{"organization", "team", "project"} {
		if kind == "authorization" || k == kind {
			expected[ids["known_"+k]] = k
		}
	}
	if len(rows) != len(expected) {
		return checkpointEvidenceRejected
	}
	for _, row := range rows {
		k, ok := expected[row.ID]
		if !ok || row.Kind != k || !row.Ready || (kind != "authorization" && kind != "organization" && row.Organization != ids["known_organization"]) {
			return checkpointEvidenceRejected
		}
		delete(expected, row.ID)
	}
	if len(expected) != 0 {
		return checkpointEvidenceRejected
	}
	return nil
}

type checkpointAuditRow struct {
	ID, RequestID, Actor, Action, Decision         string
	NullResource                                   bool
	ActorType, ActorID, EvidenceAction, DecisionID string
	Occurred                                       time.Time
	EvidenceOccurred                               string
	SafeShape                                      bool
}

func checkpointCheckAudits(rows []checkpointAuditRow, expected map[string]checkpointExpected, now time.Time) ([]string, error) {
	if len(rows) != 54 || len(expected) != 54 {
		return nil, checkpointEvidenceRejected
	}
	requests, audits, decisions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, row := range rows {
		wanted, ok := expected[row.RequestID]
		evidenceTime, err := time.Parse(time.RFC3339Nano, row.EvidenceOccurred)
		if !ok || requests[row.RequestID] || !checkpointUUID.MatchString(row.ID) || audits[row.ID] || !checkpointCorrelation.MatchString(row.DecisionID) || decisions[row.DecisionID] || row.DecisionID == row.RequestID || row.Actor != wanted.Actor || row.Action != wanted.Action || row.Decision != "deny" || !row.NullResource || row.ActorType != "user" || "user:"+row.ActorID != wanted.Actor || row.EvidenceAction != wanted.Action || !row.SafeShape || row.Occurred.IsZero() || row.Occurred.After(now.Add(time.Second)) || err != nil || evidenceTime.Sub(row.Occurred).Abs() > time.Microsecond {
			return nil, checkpointEvidenceRejected
		}
		requests[row.RequestID] = true
		audits[row.ID] = true
		decisions[row.DecisionID] = true
	}
	ids := make([]string, 0, 54)
	for id := range requests {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

func checkpointCollect(ctx context.Context, config *pgx.ConnConfig, identity checkpointIdentity, report checkpointReport, expected map[string]checkpointExpected) (matched []string, err error) {
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, checkpointEvidenceRejected
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if conn.Close(cleanup) != nil {
			err = checkpointEvidenceRejected
		}
	}()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, checkpointEvidenceRejected
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if rollback := tx.Rollback(cleanup); rollback != nil && !errors.Is(rollback, pgx.ErrTxClosed) {
			err = checkpointEvidenceRejected
		}
	}()
	var database, user, sessionUser, readOnly, isolation string
	var port, version int
	var login, unsafe bool
	err = tx.QueryRow(ctx, `SELECT current_database(),current_user,session_user,inet_server_port(),current_setting('server_version_num')::integer,rolcanlogin,rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR rolinherit,current_setting('transaction_read_only'),current_setting('transaction_isolation') FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&database, &user, &sessionUser, &port, &version, &login, &unsafe, &readOnly, &isolation)
	if err != nil || database != "stead" || user != RuntimeRole(identity.InstanceID) || sessionUser != user || port != 15432 || version < MinimumServerVersion || !login || unsafe || readOnly != "on" || isolation != "repeatable read" {
		return nil, checkpointEvidenceRejected
	}
	if checkpointSetRole(ctx, tx, identity.InstanceID, "authorization") != nil {
		return nil, checkpointEvidenceRejected
	}
	var instance, domain, activation, store, model string
	if tx.QueryRow(ctx, `SELECT instance_id::text,security_domain,activation_digest,store_id,model_id FROM "authorization".namespace WHERE id`).Scan(&instance, &domain, &activation, &store, &model) != nil || instance != identity.InstanceID || domain != "stead-local-development" || activation != identity.Activation || store != identity.Store || model != identity.Model {
		return nil, checkpointEvidenceRejected
	}
	ids := make([]string, 0, 6)
	for _, id := range report.Resources {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, query := range checkpointResourceSQL {
		if checkpointSetRole(ctx, tx, identity.InstanceID, query.owner) != nil {
			return nil, checkpointEvidenceRejected
		}
		rows, queryErr := tx.Query(ctx, query.query, ids)
		if queryErr != nil {
			return nil, checkpointEvidenceRejected
		}
		collected := []checkpointResourceRow{}
		for rows.Next() {
			var row checkpointResourceRow
			if rows.Scan(&row.ID, &row.Kind, &row.Organization, &row.Ready) != nil {
				rows.Close()
				return nil, checkpointEvidenceRejected
			}
			collected = append(collected, row)
			if len(collected) > 6 {
				rows.Close()
				return nil, checkpointEvidenceRejected
			}
		}
		queryErr = rows.Err()
		rows.Close()
		if queryErr != nil || checkpointCheckResources(collected, query.kind, report.Resources) != nil {
			return nil, checkpointEvidenceRejected
		}
	}
	if checkpointSetRole(ctx, tx, identity.InstanceID, "audit") != nil {
		return nil, checkpointEvidenceRejected
	}
	requests := make([]string, 0, 54)
	for id := range expected {
		requests = append(requests, id)
	}
	slices.Sort(requests)
	rows, err := tx.Query(ctx, checkpointAuditSQL, requests)
	if err != nil {
		return nil, checkpointEvidenceRejected
	}
	collected := []checkpointAuditRow{}
	for rows.Next() {
		var row checkpointAuditRow
		if rows.Scan(&row.ID, &row.RequestID, &row.Actor, &row.Action, &row.Decision, &row.NullResource, &row.ActorType, &row.ActorID, &row.EvidenceAction, &row.DecisionID, &row.Occurred, &row.EvidenceOccurred, &row.SafeShape) != nil {
			rows.Close()
			return nil, checkpointEvidenceRejected
		}
		collected = append(collected, row)
		if len(collected) > 54 {
			rows.Close()
			return nil, checkpointEvidenceRejected
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, checkpointEvidenceRejected
	}
	matched, err = checkpointCheckAudits(collected, expected, time.Now())
	if err != nil {
		return nil, checkpointEvidenceRejected
	}
	// Never commit: even the successful collector always ends by rollback.
	if tx.Rollback(ctx) != nil {
		return nil, checkpointEvidenceRejected
	}
	return matched, nil
}
