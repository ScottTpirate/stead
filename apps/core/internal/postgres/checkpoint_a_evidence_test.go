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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/localdev"
	"github.com/jackc/pgx/v5"
)

var checkpointEvidenceRejected = errors.New("checkpoint A SQL evidence rejected")
var checkpointHex = regexp.MustCompile(`^[0-9a-f]{64}$`)
var checkpointCorrelation = regexp.MustCompile(`^[0-9a-f]{32}$`)
var checkpointUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const checkpointNode = "/tmp/stead-node-toolchain-26.8.1/toolchain/node-v26.8.1-linux-x64/bin/node"
const checkpointNodeHash = "19235a9b678f84729464c52623f92de130a165452747c6826d3fdc13df3abcc3"

// The caller supplies an independently reviewed exact report hash. Decode only
// the bindings and correlation selection needed here, not the producer's full
// timing/worker/SDK contract or a second generic JSON validation framework.
type checkpointReport struct {
	Scope           string            `json:"scope"`
	Passed          bool              `json:"passed"`
	FailedStage     *string           `json:"failed_stage"`
	AdmissionHash   string            `json:"admissionSHA256"`
	InstanceID      string            `json:"instanceID"`
	SourceRevision  string            `json:"sourceRevision"`
	Resources       map[string]string `json:"resources"`
	HarnessRevision string            `json:"prior_browser_harness_revision"`
	RuntimeVerified bool              `json:"runtime_process_identity_reverified"`
	Readers         struct {
		Passed      bool             `json:"passed"`
		FailedStage *string          `json:"failed_stage"`
		Records     []checkpointRead `json:"records"`
		Attempts    int              `json:"dispatch_attempts"`
		Validated   int              `json:"sdk_validated_responses"`
		Unobserved  int              `json:"unobserved_dispatch_attempts"`
	} `json:"readers"`
}
type checkpointRead struct {
	Principal string `json:"principal"`
	Operation string `json:"operation"`
	RequestID string `json:"correlation_id"`
	Status    int    `json:"status"`
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

// Separate optional proof: never reinterpret the 80-response/54-denial report.
type checkpointCollectionReport struct {
	Scope           string `json:"scope"`
	Passed          bool   `json:"passed"`
	Stage           string `json:"stage"`
	AdmissionHash   string `json:"admissionSHA256"`
	InstanceID      string `json:"instanceID"`
	SourceRevision  string `json:"sourceRevision"`
	HarnessRevision string `json:"prior_browser_harness_revision"`
	Discovery       string `json:"discovery_revision"`
	RuntimeVerified bool   `json:"runtime_process_identity_reverified"`
	Attempts        int    `json:"dispatch_attempts"`
	Records         []struct {
		RequestID string `json:"correlation_id"`
		Status    int    `json:"status"`
	} `json:"records"`
	Denial struct {
		checkpointRead
		Generic bool `json:"generic_response_validated"`
	} `json:"collection_denial"`
}

func checkpointParseCollection(data []byte, identity checkpointIdentity, admissionHash string) (map[string]checkpointExpected, error) {
	var report checkpointCollectionReport
	if json.Unmarshal(data, &report) != nil || !report.Passed || report.Stage != "complete" ||
		report.Scope != "fixed-established-session-discovery-and-organization-list-denial-only" ||
		report.AdmissionHash != admissionHash || report.InstanceID != identity.InstanceID || report.SourceRevision != identity.SourceRevision ||
		report.HarnessRevision != identity.HarnessRevision || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(report.Discovery) || !report.RuntimeVerified ||
		report.Attempts != 6 || len(report.Records) != 6 || !report.Denial.Generic || report.Denial.Principal != "denied" ||
		report.Denial.Operation != "listOrganizations" || report.Denial.Status != 404 {
		return nil, checkpointEvidenceRejected
	}
	seen := map[string]bool{}
	for index, record := range report.Records {
		status := 200
		if index == 5 {
			status = 404
		}
		if !checkpointCorrelation.MatchString(record.RequestID) || seen[record.RequestID] || record.Status != status {
			return nil, checkpointEvidenceRejected
		}
		seen[record.RequestID] = true
	}
	if report.Denial.RequestID != report.Records[5].RequestID {
		return nil, checkpointEvidenceRejected
	}
	return map[string]checkpointExpected{report.Denial.RequestID: {Actor: "user:" + identity.Denied, Action: "organization.list"}}, nil
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
	var admission struct {
		Files map[string]string `json:"files"`
	}
	if json.Unmarshal(data, &admission) != nil {
		return checkpointIdentity{}, checkpointEvidenceRejected
	}
	for _, relative := range []string{"scripts/checkpoint_a_browser.mjs", "scripts/checkpoint_a_browser_boundary.mjs"} {
		actual, err := checkpointPublic(filepath.Join(repo, relative), 1<<20)
		if err != nil || !checkpointHex.MatchString(admission.Files[relative]) || checkpointHash(actual) != admission.Files[relative] {
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
	if json.Unmarshal(output.Bytes(), &result) != nil || !checkpointUUID.MatchString(result.InstanceID) || !checkpointUUID.MatchString(result.Primary) || !checkpointUUID.MatchString(result.Denied) || result.Primary == result.Denied {
		return checkpointIdentity{}, checkpointEvidenceRejected
	}
	return result, nil
}

func checkpointParseReport(data []byte, identity checkpointIdentity, admissionHash string) (checkpointReport, map[string]checkpointExpected, error) {
	var report checkpointReport
	if json.Unmarshal(data, &report) != nil || !report.Passed || report.FailedStage != nil || !report.Readers.Passed || report.Readers.FailedStage != nil ||
		report.Scope != "established-session-tls-sdk-reads-not-browser-sql-or-release" || report.AdmissionHash != admissionHash || report.InstanceID != identity.InstanceID || report.SourceRevision != identity.SourceRevision || report.HarnessRevision != identity.HarnessRevision || !report.RuntimeVerified ||
		len(report.Readers.Records) != 80 || report.Readers.Attempts != 80 || report.Readers.Validated != 80 || report.Readers.Unobserved != 0 || len(report.Resources) != 6 {
		return checkpointReport{}, nil, checkpointEvidenceRejected
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
	denials := map[string]int{}
	sessions, allowed := 0, 0
	expected := map[string]checkpointExpected{}
	for _, r := range report.Readers.Records {
		actor := map[string]string{"primary": identity.Primary, "denied": identity.Denied}[r.Principal]
		if actor == "" || !checkpointCorrelation.MatchString(r.RequestID) || seen[r.RequestID] {
			return checkpointReport{}, nil, checkpointEvidenceRejected
		}
		seen[r.RequestID] = true
		if r.Operation == "getSession" && r.Status == 200 {
			sessions++
			continue
		}
		action := map[string]string{"getOrganization": "organization.read", "getTeam": "team.read", "getProject": "project.read"}[r.Operation]
		if action == "" || (r.Status != 200 && r.Status != 404) || (r.Principal == "denied" && r.Status != 404) {
			return checkpointReport{}, nil, checkpointEvidenceRejected
		}
		if r.Status == 404 {
			expected[r.RequestID] = checkpointExpected{Actor: "user:" + actor, Action: action}
			denials[r.Principal]++
		} else {
			allowed++
		}
	}
	if sessions != 8 || allowed != 18 || len(expected) != 54 || denials["primary"] != 18 || denials["denied"] != 36 {
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
 ELSE false END,evidence->>'Reason'
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
	Reason                                         string
}

func checkpointCheckAudits(rows []checkpointAuditRow, expected map[string]checkpointExpected, now time.Time) ([]string, error) {
	if len(rows) != 54 || len(expected) != 54 {
		return nil, checkpointEvidenceRejected
	}
	return checkpointCheckAuditRows(rows, expected, now)
}

func checkpointCheckCollectionAudit(rows []checkpointAuditRow, expected map[string]checkpointExpected, now time.Time) ([]string, error) {
	if len(rows) != 1 || len(expected) != 1 || rows[0].Action != "organization.list" || rows[0].Reason != "context_denied" {
		return nil, checkpointEvidenceRejected
	}
	return checkpointCheckAuditRows(rows, expected, now)
}

func checkpointCheckAuditRows(rows []checkpointAuditRow, expected map[string]checkpointExpected, now time.Time) ([]string, error) {
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
	ids := make([]string, 0, len(expected))
	for id := range requests {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

func checkpointCollect(ctx context.Context, config *pgx.ConnConfig, identity checkpointIdentity, report checkpointReport, expected map[string]checkpointExpected) (matched []string, err error) {
	if len(expected) != 54 || len(report.Resources) != 6 {
		return nil, checkpointEvidenceRejected
	}
	return checkpointCollectMode(ctx, config, identity, report, expected, false)
}

func checkpointCollectCollection(ctx context.Context, config *pgx.ConnConfig, identity checkpointIdentity, expected map[string]checkpointExpected) ([]string, error) {
	if len(expected) != 1 {
		return nil, checkpointEvidenceRejected
	}
	for request, wanted := range expected {
		if !checkpointCorrelation.MatchString(request) || wanted.Actor != "user:"+identity.Denied || wanted.Action != "organization.list" {
			return nil, checkpointEvidenceRejected
		}
	}
	return checkpointCollectMode(ctx, config, identity, checkpointReport{}, expected, true)
}

// Both fixed modes share only connection/namespace/rollback and row safety.
// The optional collection mode never queries any canonical resource table.
func checkpointCollectMode(ctx context.Context, config *pgx.ConnConfig, identity checkpointIdentity, report checkpointReport, expected map[string]checkpointExpected, collection bool) (matched []string, err error) {
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
		if collection {
			break
		}
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
	requests := make([]string, 0, len(expected))
	for id := range expected {
		requests = append(requests, id)
	}
	slices.Sort(requests)
	query := checkpointAuditSQL
	if collection {
		query = strings.TrimSuffix(checkpointAuditSQL, " LIMIT 55") + " LIMIT 2"
	}
	rows, err := tx.Query(ctx, query, requests)
	if err != nil {
		return nil, checkpointEvidenceRejected
	}
	collected := []checkpointAuditRow{}
	for rows.Next() {
		var row checkpointAuditRow
		if rows.Scan(&row.ID, &row.RequestID, &row.Actor, &row.Action, &row.Decision, &row.NullResource, &row.ActorType, &row.ActorID, &row.EvidenceAction, &row.DecisionID, &row.Occurred, &row.EvidenceOccurred, &row.SafeShape, &row.Reason) != nil {
			rows.Close()
			return nil, checkpointEvidenceRejected
		}
		collected = append(collected, row)
		if len(collected) > len(expected) {
			rows.Close()
			return nil, checkpointEvidenceRejected
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, checkpointEvidenceRejected
	}
	if collection {
		matched, err = checkpointCheckCollectionAudit(collected, expected, time.Now())
	} else {
		matched, err = checkpointCheckAudits(collected, expected, time.Now())
	}
	if err != nil {
		return nil, checkpointEvidenceRejected
	}
	// Never commit: even the successful collector always ends by rollback.
	if tx.Rollback(ctx) != nil {
		return nil, checkpointEvidenceRejected
	}
	return matched, nil
}
