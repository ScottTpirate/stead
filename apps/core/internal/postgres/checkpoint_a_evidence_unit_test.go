//go:build linux

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func checkpointUnitID(n int) string { return fmt.Sprintf("01991c05-1a00-7000-8000-%012x", n) }
func checkpointUnitReport() (checkpointReport, checkpointIdentity, string) {
	identity := checkpointIdentity{InstanceID: checkpointUnitID(10), Primary: checkpointUnitID(11), Denied: checkpointUnitID(12), SourceRevision: strings.Repeat("a", 40), HarnessRevision: strings.Repeat("b", 40)}
	hash := strings.Repeat("c", 64)
	r := checkpointReport{Scope: "established-session-tls-sdk-reads-not-browser-sql-or-release", Passed: true, AdmissionHash: hash, InstanceID: identity.InstanceID, SourceRevision: identity.SourceRevision, HarnessRevision: identity.HarnessRevision, RuntimeVerified: true, Resources: map[string]string{}}
	for n, kind := range []string{"organization", "team", "project"} {
		r.Resources["known_"+kind] = checkpointUnitID(n*2 + 1)
		r.Resources["unknown_"+kind] = checkpointUnitID(n*2 + 2)
	}
	r.Readers.Passed, r.Readers.Attempts, r.Readers.Validated = true, 80, 80
	for i := 0; i < 80; i++ {
		v := checkpointRead{Principal: "primary", Operation: "getSession", Status: 200, RequestID: fmt.Sprintf("%032x", i+1)}
		if i >= 8 {
			v.Operation = []string{"getOrganization", "getTeam", "getProject"}[(i-8)%3]
		}
		if i >= 26 {
			v.Status = 404
		}
		if i >= 44 {
			v.Principal = "denied"
		}
		r.Readers.Records = append(r.Readers.Records, v)
	}
	return r, identity, hash
}
func checkpointUnitJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("owned fixture encoding failed")
	}
	return data
}
func TestCheckpointEvidenceCompletedReportSelection(t *testing.T) {
	report, identity, hash := checkpointUnitReport()
	_, expected, err := checkpointParseReport(checkpointUnitJSON(t, report), identity, hash)
	if err != nil || len(expected) != 54 {
		t.Fatal("complete synthetic report rejected")
	}
	count := map[string]int{}
	for _, value := range expected {
		count[value.Actor]++
	}
	if count["user:"+identity.Primary] != 18 || count["user:"+identity.Denied] != 36 {
		t.Fatal("expected principal split changed")
	}
	for name, change := range map[string]func(*checkpointReport){
		"incomplete":            func(r *checkpointReport) { r.Passed = false },
		"lost response":         func(r *checkpointReport) { r.Readers.Validated = 79 },
		"wrong binding":         func(r *checkpointReport) { r.SourceRevision = strings.Repeat("d", 40) },
		"duplicate correlation": func(r *checkpointReport) { r.Readers.Records[1].RequestID = r.Readers.Records[0].RequestID },
		"wrong action":          func(r *checkpointReport) { r.Readers.Records[26].Operation = "createOrganization" },
		"wrong principal":       func(r *checkpointReport) { r.Readers.Records[26].Principal = "administrator" },
		"duplicate resource":    func(r *checkpointReport) { r.Resources["unknown_project"] = r.Resources["known_team"] },
	} {
		t.Run(name, func(t *testing.T) {
			r, _, _ := checkpointUnitReport()
			change(&r)
			if _, _, err := checkpointParseReport(checkpointUnitJSON(t, r), identity, hash); err == nil {
				t.Fatal("invalid correlation selection accepted")
			}
		})
	}
}
func TestCheckpointEvidencePrivateInputsAndOutputBounds(t *testing.T) {
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private owned fixture setup failed")
	}
	file := filepath.Join(directory, "report.json")
	data := []byte(`{"synthetic":true}`)
	if os.WriteFile(file, data, 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if _, err := checkpointPrivate(file, checkpointHash(data), 1024); err != nil {
		t.Fatal("owned private fixture rejected")
	}
	if _, err := checkpointPrivate(file, strings.Repeat("0", 64), 1024); err == nil {
		t.Fatal("wrong hash accepted")
	}
	for _, name := range []string{"symlink", "hardlink"} {
		alias := filepath.Join(directory, name)
		var err error
		if name == "symlink" {
			err = os.Symlink(file, alias)
		} else {
			err = os.Link(file, alias)
		}
		if err != nil {
			t.Fatal("owned alias fixture failed")
		}
		if _, err = checkpointPrivate(alias, checkpointHash(data), 1024); err == nil {
			t.Fatal("alias accepted")
		}
	}
	var output checkpointOutput
	if _, err := output.Write(make([]byte, 16385)); err == nil || output.Len() != 0 {
		t.Fatal("unbounded child output accepted")
	}
}
func TestCheckpointEvidenceRuntimeDSNBoundary(t *testing.T) {
	instance := checkpointUnitID(10)
	address := url.URL{Scheme: "postgresql", Host: "127.0.0.1:15432", Path: "/stead", RawQuery: "sslmode=disable", User: url.UserPassword(RuntimeRole(instance), strings.Repeat("a", 32))}
	valid := address.String()
	for _, query := range []string{"sslmode=disable", "sslmode=disable&connect_timeout=5"} {
		copy := address
		copy.RawQuery = query
		config, err := checkpointDSN([]byte(copy.String()), instance, nil)
		if err != nil || config.ConnectTimeout != 5*time.Second || config.RuntimeParams["search_path"] != "pg_catalog, pg_temp" {
			t.Fatal("scoped runtime DSN rejected")
		}
	}
	for _, bad := range []string{strings.Replace(valid, "127.0.0.1", "localhost", 1), strings.Replace(valid, "15432", "5432", 1), strings.Replace(valid, "/stead", "/postgres", 1),
		strings.Replace(valid, RuntimeRole(instance), "postgres", 1), valid + "&options=-crole=postgres", valid + "&sslmode=disable", valid + "#fragment", valid + "\n",
		"host=127.0.0.1 user=postgres dbname=stead", strings.Replace(valid, "sslmode=disable", "sslmode=require", 1), valid + "&connect_timeout=50",
	} {
		if _, err := checkpointDSN([]byte(bad), instance, nil); err == nil {
			t.Fatal("unsafe DSN accepted")
		}
	}
	for _, variable := range []string{"PGHOST=other", "PGSERVICE=other", "PGPASSWORD=not-read", "PGOPTIONS=-crole=other"} {
		if _, err := checkpointDSN([]byte(valid), instance, []string{variable}); err == nil {
			t.Fatal("PG override accepted")
		}
	}
}

type checkpointRoleFixture struct {
	pgx.Tx
	statements []string
}

func (f *checkpointRoleFixture) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.statements = append(f.statements, sql)
	return pgconn.NewCommandTag("SET"), nil
}
func TestCheckpointEvidenceFixedRoleAndQueryContract(t *testing.T) {
	fake := &checkpointRoleFixture{}
	instance := checkpointUnitID(10)
	for _, owner := range []string{"authorization", "organization", "project", "audit"} {
		if checkpointSetRole(context.Background(), fake, instance, owner) != nil {
			t.Fatal("fixed role rejected")
		}
	}
	for _, owner := range []string{"identity", "audit_owner", "audit_rw", "public", "audit; SELECT 1"} {
		if checkpointSetRole(context.Background(), fake, instance, owner) == nil {
			t.Fatal("noncontract role accepted")
		}
	}
	if len(fake.statements) != 4 || fake.statements[3] != `SET LOCAL ROLE "sd_`+DeploymentKey(instance)+`_audit_execute"` {
		t.Fatal("role sequence changed")
	}
	if !strings.Contains(checkpointAuditSQL, `WHERE evidence->>'RequestID'=ANY($1::text[]) LIMIT 55`) {
		t.Fatal("audit lookup no longer bounded by request IDs")
	}
	for _, query := range checkpointResourceSQL {
		if !strings.Contains(query.query, "id=ANY($1::uuid[]) LIMIT 7") || strings.Contains(query.query, "record") {
			t.Fatal("resource lookup broadened")
		}
	}
}
func TestCheckpointEvidenceCanonicalExistenceAcrossAllOwners(t *testing.T) {
	report, _, _ := checkpointUnitReport()
	ids := report.Resources
	authorization := []checkpointResourceRow{{ids["known_organization"], "organization", "", true}, {ids["known_team"], "team", "", true}, {ids["known_project"], "project", "", true}}
	if checkpointCheckResources(authorization, "authorization", ids) != nil {
		t.Fatal("canonical authorization fixture rejected")
	}
	for _, kind := range []string{"organization", "team", "project"} {
		rows := []checkpointResourceRow{{ids["known_"+kind], kind, ids["known_organization"], true}}
		if checkpointCheckResources(rows, kind, ids) != nil {
			t.Fatal("canonical domain fixture rejected")
		}
		for _, change := range []func([]checkpointResourceRow){func(r []checkpointResourceRow) { r[0].ID = ids["unknown_"+kind] }, func(r []checkpointResourceRow) { r[0].Ready = false }, func(r []checkpointResourceRow) { r[0].Kind = "foreign" }} {
			copy := append([]checkpointResourceRow{}, rows...)
			change(copy)
			if checkpointCheckResources(copy, kind, ids) == nil {
				t.Fatal("wrong canonical state accepted")
			}
		}
		if checkpointCheckResources(append(rows, checkpointResourceRow{ids["unknown_project"], "project", "", true}), kind, ids) == nil {
			t.Fatal("unknown canonical resource accepted")
		}
	}
	wrong := append([]checkpointResourceRow{}, authorization...)
	wrong[2] = wrong[1]
	if checkpointCheckResources(wrong, "authorization", ids) == nil {
		t.Fatal("duplicate canonical row accepted")
	}
}
func TestCheckpointEvidenceActualRequestIDsRequireExactlyOneSafeDenial(t *testing.T) {
	report, identity, hash := checkpointUnitReport()
	_, expected, err := checkpointParseReport(checkpointUnitJSON(t, report), identity, hash)
	if err != nil {
		t.Fatal("fixture report rejected")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	rows := []checkpointAuditRow{}
	for request, wanted := range expected {
		n := len(rows)
		rows = append(rows, checkpointAuditRow{ID: checkpointUnitID(100 + n), RequestID: request, Actor: wanted.Actor, Action: wanted.Action, Decision: "deny", NullResource: true, ActorType: "user", ActorID: strings.TrimPrefix(wanted.Actor, "user:"), EvidenceAction: wanted.Action, DecisionID: fmt.Sprintf("%032x", 1000+n), Occurred: now, EvidenceOccurred: now.Add(123 * time.Nanosecond).Format(time.RFC3339Nano), SafeShape: true})
	}
	matches, err := checkpointCheckAudits(rows, expected, now)
	if err != nil || len(matches) != 54 {
		t.Fatal("safe microsecond/nanosecond correlated evidence rejected")
	}
	for name, change := range map[string]func([]checkpointAuditRow){
		"duplicate": func(r []checkpointAuditRow) { r[1] = r[0] }, "resource leak": func(r []checkpointAuditRow) { r[0].NullResource = false },
		"wrong actor": func(r []checkpointAuditRow) { r[0].Actor = "user:" + checkpointUnitID(99) }, "nested actor": func(r []checkpointAuditRow) { r[0].ActorID = checkpointUnitID(99) },
		"wrong action": func(r []checkpointAuditRow) { r[0].Action = "project.create" }, "nested action": func(r []checkpointAuditRow) { r[0].EvidenceAction = "project.create" },
		"not denial": func(r []checkpointAuditRow) { r[0].Decision = "allow" }, "unsafe evidence": func(r []checkpointAuditRow) { r[0].SafeShape = false },
		"decision confused": func(r []checkpointAuditRow) { r[0].DecisionID = r[0].RequestID }, "time mismatch": func(r []checkpointAuditRow) { r[0].EvidenceOccurred = now.Add(time.Second).Format(time.RFC3339Nano) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := append([]checkpointAuditRow{}, rows...)
			change(copy)
			if _, err := checkpointCheckAudits(copy, expected, now); err == nil {
				t.Fatal("incorrect denial evidence accepted")
			}
		})
	}
	for _, bad := range [][]checkpointAuditRow{rows[:53], append(append([]checkpointAuditRow{}, rows...), rows[0])} {
		if _, err := checkpointCheckAudits(bad, expected, now); err == nil {
			t.Fatal("missing/extra audit evidence accepted")
		}
	}
}
