package gitea

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const syntheticToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const exactID int64 = 9007199254740993

func testClient(t *testing.T, h http.HandlerFunc) (*client, *atomic.Int64) {
	t.Helper()
	calls := &atomic.Int64{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "token "+syntheticToken || r.Header.Get("Cookie") != "" || r.Header.Get("Idempotency-Key") != "" || r.Header.Get("Accept-Encoding") != "" {
			t.Error("unexpected request authority or replay/compression header")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		h(w, r)
	}))
	t.Cleanup(s.Close)
	c, err := newClient(s.URL, "probe-admin", syntheticToken)
	if err != nil {
		t.Fatal(err)
	}
	return c, calls
}
func repoFixture(c *client) RepositoryRef {
	return RepositoryRef{c.origin, c.owner, "probe-tracker", exactID}
}
func issueFixture(c *client) Issue {
	ref := IssueRef{repoFixture(c), 1, exactID}
	return Issue{Ref: ref, Revision: IssueRevision{ref, exactID, true}, Title: "Synthetic", Body: "one"}
}
func writeJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error("fixture response write failed")
	}
}
func repoJSON() map[string]any {
	return map[string]any{"id": exactID, "name": "probe-tracker", "full_name": "probe-admin/probe-tracker", "owner": map[string]any{"login": "probe-admin"}, "private": true, "empty": false, "default_branch": "main"}
}
func issueJSON(version int64, body string) map[string]any {
	return map[string]any{"id": exactID, "number": 1, "title": "Synthetic", "body": body, "state": "open", "content_version": version, "pull_request": nil}
}
func fileJSON(content string, includeContent bool) map[string]any {
	v := map[string]any{"name": "probe.md", "path": "probe.md", "sha": blobSHA(content), "type": "file", "mode": "100644", "size": len(content), "target": nil, "submodule_git_url": nil}
	if includeContent {
		v["content"] = base64.StdEncoding.EncodeToString([]byte(content))
		v["encoding"] = "base64"
	}
	return v
}
func wantCompletion(t *testing.T, err error, want Completion) {
	t.Helper()
	var ce *CallError
	if !errors.As(err, &ce) || ce.Completion() != want || ce.Error() != "gitea: "+string(want) || errors.Unwrap(err) != nil {
		t.Fatalf("wanted closed failure %s; got %T", want, err)
	}
}
func decodeRequest(t *testing.T, r *http.Request, out any) {
	t.Helper()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		t.Error("request contract mismatch")
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		t.Error("extra request data")
	}
}

func TestRepositoryIssueSingleCallContractsAndExactIntegers(t *testing.T) {
	var step int
	c, calls := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		step++
		switch step {
		case 1:
			if r.Method != "POST" || r.URL.RequestURI() != "/api/v1/user/repos" {
				t.Error("repository path")
			}
			var p struct {
				Name          string `json:"name"`
				Private       bool   `json:"private"`
				AutoInit      bool   `json:"auto_init"`
				DefaultBranch string `json:"default_branch"`
				Readme        string `json:"readme"`
			}
			decodeRequest(t, r, &p)
			if p.Name != "probe-tracker" || !p.Private || !p.AutoInit || p.DefaultBranch != "main" || p.Readme != "Default" {
				t.Error("unsafe provisioning shape")
			}
			writeJSON(t, w, 201, repoJSON())
		case 2:
			if r.Method != "GET" || r.URL.RequestURI() != "/api/v1/repos/probe-admin/probe-tracker" {
				t.Error("repository read path")
			}
			writeJSON(t, w, 200, repoJSON())
		case 3:
			if r.Method != "POST" || r.URL.RequestURI() != "/api/v1/repos/probe-admin/probe-tracker/issues" {
				t.Error("issue create path")
			}
			var p struct {
				Title string `json:"title"`
				Body  string `json:"body"`
			}
			decodeRequest(t, r, &p)
			if p.Title != "Synthetic" || p.Body != "one" {
				t.Error("issue input")
			}
			writeJSON(t, w, 201, issueJSON(exactID, "one"))
		case 4:
			if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/issues/1") {
				t.Error("issue read path")
			}
			writeJSON(t, w, 200, issueJSON(exactID, "one"))
		case 5:
			if r.Method != "PATCH" || !strings.HasSuffix(r.URL.Path, "/issues/1") {
				t.Error("issue edit path")
			}
			var p struct {
				Body    string `json:"body"`
				Version int64  `json:"content_version"`
			}
			decodeRequest(t, r, &p)
			if p.Body != "two" || p.Version != exactID {
				t.Error("version precision or body changed")
			}
			writeJSON(t, w, 201, issueJSON(exactID+1, "two"))
		case 6:
			if r.Method != "GET" || r.URL.RawQuery != "state=all&page=1&limit=10" {
				t.Error("bounded list path")
			}
			w.Header().Set("Link", "<https://forbidden.invalid/?secret>; rel=next")
			writeJSON(t, w, 200, []any{issueJSON(exactID+1, "two")})
		default:
			t.Error("unexpected provider call")
		}
	})
	ctx := context.Background()
	repo, err := c.createRepository(ctx, "probe-tracker")
	if err != nil {
		t.Fatal(err)
	}
	if repo.Ref.id != exactID {
		t.Fatal("lost repository ID precision")
	}
	if _, err = c.getRepository(ctx, repo.Ref); err != nil {
		t.Fatal(err)
	}
	i, err := c.createIssue(ctx, repo.Ref, "Synthetic", "one")
	if err != nil {
		t.Fatal(err)
	}
	if i.Ref.id != exactID || i.Revision.value != exactID {
		t.Fatal("lost issue integer precision")
	}
	if _, err = c.getIssue(ctx, i.Ref); err != nil {
		t.Fatal(err)
	}
	i, err = c.updateIssueBody(ctx, i.Ref, i.Revision, "two")
	if err != nil || i.Revision.value != exactID+1 {
		t.Fatal("conditional body update failed")
	}
	rows, err := c.firstIssues(ctx, repo.Ref)
	if err != nil || len(rows) != 1 {
		t.Fatal("bounded first page failed")
	}
	if calls.Load() != 6 {
		t.Fatal("hidden provider call")
	}
}

func TestIssueStaleVersionAndNoopIncrement(t *testing.T) {
	c, calls := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Body    string `json:"body"`
			Version int64  `json:"content_version"`
		}
		decodeRequest(t, r, &p)
		if p.Version == exactID {
			writeJSON(t, w, 409, map[string]string{"message": "secret-provider-error"})
			return
		}
		writeJSON(t, w, 201, issueJSON(p.Version+1, p.Body))
	})
	i := issueFixture(c)
	_, err := c.updateIssueBody(context.Background(), i.Ref, i.Revision, "two")
	wantCompletion(t, err, VersionConflict)
	i.Revision.value++
	updated, err := c.updateIssueBody(context.Background(), i.Ref, i.Revision, i.Body)
	if err != nil || updated.Revision.value != i.Revision.value+1 {
		t.Fatal("no-op must increment")
	}
	if calls.Load() != 2 {
		t.Fatal("stale issue was replayed or verified")
	}
}

func TestMarkdownBoundedConditionalCalls(t *testing.T) {
	var step int
	c, calls := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		step++
		if r.URL.Path != "/api/v1/repos/probe-admin/probe-tracker/contents/probe.md" {
			t.Error("file path escaped capability")
		}
		if step == 2 {
			if r.Method != "GET" || r.URL.RawQuery != "ref=main" {
				t.Error("file read contract")
			}
			writeJSON(t, w, 200, fileJSON("# one\n", true))
			return
		}
		var p struct {
			Branch  string `json:"branch"`
			Message string `json:"message"`
			Content string `json:"content"`
			SHA     string `json:"sha"`
		}
		decodeRequest(t, r, &p)
		if p.Branch != "main" || p.Message == "" {
			t.Error("file branch/message")
		}
		content := "# one\n"
		status := 201
		if step == 1 {
			if r.Method != "POST" || p.SHA != "" {
				t.Error("create file contract")
			}
		} else {
			content = "# two\n"
			status = 200
			if r.Method != "PUT" || p.SHA != blobSHA("# one\n") {
				t.Error("file CAS missing")
			}
		}
		if p.Content != base64.StdEncoding.EncodeToString([]byte(content)) {
			t.Error("content encoding")
		}
		writeJSON(t, w, status, map[string]any{"content": fileJSON(content, false)})
	})
	x, err := c.createMarkdown(context.Background(), repoFixture(c), "probe.md", "# one\n")
	if err != nil {
		t.Fatal(err)
	}
	y, err := c.getMarkdown(context.Background(), x.Ref)
	if err != nil || y.Revision != x.Revision || y.Content != x.Content {
		t.Fatal("file read did not match")
	}
	y, err = c.updateMarkdown(context.Background(), x.Ref, x.Revision, "# two\n")
	if err != nil || y.Content != "# two\n" || y.Revision == x.Revision {
		t.Fatal("file update failed")
	}
	if calls.Load() != 3 {
		t.Fatal("extra file provider call")
	}
}

func TestMutationFailuresNeverReplayOrLeak(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		status                int
		body, ctype, encoding string
		want                  Completion
	}{
		{"server", 500, "secret", "application/json", "", Uncertain},
		{"generic422", 422, "secret", "application/json", "", Uncertain},
		{"redirect", 307, "secret", "application/json", "", Uncertain},
		{"denied", 404, "secret", "application/json", "", Rejected},
		{"wrongSuccess", 200, "{}", "application/json", "", Uncertain},
		{"truncated", 201, "{", "application/json", "", Uncertain},
		{"duplicate", 201, `{"id":1,"id":2}`, "application/json", "", Uncertain},
		{"wrongType", 201, `{"id":"1"}`, "application/json", "", Uncertain},
		{"trailing", 201, "{}{}", "application/json", "", Uncertain},
		{"oversize", 201, strings.Repeat(" ", maxResponseBytes+1), "application/json", "", Uncertain},
		{"charset", 201, "{}", "application/json; charset=iso-8859-1", "", Uncertain},
		{"compressed", 201, "{}", "application/json", "gzip", Uncertain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var redirected atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
			defer target.Close()
			c, calls := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.ctype)
				w.Header().Set("Content-Encoding", tc.encoding)
				w.Header().Set("Location", target.URL)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := c.createIssue(context.Background(), repoFixture(c), "Synthetic", "private-content-canary")
			wantCompletion(t, err, tc.want)
			if calls.Load() != 1 || redirected.Load() != 0 {
				t.Fatal("mutation retried or redirected")
			}
		})
	}
}

func TestDispatchTimeoutDisconnectAndPrecancel(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(fmt.Sprint(disconnect), func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			c, calls := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if disconnect {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error("hijack failed")
						return
					}
					_ = conn.Close()
					return
				}
				<-release
			})
			c.http.Timeout = 25 * time.Millisecond
			_, err := c.createIssue(context.Background(), repoFixture(c), "Synthetic", "one")
			wantCompletion(t, err, Uncertain)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = c.createIssue(ctx, repoFixture(c), "Synthetic", "one")
			wantCompletion(t, err, NotDispatched)
			if calls.Load() != 1 {
				t.Fatal("timeout replay or canceled dispatch")
			}
		})
	}
}

func TestInvalidAndCrossBoundInputsNeverDispatch(t *testing.T) {
	c, calls := testClient(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid input dispatched") })
	ctx := context.Background()
	for _, name := range []string{"", "../escape", "x/y", "x?token=secret", "x%2fy", "UPPER", strings.Repeat("a", 81)} {
		_, err := c.createRepository(ctx, name)
		wantCompletion(t, err, NotDispatched)
	}
	for _, body := range []string{strings.Repeat("x", maxContentBytes+1), "bad\x00", string([]byte{255})} {
		_, err := c.createIssue(ctx, repoFixture(c), "Synthetic", body)
		wantCompletion(t, err, NotDispatched)
	}
	for _, title := range []string{" Synthetic", "Synthetic ", "\tSynthetic", "Synthetic\t", "\u00a0Synthetic", "Synthetic\u2003", "\u3000Synthetic\u3000"} {
		_, err := c.createIssue(ctx, repoFixture(c), title, "body")
		wantCompletion(t, err, NotDispatched)
	}
	i := issueFixture(c)
	wrong := i.Revision
	wrong.ref.number++
	_, err := c.updateIssueBody(ctx, i.Ref, wrong, "two")
	wantCompletion(t, err, NotDispatched)
	_, err = c.updateIssueBody(ctx, i.Ref, IssueRevision{}, "two")
	wantCompletion(t, err, NotDispatched)
	_, err = c.getIssue(ctx, IssueRef{})
	wantCompletion(t, err, NotDispatched)
	r := repoFixture(c)
	r.origin = "http://127.0.0.1:1"
	_, err = c.getRepository(ctx, r)
	wantCompletion(t, err, NotDispatched)
	for _, path := range []string{"../a.md", "a/b.md", "a.md?ref=evil", "a.md%2f", "a.txt", ".md"} {
		_, err = c.createMarkdown(ctx, repoFixture(c), path, "x")
		wantCompletion(t, err, NotDispatched)
	}
	m := MarkdownRef{repoFixture(c), "probe.md"}
	_, err = c.updateMarkdown(ctx, m, BlobRevision{}, "x")
	wantCompletion(t, err, NotDispatched)
	other := m
	other.path = "other.md"
	_, err = c.updateMarkdown(ctx, m, BlobRevision{other, blobSHA("x")}, "x")
	wantCompletion(t, err, NotDispatched)
	if calls.Load() != 0 {
		t.Fatal("invalid values reached provider")
	}
}

func TestClientRejectsAmbientAndUnprovenOrigins(t *testing.T) {
	for _, origin := range []string{"http://localhost:3000", "https://127.0.0.1:3000", "http://127.0.0.2:3000", "http://127.0.0.1:03000", "http://127.0.0.1:3000/", "http://127.0.0.1:3000?token=x", "http://user:pass@127.0.0.1:3000", "http://127.0.0.1:3000#secret", "http://127.0.0.1:0"} {
		_, err := newClient(origin, "probe-admin", syntheticToken)
		wantCompletion(t, err, NotDispatched)
	}
	_, err := newClient("http://127.0.0.1:3000", "probe-admin", "bad\r\nsecret")
	wantCompletion(t, err, NotDispatched)
	c, err := newClient("http://127.0.0.1:3000", "probe-admin", syntheticToken)
	if err != nil {
		t.Fatal(err)
	}
	tr := c.http.Transport.(*http.Transport)
	if tr.Proxy != nil || !tr.DisableKeepAlives || !tr.DisableCompression || c.http.Jar != nil || tr.MaxConnsPerHost != 1 || c.http.Timeout != 5*time.Second || tr.MaxResponseHeaderBytes != 16<<10 {
		t.Fatal("transport lost fixed bounded profile")
	}
	for _, v := range []any{c, repoFixture(c), issueFixture(c).Ref, issueFixture(c).Revision, MarkdownRef{repoFixture(c), "secret.md"}, BlobRevision{MarkdownRef{repoFixture(c), "secret.md"}, strings.Repeat("a", 40)}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			s := fmt.Sprintf(format, v)
			if strings.Contains(s, syntheticToken) || strings.Contains(s, "probe-admin") || strings.Contains(s, "secret.md") || strings.Contains(s, "127.0.0.1") {
				t.Fatal("opaque value formatting leaked")
			}
		}
	}
}

func TestOriginMustMatchCompleteCanonicalBytes(t *testing.T) {
	c, calls := testClient(t, func(http.ResponseWriter, *http.Request) {
		t.Error("noncanonical origin dispatched")
	})
	for _, origin := range []string{c.origin + "#", c.origin + "?", c.origin + "?#", c.origin + "#ignored", "HTTP" + strings.TrimPrefix(c.origin, "http")} {
		bad, err := newClient(origin, "probe-admin", syntheticToken)
		wantCompletion(t, err, NotDispatched)
		if bad != nil {
			t.Fatal("noncanonical origin produced a client")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("noncanonical origin reached provider")
	}
}

func TestReadValidationAndExistenceNondisclosure(t *testing.T) {
	for _, mutation := range []string{"missing-version", "float-version", "overflow-version", "negative-version", "wrong-id", "pull-request", "oversized-body", "duplicate-list"} {
		t.Run(mutation, func(t *testing.T) {
			c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				v := issueJSON(exactID, "one")
				switch mutation {
				case "missing-version":
					delete(v, "content_version")
				case "float-version":
					v["content_version"] = 1.5
				case "overflow-version":
					v["content_version"] = json.Number("9223372036854775808")
				case "negative-version":
					v["content_version"] = -1
				case "wrong-id":
					v["id"] = 2
				case "pull-request":
					v["pull_request"] = map[string]any{}
				case "oversized-body":
					v["body"] = strings.Repeat("x", maxContentBytes+1)
				case "duplicate-list":
					writeJSON(t, w, 200, []any{v, v})
					return
				}
				writeJSON(t, w, 200, v)
			})
			var err error
			if mutation == "duplicate-list" {
				_, err = c.firstIssues(context.Background(), repoFixture(c))
			} else {
				_, err = c.getIssue(context.Background(), issueFixture(c).Ref)
			}
			wantCompletion(t, err, ReadFailed)
		})
	}
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "protected existence secret")
	})
	i := issueFixture(c)
	_, err := c.getIssue(context.Background(), i.Ref)
	wantCompletion(t, err, ReadFailed)
	i.Ref.number++
	_, err = c.getIssue(context.Background(), i.Ref)
	wantCompletion(t, err, ReadFailed)
}

func TestMarkdownResponseMustBeExactRegularBoundedBlob(t *testing.T) {
	for _, kind := range []string{"sha", "mode", "symlink", "path", "size", "encoding", "content", "lfs", "newline-base64"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				v := fileJSON("# synthetic", true)
				switch kind {
				case "sha":
					v["sha"] = strings.Repeat("a", 40)
				case "mode":
					v["mode"] = "100755"
				case "symlink":
					v["type"] = "symlink"
					v["target"] = "secret"
				case "path":
					v["path"] = "other.md"
				case "size":
					v["size"] = maxContentBytes + 1
				case "encoding":
					v["encoding"] = "utf-8"
				case "content":
					v["content"] = nil
				case "lfs":
					v["lfs_oid"] = "secret"
				case "newline-base64":
					v["content"] = v["content"].(string) + "\n"
				}
				writeJSON(t, w, 200, v)
			})
			_, err := c.getMarkdown(context.Background(), MarkdownRef{repoFixture(c), "probe.md"})
			wantCompletion(t, err, ReadFailed)
		})
	}
}

func TestJSONBoundsAndDuplicateKeys(t *testing.T) {
	for _, b := range [][]byte{[]byte(`{"a":1,"a":2}`), []byte(`{"a":{"x":1,"x":2}}`), []byte(`{"\u0061":1,"a":2}`), []byte(`{"id":1,"ID":2}`), []byte(`{"size":1,"\u017fize":2}`), []byte(`{"body":"\ud800"}`), []byte(`{"body":"\udc00"}`), []byte("{}[]"), []byte(strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)), {'"', 255, '"'}} {
		if validJSON(b) {
			t.Fatal("ambiguous or unbounded JSON accepted")
		}
	}
	if !validJSON([]byte(`{"id":9007199254740993,"unknown":{"ordinary":true}}`)) {
		t.Fatal("bounded stock extension rejected")
	}
	if !validJSON([]byte(`{"body":"\ud83d\ude00 and \\ud800"}`)) {
		t.Fatal("valid surrogate pair or literal escape rejected")
	}
}

func TestExactLargeIssueNumberAndInitialZeroVersion(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/issues/9007199254740993") {
			t.Error("issue number lost precision")
		}
		v := issueJSON(0, "one")
		v["number"] = exactID
		writeJSON(t, w, 200, v)
	})
	ref := issueFixture(c).Ref
	ref.number = exactID
	i, err := c.getIssue(context.Background(), ref)
	if err != nil || i.Ref.number != exactID || !i.Revision.valid || i.Revision.value != 0 {
		t.Fatal("initial version or exact large index rejected")
	}
}

func TestInvalidSuccessNeverClaimsMutationCompletion(t *testing.T) {
	for _, kind := range []string{"wrong-repo-owner", "public-repo", "empty-repo", "wrong-branch", "unchanged-issue-version", "wrong-file-sha"} {
		t.Run(kind, func(t *testing.T) {
			c, calls := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if kind == "unchanged-issue-version" {
					writeJSON(t, w, 201, issueJSON(exactID, "two"))
					return
				}
				if kind == "wrong-file-sha" {
					v := fileJSON("wrong", false)
					writeJSON(t, w, 201, map[string]any{"content": v})
					return
				}
				v := repoJSON()
				switch kind {
				case "wrong-repo-owner":
					v["owner"] = map[string]string{"login": "other"}
				case "public-repo":
					v["private"] = false
				case "empty-repo":
					v["empty"] = true
				case "wrong-branch":
					v["default_branch"] = "other"
				}
				writeJSON(t, w, 201, v)
			})
			var err error
			switch kind {
			case "unchanged-issue-version":
				i := issueFixture(c)
				_, err = c.updateIssueBody(context.Background(), i.Ref, i.Revision, "two")
			case "wrong-file-sha":
				_, err = c.createMarkdown(context.Background(), repoFixture(c), "probe.md", "expected")
			default:
				_, err = c.createRepository(context.Background(), "probe-tracker")
			}
			wantCompletion(t, err, Uncertain)
			if calls.Load() != 1 {
				t.Fatal("invalid success led to retry/verification")
			}
		})
	}
}
