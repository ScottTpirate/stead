//go:build gitea_contract && linux

package gitea

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

// This is an opt-in consumer for the independently reviewed, fresh synthetic
// probe controller, NOT a product authorization bypass or a developer endpoint.
// The controller must bind this compiled binary/configuration in its exact input
// manifest and acceptance before invoking it. Never point it at a live instance.
// It performs no bootstrap, token minting, service launch, or cleanup/deletion.
func TestRealIsolatedProviderContract(t *testing.T) {
	if os.Getenv("STEAD_GITEA_CONTRACT") != "isolated-synthetic-v1" {
		t.Skip("explicit isolated-provider opt-in absent")
	}
	var launch struct{ HostNetwork, ProfileSHA256, ControllerSHA256, ReviewReference string }
	readPrivateFixtureJSON(t, "/state/launch.json", &launch)
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || launch.HostNetwork == "" || ns == launch.HostNetwork || !hexOK(launch.ProfileSHA256, 64) || !hexOK(launch.ControllerSHA256, 64) || launch.ReviewReference == "" {
		t.Fatal("reviewed isolated launch binding absent")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp == 0 {
		t.Fatal("isolated loopback-only fixture required")
	}
	var config struct {
		Owner       string `json:"owner"`
		AdminToken  string `json:"admin_token"`
		DeniedToken string `json:"denied_token"`
	}
	readPrivateFixtureJSON(t, "/state/adapter-contract.json", &config)
	if config.Owner != "probe-admin" || config.AdminToken == config.DeniedToken {
		t.Fatal("fresh distinct synthetic fixture identities required")
	}
	admin, err := newClient("http://127.0.0.1:13000", config.Owner, config.AdminToken)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := newClient("http://127.0.0.1:13000", config.Owner, config.DeniedToken)
	if err != nil {
		t.Fatal(err)
	}
	adminObserved := &contractObservations{base: admin.http.Transport}
	admin.http.Transport = adminObserved
	deniedObserved := &contractObservations{base: denied.http.Transport}
	denied.http.Transport = deniedObserved
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// Only method/status/count are retained. No credentials, protected bodies,
	// request paths/headers, raw failures, HAR, or body-derived hashes are logged.
	once := func(obs *contractObservations, method string, status int, want Completion, call func() error) {
		t.Helper()
		before := len(obs.calls)
		err := call()
		if want == "" {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			wantCompletion(t, err, want)
		}
		if len(obs.calls) != before+1 || obs.calls[before] != (contractObservation{method, status}) {
			t.Fatal("single-call provider method/status contract failed")
		}
	}
	var tracker, docs Repository
	once(adminObserved, "POST", 201, "", func() error { var e error; tracker, e = admin.createRepository(ctx, "stead-adapter-tracker"); return e })
	once(adminObserved, "POST", 201, "", func() error { var e error; docs, e = admin.createRepository(ctx, "stead-adapter-docs"); return e })
	once(adminObserved, "GET", 200, "", func() error { _, e := admin.getRepository(ctx, tracker.Ref); return e })
	var issue, updated Issue
	once(adminObserved, "POST", 201, "", func() error {
		var e error
		issue, e = admin.createIssue(ctx, tracker.Ref, "Synthetic adapter contract", "Revision one.")
		return e
	})
	once(adminObserved, "GET", 200, "", func() error { var e error; updated, e = admin.getIssue(ctx, issue.Ref); return e })
	if updated.Revision != issue.Revision || updated.Body != issue.Body {
		t.Fatal("issue create/read mismatch")
	}
	once(adminObserved, "PATCH", 201, "", func() error {
		var e error
		updated, e = admin.updateIssueBody(ctx, issue.Ref, issue.Revision, "Revision two.")
		return e
	})
	// This extends the original probe with an actual stale issue-version check.
	// A unit fixture is not evidence that this pinned provider has passed it.
	once(adminObserved, "PATCH", 409, VersionConflict, func() error {
		_, e := admin.updateIssueBody(ctx, issue.Ref, issue.Revision, "Rejected stale body.")
		return e
	})
	once(adminObserved, "GET", 200, "", func() error {
		got, e := admin.getIssue(ctx, issue.Ref)
		if e == nil && (got.Body != updated.Body || got.Revision != updated.Revision) {
			t.Fatal("stale issue write changed provider content")
		}
		return e
	})
	once(adminObserved, "GET", 200, "", func() error {
		rows, e := admin.firstIssues(ctx, tracker.Ref)
		if e == nil && (len(rows) != 1 || rows[0].Ref != issue.Ref || rows[0].Body != updated.Body) {
			t.Fatal("issue projection-source page mismatch")
		}
		return e
	})
	var doc, changed Markdown
	once(adminObserved, "POST", 201, "", func() error {
		var e error
		doc, e = admin.createMarkdown(ctx, docs.Ref, "probe.md", "# Synthetic adapter contract\n\nRevision one.\n")
		return e
	})
	once(adminObserved, "GET", 200, "", func() error {
		got, e := admin.getMarkdown(ctx, doc.Ref)
		if e == nil && got != doc {
			t.Fatal("Markdown create/read mismatch")
		}
		return e
	})
	once(adminObserved, "PUT", 200, "", func() error {
		var e error
		changed, e = admin.updateMarkdown(ctx, doc.Ref, doc.Revision, "# Synthetic adapter contract\n\nRevision two.\n")
		return e
	})
	once(adminObserved, "PUT", 422, Uncertain, func() error {
		_, e := admin.updateMarkdown(ctx, doc.Ref, doc.Revision, "Rejected stale body.")
		return e
	})
	once(adminObserved, "GET", 200, "", func() error {
		got, e := admin.getMarkdown(ctx, doc.Ref)
		if e == nil && got != changed {
			t.Fatal("stale Markdown write changed content")
		}
		return e
	})
	// In this test harness each explicit read is an independent contract action;
	// production may perform none of these reads using a mutation permit.
	unknownRepo := tracker.Ref
	unknownRepo.name = "stead-adapter-unknown"
	unknownIssue := issue.Ref
	unknownIssue.repo = unknownRepo
	unknownDoc := doc.Ref
	unknownDoc.repo = unknownRepo
	for _, ref := range []RepositoryRef{tracker.Ref, unknownRepo} {
		once(deniedObserved, "GET", 404, ReadFailed, func() error { _, e := denied.getRepository(ctx, ref); return e })
	}
	for _, ref := range []IssueRef{issue.Ref, unknownIssue} {
		once(deniedObserved, "GET", 404, ReadFailed, func() error { _, e := denied.getIssue(ctx, ref); return e })
	}
	for _, ref := range []MarkdownRef{doc.Ref, unknownDoc} {
		once(deniedObserved, "GET", 404, ReadFailed, func() error { _, e := denied.getMarkdown(ctx, ref); return e })
	}
	once(deniedObserved, "POST", 404, Rejected, func() error {
		_, e := denied.createIssue(ctx, tracker.Ref, "Denied synthetic write", "not stored")
		return e
	})
	once(deniedObserved, "PUT", 404, Rejected, func() error { _, e := denied.updateMarkdown(ctx, doc.Ref, changed.Revision, "not stored"); return e })
	once(adminObserved, "GET", 200, "", func() error {
		got, e := admin.getMarkdown(ctx, doc.Ref)
		if e == nil && got != changed {
			t.Fatal("denied Markdown write changed content")
		}
		return e
	})
	once(adminObserved, "GET", 200, "", func() error {
		rows, e := admin.firstIssues(ctx, tracker.Ref)
		if e == nil && len(rows) != 1 {
			t.Fatal("denied issue write created content")
		}
		return e
	})
	t.Logf("isolated provider contract passed: %d owner calls, %d denied calls; stale issue 409; stale Markdown 422; known/unknown reads 404", len(adminObserved.calls), len(deniedObserved.calls))
}

type contractObservation struct {
	method string
	status int
}
type contractObservations struct {
	base  http.RoundTripper
	calls []contractObservation
}

func (o *contractObservations) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := o.base.RoundTrip(r)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	o.calls = append(o.calls, contractObservation{r.Method, status})
	return resp, err
}

func readPrivateFixtureJSON(t *testing.T, path string, out any) {
	t.Helper()
	info, err := os.Lstat("/state")
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private fresh fixture directory required")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("private fixture unavailable")
	}
	f := os.NewFile(uintptr(fd), "private-fixture")
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || info.Size() > 4096 {
		t.Fatal("unsafe private fixture")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 || !validJSON(b) {
		t.Fatal("invalid private fixture")
	}
	defer clear(b)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		t.Fatal("invalid private fixture fields")
	}
}
