package gitea

import (
	"context"
	"net/http"
	"strconv"
)

// RepositoryRef is an opaque backend locator, not a canonical Project ID or an
// authorization capability. Zero values are invalid. No provider URL is exposed.
type RepositoryRef struct {
	origin, owner, name string
	id                  int64
}

func (RepositoryRef) String() string     { return "gitea.repository[opaque]" }
func (r RepositoryRef) GoString() string { return r.String() }

type Repository struct{ Ref RepositoryRef }

type IssueRef struct {
	repo       RepositoryRef
	number, id int64
}

func (IssueRef) String() string     { return "gitea.issue[opaque]" }
func (r IssueRef) GoString() string { return r.String() }

// IssueRevision preserves the exact provider integer, including valid zero.
// It is bound to one issue and cannot be substituted onto a different object.
type IssueRevision struct {
	ref   IssueRef
	value int64
	valid bool
}

func (IssueRevision) String() string     { return "gitea.issue-revision[opaque]" }
func (r IssueRevision) GoString() string { return r.String() }

type Issue struct {
	Ref         IssueRef
	Revision    IssueRevision
	Title, Body string
}

type repositoryWire struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Owner    *struct {
		Login string `json:"login"`
	} `json:"owner"`
	Private       *bool  `json:"private"`
	Empty         *bool  `json:"empty"`
	DefaultBranch string `json:"default_branch"`
}
type issueWire struct {
	ID             int64   `json:"id"`
	Number         int64   `json:"number"`
	Title          *string `json:"title"`
	Body           *string `json:"body"`
	State          string  `json:"state"`
	ContentVersion *int64  `json:"content_version"`
	PullRequest    any     `json:"pull_request"`
}

func (c *client) repoOK(r RepositoryRef) bool {
	return c != nil && r.origin == c.origin && r.owner == c.owner && nameOK(r.name) && r.id > 0
}
func repoPath(r RepositoryRef) string { return "/api/v1/repos/" + r.owner + "/" + r.name }
func issuePath(r IssueRef) string {
	return repoPath(r.repo) + "/issues/" + strconv.FormatInt(r.number, 10)
}
func (c *client) issueOK(r IssueRef) bool { return c.repoOK(r.repo) && r.number > 0 && r.id > 0 }
func (c *client) repository(v repositoryWire, name string) (Repository, bool) {
	if v.ID <= 0 || v.Name != name || v.FullName != c.owner+"/"+name || v.Owner == nil || v.Owner.Login != c.owner || v.Private == nil || !*v.Private || v.Empty == nil || *v.Empty || v.DefaultBranch != "main" {
		return Repository{}, false
	}
	return Repository{RepositoryRef{origin: c.origin, owner: c.owner, name: name, id: v.ID}}, true
}

// createRepository creates only a private initialized main-branch repository.
// Hidden-tracker mapping, managed labels/board, permissions and idempotency are
// NOT implemented here and this response alone does not make a Project ready.
func (c *client) createRepository(ctx context.Context, name string) (Repository, error) {
	if !nameOK(name) {
		return Repository{}, failure(NotDispatched)
	}
	p := struct {
		Name          string `json:"name"`
		Private       bool   `json:"private"`
		AutoInit      bool   `json:"auto_init"`
		DefaultBranch string `json:"default_branch"`
		Readme        string `json:"readme"`
	}{name, true, true, "main", "Default"}
	var v repositoryWire
	if err := c.request(ctx, http.MethodPost, "/api/v1/user/repos", p, 201, false, &v); err != nil {
		return Repository{}, err
	}
	r, ok := c.repository(v, name)
	if !ok {
		return Repository{}, failure(Uncertain)
	}
	return r, nil
}
func (c *client) getRepository(ctx context.Context, r RepositoryRef) (Repository, error) {
	if !c.repoOK(r) {
		return Repository{}, failure(NotDispatched)
	}
	var v repositoryWire
	if err := c.request(ctx, http.MethodGet, repoPath(r), nil, 200, false, &v); err != nil {
		return Repository{}, err
	}
	x, ok := c.repository(v, r.name)
	if !ok || x.Ref != r {
		return Repository{}, failure(ReadFailed)
	}
	return x, nil
}

func decodeIssue(v issueWire, repo RepositoryRef) (Issue, bool) {
	if v.ID <= 0 || v.Number <= 0 || v.Title == nil || !titleOK(*v.Title) || v.Body == nil || !textOK(*v.Body) || v.ContentVersion == nil || *v.ContentVersion < 0 || (v.State != "open" && v.State != "closed") || v.PullRequest != nil {
		return Issue{}, false
	}
	r := IssueRef{repo: repo, number: v.Number, id: v.ID}
	return Issue{Ref: r, Revision: IssueRevision{ref: r, value: *v.ContentVersion, valid: true}, Title: *v.Title, Body: *v.Body}, true
}
func (c *client) createIssue(ctx context.Context, repo RepositoryRef, title, body string) (Issue, error) {
	if !c.repoOK(repo) || !titleOK(title) || !textOK(body) {
		return Issue{}, failure(NotDispatched)
	}
	p := struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}{title, body}
	var v issueWire
	if err := c.request(ctx, http.MethodPost, repoPath(repo)+"/issues", p, 201, false, &v); err != nil {
		return Issue{}, err
	}
	i, ok := decodeIssue(v, repo)
	if !ok || i.Title != title || i.Body != body || v.State != "open" {
		return Issue{}, failure(Uncertain)
	}
	return i, nil
}
func (c *client) getIssue(ctx context.Context, ref IssueRef) (Issue, error) {
	if !c.issueOK(ref) {
		return Issue{}, failure(NotDispatched)
	}
	var v issueWire
	if err := c.request(ctx, http.MethodGet, issuePath(ref), nil, 200, false, &v); err != nil {
		return Issue{}, err
	}
	i, ok := decodeIssue(v, ref.repo)
	if !ok || i.Ref != ref {
		return Issue{}, failure(ReadFailed)
	}
	return i, nil
}

// updateIssueBody sends only the body and mandatory content_version. The pinned
// API's multi-field edit is not atomic; do not extend this into a composite edit.
func (c *client) updateIssueBody(ctx context.Context, ref IssueRef, rev IssueRevision, body string) (Issue, error) {
	if !c.issueOK(ref) || !rev.valid || rev.ref != ref || rev.value < 0 || rev.value == 1<<63-1 || !textOK(body) {
		return Issue{}, failure(NotDispatched)
	}
	p := struct {
		Body    string `json:"body"`
		Version int64  `json:"content_version"`
	}{body, rev.value}
	var v issueWire
	if err := c.request(ctx, http.MethodPatch, issuePath(ref), p, 201, true, &v); err != nil {
		return Issue{}, err
	}
	i, ok := decodeIssue(v, ref.repo)
	// The pinned body handler increments even for identical content.
	if !ok || i.Ref != ref || i.Body != body || i.Revision.value != rev.value+1 {
		return Issue{}, failure(Uncertain)
	}
	return i, nil
}

// firstIssues returns at most ten entries, NOT a complete inventory. It never
// follows Link headers or silently widens a future WS-06 bounded read plan.
func (c *client) firstIssues(ctx context.Context, repo RepositoryRef) ([]Issue, error) {
	if !c.repoOK(repo) {
		return nil, failure(NotDispatched)
	}
	var rows []issueWire
	if err := c.request(ctx, http.MethodGet, repoPath(repo)+"/issues?state=all&page=1&limit=10", nil, 200, false, &rows); err != nil {
		return nil, err
	}
	if rows == nil || len(rows) > 10 {
		return nil, failure(ReadFailed)
	}
	result := make([]Issue, 0, len(rows))
	ids := map[int64]bool{}
	numbers := map[int64]bool{}
	for _, v := range rows {
		i, ok := decodeIssue(v, repo)
		if !ok || ids[i.Ref.id] || numbers[i.Ref.number] {
			return nil, failure(ReadFailed)
		}
		ids[i.Ref.id] = true
		numbers[i.Ref.number] = true
		result = append(result, i)
	}
	return result, nil
}
