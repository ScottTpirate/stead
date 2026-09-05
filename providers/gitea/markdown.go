package gitea

import (
	"context"
	"crypto/sha1" // Git SHA-1 object identity, not a security signature or policy digest.
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
)

type MarkdownRef struct {
	repo RepositoryRef
	path string
}

func (MarkdownRef) String() string     { return "gitea.markdown[opaque]" }
func (r MarkdownRef) GoString() string { return r.String() }

// BlobRevision is a main-branch content precondition, not whole-branch CAS or
// protection against ABA. It is inseparably bound to one repository/file.
type BlobRevision struct {
	ref MarkdownRef
	sha string
}

func (BlobRevision) String() string     { return "gitea.blob-revision[opaque]" }
func (r BlobRevision) GoString() string { return r.String() }

type Markdown struct {
	Ref      MarkdownRef
	Revision BlobRevision
	Content  string
}

type contentsWire struct {
	Name      string  `json:"name"`
	Path      string  `json:"path"`
	SHA       string  `json:"sha"`
	Type      string  `json:"type"`
	Mode      string  `json:"mode"`
	Size      *int64  `json:"size"`
	Encoding  *string `json:"encoding"`
	Content   *string `json:"content"`
	Target    *string `json:"target"`
	Submodule *string `json:"submodule_git_url"`
	LFSOID    *string `json:"lfs_oid"`
}
type fileWire struct {
	Content *contentsWire `json:"content"`
}

func (c *client) markdownOK(r MarkdownRef) bool { return c.repoOK(r.repo) && markdownPathOK(r.path) }
func markdownPath(r MarkdownRef) string         { return repoPath(r.repo) + "/contents/" + r.path }
func blobSHA(s string) string {
	h := sha1.New()
	_, _ = h.Write([]byte("blob " + strconv.Itoa(len(s)) + "\x00"))
	_, _ = h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
func contentMetaOK(v contentsWire, r MarkdownRef) bool {
	return v.Name == r.path && v.Path == r.path && hexOK(v.SHA, 40) && v.Type == "file" && v.Mode == "100644" && v.Size != nil && *v.Size >= 0 && *v.Size <= maxContentBytes && v.Target == nil && v.Submodule == nil && (v.LFSOID == nil || *v.LFSOID == "")
}
func (c *client) getMarkdown(ctx context.Context, ref MarkdownRef) (Markdown, error) {
	if !c.markdownOK(ref) {
		return Markdown{}, failure(NotDispatched)
	}
	var v contentsWire
	if err := c.request(ctx, http.MethodGet, markdownPath(ref)+"?ref=main", nil, 200, false, &v); err != nil {
		return Markdown{}, err
	}
	if !contentMetaOK(v, ref) || v.Encoding == nil || *v.Encoding != "base64" || v.Content == nil || len(*v.Content) > base64.StdEncoding.EncodedLen(maxContentBytes) {
		return Markdown{}, failure(ReadFailed)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(*v.Content)
	if err != nil || base64.StdEncoding.EncodeToString(b) != *v.Content || !textOK(string(b)) || int64(len(b)) != *v.Size || blobSHA(string(b)) != v.SHA {
		return Markdown{}, failure(ReadFailed)
	}
	return Markdown{ref, BlobRevision{ref, v.SHA}, string(b)}, nil
}
func (c *client) createMarkdown(ctx context.Context, repo RepositoryRef, path, content string) (Markdown, error) {
	ref := MarkdownRef{repo, path}
	if !c.markdownOK(ref) || !textOK(content) {
		return Markdown{}, failure(NotDispatched)
	}
	return c.writeMarkdown(ctx, ref, "", content)
}
func (c *client) updateMarkdown(ctx context.Context, ref MarkdownRef, rev BlobRevision, content string) (Markdown, error) {
	if !c.markdownOK(ref) || rev.ref != ref || !hexOK(rev.sha, 40) || !textOK(content) {
		return Markdown{}, failure(NotDispatched)
	}
	return c.writeMarkdown(ctx, ref, rev.sha, content)
}
func (c *client) writeMarkdown(ctx context.Context, ref MarkdownRef, sha, content string) (Markdown, error) {
	method, status, message := http.MethodPost, 201, "stead: create Markdown"
	if sha != "" {
		method, status, message = http.MethodPut, 200, "stead: update Markdown"
	}
	p := struct {
		Branch  string `json:"branch"`
		Message string `json:"message"`
		Content string `json:"content"`
		SHA     string `json:"sha,omitempty"`
	}{"main", message, base64.StdEncoding.EncodeToString([]byte(content)), sha}
	var v fileWire
	if err := c.request(ctx, method, markdownPath(ref), p, status, false, &v); err != nil {
		return Markdown{}, err
	}
	// The mutation response supplies authoritative blob metadata. Never perform an
	// implicit GET with this mutation's authority. Protected content is our input.
	if v.Content == nil || !contentMetaOK(*v.Content, ref) || *v.Content.Size != int64(len(content)) || v.Content.SHA != blobSHA(content) {
		return Markdown{}, failure(Uncertain)
	}
	return Markdown{ref, BlobRevision{ref, v.Content.SHA}, content}, nil
}
