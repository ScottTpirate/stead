// Package gitea contains the inactive WS-03 stock-provider adapter. No exported
// entry point can perform I/O. WS-06 consumed-handle dispatch must land before
// application use; provider credentials are enforcement, not Stead authority.
package gitea

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxResponseBytes = 1 << 20
	maxContentBytes  = 64 << 10
	callTimeout      = 5 * time.Second
)

// Completion describes a failed call, never authorization or permission to retry.
type Completion string

const (
	NotDispatched   Completion = "not_dispatched"
	ReadFailed      Completion = "read_failed"
	Rejected        Completion = "rejected"
	VersionConflict Completion = "version_conflict"
	Uncertain       Completion = "uncertain"
)

// CallError intentionally retains no URL, credential, payload, provider error,
// headers, or wrapped network error. Uncertain writes require reconciliation,
// not replay; even a rejected call cannot reuse its consumed effect handle.
type CallError struct{ completion Completion }

func (e *CallError) Error() string          { return "gitea: " + string(e.completion) }
func (e *CallError) Completion() Completion { return e.completion }
func failure(c Completion) error            { return &CallError{completion: c} }

type client struct {
	origin, owner, token string
	http                 *http.Client
}

func (*client) String() string     { return "gitea.client[private]" }
func (c *client) GoString() string { return c.String() }

// newClient is deliberately private and restricted to the proven private
// loopback profile. It neither loads credentials nor grants dispatch authority.
// Remote/TLS profiles require their own reviewed configuration and tests.
func newClient(origin, owner, token string) (*client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !nameOK(owner) || !hexOK(token, 40) {
		return nil, failure(NotDispatched)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Host != "127.0.0.1:"+strconv.Itoa(port) {
		return nil, failure(NotDispatched)
	}
	t := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		MaxConnsPerHost: 1, MaxResponseHeaderBytes: 16 << 10,
		DialContext:           (&net.Dialer{Timeout: callTimeout}).DialContext,
		ResponseHeaderTimeout: callTimeout,
	}
	return &client{origin: origin, owner: owner, token: token, http: &http.Client{
		Transport: t, Timeout: callTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") },
	}}, nil
}

// request makes exactly one bounded call: no redirects, cookies, proxy, retry,
// Link following, verification read, or background work. Closed-connection use
// prevents net/http's replay of idempotent requests on reused connections.
func (c *client) request(ctx context.Context, method, path string, payload any, status int, issueCAS bool, out any) error {
	if c == nil || c.http == nil || ctx == nil || ctx.Err() != nil {
		return failure(NotDispatched)
	}
	b, err := json.Marshal(payload)
	if err != nil || len(b) > maxResponseBytes {
		return failure(NotDispatched)
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, body)
	if err != nil {
		return failure(NotDispatched)
	}
	// Disable redirect/retry replay even if transport defaults change later.
	req.GetBody = nil
	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	uncertain := ReadFailed
	if method != http.MethodGet {
		uncertain = Uncertain
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return failure(uncertain)
	}
	defer resp.Body.Close()
	if resp.StatusCode != status {
		if method != http.MethodGet {
			switch resp.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
				return failure(Rejected)
			case http.StatusConflict:
				if issueCAS {
					return failure(VersionConflict)
				}
			}
		}
		// In particular, generic file 422 is NOT proof of a stale-SHA conflict.
		// Provider errors are discarded, never parsed for message matching.
		return failure(uncertain)
	}
	media, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) || resp.Header.Get("Content-Encoding") != "" {
		return failure(uncertain)
	}
	b, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(b) > maxResponseBytes || !validJSON(b) || json.Unmarshal(b, out) != nil {
		return failure(uncertain)
	}
	return nil
}

// Stock replies have many irrelevant fields; ignore those after checking the
// complete bounded JSON for duplicates, invalid encoding, and excessive depth.
func validJSON(b []byte) bool {
	if !utf8.Valid(b) || !pairedEscapes(b) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if !jsonValue(d, 0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
func jsonValue(d *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	t, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			s, ok := key.(string)
			// encoding/json also accepts case-folded struct field names. Reject
			// collisions under that interpretation, not just byte-identical keys.
			folded := strings.Map(func(r rune) rune {
				min := r
				for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
					if next < min {
						min = next
					}
				}
				return min
			}, s)
			if err != nil || !ok || keys[folded] || !jsonValue(d, depth+1) {
				return false
			}
			keys[folded] = true
		}
	case '[':
		for d.More() {
			if !jsonValue(d, depth+1) {
				return false
			}
		}
	default:
		return false
	}
	end, err := d.Token()
	return err == nil && ((delim == '{' && end == json.Delim('}')) || (delim == '[' && end == json.Delim(']')))
}

// encoding/json otherwise replaces unpaired escaped UTF-16 surrogates, losing
// the exact provider content. Grammar is checked separately by the decoder.
func pairedEscapes(b []byte) bool {
	inside := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		x, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if x >= 0xdc00 && x <= 0xdfff {
			return false
		}
		if x >= 0xd800 && x <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			y, err := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
			if err != nil || y < 0xdc00 || y > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func nameOK(s string) bool {
	if len(s) < 1 || len(s) > 80 || s[0] == '-' || s[0] == '_' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func hexOK(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func textOK(s string) bool {
	return len(s) <= maxContentBytes && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func titleOK(s string) bool {
	return textOK(s) && strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= 160 && !strings.ContainsAny(s, "\r\n")
}
func markdownPathOK(s string) bool {
	return strings.HasSuffix(s, ".md") && nameOK(strings.TrimSuffix(s, ".md"))
}
