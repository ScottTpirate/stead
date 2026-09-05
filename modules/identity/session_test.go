package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

type sessionRepo struct {
	record SessionRecord
	want   [32]byte
	calls  int
	err    error
}

func (repo *sessionRepo) LookupSession(_ context.Context, digest [32]byte) (SessionRecord, error) {
	repo.calls++
	if digest != repo.want {
		return SessionRecord{}, errors.New("not found")
	}
	return repo.record, repo.err
}
func record(now time.Time) SessionRecord {
	return SessionRecord{ID: "019ec4e0-0000-7000-8000-000000000001", Principal: Principal{Type: "user", ID: "019ec4e0-0000-7000-8000-000000000002"}, InstanceID: "019ec4e0-0000-7000-8000-000000000003", SecurityDomain: "local-dev", Authority: "stead_local_identity", AuthenticationStrength: "local_bootstrap", NetworkZone: "loopback", DeviceTrust: "local", Environment: "local-development", ClassificationCeilings: map[string]string{"commercial": "internal"}, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Revision: 1, PrincipalRevision: 1, Active: true, PrincipalActive: true}
}

func TestLocalIdentityIsFreshAndDoesNotCarryPermissions(t *testing.T) {
	now := time.Now().UTC()
	token, digest, err := NewLocalToken()
	if err != nil || digest != sha256.Sum256([]byte(token)) {
		t.Fatal("token generation")
	}
	repo := &sessionRepo{record: record(now), want: digest}
	auth, _ := NewLocalAuthenticator(repo, repo.record.InstanceID, func() time.Time { return now })
	first, err := auth.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	copy := first.Context()
	copy.ClassificationCeilings["commercial"] = "restricted"
	if first.Context().ClassificationCeilings["commercial"] != "internal" {
		t.Fatal("mutable identity context")
	}
	repo.record.Active = false
	if _, err := auth.Authenticate(context.Background(), token); err != ErrUnauthenticated || repo.calls != 2 {
		t.Fatal("revocation cached")
	}
}

func TestLocalIdentityNegativeContexts(t *testing.T) {
	now := time.Now().UTC()
	token, digest, _ := NewLocalToken()
	mutations := map[string]func(*SessionRecord){"agent": func(r *SessionRecord) { r.Principal.Type = "agent" }, "service": func(r *SessionRecord) { r.Principal.Type = "service_account" }, "group": func(r *SessionRecord) { r.Principal.Type = "directory_group" }, "principal-inactive": func(r *SessionRecord) { r.PrincipalActive = false }, "expired": func(r *SessionRecord) { r.ExpiresAt = now }, "future": func(r *SessionRecord) { r.IssuedAt = now.Add(time.Second) }, "wrong-domain": func(r *SessionRecord) { r.SecurityDomain = "" }, "wrong-instance": func(r *SessionRecord) { r.InstanceID = "019ec4e0-0000-7000-8000-000000000004" }, "authority": func(r *SessionRecord) { r.Authority = "untrusted" }, "network": func(r *SessionRecord) { r.NetworkZone = "internet" }, "environment": func(r *SessionRecord) { r.Environment = "production" }, "strength": func(r *SessionRecord) { r.AuthenticationStrength = "none" }, "device": func(r *SessionRecord) { r.DeviceTrust = "unknown" }, "revision": func(r *SessionRecord) { r.Revision = 0 }, "principal-revision": func(r *SessionRecord) { r.PrincipalRevision = 0 }, "ceiling": func(r *SessionRecord) { r.ClassificationCeilings = nil }}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			base := record(now)
			instance := base.InstanceID
			mutate(&base)
			repo := &sessionRepo{record: base, want: digest}
			auth, _ := NewLocalAuthenticator(repo, instance, func() time.Time { return now })
			if _, err := auth.Authenticate(context.Background(), token); err != ErrUnauthenticated {
				t.Fatal("unsafe context authenticated")
			}
		})
	}
	for _, token := range []string{"", token + "=", "Bearer " + token, "!" + token[1:]} {
		repo := &sessionRepo{record: record(now), want: digest}
		auth, _ := NewLocalAuthenticator(repo, repo.record.InstanceID, func() time.Time { return now })
		if _, err := auth.Authenticate(context.Background(), token); err != ErrUnauthenticated || repo.calls != 0 {
			t.Fatal("malformed token reached repository")
		}
	}
}
