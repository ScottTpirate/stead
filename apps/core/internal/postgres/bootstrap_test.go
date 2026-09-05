package postgres

import (
	"context"
	"crypto/sha256"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
)

func TestBootstrapRejectsOtherInstallationBeforeDatabaseAccess(t *testing.T) {
	_, err := Bootstrap(context.Background(), BootstrapConfig{
		AdminDSN: "intentionally-invalid-dsn", InstanceID: "019ed5bf-0000-7000-8000-000000000001",
		ActivationBinding: authorization.ActivationBinding{InstallationID: "019ed5bf-0000-7000-8000-000000000002"},
	})
	if err == nil || !strings.Contains(err.Error(), "installation binding mismatch") {
		t.Fatal("foreign installation reached database bootstrap", err)
	}
}

func bootstrapUsersFixture() (BootstrapConfig, time.Time) {
	now := time.Now().UTC().Add(-time.Second)
	instance, label := "019ed5bf-0000-7000-8000-000000000001", "019ed5bf-0000-7000-8000-000000000002"
	session := identity.SessionRecord{ID: "019ed5bf-0000-7000-8000-000000000003", Principal: identity.Principal{Type: "user", ID: "019ed5bf-0000-7000-8000-000000000004"}, InstanceID: instance, SecurityDomain: "stead-local-development", Authority: "stead_local_identity", AuthenticationStrength: "local_bootstrap", Environment: "local-development", NetworkZone: "loopback", DeviceTrust: "local", Revision: 1, PrincipalRevision: 1, Active: true, PrincipalActive: true, IssuedAt: now, ExpiresAt: now.Add(time.Hour), ClassificationCeilings: map[string]string{"commercial": "internal"}}
	unprivileged := session
	unprivileged.ID, unprivileged.Principal.ID = "019ed5bf-0000-7000-8000-000000000005", "019ed5bf-0000-7000-8000-000000000006"
	unprivileged.ClassificationCeilings = maps.Clone(session.ClassificationCeilings)
	config := BootstrapConfig{AdminDSN: "intentionally-invalid-dsn", AppPassword: strings.Repeat("synthetic-only-", 3), InstanceID: instance, LabelID: label, SecurityDomain: session.SecurityDomain, OpenFGAStoreID: "test-only-store", ActivationBinding: authorization.ActivationBinding{InstallationID: instance, DeploymentPolicyID: session.SecurityDomain, OpenFGAStoreID: "test-only-store", OpenFGAModelID: "test-only-model", ActivationSetID: "test-only-activation", ActivationSequence: 1}, PolicyTimeHighWater: now, PolicyTimeRevision: 1, Label: classification.Label{ProfileID: "commercial", SensitivityLevel: "internal", Version: 1}, Session: session, TokenDigest: sha256.Sum256([]byte("primary-synthetic-test-only")), UnprivilegedSession: unprivileged, UnprivilegedTokenDigest: sha256.Sum256([]byte("unprivileged-synthetic-test-only"))}
	return config, now
}

func TestBootstrapRequiresTwoDistinctUsersBeforeDatabaseAccess(t *testing.T) {
	for name, change := range map[string]func(*BootstrapConfig){
		"missing second user":          func(c *BootstrapConfig) { c.UnprivilegedSession = identity.SessionRecord{} },
		"duplicate principal":          func(c *BootstrapConfig) { c.UnprivilegedSession.Principal = c.Session.Principal },
		"duplicate session":            func(c *BootstrapConfig) { c.UnprivilegedSession.ID = c.Session.ID },
		"principal-session collision":  func(c *BootstrapConfig) { c.UnprivilegedSession.Principal.ID = c.Session.ID },
		"session-principal collision":  func(c *BootstrapConfig) { c.UnprivilegedSession.ID = c.Session.Principal.ID },
		"same own principal-session":   func(c *BootstrapConfig) { c.UnprivilegedSession.ID = c.UnprivilegedSession.Principal.ID },
		"installation collision":       func(c *BootstrapConfig) { c.UnprivilegedSession.Principal.ID = c.InstanceID },
		"label-installation collision": func(c *BootstrapConfig) { c.LabelID = c.InstanceID },
		"duplicate credential":         func(c *BootstrapConfig) { c.UnprivilegedTokenDigest = c.TokenDigest },
		"missing primary credential":   func(c *BootstrapConfig) { c.TokenDigest = [sha256.Size]byte{} },
		"missing second credential":    func(c *BootstrapConfig) { c.UnprivilegedTokenDigest = [sha256.Size]byte{} },
		"changed signed ceilings":      func(c *BootstrapConfig) { c.UnprivilegedSession.ClassificationCeilings["commercial"] = "restricted" },
		"changed issue time": func(c *BootstrapConfig) {
			c.UnprivilegedSession.IssuedAt = c.UnprivilegedSession.IssuedAt.Add(-time.Second)
		},
		"changed expiry": func(c *BootstrapConfig) {
			c.UnprivilegedSession.ExpiresAt = c.UnprivilegedSession.ExpiresAt.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, now := bootstrapUsersFixture()
			if !validBootstrapUsers(config, now) {
				t.Fatal("valid fixed two-user fixture rejected")
			}
			change(&config)
			if validBootstrapUsers(config, now) {
				t.Fatal("ambiguous initial users accepted")
			}
			if _, err := Bootstrap(context.Background(), config); err == nil || err.Error() != "invalid bootstrap configuration" {
				t.Fatal("ambiguous initial users reached database parsing", err)
			}
		})
	}
	config, _ := bootstrapUsersFixture()
	if _, err := Bootstrap(context.Background(), config); err == nil || err.Error() != "bootstrap database identity rejected" {
		t.Fatal("valid fixed two-user input did not reach the deliberately invalid database identity")
	}
}

func TestBootstrapBothUsersRetainCanonicalLocalContextBounds(t *testing.T) {
	for _, second := range []bool{false, true} {
		for name, change := range map[string]func(*identity.SessionRecord){
			"agent":                      func(s *identity.SessionRecord) { s.Principal.Type = "agent" },
			"foreign instance":           func(s *identity.SessionRecord) { s.InstanceID = "019ed5bf-0000-7000-8000-000000000009" },
			"foreign domain":             func(s *identity.SessionRecord) { s.SecurityDomain = "production" },
			"foreign authority":          func(s *identity.SessionRecord) { s.Authority = "other" },
			"foreign authentication":     func(s *identity.SessionRecord) { s.AuthenticationStrength = "other" },
			"production environment":     func(s *identity.SessionRecord) { s.Environment = "production" },
			"nonlocal network":           func(s *identity.SessionRecord) { s.NetworkZone = "public" },
			"untrusted device":           func(s *identity.SessionRecord) { s.DeviceTrust = "untrusted" },
			"inactive session":           func(s *identity.SessionRecord) { s.Active = false },
			"inactive principal":         func(s *identity.SessionRecord) { s.PrincipalActive = false },
			"changed revision":           func(s *identity.SessionRecord) { s.Revision++ },
			"changed principal revision": func(s *identity.SessionRecord) { s.PrincipalRevision++ },
			"empty ceilings":             func(s *identity.SessionRecord) { s.ClassificationCeilings = nil },
			"empty ceiling":              func(s *identity.SessionRecord) { s.ClassificationCeilings["commercial"] = "" },
			"future issued":              func(s *identity.SessionRecord) { s.IssuedAt = s.IssuedAt.Add(time.Minute) },
			"expired":                    func(s *identity.SessionRecord) { s.ExpiresAt = s.IssuedAt },
			"overlong":                   func(s *identity.SessionRecord) { s.ExpiresAt = s.IssuedAt.Add(8*time.Hour + time.Nanosecond) },
		} {
			t.Run(name, func(t *testing.T) {
				config, now := bootstrapUsersFixture()
				session := &config.Session
				if second {
					session = &config.UnprivilegedSession
				}
				change(session)
				if validBootstrapUsers(config, now) {
					t.Fatal("unsafe canonical local session accepted")
				}
			})
		}
	}
}

func TestFreshBootstrapRejectsWrongDatabaseBeforeConnecting(t *testing.T) {
	for _, name := range []string{"", "postgres", "template0", "template1", "gitea", "openfga", "Stead", "stead;drop", strings.Repeat("s", 64)} {
		if bootstrapDatabaseName(name) {
			t.Fatal("reserved or unsafe bootstrap name accepted", name)
		}
	}
	if err := CheckFreshBootstrapDatabase(context.Background(), "host=/missing user=bootstrap dbname=wrong", "stead"); err == nil || !strings.Contains(err.Error(), "identity rejected") {
		t.Fatal("DSN mismatch reached database", err)
	}
}

func TestExistingBootstrapCatalogRejectsWrongIdentityBeforeConnecting(t *testing.T) {
	instance := "019ed5bf-0000-7000-8000-000000000001"
	for _, fixture := range []struct{ dsn, instance string }{
		{"host=/missing user=bootstrap dbname=wrong", instance},
		{"host=/missing user=bootstrap dbname=stead", "invalid"},
		{"host=/missing user=" + RuntimeRole(instance) + " dbname=stead", instance},
		{"intentionally-invalid-dsn", instance},
	} {
		if err := CheckExistingBootstrapCatalog(context.Background(), fixture.dsn, fixture.instance); err == nil || err.Error() != "existing bootstrap catalog rejected" {
			t.Fatal("wrong startup identity or leaked diagnostic", err)
		}
	}
}
