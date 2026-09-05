package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/ScottTpirate/stead/modules/authorization"
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
