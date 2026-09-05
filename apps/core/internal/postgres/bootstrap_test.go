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
