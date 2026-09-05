//go:build linux

package localdev

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func privateFixture(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestPrivateFilesPreserveExistingStateAndDenyUnsafeTargets(t *testing.T) {
	directory := privateFixture(t)
	path := filepath.Join(directory, "credential")
	if err := WriteExclusive(path, []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err := WriteExclusive(path, []byte("replacement")); err == nil {
		t.Fatal("existing state overwritten")
	}
	if data, err := ReadPrivate(path, 32); err != nil || string(data) != "synthetic" {
		t.Fatal("private input unreadable")
	}
	if _, err := ReadPrivate(path, 2); err == nil {
		t.Fatal("size limit ignored")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(link, 32); err == nil {
		t.Fatal("symlink followed")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path, 32); err == nil {
		t.Fatal("shared credential accepted")
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDirectory(directory); err == nil {
		t.Fatal("shared directory accepted")
	}
}

func TestRuntimeDoesNotInheritBootstrapCredentials(t *testing.T) {
	directory := privateFixture(t)
	password := strings.Repeat("a", 64)
	admin := "postgresql://bootstrap:" + password + "@127.0.0.1:15432/stead?sslmode=disable"
	for name, data := range map[string]string{"openfga-key": password, "database-admin-url": admin, "database-password": password, "database-url": admin} {
		if err := WriteExclusive(filepath.Join(directory, name), []byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	environment := map[string]string{
		"STEAD_BOOTSTRAP_STATE_DIR": directory, "STEAD_POLICY_DIR": filepath.Join(directory, "policy"),
		"STEAD_INSTANCE_ID": "019ed5bf-0000-7000-8000-000000000001", "STEAD_SECURITY_DOMAIN": "stead-local-development",
		"STEAD_PUBLIC_ORIGIN": "https://localhost:18443", "STEAD_LISTEN": "127.0.0.1:18000",
		"STEAD_OPENFGA_URL": "http://127.0.0.1:18080", "STEAD_OPENFGA_STORE_ID": "store", "STEAD_OPENFGA_MODEL_ID": "model",
		"STEAD_OPENFGA_TOKEN_FILE": filepath.Join(directory, "openfga-key"), "STEAD_DATABASE_URL_FILE": filepath.Join(directory, "database-url"),
		"STEAD_DATABASE_ADMIN_URL_FILE": filepath.Join(directory, "database-admin-url"), "STEAD_DATABASE_PASSWORD_FILE": filepath.Join(directory, "database-password"),
	}
	getenv := func(key string) string { return environment[key] }
	if _, err := Load(getenv, true); err != nil {
		t.Fatal("valid bootstrap rejected")
	}
	if _, err := Load(getenv, false); err == nil {
		t.Fatal("bootstrap privilege inherited")
	}
	delete(environment, "STEAD_DATABASE_ADMIN_URL_FILE")
	delete(environment, "STEAD_DATABASE_PASSWORD_FILE")
	if _, err := Load(getenv, false); err != nil {
		t.Fatal("valid runtime rejected")
	}
	environment["STEAD_LISTEN"] = "0.0.0.0:18000"
	if _, err := Load(getenv, false); err == nil {
		t.Fatal("external runtime accepted")
	}
}

func TestDatabaseEndpointCannotEscapeLocalDevelopment(t *testing.T) {
	password := strings.Repeat("a", 64)
	base := "postgresql://bootstrap:" + password + "@127.0.0.1:15432/stead?sslmode=disable"
	for _, bad := range []string{strings.Replace(base, "127.0.0.1", "db.example", 1), base + "&search_path=public", strings.Replace(base, "/stead?", "/gitea?", 1), base + "#fragment"} {
		if validDatabase(bad) {
			t.Fatal("unsafe database URL accepted")
		}
	}
	derived, err := RuntimeDatabaseURL(base, "runtime", password+"@:")
	if err != nil || !validDatabase(derived) || strings.Contains(derived, "bootstrap") {
		t.Fatal("runtime URI was not safely derived")
	}
}
