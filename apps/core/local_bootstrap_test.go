package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/localdev"
	"github.com/ScottTpirate/stead/modules/identity"
)

func TestLocalCommandsRejectArgumentsBeforeBootstrap(t *testing.T) {
	var output bytes.Buffer
	if runDevBootstrap([]string{"--unsafe"}, &output) != 2 {
		t.Fatal("unexpected bootstrap options")
	}
	if runDevCatalogCheck([]string{"--repair"}, &output) != 2 {
		t.Fatal("catalog repair option admitted")
	}
	output.Reset()
	if runDevTemplateInspect([]string{"--template=other"}, &output, &output) != 2 {
		t.Fatal("template override admitted")
	}
}

func TestLocalBootstrapSecondUserMetadataAndPrivateCredential(t *testing.T) {
	record := localBootstrapRecord{InstanceID: "019ed5bf-0000-7000-8000-000000000001", LabelID: "019ed5bf-0000-7000-8000-000000000002", PrincipalID: "019ed5bf-0000-7000-8000-000000000003", SessionID: "019ed5bf-0000-7000-8000-000000000004", UnprivilegedPrincipalID: "019ed5bf-0000-7000-8000-000000000005", UnprivilegedSessionID: "019ed5bf-0000-7000-8000-000000000006"}
	if !validLocalBootstrapUserIDs(record) {
		t.Fatal("distinct fixed bootstrap identities rejected")
	}
	for _, duplicate := range []string{"", "invalid", record.InstanceID, record.LabelID, record.PrincipalID, record.SessionID, record.UnprivilegedSessionID} {
		changed := record
		changed.UnprivilegedPrincipalID = duplicate
		if validLocalBootstrapUserIDs(changed) {
			t.Fatal("ambiguous second bootstrap principal accepted")
		}
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	primary, _, err := identity.NewLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	unprivileged, _, err := identity.NewLocalToken()
	if err != nil || primary == unprivileged {
		t.Fatal("distinct local credentials unavailable")
	}
	primaryPath := filepath.Join(directory, "one-time-login-token")
	unprivilegedPath := filepath.Join(directory, "one-time-unprivileged-login-token")
	if localdev.WriteExclusive(primaryPath, []byte(primary)) != nil || localdev.WriteExclusive(unprivilegedPath, []byte(unprivileged)) != nil {
		t.Fatal("private distinct credentials not persisted")
	}
	if localdev.WriteExclusive(unprivilegedPath, []byte(primary)) == nil {
		t.Fatal("second credential overwritten")
	}
	for filename, want := range map[string]string{primaryPath: primary, unprivilegedPath: unprivileged} {
		actual, err := localdev.ReadPrivate(filename, 128)
		if err != nil || string(actual) != want {
			t.Fatal("credential content or private file boundary changed")
		}
	}
}

func TestLocalMetadataIsPrivateClosedAndCanonical(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	type record struct {
		ID              string `json:"id"`
		DevelopmentOnly bool   `json:"development_only"`
	}
	for name, data := range map[string]string{"good": `{"id":"local","development_only":true}`, "unknown": `{"id":"local","development_only":true,"extra":true}`, "duplicate": `{"id":"other","id":"local","development_only":true}`, "alias": `{"ID":"local","development_only":true}`, "missing": `{"id":"local"}`, "invalid-utf8": "{\"id\":\"\xff\",\"development_only\":true}"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name+".json")
			if err := localdev.WriteExclusive(path, []byte(data)); err != nil {
				t.Fatal(err)
			}
			value, err := readLocalMetadata[record](path, 4096)
			if name == "good" {
				if err != nil || value.ID != "local" {
					t.Fatal("canonical metadata rejected")
				}
			} else if err == nil {
				t.Fatal("ambiguous local metadata accepted")
			}
		})
	}
	if err := os.WriteFile(filepath.Join(directory, "public.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalMetadata[record](filepath.Join(directory, "public.json"), 4096); err == nil {
		t.Fatal("public trust metadata admitted")
	}
}

func TestBootstrapRejectsUnsafeConfigBeforeExternalEffects(t *testing.T) {
	if err := bootstrapLocal(context.Background(), ".", localdev.Config{}, func(string) string { return "" }, nil); err != localStageError("private-configuration") {
		t.Fatal("incomplete configuration reached external effect")
	}
	var runtime *localRuntime
	if runtime.ready(context.Background()) == nil {
		t.Fatal("empty runtime ready")
	}
}
