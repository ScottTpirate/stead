package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/localdev"
	"github.com/ScottTpirate/stead/apps/core/internal/postgres"
)

// Full password-presence/ACL catalog inspection uses a one-shot administrative
// process before serving, never an administrative credential in the API. This
// is a read-only startup check, not ongoing privileged runtime monitoring.
func runDevCatalogCheck(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: stead-api dev-catalog-check (private completed local installation required)")
		return 2
	}
	config, err := localdev.Load(os.Getenv, true)
	if err != nil {
		fmt.Fprintln(stderr, "stead-api: private catalog-check configuration rejected")
		return 1
	}
	record, err := readLocalMetadata[localBootstrapRecord](filepath.Join(config.StateDirectory, "bootstrap.json"), 64<<10)
	if err != nil || record.SchemaVersion != "1.0.0" || !record.DevelopmentOnly || record.InstanceID != config.InstanceID || record.SecurityDomain != config.SecurityDomain {
		fmt.Fprintln(stderr, "stead-api: completed installation catalog binding rejected")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if postgres.CheckExistingBootstrapCatalog(ctx, config.DatabaseAdminURL, config.InstanceID) != nil {
		fmt.Fprintln(stderr, "stead-api: startup catalog conformance denied; no privileges or data were changed")
		return 1
	}
	fmt.Fprintln(stderr, "stead-api: read-only startup catalog conformance passed")
	return 0
}
