// This executable emits synthetic inputs through the actual Go event producer
// for the existing JSON Schema gate. It is not a runtime/bootstrap activation.
package main

import (
	"encoding/json"
	"github.com/ScottTpirate/stead/modules/audit"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
	"os"
	"time"
)

func main() {
	events := []json.RawMessage{}
	for _, kind := range []string{"organization", "team", "project"} {
		resource := organization.Resource{ID: "019ed5bf-0000-7000-8000-000000000001", Kind: kind, OrganizationID: "019ed5bf-0000-7000-8000-000000000001", Version: 1, CreatedAt: time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC), CreatedBy: identity.Principal{Type: "user", ID: "019ed5bf-0000-7000-8000-000000000002"}, Label: classification.Label{ProfileID: "local", SensitivityLevel: "internal", Version: 1}}
		data, err := audit.CreatedEvent("019ed5bf-0000-7000-8000-000000000003", resource, "schema-fixture-001", "synthetic-test-domain", "schema-fixture-request")
		if err != nil {
			panic(err)
		}
		events = append(events, data)
	}
	if err := json.NewEncoder(os.Stdout).Encode(events); err != nil {
		panic(err)
	}
}
