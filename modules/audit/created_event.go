// Package audit owns safe durable evidence and canonical event serialization.
package audit

import (
	"encoding/json"
	"errors"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
	"github.com/ScottTpirate/stead/modules/organization"
	"time"
)

type actorContext struct {
	Actor         identity.Principal `json:"actor"`
	CorrelationID string             `json:"correlation_id"`
	CausationID   string             `json:"causation_id"`
}
type resourceRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	URI  string `json:"uri"`
}
type createdData struct {
	SchemaVersion  string               `json:"schema_version"`
	OrganizationID string               `json:"organization_id"`
	SecurityDomain string               `json:"security_domain_id"`
	Container      resourceRef          `json:"container"`
	Label          classification.Label `json:"effective_security_label"`
	Actor          actorContext         `json:"actor_context"`
	Resource       resourceRef          `json:"resource"`
	IdempotencyKey string               `json:"idempotency_key"`
	ChangedFields  []string             `json:"changed_fields"`
}
type createdEvent struct {
	SpecVersion     string      `json:"specversion"`
	ID              string      `json:"id"`
	Source          string      `json:"source"`
	Type            string      `json:"type"`
	Subject         string      `json:"subject"`
	Time            time.Time   `json:"time"`
	DataContentType string      `json:"datacontenttype"`
	DataSchema      string      `json:"dataschema"`
	Data            createdData `json:"data"`
}

// CreatedEvent validates the closed Checkpoint A producer shape before the
// composition root wraps its immutable bytes as an outbox intent. It accepts
// canonical owner records, never arbitrary request/event JSON.
func CreatedEvent(eventID string, resource organization.Resource, idempotencyKey, domain, correlationID string) ([]byte, error) {
	if !identity.ValidID(eventID) || !identity.ValidID(resource.ID) || !identity.ValidID(resource.OrganizationID) || !resource.CreatedBy.Valid() || resource.Version != 1 || resource.CreatedAt.IsZero() || resource.Label.Version == 0 || resource.Label.ProfileID == "" || resource.Label.SensitivityLevel == "" || !organization.ValidIdempotencyKey(idempotencyKey) || domain == "" || correlationID == "" {
		return nil, errors.New("invalid created event")
	}
	producer := "organization"
	switch resource.Kind {
	case "organization", "team":
	case "project":
		producer = "project"
	default:
		return nil, errors.New("invalid created event kind")
	}
	ref := resourceRef{Kind: resource.Kind, ID: resource.ID, URI: "urn:uuid:" + resource.ID}
	value := createdEvent{SpecVersion: "1.0", ID: eventID, Source: "urn:stead:producer:" + producer, Type: "stead." + resource.Kind + ".created.v1", Subject: "urn:uuid:" + resource.ID, Time: resource.CreatedAt, DataContentType: "application/json", DataSchema: "https://stead.example/packages/event-schemas/stead/stead-event-v0.1.schema.json", Data: createdData{SchemaVersion: "0.1", OrganizationID: resource.OrganizationID, SecurityDomain: domain, Container: resourceRef{Kind: "organization", ID: resource.OrganizationID, URI: "urn:uuid:" + resource.OrganizationID}, Label: resource.Label.Copy(), Actor: actorContext{Actor: resource.CreatedBy, CorrelationID: correlationID, CausationID: correlationID}, Resource: ref, IdempotencyKey: idempotencyKey, ChangedFields: []string{"created"}}}
	return json.Marshal(value)
}
