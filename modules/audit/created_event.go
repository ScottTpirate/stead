// Package audit owns safe durable evidence and canonical event serialization.
package audit

import (
	"encoding/json"
	"errors"
	"github.com/ScottTpirate/stead/modules/authorization"
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
type createdData struct {
	SchemaVersion  string                    `json:"schema_version"`
	OrganizationID string                    `json:"organization_id"`
	SecurityDomain string                    `json:"security_domain_id"`
	Container      authorization.ResourceRef `json:"container"`
	Label          classification.Label      `json:"effective_security_label"`
	Actor          actorContext              `json:"actor_context"`
	Resource       authorization.ResourceRef `json:"resource"`
	IdempotencyKey string                    `json:"idempotency_key"`
	ChangedFields  []string                  `json:"changed_fields"`
}
type createdEvent struct {
	SpecVersion     string      `json:"specversion"`
	ID              string      `json:"id"`
	Source          string      `json:"source"`
	Type            string      `json:"type"`
	Subject         string      `json:"subject"`
	Time            time.Time   `json:"time"`
	DataContentType string      `json:"datacontenttype"`
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
	ref := authorization.ResourceRef{Kind: resource.Kind, ID: resource.ID}
	value := createdEvent{SpecVersion: "1.0", ID: eventID, Source: "urn:stead:producer:" + producer, Type: "stead." + resource.Kind + ".created.v1", Subject: "urn:uuid:" + resource.ID, Time: resource.CreatedAt, DataContentType: "application/json", Data: createdData{SchemaVersion: "0.1", OrganizationID: resource.OrganizationID, SecurityDomain: domain, Container: authorization.ResourceRef{Kind: "organization", ID: resource.OrganizationID}, Label: resource.Label.Copy(), Actor: actorContext{Actor: resource.CreatedBy, CorrelationID: correlationID, CausationID: correlationID}, Resource: ref, IdempotencyKey: idempotencyKey, ChangedFields: []string{"created"}}}
	return json.Marshal(value)
}
