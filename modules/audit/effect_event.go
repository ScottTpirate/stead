package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/classification"
	"github.com/ScottTpirate/stead/modules/identity"
)

const EffectEventType = "stead.authorization.effect_changed.v1"
const EffectEventSubject = "stead.authorization.changed.v1"

// EffectEvent is the WS-07 encoder for an owned synchronous User lifecycle
// transition. It validates data, not authority: the caller must commit the exact
// WS-06 transition, protected audit and immutable outbox intent together. This
// event contains no provider locator, payload, credential or terminal proof.
// Service-owned recovery must not borrow the historical User as its actor.
func EffectEvent(eventID string, record authorization.EffectRecord, label classification.Label) ([]byte, error) {
	if !identity.ValidID(eventID) || record.Validate() != nil || label.Version != record.Authorization.Revisions.Label || !effectLabel(label) || !utf8.ValidString(record.Authorization.SecurityDomain) {
		return nil, errors.New("invalid effect event")
	}
	e := record.Authorization
	ref := resourceRef{Kind: "project", ID: record.Binding.Project.ID, URI: "urn:uuid:" + record.Binding.Project.ID}
	value := createdEvent{SpecVersion: "1.0", ID: eventID, Source: "urn:stead:producer:authorization", Type: EffectEventType,
		Subject: ref.URI, Time: record.UpdatedAt, DataContentType: "application/json",
		DataSchema: "https://stead.example/packages/event-schemas/stead/stead-event-v0.1.schema.json",
		Data: createdData{SchemaVersion: "0.1", OrganizationID: e.OrganizationID, SecurityDomain: e.SecurityDomain,
			Container: resourceRef{Kind: "organization", ID: e.OrganizationID, URI: "urn:uuid:" + e.OrganizationID},
			Label:     label.Copy(), Actor: actorContext{Actor: e.Actor, CorrelationID: record.Binding.RequestID, CausationID: record.Binding.OperationID},
			Resource: ref, IdempotencyKey: fmt.Sprintf("%s:%d", record.Binding.EffectID, record.Version), ChangedFields: []string{"effect_" + string(record.State)}}}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("invalid effect event")
	}
	if _, _, err = DecodeEffectEvent(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

// DecodeEffectEvent consumes only the canonical closed serialization produced
// above. Its result is routing metadata, never permission to dispatch, complete
// a permit, acknowledge revocation or disclose a Project. The eventual delivery
// consumer still needs its registered durable outcome and authorization checks.
// Exact re-encoding rejects duplicates, case variants, unknown fields, trailing
// bytes and lossy Unicode decoding without making generic JSON prose a contract.
func DecodeEffectEvent(encoded []byte) (eventID, projectID string, err error) {
	denied := errors.New("invalid effect event")
	if len(encoded) == 0 || len(encoded) > 64<<10 || !utf8.Valid(encoded) {
		return "", "", denied
	}
	var value createdEvent
	if json.Unmarshal(encoded, &value) != nil {
		return "", "", denied
	}
	canonical, e := json.Marshal(value)
	if e != nil || !bytes.Equal(canonical, encoded) {
		return "", "", denied
	}
	d := value.Data
	if value.SpecVersion != "1.0" || !identity.ValidID(value.ID) || value.Source != "urn:stead:producer:authorization" || value.Type != EffectEventType ||
		value.Subject != "urn:uuid:"+d.Resource.ID || value.Time.IsZero() || value.DataContentType != "application/json" ||
		value.DataSchema != "https://stead.example/packages/event-schemas/stead/stead-event-v0.1.schema.json" || d.SchemaVersion != "0.1" ||
		!identity.ValidID(d.OrganizationID) || d.SecurityDomain == "" || d.Container != (resourceRef{Kind: "organization", ID: d.OrganizationID, URI: "urn:uuid:" + d.OrganizationID}) ||
		d.Resource.Kind != "project" || !identity.ValidID(d.Resource.ID) || d.Resource.URI != "urn:uuid:"+d.Resource.ID ||
		!effectLabel(d.Label) || d.Actor.Actor.Type != "user" || !d.Actor.Actor.Valid() ||
		!lowerHex(d.Actor.CorrelationID, 32) || !identity.ValidID(d.Actor.CausationID) || len(d.ChangedFields) != 1 {
		return "", "", denied
	}
	switch d.ChangedFields[0] {
	case "effect_issued", "effect_consumed", "effect_reconciling", "effect_terminal":
	default:
		return "", "", denied
	}
	parts := strings.Split(d.IdempotencyKey, ":")
	if len(parts) != 2 || !identity.ValidID(parts[0]) || len(parts[1]) == 0 || len(parts[1]) > 20 || parts[1][0] == '0' {
		return "", "", denied
	}
	for _, digit := range parts[1] {
		if digit < '0' || digit > '9' {
			return "", "", denied
		}
	}
	if _, err := strconv.ParseUint(parts[1], 10, 64); err != nil {
		return "", "", denied
	}
	return value.ID, d.Resource.ID, nil
}

// The local native evaluator admits sensitivity-only labels. Fail closed on
// unsupported dimensions; never omit them or serialize the internal derivation
// references as though they were complete canonical OWGP ResourceRefs.
func effectLabel(label classification.Label) bool {
	return label.Version > 0 && label.ProfileID != "" && label.SensitivityLevel != "" &&
		utf8.ValidString(label.ProfileID) && utf8.ValidString(label.SensitivityLevel) &&
		len(label.HandlingRegimes)+len(label.Categories)+len(label.Compartments)+len(label.DisseminationControls)+len(label.ReleasableTo)+len(label.ExportControls)+len(label.DerivationSources) == 0 &&
		label.Originator == "" && label.ClassificationAuthority == "" && label.DeclassificationOrReviewInstructions == ""
}

func lowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
