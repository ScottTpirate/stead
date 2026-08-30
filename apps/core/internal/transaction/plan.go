// Package transaction provides the WS-02-owned dependency-free transaction
// and disclosure composition seams. It is internal to apps/core so domain and
// security modules cannot import a unit of work, transaction handle, or role
// selector.
package transaction

import (
	"context"
	"regexp"
	"slices"
	"sync/atomic"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

const (
	ContractVersionV1 = "stead.core.transaction-coordinator/v1"
	maxParticipants   = 64
)

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

type OutboxPolicy string

const (
	OutboxRequired OutboxPolicy = "required"
	OutboxOptional OutboxPolicy = "optional"
)

// ParticipantTemplate is a server-owned registration, not request input.
// After may name only participants that precede this participant in the
// declared serial order; this makes the registered graph closed and acyclic.
type ParticipantTemplate struct {
	Key                       string
	Owner                     string
	After                     []string
	DeclaresWrite             bool
	Operation                 OwnerOperation
	logicalAuthorizationAudit bool
	durableEffectHandoff      bool
}

type PlanTemplate struct {
	ContractVersion string
	Key             string
	Participants    []ParticipantTemplate
	OutboxPolicy    OutboxPolicy
}

type registeredTemplate struct {
	key          string
	participants []ParticipantTemplate
	outboxPolicy OutboxPolicy
}

// Registry is immutable after NewRegistry returns. There is no registration,
// discovery, or mutation method on a live coordinator.
type Registry struct {
	seal      *registrySeal
	templates map[string]registeredTemplate
}

type registrySeal struct{ marker byte }

func NewRegistry(templates []PlanTemplate) (Registry, error) {
	if len(templates) == 0 {
		return Registry{}, fail(CodeInvalidPlan)
	}
	registry := Registry{seal: &registrySeal{}, templates: make(map[string]registeredTemplate, len(templates))}
	for _, template := range templates {
		if err := validateTemplate(template); err != nil {
			return Registry{}, err
		}
		if _, exists := registry.templates[template.Key]; exists {
			return Registry{}, fail(CodeInvalidPlan)
		}
		participants := cloneParticipantTemplates(template.Participants)
		registry.templates[template.Key] = registeredTemplate{
			key:          template.Key,
			participants: participants,
			outboxPolicy: template.OutboxPolicy,
		}
	}
	return registry, nil
}

func cloneParticipantTemplates(source []ParticipantTemplate) []ParticipantTemplate {
	result := make([]ParticipantTemplate, len(source))
	for index, participant := range source {
		result[index] = participant
		result[index].After = slices.Clone(participant.After)
	}
	return result
}

// withTemplates creates a coordinator-owned registry snapshot with reserved
// templates added before the coordinator can serve. It preserves the original
// seal so plans already minted by the caller's immutable registry remain valid,
// while the copied map prevents the reserved templates from mutating or
// becoming visible through that caller-owned value.
func (registry Registry) withTemplates(templates []PlanTemplate) (Registry, error) {
	if registry.seal == nil || len(registry.templates) == 0 || len(templates) == 0 {
		return Registry{}, fail(CodeInvalidContract)
	}
	result := Registry{
		seal:      registry.seal,
		templates: make(map[string]registeredTemplate, len(registry.templates)+len(templates)),
	}
	for key, template := range registry.templates {
		result.templates[key] = registeredTemplate{
			key:          template.key,
			participants: cloneParticipantTemplates(template.participants),
			outboxPolicy: template.outboxPolicy,
		}
	}
	for _, template := range templates {
		if err := validateTemplate(template); err != nil {
			return Registry{}, err
		}
		if _, exists := result.templates[template.Key]; exists {
			return Registry{}, fail(CodeInvalidContract)
		}
		result.templates[template.Key] = registeredTemplate{
			key:          template.Key,
			participants: cloneParticipantTemplates(template.Participants),
			outboxPolicy: template.OutboxPolicy,
		}
	}
	return result, nil
}

func validateTemplate(template PlanTemplate) error {
	if template.ContractVersion != ContractVersionV1 || !identifierPattern.MatchString(template.Key) {
		return fail(CodeInvalidContract)
	}
	if len(template.Participants) == 0 || len(template.Participants) > maxParticipants {
		return fail(CodeInvalidPlan)
	}
	if template.OutboxPolicy != OutboxRequired && template.OutboxPolicy != OutboxOptional {
		return fail(CodeInvalidPlan)
	}
	seen := make(map[string]struct{}, len(template.Participants))
	for _, participant := range template.Participants {
		if !identifierPattern.MatchString(participant.Key) || !identifierPattern.MatchString(participant.Owner) {
			return fail(CodeInvalidPlan)
		}
		if participant.Operation == nil {
			return fail(CodeInvalidPlan)
		}
		if participant.Key == "core_outbox" || participant.Owner == "core_outbox" {
			return fail(CodeInvalidPlan)
		}
		if _, duplicate := seen[participant.Key]; duplicate {
			return fail(CodeInvalidPlan)
		}
		dependencies := make(map[string]struct{}, len(participant.After))
		for _, dependency := range participant.After {
			if _, duplicate := dependencies[dependency]; duplicate {
				return fail(CodeInvalidPlan)
			}
			dependencies[dependency] = struct{}{}
			if _, alreadyDeclared := seen[dependency]; !alreadyDeclared {
				return fail(CodeInvalidPlan)
			}
		}
		seen[participant.Key] = struct{}{}
	}
	return nil
}

type capabilityState struct {
	registry *registrySeal
	plan     *planState
	owner    string
	active   atomic.Bool
}

// OwnerCapability is a short-lived opaque proof that the coordinator is
// currently invoking one registered owner participant. It exposes no driver,
// SQL, role, connection, transaction, commit, rollback, or widening method.
type OwnerCapability struct {
	state *capabilityState
}

func (capability OwnerCapability) ValidFor(owner string) bool {
	return capability.state != nil && capability.state.registry != nil && capability.state.plan != nil &&
		capability.state.active.Load() && capability.state.owner == owner && capability.state.plan.state.Load() == planRunning
}

// OwnerOperation is bound to one exact registered participant before Begin.
// The callback receives only the opaque owner capability and must invoke its
// owner-authored typed port; it cannot obtain transaction machinery here.
type OwnerOperation func(context.Context, OwnerCapability) error

const (
	planReady uint32 = iota
	planRunning
	planFinished
)

type planState struct {
	state      atomic.Uint32
	invocation any
}

// Plan is an immutable, single-use binding of a release-registered template's
// owner operations and, when present, one request-scoped validated intent. It
// deliberately has no Add, Begin, Commit, Rollback, or Retry method.
type Plan struct {
	registry     *registrySeal
	templateKey  string
	participants []runtimeParticipant
	outboxPolicy OutboxPolicy
	intent       func() *outbox.ValidatedIntent
	state        *planState
}

type runtimeParticipant struct {
	owner                     string
	declaresWrite             bool
	logicalAuthorizationAudit bool
	durableEffectHandoff      bool
	operation                 OwnerOperation
}

func (registry Registry) Bind(templateKey string, intent *outbox.ValidatedIntent) (Plan, error) {
	return registry.bind(templateKey, intent, nil, nil)
}

// bind is available only inside this package for reserved coordinator-owned
// templates whose final owner operation produces the validated intent. It can
// bind request-local result storage, but it cannot replace, add, remove, or
// reorder any registered participant.
func (registry Registry) bind(templateKey string, intent *outbox.ValidatedIntent, deferredIntent func() *outbox.ValidatedIntent, invocation any) (Plan, error) {
	if registry.seal == nil {
		return Plan{}, fail(CodeInvalidPlan)
	}
	template, exists := registry.templates[templateKey]
	if !exists {
		return Plan{}, fail(CodeInvalidPlan)
	}
	participants := make([]runtimeParticipant, len(template.participants))
	for index, expected := range template.participants {
		participants[index] = runtimeParticipant{
			owner:                     expected.Owner,
			declaresWrite:             expected.DeclaresWrite,
			logicalAuthorizationAudit: expected.logicalAuthorizationAudit,
			durableEffectHandoff:      expected.durableEffectHandoff,
			operation:                 expected.Operation,
		}
	}
	if intent != nil && deferredIntent != nil {
		return Plan{}, fail(CodeInvalidPlan)
	}
	var intentCopy *outbox.ValidatedIntent
	if intent != nil {
		if err := intent.Verify(); err != nil {
			return Plan{}, fail(CodeInvalidPlan)
		}
		value := *intent
		intentCopy = &value
	}
	if template.outboxPolicy == OutboxRequired && intentCopy == nil && deferredIntent == nil {
		return Plan{}, fail(CodeInvalidPlan)
	}
	intentSource := deferredIntent
	if intentSource == nil {
		intentSource = func() *outbox.ValidatedIntent {
			if intentCopy == nil {
				return nil
			}
			value := *intentCopy
			return &value
		}
	}
	return Plan{
		registry:     registry.seal,
		templateKey:  template.key,
		participants: participants,
		outboxPolicy: template.outboxPolicy,
		intent:       intentSource,
		state:        &planState{invocation: invocation},
	}, nil
}
