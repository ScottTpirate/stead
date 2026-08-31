// Package transaction provides the WS-02-owned dependency-free transaction
// and disclosure composition seams. It is internal to apps/core so modules
// outside that application cannot import a unit of work, transaction handle,
// or role selector.
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

// TypedParticipant is a server-startup registration, never request input.
// Owner is fixed here and is not accepted by Bind. After may name only earlier
// participants, making the registered execution order closed and acyclic.
// Operation receives one opaque binding active only during this exact call and
// the statically typed request-local invocation selected by PlanContract[T].
type TypedParticipant[T any] struct {
	Key           string
	Owner         string
	After         []string
	DeclaresWrite bool
	Operation     func(context.Context, SessionBinding, T) (BindingReceipt, error)
}

type participantDefinition struct {
	key                       string
	owner                     string
	after                     []string
	declaresWrite             bool
	logicalAuthorizationAudit bool
	durableEffectHandoff      bool
}

type templateSeal struct{ marker byte }

type templateDefinition struct {
	seal            *templateSeal
	contractVersion string
	key             string
	participants    []participantDefinition
	outboxPolicy    OutboxPolicy
}

// PlanTemplate is an opaque, immutable registration artifact returned by
// NewPlanContract. Request code cannot edit its participants or operations.
type PlanTemplate struct {
	definition *templateDefinition
}

type typedOperation[T any] func(context.Context, SessionBinding, T) (BindingReceipt, error)

// PlanContract preserves the exact invocation type and owner operations for
// one PlanTemplate. Its fields are opaque, so a caller cannot replace or
// reorder participants. Bind accepts no template key, owner, or operation.
type PlanContract[T any] struct {
	definition *templateDefinition
	operations []typedOperation[T]
}

// NewPlanContract freezes a typed plan registration before the registry can
// serve. Mutating the caller's slices afterward cannot affect it.
func NewPlanContract[T any](contractVersion, key string, participants []TypedParticipant[T], policy OutboxPolicy) (PlanTemplate, PlanContract[T], error) {
	definitions := make([]typedParticipantDefinition[T], len(participants))
	for index, participant := range participants {
		definitions[index] = typedParticipantDefinition[T]{
			key:           participant.Key,
			owner:         participant.Owner,
			after:         slices.Clone(participant.After),
			declaresWrite: participant.DeclaresWrite,
			operation:     participant.Operation,
		}
	}
	return newPlanContract(contractVersion, key, definitions, policy)
}

type typedParticipantDefinition[T any] struct {
	key                       string
	owner                     string
	after                     []string
	declaresWrite             bool
	operation                 typedOperation[T]
	logicalAuthorizationAudit bool
	durableEffectHandoff      bool
}

func newPlanContract[T any](contractVersion, key string, participants []typedParticipantDefinition[T], policy OutboxPolicy) (PlanTemplate, PlanContract[T], error) {
	definition := &templateDefinition{
		seal:            &templateSeal{},
		contractVersion: contractVersion,
		key:             key,
		participants:    make([]participantDefinition, len(participants)),
		outboxPolicy:    policy,
	}
	operations := make([]typedOperation[T], len(participants))
	for index, participant := range participants {
		definition.participants[index] = participantDefinition{
			key:                       participant.key,
			owner:                     participant.owner,
			after:                     slices.Clone(participant.after),
			declaresWrite:             participant.declaresWrite,
			logicalAuthorizationAudit: participant.logicalAuthorizationAudit,
			durableEffectHandoff:      participant.durableEffectHandoff,
		}
		operations[index] = participant.operation
	}
	if err := validateTemplateDefinition(definition, operations); err != nil {
		return PlanTemplate{}, PlanContract[T]{}, err
	}
	return PlanTemplate{definition: cloneTemplateDefinition(definition)}, PlanContract[T]{
		definition: cloneTemplateDefinition(definition),
		operations: slices.Clone(operations),
	}, nil
}

func validateTemplateDefinition[T any](definition *templateDefinition, operations []typedOperation[T]) error {
	if definition == nil || definition.seal == nil || definition.contractVersion != ContractVersionV1 ||
		!identifierPattern.MatchString(definition.key) {
		return fail(CodeInvalidContract)
	}
	if len(definition.participants) == 0 || len(definition.participants) > maxParticipants ||
		len(definition.participants) != len(operations) {
		return fail(CodeInvalidPlan)
	}
	if definition.outboxPolicy != OutboxRequired && definition.outboxPolicy != OutboxOptional {
		return fail(CodeInvalidPlan)
	}
	seen := make(map[string]struct{}, len(definition.participants))
	for index, participant := range definition.participants {
		if !identifierPattern.MatchString(participant.key) || !identifierPattern.MatchString(participant.owner) || operations[index] == nil {
			return fail(CodeInvalidPlan)
		}
		if participant.key == "core_outbox" || participant.owner == "core_outbox" {
			return fail(CodeInvalidPlan)
		}
		if _, duplicate := seen[participant.key]; duplicate {
			return fail(CodeInvalidPlan)
		}
		dependencies := make(map[string]struct{}, len(participant.after))
		for _, dependency := range participant.after {
			if _, duplicate := dependencies[dependency]; duplicate {
				return fail(CodeInvalidPlan)
			}
			dependencies[dependency] = struct{}{}
			if _, alreadyDeclared := seen[dependency]; !alreadyDeclared {
				return fail(CodeInvalidPlan)
			}
		}
		seen[participant.key] = struct{}{}
	}
	return nil
}

func cloneTemplateDefinition(source *templateDefinition) *templateDefinition {
	if source == nil {
		return nil
	}
	result := *source
	result.participants = make([]participantDefinition, len(source.participants))
	for index, participant := range source.participants {
		result.participants[index] = participant
		result.participants[index].after = slices.Clone(participant.after)
	}
	return &result
}

type registeredTemplate struct {
	definition *templateDefinition
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
		definition := template.definition
		if definition == nil || definition.seal == nil || definition.contractVersion != ContractVersionV1 ||
			!identifierPattern.MatchString(definition.key) || len(definition.participants) == 0 ||
			len(definition.participants) > maxParticipants ||
			(definition.outboxPolicy != OutboxRequired && definition.outboxPolicy != OutboxOptional) {
			return Registry{}, fail(CodeInvalidPlan)
		}
		if _, exists := registry.templates[definition.key]; exists {
			return Registry{}, fail(CodeInvalidPlan)
		}
		registry.templates[definition.key] = registeredTemplate{definition: cloneTemplateDefinition(definition)}
	}
	return registry, nil
}

// withTemplates creates a coordinator-owned registry snapshot with reserved
// templates added before the coordinator can serve. The original registry map
// remains unchanged, while the registry seal remains the execution authority.
func (registry Registry) withTemplates(templates []PlanTemplate) (Registry, error) {
	if registry.seal == nil || len(registry.templates) == 0 || len(templates) == 0 {
		return Registry{}, fail(CodeInvalidContract)
	}
	result := Registry{seal: registry.seal, templates: make(map[string]registeredTemplate, len(registry.templates)+len(templates))}
	for key, template := range registry.templates {
		result.templates[key] = registeredTemplate{definition: cloneTemplateDefinition(template.definition)}
	}
	for _, template := range templates {
		definition := template.definition
		if definition == nil || definition.seal == nil || definition.contractVersion != ContractVersionV1 ||
			!identifierPattern.MatchString(definition.key) || len(definition.participants) == 0 {
			return Registry{}, fail(CodeInvalidContract)
		}
		if _, exists := result.templates[definition.key]; exists {
			return Registry{}, fail(CodeInvalidContract)
		}
		result.templates[definition.key] = registeredTemplate{definition: cloneTemplateDefinition(definition)}
	}
	return result, nil
}

const (
	planReady uint32 = iota
	planRunning
	planFinished
)

type planState struct {
	state atomic.Uint32
}

// Plan is an immutable, single-use binding of a release-registered template,
// one statically typed request invocation, and zero or one validated intent.
// It deliberately has no Add, Begin, Commit, Rollback, or Retry method.
type Plan struct {
	registry     *registrySeal
	templateSeal *templateSeal
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
	operation                 func(context.Context, SessionBinding) (BindingReceipt, error)
}

// Bind accepts only the exact Registry containing this contract's immutable
// template, the contract's static invocation type T, and an optional validated
// intent. It accepts no key, owner, participant, operation, or ordering input.
func (contract PlanContract[T]) Bind(registry Registry, invocation T, intent *outbox.ValidatedIntent) (Plan, error) {
	return contract.bind(registry, invocation, intent, nil)
}

func (contract PlanContract[T]) bind(registry Registry, invocation T, intent *outbox.ValidatedIntent, deferredIntent func(T) *outbox.ValidatedIntent) (Plan, error) {
	if contract.definition == nil || contract.definition.seal == nil || registry.seal == nil || len(contract.operations) == 0 {
		return Plan{}, fail(CodeInvalidPlan)
	}
	if isNil(invocation) {
		return Plan{}, fail(CodeInvalidPlan)
	}
	registered, exists := registry.templates[contract.definition.key]
	if !exists || registered.definition == nil || registered.definition.seal != contract.definition.seal ||
		len(registered.definition.participants) != len(contract.operations) {
		return Plan{}, fail(CodeInvalidPlan)
	}
	participants := make([]runtimeParticipant, len(contract.operations))
	for index, operation := range contract.operations {
		if operation == nil {
			return Plan{}, fail(CodeInvalidPlan)
		}
		definition := registered.definition.participants[index]
		typedOperation := operation
		participants[index] = runtimeParticipant{
			owner:                     definition.owner,
			declaresWrite:             definition.declaresWrite,
			logicalAuthorizationAudit: definition.logicalAuthorizationAudit,
			durableEffectHandoff:      definition.durableEffectHandoff,
			operation: func(ctx context.Context, binding SessionBinding) (BindingReceipt, error) {
				return typedOperation(ctx, binding, invocation)
			},
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
	if registered.definition.outboxPolicy == OutboxRequired && intentCopy == nil && deferredIntent == nil {
		return Plan{}, fail(CodeInvalidPlan)
	}
	intentSource := func() *outbox.ValidatedIntent {
		if deferredIntent != nil {
			return deferredIntent(invocation)
		}
		if intentCopy == nil {
			return nil
		}
		value := *intentCopy
		return &value
	}
	return Plan{
		registry:     registry.seal,
		templateSeal: registered.definition.seal,
		templateKey:  registered.definition.key,
		participants: participants,
		outboxPolicy: registered.definition.outboxPolicy,
		intent:       intentSource,
		state:        &planState{},
	}, nil
}
