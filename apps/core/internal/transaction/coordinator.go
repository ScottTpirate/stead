package transaction

import (
	"context"
	"reflect"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

// Backend and Session are WS-02 adapter contracts. They are intentionally
// internal to apps/core and are never passed to an owner participant. Session
// contains only lifecycle methods; the later driver-backed implementation must
// remain in this trusted boundary and expose typed owner repositories instead
// of a raw connection or query executor.
type Backend interface {
	Begin(context.Context) (Session, error)
}

type Session interface {
	Commit(context.Context) error
	Rollback(context.Context) error
}

type Configuration struct {
	Backend                  Backend
	Registry                 Registry
	Outbox                   outbox.AppendPort
	FinalAuthorizationAudit  FinalAuthorizationAuditPort
	DurableEffectPreparation DurableEffectPreparationPort
}

// Report contains fixed, low-cardinality seam counters. PostgreSQL, OpenFGA,
// provider, NATS, browser, and frontend counts remain zero in this dependency-
// free slice; a later instrumented adapter must populate product-path evidence.
type Report struct {
	BeginCalls                    uint64
	ParticipantCalls              uint64
	DeclaredWriteParticipantCalls uint64
	OutboxParticipantCalls        uint64
	OutboxAppendCalls             uint64
	CommitCalls                   uint64
	RollbackCalls                 uint64
	LogicalAuthorizationAudits    uint64
	DurableEffectHandoffs         uint64
	Retries                       uint64
	SQLQueries                    uint64
	PostgreSQLWrites              uint64
	OpenFGACalls                  uint64
	ProviderCalls                 uint64
	NATSWaits                     uint64
	BrowserRequests               uint64
	FrontendBytes                 uint64
}

type Coordinator struct {
	backend                  Backend
	registry                 Registry
	outbox                   outbox.AppendPort
	scopes                   outbox.ScopeAuthority
	finalAuthorizationAudit  FinalAuthorizationAuditPort
	durableEffectPreparation DurableEffectPreparationPort
}

func NewCoordinator(configuration Configuration) (*Coordinator, error) {
	if isNil(configuration.Backend) || isNil(configuration.Outbox) || configuration.Registry.seal == nil {
		return nil, fail(CodeInvalidContract)
	}
	coordinator := &Coordinator{
		backend:                  configuration.Backend,
		outbox:                   configuration.Outbox,
		scopes:                   outbox.NewScopeAuthority(),
		finalAuthorizationAudit:  configuration.FinalAuthorizationAudit,
		durableEffectPreparation: configuration.DurableEffectPreparation,
	}
	registry, err := configuration.Registry.withTemplates(coordinator.reservedTemplates())
	if err != nil {
		return nil, fail(CodeInvalidContract)
	}
	coordinator.registry = registry
	return coordinator, nil
}

func (coordinator *Coordinator) reservedTemplates() []PlanTemplate {
	return []PlanTemplate{
		{
			ContractVersion: ContractVersionV1,
			Key:             finalReadTemplateKey,
			Participants: []ParticipantTemplate{{
				Key:                       "final_authorization_audit",
				Owner:                     FinalAuthorizationOwner,
				DeclaresWrite:             true,
				Operation:                 coordinator.finalizeReadParticipant,
				logicalAuthorizationAudit: true,
			}},
			OutboxPolicy: OutboxOptional,
		},
		{
			ContractVersion: ContractVersionV1,
			Key:             durableEffectTemplateKey,
			Participants: []ParticipantTemplate{{
				Key:                  "durable_effect_preparation",
				Owner:                DurableEffectOwner,
				DeclaresWrite:        true,
				Operation:            coordinator.prepareDurableEffectParticipant,
				durableEffectHandoff: true,
			}},
			OutboxPolicy: OutboxRequired,
		},
	}
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// Execute runs one immutable registered plan exactly once. It never retries
// and never returns a session, transaction, or commit capability.
func (coordinator *Coordinator) Execute(ctx context.Context, plan Plan) (Report, error) {
	if coordinator == nil || plan.registry == nil || plan.registry != coordinator.registry.seal || plan.state == nil {
		return Report{}, fail(CodeInvalidPlan)
	}
	if !plan.state.state.CompareAndSwap(planReady, planRunning) {
		return Report{}, fail(CodePlanUnavailable)
	}
	defer plan.state.state.Store(planFinished)

	specification := executionSpecification{
		registry:     plan.registry,
		plan:         plan.state,
		participants: slicesCloneParticipants(plan.participants),
		outboxPolicy: plan.outboxPolicy,
		intent: func() *outbox.ValidatedIntent {
			if plan.intent == nil {
				return nil
			}
			intent := plan.intent()
			if intent == nil {
				return nil
			}
			value := *intent
			return &value
		},
	}
	return coordinator.run(ctx, specification)
}

func slicesCloneParticipants(participants []runtimeParticipant) []runtimeParticipant {
	result := make([]runtimeParticipant, len(participants))
	copy(result, participants)
	return result
}

type executionSpecification struct {
	registry     *registrySeal
	plan         *planState
	participants []runtimeParticipant
	outboxPolicy OutboxPolicy
	intent       func() *outbox.ValidatedIntent
}

func (coordinator *Coordinator) run(ctx context.Context, specification executionSpecification) (report Report, resultErr error) {
	if coordinator == nil || specification.registry == nil || specification.registry != coordinator.registry.seal ||
		specification.plan == nil || specification.plan.state.Load() != planRunning || len(specification.participants) == 0 ||
		(specification.outboxPolicy != OutboxRequired && specification.outboxPolicy != OutboxOptional) || specification.intent == nil {
		return report, fail(CodeInvalidPlan)
	}
	if err := contextFailure(ctx); err != nil {
		return report, err
	}

	report.BeginCalls++
	session, err := safeBegin(ctx, coordinator.backend)
	if err != nil || isNil(session) {
		return report, fail(CodeBeginFailed)
	}

	scope, err := coordinator.scopes.Open()
	if err != nil {
		return coordinator.rollback(ctx, session, report, fail(CodeBeginFailed))
	}
	defer coordinator.scopes.Close(scope)

	rollback := func(cause error) (Report, error) {
		coordinator.scopes.Close(scope)
		return coordinator.rollback(ctx, session, report, cause)
	}

	for _, participant := range specification.participants {
		if err := contextFailure(ctx); err != nil {
			return rollback(err)
		}
		capabilityState := &capabilityState{
			registry: specification.registry,
			plan:     specification.plan,
			owner:    participant.owner,
		}
		capabilityState.active.Store(true)
		capability := OwnerCapability{state: capabilityState}
		report.ParticipantCalls++
		if participant.declaresWrite {
			report.DeclaredWriteParticipantCalls++
		}
		if participant.logicalAuthorizationAudit {
			report.LogicalAuthorizationAudits++
		}
		if participant.durableEffectHandoff {
			report.DurableEffectHandoffs++
		}
		err := safeParticipant(ctx, participant.operation, capability)
		capabilityState.active.Store(false)
		if err != nil {
			return rollback(fail(CodeParticipantFailed))
		}
	}

	if err := contextFailure(ctx); err != nil {
		return rollback(err)
	}
	report.OutboxParticipantCalls++
	intent, err := safeIntent(specification.intent)
	if err != nil {
		return rollback(fail(CodeOutboxFailed))
	}
	if specification.outboxPolicy == OutboxRequired && intent == nil {
		return rollback(fail(CodeOutboxFailed))
	}
	if intent != nil {
		if err := intent.Verify(); err != nil || !coordinator.scopes.Owns(scope) {
			return rollback(fail(CodeOutboxFailed))
		}
		report.OutboxAppendCalls++
		if err := safeAppend(ctx, coordinator.outbox, scope, *intent); err != nil {
			return rollback(fail(CodeOutboxFailed))
		}
	}
	coordinator.scopes.Close(scope)

	if err := contextFailure(ctx); err != nil {
		return coordinator.rollback(ctx, session, report, err)
	}
	report.CommitCalls++
	if err := safeCommit(ctx, session); err != nil {
		return coordinator.rollback(ctx, session, report, fail(CodeCommitFailed))
	}
	return report, nil
}

func (coordinator *Coordinator) rollback(ctx context.Context, session Session, report Report, cause error) (Report, error) {
	report.RollbackCalls++
	if ctx == nil {
		ctx = context.Background()
	} else {
		ctx = context.WithoutCancel(ctx)
	}
	if err := safeRollback(ctx, session); err != nil {
		return report, fail(CodeRollbackFailed)
	}
	return report, cause
}

func contextFailure(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return fail(CodeCancelled)
	}
	return nil
}

func safeBegin(ctx context.Context, backend Backend) (session Session, err error) {
	defer func() {
		if recover() != nil {
			session = nil
			err = fail(CodeBeginFailed)
		}
	}()
	return backend.Begin(ctx)
}

func safeParticipant(ctx context.Context, operation OwnerOperation, capability OwnerCapability) (err error) {
	defer func() {
		if recover() != nil {
			err = fail(CodeParticipantFailed)
		}
	}()
	return operation(ctx, capability)
}

func safeAppend(ctx context.Context, appender outbox.AppendPort, scope outbox.TransactionScope, intent outbox.ValidatedIntent) (err error) {
	defer func() {
		if recover() != nil {
			err = fail(CodeOutboxFailed)
		}
	}()
	return appender.Append(ctx, scope, intent)
}

func safeIntent(source func() *outbox.ValidatedIntent) (intent *outbox.ValidatedIntent, err error) {
	defer func() {
		if recover() != nil {
			intent = nil
			err = fail(CodeOutboxFailed)
		}
	}()
	return source(), nil
}

func safeCommit(ctx context.Context, session Session) (err error) {
	defer func() {
		if recover() != nil {
			err = fail(CodeCommitFailed)
		}
	}()
	return session.Commit(ctx)
}

func safeRollback(ctx context.Context, session Session) (err error) {
	defer func() {
		if recover() != nil {
			err = fail(CodeRollbackFailed)
		}
	}()
	return session.Rollback(ctx)
}
