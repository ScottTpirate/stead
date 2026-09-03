package transaction

import (
	"context"
	"reflect"
	"sync/atomic"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

// Backend and Session are WS-02 adapter contracts. Every successful Begin must
// return a distinct independently live Session, including for overlapping
// requests. They are intentionally internal to apps/core and are never passed
// to an owner participant. Session contains only lifecycle methods; the later
// driver-backed implementation must remain in this trusted boundary and expose
// typed owner repositories instead of a raw connection or query executor.
type Backend interface {
	Begin(context.Context) (Session, error)
}

type Session interface {
	Commit(context.Context) error
	Rollback(context.Context) error
}

type Configuration struct {
	Backend                     BackendContract
	Registry                    Registry
	Outbox                      outbox.AppendPort[SessionBinding, BindingReceipt]
	FinalAuthorizationAudit     FinalAuthorizationAuditPort
	FinalAuthorizationOperation BackendOperation[*FinalAuthorizationAuditOperation]
	DurableEffectPreparation    DurableEffectPreparationPort
	DurableEffectOperation      BackendOperation[*DurableEffectOperation]
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
	backendContract          BackendContract
	registry                 Registry
	outbox                   outbox.AppendPort[SessionBinding, BindingReceipt]
	scopes                   outbox.ScopeAuthority
	finalAuthorizationAudit  FinalAuthorizationAuditPort
	durableEffectPreparation DurableEffectPreparationPort
	finalReadContract        PlanContract[*FinalAuthorizationAuditOperation]
	durableEffectContract    PlanContract[*DurableEffectOperation]
}

func NewCoordinator(configuration Configuration) (*Coordinator, error) {
	if configuration.Backend.seal == nil || isNil(configuration.Backend.backend) || isNil(configuration.Outbox) ||
		configuration.Registry.seal == nil || configuration.Registry.backend == nil ||
		configuration.Registry.backend != configuration.Backend.seal {
		return nil, fail(CodeInvalidContract)
	}
	coordinator := &Coordinator{
		backend:                  configuration.Backend.backend,
		backendContract:          configuration.Backend,
		outbox:                   configuration.Outbox,
		scopes:                   outbox.NewScopeAuthority(),
		finalAuthorizationAudit:  configuration.FinalAuthorizationAudit,
		durableEffectPreparation: configuration.DurableEffectPreparation,
	}
	reserved, err := coordinator.reservedTemplates(configuration.FinalAuthorizationOperation, configuration.DurableEffectOperation)
	if err != nil {
		return nil, fail(CodeInvalidContract)
	}
	registry, err := configuration.Registry.withTemplates(reserved)
	if err != nil {
		return nil, fail(CodeInvalidContract)
	}
	coordinator.registry = registry
	return coordinator, nil
}

func (coordinator *Coordinator) reservedTemplates(finalOperation BackendOperation[*FinalAuthorizationAuditOperation], durableOperation BackendOperation[*DurableEffectOperation]) ([]PlanTemplate, error) {
	if isNil(coordinator.finalAuthorizationAudit) {
		finalOperation, _ = NewBackendOperation(coordinator.backendContract, FinalAuthorizationOwner, func(context.Context, Session, *FinalAuthorizationAuditOperation) error {
			return fail(CodeBoundaryDenied)
		})
	} else if !backendOperationMatches(finalOperation, coordinator.backendContract.seal, FinalAuthorizationOwner) {
		return nil, fail(CodeInvalidContract)
	}
	registeredFinal, err := NewRegisteredOperation(finalOperation, coordinator.finalizeReadParticipant)
	if err != nil {
		return nil, err
	}
	finalTemplate, finalContract, err := newCoordinatorPlanContract(
		ContractVersionV1,
		finalReadTemplateKey,
		[]typedParticipantDefinition[*FinalAuthorizationAuditOperation]{
			{
				key:                       "final_authorization_audit",
				declaresWrite:             true,
				operation:                 registeredFinal,
				logicalAuthorizationAudit: true,
			},
		},
		OutboxOptional,
	)
	if err != nil {
		return nil, err
	}
	if isNil(coordinator.durableEffectPreparation) {
		durableOperation, _ = NewBackendOperation(coordinator.backendContract, DurableEffectOwner, func(context.Context, Session, *DurableEffectOperation) error {
			return fail(CodeDurableHandoffFail)
		})
	} else if !backendOperationMatches(durableOperation, coordinator.backendContract.seal, DurableEffectOwner) {
		return nil, fail(CodeInvalidContract)
	}
	registeredDurable, err := NewRegisteredOperation(durableOperation, coordinator.prepareDurableEffectParticipant)
	if err != nil {
		return nil, err
	}
	durableTemplate, durableContract, err := newCoordinatorPlanContract(
		ContractVersionV1,
		durableEffectTemplateKey,
		[]typedParticipantDefinition[*DurableEffectOperation]{
			{
				key:                  "durable_effect_preparation",
				declaresWrite:        true,
				operation:            registeredDurable,
				durableEffectHandoff: true,
			},
		},
		OutboxRequired,
	)
	if err != nil {
		return nil, err
	}
	coordinator.finalReadContract = finalContract
	coordinator.durableEffectContract = durableContract
	return []PlanTemplate{finalTemplate, durableTemplate}, nil
}

const (
	bindingFresh uint32 = iota
	bindingRunning
	bindingConsumed
	bindingClosed
)

type sessionState struct {
	registry *registrySeal
	backend  *backendSeal
	plan     *planState
	session  Session
	active   atomic.Bool
}

type bindingState struct {
	session *sessionState
	owner   string
	state   atomic.Uint32
}

// SessionBinding is the opaque WS-02-owned lease used only to enlist the
// predeclared core outbox append in the exact Session returned by this
// execution's Begin. Domain owner adapters receive OperationPort instead.
type SessionBinding struct {
	state *bindingState
}

// BindingReceipt proves that one exact SessionBinding completed its own Use
// callback. It grants no operation and exposes no session, owner, or validity
// predicate.
type BindingReceipt struct {
	state *bindingState
}

// Use runs the one exact synchronous outbox storage operation. There is no
// separable validity boolean: zero, copied, concurrent, retained, wrong-plan,
// and post-return uses fail before invoking operation.
func (binding SessionBinding) Use(operation func() error) (BindingReceipt, error) {
	if binding.state == nil || binding.state.session == nil || binding.state.session.registry == nil || operation == nil ||
		!binding.state.session.active.Load() || binding.state.session.plan == nil ||
		binding.state.session.plan.state.Load() != planRunning ||
		!binding.state.state.CompareAndSwap(bindingFresh, bindingRunning) {
		return BindingReceipt{}, fail(CodeParticipantFailed)
	}
	defer binding.state.state.CompareAndSwap(bindingRunning, bindingConsumed)
	if err := operation(); err != nil {
		return BindingReceipt{}, err
	}
	return BindingReceipt{state: binding.state}, nil
}

func newSessionBinding(session *sessionState, owner string) SessionBinding {
	return SessionBinding{state: &bindingState{session: session, owner: owner}}
}

// close invalidates every copy and reports exact single synchronous
// consumption. Only the coordinator calls it.
func (binding SessionBinding) close(receipt BindingReceipt) bool {
	if binding.state == nil {
		return false
	}
	return binding.state.state.Swap(bindingClosed) == bindingConsumed && receipt.state == binding.state
}

// resolve is used only by the trusted WS-02 outbox storage adapter to bind its
// append to the exact returned Session. Domain owner packages never receive a
// SessionBinding, this resolver, or the Session.
func (binding SessionBinding) resolve(owner string) (Session, bool) {
	if binding.state == nil || binding.state.session == nil || binding.state.session.registry == nil || binding.state.owner != owner ||
		binding.state.state.Load() != bindingRunning || !binding.state.session.active.Load() ||
		binding.state.session.plan == nil || binding.state.session.plan.state.Load() != planRunning {
		return nil, false
	}
	return binding.state.session.session, true
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
	registered, exists := coordinator.registry.templates[plan.templateKey]
	if !exists || registered.definition == nil || plan.templateSeal == nil ||
		registered.definition.seal != plan.templateSeal || len(plan.participants) != len(registered.definition.participants) {
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
		intent: func() (*outbox.ValidatedIntent, error) {
			if plan.intent == nil {
				return nil, nil
			}
			intent, err := plan.intent()
			if err != nil {
				return nil, err
			}
			if intent == nil {
				return nil, nil
			}
			value := *intent
			return &value, nil
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
	intent       func() (*outbox.ValidatedIntent, error)
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

	operation := &sessionState{registry: specification.registry, backend: coordinator.backendContract.seal, plan: specification.plan, session: session}
	operation.active.Store(true)
	defer operation.active.Store(false)

	rollback := func(cause error) (Report, error) {
		operation.active.Store(false)
		return coordinator.rollback(ctx, session, report, cause)
	}

	for _, participant := range specification.participants {
		if err := contextFailure(ctx); err != nil {
			return rollback(err)
		}
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
		if err := safeParticipant(ctx, participant.operation, operation); err != nil {
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
		if err := intent.Verify(); err != nil {
			return rollback(fail(CodeOutboxFailed))
		}
		binding := newSessionBinding(operation, "core_outbox")
		scope, err := outbox.OpenScope[SessionBinding, BindingReceipt](coordinator.scopes, binding)
		if err != nil {
			binding.close(BindingReceipt{})
			return rollback(fail(CodeOutboxFailed))
		}
		report.OutboxAppendCalls++
		scopeReceipt, bindingReceipt, err := safeAppend(ctx, coordinator.outbox, scope, *intent)
		if err != nil {
			outbox.CloseScope(coordinator.scopes, scope, scopeReceipt)
			binding.close(bindingReceipt)
			return rollback(fail(CodeOutboxFailed))
		}
		scopeConsumed := outbox.CloseScope(coordinator.scopes, scope, scopeReceipt)
		bindingConsumed := binding.close(bindingReceipt)
		if !scopeConsumed || !bindingConsumed {
			return rollback(fail(CodeOutboxFailed))
		}
	}
	operation.active.Store(false)

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

func safeParticipant(ctx context.Context, operation func(context.Context, *sessionState) error, session *sessionState) (err error) {
	defer func() {
		if recover() != nil {
			err = fail(CodeParticipantFailed)
		}
	}()
	return operation(ctx, session)
}

func backendOperationMatches[T any](operation BackendOperation[T], backend *backendSeal, owner string) bool {
	return operation.definition != nil && operation.definition.backend == backend && operation.definition.seal != nil &&
		operation.definition.owner == owner && operation.definition.execute != nil
}

func safeAppend(ctx context.Context, appender outbox.AppendPort[SessionBinding, BindingReceipt], scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (scopeReceipt outbox.ScopeReceipt[SessionBinding, BindingReceipt], bindingReceipt BindingReceipt, err error) {
	defer func() {
		if recover() != nil {
			scopeReceipt = outbox.ScopeReceipt[SessionBinding, BindingReceipt]{}
			bindingReceipt = BindingReceipt{}
			err = fail(CodeOutboxFailed)
		}
	}()
	return appender.Append(ctx, scope, intent)
}

func safeIntent(source func() (*outbox.ValidatedIntent, error)) (intent *outbox.ValidatedIntent, err error) {
	defer func() {
		if recover() != nil {
			intent = nil
			err = fail(CodeOutboxFailed)
		}
	}()
	return source()
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
