package transaction

import (
	"context"
	"crypto/sha256"
	"sync/atomic"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

const (
	DurableEffectHandoffV1   = "stead.core.durable-effect-handoff/v1"
	DurableEffectOwner       = "authorization.durable-effect"
	durableEffectTemplateKey = "core.prepare_durable_effect.v1"
)

type durableSeal struct{ marker byte }

type durableIssuerState struct {
	seal   *durableSeal
	active atomic.Bool
}

// DurableEffectIssuer wraps only an opaque WS-06-owned durable-effect result.
// Core defines no permit state, transition, expiry, storage, or effect class.
type DurableEffectIssuer struct {
	state *durableIssuerState
}

func newDurableEffectIssuer() DurableEffectIssuer {
	state := &durableIssuerState{seal: &durableSeal{}}
	state.active.Store(true)
	return DurableEffectIssuer{state: state}
}

func (issuer DurableEffectIssuer) BindValidated(version string, opaque []byte) (DurableEffectReceipt, error) {
	if issuer.state == nil || issuer.state.seal == nil || !issuer.state.active.Load() ||
		version != DurableEffectHandoffV1 || len(opaque) == 0 {
		return DurableEffectReceipt{}, fail(CodeDurableHandoffFail)
	}
	value := append([]byte(nil), opaque...)
	return DurableEffectReceipt{
		seal:    issuer.state.seal,
		version: version,
		opaque:  value,
		digest:  sha256.Sum256(value),
	}, nil
}

func (issuer DurableEffectIssuer) close() {
	if issuer.state != nil {
		issuer.state.active.Store(false)
	}
}

// DurableEffectReceipt is returned only after the WS-06 preparation and its
// required immutable intent commit together. It does not authorize or execute
// a provider call and carries no caller-selected mode/effect-class field.
type DurableEffectReceipt struct {
	seal    *durableSeal
	version string
	opaque  []byte
	digest  [sha256.Size]byte
}

func (receipt DurableEffectReceipt) HandoffVersion() string {
	return receipt.version
}

func (receipt DurableEffectReceipt) Digest() [sha256.Size]byte {
	return receipt.digest
}

func (receipt DurableEffectReceipt) OpaqueCopy() []byte {
	return append([]byte(nil), receipt.opaque...)
}

func (receipt DurableEffectReceipt) validFor(seal *durableSeal) bool {
	return receipt.seal != nil && receipt.seal == seal && receipt.version == DurableEffectHandoffV1 &&
		len(receipt.opaque) != 0 && sha256.Sum256(receipt.opaque) == receipt.digest
}

type DurableEffectPreparation struct {
	Receipt DurableEffectReceipt
	Intent  outbox.ValidatedIntent
	Binding BindingReceipt
}

// DurableEffectPreparationPort is the typed handoff to the WS-06 owner. It
// prepares owner state and one required audit/event intent but performs no
// provider, network, credential, stream, or other external effect.
type DurableEffectPreparationPort interface {
	Prepare(context.Context, SessionBinding, DurableEffectIssuer) (DurableEffectPreparation, error)
}

type durableEffectInvocation struct {
	result     DurableEffectPreparation
	issuerSeal *durableSeal
}

func (invocation *durableEffectInvocation) intent() *outbox.ValidatedIntent {
	if invocation == nil {
		return nil
	}
	return &invocation.result.Intent
}

func (coordinator *Coordinator) prepareDurableEffectParticipant(ctx context.Context, binding SessionBinding, invocation *durableEffectInvocation) (BindingReceipt, error) {
	if coordinator == nil || isNil(coordinator.durableEffectPreparation) || invocation == nil {
		return BindingReceipt{}, fail(CodeDurableHandoffFail)
	}
	issuer := newDurableEffectIssuer()
	invocation.issuerSeal = issuer.state.seal
	result, err := coordinator.durableEffectPreparation.Prepare(ctx, binding, issuer)
	issuer.close()
	if err != nil || !result.Receipt.validFor(invocation.issuerSeal) {
		return BindingReceipt{}, fail(CodeDurableHandoffFail)
	}
	if err := result.Intent.Verify(); err != nil {
		return BindingReceipt{}, fail(CodeOutboxFailed)
	}
	invocation.result = result
	return result.Binding, nil
}

func (coordinator *Coordinator) PrepareDurableEffect(ctx context.Context) (DurableEffectReceipt, Report, error) {
	if coordinator == nil || isNil(coordinator.durableEffectPreparation) {
		return DurableEffectReceipt{}, Report{}, fail(CodeDurableHandoffFail)
	}
	invocation := &durableEffectInvocation{}
	plan, err := coordinator.durableEffectContract.bind(coordinator.registry, invocation, nil, func(value *durableEffectInvocation) *outbox.ValidatedIntent {
		return value.intent()
	})
	if err != nil {
		return DurableEffectReceipt{}, Report{}, fail(CodeDurableHandoffFail)
	}
	report, err := coordinator.Execute(ctx, plan)
	if err != nil {
		return DurableEffectReceipt{}, report, err
	}
	if !invocation.result.Receipt.validFor(invocation.issuerSeal) {
		return DurableEffectReceipt{}, report, fail(CodeDurableHandoffFail)
	}
	return invocation.result.Receipt, report, nil
}
