package transaction

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

const (
	DurableEffectHandoffV1   = "stead.core.durable-effect-handoff/v1"
	DurableEffectOwner       = "authorization.durable-effect"
	durableEffectTemplateKey = "core.prepare_durable_effect.v1"
)

type durableSeal struct{ marker byte }

type durableIssuerState struct {
	mu       sync.Mutex
	seal     *durableSeal
	open     bool
	issued   *durableReceiptState
	accepted bool
}

// DurableEffectIssuer wraps only an opaque WS-06-owned durable-effect result.
// Core defines no permit state, transition, expiry, storage, or effect class.
type DurableEffectIssuer struct {
	state *durableIssuerState
}

func newDurableEffectIssuer() DurableEffectIssuer {
	return DurableEffectIssuer{state: &durableIssuerState{seal: &durableSeal{}, open: true}}
}

func (issuer DurableEffectIssuer) BindValidated(version string, opaque []byte) (DurableEffectReceipt, error) {
	if issuer.state == nil || version != DurableEffectHandoffV1 || len(opaque) == 0 {
		return DurableEffectReceipt{}, fail(CodeDurableHandoffFail)
	}
	issuer.state.mu.Lock()
	defer issuer.state.mu.Unlock()
	if issuer.state.seal == nil || !issuer.state.open || issuer.state.issued != nil {
		return DurableEffectReceipt{}, fail(CodeDurableHandoffFail)
	}
	value := append([]byte(nil), opaque...)
	state := &durableReceiptState{
		seal:    issuer.state.seal,
		version: version,
		opaque:  value,
		digest:  sha256.Sum256(value),
	}
	issuer.state.issued = state
	return DurableEffectReceipt{state: state}, nil
}

func (issuer DurableEffectIssuer) close() {
	if issuer.state == nil {
		return
	}
	issuer.state.mu.Lock()
	if !issuer.state.open {
		issuer.state.mu.Unlock()
		return
	}
	issuer.state.open = false
	issued := issuer.state.issued
	accepted := issuer.state.accepted
	issuer.state.mu.Unlock()
	if issued != nil && !accepted {
		issued.proof.invalidate()
	}
}

func (issuer DurableEffectIssuer) accept(receipt DurableEffectReceipt) bool {
	if issuer.state == nil || receipt.state == nil {
		return false
	}
	issuer.state.mu.Lock()
	defer issuer.state.mu.Unlock()
	if issuer.state.seal == nil || !issuer.state.open || issuer.state.accepted ||
		issuer.state.issued != receipt.state || !receipt.validMaterialFor(issuer.state.seal) ||
		!receipt.state.proof.sealForCommit() {
		return false
	}
	issuer.state.accepted = true
	return true
}

// DurableEffectReceipt is returned only after the WS-06 preparation and its
// required immutable intent commit together. It does not authorize or execute
// a provider call and carries no caller-selected mode/effect-class field.
type durableReceiptState struct {
	seal    *durableSeal
	version string
	opaque  []byte
	digest  [sha256.Size]byte
	proof   proofLifecycle
}

type DurableEffectReceipt struct {
	state *durableReceiptState
}

func (receipt DurableEffectReceipt) HandoffVersion() string {
	if receipt.state == nil {
		return ""
	}
	return receipt.state.version
}

func (receipt DurableEffectReceipt) Digest() [sha256.Size]byte {
	if receipt.state == nil {
		return [sha256.Size]byte{}
	}
	return receipt.state.digest
}

func (receipt DurableEffectReceipt) OpaqueCopy() []byte {
	if receipt.state == nil {
		return nil
	}
	return append([]byte(nil), receipt.state.opaque...)
}

func (receipt DurableEffectReceipt) validMaterialFor(seal *durableSeal) bool {
	return receipt.state != nil && receipt.state.seal != nil && receipt.state.seal == seal &&
		receipt.state.version == DurableEffectHandoffV1 && len(receipt.state.opaque) != 0 &&
		sha256.Sum256(receipt.state.opaque) == receipt.state.digest
}

func (receipt DurableEffectReceipt) validFor(seal *durableSeal) bool {
	return receipt.validMaterialFor(seal) && receipt.state.proof.isActive()
}

func (receipt DurableEffectReceipt) activate(seal *durableSeal) bool {
	return receipt.validMaterialFor(seal) && receipt.state.proof.activate()
}

func (receipt DurableEffectReceipt) invalidate() {
	if receipt.state != nil {
		receipt.state.proof.invalidate()
	}
}

type DurableEffectPreparation struct {
	Receipt DurableEffectReceipt
	Intent  outbox.ValidatedIntent
}

// DurableEffectPreparationPort is the typed handoff to the WS-06 owner. It
// prepares owner state and one required audit/event intent but performs no
// provider, network, credential, stream, or other external effect.
type DurableEffectPreparationPort interface {
	Prepare(context.Context, OperationPort[*DurableEffectOperation], DurableEffectIssuer) (DurableEffectPreparation, error)
}

// DurableEffectOperation is an opaque invocation identity used only to type
// the registration-bound repository port.
type DurableEffectOperation struct {
	result     DurableEffectPreparation
	issuerSeal *durableSeal
}

func (invocation *DurableEffectOperation) intent() *outbox.ValidatedIntent {
	if invocation == nil {
		return nil
	}
	return &invocation.result.Intent
}

func (coordinator *Coordinator) prepareDurableEffectParticipant(ctx context.Context, port OperationPort[*DurableEffectOperation], invocation *DurableEffectOperation) error {
	if coordinator == nil || isNil(coordinator.durableEffectPreparation) || invocation == nil {
		return fail(CodeDurableHandoffFail)
	}
	issuer := newDurableEffectIssuer()
	defer issuer.close()
	invocation.issuerSeal = issuer.state.seal
	result, err := coordinator.durableEffectPreparation.Prepare(ctx, port, issuer)
	if err != nil {
		return fail(CodeDurableHandoffFail)
	}
	if err := result.Intent.Verify(); err != nil {
		return fail(CodeOutboxFailed)
	}
	if !issuer.accept(result.Receipt) {
		return fail(CodeDurableHandoffFail)
	}
	invocation.result = result
	return nil
}

func (coordinator *Coordinator) PrepareDurableEffect(ctx context.Context) (DurableEffectReceipt, Report, error) {
	if coordinator == nil || isNil(coordinator.durableEffectPreparation) {
		return DurableEffectReceipt{}, Report{}, fail(CodeDurableHandoffFail)
	}
	invocation := &DurableEffectOperation{}
	activated := false
	defer func() {
		if !activated {
			invocation.result.Receipt.invalidate()
		}
	}()
	plan, err := coordinator.durableEffectContract.bindCoordinatorOwned(coordinator.registry, invocation, func(value *DurableEffectOperation) *outbox.ValidatedIntent {
		return value.intent()
	})
	if err != nil {
		return DurableEffectReceipt{}, Report{}, fail(CodeDurableHandoffFail)
	}
	report, err := coordinator.Execute(ctx, plan)
	if err != nil {
		return DurableEffectReceipt{}, report, err
	}
	if !invocation.result.Receipt.activate(invocation.issuerSeal) || !invocation.result.Receipt.validFor(invocation.issuerSeal) {
		return DurableEffectReceipt{}, report, fail(CodeDurableHandoffFail)
	}
	activated = true
	return invocation.result.Receipt, report, nil
}
