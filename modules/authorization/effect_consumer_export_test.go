package authorization

import (
	"context"
	"testing"
)

// NewEffectConsumerUnitFixture is exported only by Go's test variant of this
// package. It reuses the existing explicit synthetic successor activation and
// fake owner store; it adds no runtime constructor or activation exception.
// External-package tests can exercise the real sealed handle through Gitea
// without forging private fields or weakening production package boundaries.
func NewEffectConsumerUnitFixture(t *testing.T) (context.Context, ResourceRef, func(EffectBinding) (*EffectExecution, error), func() EffectRecord, context.CancelFunc) {
	f := newEffectUnitFixture(t)
	consume := func(binding EffectBinding) (*EffectExecution, error) {
		issued, err := f.effects.Prepare(f.ctx, f.decision, binding)
		if err != nil {
			return nil, err
		}
		return f.effects.Consume(f.ctx, issued)
	}
	return f.ctx, f.binding.Project, consume, f.store.snapshot, f.cancel
}
