package transaction

import (
	"context"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
)

// StorageOutbox binds the real WS-02 appender to one startup backend. It
// consumes the existing scoped lease before handing its non-lifecycle identity
// to trusted storage; owner modules still cannot import this internal package.
type StorageOutbox struct {
	backend *backendSeal
	append  func(context.Context, ExecutorBinding, outbox.ValidatedIntent) error
}

func NewStorageOutbox(contract BackendContract, appendRow func(context.Context, ExecutorBinding, outbox.ValidatedIntent) error) (*StorageOutbox, error) {
	if contract.seal == nil || appendRow == nil {
		return nil, fail(CodeInvalidContract)
	}
	return &StorageOutbox{backend: contract.seal, append: appendRow}, nil
}

func (adapter *StorageOutbox) Append(ctx context.Context, scope outbox.TransactionScope[SessionBinding, BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[SessionBinding, BindingReceipt], BindingReceipt, error) {
	return scope.Use(func(binding SessionBinding) (BindingReceipt, error) {
		return binding.Use(func() error {
			if adapter == nil || adapter.backend == nil || binding.state.session.backend != adapter.backend || intent.Verify() != nil {
				return fail(CodeOutboxFailed)
			}
			executor, ok := binding.resolve("core_outbox")
			if !ok {
				return fail(CodeOutboxFailed)
			}
			return adapter.append(ctx, executor, intent)
		})
	})
}
