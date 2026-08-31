// Package testowneradapter proves that an owner-authored typed adapter can
// live outside the transaction package while consuming only the opaque,
// synchronous SessionBinding callback. It is test evidence, not a domain API.
package testowneradapter

import (
	"context"
	"sync"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
)

type Command struct {
	Value string
}

type Adapter struct {
	mu      sync.Mutex
	applied []string
}

func (adapter *Adapter) Apply(ctx context.Context, binding transaction.SessionBinding, command Command) (transaction.BindingReceipt, error) {
	if ctx == nil || ctx.Err() != nil {
		return transaction.BindingReceipt{}, context.Canceled
	}
	return binding.Use(func() error {
		adapter.mu.Lock()
		defer adapter.mu.Unlock()
		adapter.applied = append(adapter.applied, command.Value)
		return nil
	})
}

func (adapter *Adapter) Applied() []string {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return append([]string(nil), adapter.applied...)
}
