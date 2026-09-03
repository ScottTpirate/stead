package testbackendadapter

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
)

func TestBindingJournalRejectsUnknownForeignAndExpiredIdentities(t *testing.T) {
	backend := &Backend{}
	firstValue, firstBinding, err := backend.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondValue, secondBinding, err := backend.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if firstBinding == secondBinding {
		t.Fatal("overlapping sessions shared an executor identity")
	}
	if err := backend.stage(context.Background(), transaction.ExecutorBinding{}, "owner", "zero"); !errors.Is(err, errInvalidSession) {
		t.Fatalf("zero identity error = %v", err)
	}
	foreign := &Backend{}
	foreignValue, foreignBinding, err := foreign.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.stage(context.Background(), foreignBinding, "owner", "foreign"); !errors.Is(err, errInvalidSession) {
		t.Fatalf("foreign identity error = %v", err)
	}
	if err := foreignValue.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.stage(context.Background(), firstBinding, "owner", "first"); err != nil {
		t.Fatal(err)
	}
	if err := backend.stage(context.Background(), secondBinding, "owner", "second"); err != nil {
		t.Fatal(err)
	}
	firstCopy := firstBinding
	if err := firstValue.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.stage(context.Background(), firstCopy, "owner", "late-commit"); !errors.Is(err, errInvalidSession) {
		t.Fatalf("committed identity error = %v", err)
	}
	if err := backend.stage(context.Background(), secondBinding, "owner", "second-still-live"); err != nil {
		t.Fatalf("independent identity expired early: %v", err)
	}
	secondCopy := secondBinding
	if err := secondValue.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.stage(context.Background(), secondCopy, "owner", "late-rollback"); !errors.Is(err, errInvalidSession) {
		t.Fatalf("rolled-back identity error = %v", err)
	}
	committed, rolledBack, active, executed := backend.Snapshot()
	backend.mu.Lock()
	bindings, bound := len(backend.bindings), len(backend.bound)
	backend.mu.Unlock()
	wantCommitted := []Record{{SessionID: 1, Owner: "owner", Value: "first"}}
	wantRolledBack := []Record{
		{SessionID: 2, Owner: "owner", Value: "second"},
		{SessionID: 2, Owner: "owner", Value: "second-still-live"},
	}
	if !reflect.DeepEqual(committed, wantCommitted) || !reflect.DeepEqual(rolledBack, wantRolledBack) ||
		active != 0 || executed["owner"] != 3 || bindings != 0 || bound != 0 {
		t.Fatalf("journal committed=%v rolled-back=%v active=%d executed=%v identities=%d/%d",
			committed, rolledBack, active, executed, bindings, bound)
	}
}
