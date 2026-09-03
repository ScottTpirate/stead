package testbackendadapter

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
)

func TestBeginReturnsOpaqueResultAndCreatesOnePrivateJournalEntry(t *testing.T) {
	backend := &Backend{}
	result, err := backend.Begin(context.Background())
	if err != nil || result == (transaction.BeginResult{}) {
		t.Fatalf("begin result=%#v err=%v", result, err)
	}
	backend.mu.Lock()
	if len(backend.active) != 1 || len(backend.bindings) != 1 || len(backend.bound) != 1 {
		backend.mu.Unlock()
		t.Fatalf("begin journal active=%d bindings=%d bound=%d", len(backend.active), len(backend.bindings), len(backend.bound))
	}
	var value *session
	for active := range backend.active {
		value = active
	}
	binding, paired := backend.bound[value]
	journaled := backend.bindings[binding]
	backend.mu.Unlock()
	if value == nil || !paired || journaled != value {
		t.Fatalf("begin did not create an exact private journal: value=%p paired=%t journaled=%p", value, paired, journaled)
	}
	if err := value.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, active, _ := backend.Snapshot()
	backend.mu.Lock()
	bindings, bound := len(backend.bindings), len(backend.bound)
	backend.mu.Unlock()
	if active != 0 || bindings != 0 || bound != 0 {
		t.Fatalf("rollback retained begin journal active=%d identities=%d/%d", active, bindings, bound)
	}
}

func TestBindingJournalRejectsUnknownForeignAndExpiredIdentities(t *testing.T) {
	backend := &Backend{}
	_, firstValue, firstBinding, err := backend.begin()
	if err != nil {
		t.Fatal(err)
	}
	_, secondValue, secondBinding, err := backend.begin()
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
	_, foreignValue, foreignBinding, err := foreign.begin()
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
