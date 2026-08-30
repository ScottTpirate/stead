package outbox

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestValidatedIntentIsSealedAndImmutable(t *testing.T) {
	authority := NewValidationAuthority()
	source := []byte(`{"safe_aggregate_ref":"aggregate:one"}`)
	intent, err := authority.WrapValidated(ValidatedIntentHandoffV1, source)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := intent.Digest()
	source[0] = 'X'
	copy := intent.PayloadCopy()
	copy[0] = 'Y'
	if err := intent.Verify(); err != nil {
		t.Fatalf("immutable intent failed verification: %v", err)
	}
	if intent.Digest() != wantDigest || string(intent.PayloadCopy()) != `{"safe_aggregate_ref":"aggregate:one"}` {
		t.Fatal("caller mutation changed immutable intent")
	}
	if intent.HandoffVersion() != ValidatedIntentHandoffV1 || intent.Size() != len(source) {
		t.Fatal("safe intent metadata drifted")
	}
}

func TestValidatedIntentRejectsZeroWrongVersionAndEmpty(t *testing.T) {
	if err := (ValidatedIntent{}).Verify(); !errors.Is(err, ErrInvalidValidatedIntent) {
		t.Fatalf("zero intent error = %v", err)
	}
	authority := NewValidationAuthority()
	tests := []struct {
		name    string
		version string
		payload []byte
	}{
		{"wrong version", "stead.core.validated-intent-handoff/v2", []byte("safe")},
		{"missing version", "", []byte("safe")},
		{"empty payload", ValidatedIntentHandoffV1, nil},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := authority.WrapValidated(testCase.version, testCase.payload); !errors.Is(err, ErrInvalidValidatedIntent) {
				t.Fatalf("WrapValidated() error = %v", err)
			}
		})
	}
	if _, err := (ValidationAuthority{}).WrapValidated(ValidatedIntentHandoffV1, []byte("safe")); !errors.Is(err, ErrInvalidValidatedIntent) {
		t.Fatalf("zero authority error = %v", err)
	}
}

func TestTransactionScopeExpiresAcrossCopies(t *testing.T) {
	authority := NewScopeAuthority()
	scope, err := authority.Open()
	if err != nil {
		t.Fatal(err)
	}
	copy := scope
	if err := scope.Verify(); err != nil || !authority.Owns(scope) {
		t.Fatal("fresh scope did not verify")
	}
	if NewScopeAuthority().Owns(scope) {
		t.Fatal("foreign authority accepted scope")
	}
	authority.Close(scope)
	if err := scope.Verify(); !errors.Is(err, ErrInvalidTransactionScope) {
		t.Fatalf("closed scope error = %v", err)
	}
	if err := copy.Verify(); !errors.Is(err, ErrInvalidTransactionScope) {
		t.Fatalf("copied closed scope error = %v", err)
	}
	if err := (TransactionScope{}).Verify(); !errors.Is(err, ErrInvalidTransactionScope) {
		t.Fatalf("zero scope error = %v", err)
	}
	if _, err := (ScopeAuthority{}).Open(); !errors.Is(err, ErrInvalidTransactionScope) {
		t.Fatalf("zero authority error = %v", err)
	}
}

func TestAppendPortHasOnlyTransactionScopedAppend(t *testing.T) {
	type portType interface {
		Append(context.Context, TransactionScope, ValidatedIntent) error
	}
	interfaceType := reflect.TypeOf((*AppendPort)(nil)).Elem()
	wantType := reflect.TypeOf((*portType)(nil)).Elem()
	if interfaceType.NumMethod() != 1 || !interfaceType.Implements(wantType) {
		t.Fatalf("AppendPort surface drifted: %v", interfaceType)
	}
	method := interfaceType.Method(0)
	if method.Name != "Append" {
		t.Fatalf("unexpected outbox method %q", method.Name)
	}
}

func FuzzValidatedIntentDefensiveCopy(f *testing.F) {
	f.Add([]byte("safe"))
	f.Add([]byte(`{"aggregate":"one"}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) == 0 {
			return
		}
		authority := NewValidationAuthority()
		intent, err := authority.WrapValidated(ValidatedIntentHandoffV1, payload)
		if err != nil {
			t.Fatal(err)
		}
		before := intent.Digest()
		payload[0] ^= 0xff
		if intent.Digest() != before || intent.Verify() != nil {
			t.Fatal("input alias changed validated intent")
		}
	})
}
