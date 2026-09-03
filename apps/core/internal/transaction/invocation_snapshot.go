package transaction

import (
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"reflect"
)

const (
	maxInvocationSnapshotBytes = 1 << 20
	maxInvocationSnapshotDepth = 64
	maxInvocationSnapshotNodes = 262_144
)

var (
	jsonMarshalerType     = reflect.TypeFor[json.Marshaler]()
	jsonUnmarshalerType   = reflect.TypeFor[json.Unmarshaler]()
	textMarshalerType     = reflect.TypeFor[encoding.TextMarshaler]()
	textUnmarshalerType   = reflect.TypeFor[encoding.TextUnmarshaler]()
	unsupportedValueKinds = map[reflect.Kind]struct{}{
		reflect.Chan:          {},
		reflect.Complex64:     {},
		reflect.Complex128:    {},
		reflect.Func:          {},
		reflect.Interface:     {},
		reflect.UnsafePointer: {},
		reflect.Uintptr:       {},
	}
)

// invocationSnapshotProfile is fixed when a plan contract is registered. A
// reference-free invocation can be copied directly. A reference-bearing
// invocation must pass the closed JSON snapshot profile below; callers cannot
// supply a copier or an identity function.
type invocationSnapshotProfile struct {
	referenceBearing bool
}

type immutableInvocationSnapshot[T any] struct {
	profile invocationSnapshotProfile
	value   T
	encoded []byte
	digest  [sha256.Size]byte
}

func newInvocationSnapshotProfile[T any]() (invocationSnapshotProfile, error) {
	typeOfT := reflect.TypeFor[T]()
	referenceBearing, err := snapshotTypeContainsReferences(typeOfT, make(map[reflect.Type]bool))
	if err != nil {
		return invocationSnapshotProfile{}, fail(CodeInvalidContract)
	}
	profile := invocationSnapshotProfile{referenceBearing: referenceBearing}
	if referenceBearing && !validateSerializedSnapshotType(typeOfT, make(map[reflect.Type]bool)) {
		return invocationSnapshotProfile{}, fail(CodeInvalidContract)
	}
	return profile, nil
}

func snapshotTypeContainsReferences(value reflect.Type, visiting map[reflect.Type]bool) (bool, error) {
	if value == nil {
		return false, fail(CodeInvalidContract)
	}
	if _, unsupported := unsupportedValueKinds[value.Kind()]; unsupported {
		return false, fail(CodeInvalidContract)
	}
	if visiting[value] {
		return true, nil
	}
	visiting[value] = true
	defer delete(visiting, value)

	switch value.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice:
		return true, nil
	case reflect.Array:
		return snapshotTypeContainsReferences(value.Elem(), visiting)
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			referenceBearing, err := snapshotTypeContainsReferences(value.Field(index).Type, visiting)
			if err != nil {
				return false, err
			}
			if referenceBearing {
				return true, nil
			}
		}
	}
	return false, nil
}

// Reference-bearing snapshots deliberately use only encoding/json's default
// structural codec. Custom codecs, interfaces, ignored/tagged fields,
// anonymous fields, and unexported fields are rejected so a type cannot hide
// an aliasing identity decoder or silently omit request state.
func validateSerializedSnapshotType(value reflect.Type, visiting map[reflect.Type]bool) bool {
	if value == nil || implementsSnapshotCodec(value) {
		return false
	}
	if _, unsupported := unsupportedValueKinds[value.Kind()]; unsupported {
		return false
	}
	if visiting[value] {
		return true
	}
	visiting[value] = true
	defer delete(visiting, value)

	switch value.Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64, reflect.String:
		return true
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return validateSerializedSnapshotType(value.Elem(), visiting)
	case reflect.Map:
		key := value.Key().Kind()
		if key != reflect.String && key != reflect.Int && key != reflect.Int8 && key != reflect.Int16 && key != reflect.Int32 && key != reflect.Int64 &&
			key != reflect.Uint && key != reflect.Uint8 && key != reflect.Uint16 && key != reflect.Uint32 && key != reflect.Uint64 {
			return false
		}
		return validateSerializedSnapshotType(value.Key(), visiting) && validateSerializedSnapshotType(value.Elem(), visiting)
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			_, tagged := field.Tag.Lookup("json")
			if field.PkgPath != "" || field.Anonymous || tagged ||
				!validateSerializedSnapshotType(field.Type, visiting) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func implementsSnapshotCodec(value reflect.Type) bool {
	candidates := []reflect.Type{value}
	if value.Kind() != reflect.Pointer {
		candidates = append(candidates, reflect.PointerTo(value))
	}
	for _, candidate := range candidates {
		if candidate.Implements(jsonMarshalerType) || candidate.Implements(jsonUnmarshalerType) ||
			candidate.Implements(textMarshalerType) || candidate.Implements(textUnmarshalerType) {
			return true
		}
	}
	return false
}

func captureImmutableInvocation[T any](profile invocationSnapshotProfile, invocation T) (immutableInvocationSnapshot[T], error) {
	if isNil(invocation) {
		return immutableInvocationSnapshot[T]{}, fail(CodeInvalidPlan)
	}
	if err := validateSnapshotValue(reflect.ValueOf(invocation), 0, &snapshotBudget{}, make(map[snapshotVisit]bool)); err != nil {
		return immutableInvocationSnapshot[T]{}, fail(CodeInvalidPlan)
	}
	if !profile.referenceBearing {
		return immutableInvocationSnapshot[T]{profile: profile, value: invocation}, nil
	}
	encoded, err := json.Marshal(invocation)
	if err != nil || len(encoded) == 0 || len(encoded) > maxInvocationSnapshotBytes {
		return immutableInvocationSnapshot[T]{}, fail(CodeInvalidPlan)
	}
	result := immutableInvocationSnapshot[T]{
		profile: profile,
		encoded: append([]byte(nil), encoded...),
		digest:  sha256.Sum256(encoded),
	}
	view, err := result.view()
	if err != nil || !reflect.DeepEqual(invocation, view) {
		return immutableInvocationSnapshot[T]{}, fail(CodeInvalidPlan)
	}
	return result, nil
}

func (snapshot immutableInvocationSnapshot[T]) view() (T, error) {
	if !snapshot.profile.referenceBearing {
		return snapshot.value, nil
	}
	var result T
	if len(snapshot.encoded) == 0 || len(snapshot.encoded) > maxInvocationSnapshotBytes ||
		sha256.Sum256(snapshot.encoded) != snapshot.digest {
		return result, fail(CodeInvalidPlan)
	}
	if err := json.Unmarshal(snapshot.encoded, &result); err != nil || isNil(result) {
		return result, fail(CodeInvalidPlan)
	}
	return result, nil
}

type snapshotVisit struct {
	typeOf  reflect.Type
	pointer uintptr
}

type snapshotBudget struct {
	nodes int
	bytes int
}

func (budget *snapshotBudget) consume(bytes int) error {
	if bytes < 0 || budget.bytes > maxInvocationSnapshotBytes-bytes {
		return fail(CodeInvalidPlan)
	}
	budget.bytes += bytes
	return nil
}

func validateSnapshotValue(value reflect.Value, depth int, budget *snapshotBudget, path map[snapshotVisit]bool) error {
	if !value.IsValid() {
		return nil
	}
	budget.nodes++
	if depth > maxInvocationSnapshotDepth || budget.nodes > maxInvocationSnapshotNodes {
		return fail(CodeInvalidPlan)
	}

	switch value.Kind() {
	case reflect.Bool:
		return budget.consume(5)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return budget.consume(24)
	case reflect.Float32, reflect.Float64:
		return budget.consume(32)
	case reflect.Pointer:
		if value.IsNil() {
			return budget.consume(4)
		}
		visit := snapshotVisit{typeOf: value.Type(), pointer: value.Pointer()}
		if path[visit] {
			return fail(CodeInvalidPlan)
		}
		path[visit] = true
		defer delete(path, visit)
		return validateSnapshotValue(value.Elem(), depth+1, budget, path)
	case reflect.Slice:
		if value.IsNil() {
			return budget.consume(4)
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			if value.Len() > maxInvocationSnapshotNodes-budget.nodes {
				return fail(CodeInvalidPlan)
			}
			budget.nodes += value.Len()
			return budget.consume(2 + value.Len())
		}
		if value.Len() > maxInvocationSnapshotNodes-budget.nodes || budget.consume(2+value.Len()) != nil {
			return fail(CodeInvalidPlan)
		}
		for index := 0; index < value.Len(); index++ {
			if err := validateSnapshotValue(value.Index(index), depth+1, budget, path); err != nil {
				return err
			}
		}
	case reflect.Array:
		if value.Len() > maxInvocationSnapshotNodes-budget.nodes || budget.consume(2+value.Len()) != nil {
			return fail(CodeInvalidPlan)
		}
		for index := 0; index < value.Len(); index++ {
			if err := validateSnapshotValue(value.Index(index), depth+1, budget, path); err != nil {
				return err
			}
		}
	case reflect.Map:
		if value.IsNil() {
			return budget.consume(4)
		}
		if value.Len() > (maxInvocationSnapshotNodes-budget.nodes)/2 || budget.consume(2+2*value.Len()) != nil {
			return fail(CodeInvalidPlan)
		}
		iterator := value.MapRange()
		for iterator.Next() {
			if err := validateSnapshotValue(iterator.Key(), depth+1, budget, path); err != nil {
				return err
			}
			if err := validateSnapshotValue(iterator.Value(), depth+1, budget, path); err != nil {
				return err
			}
		}
	case reflect.Struct:
		if err := budget.consume(2 + value.NumField()); err != nil {
			return err
		}
		for index := 0; index < value.NumField(); index++ {
			if err := budget.consume(3 + len(value.Type().Field(index).Name)); err != nil {
				return err
			}
			if err := validateSnapshotValue(value.Field(index), depth+1, budget, path); err != nil {
				return err
			}
		}
	case reflect.String:
		if value.Len() > maxInvocationSnapshotBytes-2 {
			return fail(CodeInvalidPlan)
		}
		return budget.consume(2 + value.Len())
	default:
		return fail(CodeInvalidPlan)
	}
	return nil
}
