package policyrelease

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var integerJSONNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func marshalCanonical(value any) ([]byte, error) {
	result, err := json.Marshal(value)
	if err != nil {
		return nil, contractError("json_encode_failed", "", err)
	}
	if err := validateJSON(result, MaxJSONDepth, true); err != nil {
		return nil, err
	}
	return result, nil
}

func validateJSON(data []byte, maxDepth int, rejectNonIntegers bool) error {
	if !json.Valid(data) {
		return contractError("malformed_json", "", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, 0, maxDepth, rejectNonIntegers); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return contractError("json_trailing_value", "json", nil)
		}
		return contractError("malformed_json", "json", nil)
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, depth, maxDepth int, rejectNonIntegers bool) error {
	token, err := decoder.Token()
	if err != nil {
		return contractError("malformed_json", "json", nil)
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		if number, ok := token.(json.Number); ok && rejectNonIntegers && !integerJSONNumber.MatchString(string(number)) {
			return contractError("non_integer_json_number", "", nil)
		}
		return nil
	}

	depth++
	if depth > maxDepth {
		return contractError("json_depth_limit", "", nil)
	}
	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return contractError("malformed_json", "json", nil)
			}
			key, ok := keyToken.(string)
			if !ok {
				return contractError("malformed_json_object_key", "", nil)
			}
			if _, exists := keys[key]; exists {
				return contractError("duplicate_json_key", "json", nil)
			}
			keys[key] = struct{}{}
			if err := validateJSONValue(decoder, depth, maxDepth, rejectNonIntegers); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return contractError("malformed_json", "json", nil)
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder, depth, maxDepth, rejectNonIntegers); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return contractError("malformed_json", "json", nil)
		}
	default:
		return contractError("malformed_json", "", nil)
	}
	return nil
}

func decodeJSONShape(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var shape any
	if err := decoder.Decode(&shape); err != nil {
		return nil, contractError("malformed_json", "json", nil)
	}
	return shape, nil
}

type jsonMemberDefinition struct {
	kind     reflect.Type
	optional bool
}

func jsonMemberDefinitions(kind reflect.Type) map[string]jsonMemberDefinition {
	members := make(map[string]jsonMemberDefinition)
	if kind.Kind() != reflect.Struct {
		return members
	}
	for index := 0; index < kind.NumField(); index++ {
		field := kind.Field(index)
		if !field.IsExported() {
			continue
		}
		tag := strings.Split(field.Tag.Get("json"), ",")
		name := tag[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		optional := false
		for _, option := range tag[1:] {
			if option == "omitempty" {
				optional = true
			}
		}
		members[name] = jsonMemberDefinition{kind: field.Type, optional: optional}
	}
	return members
}

// validateExactJSONMembers closes the case-insensitive matching performed by
// encoding/json. When allowUnknown is true, genuinely unknown DSSE envelope
// extensions remain ignorable, but a case-folded alias of a known member is
// never an extension and is rejected.
func validateExactJSONMembers(shape any, kind reflect.Type, allowUnknown bool) error {
	if kind.Kind() == reflect.Pointer {
		if shape == nil {
			return nil
		}
		return validateExactJSONMembers(shape, kind.Elem(), allowUnknown)
	}
	if shape == nil {
		return contractError("signed_payload_contract_error", "json", nil)
	}
	switch kind.Kind() {
	case reflect.Struct:
		object, ok := shape.(map[string]any)
		if !ok {
			return contractError("signed_payload_contract_error", "json", nil)
		}
		members := jsonMemberDefinitions(kind)
		for name, value := range object {
			member, exact := members[name]
			if !exact {
				for known := range members {
					if strings.EqualFold(name, known) {
						return contractError("json_member_name_mismatch", "json", nil)
					}
				}
				if allowUnknown {
					continue
				}
				return contractError("signed_payload_contract_error", "json", nil)
			}
			if err := validateExactJSONMembers(value, member.kind, allowUnknown); err != nil {
				return err
			}
		}
		for name, member := range members {
			if _, present := object[name]; !present && !member.optional {
				return contractError("schema_required_field_missing", "json", nil)
			}
		}
	case reflect.Slice, reflect.Array:
		items, ok := shape.([]any)
		if !ok {
			return contractError("signed_payload_contract_error", "json", nil)
		}
		if kind.Kind() == reflect.Array && len(items) != kind.Len() {
			return contractError("signed_payload_contract_error", "json", nil)
		}
		for _, item := range items {
			if err := validateExactJSONMembers(item, kind.Elem(), allowUnknown); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := shape.(map[string]any)
		if !ok {
			return contractError("signed_payload_contract_error", "json", nil)
		}
		for _, value := range object {
			if err := validateExactJSONMembers(value, kind.Elem(), allowUnknown); err != nil {
				return err
			}
		}
	case reflect.Bool:
		if _, ok := shape.(bool); !ok {
			return contractError("signed_payload_contract_error", "json", nil)
		}
	case reflect.String:
		if _, ok := shape.(string); !ok {
			return contractError("signed_payload_contract_error", "json", nil)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		number, ok := shape.(json.Number)
		if !ok || !integerJSONNumber.MatchString(string(number)) {
			return contractError("signed_payload_contract_error", "json", nil)
		}
		if _, err := strconv.ParseInt(string(number), 10, kind.Bits()); err != nil {
			return contractError("signed_payload_contract_error", "json", nil)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		number, ok := shape.(json.Number)
		if !ok || !integerJSONNumber.MatchString(string(number)) {
			return contractError("signed_payload_contract_error", "json", nil)
		}
		if _, err := strconv.ParseUint(string(number), 10, kind.Bits()); err != nil {
			return contractError("signed_payload_contract_error", "json", nil)
		}
	case reflect.Float32, reflect.Float64:
		number, ok := shape.(json.Number)
		if !ok {
			return contractError("signed_payload_contract_error", "json", nil)
		}
		if _, err := strconv.ParseFloat(string(number), kind.Bits()); err != nil {
			return contractError("signed_payload_contract_error", "json", nil)
		}
	case reflect.Interface:
		return nil
	default:
		return contractError("signed_payload_contract_error", "json", nil)
	}
	return nil
}

func validateJSONMembers(data []byte, value any, allowUnknown bool) error {
	shape, err := decodeJSONShape(data)
	if err != nil {
		return err
	}
	kind := reflect.TypeOf(value)
	if kind == nil {
		return contractError("signed_payload_contract_error", "json", nil)
	}
	// The outer pointer is the decoder destination, not a nullable member of the
	// signed contract. Nullable pointers inside that destination remain explicit.
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	return validateExactJSONMembers(shape, kind, allowUnknown)
}

func decodeStrict(data []byte, value any) error {
	if err := validateJSON(data, MaxJSONDepth, true); err != nil {
		return err
	}
	if err := validateJSONMembers(data, value, false); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return contractError("signed_payload_contract_error", "json", nil)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return contractError("signed_payload_trailing_value", "json", nil)
	}
	return nil
}
