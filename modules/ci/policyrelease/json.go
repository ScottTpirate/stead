package policyrelease

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
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

func jsonMemberTypes(kind reflect.Type) map[string]reflect.Type {
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	members := make(map[string]reflect.Type)
	if kind.Kind() != reflect.Struct {
		return members
	}
	for index := 0; index < kind.NumField(); index++ {
		field := kind.Field(index)
		if !field.IsExported() {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		members[name] = field.Type
	}
	return members
}

// validateExactJSONMembers closes the case-insensitive matching performed by
// encoding/json. When allowUnknown is true, genuinely unknown DSSE envelope
// extensions remain ignorable, but a case-folded alias of a known member is
// never an extension and is rejected.
func validateExactJSONMembers(shape any, kind reflect.Type, allowUnknown bool) error {
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	switch kind.Kind() {
	case reflect.Struct:
		object, ok := shape.(map[string]any)
		if !ok {
			return contractError("signed_payload_contract_error", "json", nil)
		}
		members := jsonMemberTypes(kind)
		for name, value := range object {
			memberType, exact := members[name]
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
			if err := validateExactJSONMembers(value, memberType, allowUnknown); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		items, ok := shape.([]any)
		if !ok {
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
	case reflect.Interface:
		return nil
	}
	return nil
}

func validateJSONMembers(data []byte, value any, allowUnknown bool) error {
	shape, err := decodeJSONShape(data)
	if err != nil {
		return err
	}
	return validateExactJSONMembers(shape, reflect.TypeOf(value), allowUnknown)
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
