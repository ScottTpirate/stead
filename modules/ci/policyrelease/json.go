package policyrelease

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
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
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return contractError("json_trailing_value", fmt.Sprint(token), nil)
		}
		return contractError("malformed_json", "", err)
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, depth, maxDepth int, rejectNonIntegers bool) error {
	token, err := decoder.Token()
	if err != nil {
		return contractError("malformed_json", "", err)
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
				return contractError("malformed_json", "", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return contractError("malformed_json_object_key", "", nil)
			}
			if _, exists := keys[key]; exists {
				return contractError("duplicate_json_key", key, nil)
			}
			keys[key] = struct{}{}
			if err := validateJSONValue(decoder, depth, maxDepth, rejectNonIntegers); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return contractError("malformed_json", "", err)
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder, depth, maxDepth, rejectNonIntegers); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return contractError("malformed_json", "", err)
		}
	default:
		return contractError("malformed_json", "", nil)
	}
	return nil
}

func decodeStrict(data []byte, value any) error {
	if err := validateJSON(data, MaxJSONDepth, true); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return contractError("signed_payload_contract_error", "", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return contractError("signed_payload_trailing_value", "", err)
	}
	return nil
}
