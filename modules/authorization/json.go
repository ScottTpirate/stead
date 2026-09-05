package authorization

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// decodeClosed rejects ambiguity before decoding typed security input. JSON
// field names are case-sensitive; encoding/json's case-folding is not a
// security contract. All numbers in these contracts are integers.
func decodeClosed(data []byte, target any) error {
	if len(data) == 0 || len(data) > 8<<20 || !utf8.Valid(data) {
		return ErrDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	shape, err := jsonValue(decoder, 0)
	if err != nil {
		return ErrDenied
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrDenied
	}
	if !exactMembers(shape, reflect.TypeOf(target)) {
		return ErrDenied
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrDenied
	}
	return nil
}

func jsonValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, ErrDenied
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrDenied
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				if len(object) >= 512 {
					return nil, ErrDenied
				}
				key, err := decoder.Token()
				if err != nil {
					return nil, ErrDenied
				}
				name, ok := key.(string)
				if !ok {
					return nil, ErrDenied
				}
				if _, exists := object[name]; exists {
					return nil, ErrDenied
				}
				child, err := jsonValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrDenied
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				if len(array) >= 512 {
					return nil, ErrDenied
				}
				child, err := jsonValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrDenied
			}
			return array, nil
		}
	case json.Number:
		if strings.ContainsAny(string(value), ".eE") {
			return nil, ErrDenied
		}
		return value, nil
	case string, bool, nil:
		return value, nil
	}
	return nil, ErrDenied
}

func exactMembers(shape any, kind reflect.Type) bool {
	if shape == nil && kind.Kind() == reflect.Pointer {
		return true
	}
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	if kind == reflect.TypeOf(json.RawMessage{}) {
		return true
	}
	if kind.Kind() == reflect.Interface {
		return true
	}
	if shape == nil {
		return kind.Kind() == reflect.Pointer || kind.Kind() == reflect.Slice || kind.Kind() == reflect.Map
	}
	switch value := shape.(type) {
	case map[string]any:
		if kind.Kind() == reflect.Map {
			for _, child := range value {
				if !exactMembers(child, kind.Elem()) {
					return false
				}
			}
			return true
		}
		if kind.Kind() != reflect.Struct {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < kind.NumField(); i++ {
			field := kind.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for name, child := range value {
			field, ok := fields[name]
			if !ok || !exactMembers(child, field) {
				return false
			}
		}
	case []any:
		if kind.Kind() != reflect.Slice && kind.Kind() != reflect.Array {
			return false
		}
		for _, child := range value {
			if !exactMembers(child, kind.Elem()) {
				return false
			}
		}
	}
	return true
}
