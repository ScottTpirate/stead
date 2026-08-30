package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maximumManifestBytes = 8 << 20

var canonicalJSONInteger = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

type manifestJSONKind uint8

const (
	manifestJSONObject manifestJSONKind = iota
	manifestJSONArray
	manifestJSONString
	manifestJSONBoolean
	manifestJSONInteger
)

type manifestJSONShape struct {
	kind     manifestJSONKind
	fields   map[string]*manifestJSONShape
	required map[string]struct{}
	element  *manifestJSONShape
}

var manifestRootJSONShape = buildManifestJSONShape()

// DecodeManifest performs a canonical structural pass before typed decoding.
// Rendering and effective-config ownership remain outside this package.
func DecodeManifest(reader io.Reader) (Manifest, error) {
	encoded, err := io.ReadAll(io.LimitReader(reader, maximumManifestBytes+1))
	if err != nil || len(encoded) > maximumManifestBytes {
		return Manifest{}, errors.New("postgres catalog manifest read failed")
	}
	if !utf8.Valid(encoded) {
		return Manifest{}, errors.New("postgres catalog manifest is not valid UTF-8")
	}
	if err := validateCanonicalManifestJSON(encoded); err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		return Manifest{}, errors.New("postgres catalog manifest typed decode failed")
	}
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func validateCanonicalManifestJSON(encoded []byte) error {
	if hasEscapedObjectKey(encoded) {
		return errors.New("postgres catalog manifest has an ambiguous object-key encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := validateManifestJSONValue(decoder, manifestRootJSONShape); err != nil {
		return errors.New("postgres catalog manifest is not canonical JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("postgres catalog manifest has trailing data")
	}
	return nil
}

func hasEscapedObjectKey(encoded []byte) bool {
	for index := 0; index < len(encoded); index++ {
		if encoded[index] != '"' {
			continue
		}
		escaped := false
		closing := index + 1
		for ; closing < len(encoded); closing++ {
			switch encoded[closing] {
			case '\\':
				escaped = true
				closing++
			case '"':
				goto stringClosed
			}
		}
		return false
	stringClosed:
		next := closing + 1
		for next < len(encoded) && (encoded[next] == ' ' || encoded[next] == '\t' || encoded[next] == '\r' || encoded[next] == '\n') {
			next++
		}
		if escaped && next < len(encoded) && encoded[next] == ':' {
			return true
		}
		index = closing
	}
	return false
}

func validateManifestJSONValue(decoder *json.Decoder, shape *manifestJSONShape) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch shape.kind {
	case manifestJSONObject:
		delimiter, ok := token.(json.Delim)
		if !ok || delimiter != '{' {
			return errors.New("expected object")
		}
		seen := make(map[string]struct{}, len(shape.fields))
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || strings.ContainsRune(key, utf8.RuneError) {
				return errors.New("invalid object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			fieldShape, known := shape.fields[key]
			if !known {
				for knownKey := range shape.fields {
					if strings.EqualFold(key, knownKey) {
						return errors.New("case-variant object key")
					}
				}
				return errors.New("unknown object key")
			}
			seen[key] = struct{}{}
			if err := validateManifestJSONValue(decoder, fieldShape); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated object")
		}
		for required := range shape.required {
			if _, present := seen[required]; !present {
				return errors.New("missing required object key")
			}
		}
		return nil
	case manifestJSONArray:
		delimiter, ok := token.(json.Delim)
		if !ok || delimiter != '[' {
			return errors.New("expected array")
		}
		for decoder.More() {
			if err := validateManifestJSONValue(decoder, shape.element); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated array")
		}
		return nil
	case manifestJSONString:
		value, ok := token.(string)
		if !ok || strings.ContainsRune(value, utf8.RuneError) {
			return errors.New("expected canonical string")
		}
		return nil
	case manifestJSONBoolean:
		if _, ok := token.(bool); !ok {
			return errors.New("expected boolean")
		}
		return nil
	case manifestJSONInteger:
		value, ok := token.(json.Number)
		if !ok || !canonicalJSONInteger.MatchString(value.String()) {
			return errors.New("expected canonical integer")
		}
		return nil
	default:
		return errors.New("unknown manifest JSON shape")
	}
}

func buildManifestJSONShape() *manifestJSONShape {
	stringValue := &manifestJSONShape{kind: manifestJSONString}
	booleanValue := &manifestJSONShape{kind: manifestJSONBoolean}
	integerValue := &manifestJSONShape{kind: manifestJSONInteger}
	stringArray := arrayShape(stringValue)
	roleProperties := objectShape(map[string]*manifestJSONShape{
		"superuser": booleanValue, "inherit": booleanValue, "create_role": booleanValue,
		"create_database": booleanValue, "login": booleanValue, "replication": booleanValue,
		"bypass_rls": booleanValue, "connection_limit": integerValue,
		"password_present": booleanValue, "valid_until_utc": stringValue,
		"configuration": stringArray,
	})
	role := objectShape(map[string]*manifestJSONShape{
		"semantic_id": stringValue, "name": stringValue, "binding": stringValue, "properties": roleProperties,
	})
	principal := objectShape(map[string]*manifestJSONShape{"semantic_id": stringValue, "name": stringValue})
	membership := objectShape(map[string]*manifestJSONShape{
		"role": stringValue, "member": stringValue, "grantor": stringValue,
		"admin_option": booleanValue, "inherit_option": booleanValue, "set_option": booleanValue,
	})
	database := objectShape(map[string]*manifestJSONShape{"name": stringValue, "owner": stringValue})
	schema := objectShape(map[string]*manifestJSONShape{"name": stringValue, "owner": stringValue})
	object := objectShape(map[string]*manifestJSONShape{
		"schema": stringValue, "name": stringValue, "kind": stringValue, "owner": stringValue,
	})
	databaseACL := objectShape(map[string]*manifestJSONShape{
		"database": stringValue, "grantor": stringValue, "grantee": stringValue,
		"privilege": stringValue, "grant_option": booleanValue,
	})
	schemaACL := objectShape(map[string]*manifestJSONShape{
		"schema": stringValue, "grantor": stringValue, "grantee": stringValue,
		"privilege": stringValue, "grant_option": booleanValue,
	})
	objectACL := objectShape(map[string]*manifestJSONShape{
		"schema": stringValue, "object": stringValue, "object_kind": stringValue,
		"grantor": stringValue, "grantee": stringValue, "privilege": stringValue,
		"grant_option": booleanValue,
	})
	defaultACL := objectShapeWithOptional(map[string]*manifestJSONShape{
		"owner": stringValue, "schema": stringValue, "object_kind": stringValue,
		"grantor": stringValue, "grantee": stringValue, "privilege": stringValue,
		"grant_option": booleanValue,
	}, "schema")
	return objectShape(map[string]*manifestJSONShape{
		"deployment_key":    stringValue,
		"installation_uuid": stringValue,
		"databases":         arrayShape(database),
		"roles":             arrayShape(role),
		"principals":        arrayShape(principal),
		"memberships":       arrayShape(membership),
		"schemas":           arrayShape(schema),
		"objects":           arrayShape(object),
		"database_acls":     arrayShape(databaseACL),
		"schema_acls":       arrayShape(schemaACL),
		"object_acls":       arrayShape(objectACL),
		"default_acls":      arrayShape(defaultACL),
	})
}

func objectShape(fields map[string]*manifestJSONShape) *manifestJSONShape {
	return objectShapeWithOptional(fields)
}

func objectShapeWithOptional(fields map[string]*manifestJSONShape, optional ...string) *manifestJSONShape {
	required := make(map[string]struct{}, len(fields))
	for field := range fields {
		required[field] = struct{}{}
	}
	for _, field := range optional {
		delete(required, field)
	}
	return &manifestJSONShape{kind: manifestJSONObject, fields: fields, required: required}
}

func arrayShape(element *manifestJSONShape) *manifestJSONShape {
	return &manifestJSONShape{kind: manifestJSONArray, element: element}
}
