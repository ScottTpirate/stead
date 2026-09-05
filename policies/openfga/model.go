// Package openfga owns the versioned Stead model source and its deterministic
// JSON representation used for immutable upload/read-back verification.
package openfga

import (
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
)

//go:embed model-v0.2.fga
var source string

// ModelJSON converts this binary's fixed reviewed model (not arbitrary caller
// DSL) to the stock OpenFGA schema1.1 JSON wire format. The canonicalizer is
// stead.openfga-json.v1: exact type/relation names, array order, and rewrites;
// object member ordering follows encoding/json, with no untyped defaults.
func ModelJSON() ([]byte, error) {
	types := []any{}
	var current map[string]any
	for _, raw := range strings.Split(source, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || line == "model" || line == "relations" || line == "schema 1.1" {
			continue
		}
		if strings.HasPrefix(line, "type ") {
			current = map[string]any{"type": strings.TrimPrefix(line, "type ")}
			types = append(types, current)
			continue
		}
		if !strings.HasPrefix(line, "define ") || current == nil {
			return nil, errors.New("invalid fixed model")
		}
		parts := strings.SplitN(strings.TrimPrefix(line, "define "), ": ", 2)
		if len(parts) != 2 {
			return nil, errors.New("invalid fixed relation")
		}
		rewrite, allowed, err := expression(parts[1])
		if err != nil {
			return nil, err
		}
		if current["relations"] == nil {
			current["relations"] = map[string]any{}
		}
		current["relations"].(map[string]any)[parts[0]] = rewrite
		if len(allowed) > 0 {
			if current["metadata"] == nil {
				current["metadata"] = map[string]any{"relations": map[string]any{}}
			}
			current["metadata"].(map[string]any)["relations"].(map[string]any)[parts[0]] = map[string]any{"directly_related_user_types": allowed}
		}
	}
	return json.Marshal(map[string]any{"schema_version": "1.1", "type_definitions": types})
}

func expression(source string) (any, []any, error) {
	for _, operator := range []struct{ word, key string }{{" or ", "union"}, {" and ", "intersection"}} {
		parts := strings.Split(source, operator.word)
		if len(parts) > 1 {
			children := []any{}
			allowed := []any{}
			for _, part := range parts {
				child, direct, err := expression(part)
				if err != nil {
					return nil, nil, err
				}
				children = append(children, child)
				allowed = append(allowed, direct...)
			}
			return map[string]any{operator.key: map[string]any{"child": children}}, allowed, nil
		}
	}
	if strings.HasPrefix(source, "[") && strings.HasSuffix(source, "]") {
		allowed := []any{}
		for _, name := range strings.Split(source[1:len(source)-1], ",") {
			parts := strings.Split(strings.TrimSpace(name), "#")
			value := map[string]any{"type": parts[0]}
			if len(parts) == 2 {
				value["relation"] = parts[1]
			}
			allowed = append(allowed, value)
		}
		return map[string]any{"this": map[string]any{}}, allowed, nil
	}
	parts := strings.Split(source, " from ")
	if len(parts) == 2 {
		return map[string]any{"tupleToUserset": map[string]any{"tupleset": map[string]any{"relation": parts[1]}, "computedUserset": map[string]any{"relation": parts[0]}}}, nil, nil
	}
	if source == "" || strings.ContainsAny(source, " []:#") {
		return nil, nil, errors.New("invalid fixed expression")
	}
	return map[string]any{"computedUserset": map[string]any{"relation": source}}, nil, nil
}
