package postgres

import (
	"encoding/json"
	"errors"
	"io"
)

// DecodeManifest decodes one WS-12-rendered manifest without accepting unknown
// fields or trailing documents. Rendering and effective-config ownership remain
// outside this package.
func DecodeManifest(reader io.Reader) (Manifest, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, errors.New("postgres catalog manifest decode failed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, errors.New("postgres catalog manifest has trailing data")
	}
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}
