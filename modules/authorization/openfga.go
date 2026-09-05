package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ScottTpirate/stead/internal/telemetry"
	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
	"github.com/ScottTpirate/stead/modules/identity"
	fixedmodel "github.com/ScottTpirate/stead/policies/openfga"
)

type Tuple struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// OpenFGA owns a fixed deployment endpoint/store/model. Request bodies cannot
// redirect it or select an alternate model. No retries or decision cache exist.
type OpenFGA struct {
	endpoint, storeID, modelID, token string
	client                            *http.Client
}
type OpenFGAConfig struct {
	URL, StoreID, ModelID, Token string
	LocalDevelopment             bool
}

var ulidPattern = regexp.MustCompile(`^[ABCDEFGHJKMNPQRSTVWXYZ0-9]{26}$`)
var relationPattern = regexp.MustCompile(`^[a-z][a-z_]{0,49}$`)

func NewOpenFGA(config OpenFGAConfig) (*OpenFGA, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || !ulidPattern.MatchString(config.StoreID) || !ulidPattern.MatchString(config.ModelID) {
		return nil, ErrDenied
	}
	local := net.ParseIP(endpoint.Hostname())
	loopback := local != nil && local.IsLoopback()
	if endpoint.Scheme != "https" && !(config.LocalDevelopment && endpoint.Scheme == "http" && loopback) {
		return nil, ErrDenied
	}
	if endpoint.Hostname() == "" || strings.ContainsAny(config.Token, "\r\n") {
		return nil, ErrDenied
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &OpenFGA{endpoint: strings.TrimSuffix(config.URL, "/"), storeID: config.StoreID, modelID: config.ModelID, token: config.Token, client: client}, nil
}

func (client *OpenFGA) ModelID() string {
	if client == nil {
		return ""
	}
	return client.modelID
}
func (client *OpenFGA) StoreID() string {
	if client == nil {
		return ""
	}
	return client.storeID
}
func validTuple(tuple Tuple) bool {
	user := strings.Split(tuple.User, ":")
	object := strings.Split(tuple.Object, ":")
	if len(user) != 2 || len(object) != 2 || !identity.ValidID(user[1]) || !identity.ValidID(object[1]) || !relationPattern.MatchString(tuple.Relation) {
		return false
	}
	return slices.Contains([]string{"user", "agent", "service_account", "organization", "team", "project"}, user[0]) && slices.Contains([]string{"instance", "organization", "team", "project"}, object[0])
}

func (client *OpenFGA) call(ctx context.Context, path string, input, output any) error {
	return client.request(ctx, http.MethodPost, "/stores/"+client.storeID+path, input, output)
}

func (client *OpenFGA) request(ctx context.Context, method, path string, input, output any) error {
	if client == nil || ctx.Err() != nil {
		return ErrDenied
	}
	body, err := json.Marshal(input)
	if err != nil {
		return ErrDenied
	}
	request, err := http.NewRequestWithContext(ctx, method, client.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return ErrDenied
	}
	request.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		request.Header.Set("Authorization", "Bearer "+client.token)
	}
	telemetry.AddOpenFGA(ctx, 1)
	response, err := client.client.Do(request)
	if err != nil {
		return ErrDenied
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if err != nil || len(data) > 64<<10 || response.StatusCode < 200 || response.StatusCode > 299 {
		return ErrDenied
	}
	if output == nil {
		return nil
	}
	return decodeClosed(data, output)
}

func (client *OpenFGA) Check(ctx context.Context, tuple Tuple) (bool, error) {
	if client == nil || !validTuple(tuple) {
		return false, ErrDenied
	}
	var result struct {
		Allowed    *bool  `json:"allowed"`
		Resolution string `json:"resolution"`
	}
	err := client.call(ctx, "/check", struct {
		ModelID     string `json:"authorization_model_id"`
		Tuple       Tuple  `json:"tuple_key"`
		Consistency string `json:"consistency"`
	}{client.modelID, tuple, "HIGHER_CONSISTENCY"}, &result)
	if err != nil || result.Allowed == nil {
		return false, ErrDenied
	}
	return *result.Allowed, nil
}

// ModelReceipt cannot be constructed by an API caller. It binds the exact
// fixed model canonical bytes to an immutable model returned by OpenFGA.
type ModelReceipt struct{ modelID, storeID, sourceDigest string }

func (receipt *ModelReceipt) ModelID() string {
	if receipt == nil {
		return ""
	}
	return receipt.modelID
}
func (receipt *ModelReceipt) StoreID() string {
	if receipt == nil {
		return ""
	}
	return receipt.storeID
}
func (receipt *ModelReceipt) SourceDigest() string {
	if receipt == nil {
		return ""
	}
	return receipt.sourceDigest
}

func canonicalModel(data []byte) ([]byte, error) {
	var value map[string]any
	if decodeClosed(data, &value) != nil {
		return nil, ErrDenied
	}
	for key := range value {
		if !slices.Contains([]string{"schema_version", "type_definitions", "conditions", "id"}, key) {
			return nil, ErrDenied
		}
	}
	delete(value, "id")
	// Stock protojson emits these known protobuf defaults while an upload may
	// omit them. Only these non-semantic defaults are removed; unknown fields,
	// nonempty metadata, conditions, or rewrites remain and must compare equal.
	normalizeModelDefaults(value)
	if conditions, present := value["conditions"]; present {
		object, ok := conditions.(map[string]any)
		if !ok || len(object) != 0 {
			return nil, ErrDenied
		}
		delete(value, "conditions")
	}
	types, ok := value["type_definitions"].([]any)
	if !ok {
		return nil, ErrDenied
	}
	for _, raw := range types {
		definition, ok := raw.(map[string]any)
		if !ok {
			return nil, ErrDenied
		}
		for _, key := range []string{"relations", "metadata"} {
			if child, ok := definition[key].(map[string]any); ok && len(child) == 0 {
				delete(definition, key)
			}
		}
	}
	return json.Marshal(value)
}

func normalizeModelDefaults(value any) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if child == nil && slices.Contains([]string{"metadata", "source_info", "wildcard"}, key) {
				delete(node, key)
				continue
			}
			if text, ok := child.(string); ok && text == "" && slices.Contains([]string{"module", "object", "relation", "condition"}, key) {
				delete(node, key)
				continue
			}
			normalizeModelDefaults(child)
			if object, ok := child.(map[string]any); ok && len(object) == 0 && slices.Contains([]string{"relations", "conditions", "metadata"}, key) {
				delete(node, key)
			}
		}
	case []any:
		for _, child := range node {
			normalizeModelDefaults(child)
		}
	}
}

func (client *OpenFGA) VerifyModel(ctx context.Context) (*ModelReceipt, error) {
	if client == nil {
		return nil, ErrDenied
	}
	source, err := fixedmodel.ModelJSON()
	if err != nil {
		return nil, ErrDenied
	}
	var result struct {
		Model json.RawMessage `json:"authorization_model"`
	}
	if client.request(ctx, http.MethodGet, "/stores/"+client.storeID+"/authorization-models/"+client.modelID, nil, &result) != nil {
		return nil, ErrDenied
	}
	var identity struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(result.Model, &identity) != nil || identity.ID != client.modelID {
		return nil, ErrDenied
	}
	actual, err := canonicalModel(result.Model)
	if err != nil || !bytes.Equal(actual, source) {
		return nil, ErrDenied
	}
	return &ModelReceipt{modelID: client.modelID, storeID: client.storeID, sourceDigest: policyrelease.SHA256Digest(source)}, nil
}

// ProvisionLocalOpenFGA is explicit disposable-development setup. It creates
// a new store, uploads the fixed expand-compatible model, and reads it back.
// Failure leaves an inert store for diagnosis; it never selects latest or
// pretends an unverified upload is an activation.
func ProvisionLocalOpenFGA(ctx context.Context, endpoint, token string) (*OpenFGA, *ModelReceipt, error) {
	const placeholder = "00000000000000000000000000"
	client, err := NewOpenFGA(OpenFGAConfig{URL: endpoint, StoreID: placeholder, ModelID: placeholder, Token: token, LocalDevelopment: true})
	if err != nil {
		return nil, nil, err
	}
	var store struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Created string `json:"created_at"`
		Updated string `json:"updated_at"`
		Deleted string `json:"deleted_at"`
	}
	if client.request(ctx, http.MethodPost, "/stores", map[string]string{"name": "Stead local development"}, &store) != nil || !ulidPattern.MatchString(store.ID) {
		return nil, nil, fmt.Errorf("OpenFGA bootstrap store: %w", ErrDenied)
	}
	client.storeID = store.ID
	source, err := fixedmodel.ModelJSON()
	if err != nil {
		return nil, nil, ErrDenied
	}
	var model struct {
		ID string `json:"authorization_model_id"`
	}
	if client.call(ctx, "/authorization-models", json.RawMessage(source), &model) != nil || !ulidPattern.MatchString(model.ID) {
		return nil, nil, fmt.Errorf("OpenFGA bootstrap model upload: %w", ErrDenied)
	}
	client.modelID = model.ID
	receipt, err := client.VerifyModel(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("OpenFGA bootstrap model readback: %w", ErrDenied)
	}
	return client, receipt, nil
}

// TupleReceipt proves exact direct tuples were observed after acknowledged
// writes. It is not authorization and cannot clear a pending row by itself.
type TupleReceipt struct {
	tuples           []Tuple
	storeID, modelID string
	verifiedAt       time.Time
}

func (receipt *TupleReceipt) Match(tuples []Tuple) bool {
	return receipt != nil && len(tuples) > 0 && slices.Equal(receipt.tuples, sortedTuples(tuples))
}
func (receipt *TupleReceipt) ModelID() string {
	if receipt == nil {
		return ""
	}
	return receipt.modelID
}
func (receipt *TupleReceipt) StoreID() string {
	if receipt == nil {
		return ""
	}
	return receipt.storeID
}
func (receipt *TupleReceipt) VerifiedAt() time.Time {
	if receipt == nil {
		return time.Time{}
	}
	return receipt.verifiedAt
}
func sortedTuples(tuples []Tuple) []Tuple {
	copy := append([]Tuple(nil), tuples...)
	slices.SortFunc(copy, func(a, b Tuple) int {
		return strings.Compare(a.Object+"\x00"+a.Relation+"\x00"+a.User, b.Object+"\x00"+b.Relation+"\x00"+b.User)
	})
	return copy
}

// WriteVerified is only for the owned pending-grant worker/bootstrap caller,
// never browser data. Actual stored tuples are read; a computed Check allow
// would not prove a direct creator/lead binding. Duplicate writes are ignored
// by the API's explicit idempotency option, not by swallowing errors.
func (client *OpenFGA) WriteVerified(ctx context.Context, tuples []Tuple) (*TupleReceipt, error) {
	if client == nil || len(tuples) < 1 || len(tuples) > 8 {
		return nil, ErrDenied
	}
	tuples = sortedTuples(tuples)
	for i, tuple := range tuples {
		if !validTuple(tuple) || (i > 0 && tuple == tuples[i-1]) {
			return nil, ErrDenied
		}
	}
	input := struct {
		ModelID string `json:"authorization_model_id"`
		Writes  struct {
			Tuples    []Tuple `json:"tuple_keys"`
			Duplicate string  `json:"on_duplicate"`
		} `json:"writes"`
	}{ModelID: client.modelID}
	input.Writes.Tuples = tuples
	input.Writes.Duplicate = "ignore"
	if err := client.call(ctx, "/write", input, nil); err != nil {
		return nil, ErrDenied
	}
	for _, tuple := range tuples {
		var result struct {
			Tuples []struct {
				Key struct {
					User      string          `json:"user"`
					Relation  string          `json:"relation"`
					Object    string          `json:"object"`
					Condition json.RawMessage `json:"condition"`
				} `json:"key"`
				Timestamp string `json:"timestamp"`
			} `json:"tuples"`
			Continuation string `json:"continuation_token"`
		}
		err := client.call(ctx, "/read", struct {
			Tuple       Tuple  `json:"tuple_key"`
			PageSize    int    `json:"page_size"`
			Consistency string `json:"consistency"`
		}{tuple, 2, "HIGHER_CONSISTENCY"}, &result)
		if err != nil || len(result.Tuples) != 1 || result.Continuation != "" {
			return nil, ErrDenied
		}
		key := result.Tuples[0].Key
		if (Tuple{User: key.User, Relation: key.Relation, Object: key.Object}) != tuple || (len(key.Condition) != 0 && !bytes.Equal(key.Condition, []byte("null"))) {
			return nil, ErrDenied
		}
	}
	return &TupleReceipt{tuples: tuples, storeID: client.storeID, modelID: client.modelID, verifiedAt: time.Now().UTC()}, nil
}
