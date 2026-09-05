package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ScottTpirate/stead/modules/identity"
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
	if client == nil || ctx.Err() != nil {
		return ErrDenied
	}
	body, err := json.Marshal(input)
	if err != nil {
		return ErrDenied
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint+"/stores/"+client.storeID+path, bytes.NewReader(body))
	if err != nil {
		return ErrDenied
	}
	request.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		request.Header.Set("Authorization", "Bearer "+client.token)
	}
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
	if !validTuple(tuple) {
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
				Key       Tuple  `json:"key"`
				Timestamp string `json:"timestamp"`
			} `json:"tuples"`
			Continuation string `json:"continuation_token"`
		}
		err := client.call(ctx, "/read", struct {
			Tuple       Tuple  `json:"tuple_key"`
			PageSize    int    `json:"page_size"`
			Consistency string `json:"consistency"`
		}{tuple, 2, "HIGHER_CONSISTENCY"}, &result)
		if err != nil || len(result.Tuples) != 1 || result.Continuation != "" || result.Tuples[0].Key != tuple {
			return nil, ErrDenied
		}
	}
	return &TupleReceipt{tuples: tuples, storeID: client.storeID, modelID: client.modelID, verifiedAt: time.Now().UTC()}, nil
}
