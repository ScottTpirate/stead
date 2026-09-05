package authorization

import (
	"context"
	"strconv"
)

// Stock OpenFGA's default batch bound. A local collection can need at most
// three HTTP requests; every request pins the model and fresh consistency.
const maxBatchChecks = 50

func (client *OpenFGA) BatchCheck(ctx context.Context, tuples []Tuple) ([]bool, error) {
	if client == nil || ctx == nil || ctx.Err() != nil || len(tuples) == 0 || len(tuples) > MaxReadSet {
		return nil, ErrDenied
	}
	seen := map[Tuple]bool{}
	for _, tuple := range tuples {
		if !validTuple(tuple) || seen[tuple] {
			return nil, ErrDenied
		}
		seen[tuple] = true
	}
	type check struct {
		Tuple       Tuple  `json:"tuple_key"`
		Correlation string `json:"correlation_id"`
	}
	results := make([]bool, len(tuples))
	for start := 0; start < len(tuples); start += maxBatchChecks {
		end := min(start+maxBatchChecks, len(tuples))
		checks := make([]check, end-start)
		for i := start; i < end; i++ {
			checks[i-start] = check{tuples[i], strconv.Itoa(i + 1)}
		}
		var response struct {
			Result map[string]struct {
				Allowed *bool `json:"allowed"`
			} `json:"result"`
		}
		if err := client.call(ctx, "/batch-check", struct {
			Model       string  `json:"authorization_model_id"`
			Consistency string  `json:"consistency"`
			Checks      []check `json:"checks"`
		}{client.modelID, "HIGHER_CONSISTENCY", checks}, &response); err != nil || len(response.Result) != len(checks) {
			return nil, ErrDenied
		}
		for i := start; i < end; i++ {
			result, ok := response.Result[strconv.Itoa(i+1)]
			if !ok || result.Allowed == nil {
				return nil, ErrDenied
			}
			results[i] = *result.Allowed
		}
	}
	return results, nil
}
