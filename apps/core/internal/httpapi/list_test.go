package httpapi

import (
	"context"
	"fmt"
	"testing"

	"github.com/ScottTpirate/stead/modules/authorization"
)

func candidateID(number int) string { return fmt.Sprintf("019ed5bf-0000-7000-8000-%012x", number) }

func TestClosedPageParameters(t *testing.T) {
	for _, raw := range []string{"", "page_size=1", "page_size=20&after=" + candidateID(1)} {
		if _, _, err := pageParameters(raw); err != nil {
			t.Errorf("valid page rejected %q", raw)
		}
	}
	for _, raw := range []string{"page_size=0", "page_size=21", "page_size=01", "page_size=-1", "page_size=2&page_size=3", "after=", "after=not-an-id", "after=" + candidateID(1) + "&after=" + candidateID(2), "total=1", "page_size=1;after=bad", "%zz=x"} {
		if _, _, err := pageParameters(raw); err == nil {
			t.Errorf("invalid page accepted %q", raw)
		}
	}
	if listPattern("GET /api/v1/session") || listPattern("POST /api/v1/organizations") {
		t.Fatal("pagination enabled on non-list route")
	}
}

// These tests exercise discovery mechanics only. The callback is not an
// authorization permit: production still freshly Authorizes/reads every
// selected ID and requires the aggregate sealed response fence afterward.
func TestDiscoveryCrossesDeniedChunksAndUsesAuthorizedLookahead(t *testing.T) {
	calls := 0
	fetch := func(_ context.Context, after string, limit int) ([]string, error) {
		calls++
		ids := []string{}
		for number := 1; number <= 205 && len(ids) < limit; number++ {
			if id := candidateID(number); id > after {
				ids = append(ids, id)
			}
		}
		return ids, nil
	}
	eligible := func(_ context.Context, id string) error {
		if id < candidateID(151) || id > candidateID(154) {
			return authorization.ErrDenied
		}
		return nil
	}
	selected, err := discoverPage(context.Background(), "", 2, fetch, eligible)
	if err != nil || calls != 2 || len(selected) != 3 || selected[0] != candidateID(151) || selected[2] != candidateID(153) {
		t.Fatal("authorized rows after hidden first chunk were lost", selected, err)
	}
	next, err := discoverPage(context.Background(), selected[1], 2, fetch, eligible)
	if err != nil || len(next) != 2 || next[0] != candidateID(153) || next[1] != candidateID(154) {
		t.Fatal("authorized cursor skipped or duplicated rows", next, err)
	}
}

func TestDiscoveryBudgetNeverReturnsPartialOrRawCursor(t *testing.T) {
	fetch := func(_ context.Context, after string, limit int) ([]string, error) {
		ids := []string{}
		for number := 1; number <= 1100 && len(ids) < limit; number++ {
			if id := candidateID(number); id > after {
				ids = append(ids, id)
			}
		}
		return ids, nil
	}
	for _, allowOne := range []bool{false, true} {
		selected, err := discoverPage(context.Background(), "", 2, fetch, func(_ context.Context, id string) error {
			if allowOne && id == candidateID(1) {
				return nil
			}
			return authorization.ErrDenied
		})
		if err == nil || selected != nil {
			t.Fatal("scan exhaustion returned a partial or false empty page")
		}
	}
}
func TestDiscoveryRejectsNonMonotonicCandidatesAndCancellation(t *testing.T) {
	for _, ids := range [][]string{{candidateID(2), candidateID(1)}, {candidateID(1), candidateID(1)}, {"invalid"}} {
		result, err := discoverPage(context.Background(), "", 20, func(context.Context, string, int) ([]string, error) { return ids, nil }, func(context.Context, string) error { return authorization.ErrDenied })
		if err == nil || result != nil {
			t.Fatal("untrusted candidate order accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := discoverPage(ctx, "", 20, func(context.Context, string, int) ([]string, error) {
		t.Fatal("canceled scan reached repository")
		return nil, nil
	}, nil); err == nil {
		t.Fatal("canceled scan accepted")
	}
}
