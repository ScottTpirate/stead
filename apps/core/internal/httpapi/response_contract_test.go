package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ScottTpirate/stead/apps/core/internal/transaction"
	"github.com/ScottTpirate/stead/modules/authorization"
)

func TestProtectedResponseETagsAreResourceOnly(t *testing.T) {
	for _, resourceETag := range []bool{false, true} {
		for _, status := range []int{http.StatusOK, http.StatusCreated} {
			w := httptest.NewRecorder()
			response, err := newProtectedResponse(w, status, map[string]string{"title": "Resource fixture"}, resourceETag)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(response.body)
			if w.Body.Len() != 0 || len(w.Header()) != 0 {
				t.Fatal("response preparation released protected bytes or headers")
			}
			if err := response.Release(context.Background()); err != nil {
				t.Fatal(err)
			}
			wantETag := ""
			if resourceETag {
				wantETag = `"` + hex.EncodeToString(digest[:]) + `"`
			}
			if w.Code != status || w.Header().Get("ETag") != wantETag || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Stead-Schema-Version") != "1.0" {
				t.Fatal("protected response transport contract mismatch")
			}
			if err := response.Release(context.Background()); err == nil {
				t.Fatal("response released twice")
			}
		}
	}
}

type deniedResponseRepository struct {
	Repository
	zeroProof bool
}

func (repository deniedResponseRepository) FinalizeResponse(context.Context, []*authorization.Decision) (transaction.BoundRevision, error) {
	if repository.zeroProof {
		return transaction.BoundRevision{}, nil
	}
	return transaction.BoundRevision{}, errors.New("finalization denied")
}

func TestResourceAndCollectionFinalizationFailuresDoNotRelease(t *testing.T) {
	boundary, err := transaction.NewRequestBoundaryAdapter(denyRecheck{})
	if err != nil {
		t.Fatal(err)
	}
	for _, resourceETag := range []bool{false, true} {
		for _, zeroProof := range []bool{false, true} {
			server := &Server{config: Config{Repository: deniedResponseRepository{zeroProof: zeroProof}}, boundary: boundary}
			w := httptest.NewRecorder()
			server.release(w, httptest.NewRequest(http.MethodGet, "/", nil), http.StatusOK, map[string]string{"title": "protected"}, nil, resourceETag)
			if w.Code != http.StatusNotFound || bytes.Contains(w.Body.Bytes(), []byte("protected")) || w.Header().Get("ETag") != "" || w.Header().Get("Stead-Schema-Version") != "" {
				t.Fatal("failed final fence released protected body or metadata")
			}
		}
	}
}

// Feed the production Go response encoder's actual bytes and headers through
// the checked-in generated SDK. This is a transport regression, not a claim of
// live identity, authorization, database, or browser coverage.
func TestCollectionResponseEncoderMatchesGeneratedSDK(t *testing.T) {
	type fixture struct {
		Operation string            `json:"operation"`
		Headers   map[string]string `json:"headers"`
		Body      string            `json:"body"`
	}
	fixtures := []fixture{}
	for _, operation := range []string{"listOrganizations", "listTeams", "listProjects"} {
		for _, nextAfter := range []string{"", candidateID(1)} {
			w := httptest.NewRecorder()
			response, err := newProtectedResponse(w, http.StatusOK, resourcePage{Items: []map[string]any{}, NextAfter: nextAfter}, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := response.Release(context.Background()); err != nil {
				t.Fatal(err)
			}
			headers := map[string]string{}
			for name := range w.Header() {
				headers[name] = w.Header().Get(name)
			}
			fixtures = append(fixtures, fixture{Operation: operation, Headers: headers, Body: w.Body.String()})
		}
	}
	input, err := json.Marshal(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join(root, "scripts/run_pinned_node.sh"), "node", "--input-type=module", "--eval", `
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPlatformClient, operationDefinitions, PlatformApiError } from "./packages/api-client/src/index.ts";
for (const fixture of JSON.parse(readFileSync(0, "utf8"))) {
  assert.equal(operationDefinitions[fixture.operation].response.etag, null);
  const options = fixture.operation === "listOrganizations" ? {} : { path: { organization_id: "019ed5bf-0000-7000-8000-000000000001" } };
  const client = createPlatformClient({ fetchImplementation: async () => new Response(fixture.body, { status: 200, headers: fixture.headers }) });
  const result = await client.request(fixture.operation, options);
  assert.deepEqual(result.data, JSON.parse(fixture.body));
  assert.equal(result.etag, undefined);
  const oldHeaders = { ...fixture.headers, ETag: '"old-unexpected-collection-tag"' };
  const oldClient = createPlatformClient({ fetchImplementation: async () => new Response(fixture.body, { status: 200, headers: oldHeaders }) });
  await assert.rejects(oldClient.request(fixture.operation, options), error => error instanceof PlatformApiError && error.status === 502);
}
`)
	command.Dir = root
	command.Stdin = bytes.NewReader(input)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Go response / generated SDK regression failed: %v\n%s", err, output)
	}
}
