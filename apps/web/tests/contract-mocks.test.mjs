import assert from "node:assert/strict";
import test from "node:test";

import {
  createContractMockFetch,
} from "../../../packages/test-fixtures/frontend/src/index.ts";

const VALID_UUID = "018f0f4e-7d65-7c25-8ca5-23f96ae107aa";
const ACCEPT = "application/json, application/problem+json";
const VALID_CREATE_BODY = {
  title: "Contract fixture",
  body: "",
  work_type: "deliverable",
  status: "backlog",
  priority: "none",
  assignees: [],
};

function requestInit(method, headers = {}, body) {
  return {
    method,
    headers: { Accept: ACCEPT, ...headers },
    credentials: "same-origin",
    redirect: "error",
    ...(body === undefined ? {} : { body }),
  };
}

test("contract mocks accept only a generated operation on the trusted Stead origin", async () => {
  const observed = [];
  const mocks = createContractMockFetch({}, (observation) => observed.push(observation));
  const validPath = `/api/v1/projects/${VALID_UUID}`;

  await mocks.fetch(validPath, requestInit("GET"));
  await mocks.fetch(`https://stead.invalid${validPath}`, requestInit("GET"));
  assert.equal(mocks.requestCount(), 2);
  assert.equal(mocks.operationCount("getProject"), 2);
  assert.deepEqual(observed.map(({ operationId }) => operationId), [
    "getProject",
    "getProject",
  ]);

  for (const [url, init] of [
    [`https://gitea.invalid${validPath}`, requestInit("GET")],
    [`${validPath}#provider-state`, requestInit("GET")],
    [`/api/v1/projects/not-a-uuid`, requestInit("GET")],
    [`/api/v1/projects/${VALID_UUID}/extra`, requestInit("GET")],
    [validPath, requestInit("PUT")],
    [`/api/v1/principals/user/%ZZ`, requestInit("GET")],
  ]) {
    await assert.rejects(mocks.fetch(url, init), /Contract mock rejected request/u);
  }
  assert.equal(mocks.requestCount(), 2);
});

test("contract mocks enforce generated query names, cardinality, encoding, and schemas", async () => {
  const mocks = createContractMockFetch();
  await mocks.fetch(
    "/api/v1/search?q=fixture&resource_type=project&resource_type=work_item",
    requestInit("GET"),
  );
  assert.equal(mocks.operationCount("searchAuthorizedResources"), 1);

  for (const url of [
    "/api/v1/search",
    "/api/v1/search?q=fixture&undeclared=provider",
    "/api/v1/search?q=fixture&constructor=provider",
    "/api/v1/search?q=one&q=two",
    "/api/v1/search?q=fixture&resource_type=provider_repository",
    "/api/v1/search?q=%",
    `/api/v1/projects/${VALID_UUID}?undeclared=provider`,
  ]) {
    await assert.rejects(
      mocks.fetch(url, requestInit("GET")),
      /Contract mock rejected request/u,
    );
  }
  assert.equal(mocks.requestCount(), 1);
});

test("contract mocks enforce generated headers, media type, and request body schema", async () => {
  const mocks = createContractMockFetch();
  const path = `/api/v1/projects/${VALID_UUID}/work-items`;
  const validHeaders = {
    "Content-Type": "application/json",
    "Idempotency-Key": "request-0001",
  };
  const validBody = JSON.stringify(VALID_CREATE_BODY);

  await mocks.fetch(path, requestInit("POST", validHeaders, validBody));
  assert.equal(mocks.operationCount("createWorkItem"), 1);

  const updatePath = `/api/v1/work-items/${VALID_UUID}`;
  const updateHeaders = {
    "Content-Type": "application/merge-patch+json",
    "Idempotency-Key": "request-0002",
    "If-Match": '"3"',
  };
  await mocks.fetch(
    updatePath,
    requestInit("PATCH", updateHeaders, JSON.stringify({ title: "Updated" })),
  );
  assert.equal(mocks.operationCount("updateWorkItem"), 1);

  for (const init of [
    requestInit("POST", { "Content-Type": "application/json" }, validBody),
    requestInit(
      "POST",
      { ...validHeaders, "Idempotency-Key": "short" },
      validBody,
    ),
    requestInit(
      "POST",
      { ...validHeaders, "X-Provider-Token": "must-not-pass" },
      validBody,
    ),
    requestInit(
      "POST",
      { ...validHeaders, "Content-Type": "text/plain" },
      validBody,
    ),
    requestInit(
      "POST",
      validHeaders,
      JSON.stringify({ title: "missing generated fields" }),
    ),
    requestInit(
      "POST",
      validHeaders,
      JSON.stringify({ ...VALID_CREATE_BODY, undeclared: "provider" }),
    ),
    requestInit("POST", validHeaders, "{not-json"),
    requestInit("POST", validHeaders),
  ]) {
    await assert.rejects(mocks.fetch(path, init), /Contract mock rejected request/u);
  }

  await assert.rejects(
    mocks.fetch(
      updatePath,
      requestInit(
        "PATCH",
        { ...updateHeaders, "If-Match": 'W/"3"' },
        JSON.stringify({ title: "Updated" }),
      ),
    ),
    /Contract mock rejected request/u,
  );

  await assert.rejects(
    mocks.fetch(`/api/v1/projects/${VALID_UUID}`, {
      ...requestInit("GET"),
      headers: { Accept: ACCEPT, "Content-Type": "application/json" },
      body: "{}",
    }),
    /Contract mock rejected request/u,
  );
  assert.equal(mocks.requestCount(), 2);
});

test("contract mocks reject missing headers and every altered effective transport", async () => {
  const mocks = createContractMockFetch();
  const path = `/api/v1/projects/${VALID_UUID}`;
  for (const init of [
    {
      method: "GET",
      credentials: "same-origin",
      redirect: "error",
    },
    requestInit("GET", { Authorization: "Bearer provider-token" }),
    { ...requestInit("GET"), credentials: "include" },
    { ...requestInit("GET"), redirect: "follow" },
    { ...requestInit("GET"), cache: "no-store" },
    { ...requestInit("GET"), mode: "same-origin" },
    { ...requestInit("GET"), referrer: "https://stead.invalid/protected" },
    { ...requestInit("GET"), referrerPolicy: "unsafe-url" },
    { ...requestInit("GET"), integrity: "sha256-deadbeef" },
    { ...requestInit("GET"), keepalive: true },
  ]) {
    await assert.rejects(mocks.fetch(path, init), /Contract mock rejected request/u);
  }
  await assert.rejects(
    mocks.fetch(
      new Request(`https://stead.invalid${path}`, {
        ...requestInit("GET"),
        cache: "reload",
      }),
    ),
    /Contract mock rejected request/u,
  );
  assert.equal(mocks.requestCount(), 0);
});
