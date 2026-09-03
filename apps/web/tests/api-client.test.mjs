import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createPlatformClient,
  operationDefinitions,
  PLATFORM_MAX_RESPONSE_BYTES,
  PlatformApiError,
  QueryCancellationError,
  QueryPresentationError,
  QueryStore,
} from "../../../packages/api-client/src/index.ts";
import {
  createContractMockFetch,
  nonDisclosingDenial,
} from "../../../packages/test-fixtures/frontend/src/index.ts";

const VALID_UUID = "018f0f4e-7d65-7c25-8ca5-23f96ae107aa";

const validOperationOptions = {
  getOrganization: { path: { organization_id: VALID_UUID } },
  listTeams: { path: { organization_id: VALID_UUID } },
  getProject: { path: { project_id: VALID_UUID } },
  listWorkItems: { path: { project_id: VALID_UUID } },
  createWorkItem: {
    path: { project_id: VALID_UUID },
    idempotencyKey: "request-0001",
    body: {
      title: "Contract fixture",
      body: "",
      work_type: "deliverable",
      status: "backlog",
      priority: "none",
      assignees: [],
    },
  },
  updateWorkItem: {
    path: { work_item_id: VALID_UUID },
    ifMatch: '"3"',
    idempotencyKey: "request-0002",
    body: { title: "Updated fixture" },
  },
  listOrganizationDocuments: { path: { organization_id: VALID_UUID } },
  listTeamDocuments: { path: { team_id: VALID_UUID } },
  listProjectDocuments: { path: { project_id: VALID_UUID } },
  getPrincipal: {
    path: { principal_type: "user", principal_id: VALID_UUID },
  },
  searchAuthorizedResources: {
    query: { q: "fixture", resource_type: ["project", "work_item"] },
  },
};

function successfulResponse(operationId, body = { contract_fixture: true }) {
  const headers = { "content-type": "application/json" };
  if (operationDefinitions[operationId].response.schemaVersion) {
    headers["stead-schema-version"] = "1.0";
  }
  return new Response(JSON.stringify(body), { status: 200, headers });
}

test("generated operation registry is reproducible from the current OpenAPI contract", async () => {
  const generatedPath = new URL(
    "../../../packages/api-client/src/generated/platform-v1.ts",
    import.meta.url,
  );
  const before = await readFile(generatedPath, "utf8");
  await import("../../../packages/api-client/scripts/generate-operation-registry.mjs");
  const after = await readFile(generatedPath, "utf8");
  assert.equal(after, before);
  assert.equal(Object.keys(operationDefinitions).length, 11);
});

test("browser transport calls one generated same-origin Platform operation", async () => {
  const mocks = createContractMockFetch({
    getProject: {
      status: 200,
      body: { contract_fixture: true },
      headers: { "stead-schema-version": "1.0", etag: '"1"' },
    },
  });
  const client = createPlatformClient({ fetchImplementation: mocks.fetch });
  const response = await client.request("getProject", {
    path: { project_id: "018f0f4e-7d65-7c25-8ca5-23f96ae107aa" },
  });
  assert.deepEqual(response.data, { contract_fixture: true });
  assert.equal(response.schemaVersion, "1.0");
  assert.equal(mocks.requestCount(), 1);
  assert.equal(mocks.operationCount("getProject"), 1);
  assert.throws(
    () => createPlatformClient({ basePath: "https://provider.invalid/api/v1" }),
    /same-origin Stead/u,
  );
});

test("all generated operations enforce their allowed and required request shape", async () => {
  let fetches = 0;
  const operationIds = Object.keys(operationDefinitions);
  const client = createPlatformClient({
    fetchImplementation: (async (input, init) => {
      const operationId = operationIds[fetches];
      const definition = operationDefinitions[operationId];
      const expectedOptions = validOperationOptions[operationId];
      fetches += 1;
      const url = new URL(String(input), "https://stead.invalid");
      const expectedPath = definition.path.replace(
        /\{([a-z_]+)\}/gu,
        (_placeholder, name) => encodeURIComponent(expectedOptions.path[name]),
      );
      assert.equal(url.pathname, `/api/v1${expectedPath}`);
      for (const [name, value] of Object.entries(expectedOptions.query ?? {})) {
        assert.deepEqual(
          url.searchParams.getAll(name),
          (Array.isArray(value) ? value : [value]).map(String),
        );
      }
      assert.equal(init?.method, definition.method);
      assert.equal(init?.credentials, "same-origin");
      assert.equal(init?.redirect, "error");
      const headers = new Headers(init?.headers);
      if (definition.request.body) {
        assert.equal(headers.get("content-type"), definition.request.body.mediaType);
        assert.deepEqual(JSON.parse(init.body), expectedOptions.body);
      } else {
        assert.equal(headers.has("content-type"), false);
        assert.equal(init?.body, undefined);
      }
      for (const [name, header] of Object.entries(definition.request.headers)) {
        assert.equal(headers.get(header.wireName), expectedOptions[name]);
      }
      return successfulResponse(operationId);
    }),
  });

  for (const operationId of Object.keys(operationDefinitions)) {
    await client.request(operationId, validOperationOptions[operationId]);
  }
  assert.equal(fetches, operationIds.length);

  const expectPreflightRejection = async (operationId, options) => {
    const before = fetches;
    await assert.rejects(client.request(operationId, options), /generated Platform contract|missing|unexpected|strong ETag/u);
    assert.equal(fetches, before);
  };

  for (const [operationId, definition] of Object.entries(operationDefinitions)) {
    const valid = structuredClone(validOperationOptions[operationId]);
    for (const [name, parameter] of Object.entries(definition.request.path)) {
      if (parameter.required) {
        const missing = structuredClone(valid);
        delete missing.path[name];
        await expectPreflightRejection(operationId, missing);
      }
      const invalid = structuredClone(valid);
      invalid.path[name] = "not-contract-valid";
      await expectPreflightRejection(operationId, invalid);
    }
    for (const [name, parameter] of Object.entries(definition.request.query)) {
      if (parameter.required) {
        const missing = structuredClone(valid);
        delete missing.query[name];
        await expectPreflightRejection(operationId, missing);
      }
    }
    for (const [name, header] of Object.entries(definition.request.headers)) {
      if (header.required) {
        const missing = structuredClone(valid);
        delete missing[name];
        await expectPreflightRejection(operationId, missing);
      }
    }

    await expectPreflightRejection(operationId, {
      ...structuredClone(valid),
      path: { ...(valid.path ?? {}), undeclared_path: VALID_UUID },
    });
    await expectPreflightRejection(operationId, {
      ...structuredClone(valid),
      query: { ...(valid.query ?? {}), undeclared_query: "secret" },
    });
    if (definition.request.body === null) {
      await expectPreflightRejection(operationId, {
        ...structuredClone(valid),
        body: { undeclared: true },
      });
    } else {
      await expectPreflightRejection(operationId, {
        ...structuredClone(valid),
        body: { ...valid.body, undeclared: true },
      });
    }
    for (const header of ["ifMatch", "idempotencyKey"]) {
      if (!(header in definition.request.headers)) {
        await expectPreflightRejection(operationId, {
          ...structuredClone(valid),
          [header]: header === "ifMatch" ? '"1"' : "request-9999",
        });
      }
    }
  }

  await expectPreflightRejection("searchAuthorizedResources", { query: { q: "" } });
  await expectPreflightRejection("searchAuthorizedResources", {
    query: { q: "fixture", resource_type: ["not-a-resource"] },
  });
  await expectPreflightRejection("createWorkItem", {
    ...structuredClone(validOperationOptions.createWorkItem),
    idempotencyKey: "short",
  });
  await expectPreflightRejection("createWorkItem", {
    ...structuredClone(validOperationOptions.createWorkItem),
    body: { title: "missing required fields" },
  });
  await expectPreflightRejection("updateWorkItem", {
    ...structuredClone(validOperationOptions.updateWorkItem),
    ifMatch: 'W/"3"',
  });
  await expectPreflightRejection("updateWorkItem", {
    ...structuredClone(validOperationOptions.updateWorkItem),
    body: {},
  });
});

test("request validation and serialization share one closed own-data snapshot", async () => {
  const sentBodies = [];
  const client = createPlatformClient({
    fetchImplementation: async (_input, init) => {
      sentBodies.push(init.body);
      return successfulResponse("createWorkItem");
    },
  });
  const request = (body) =>
    client.request("createWorkItem", {
      ...validOperationOptions.createWorkItem,
      body,
    });
  const validBody = structuredClone(validOperationOptions.createWorkItem.body);

  const proxyBody = new Proxy(validBody, {
    get(target, key, receiver) {
      if (key === "toJSON") return () => ({});
      if (key === "title") return "unvalidated-proxy-title";
      return Reflect.get(target, key, receiver);
    },
  });
  await request(proxyBody);
  assert.equal(sentBodies.length, 1);
  assert.deepEqual(JSON.parse(sentBodies[0]), validBody);

  const inheritedToJsonBody = Object.assign(
    Object.create({
      toJSON() {
        return {};
      },
    }),
    structuredClone(validBody),
  );
  const ownToJsonBody = structuredClone(validBody);
  Object.defineProperty(ownToJsonBody, "toJSON", {
    value() {
      return {};
    },
  });
  let accessorReads = 0;
  const accessorBody = structuredClone(validBody);
  Object.defineProperty(accessorBody, "title", {
    enumerable: true,
    get() {
      accessorReads += 1;
      return "accessor-title";
    },
  });
  class RequestBody {}
  const nonPlainBody = Object.assign(new RequestBody(), structuredClone(validBody));
  const cyclicBody = structuredClone(validBody);
  cyclicBody.assignees.push(cyclicBody);
  const sparseArrayBody = {
    ...structuredClone(validBody),
    assignees: new Array(1),
  };

  for (const body of [
    inheritedToJsonBody,
    ownToJsonBody,
    accessorBody,
    nonPlainBody,
    cyclicBody,
    sparseArrayBody,
  ]) {
    await assert.rejects(request(body), /closed plain own-data JSON values/u);
    assert.equal(sentBodies.length, 1);
  }
  assert.equal(accessorReads, 0);

  let pathAccessorReads = 0;
  const accessorPath = {};
  Object.defineProperty(accessorPath, "project_id", {
    enumerable: true,
    get() {
      pathAccessorReads += 1;
      return VALID_UUID;
    },
  });
  await assert.rejects(
    client.request("createWorkItem", {
      ...validOperationOptions.createWorkItem,
      path: accessorPath,
    }),
    /path parameters must be a plain own-data object/u,
  );
  assert.equal(pathAccessorReads, 0);
  assert.equal(sentBodies.length, 1);

  let optionAccessorReads = 0;
  const accessorOptions = {};
  Object.defineProperty(accessorOptions, "path", {
    enumerable: true,
    get() {
      optionAccessorReads += 1;
      return { project_id: VALID_UUID };
    },
  });
  for (const options of [
    accessorOptions,
    Object.assign(Object.create({ inherited: true }), validOperationOptions.getProject),
    { ...validOperationOptions.getProject, undeclared: "secret" },
    { ...validOperationOptions.getProject, signal: {} },
  ]) {
    await assert.rejects(
      client.request("getProject", options),
      /request options must be a closed plain own-data object/u,
    );
    assert.equal(sentBodies.length, 1);
  }
  assert.equal(optionAccessorReads, 0);
});

test("response envelope rejects unsafe metadata and media before reading the body", async () => {
  for (const headers of [
    { "content-type": "text/plain", "stead-schema-version": "1.0" },
    { "content-type": "application/json" },
    { "content-type": "application/json", "stead-schema-version": "garbage" },
    { "content-type": "application/json", "stead-schema-version": "2.0" },
    {
      "content-type": "application/json",
      "stead-schema-version": "1.0",
      "x-correlation-id": "<script>alert(1)</script>",
    },
    {
      "content-type": "application/json",
      "stead-schema-version": "1.0",
      "x-correlation-id": `a${"x".repeat(128)}`,
    },
    {
      "content-type": "application/json",
      "stead-schema-version": "1.0",
      etag: 'W/"1"',
    },
    {
      "content-type": "application/json",
      "stead-schema-version": "1.0",
      etag: "<script>alert(1)</script>",
    },
  ]) {
    let reads = 0;
    const response = {
      ok: true,
      status: 200,
      headers: new Headers(headers),
      body: {
        getReader() {
          reads += 1;
          throw new Error("protected body reader must not be reached");
        },
      },
    };
    const client = createPlatformClient({
      fetchImplementation: async () => response,
    });
    await assert.rejects(
      client.request("getProject", validOperationOptions.getProject),
      (error) => {
        assert.ok(error instanceof PlatformApiError);
        assert.equal(error.status, 502);
        assert.equal(error.message, "The request could not be completed.");
        assert.doesNotMatch(error.message, /protected|script|garbage/u);
        return true;
      },
    );
    assert.equal(reads, 0);
  }

  for (const [operationId, headers] of [
    [
      "getPrincipal",
      { "content-type": "application/json", "stead-schema-version": "1.0" },
    ],
    [
      "listTeams",
      {
        "content-type": "application/json",
        "stead-schema-version": "1.0",
        etag: '"1"',
      },
    ],
  ]) {
    let reads = 0;
    const client = createPlatformClient({
      fetchImplementation: async () => ({
        ok: true,
        status: 200,
        headers: new Headers(headers),
        body: {
          getReader() {
            reads += 1;
            throw new Error("undeclared metadata must fail before body read");
          },
        },
      }),
    });
    await assert.rejects(
      client.request(operationId, validOperationOptions[operationId]),
      (error) => error instanceof PlatformApiError && error.status === 502,
    );
    assert.equal(reads, 0);
  }
});

test("response bodies and embedded correlation IDs are bounded before presentation", async () => {
  const tooLargeByHeader = createPlatformClient({
    fetchImplementation: async () =>
      new Response('{"protected":"secret"}', {
        status: 200,
        headers: {
          "content-type": "application/json",
          "stead-schema-version": "1.0",
          "content-length": String(PLATFORM_MAX_RESPONSE_BYTES + 1),
        },
      }),
  });
  await assert.rejects(
    tooLargeByHeader.request("getProject", validOperationOptions.getProject),
    (error) => error instanceof PlatformApiError && error.status === 502,
  );

  let cancellations = 0;
  const oversizedStream = createPlatformClient({
    fetchImplementation: async () =>
      new Response(
        new ReadableStream({
          pull(controller) {
            controller.enqueue(new Uint8Array(PLATFORM_MAX_RESPONSE_BYTES));
            controller.enqueue(new Uint8Array(1));
          },
          cancel() {
            cancellations += 1;
          },
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
            "stead-schema-version": "1.0",
          },
        },
      ),
  });
  await assert.rejects(
    oversizedStream.request("getProject", validOperationOptions.getProject),
    (error) => error instanceof PlatformApiError && error.status === 502,
  );
  assert.equal(cancellations, 1);

  const unsafeEmbeddedId = createPlatformClient({
    fetchImplementation: async () =>
      successfulResponse("getProject", {
        correlation_id: "unsafe correlation with spaces",
      }),
  });
  await assert.rejects(
    unsafeEmbeddedId.request("getProject", validOperationOptions.getProject),
    (error) => {
      assert.ok(error instanceof PlatformApiError);
      assert.equal(error.correlationId, undefined);
      assert.equal(error.message, "The request could not be completed.");
      return true;
    },
  );
});

test("denials stay generic and reveal only safe correlation context", async () => {
  const mocks = createContractMockFetch({ getProject: nonDisclosingDenial() });
  const client = createPlatformClient({ fetchImplementation: mocks.fetch });
  await assert.rejects(
    client.request("getProject", {
      path: { project_id: "018f0f4e-7d65-7c25-8ca5-23f96ae107aa" },
    }),
    (error) => {
      assert.ok(error instanceof PlatformApiError);
      assert.equal(error.message, "The request could not be completed.");
      assert.equal(error.status, 404);
      assert.equal(error.correlationId, "mock-correlation-0001");
      return true;
    },
  );
});

test("query state deduplicates reads and clears on authorization-context change", async () => {
  const store = new QueryStore();
  store.setAuthorizationContext({
    principal: "principal-a",
    session: "session-a",
    securityDomain: "domain-a",
  });
  let calls = 0;
  let resolveLoader;
  const loader = () => {
    calls += 1;
    return new Promise((resolve) => {
      resolveLoader = resolve;
    });
  };
  const first = store.load("project-surface", loader);
  const second = store.load("project-surface", loader);
  assert.equal(calls, 1);
  resolveLoader({ ok: true });
  assert.deepEqual(await first, { ok: true });
  assert.deepEqual(await second, { ok: true });
  assert.equal(store.getSnapshot("project-surface").status, "success");

  let notifications = 0;
  const unsubscribe = store.subscribe("project-surface", () => {
    notifications += 1;
  });
  store.setAuthorizationContext({
    principal: "principal-b",
    session: "session-b",
    securityDomain: "domain-a",
  });
  assert.equal(store.getSnapshot("project-surface").status, "idle");
  assert.equal(notifications, 1);
  unsubscribe();
});

test("query snapshots and public promises sanitize loader errors", async () => {
  const store = new QueryStore();
  store.setAuthorizationContext({
    principal: "principal-a",
    session: "session-a",
    securityDomain: "domain-a",
  });
  await assert.rejects(
    store.load("protected", async () => {
      const error = new Error("protected-title-secret must not reach presentation");
      error.correlationId = "<unsafe-correlation-secret>";
      throw error;
    }),
    (error) => {
      assert.ok(error instanceof QueryPresentationError);
      assert.equal(error.message, "The request could not be completed.");
      assert.equal(error.correlationId, undefined);
      assert.doesNotMatch(error.message, /protected-title-secret/u);
      return true;
    },
  );
  const snapshot = store.getSnapshot("protected");
  assert.equal(snapshot.error?.message, "The request could not be completed.");
  assert.doesNotMatch(snapshot.error?.message ?? "", /protected-title-secret/u);

  await assert.rejects(
    store.load("protected-sync", () => {
      const protectedError = new Error("protected-sync-secret");
      Object.defineProperty(protectedError, "correlationId", {
        get() {
          throw new Error("protected-getter-secret");
        },
      });
      throw protectedError;
    }),
    (error) => {
      assert.ok(error instanceof QueryPresentationError);
      assert.equal(error.correlationId, undefined);
      assert.doesNotMatch(error.message, /protected|getter/u);
      return true;
    },
  );
});

test("an aborted prior-context request cannot overwrite cleared state", async () => {
  const store = new QueryStore();
  store.setAuthorizationContext({
    principal: "principal-a",
    session: "session-a",
    securityDomain: "domain-a",
  });
  const pending = store.load(
    "protected",
    (signal) =>
      new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        );
      }),
  );
  store.setAuthorizationContext({
    principal: "principal-b",
    session: "session-b",
    securityDomain: "domain-a",
  });
  await assert.rejects(pending, (error) => {
    assert.ok(error instanceof QueryCancellationError);
    assert.equal(error.message, "The request was cancelled.");
    assert.doesNotMatch(error.message, /aborted|authorized context/iu);
    return true;
  });
  assert.equal(store.getSnapshot("protected").status, "idle");
});

test("logout clears both presentation state and authority to load", async () => {
  const store = new QueryStore();
  store.setAuthorizationContext({
    principal: "principal-a",
    session: "session-a",
    securityDomain: "domain-a",
  });
  store.optimisticallySet("protected", { title: "synthetic" });
  store.clearAuthorizationContext();
  assert.equal(store.getSnapshot("protected").status, "idle");
  await assert.rejects(
    store.load("protected", async () => ({ title: "must not load" })),
    /authorization context must be set/u,
  );
  assert.throws(
    () => store.optimisticallySet("protected", { title: "must not present" }),
    /authorization context must be set/u,
  );
});

test("optimistic presentation exposes a bounded rollback", () => {
  const store = new QueryStore();
  store.setAuthorizationContext({
    principal: "principal-a",
    session: "session-a",
    securityDomain: "domain-a",
  });
  const rollback = store.optimisticallySet("view", { state: "pending" });
  assert.deepEqual(store.getSnapshot("view").data, { state: "pending" });
  rollback();
  assert.equal(store.getSnapshot("view").status, "idle");
});

test("optimistic rollback is ordered, idempotent, and cannot resurrect a failed predecessor", () => {
  const store = new QueryStore();
  store.setAuthorizationContext({
    principal: "principal-a",
    session: "session-a",
    securityDomain: "domain-a",
  });
  let notifications = 0;
  store.subscribe("view", () => {
    notifications += 1;
  });

  const rollbackOlder = store.optimisticallySet("view", { state: "older" });
  const rollbackNewer = store.optimisticallySet("view", { state: "newer" });
  rollbackOlder();
  assert.deepEqual(store.getSnapshot("view").data, { state: "newer" });

  rollbackNewer();
  assert.equal(store.getSnapshot("view").status, "idle");
  assert.equal(store.getSnapshot("view").data, undefined);

  const afterFirstRollback = notifications;
  rollbackOlder();
  rollbackNewer();
  assert.equal(notifications, afterFirstRollback);
});

test("an older loader failure cannot erase newer optimistic success", async () => {
  const store = new QueryStore();
  store.setAuthorizationContext({
    principal: "principal-a",
    session: "session-a",
    securityDomain: "domain-a",
  });
  let rejectLoader;
  const pending = store.load(
    "view",
    () =>
      new Promise((_resolve, reject) => {
        rejectLoader = reject;
      }),
  );
  const rollback = store.optimisticallySet("view", { state: "newer-success" });
  rejectLoader(new Error("protected-older-failure"));

  await assert.rejects(pending, (error) => {
    assert.ok(error instanceof QueryPresentationError);
    assert.doesNotMatch(error.message, /protected-older-failure/u);
    return true;
  });
  assert.deepEqual(store.getSnapshot("view"), {
    status: "success",
    data: { state: "newer-success" },
    updatedAt: store.getSnapshot("view").updatedAt,
  });
  rollback();
  assert.equal(store.getSnapshot("view").status, "error");
  assert.ok(store.getSnapshot("view").error instanceof QueryPresentationError);
});

test("an older loader success becomes the fallback without replacing optimistic state", async () => {
  const store = new QueryStore();
  store.setAuthorizationContext({
    principal: "principal-a",
    session: "session-a",
    securityDomain: "domain-a",
  });
  let resolveLoader;
  const pending = store.load(
    "view",
    () =>
      new Promise((resolve) => {
        resolveLoader = resolve;
      }),
  );
  const rollback = store.optimisticallySet("view", { state: "optimistic" });
  resolveLoader({ state: "loaded-fallback" });
  await pending;
  assert.deepEqual(store.getSnapshot("view").data, { state: "optimistic" });

  rollback();
  assert.deepEqual(store.getSnapshot("view").data, { state: "loaded-fallback" });
});

test("a stale optimistic rollback cannot replace a newer loaded result", async () => {
  const store = new QueryStore();
  store.setAuthorizationContext({
    principal: "principal-a",
    session: "session-a",
    securityDomain: "domain-a",
  });
  const staleRollback = store.optimisticallySet("view", { state: "optimistic" });
  assert.deepEqual(
    await store.load("view", async () => ({ state: "loaded-success" })),
    { state: "loaded-success" },
  );
  staleRollback();
  assert.deepEqual(store.getSnapshot("view").data, { state: "loaded-success" });
});
