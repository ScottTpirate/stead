import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createPlatformClient,
  operationDefinitions,
  PlatformApiError,
  QueryStore,
} from "../../../packages/api-client/src/index.ts";
import {
  createContractMockFetch,
  nonDisclosingDenial,
} from "../../../packages/test-fixtures/frontend/src/index.ts";

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

test("query snapshots sanitize loader errors", async () => {
  const store = new QueryStore();
  store.setAuthorizationContext({
    principal: "principal-a",
    session: "session-a",
    securityDomain: "domain-a",
  });
  await assert.rejects(
    store.load("protected", async () => {
      throw new Error("protected title must not reach presentation");
    }),
  );
  const snapshot = store.getSnapshot("protected");
  assert.equal(snapshot.error?.message, "The request could not be completed.");
  assert.doesNotMatch(snapshot.error?.message ?? "", /protected title/u);
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
  await assert.rejects(pending, { name: "AbortError" });
  assert.equal(store.getSnapshot("protected").status, "idle");
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
