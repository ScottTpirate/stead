import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const webSource = new URL("../src/", import.meta.url);

async function source(name) {
  return readFile(new URL(name, webSource), "utf8");
}

test("primary navigation preserves the canonical order and omits blocked capabilities", async () => {
  const routes = await import("../src/routes.ts");
  assert.deepEqual(
    routes.primaryNavigation.map((route) => route.label),
    ["Home", "Inbox", "My Work", "Projects", "Knowledge", "Teams"],
  );
  const serialized = JSON.stringify(routes.primaryNavigation);
  assert.doesNotMatch(serialized, /Code|Delivery|Administration|Migration/u);
});

test("shell includes keyboard, screen-reader, and stable-state hooks", async () => {
  const [shell, command, primitives] = await Promise.all([
    source("AppShell.tsx"),
    source("CommandPalette.tsx"),
    readFile(
      new URL("../../../packages/design-system/src/primitives.tsx", import.meta.url),
      "utf8",
    ),
  ]);
  assert.match(shell, /Skip to content/u);
  assert.match(shell, /aria-current/u);
  assert.match(command, /aria-haspopup="dialog"/u);
  assert.match(command, /metaKey \|\| event\.ctrlKey/u);
  assert.match(primitives, /aria-busy/u);
  assert.match(primitives, /role="alert"/u);
  assert.match(primitives, /stead-visually-hidden/u);
});

test("every required capability remains behind a dynamic import", async () => {
  const lazySource = await source("capabilities/lazy.ts");
  for (const boundary of [
    "docs-editor",
    "code",
    "delivery",
    "administration",
    "migration",
    "analytics",
  ]) {
    assert.ok(lazySource.includes(`import("./${boundary}")`));
  }
});

test("browser source has no direct provider or infrastructure network path", async () => {
  const files = [
    "AppShell.tsx",
    "CommandPalette.tsx",
    "Foundation.tsx",
    "main.tsx",
    "platform.ts",
    "routes.ts",
    "useRoute.ts",
  ];
  const combined = (await Promise.all(files.map(source))).join("\n");
  assert.doesNotMatch(combined, /gitea|commonplace|openfga|nats|\/api\/v1\/repos/iu);
  assert.doesNotMatch(combined, /fetch\s*\(/u);
});

test("original shell does not introduce Devlane ontology", async () => {
  const files = [
    "AppShell.tsx",
    "CommandPalette.tsx",
    "Foundation.tsx",
    "routes.ts",
  ];
  const combined = (await Promise.all(files.map(source))).join("\n");
  assert.doesNotMatch(combined, /\bModules\b|\bEpics\b|\bPages\b|\bBoard\b|\bIntake\b|\bArchives\b|\bDrafts\b/u);
});

test("merged provenance still prohibits a Devlane distribution import", async () => {
  const provenance = await readFile(
    new URL("../../../docs/governance/devlane-provenance.yaml", import.meta.url),
    "utf8",
  );
  const approvals = await readFile(
    new URL("../../../docs/governance/dependency-approvals.yaml", import.meta.url),
    "utf8",
  );
  const sourceRecord = approvals.split("  - approval_id:")[1] ?? "";
  assert.match(provenance, /status: PINNED_SOURCE_NOT_IMPORTED/u);
  assert.match(provenance, /imported: false/u);
  assert.match(sourceRecord, /^ DEP-APP-DEVLANE-SOURCE-7719DCAD$/mu);
  assert.match(sourceRecord, /distributed_in: \[\]/u);
  assert.match(sourceRecord, /relationship: source-reference/u);
});

test("approved unit harness is exact while browser and accessibility engines remain absent", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );
  const lock = await readFile(new URL("../../../package-lock.json", import.meta.url), "utf8");
  const approvals = await readFile(
    new URL("../../../docs/governance/dependency-approvals.yaml", import.meta.url),
    "utf8",
  );
  const declared = {
    ...manifest.dependencies,
    ...manifest.devDependencies,
  };

  const approvedUnitHarness = {
    vitest: ["4.1.11", "DEP-APP-NPM-VITEST-4-1-11"],
    "@testing-library/react": [
      "16.3.3",
      "DEP-APP-NPM-TESTING-LIBRARY-REACT-16-3-3",
    ],
    "@testing-library/dom": ["10.4.1", "DEP-APP-NPM-TESTING-LIBRARY-DOM-10-4-1"],
    "@testing-library/user-event": [
      "14.6.6",
      "DEP-APP-NPM-TESTING-LIBRARY-USER-EVENT-14-6-6",
    ],
    "happy-dom": ["20.11.2", "DEP-APP-NPM-HAPPY-DOM-20-11-2"],
  };
  for (const [dependency, [version, approvalId]] of Object.entries(approvedUnitHarness)) {
    assert.equal(declared[dependency], version);
    assert.match(approvals, new RegExp(`approval_id: ${approvalId}\\n`, "u"));
  }

  for (const dependency of ["@playwright/test", "axe-core"]) {
    assert.equal(declared[dependency], undefined);
    assert.doesNotMatch(lock, new RegExp(`node_modules/${dependency.replace("/", "\\/")}`, "u"));
  }
});
