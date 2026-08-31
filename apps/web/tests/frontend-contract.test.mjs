import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  collectBrowserSourceGraph,
  findBrowserBoundaryViolations,
  undeclaredRuntimePackages,
} from "../scripts/browser-source-graph.mjs";
import {
  buildBundleMembership,
  REQUIRED_LAZY_BOUNDARIES,
} from "../scripts/measure-bundle.mjs";

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

test("lazy bundle graphs include transitive and shared chunks exactly once", () => {
  const manifest = {
    "index.html": {
      file: "assets/index.js",
      isEntry: true,
      imports: ["eager-shared"],
      dynamicImports: Object.values(REQUIRED_LAZY_BOUNDARIES),
    },
    "eager-shared": { file: "assets/eager.js" },
    "src/capabilities/docs-editor.ts": {
      file: "assets/docs.js",
      imports: ["lazy-shared"],
      dynamicImports: ["docs-transitive"],
    },
    "src/capabilities/code.ts": {
      file: "assets/code.js",
      imports: ["lazy-shared"],
    },
    "src/capabilities/delivery.ts": { file: "assets/delivery.js" },
    "src/capabilities/administration.ts": { file: "assets/admin.js" },
    "src/capabilities/migration.ts": { file: "assets/migration.js" },
    "src/capabilities/analytics.ts": { file: "assets/analytics.js" },
    "lazy-shared": { file: "assets/lazy-shared.js" },
    "docs-transitive": { file: "assets/docs-transitive.js" },
  };
  const membership = buildBundleMembership(manifest);

  assert.deepEqual(membership.eagerKeys, ["eager-shared", "index.html"]);
  assert.deepEqual(
    membership.dynamicFrontierKeys,
    Object.values(REQUIRED_LAZY_BOUNDARIES).sort(),
  );
  assert.deepEqual(membership.capabilityKeys.docs_editor, [
    "docs-transitive",
    "lazy-shared",
    "src/capabilities/docs-editor.ts",
  ]);
  assert.deepEqual(membership.capabilityKeys.code, [
    "lazy-shared",
    "src/capabilities/code.ts",
  ]);
  assert.deepEqual(membership.ownersByKey["lazy-shared"], ["code", "docs_editor"]);
  assert.equal(
    membership.lazyUniqueKeys.filter((key) => key === "lazy-shared").length,
    1,
  );

  assert.throws(
    () =>
      buildBundleMembership({
        ...manifest,
        orphan: { file: "assets/ungoverned.js" },
      }),
    /outside required capability graphs.*orphan/u,
  );

  const disconnectedManifest = structuredClone(manifest);
  disconnectedManifest["index.html"].dynamicImports = [];
  assert.throws(
    () => buildBundleMembership(disconnectedManifest),
    (error) => {
      assert.match(error.message, /dynamic frontier must be exactly.*missing:/u);
      for (const source of Object.values(REQUIRED_LAZY_BOUNDARIES)) {
        assert.ok(error.message.includes(source));
      }
      return true;
    },
  );

  assert.throws(
    () =>
      buildBundleMembership({
        ...manifest,
        "index.html": {
          ...manifest["index.html"],
          dynamicImports: [
            ...manifest["index.html"].dynamicImports,
            "unexpected-capability",
          ],
        },
        "unexpected-capability": { file: "assets/unexpected.js" },
      }),
    /dynamic frontier must be exactly.*unexpected: unexpected-capability/u,
  );
});

test("the complete browser module graph closes network, provider, ontology, and dependency boundaries", async () => {
  const repositoryRoot = resolve(new URL("../../..", import.meta.url).pathname);
  const manifest = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );
  const graph = await collectBrowserSourceGraph({
    entryPath: new URL("../src/main.tsx", import.meta.url).pathname,
    repositoryRoot,
  });
  const relativePaths = graph.modules.map((module) =>
    module.path.slice(repositoryRoot.length + 1),
  );

  assert.ok(relativePaths.includes("apps/web/src/capabilities/docs-editor.ts"));
  assert.ok(relativePaths.includes("packages/api-client/src/client.ts"));
  assert.ok(relativePaths.includes("packages/design-system/src/primitives.tsx"));
  assert.deepEqual(findBrowserBoundaryViolations(graph), []);
  assert.deepEqual(undeclaredRuntimePackages(graph, manifest), []);
});

test("a newly imported forbidden network module cannot escape the graph gate", async () => {
  const fixtureParent =
    process.env.STEAD_TEST_TMPDIR ?? join(homedir(), ".cache", "stead-test-tmp");
  await mkdir(fixtureParent, { recursive: true });
  const fixtureRoot = await mkdtemp(join(fixtureParent, "stead-browser-graph-"));
  try {
    await writeFile(
      join(fixtureRoot, "entry.ts"),
      'import "./new-module";\nexport const entry = true;\n',
      "utf8",
    );
    await writeFile(
      join(fixtureRoot, "new-module.ts"),
      'export const bypass = () => fetch("https://gitea.invalid/api/v1/repos");\n',
      "utf8",
    );
    const graph = await collectBrowserSourceGraph({
      entryPath: join(fixtureRoot, "entry.ts"),
      repositoryRoot: fixtureRoot,
    });
    assert.deepEqual(
      findBrowserBoundaryViolations(graph).map(({ rule }) => rule),
      ["direct-browser-network", "provider-or-infrastructure"],
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("browser source paths reject symlinks, realpath escapes, and special components", async () => {
  const fixtureParent =
    process.env.STEAD_TEST_TMPDIR ?? join(homedir(), ".cache", "stead-test-tmp");
  await mkdir(fixtureParent, { recursive: true });
  const fixtureRoot = await mkdtemp(join(fixtureParent, "stead-browser-root-"));
  const outsideRoot = await mkdtemp(join(fixtureParent, "stead-browser-outside-"));
  const linkedRoot = `${fixtureRoot}-linked-root`;
  const linkedComponent = join(fixtureRoot, "linked");
  try {
    await writeFile(
      join(fixtureRoot, "entry.ts"),
      'import "./linked/outside";\nexport const entry = true;\n',
      "utf8",
    );
    await writeFile(
      join(outsideRoot, "outside.ts"),
      "export const escaped = true;\n",
      "utf8",
    );
    await symlink(outsideRoot, linkedComponent, "dir");
    await assert.rejects(
      collectBrowserSourceGraph({
        entryPath: join(fixtureRoot, "entry.ts"),
        repositoryRoot: fixtureRoot,
      }),
      /browser module path contains a symbolic link/u,
    );

    await rm(linkedComponent, { force: true });
    await writeFile(linkedComponent, "not a directory\n", "utf8");
    await assert.rejects(
      collectBrowserSourceGraph({
        entryPath: join(fixtureRoot, "entry.ts"),
        repositoryRoot: fixtureRoot,
      }),
      /browser module path contains a non-directory component/u,
    );

    await symlink(fixtureRoot, linkedRoot, "dir");
    await assert.rejects(
      collectBrowserSourceGraph({
        entryPath: join(linkedRoot, "entry.ts"),
        repositoryRoot: linkedRoot,
      }),
      /browser repository root is not a real directory/u,
    );
  } finally {
    await rm(linkedRoot, { force: true });
    await rm(fixtureRoot, { recursive: true, force: true });
    await rm(outsideRoot, { recursive: true, force: true });
  }
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
