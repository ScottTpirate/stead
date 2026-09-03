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
  validateDistributionArtifacts,
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
        orphan: { file: "assets/ungoverned.mjs" },
      }),
    /outside required capability graphs.*orphan/u,
  );

  assert.throws(
    () =>
      buildBundleMembership({
        ...manifest,
        escaped: { file: "../ungoverned.cjs" },
      }),
    /escapes or aliases the distribution root/u,
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
    entryPath: new URL("../index.html", import.meta.url).pathname,
    repositoryRoot,
  });
  const configGraph = await collectBrowserSourceGraph({
    entryPath: new URL("../vite.config.ts", import.meta.url).pathname,
    repositoryRoot,
  });
  const relativePaths = graph.modules.map((module) =>
    module.path.slice(repositoryRoot.length + 1),
  );

  assert.ok(relativePaths.includes("apps/web/index.html"));
  assert.ok(relativePaths.includes("apps/web/src/main.tsx"));
  assert.ok(relativePaths.includes("apps/web/src/styles.css"));
  assert.ok(relativePaths.includes("apps/web/src/capabilities/docs-editor.ts"));
  assert.ok(relativePaths.includes("packages/api-client/src/client.ts"));
  assert.ok(relativePaths.includes("packages/design-system/src/primitives.tsx"));
  assert.deepEqual(findBrowserBoundaryViolations(graph), []);
  assert.deepEqual(findBrowserBoundaryViolations(configGraph), []);
  assert.deepEqual(undeclaredRuntimePackages(graph, manifest), []);
  assert.deepEqual(
    undeclaredRuntimePackages(configGraph, manifest, {
      includeDevDependencies: true,
    }),
    [],
  );
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

test("statically composed network, provider, and source-ontology tokens cannot evade the graph gate", async () => {
  const fixtureParent =
    process.env.STEAD_TEST_TMPDIR ?? join(homedir(), ".cache", "stead-test-tmp");
  await mkdir(fixtureParent, { recursive: true });
  const fixtureRoot = await mkdtemp(join(fixtureParent, "stead-static-evasion-"));
  try {
    await writeFile(
      join(fixtureRoot, "entry.ts"),
      [
        'const networkName = "fe" + "tch";',
        "const request = globalThis[networkName];",
        'const protocol = "https:";',
        'const providerName = ["gi", "tea"].join("");',
        'const provider = protocol + "//" + providerName + ".invalid/api/v1/repos";',
        'const nounSuffix = "ules";',
        'const forbiddenNoun = "Mod" + nounSuffix;',
        "export const bypass = () => request(provider + forbiddenNoun);",
      ].join("\n"),
      "utf8",
    );
    const graph = await collectBrowserSourceGraph({
      entryPath: join(fixtureRoot, "entry.ts"),
      repositoryRoot: fixtureRoot,
    });
    assert.deepEqual(
      findBrowserBoundaryViolations(graph).map(({ rule }) => rule),
      [
        "devlane-ontology",
        "direct-browser-network",
        "provider-or-infrastructure",
      ],
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("HTML-loaded scripts and styles are governed while external or inline execution fails closed", async () => {
  const fixtureParent =
    process.env.STEAD_TEST_TMPDIR ?? join(homedir(), ".cache", "stead-test-tmp");
  await mkdir(fixtureParent, { recursive: true });
  const fixtureRoot = await mkdtemp(join(fixtureParent, "stead-html-graph-"));
  try {
    await mkdir(join(fixtureRoot, "src"));
    await writeFile(
      join(fixtureRoot, "index.html"),
      [
        '<!doctype html><html><head><link rel="stylesheet" href="/src/app.css" /></head>',
        '<body><script type="module" src="/src/app.ts"></script></body></html>',
      ].join(""),
      "utf8",
    );
    await writeFile(join(fixtureRoot, "src/app.css"), ":root { color: black; }\n");
    await writeFile(join(fixtureRoot, "src/app.ts"), "export const app = true;\n");
    const graph = await collectBrowserSourceGraph({
      entryPath: join(fixtureRoot, "index.html"),
      repositoryRoot: fixtureRoot,
    });
    assert.deepEqual(
      graph.modules.map(({ path }) => path.slice(fixtureRoot.length + 1)),
      ["index.html", "src/app.css", "src/app.ts"],
    );

    await writeFile(
      join(fixtureRoot, "index.html"),
      '<script type="module" src="https://gitea.invalid/app.js"></script>\n',
    );
    await assert.rejects(
      collectBrowserSourceGraph({
        entryPath: join(fixtureRoot, "index.html"),
        repositoryRoot: fixtureRoot,
      }),
      /external or modified HTML resource URL/u,
    );

    await writeFile(
      join(fixtureRoot, "index.html"),
      '<script type="module" src="/src/app.ts">globalThis.fetch("/api")</script>\n',
    );
    await assert.rejects(
      collectBrowserSourceGraph({
        entryPath: join(fixtureRoot, "index.html"),
        repositoryRoot: fixtureRoot,
      }),
      /inline HTML script/u,
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("built artifact inventory rejects orphan executable files, unknown HTML edges, and symlinks", async () => {
  const fixtureParent =
    process.env.STEAD_TEST_TMPDIR ?? join(homedir(), ".cache", "stead-test-tmp");
  await mkdir(fixtureParent, { recursive: true });
  const fixtureRoot = await mkdtemp(join(fixtureParent, "stead-distribution-"));
  const manifest = {
    "index.html": {
      file: "assets/index.js",
      isEntry: true,
      css: ["assets/index.css"],
      dynamicImports: Object.values(REQUIRED_LAZY_BOUNDARIES),
    },
    "src/capabilities/docs-editor.ts": { file: "assets/docs.js" },
    "src/capabilities/code.ts": { file: "assets/code.js" },
    "src/capabilities/delivery.ts": { file: "assets/delivery.js" },
    "src/capabilities/administration.ts": { file: "assets/admin.js" },
    "src/capabilities/migration.ts": { file: "assets/migration.js" },
    "src/capabilities/analytics.ts": { file: "assets/analytics.js" },
  };
  try {
    await mkdir(join(fixtureRoot, "assets"));
    await mkdir(join(fixtureRoot, ".vite"));
    for (const chunk of Object.values(manifest)) {
      await writeFile(join(fixtureRoot, chunk.file), "export {};\n");
    }
    await writeFile(join(fixtureRoot, "assets/index.css"), ":root {}\n");
    await writeFile(
      join(fixtureRoot, ".vite/manifest.json"),
      `${JSON.stringify(manifest)}\n`,
    );
    await writeFile(
      join(fixtureRoot, "index.html"),
      [
        '<link rel="stylesheet" href="/assets/index.css" />',
        '<script type="module" src="/assets/index.js"></script>',
      ].join("\n"),
    );

    const result = await validateDistributionArtifacts({
      distributionRoot: fixtureRoot,
      manifest,
    });
    assert.ok(result.files.includes("assets/index.js"));

    await writeFile(join(fixtureRoot, "assets/ungoverned.mjs"), "export {};\n");
    await assert.rejects(
      validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
      /executable files are outside the Vite manifest.*ungoverned\.mjs/u,
    );
    await rm(join(fixtureRoot, "assets/ungoverned.mjs"));

    await writeFile(
      join(fixtureRoot, "unreviewed.html"),
      '<script type="module" src="/assets/index.js"></script>\n',
    );
    await assert.rejects(
      validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
      /HTML entry set must be exactly index\.html.*unreviewed\.html/u,
    );
    await rm(join(fixtureRoot, "unreviewed.html"));

    await writeFile(
      join(fixtureRoot, "index.html"),
      '<script type="module" src="/assets/unknown.js"></script>\n',
    );
    await assert.rejects(
      validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
      /HTML references an absent distribution file/u,
    );

    await writeFile(
      join(fixtureRoot, "index.html"),
      '<script type="module" src="/assets/index.js"></script>\n',
    );
    await rm(join(fixtureRoot, "assets/code.js"));
    await symlink("delivery.js", join(fixtureRoot, "assets/code.js"));
    await assert.rejects(
      validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
      /distribution path contains a symbolic link.*code\.js/u,
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("Vite glob and CSS asset edges cannot bypass the browser graph", async () => {
  const fixtureParent =
    process.env.STEAD_TEST_TMPDIR ?? join(homedir(), ".cache", "stead-test-tmp");
  await mkdir(fixtureParent, { recursive: true });
  const globRoot = await mkdtemp(join(fixtureParent, "stead-browser-glob-"));
  const cssRoot = await mkdtemp(join(fixtureParent, "stead-browser-css-"));
  try {
    await writeFile(
      join(globRoot, "entry.ts"),
      'export const modules = import.meta.glob("./hidden/*.ts");\n',
      "utf8",
    );
    await assert.rejects(
      collectBrowserSourceGraph({
        entryPath: join(globRoot, "entry.ts"),
        repositoryRoot: globRoot,
      }),
      /Vite import\.meta\.glob is not a governed browser edge/u,
    );

    await writeFile(cssRoot + "/entry.ts", 'import "./styles.css";\n', "utf8");
    await writeFile(cssRoot + "/styles.css", "@IMPORT url(./hidden.css);\n", "utf8");
    await writeFile(
      cssRoot + "/hidden.css",
      ":root { --unapproved-provider: gitea; }\n",
      "utf8",
    );
    const graph = await collectBrowserSourceGraph({
      entryPath: join(cssRoot, "entry.ts"),
      repositoryRoot: cssRoot,
    });
    assert.deepEqual(
      findBrowserBoundaryViolations(graph).map(({ rule }) => rule),
      ["provider-or-infrastructure"],
    );

    await writeFile(
      cssRoot + "/styles.css",
      "body { background-image: url(./untracked.svg); }\n",
      "utf8",
    );
    await assert.rejects(
      collectBrowserSourceGraph({
        entryPath: join(cssRoot, "entry.ts"),
        repositoryRoot: cssRoot,
      }),
      /unsupported CSS asset URL outside @import/u,
    );
  } finally {
    await rm(globRoot, { recursive: true, force: true });
    await rm(cssRoot, { recursive: true, force: true });
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
