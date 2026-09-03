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
  for (const route of routes.primaryNavigation) {
    assert.equal(routes.internalNavigationHref(route.href), route.href);
  }
  for (const destination of [
    "//outside.invalid",
    "https://outside.invalid",
    "/projects?redirect=//outside.invalid",
    "#main-content",
  ]) {
    assert.throws(
      () => routes.internalNavigationHref(destination),
      /outside the canonical primary routes/u,
    );
  }
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
        orphan: { file: "assets/ungoverned.json" },
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

test("the application browser graph closes owned boundaries and enumerates external packages", async () => {
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
  assert.deepEqual(graph.externalPackages, ["react", "react-dom"]);
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

test("computed and runtime-composed browser boundaries cannot evade the graph gate", async () => {
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
        "const reflectedRequest = Reflect.get(globalThis, networkName);",
        'const protocol = "https:";',
        "const providerName = String.fromCodePoint(103, 105, 116, 101, 97);",
        'const provider = protocol + "//" + providerName + ".invalid/api/v1/repos";',
        "const forbiddenNoun = String.fromCharCode(77, 111, 100, 117, 108, 101, 115);",
        "export const opaque = (codes: number[]) => String.fromCharCode(...codes);",
        "export const bypass = () => reflectedRequest(provider + forbiddenNoun) ?? request(provider);",
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
        "dynamic-boundary-construction",
        "provider-or-infrastructure",
      ],
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("aliased call-through and encoded JSX resource sinks fail independently", async () => {
  const fixtureParent =
    process.env.STEAD_TEST_TMPDIR ?? join(homedir(), ".cache", "stead-test-tmp");
  await mkdir(fixtureParent, { recursive: true });
  const fixtureRoot = await mkdtemp(join(fixtureParent, "stead-call-through-"));
  const cases = [
    'const reflectedGet = Reflect.get; reflectedGet(globalThis, "fetch");\n',
    'Location.prototype.replace.call(location, "/outside");\n',
    'Element.prototype.setAttribute.call(document.body, "src", "/outside");\n',
    'export const Link = () => <a href="&#104;ttps://outside.invalid">go</a>;\n',
  ];
  try {
    for (const fixture of cases) {
      await writeFile(join(fixtureRoot, "entry.tsx"), fixture, "utf8");
      const graph = await collectBrowserSourceGraph({
        entryPath: join(fixtureRoot, "entry.tsx"),
        repositoryRoot: fixtureRoot,
      });
      assert.deepEqual(
        findBrowserBoundaryViolations(graph).map(({ rule }) => rule),
        ["direct-browser-network"],
        fixture,
      );
    }
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("navigation, resource-loading, and external-destination sinks fail closed", async () => {
  const fixtureParent =
    process.env.STEAD_TEST_TMPDIR ?? join(homedir(), ".cache", "stead-test-tmp");
  await mkdir(fixtureParent, { recursive: true });
  const fixtureRoot = await mkdtemp(join(fixtureParent, "stead-resource-sinks-"));
  try {
    await writeFile(
      join(fixtureRoot, "entry.tsx"),
      [
        'const destination = "//outside.invalid/resource";',
        'const image = document.createElement("img");',
        'image["src"] = destination;',
        'location.assign("/unapproved-navigation");',
        "window.open(destination);",
        "export const Link = ({ href }: { href: string }) => <a href={href}>go</a>;",
        "export const Spread = ({ properties }: { properties: object }) => <a {...properties}>go</a>;",
        "export const Resource = () => <img src={destination} />;",
      ].join("\n"),
      "utf8",
    );
    const graph = await collectBrowserSourceGraph({
      entryPath: join(fixtureRoot, "entry.tsx"),
      repositoryRoot: fixtureRoot,
    });
    assert.deepEqual(
      findBrowserBoundaryViolations(graph).map(({ rule }) => rule),
      ["direct-browser-network"],
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
      /external HTML destination|external or modified HTML resource URL/u,
    );

    await writeFile(
      join(fixtureRoot, "index.html"),
      '<script type="module" src="&#x2f;&#x2f;outside.invalid/app.js"></script>\n',
    );
    await assert.rejects(
      collectBrowserSourceGraph({
        entryPath: join(fixtureRoot, "index.html"),
        repositoryRoot: fixtureRoot,
      }),
      /HTML character references are not governed browser content/u,
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

test("every built artifact is manifest-bound, content-scanned, and symlink-safe", async () => {
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
    assert.deepEqual(
      result.javascriptCapabilities.find(({ file }) => file === "assets/index.js"),
      {
        file: "assets/index.js",
        dynamicNetworkCalls: 0,
        dynamicResourceTargets: 0,
        externalDestinations: [],
        indirectNetworkAccesses: 0,
        indirectResourceAccesses: 0,
        networkCalls: 0,
        resourceMethodCalls: 0,
        staticNetworkTargets: [],
        staticResourceTargets: [],
        unsafeExternalDestinations: [],
        unsafeIndirectNetworkAccesses: 0,
        unsafeIndirectResourceAccesses: 0,
        unsafeStaticNetworkTargets: [],
        unsafeStaticResourceTargets: [],
      },
    );

    await writeFile(join(fixtureRoot, "assets/ungoverned.mjs"), "export {};\n");
    await assert.rejects(
      validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
      /distribution files are outside.*ungoverned\.mjs/u,
    );
    await rm(join(fixtureRoot, "assets/ungoverned.mjs"));

    await writeFile(
      join(fixtureRoot, "assets/provider-config.json"),
      '{"endpoint":"//outside.invalid/api"}\n',
    );
    await assert.rejects(
      validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
      /distribution files are outside.*provider-config\.json/u,
    );
    await rm(join(fixtureRoot, "assets/provider-config.json"));

    manifest["index.html"].assets = ["assets/runtime-config.json"];
    await writeFile(
      join(fixtureRoot, "assets/runtime-config.json"),
      '{"theme":"system"}\n',
    );
    await writeFile(
      join(fixtureRoot, ".vite/manifest.json"),
      `${JSON.stringify(manifest)}\n`,
    );
    const boundResult = await validateDistributionArtifacts({
      distributionRoot: fixtureRoot,
      manifest,
    });
    assert.ok(
      boundResult.artifacts.some(
        ({ file, sha256 }) =>
          file === "assets/runtime-config.json" && /^[a-f0-9]{64}$/u.test(sha256),
      ),
    );

    for (const [limits, expected] of [
      [{ maxAggregateBytes: 1 }, /aggregate-byte ceiling/u],
      [{ maxDepth: 1 }, /directory-depth ceiling/u],
      [{ maxEntries: 1 }, /entry-count ceiling/u],
      [{ maxFileBytes: 1 }, /file-size ceiling/u],
    ]) {
      await assert.rejects(
        validateDistributionArtifacts({
          distributionRoot: fixtureRoot,
          manifest,
          limits,
        }),
        expected,
      );
    }

    await writeFile(
      join(fixtureRoot, "assets/runtime-config.json"),
      '{"endpoint":"https://gitea.invalid/api/v1/repos"}\n',
    );
    await assert.rejects(
      validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
      /browser artifact violates boundary rules.*runtime-config\.json/u,
    );
    await writeFile(
      join(fixtureRoot, "assets/runtime-config.json"),
      '{"theme":"system"}\n',
    );

    await writeFile(
      join(fixtureRoot, "assets/index.css"),
      ":root { background-image: url(//outside.invalid/pixel); }\n",
    );
    await assert.rejects(
      validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
      /unsupported CSS asset URL outside @import/u,
    );
    await writeFile(join(fixtureRoot, "assets/index.css"), ":root {}\n");

    for (const [file, contents] of [
      ["assets/runtime.wasm", new Uint8Array([0, 97, 115, 109])],
      ["assets/index.js.map", '{"version":3,"sources":[]}\n'],
    ]) {
      manifest["index.html"].assets.push(file);
      await writeFile(join(fixtureRoot, file), contents);
      await writeFile(
        join(fixtureRoot, ".vite/manifest.json"),
        `${JSON.stringify(manifest)}\n`,
      );
      await assert.rejects(
        validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
        new RegExp(`browser artifact type is not governed: ${file.replace(".", "\\.")}$`, "u"),
      );
      manifest["index.html"].assets.pop();
      await rm(join(fixtureRoot, file));
    }
    await writeFile(
      join(fixtureRoot, ".vite/manifest.json"),
      `${JSON.stringify(manifest)}\n`,
    );

    await writeFile(
      join(fixtureRoot, "assets/code.js"),
      "export {};\n//# sourceMappingURL=code.js.map\n",
    );
    await assert.rejects(
      validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
      /JavaScript source-map loading is not governed.*code\.js/u,
    );
    await writeFile(join(fixtureRoot, "assets/code.js"), "export {};\n");

    for (const source of [
      'fetch("https://gitea.invalid/api/v1/repos");\n',
      'fetch("/unapproved-data-route");\n',
      'const image = {}; image.src = "https://outside.invalid/pixel";\n',
      'document.createElement("img").setAttribute("src", "//outside.invalid/pixel");\n',
      'const request = Reflect.get(globalThis, "fetch"); request("/api/v1");\n',
      'Reflect.apply(fetch, globalThis, ["/api/v1"]);\n',
      'fetch.call(globalThis, "/api/v1");\n',
      'Location.prototype.replace.call(location, "/api/v1");\n',
      'Element.prototype.setAttribute.call(document.body, "src", "/api/v1");\n',
    ]) {
      await writeFile(join(fixtureRoot, "assets/index.js"), source);
      await assert.rejects(
        validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
        /browser artifact violates boundary rules.*index\.js/u,
      );
    }
    await writeFile(
      join(fixtureRoot, "assets/index.js"),
      "const route = globalThis.location.pathname; fetch(route); fetch(route);\n",
    );
    await assert.rejects(
      validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest }),
      /network call sites; maximum is 1/u,
    );
    await writeFile(
      join(fixtureRoot, "assets/index.js"),
      'const diagnostic = { data: " at new " }; void diagnostic;\n',
    );
    await validateDistributionArtifacts({ distributionRoot: fixtureRoot, manifest });
    await writeFile(join(fixtureRoot, "assets/index.js"), "export {};\n");

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

    await writeFile(
      join(globRoot, "entry.ts"),
      'export const modules = import.meta["glob"]("./hidden/*.ts");\n',
      "utf8",
    );
    await assert.rejects(
      collectBrowserSourceGraph({
        entryPath: join(globRoot, "entry.ts"),
        repositoryRoot: globRoot,
      }),
      /Vite import\.meta APIs are not governed browser edges/u,
    );

    await writeFile(
      join(globRoot, "entry.ts"),
      'import "./runtime-config.json";\n',
      "utf8",
    );
    await writeFile(
      join(globRoot, "runtime-config.json"),
      '{"providerParts":["gi","tea"]}\n',
      "utf8",
    );
    await assert.rejects(
      collectBrowserSourceGraph({
        entryPath: join(globRoot, "entry.ts"),
        repositoryRoot: globRoot,
      }),
      /browser module type is not governed.*runtime-config\.json/u,
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

test("browser source graph enforces independently tighten-able resource ceilings", async () => {
  const fixtureParent =
    process.env.STEAD_TEST_TMPDIR ?? join(homedir(), ".cache", "stead-test-tmp");
  await mkdir(fixtureParent, { recursive: true });
  const fixtureRoot = await mkdtemp(join(fixtureParent, "stead-browser-limits-"));
  const collect = (directory, limits) =>
    collectBrowserSourceGraph({
      entryPath: join(fixtureRoot, directory, "entry.ts"),
      repositoryRoot: join(fixtureRoot, directory),
      limits,
    });
  try {
    await mkdir(join(fixtureRoot, "file"));
    await writeFile(
      join(fixtureRoot, "file/entry.ts"),
      `export const value = "${"x".repeat(64)}";\n`,
    );
    await assert.rejects(
      collect("file", { maxFileBytes: 32 }),
      /file-size ceiling/u,
    );

    await mkdir(join(fixtureRoot, "aggregate"));
    await writeFile(
      join(fixtureRoot, "aggregate/entry.ts"),
      'import "./dependency";\nexport const entry = true;\n',
    );
    await writeFile(
      join(fixtureRoot, "aggregate/dependency.ts"),
      "export const dependency = true;\n",
    );
    await assert.rejects(
      collect("aggregate", { maxAggregateBytes: 64 }),
      /aggregate-byte ceiling/u,
    );

    await mkdir(join(fixtureRoot, "depth"));
    await writeFile(join(fixtureRoot, "depth/entry.ts"), 'import "./a";\n');
    await writeFile(join(fixtureRoot, "depth/a.ts"), 'import "./b";\n');
    await writeFile(join(fixtureRoot, "depth/b.ts"), "export {};\n");
    await assert.rejects(
      collect("depth", { maxDepth: 1 }),
      /depth ceiling/u,
    );

    await mkdir(join(fixtureRoot, "imports"));
    await writeFile(
      join(fixtureRoot, "imports/entry.ts"),
      'import "./dependency";\nimport "./dependency";\n',
    );
    await writeFile(join(fixtureRoot, "imports/dependency.ts"), "export {};\n");
    await assert.rejects(
      collect("imports", { maxImportsPerModule: 1 }),
      /import-count ceiling/u,
    );

    await mkdir(join(fixtureRoot, "modules"));
    await writeFile(
      join(fixtureRoot, "modules/entry.ts"),
      'import "./a";\nimport "./b";\n',
    );
    await writeFile(join(fixtureRoot, "modules/a.ts"), "export {};\n");
    await writeFile(join(fixtureRoot, "modules/b.ts"), "export {};\n");
    await assert.rejects(
      collect("modules", { maxModules: 2 }),
      /module-count ceiling/u,
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
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
