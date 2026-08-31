import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

export const REQUIRED_LAZY_BOUNDARIES = {
  docs_editor: "src/capabilities/docs-editor.ts",
  code: "src/capabilities/code.ts",
  delivery: "src/capabilities/delivery.ts",
  administration: "src/capabilities/administration.ts",
  migration: "src/capabilities/migration.ts",
  analytics: "src/capabilities/analytics.ts",
};

function visitGraph(manifest, root, edges, visited = new Set()) {
  if (visited.has(root)) return visited;
  const chunk = manifest[root];
  if (!chunk) throw new Error(`manifest references missing chunk ${root}`);
  visited.add(root);
  for (const edge of edges) {
    for (const imported of chunk[edge] ?? []) {
      visitGraph(manifest, imported, edges, visited);
    }
  }
  return visited;
}

export function buildBundleMembership(
  manifest,
  requiredBoundaries = REQUIRED_LAZY_BOUNDARIES,
) {
  const entries = Object.entries(manifest).filter(([, chunk]) => chunk.isEntry);
  if (entries.length !== 1) {
    throw new Error(`expected one browser entry, found ${entries.length}`);
  }
  const entryKey = entries[0][0];
  const eagerKeys = visitGraph(manifest, entryKey, ["imports"]);
  const capabilityKeys = {};
  const ownersByKey = new Map();

  for (const [name, source] of Object.entries(requiredBoundaries)) {
    const boundary = manifest[source];
    if (!boundary || eagerKeys.has(source) || !boundary.file?.endsWith(".js")) {
      throw new Error(`${name} is not a separate lazy JavaScript chunk`);
    }
    const keys = visitGraph(manifest, source, ["imports", "dynamicImports"]);
    const lazyKeys = [...keys]
      .filter((key) => !eagerKeys.has(key) && manifest[key].file?.endsWith(".js"))
      .sort();
    capabilityKeys[name] = lazyKeys;
    for (const key of lazyKeys) {
      const owners = ownersByKey.get(key) ?? [];
      owners.push(name);
      ownersByKey.set(key, owners);
    }
  }

  const ungovernedLazyKeys = Object.keys(manifest)
    .filter(
      (key) =>
        manifest[key].file?.endsWith(".js") &&
        !eagerKeys.has(key) &&
        !ownersByKey.has(key),
    )
    .sort();
  if (ungovernedLazyKeys.length > 0) {
    throw new Error(
      `lazy JavaScript is outside required capability graphs: ${ungovernedLazyKeys.join(", ")}`,
    );
  }

  return {
    entryKey,
    eagerKeys: [...eagerKeys].sort(),
    capabilityKeys,
    lazyUniqueKeys: [...ownersByKey.keys()].sort(),
    ownersByKey: Object.fromEntries(
      [...ownersByKey.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, owners]) => [key, [...owners].sort()]),
    ),
  };
}

async function measureFile(distributionRoot, source, file) {
  const bytes = await readFile(resolve(distributionRoot, file));
  return {
    source,
    file,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    gzip_bytes: gzipSync(bytes, { level: 9 }).byteLength,
  };
}

async function main() {
  const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const distributionRoot = resolve(webRoot, "dist");
  const manifest = JSON.parse(
    await readFile(resolve(distributionRoot, ".vite/manifest.json"), "utf8"),
  );
  const membership = buildBundleMembership(manifest);
  const measurements = new Map();
  for (const key of [...new Set([...membership.eagerKeys, ...membership.lazyUniqueKeys])]) {
    const file = manifest[key].file;
    if (!file.endsWith(".js")) continue;
    measurements.set(key, await measureFile(distributionRoot, key, file));
  }

  const eagerFiles = membership.eagerKeys
    .filter((key) => measurements.has(key))
    .map((key) => measurements.get(key));
  const eagerBytes = eagerFiles.reduce((total, file) => total + file.gzip_bytes, 0);
  const lazyCapabilities = {};
  for (const [name, source] of Object.entries(REQUIRED_LAZY_BOUNDARIES)) {
    const files = membership.capabilityKeys[name].map((key) => measurements.get(key));
    const gzipBytes = files.reduce((total, file) => total + file.gzip_bytes, 0);
    lazyCapabilities[name] = {
      source,
      baseline_bytes_gzip: 0,
      gzip_bytes: gzipBytes,
      delta_bytes_gzip: gzipBytes,
      files,
    };
  }
  const lazyUniqueFiles = membership.lazyUniqueKeys.map((key) => ({
    ...measurements.get(key),
    capabilities: membership.ownersByKey[key],
    attributed_to: membership.ownersByKey[key][0],
  }));
  const lazyUniqueBytes = lazyUniqueFiles.reduce(
    (total, file) => total + file.gzip_bytes,
    0,
  );

  const baseline = 60_808;
  const budget = 250 * 1024;
  const evidence = {
    schema_version: "1.0",
    issue: "P1-005-FE-FOUNDATION",
    contract: "PERF-005",
    generated_by: "apps/web/scripts/measure-bundle.mjs",
    measurement_method:
      "Node zlib level 9 over closed Vite manifest JavaScript graphs with SHA-256 digests and stable shared-chunk attribution",
    scope: "Wave 0 original non-import foundation",
    mature_interface_perf005_complete: false,
    lazy_boundaries_are_placeholders: true,
    minimal_foundation_baseline_bytes_gzip: baseline,
    budget_bytes_gzip: budget,
    eager_javascript: {
      gzip_bytes: eagerBytes,
      delta_bytes_gzip: eagerBytes - baseline,
      files: eagerFiles,
    },
    lazy_capabilities: lazyCapabilities,
    lazy_unique_javascript: {
      gzip_bytes: lazyUniqueBytes,
      files: lazyUniqueFiles,
    },
  };

  const evidencePath = resolve(webRoot, "evidence/frontend-foundation-bundle.json");
  const renderedEvidence = `${JSON.stringify(evidence, null, 2)}\n`;
  if (process.argv.includes("--check")) {
    const recordedEvidence = await readFile(evidencePath, "utf8");
    if (recordedEvidence !== renderedEvidence) {
      throw new Error(
        "frontend bundle evidence is stale; run npm run measure:bundle --workspace=@stead/web",
      );
    }
  } else {
    await mkdir(resolve(webRoot, "evidence"), { recursive: true });
    await writeFile(evidencePath, renderedEvidence, "utf8");
  }
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
  if (eagerBytes > budget) {
    throw new Error(`eager JavaScript is ${eagerBytes} bytes gzip, over ${budget}`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
