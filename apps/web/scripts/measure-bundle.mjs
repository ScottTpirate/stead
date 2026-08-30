import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";

const webRoot = resolve(import.meta.dirname, "..");
const distributionRoot = resolve(webRoot, "dist");
const manifest = JSON.parse(
  await readFile(resolve(distributionRoot, ".vite/manifest.json"), "utf8"),
);

const entries = Object.entries(manifest).filter(([, chunk]) => chunk.isEntry);
if (entries.length !== 1) {
  throw new Error(`expected one browser entry, found ${entries.length}`);
}

const eagerKeys = new Set();
function visitEager(key) {
  if (eagerKeys.has(key)) return;
  const chunk = manifest[key];
  if (!chunk) throw new Error(`manifest references missing chunk ${key}`);
  eagerKeys.add(key);
  for (const imported of chunk.imports ?? []) visitEager(imported);
}
visitEager(entries[0][0]);

async function gzipBytes(file) {
  const bytes = await readFile(resolve(distributionRoot, file));
  return gzipSync(bytes, { level: 9 }).byteLength;
}

let eagerBytes = 0;
const eagerFiles = [];
for (const key of [...eagerKeys].sort()) {
  const file = manifest[key].file;
  if (!file.endsWith(".js")) continue;
  const bytes = await gzipBytes(file);
  eagerBytes += bytes;
  eagerFiles.push({ file, gzip_bytes: bytes });
}

const requiredBoundaries = {
  docs_editor: "src/capabilities/docs-editor.ts",
  code: "src/capabilities/code.ts",
  delivery: "src/capabilities/delivery.ts",
  administration: "src/capabilities/administration.ts",
  migration: "src/capabilities/migration.ts",
  analytics: "src/capabilities/analytics.ts",
};
const lazyCapabilities = {};
for (const [name, source] of Object.entries(requiredBoundaries)) {
  const chunk = manifest[source];
  if (!chunk || eagerKeys.has(source) || !chunk.file.endsWith(".js")) {
    throw new Error(`${name} is not a separate lazy JavaScript chunk`);
  }
  const bytes = await gzipBytes(chunk.file);
  lazyCapabilities[name] = {
    source,
    file: chunk.file,
    baseline_bytes_gzip: 0,
    gzip_bytes: bytes,
    delta_bytes_gzip: bytes,
  };
}

const baseline = 60_808;
const budget = 250 * 1024;
const evidence = {
  schema_version: "1.0",
  issue: "P1-005-FE-FOUNDATION",
  contract: "PERF-005",
  generated_by: "apps/web/scripts/measure-bundle.mjs",
  measurement_method: "Node zlib level 9 over Vite manifest JavaScript graph",
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
