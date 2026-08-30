import { gzipSync } from "node:zlib";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const manifestPath = resolve("apps/web/dist/.vite/manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const entries = Object.entries(manifest).filter(([, chunk]) => chunk.isEntry);

if (entries.length !== 1) {
  throw new Error(`expected exactly one stead-web entry chunk, found ${entries.length}`);
}

const eagerKeys = new Set();
const visit = (key) => {
  if (eagerKeys.has(key)) return;
  const chunk = manifest[key];
  if (!chunk) throw new Error(`manifest references missing eager chunk ${key}`);
  eagerKeys.add(key);
  for (const imported of chunk.imports ?? []) visit(imported);
};

visit(entries[0][0]);

let gzipBytes = 0;
const measuredFiles = [];
for (const key of [...eagerKeys].sort()) {
  const file = manifest[key].file;
  if (!file.endsWith(".js")) continue;
  const bytes = await readFile(resolve("apps/web/dist", file));
  const compressed = gzipSync(bytes, { level: 9 }).byteLength;
  gzipBytes += compressed;
  measuredFiles.push({ file, gzip_bytes: compressed });
}

const budgetBytes = 250 * 1024;
const evidence = {
  contract: "PERF-005",
  budget_bytes_gzip: budgetBytes,
  eager_javascript_bytes_gzip: gzipBytes,
  lazy_capability_chunks_excluded: true,
  measured_files: measuredFiles,
};

process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
if (gzipBytes > budgetBytes) {
  throw new Error(
    `stead-web eager JavaScript is ${gzipBytes} bytes gzip, over the ${budgetBytes}-byte budget`,
  );
}
