import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  writeFile,
} from "node:fs/promises";
import { dirname, extname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

import { parseGovernedHtmlEdges } from "./browser-source-graph.mjs";

export const REQUIRED_LAZY_BOUNDARIES = {
  docs_editor: "src/capabilities/docs-editor.ts",
  code: "src/capabilities/code.ts",
  delivery: "src/capabilities/delivery.ts",
  administration: "src/capabilities/administration.ts",
  migration: "src/capabilities/migration.ts",
  analytics: "src/capabilities/analytics.ts",
};

const EXECUTABLE_JAVASCRIPT = /\.(?:c|m)?js$/iu;

function isExecutableJavaScript(file) {
  return typeof file === "string" && EXECUTABLE_JAVASCRIPT.test(file);
}

function governedDistributionPath(file, label = "distribution file") {
  if (
    typeof file !== "string" ||
    file.length === 0 ||
    file !== file.trim() ||
    file.includes("\\") ||
    file.includes("%") ||
    file.includes("?") ||
    file.includes("#") ||
    file.startsWith("/") ||
    /^(?:[A-Za-z][A-Za-z0-9+.-]*:|\/\/)/u.test(file)
  ) {
    throw new Error(`${label} is not a canonical relative path: ${String(file)}`);
  }
  const components = file.split("/");
  if (components.some((component) => component === "" || component === "." || component === "..")) {
    throw new Error(`${label} escapes or aliases the distribution root: ${file}`);
  }
  return file;
}

function manifestEdges(chunk, edge, key) {
  const values = chunk[edge] ?? [];
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) {
    throw new Error(`manifest ${key}.${edge} must be an array of chunk keys`);
  }
  return values;
}

function validateManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("Vite manifest must be an object");
  }
  const files = new Map();
  for (const [key, chunk] of Object.entries(manifest)) {
    if (!chunk || typeof chunk !== "object" || Array.isArray(chunk)) {
      throw new Error(`manifest chunk ${key} must be an object`);
    }
    governedDistributionPath(chunk.file, `manifest chunk ${key} file`);
    manifestEdges(chunk, "imports", key);
    manifestEdges(chunk, "dynamicImports", key);
    if (chunk.css !== undefined) {
      if (!Array.isArray(chunk.css) || chunk.css.some((file) => typeof file !== "string")) {
        throw new Error(`manifest ${key}.css must be an array of files`);
      }
      for (const file of chunk.css) {
        governedDistributionPath(file, `manifest ${key} CSS file`);
      }
    }
    const prior = files.get(chunk.file);
    if (prior) {
      throw new Error(`manifest chunks ${prior} and ${key} share output file ${chunk.file}`);
    }
    files.set(chunk.file, key);
  }
}

function visitGraph(manifest, root, edges, visited = new Set()) {
  if (visited.has(root)) return visited;
  const chunk = Object.hasOwn(manifest, root) ? manifest[root] : undefined;
  if (!chunk) throw new Error(`manifest references missing chunk ${root}`);
  visited.add(root);
  for (const edge of edges) {
    for (const imported of manifestEdges(chunk, edge, root)) {
      visitGraph(manifest, imported, edges, visited);
    }
  }
  return visited;
}

export function buildBundleMembership(
  manifest,
  requiredBoundaries = REQUIRED_LAZY_BOUNDARIES,
) {
  validateManifest(manifest);
  const entries = Object.entries(manifest).filter(([, chunk]) => chunk.isEntry);
  if (entries.length !== 1) {
    throw new Error(`expected one browser entry, found ${entries.length}`);
  }
  const entryKey = entries[0][0];
  const eagerKeys = visitGraph(manifest, entryKey, ["imports"]);
  const requiredBoundaryKeys = [...new Set(Object.values(requiredBoundaries))].sort();
  if (requiredBoundaryKeys.length !== Object.keys(requiredBoundaries).length) {
    throw new Error("required lazy capability roots must be unique");
  }
  const dynamicFrontierKeys = [
    ...new Set(
      [...eagerKeys].flatMap((key) => manifest[key].dynamicImports ?? []),
    ),
  ].sort();
  const missingFrontierKeys = requiredBoundaryKeys.filter(
    (key) => !dynamicFrontierKeys.includes(key),
  );
  const unexpectedFrontierKeys = dynamicFrontierKeys.filter(
    (key) => !requiredBoundaryKeys.includes(key),
  );
  if (missingFrontierKeys.length > 0 || unexpectedFrontierKeys.length > 0) {
    throw new Error(
      [
        "eager static closure dynamic frontier must be exactly the required capability roots",
        `missing: ${missingFrontierKeys.join(", ") || "none"}`,
        `unexpected: ${unexpectedFrontierKeys.join(", ") || "none"}`,
      ].join("; "),
    );
  }
  const capabilityKeys = {};
  const ownersByKey = new Map();

  for (const [name, source] of Object.entries(requiredBoundaries)) {
    const boundary = manifest[source];
    if (!boundary || eagerKeys.has(source) || !isExecutableJavaScript(boundary.file)) {
      throw new Error(`${name} is not a separate lazy JavaScript chunk`);
    }
    const keys = visitGraph(manifest, source, ["imports", "dynamicImports"]);
    const lazyKeys = [...keys]
      .filter(
        (key) => !eagerKeys.has(key) && isExecutableJavaScript(manifest[key].file),
      )
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
        isExecutableJavaScript(manifest[key].file) &&
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
    dynamicFrontierKeys,
    capabilityKeys,
    lazyUniqueKeys: [...ownersByKey.keys()].sort(),
    ownersByKey: Object.fromEntries(
      [...ownersByKey.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, owners]) => [key, [...owners].sort()]),
    ),
  };
}

async function canonicalDistributionRoot(distributionRoot) {
  const requestedRoot = resolve(distributionRoot);
  const rootStat = await lstat(requestedRoot);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new Error(`distribution root is not a real directory: ${requestedRoot}`);
  }
  const canonicalRoot = await realpath(requestedRoot);
  if (canonicalRoot !== requestedRoot) {
    throw new Error(`distribution root contains a symbolic-link component: ${requestedRoot}`);
  }
  return canonicalRoot;
}

async function readGovernedDistributionFile(distributionRoot, file) {
  const governedFile = governedDistributionPath(file);
  const absolutePath = resolve(distributionRoot, ...governedFile.split("/"));
  const relation = relative(distributionRoot, absolutePath);
  if (relation.startsWith(`..${sep}`) || relation === "..") {
    throw new Error(`distribution file escapes the root: ${file}`);
  }

  let current = distributionRoot;
  let finalStat;
  for (const [index, component] of governedFile.split("/").entries()) {
    current = resolve(current, component);
    let pathStat;
    try {
      pathStat = await lstat(current);
    } catch (error) {
      if (error?.code === "ENOENT" || error?.code === "ENOTDIR") {
        throw new Error(`distribution file does not exist: ${file}`);
      }
      throw error;
    }
    if (pathStat.isSymbolicLink()) {
      throw new Error(`distribution path contains a symbolic link: ${file}`);
    }
    if (index < governedFile.split("/").length - 1 && !pathStat.isDirectory()) {
      throw new Error(`distribution path contains a non-directory component: ${file}`);
    }
    finalStat = pathStat;
  }
  if (!finalStat?.isFile()) {
    throw new Error(`distribution path is not a regular file: ${file}`);
  }

  let handle;
  try {
    handle = await open(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const openedStat = await handle.stat();
    if (
      !openedStat.isFile() ||
      openedStat.dev !== finalStat.dev ||
      openedStat.ino !== finalStat.ino
    ) {
      throw new Error(`distribution file changed during governed read: ${file}`);
    }
    const bytes = await handle.readFile();
    const postReadPath = await realpath(absolutePath);
    if (postReadPath !== absolutePath) {
      throw new Error(`distribution file path changed during governed read: ${file}`);
    }
    return bytes;
  } catch (error) {
    if (error?.code === "ELOOP") {
      throw new Error(`distribution file became a symbolic link: ${file}`);
    }
    throw error;
  } finally {
    await handle?.close();
  }
}

async function distributionInventory(distributionRoot, directory = "") {
  const absoluteDirectory = directory
    ? resolve(distributionRoot, ...directory.split("/"))
    : distributionRoot;
  const entries = await readdir(absoluteDirectory);
  const files = [];
  for (const name of entries.sort()) {
    const file = directory ? `${directory}/${name}` : name;
    governedDistributionPath(file);
    const pathStat = await lstat(resolve(distributionRoot, ...file.split("/")));
    if (pathStat.isSymbolicLink()) {
      throw new Error(`distribution path contains a symbolic link: ${file}`);
    }
    if (pathStat.isDirectory()) {
      files.push(...(await distributionInventory(distributionRoot, file)));
    } else if (pathStat.isFile()) {
      files.push(file);
    } else {
      throw new Error(`distribution path is not regular: ${file}`);
    }
  }
  return files;
}

function htmlDistributionFile(specifier) {
  const withoutDot = specifier.startsWith("./") ? specifier.slice(2) : specifier;
  return governedDistributionPath(withoutDot, "HTML distribution resource");
}

export async function validateDistributionArtifacts({
  distributionRoot,
  manifest,
  membership = buildBundleMembership(manifest),
}) {
  const root = await canonicalDistributionRoot(distributionRoot);
  validateManifest(manifest);
  const inventory = await distributionInventory(root);
  const inventorySet = new Set(inventory);
  const htmlFiles = inventory.filter(
    (file) => extname(file).toLowerCase() === ".html",
  );
  if (htmlFiles.length !== 1 || htmlFiles[0] !== "index.html") {
    throw new Error(
      `distribution HTML entry set must be exactly index.html: ${htmlFiles.join(", ") || "none"}`,
    );
  }
  const manifestFiles = new Set();
  const manifestExecutableFiles = new Set();
  for (const chunk of Object.values(manifest)) {
    manifestFiles.add(chunk.file);
    if (isExecutableJavaScript(chunk.file)) manifestExecutableFiles.add(chunk.file);
    for (const file of chunk.css ?? []) manifestFiles.add(file);
  }

  const ungovernedExecutables = inventory.filter(
    (file) => isExecutableJavaScript(file) && !manifestExecutableFiles.has(file),
  );
  if (ungovernedExecutables.length > 0) {
    throw new Error(
      `executable files are outside the Vite manifest: ${ungovernedExecutables.join(", ")}`,
    );
  }
  for (const file of manifestFiles) {
    if (!inventorySet.has(file)) {
      throw new Error(`manifest output is absent from the distribution: ${file}`);
    }
    await readGovernedDistributionFile(root, file);
  }

  const html = (await readGovernedDistributionFile(root, "index.html")).toString("utf8");
  const edges = parseGovernedHtmlEdges("dist/index.html", html);
  const eagerFiles = new Set(
    membership.eagerKeys
      .map((key) => manifest[key].file)
      .filter(isExecutableJavaScript),
  );
  const htmlScriptFiles = new Set();
  const htmlStyleFiles = new Set();
  for (const edge of edges) {
    const file = htmlDistributionFile(edge.specifier);
    if (!inventorySet.has(file)) {
      throw new Error(`HTML references an absent distribution file: ${file}`);
    }
    await readGovernedDistributionFile(root, file);
    if (edge.kind === "script") {
      if (!isExecutableJavaScript(file) || !eagerFiles.has(file)) {
        throw new Error(`HTML script is not in the eager manifest graph: ${file}`);
      }
      if (htmlScriptFiles.has(file)) {
        throw new Error(`HTML repeats a script resource: ${file}`);
      }
      htmlScriptFiles.add(file);
    } else if (extname(file).toLowerCase() !== ".css" || !manifestFiles.has(file)) {
      throw new Error(`HTML stylesheet is not a manifest CSS output: ${file}`);
    } else {
      if (htmlStyleFiles.has(file)) {
        throw new Error(`HTML repeats a stylesheet resource: ${file}`);
      }
      htmlStyleFiles.add(file);
    }
  }
  const entryFile = manifest[membership.entryKey].file;
  if (!htmlScriptFiles.has(entryFile)) {
    throw new Error(`HTML does not load the manifest entry script: ${entryFile}`);
  }
  const missingEagerStyles = [
    ...new Set(
      membership.eagerKeys.flatMap((key) => manifest[key].css ?? []),
    ),
  ].filter((file) => !htmlStyleFiles.has(file));
  if (missingEagerStyles.length > 0) {
    throw new Error(
      `HTML does not load eager manifest stylesheets: ${missingEagerStyles.join(", ")}`,
    );
  }
  return { files: inventory, htmlEdges: edges };
}

async function measureFile(distributionRoot, source, file) {
  const bytes = await readGovernedDistributionFile(distributionRoot, file);
  return {
    source,
    file,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    uncompressed_bytes: bytes.byteLength,
    gzip_bytes: gzipSync(bytes, { level: 9 }).byteLength,
  };
}

async function main() {
  const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const distributionRoot = await canonicalDistributionRoot(resolve(webRoot, "dist"));
  const manifest = JSON.parse(
    (await readGovernedDistributionFile(distributionRoot, ".vite/manifest.json")).toString(
      "utf8",
    ),
  );
  const membership = buildBundleMembership(manifest);
  await validateDistributionArtifacts({ distributionRoot, manifest, membership });
  const measurements = new Map();
  for (const key of [...new Set([...membership.eagerKeys, ...membership.lazyUniqueKeys])]) {
    const file = manifest[key].file;
    if (!isExecutableJavaScript(file)) continue;
    measurements.set(key, await measureFile(distributionRoot, key, file));
  }

  const eagerFiles = membership.eagerKeys
    .filter((key) => measurements.has(key))
    .map((key) => measurements.get(key));
  const eagerBytes = eagerFiles.reduce((total, file) => total + file.gzip_bytes, 0);
  const eagerUncompressedBytes = eagerFiles.reduce(
    (total, file) => total + file.uncompressed_bytes,
    0,
  );
  const lazyCapabilities = {};
  for (const [name, source] of Object.entries(REQUIRED_LAZY_BOUNDARIES)) {
    const files = membership.capabilityKeys[name].map((key) => measurements.get(key));
    const gzipBytes = files.reduce((total, file) => total + file.gzip_bytes, 0);
    const uncompressedBytes = files.reduce(
      (total, file) => total + file.uncompressed_bytes,
      0,
    );
    lazyCapabilities[name] = {
      source,
      baseline_bytes_gzip: 0,
      uncompressed_bytes: uncompressedBytes,
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
  const lazyUniqueUncompressedBytes = lazyUniqueFiles.reduce(
    (total, file) => total + file.uncompressed_bytes,
    0,
  );

  const baseline = 60_808;
  const budget = 250 * 1024;
  const evidence = {
    schema_version: "1.1",
    issue: "P1-005-FE-FOUNDATION",
    contract: "PERF-005",
    generated_by: "apps/web/scripts/measure-bundle.mjs",
    measurement_method:
      "Exact uncompressed file bytes plus Node zlib level 9 over closed Vite manifest JavaScript graphs with SHA-256 digests and stable shared-chunk attribution",
    scope: "Wave 0 original non-import foundation",
    mature_interface_perf005_complete: false,
    lazy_boundaries_are_placeholders: true,
    minimal_foundation_baseline_bytes_gzip: baseline,
    budget_bytes_gzip: budget,
    eager_dynamic_frontier: membership.dynamicFrontierKeys,
    eager_javascript: {
      uncompressed_bytes: eagerUncompressedBytes,
      gzip_bytes: eagerBytes,
      delta_bytes_gzip: eagerBytes - baseline,
      files: eagerFiles,
    },
    lazy_capabilities: lazyCapabilities,
    lazy_unique_javascript: {
      uncompressed_bytes: lazyUniqueUncompressedBytes,
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
