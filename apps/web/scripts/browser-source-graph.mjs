import { readFile } from "node:fs/promises";
import { dirname, extname, relative, resolve, sep } from "node:path";

import ts from "typescript";

const SOURCE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".css"];
const PROVIDER_OR_INFRASTRUCTURE =
  /gitea|commonplace|openfga|\bnats\b|\/api\/v1\/repos/iu;
const DIRECT_BROWSER_NETWORK =
  /\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\s*\(|\bEventSource\s*\(|\bsendBeacon\s*\(|https?:\/\//iu;
const DEVLANE_ONTOLOGY =
  /\bModules\b|\bEpics\b|\bPages\b|\bBoard\b|\bIntake\b|\bArchives\b|\bDrafts\b/iu;

function insideRoot(path, root) {
  const relation = relative(root, path);
  return relation === "" || (!relation.startsWith(`..${sep}`) && relation !== "..");
}

async function existingFile(path) {
  try {
    const source = await readFile(path, "utf8");
    return { path, source };
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "EISDIR") return undefined;
    throw error;
  }
}

async function resolveLocalImport(importer, specifier) {
  if (specifier.includes("?") || specifier.includes("#")) {
    throw new Error(`browser import modifiers are not governed: ${specifier}`);
  }
  const unresolved = resolve(dirname(importer), specifier);
  const candidates = extname(unresolved)
    ? [unresolved]
    : [
        unresolved,
        ...SOURCE_EXTENSIONS.map((extension) => `${unresolved}${extension}`),
        ...SOURCE_EXTENSIONS.map((extension) => resolve(unresolved, `index${extension}`)),
      ];
  for (const candidate of candidates) {
    const found = await existingFile(candidate);
    if (found) return found;
  }
  throw new Error(`unresolved local browser import ${specifier} from ${importer}`);
}

function cssImports(source) {
  return [...source.matchAll(/@import\s+(?:url\(\s*)?["']([^"']+)["']/gu)].map(
    (match) => match[1],
  );
}

function moduleImports(path, source) {
  if (path.endsWith(".css")) return cssImports(source);
  return ts
    .preProcessFile(source, true, true)
    .importedFiles.map((entry) => entry.fileName);
}

function packageName(specifier) {
  if (specifier.startsWith("@")) return specifier.split("/", 2).join("/");
  return specifier.split("/", 1)[0];
}

export async function collectBrowserSourceGraph({ entryPath, repositoryRoot }) {
  const root = resolve(repositoryRoot);
  const pending = [resolve(entryPath)];
  const modules = new Map();
  const externalPackages = new Set();

  while (pending.length > 0) {
    const path = pending.pop();
    if (modules.has(path)) continue;
    if (!insideRoot(path, root)) {
      throw new Error(`browser module escapes the repository: ${path}`);
    }
    const found = await existingFile(path);
    if (!found) throw new Error(`browser entry/module does not exist: ${path}`);
    const imports = moduleImports(path, found.source);
    modules.set(path, { path, source: found.source, imports });
    for (const specifier of imports) {
      if (specifier.startsWith(".")) {
        const imported = await resolveLocalImport(path, specifier);
        pending.push(imported.path);
      } else if (specifier.startsWith("/")) {
        throw new Error(`absolute browser module import is not governed: ${specifier}`);
      } else {
        externalPackages.add(packageName(specifier));
      }
    }
  }

  return {
    modules: [...modules.values()].sort((left, right) =>
      left.path.localeCompare(right.path),
    ),
    externalPackages: [...externalPackages].sort(),
  };
}

export function findBrowserBoundaryViolations(graph) {
  const violations = [];
  for (const module of graph.modules) {
    for (const [rule, pattern] of [
      ["provider-or-infrastructure", PROVIDER_OR_INFRASTRUCTURE],
      ["direct-browser-network", DIRECT_BROWSER_NETWORK],
      ["devlane-ontology", DEVLANE_ONTOLOGY],
    ]) {
      if (pattern.test(module.source)) violations.push({ path: module.path, rule });
    }
  }
  return violations.sort(
    (left, right) =>
      left.path.localeCompare(right.path) || left.rule.localeCompare(right.rule),
  );
}

export function undeclaredRuntimePackages(graph, packageManifest) {
  const dependencies = new Set(Object.keys(packageManifest.dependencies ?? {}));
  return graph.externalPackages.filter((name) => !dependencies.has(name));
}
