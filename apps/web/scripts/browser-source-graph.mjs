import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
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

async function canonicalRepositoryRoot(repositoryRoot) {
  const requestedRoot = resolve(repositoryRoot);
  try {
    const rootStat = await lstat(requestedRoot);
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
      throw new Error(`browser repository root is not a real directory: ${requestedRoot}`);
    }
    const canonicalRoot = await realpath(requestedRoot);
    if (canonicalRoot !== requestedRoot) {
      throw new Error(
        `browser repository root contains a symbolic-link component: ${requestedRoot}`,
      );
    }
    return canonicalRoot;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("browser repository root")) {
      throw error;
    }
    if (error?.code === "ENOENT" || error?.code === "ENOTDIR") {
      throw new Error(`browser repository root does not exist: ${requestedRoot}`);
    }
    throw error;
  }
}

async function existingGovernedFile(path, root) {
  const absolutePath = resolve(path);
  if (!insideRoot(absolutePath, root)) {
    throw new Error(`browser module escapes the repository: ${absolutePath}`);
  }

  const relation = relative(root, absolutePath);
  const components = relation === "" ? [] : relation.split(sep);
  let current = root;
  let finalStat;
  for (const [index, component] of components.entries()) {
    current = resolve(current, component);
    let pathStat;
    try {
      pathStat = await lstat(current);
    } catch (error) {
      if (error?.code === "ENOENT" || error?.code === "ENOTDIR") return undefined;
      throw error;
    }
    if (pathStat.isSymbolicLink()) {
      throw new Error(`browser module path contains a symbolic link: ${current}`);
    }
    if (index < components.length - 1 && !pathStat.isDirectory()) {
      throw new Error(`browser module path contains a non-directory component: ${current}`);
    }
    finalStat = pathStat;
  }

  if (!finalStat || finalStat.isDirectory()) return undefined;
  if (!finalStat.isFile()) {
    throw new Error(`browser module path is not a regular file: ${absolutePath}`);
  }
  const canonicalPath = await realpath(absolutePath);
  if (canonicalPath !== absolutePath || !insideRoot(canonicalPath, root)) {
    throw new Error(`browser module realpath escapes its governed path: ${absolutePath}`);
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
      throw new Error(`browser module changed during governed read: ${absolutePath}`);
    }
    const source = await handle.readFile({ encoding: "utf8" });
    const postReadPath = await realpath(absolutePath);
    if (postReadPath !== canonicalPath) {
      throw new Error(`browser module path changed during governed read: ${absolutePath}`);
    }
    return { path: canonicalPath, source };
  } catch (error) {
    if (error?.code === "ELOOP") {
      throw new Error(`browser module became a symbolic link: ${absolutePath}`);
    }
    throw error;
  } finally {
    await handle?.close();
  }
}

async function resolveLocalImport(importer, specifier, root) {
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
    const found = await existingGovernedFile(candidate, root);
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
  const root = await canonicalRepositoryRoot(repositoryRoot);
  const pending = [resolve(entryPath)];
  const modules = new Map();
  const externalPackages = new Set();

  while (pending.length > 0) {
    const path = pending.pop();
    if (modules.has(path)) continue;
    if (!insideRoot(path, root)) {
      throw new Error(`browser module escapes the repository: ${path}`);
    }
    const found = await existingGovernedFile(path, root);
    if (!found) throw new Error(`browser entry/module does not exist: ${path}`);
    const imports = moduleImports(path, found.source);
    modules.set(path, { path, source: found.source, imports });
    for (const specifier of imports) {
      if (specifier.startsWith(".")) {
        const imported = await resolveLocalImport(path, specifier, root);
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
