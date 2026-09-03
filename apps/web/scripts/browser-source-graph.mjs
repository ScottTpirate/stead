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

function cssImports(path, source) {
  const scanned = source.replace(/\/\*[\s\S]*?\*\//gu, (comment) =>
    " ".repeat(comment.length),
  );
  if (scanned.includes("\\")) {
    throw new Error(`CSS escapes are not governed browser edges in ${path}`);
  }
  if (/\b(?:-webkit-)?image-set\s*\(/iu.test(scanned)) {
    throw new Error(`CSS image-set assets are not governed browser edges in ${path}`);
  }
  const importRanges = [];
  const imports = [];
  for (const match of scanned.matchAll(/@import\b/giu)) {
    const tail = scanned.slice(match.index);
    const parsed = /^@import\s+(?:"([^"\\\r\n]+)"|'([^'\\\r\n]+)'|url\(\s*(?:"([^"\\\r\n]+)"|'([^'\\\r\n]+)'|([^"'()\\\s]+))\s*\))/iu.exec(
      tail,
    );
    if (!parsed) {
      throw new Error(`unsupported CSS import syntax in ${path}`);
    }
    const specifier = parsed.slice(1).find((value) => value !== undefined);
    if (!specifier) throw new Error(`empty CSS import in ${path}`);
    imports.push(specifier);
    importRanges.push([match.index, match.index + parsed[0].length]);
  }

  for (const match of scanned.matchAll(/\burl\s*\(/giu)) {
    if (
      !importRanges.some(
        ([start, end]) => match.index >= start && match.index < end,
      )
    ) {
      throw new Error(`unsupported CSS asset URL outside @import in ${path}`);
    }
  }
  return imports;
}

function scriptImports(path, source) {
  const scriptKind = path.endsWith(".tsx") || path.endsWith(".jsx")
    ? ts.ScriptKind.TSX
    : path.endsWith(".js") || path.endsWith(".mjs")
      ? ts.ScriptKind.JS
      : ts.ScriptKind.TS;
  const sourceFile = ts.createSourceFile(
    path,
    source,
    ts.ScriptTarget.Latest,
    true,
    scriptKind,
  );
  if (sourceFile.parseDiagnostics.length > 0) {
    throw new Error(`browser module has TypeScript parse errors: ${path}`);
  }

  const imports = [];
  const visit = (node) => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier
    ) {
      if (!ts.isStringLiteral(node.moduleSpecifier)) {
        throw new Error(`non-literal browser module edge in ${path}`);
      }
      imports.push(node.moduleSpecifier.text);
    }
    if (ts.isImportEqualsDeclaration(node)) {
      throw new Error(`TypeScript import-equals is not a governed browser edge in ${path}`);
    }
    if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        if (node.arguments.length !== 1 || !ts.isStringLiteral(node.arguments[0])) {
          throw new Error(`non-literal dynamic browser import in ${path}`);
        }
        imports.push(node.arguments[0].text);
      }
      if (
        ts.isIdentifier(node.expression) &&
        node.expression.text === "require"
      ) {
        throw new Error(`CommonJS require is not a governed browser edge in ${path}`);
      }
      if (
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isMetaProperty(node.expression.expression) &&
        node.expression.expression.keywordToken === ts.SyntaxKind.ImportKeyword &&
        ["glob", "globEager"].includes(node.expression.name.text)
      ) {
        throw new Error(`Vite import.meta.${node.expression.name.text} is not a governed browser edge in ${path}`);
      }
      if (
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === "register" &&
        node.expression.expression.getText(sourceFile).replaceAll(/\s/gu, "").endsWith(".serviceWorker")
      ) {
        throw new Error(`service-worker registration is not a governed browser edge in ${path}`);
      }
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      if (["Worker", "SharedWorker"].includes(node.expression.text)) {
        throw new Error(`${node.expression.text} is not a governed browser edge in ${path}`);
      }
      if (
        node.expression.text === "URL" &&
        node.arguments?.some((argument) =>
          argument.getText(sourceFile).replaceAll(/\s/gu, "").includes("import.meta.url"),
        )
      ) {
        throw new Error(`import.meta.url asset loading is not a governed browser edge in ${path}`);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return imports;
}

function moduleImports(path, source) {
  if (path.endsWith(".css")) return cssImports(path, source);
  return scriptImports(path, source);
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
