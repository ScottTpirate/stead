import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, extname, relative, resolve, sep } from "node:path";

import ts from "typescript";

const SOURCE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".css"];
const PROVIDER_OR_INFRASTRUCTURE =
  /gitea|commonplace|openfga|\bnats\b|\/api\/v1\/repos/iu;
const DIRECT_BROWSER_NETWORK =
  /\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\s*\(|\bEventSource\s*\(|\bsendBeacon\s*\(/iu;
const NETWORK_URL = /https?:\/\//iu;
const DEVLANE_ONTOLOGY =
  /\bModules\b|\bEpics\b|\bPages\b|\bBoard\b|\bIntake\b|\bArchives\b|\bDrafts\b/iu;
const DIRECT_NETWORK_IDENTIFIERS = new Set([
  "EventSource",
  "SharedWorker",
  "WebSocket",
  "Worker",
  "XMLHttpRequest",
  "fetch",
  "importScripts",
  "sendBeacon",
]);
const DYNAMIC_CODE_IDENTIFIERS = new Set(["Function", "eval"]);
const HTML_RESOURCE_ATTRIBUTES = new Set([
  "action",
  "formaction",
  "href",
  "poster",
  "src",
  "srcset",
]);
const FORBIDDEN_HTML_ELEMENTS = new Set([
  "applet",
  "base",
  "embed",
  "frame",
  "iframe",
  "object",
  "portal",
  "style",
]);
const MAX_STATIC_STRING_LENGTH = 16_384;

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

function parseHtmlAttributes(path, rawAttributes) {
  const attributes = new Map();
  let cursor = 0;
  while (cursor < rawAttributes.length) {
    while (/\s/u.test(rawAttributes[cursor] ?? "")) cursor += 1;
    if (cursor >= rawAttributes.length) break;

    const nameMatch = /^[A-Za-z_:][A-Za-z0-9_.:-]*/u.exec(
      rawAttributes.slice(cursor),
    );
    if (!nameMatch) throw new Error(`unsupported HTML attribute syntax in ${path}`);
    const name = nameMatch[0].toLowerCase();
    if (attributes.has(name)) {
      throw new Error(`duplicate HTML attribute ${name} in ${path}`);
    }
    cursor += nameMatch[0].length;
    while (/\s/u.test(rawAttributes[cursor] ?? "")) cursor += 1;

    let value = true;
    if (rawAttributes[cursor] === "=") {
      cursor += 1;
      while (/\s/u.test(rawAttributes[cursor] ?? "")) cursor += 1;
      const quote = rawAttributes[cursor];
      if (quote !== '"' && quote !== "'") {
        throw new Error(`unquoted HTML attribute ${name} in ${path}`);
      }
      cursor += 1;
      const valueStart = cursor;
      while (cursor < rawAttributes.length && rawAttributes[cursor] !== quote) {
        cursor += 1;
      }
      if (cursor >= rawAttributes.length) {
        throw new Error(`unterminated HTML attribute ${name} in ${path}`);
      }
      value = rawAttributes.slice(valueStart, cursor);
      cursor += 1;
    }
    attributes.set(name, value);
  }
  return attributes;
}

function tokenizeHtml(path, source) {
  const tokens = [];
  let cursor = 0;
  while (cursor < source.length) {
    const open = source.indexOf("<", cursor);
    if (open < 0) break;
    if (source.startsWith("<!--", open)) {
      const close = source.indexOf("-->", open + 4);
      if (close < 0) throw new Error(`unterminated HTML comment in ${path}`);
      cursor = close + 3;
      continue;
    }
    if (/^<!doctype\s+html\s*>/iu.test(source.slice(open))) {
      const close = source.indexOf(">", open + 2);
      cursor = close + 1;
      continue;
    }

    let close = open + 1;
    let quote;
    for (; close < source.length; close += 1) {
      const character = source[close];
      if (quote) {
        if (character === quote) quote = undefined;
      } else if (character === '"' || character === "'") {
        quote = character;
      } else if (character === ">") {
        break;
      }
    }
    if (close >= source.length || quote) {
      throw new Error(`unterminated HTML tag in ${path}`);
    }

    let rawTag = source.slice(open + 1, close).trim();
    const closing = rawTag.startsWith("/");
    if (closing) rawTag = rawTag.slice(1).trim();
    const selfClosing = !closing && rawTag.endsWith("/");
    if (selfClosing) rawTag = rawTag.slice(0, -1).trimEnd();
    const nameMatch = /^[A-Za-z][A-Za-z0-9:-]*/u.exec(rawTag);
    if (!nameMatch) throw new Error(`unsupported HTML tag syntax in ${path}`);
    const name = nameMatch[0].toLowerCase();
    const attributes = parseHtmlAttributes(path, rawTag.slice(nameMatch[0].length));
    if (closing && (attributes.size > 0 || selfClosing)) {
      throw new Error(`unsupported HTML closing tag syntax in ${path}`);
    }
    tokens.push({ attributes, closing, end: close + 1, name, selfClosing, start: open });
    cursor = close + 1;
  }
  return tokens;
}

function governedHtmlSpecifier(path, value) {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim()) {
    throw new Error(`empty or non-canonical HTML resource URL in ${path}`);
  }
  if (
    value.includes("\\") ||
    value.includes("%") ||
    value.includes("?") ||
    value.includes("#") ||
    /^(?:[A-Za-z][A-Za-z0-9+.-]*:|\/\/)/u.test(value)
  ) {
    throw new Error(`external or modified HTML resource URL is not governed in ${path}`);
  }
  return value.startsWith("/") ? `.${value}` : value;
}

export function parseGovernedHtmlEdges(path, source) {
  const tokens = tokenizeHtml(path, source);
  const edges = [];
  let openScript;

  for (const token of tokens) {
    if (openScript) {
      if (!token.closing || token.name !== "script") {
        throw new Error(`nested or unterminated HTML script in ${path}`);
      }
      if (source.slice(openScript.end, token.start).trim().length > 0) {
        throw new Error(`inline HTML script is not a governed browser edge in ${path}`);
      }
      openScript = undefined;
      continue;
    }
    if (token.closing) continue;
    if (FORBIDDEN_HTML_ELEMENTS.has(token.name)) {
      throw new Error(`HTML ${token.name} is not a governed browser edge in ${path}`);
    }
    for (const [name] of token.attributes) {
      if (name.startsWith("on") || name === "srcdoc" || name === "style") {
        throw new Error(`HTML attribute ${name} is not governed in ${path}`);
      }
    }
    if (
      token.name === "meta" &&
      String(token.attributes.get("http-equiv") ?? "").toLowerCase() === "refresh"
    ) {
      throw new Error(`HTML refresh is not a governed browser edge in ${path}`);
    }

    if (token.name === "script") {
      if (token.selfClosing) throw new Error(`self-closing HTML script in ${path}`);
      if (
        token.attributes.get("type") !== "module" ||
        !token.attributes.has("src")
      ) {
        throw new Error(`only external module scripts are governed in ${path}`);
      }
      const allowed = new Set(["crossorigin", "src", "type"]);
      for (const [name] of token.attributes) {
        if (!allowed.has(name)) {
          throw new Error(`unsupported HTML script attribute ${name} in ${path}`);
        }
      }
      edges.push({
        kind: "script",
        specifier: governedHtmlSpecifier(path, token.attributes.get("src")),
      });
      openScript = token;
      continue;
    }

    if (token.name === "link") {
      const relation = String(token.attributes.get("rel") ?? "").toLowerCase();
      if (!["modulepreload", "stylesheet"].includes(relation)) {
        throw new Error(`unsupported HTML link relation in ${path}`);
      }
      if (!token.attributes.has("href")) {
        throw new Error(`HTML link has no href in ${path}`);
      }
      const allowed = new Set(["crossorigin", "href", "rel"]);
      for (const [name] of token.attributes) {
        if (!allowed.has(name)) {
          throw new Error(`unsupported HTML link attribute ${name} in ${path}`);
        }
      }
      edges.push({
        kind: relation === "stylesheet" ? "style" : "script",
        specifier: governedHtmlSpecifier(path, token.attributes.get("href")),
      });
      continue;
    }

    for (const [name] of token.attributes) {
      if (HTML_RESOURCE_ATTRIBUTES.has(name)) {
        throw new Error(
          `unsupported HTML resource attribute ${token.name}.${name} in ${path}`,
        );
      }
    }
  }
  if (openScript) throw new Error(`unterminated HTML script in ${path}`);
  return edges;
}

function staticString(node, bindings = new Map(), seen = new Set()) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return node.text;
  }
  if (ts.isIdentifier(node) && bindings.has(node.text) && !seen.has(node.text)) {
    return staticString(
      bindings.get(node.text),
      bindings,
      new Set([...seen, node.text]),
    );
  }
  if (ts.isParenthesizedExpression(node)) {
    return staticString(node.expression, bindings, seen);
  }
  if (
    ts.isAsExpression(node) ||
    ts.isTypeAssertionExpression(node) ||
    ts.isNonNullExpression(node)
  ) {
    return staticString(node.expression, bindings, seen);
  }
  if (
    ts.isBinaryExpression(node) &&
    node.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    const left = staticString(node.left, bindings, seen);
    const right = staticString(node.right, bindings, seen);
    if (left === undefined || right === undefined) return undefined;
    const value = left + right;
    return value.length <= MAX_STATIC_STRING_LENGTH ? value : undefined;
  }
  if (ts.isTemplateExpression(node)) {
    let value = node.head.text;
    for (const span of node.templateSpans) {
      const expression = staticString(span.expression, bindings, seen);
      if (expression === undefined) return undefined;
      value += expression + span.literal.text;
      if (value.length > MAX_STATIC_STRING_LENGTH) return undefined;
    }
    return value;
  }
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "concat"
  ) {
    const receiver = staticString(node.expression.expression, bindings, seen);
    const arguments_ = node.arguments.map((argument) =>
      staticString(argument, bindings, seen),
    );
    if (receiver === undefined || arguments_.some((value) => value === undefined)) {
      return undefined;
    }
    const value = receiver + arguments_.join("");
    return value.length <= MAX_STATIC_STRING_LENGTH ? value : undefined;
  }
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "join" &&
    ts.isArrayLiteralExpression(node.expression.expression) &&
    node.arguments.length <= 1
  ) {
    const elements = node.expression.expression.elements.map((element) =>
      staticString(element, bindings, seen),
    );
    const separator = node.arguments.length === 0
      ? ","
      : staticString(node.arguments[0], bindings, seen);
    if (separator === undefined || elements.some((value) => value === undefined)) {
      return undefined;
    }
    const value = elements.join(separator);
    return value.length <= MAX_STATIC_STRING_LENGTH ? value : undefined;
  }
  return undefined;
}

function staticConstBindings(sourceFile) {
  const declarations = new Map();
  const duplicates = new Set();
  const visit = (node) => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      ts.isVariableDeclarationList(node.parent) &&
      (node.parent.flags & ts.NodeFlags.Const) !== 0
    ) {
      if (declarations.has(node.name.text)) duplicates.add(node.name.text);
      declarations.set(node.name.text, node.initializer);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  for (const duplicate of duplicates) declarations.delete(duplicate);
  return declarations;
}

function scriptSourceFile(path, source) {
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
  return sourceFile;
}

function scriptImports(path, source) {
  const sourceFile = scriptSourceFile(path, source);

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
  if (path.endsWith(".html")) {
    return parseGovernedHtmlEdges(path, source).map(({ specifier }) => specifier);
  }
  if (path.endsWith(".css")) return cssImports(path, source);
  return scriptImports(path, source);
}

function scriptBoundaryRules(path, source) {
  const sourceFile = scriptSourceFile(path, source);
  const bindings = staticConstBindings(sourceFile);
  const staticValues = [];
  let directNetwork = false;
  const approvedPlatformFetchReference = (node) =>
    path.endsWith(`${sep}packages${sep}api-client${sep}src${sep}client.ts`) &&
    ts.isPropertyAccessExpression(node) &&
    node.expression.getText(sourceFile) === "globalThis" &&
    node.name.text === "fetch" &&
    node.parent?.getText(sourceFile) ===
      "options.fetchImplementation ?? globalThis.fetch";
  const visit = (node) => {
    const value = staticString(node, bindings);
    if (value !== undefined) staticValues.push(value);
    if (
      ts.isIdentifier(node) &&
      DYNAMIC_CODE_IDENTIFIERS.has(node.text)
    ) {
      directNetwork = true;
    }
    if (
      ts.isIdentifier(node) &&
      DIRECT_NETWORK_IDENTIFIERS.has(node.text) &&
      !ts.isTypeQueryNode(node.parent) &&
      !(
        ts.isPropertyAccessExpression(node.parent) &&
        node.parent.name === node &&
        approvedPlatformFetchReference(node.parent)
      )
    ) {
      directNetwork = true;
    }
    if (
      ts.isPropertyAccessExpression(node) &&
      DIRECT_NETWORK_IDENTIFIERS.has(node.name.text) &&
      !approvedPlatformFetchReference(node)
    ) {
      directNetwork = true;
    }
    if (ts.isElementAccessExpression(node)) {
      const property = staticString(node.argumentExpression, bindings);
      if (
        property !== undefined &&
        (DIRECT_NETWORK_IDENTIFIERS.has(property) ||
          DYNAMIC_CODE_IDENTIFIERS.has(property))
      ) {
        directNetwork = true;
      }
    }
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const expression = node.expression;
      if (
        (ts.isIdentifier(expression) &&
          DIRECT_NETWORK_IDENTIFIERS.has(expression.text)) ||
        (ts.isPropertyAccessExpression(expression) &&
          DIRECT_NETWORK_IDENTIFIERS.has(expression.name.text))
      ) {
        directNetwork = true;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);

  const analyzedText = [source, ...staticValues].join("\n");
  const generatedContractData = path.endsWith(
    `${sep}packages${sep}api-client${sep}src${sep}generated${sep}platform-v1.ts`,
  );
  const hasExecutableNetworkUrl = staticValues.some(
    (value) =>
      NETWORK_URL.test(value) &&
      !generatedContractData &&
      value !== "https://stead.invalid",
  );
  const rules = new Set();
  if (PROVIDER_OR_INFRASTRUCTURE.test(analyzedText)) {
    rules.add("provider-or-infrastructure");
  }
  if (
    DIRECT_BROWSER_NETWORK.test(analyzedText) ||
    directNetwork ||
    hasExecutableNetworkUrl
  ) {
    rules.add("direct-browser-network");
  }
  if (DEVLANE_ONTOLOGY.test(analyzedText)) rules.add("devlane-ontology");
  return rules;
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
    const rules = module.path.endsWith(".css") || module.path.endsWith(".html")
      ? new Set(
          [
            ["provider-or-infrastructure", PROVIDER_OR_INFRASTRUCTURE],
            ["direct-browser-network", DIRECT_BROWSER_NETWORK],
            ["devlane-ontology", DEVLANE_ONTOLOGY],
          ]
            .filter(([, pattern]) => pattern.test(module.source))
            .map(([rule]) => rule),
        )
      : scriptBoundaryRules(module.path, module.source);
    for (const rule of rules) {
      violations.push({ path: module.path, rule });
    }
  }
  return violations.sort(
    (left, right) =>
      left.path.localeCompare(right.path) || left.rule.localeCompare(right.rule),
  );
}

export function undeclaredRuntimePackages(
  graph,
  packageManifest,
  { includeDevDependencies = false } = {},
) {
  const dependencies = new Set([
    ...Object.keys(packageManifest.dependencies ?? {}),
    ...(includeDevDependencies
      ? Object.keys(packageManifest.devDependencies ?? {})
      : []),
  ]);
  return graph.externalPackages.filter((name) => !dependencies.has(name));
}
