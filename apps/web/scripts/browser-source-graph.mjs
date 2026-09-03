import { Buffer } from "node:buffer";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, extname, relative, resolve, sep } from "node:path";

import ts from "typescript";

const SOURCE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".css"];
const PROVIDER_OR_INFRASTRUCTURE =
  /gitea|commonplace|openfga|\bnats\b|\/api\/v1\/repos/iu;
const DIRECT_BROWSER_NETWORK =
  /\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\s*\(|\bEventSource\s*\(|\bsendBeacon\s*\(/iu;
const DEVLANE_ONTOLOGY =
  /\bModules\b|\bEpics\b|\bPages\b|\bBoard\b|\bIntake\b|\bArchives\b|\bDrafts\b/iu;
const DIRECT_NETWORK_IDENTIFIERS = new Set([
  "Audio",
  "EventSource",
  "Image",
  "RTCPeerConnection",
  "SharedWorker",
  "WebTransport",
  "WebSocket",
  "Worker",
  "XMLHttpRequest",
  "fetch",
  "importScripts",
  "sendBeacon",
]);
const DYNAMIC_CODE_IDENTIFIERS = new Set(["Function", "eval"]);
const DYNAMIC_CODE_PROPERTIES = new Set(["__proto__", "constructor"]);
const DYNAMIC_STRING_IDENTIFIERS = new Set([
  "atob",
  "decodeURI",
  "decodeURIComponent",
  "unescape",
]);
const BROWSER_GLOBAL_IDENTIFIERS = new Set([
  "document",
  "globalThis",
  "location",
  "navigator",
  "self",
  "window",
]);
const RESOURCE_PROPERTY_NAMES = new Set([
  "action",
  "background",
  "backgroundImage",
  "codeBase",
  "cssText",
  "data",
  "formAction",
  "href",
  "innerHTML",
  "outerHTML",
  "ping",
  "poster",
  "src",
  "srcdoc",
  "srcset",
]);
const RESOURCE_METHOD_NAMES = new Set([
  "addModule",
  "cloneElement",
  "createElement",
  "insertAdjacentHTML",
  "insertRule",
  "navigate",
  "parseFromString",
  "register",
  "registerProtocolHandler",
  "requestSubmit",
  "setAttribute",
  "setAttributeNS",
  "submit",
]);
const RESOURCE_JSX_ELEMENTS = new Set([
  "audio",
  "embed",
  "form",
  "iframe",
  "img",
  "link",
  "object",
  "script",
  "source",
  "track",
  "video",
]);
const HTML_RESOURCE_ATTRIBUTES = new Set([
  "action",
  "background",
  "codebase",
  "data",
  "formaction",
  "href",
  "imagesrcset",
  "manifest",
  "ping",
  "poster",
  "src",
  "srcset",
  "xlink:href",
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
const CALL_THROUGH_METHODS = new Set(["apply", "bind", "call"]);
const LOCATION_METHOD_NAMES = new Set(["assign", "reload", "replace"]);
const DEFAULT_SOURCE_LIMITS = Object.freeze({
  maxAggregateBytes: 8 * 1024 * 1024,
  maxDepth: 64,
  maxFileBytes: 512 * 1024,
  maxImportsPerModule: 256,
  maxModules: 512,
});

function containsExternalDestination(value) {
  return /(?:^|[\s=(:,;'"])(?:(?:https?|wss?|ftp):|\/\/|data:|blob:|file:|javascript:|mailto:|tel:|vbscript:)/iu.test(
    value,
  );
}

function insideRoot(path, root) {
  const relation = relative(root, path);
  return relation === "" || (!relation.startsWith(`..${sep}`) && relation !== "..");
}

function sourceLimits(requested = {}) {
  if (!requested || typeof requested !== "object" || Array.isArray(requested)) {
    throw new Error("browser source limits must be a tightening object");
  }
  const unknown = Object.keys(requested).filter(
    (name) => !Object.hasOwn(DEFAULT_SOURCE_LIMITS, name),
  );
  if (unknown.length > 0) {
    throw new Error(`unknown browser source limits: ${unknown.join(", ")}`);
  }
  return Object.fromEntries(
    Object.entries(DEFAULT_SOURCE_LIMITS).map(([name, ceiling]) => {
      const value = requested[name] ?? ceiling;
      if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) {
        throw new Error(`${name} must be a positive integer no greater than ${ceiling}`);
      }
      return [name, value];
    }),
  );
}

function sameFileSnapshot(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
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
    if (!openedStat.isFile() || !sameFileSnapshot(openedStat, finalStat)) {
      throw new Error(`browser module changed during governed read: ${absolutePath}`);
    }
    if (openedStat.size > DEFAULT_SOURCE_LIMITS.maxFileBytes) {
      throw new Error(`browser module exceeds the file-size ceiling: ${absolutePath}`);
    }
    const bytes = await handle.readFile();
    const afterReadStat = await handle.stat();
    const postReadStat = await lstat(absolutePath);
    if (
      !postReadStat.isFile() ||
      !sameFileSnapshot(openedStat, afterReadStat) ||
      !sameFileSnapshot(openedStat, postReadStat) ||
      bytes.byteLength !== openedStat.size
    ) {
      throw new Error(`browser module changed during governed read: ${absolutePath}`);
    }
    const postReadPath = await realpath(absolutePath);
    if (postReadPath !== canonicalPath) {
      throw new Error(`browser module path changed during governed read: ${absolutePath}`);
    }
    let source;
    try {
      source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new Error(`browser module is not valid UTF-8: ${absolutePath}`);
    }
    return { path: canonicalPath, source, bytes: bytes.byteLength };
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

function jsonStrings(value, values = []) {
  if (typeof value === "string") {
    values.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) jsonStrings(item, values);
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      values.push(key);
      jsonStrings(item, values);
    }
  }
  return values;
}

export function findBrowserArtifactBoundaryViolations(path, source) {
  const extension = extname(path).toLowerCase();
  let analyzedValues;
  let javascriptCapabilities;
  if (extension === ".css") {
    const imports = cssImports(path, source);
    if (imports.length > 0) {
      throw new Error(`built CSS imports are not governed in ${path}`);
    }
    analyzedValues = [source];
  } else if (extension === ".html") {
    parseGovernedHtmlEdges(path, source);
    analyzedValues = [source];
  } else if (extension === ".json") {
    let parsed;
    try {
      parsed = JSON.parse(source);
    } catch {
      throw new Error(`browser JSON is invalid in ${path}`);
    }
    analyzedValues = jsonStrings(parsed);
  } else if ([".js", ".mjs", ".cjs"].includes(extension)) {
    javascriptCapabilities = classifyBrowserJavaScriptCapabilities(path, source);
    analyzedValues = [source, ...javascriptCapabilities.externalDestinations];
  } else {
    throw new Error(`browser artifact type is not governed: ${path}`);
  }

  const analyzedText = analyzedValues.join("\n");
  const rules = new Set();
  if (PROVIDER_OR_INFRASTRUCTURE.test(analyzedText)) {
    rules.add("provider-or-infrastructure");
  }
  if (
    (!javascriptCapabilities && DIRECT_BROWSER_NETWORK.test(analyzedText)) ||
    javascriptCapabilities?.unsafeExternalDestinations.length > 0 ||
    javascriptCapabilities?.unsafeIndirectNetworkAccesses > 0 ||
    javascriptCapabilities?.unsafeIndirectResourceAccesses > 0 ||
    javascriptCapabilities?.unsafeStaticResourceTargets.length > 0 ||
    javascriptCapabilities?.unsafeStaticNetworkTargets.length > 0 ||
    (!javascriptCapabilities && analyzedValues.some(containsExternalDestination))
  ) {
    rules.add("direct-browser-network");
  }
  if (DEVLANE_ONTOLOGY.test(analyzedText)) rules.add("devlane-ontology");
  return [...rules].sort();
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
  if (source.includes("&")) {
    throw new Error(
      `HTML character references are not governed browser content in ${path}`,
    );
  }
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
    for (const value of token.attributes.values()) {
      if (typeof value === "string" && containsExternalDestination(value)) {
        throw new Error(`external HTML destination is not governed in ${path}`);
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
  if (!node) return undefined;
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
    ts.isIdentifier(node.expression.expression) &&
    node.expression.expression.text === "String" &&
    ["fromCharCode", "fromCodePoint"].includes(node.expression.name.text)
  ) {
    const values = node.arguments.map((argument) =>
      staticNumber(argument, bindings, seen),
    );
    if (values.some((value) => value === undefined)) return undefined;
    try {
      const value = String[node.expression.name.text](...values);
      return value.length <= MAX_STATIC_STRING_LENGTH ? value : undefined;
    } catch {
      return undefined;
    }
  }
  if (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    DYNAMIC_STRING_IDENTIFIERS.has(node.expression.text) &&
    node.arguments.length === 1
  ) {
    const input = staticString(node.arguments[0], bindings, seen);
    if (input === undefined) return undefined;
    try {
      let value;
      if (node.expression.text === "atob") {
        if (
          !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
            input,
          )
        ) {
          return undefined;
        }
        value = Buffer.from(input, "base64").toString("latin1");
      } else if (node.expression.text === "decodeURI") {
        value = decodeURI(input);
      } else if (node.expression.text === "decodeURIComponent") {
        value = decodeURIComponent(input);
      } else {
        value = unescape(input);
      }
      return value.length <= MAX_STATIC_STRING_LENGTH ? value : undefined;
    } catch {
      return undefined;
    }
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
    node.arguments.length <= 1
  ) {
    const elements = staticStringArray(
      node.expression.expression,
      bindings,
      seen,
    );
    const separator = node.arguments.length === 0
      ? ","
      : staticString(node.arguments[0], bindings, seen);
    if (separator === undefined || elements === undefined) {
      return undefined;
    }
    const value = elements.join(separator);
    return value.length <= MAX_STATIC_STRING_LENGTH ? value : undefined;
  }
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression)
  ) {
    const receiver = staticString(node.expression.expression, bindings, seen);
    if (receiver === undefined) return undefined;
    const name = node.expression.name.text;
    const stringArguments = node.arguments.map((argument) =>
      staticString(argument, bindings, seen),
    );
    const numericArguments = node.arguments.map((argument) =>
      staticNumber(argument, bindings, seen),
    );
    try {
      let value;
      if (
        [
          "toLowerCase",
          "toLocaleLowerCase",
          "toUpperCase",
          "toLocaleUpperCase",
        ].includes(name) &&
        node.arguments.length === 0
      ) {
        value = receiver[name]();
      } else if (
        ["slice", "substring", "substr", "repeat"].includes(name) &&
        numericArguments.every((argument) => argument !== undefined)
      ) {
        value = receiver[name](...numericArguments);
      } else if (
        ["replace", "replaceAll"].includes(name) &&
        stringArguments.every((argument) => argument !== undefined)
      ) {
        value = receiver[name](...stringArguments);
      }
      return typeof value === "string" && value.length <= MAX_STATIC_STRING_LENGTH
        ? value
        : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function staticNumber(node, bindings = new Map(), seen = new Set()) {
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (ts.isIdentifier(node) && bindings.has(node.text) && !seen.has(node.text)) {
    return staticNumber(
      bindings.get(node.text),
      bindings,
      new Set([...seen, node.text]),
    );
  }
  if (
    ts.isParenthesizedExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isTypeAssertionExpression(node) ||
    ts.isNonNullExpression(node)
  ) {
    return staticNumber(node.expression, bindings, seen);
  }
  if (ts.isPrefixUnaryExpression(node)) {
    const value = staticNumber(node.operand, bindings, seen);
    if (value === undefined) return undefined;
    if (node.operator === ts.SyntaxKind.PlusToken) return value;
    if (node.operator === ts.SyntaxKind.MinusToken) return -value;
  }
  return undefined;
}

function staticStringArray(node, bindings = new Map(), seen = new Set()) {
  if (ts.isIdentifier(node) && bindings.has(node.text) && !seen.has(node.text)) {
    return staticStringArray(
      bindings.get(node.text),
      bindings,
      new Set([...seen, node.text]),
    );
  }
  if (
    ts.isParenthesizedExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isTypeAssertionExpression(node) ||
    ts.isNonNullExpression(node)
  ) {
    return staticStringArray(node.expression, bindings, seen);
  }
  if (ts.isArrayLiteralExpression(node)) {
    const values = node.elements.map((element) =>
      staticString(element, bindings, seen),
    );
    return values.some((value) => value === undefined) ? undefined : values;
  }
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    ["reverse", "toReversed"].includes(node.expression.name.text) &&
    node.arguments.length === 0
  ) {
    const values = staticStringArray(node.expression.expression, bindings, seen);
    return values ? [...values].reverse() : undefined;
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
      ts.isMetaProperty(node) &&
      node.keywordToken === ts.SyntaxKind.ImportKeyword
    ) {
      throw new Error(`Vite import.meta APIs are not governed browser edges in ${path}`);
    }
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
  if ([".ts", ".tsx", ".js", ".jsx", ".mjs"].includes(extname(path))) {
    return scriptImports(path, source);
  }
  throw new Error(`browser module type is not governed: ${path}`);
}

function memberName(node, bindings) {
  if (!node) return undefined;
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node)) {
    return staticString(node.argumentExpression, bindings);
  }
  return undefined;
}

function unwrappedExpression(node, bindings, seen = new Set()) {
  if (!node) return undefined;
  if (ts.isIdentifier(node) && bindings.has(node.text) && !seen.has(node.text)) {
    return unwrappedExpression(
      bindings.get(node.text),
      bindings,
      new Set([...seen, node.text]),
    );
  }
  if (
    ts.isParenthesizedExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isTypeAssertionExpression(node) ||
    ts.isNonNullExpression(node)
  ) {
    return unwrappedExpression(node.expression, bindings, seen);
  }
  return node;
}

function isBrowserGlobalExpression(node, bindings) {
  const unwrapped = unwrappedExpression(node, bindings);
  if (!unwrapped) return false;
  if (ts.isIdentifier(unwrapped)) {
    return BROWSER_GLOBAL_IDENTIFIERS.has(unwrapped.text);
  }
  if (
    (ts.isPropertyAccessExpression(unwrapped) ||
      ts.isElementAccessExpression(unwrapped)) &&
    isBrowserGlobalExpression(unwrapped.expression, bindings)
  ) {
    const property = memberName(unwrapped, bindings);
    return property !== undefined && BROWSER_GLOBAL_IDENTIFIERS.has(property);
  }
  return false;
}

function isReflectExpression(node, bindings) {
  const unwrapped = unwrappedExpression(node, bindings);
  return ts.isIdentifier(unwrapped) && unwrapped.text === "Reflect";
}

function hasNamedImport(sourceFile, moduleName, importedName) {
  return sourceFile.statements.some(
    (statement) =>
      ts.isImportDeclaration(statement) &&
      ts.isStringLiteral(statement.moduleSpecifier) &&
      statement.moduleSpecifier.text === moduleName &&
      statement.importClause?.namedBindings &&
      ts.isNamedImports(statement.importClause.namedBindings) &&
      statement.importClause.namedBindings.elements.some(
        (element) =>
          (element.propertyName?.text ?? element.name.text) === importedName &&
          element.name.text === importedName,
      ),
  );
}

function isAssignmentOperator(kind) {
  return (
    kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment
  );
}

function jsxAttributeValue(attribute, bindings) {
  if (!attribute.initializer) return "";
  if (ts.isStringLiteral(attribute.initializer)) {
    let invalid = false;
    const decoded = attribute.initializer.text.replace(
      /&#(?:x([0-9A-Fa-f]+)|([0-9]+));?/gu,
      (reference, hexadecimal, decimal) => {
        const codePoint = Number.parseInt(
          hexadecimal ?? decimal,
          hexadecimal ? 16 : 10,
        );
        if (
          !Number.isSafeInteger(codePoint) ||
          codePoint === 0 ||
          codePoint > 0x10ffff ||
          (codePoint >= 0xd800 && codePoint <= 0xdfff)
        ) {
          invalid = true;
          return reference;
        }
        return String.fromCodePoint(codePoint);
      },
    );
    if (invalid || /&(?:#|[A-Za-z][A-Za-z0-9]+);/u.test(decoded)) {
      return undefined;
    }
    return decoded;
  }
  if (
    ts.isJsxExpression(attribute.initializer) &&
    attribute.initializer.expression
  ) {
    return staticString(attribute.initializer.expression, bindings);
  }
  return undefined;
}

function isDynamicStringConstruction(node, bindings) {
  if (
    ts.isIdentifier(node) &&
    DYNAMIC_STRING_IDENTIFIERS.has(node.text) &&
    !(
      ts.isCallExpression(node.parent) &&
      node.parent.expression === node &&
      staticString(node.parent, bindings) !== undefined
    )
  ) {
    return true;
  }
  return (
    ts.isPropertyAccessExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === "String" &&
    ["fromCharCode", "fromCodePoint"].includes(node.name.text) &&
    !(
      ts.isCallExpression(node.parent) &&
      node.parent.expression === node &&
      staticString(node.parent, bindings) !== undefined
    )
  );
}

function scriptBoundaryRules(path, source) {
  const sourceFile = scriptSourceFile(path, source);
  const bindings = staticConstBindings(sourceFile);
  const staticValues = [];
  let directNetwork = false;
  let dynamicBoundaryConstruction = false;
  const approvedInternalNavigationImport =
    path.endsWith(
      [sep, "apps", sep, "web", sep, "src", sep, "AppShell.tsx"].join(""),
    ) && hasNamedImport(sourceFile, "./routes", "internalNavigationHref");
  const approvedGovernedDomSpread =
    path.endsWith(
      [
        sep,
        "packages",
        sep,
        "design-system",
        sep,
        "src",
        sep,
        "primitives.tsx",
      ].join(""),
    ) &&
    sourceFile.statements.some(
      (statement) =>
        ts.isFunctionDeclaration(statement) &&
        statement.name?.text === "governedDomProperties",
    );
  const approvedPlatformFetchReference = (node) =>
    path.endsWith(`${sep}packages${sep}api-client${sep}src${sep}client.ts`) &&
    ts.isPropertyAccessExpression(node) &&
    node.expression.getText(sourceFile) === "globalThis" &&
    node.name.text === "fetch" &&
    node.parent?.getText(sourceFile) ===
      "options.fetchImplementation ?? globalThis.fetch";
  const approvedInternalNavigationReference = (attribute) => {
    if (
      !approvedInternalNavigationImport ||
      !attribute.initializer ||
      !ts.isJsxExpression(attribute.initializer) ||
      !attribute.initializer.expression
    ) {
      return false;
    }
    const expression = unwrappedExpression(
      attribute.initializer.expression,
      bindings,
    );
    return (
      ts.isCallExpression(expression) &&
      expression.arguments.length === 1 &&
      ts.isIdentifier(expression.expression) &&
      expression.expression.text === "internalNavigationHref"
    );
  };
  const approvedDomSpreadReference = (attribute) => {
    if (!approvedGovernedDomSpread || !ts.isJsxSpreadAttribute(attribute)) {
      return false;
    }
    const expression = unwrappedExpression(attribute.expression, bindings);
    return (
      ts.isCallExpression(expression) &&
      expression.arguments.length === 1 &&
      ts.isIdentifier(expression.expression) &&
      expression.expression.text === "governedDomProperties"
    );
  };
  const visit = (node) => {
    const value = staticString(node, bindings);
    if (value !== undefined) staticValues.push(value);
    if (isDynamicStringConstruction(node, bindings)) {
      dynamicBoundaryConstruction = true;
    }
    if (
      ts.isIdentifier(node) &&
      DYNAMIC_CODE_IDENTIFIERS.has(node.text)
    ) {
      directNetwork = true;
    }
    if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.initializer &&
      isBrowserGlobalExpression(node.initializer, bindings)
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
      (DYNAMIC_CODE_PROPERTIES.has(node.name.text) ||
        (DIRECT_NETWORK_IDENTIFIERS.has(node.name.text) &&
          !approvedPlatformFetchReference(node)))
    ) {
      directNetwork = true;
    }
    if (ts.isElementAccessExpression(node)) {
      const property = staticString(node.argumentExpression, bindings);
      if (
        isBrowserGlobalExpression(node.expression, bindings) ||
        (property !== undefined &&
          (DIRECT_NETWORK_IDENTIFIERS.has(property) ||
            DYNAMIC_CODE_IDENTIFIERS.has(property) ||
            DYNAMIC_CODE_PROPERTIES.has(property) ||
            RESOURCE_PROPERTY_NAMES.has(property)))
      ) {
        directNetwork = true;
      }
    }
    if (
      ts.isBinaryExpression(node) &&
      isAssignmentOperator(node.operatorToken.kind)
    ) {
      const property = memberName(node.left, bindings);
      if (
        (ts.isIdentifier(node.left) && node.left.text === "location") ||
        property === "location" ||
        (property !== undefined && RESOURCE_PROPERTY_NAMES.has(property))
      ) {
        directNetwork = true;
      }
    }
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const expression = unwrappedExpression(node.expression, bindings);
      const calledName = memberName(expression, bindings);
      if (
        (ts.isIdentifier(expression) &&
          (DIRECT_NETWORK_IDENTIFIERS.has(expression.text) ||
            expression.text === "open")) ||
        (calledName !== undefined &&
          (DIRECT_NETWORK_IDENTIFIERS.has(calledName) ||
            calledName === "open" ||
            RESOURCE_METHOD_NAMES.has(calledName)))
      ) {
        directNetwork = true;
      }
      if (
        ts.isCallExpression(node) &&
        (ts.isPropertyAccessExpression(expression) ||
          ts.isElementAccessExpression(expression))
      ) {
        const receiver = expression.expression;
        const callThroughTarget = CALL_THROUGH_METHODS.has(calledName ?? "")
          ? unwrappedExpression(receiver, bindings)
          : undefined;
        const callThroughName = callThroughTarget
          ? memberName(callThroughTarget, bindings) ??
            (ts.isIdentifier(callThroughTarget)
              ? callThroughTarget.text
              : undefined)
          : undefined;
        if (
          ((calledName === "get" || calledName === "set") &&
            isReflectExpression(receiver, bindings)) ||
          ([
            "apply",
            "construct",
            "defineProperty",
            "deleteProperty",
            "getOwnPropertyDescriptor",
            "getPrototypeOf",
            "has",
            "isExtensible",
            "ownKeys",
            "preventExtensions",
            "setPrototypeOf",
          ].includes(calledName ?? "") &&
            isReflectExpression(receiver, bindings) &&
            node.arguments[0] &&
            isBrowserGlobalExpression(node.arguments[0], bindings)) ||
          (["getOwnPropertyDescriptor", "getOwnPropertyDescriptors"].includes(
            calledName ?? "",
          ) &&
            ts.isIdentifier(receiver) &&
            receiver.text === "Object" &&
            node.arguments[0] &&
            isBrowserGlobalExpression(node.arguments[0], bindings)) ||
          (LOCATION_METHOD_NAMES.has(calledName ?? "") &&
            (isBrowserGlobalExpression(receiver, bindings) ||
              memberName(receiver, bindings) === "location")) ||
          (callThroughName !== undefined &&
            (DIRECT_NETWORK_IDENTIFIERS.has(callThroughName) ||
              RESOURCE_METHOD_NAMES.has(callThroughName) ||
              RESOURCE_PROPERTY_NAMES.has(callThroughName) ||
              LOCATION_METHOD_NAMES.has(callThroughName))) ||
          (["write", "writeln"].includes(calledName ?? "") &&
            isBrowserGlobalExpression(receiver, bindings))
        ) {
          directNetwork = true;
        }
      }
    }
    if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
      const tag = node.tagName.getText(sourceFile);
      if (/^[a-z]/u.test(tag) && RESOURCE_JSX_ELEMENTS.has(tag.toLowerCase())) {
        directNetwork = true;
      }
      for (const attribute of node.attributes.properties) {
        if (!ts.isJsxAttribute(attribute)) {
          if (!approvedDomSpreadReference(attribute)) directNetwork = true;
          continue;
        }
        const name = attribute.name.getText(sourceFile);
        const normalizedName = name.toLowerCase();
        const attributeValue = jsxAttributeValue(attribute, bindings);
        if (
          name === "dangerouslySetInnerHTML" ||
          name === "style" ||
          (HTML_RESOURCE_ATTRIBUTES.has(normalizedName) &&
            !(
              tag.toLowerCase() === "a" &&
              normalizedName === "href" &&
              (attributeValue !== undefined ||
                approvedInternalNavigationReference(attribute))
            )) ||
          (attributeValue !== undefined &&
            containsExternalDestination(attributeValue))
        ) {
          directNetwork = true;
        }
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
      containsExternalDestination(value) &&
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
  if (dynamicBoundaryConstruction) rules.add("dynamic-boundary-construction");
  if (DEVLANE_ONTOLOGY.test(analyzedText)) rules.add("devlane-ontology");
  return rules;
}

function approvedBuiltNetworkTarget(value) {
  return value === "/api/v1" || value.startsWith("/api/v1/");
}

function approvedBuiltResourceTarget(value) {
  return (
    value === "" ||
    value.startsWith("#") ||
    (value.startsWith("/") && !value.startsWith("//")) ||
    value.startsWith("./") ||
    value.startsWith("../")
  );
}

function staticResourceCallTarget(arguments_, calledName, bindings) {
  if (LOCATION_METHOD_NAMES.has(calledName)) {
    return { isSink: true, value: staticString(arguments_[0], bindings) };
  }
  if (calledName === "setAttribute") {
    const attribute = staticString(arguments_[0], bindings)?.toLowerCase();
    return HTML_RESOURCE_ATTRIBUTES.has(attribute)
      ? { isSink: true, value: staticString(arguments_[1], bindings) }
      : { isSink: false };
  }
  if (calledName === "setAttributeNS") {
    const attribute = staticString(arguments_[1], bindings)?.toLowerCase();
    return HTML_RESOURCE_ATTRIBUTES.has(attribute)
      ? { isSink: true, value: staticString(arguments_[2], bindings) }
      : { isSink: false };
  }
  return { isSink: false };
}

function staticCallArguments(node, index, bindings) {
  const argumentList = unwrappedExpression(node.arguments?.[index], bindings);
  return argumentList && ts.isArrayLiteralExpression(argumentList)
    ? [...argumentList.elements]
    : [];
}

export function classifyBrowserJavaScriptCapabilities(path, source) {
  const sourceFile = scriptSourceFile(path, source);
  const bindings = staticConstBindings(sourceFile);
  let dynamicResourceTargets = 0;
  const staticResourceTargets = new Set();
  const staticNetworkTargets = new Set();
  let dynamicNetworkCalls = 0;
  let indirectNetworkAccesses = 0;
  let indirectResourceAccesses = 0;
  let networkCalls = 0;
  let resourceMethodCalls = 0;

  const visit = (node) => {
    if (
      ts.isBinaryExpression(node) &&
      isAssignmentOperator(node.operatorToken.kind)
    ) {
      const property = memberName(node.left, bindings)?.toLowerCase();
      if (
        (ts.isIdentifier(node.left) && node.left.text === "location") ||
        property === "location" ||
        (property !== undefined &&
          [...RESOURCE_PROPERTY_NAMES].some(
            (candidate) => candidate.toLowerCase() === property,
          ))
      ) {
        const target = staticString(node.right, bindings);
        if (target === undefined) dynamicResourceTargets += 1;
        else staticResourceTargets.add(target);
      }
    }
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const expression = unwrappedExpression(node.expression, bindings);
      let calledName = memberName(expression, bindings) ??
        (ts.isIdentifier(expression) ? expression.text : undefined);
      let callArguments = [...(node.arguments ?? [])];
      let indirect = false;
      if (
        ts.isCallExpression(node) &&
        (ts.isPropertyAccessExpression(expression) ||
          ts.isElementAccessExpression(expression)) &&
        !isReflectExpression(expression.expression, bindings) &&
        CALL_THROUGH_METHODS.has(calledName ?? "")
      ) {
        const callThroughMethod = calledName;
        const target = unwrappedExpression(expression.expression, bindings);
        calledName = memberName(target, bindings) ??
          (ts.isIdentifier(target) ? target.text : undefined);
        callArguments = callThroughMethod === "apply"
          ? staticCallArguments(node, 1, bindings)
          : callArguments.slice(1);
        indirect = true;
      } else if (
        ts.isCallExpression(node) &&
        (ts.isPropertyAccessExpression(expression) ||
          ts.isElementAccessExpression(expression)) &&
        isReflectExpression(expression.expression, bindings) &&
        ["apply", "construct"].includes(calledName ?? "")
      ) {
        const target = unwrappedExpression(node.arguments[0], bindings);
        calledName = memberName(target, bindings) ??
          (ts.isIdentifier(target) ? target.text : undefined);
        callArguments = staticCallArguments(node, 2, bindings);
        indirect = true;
      } else if (
        ts.isCallExpression(node) &&
        (ts.isPropertyAccessExpression(expression) ||
          ts.isElementAccessExpression(expression)) &&
        isReflectExpression(expression.expression, bindings) &&
        calledName === "get"
      ) {
        const reflectedName = staticString(node.arguments[1], bindings);
        if (
          node.arguments[0] &&
          isBrowserGlobalExpression(node.arguments[0], bindings) &&
          reflectedName &&
          DIRECT_NETWORK_IDENTIFIERS.has(reflectedName)
        ) {
          networkCalls += 1;
          dynamicNetworkCalls += 1;
          indirectNetworkAccesses += 1;
        } else if (
          reflectedName &&
          (RESOURCE_PROPERTY_NAMES.has(reflectedName) ||
            RESOURCE_METHOD_NAMES.has(reflectedName) ||
            LOCATION_METHOD_NAMES.has(reflectedName))
        ) {
          resourceMethodCalls += 1;
          dynamicResourceTargets += 1;
          indirectResourceAccesses += 1;
        }
        calledName = undefined;
      }
      if (calledName && DIRECT_NETWORK_IDENTIFIERS.has(calledName)) {
        networkCalls += 1;
        if (indirect) indirectNetworkAccesses += 1;
        const target = callArguments[0]
          ? staticString(callArguments[0], bindings)
          : undefined;
        if (target === undefined) dynamicNetworkCalls += 1;
        else staticNetworkTargets.add(target);
      }
      if (
        calledName &&
        (RESOURCE_METHOD_NAMES.has(calledName) ||
          LOCATION_METHOD_NAMES.has(calledName))
      ) {
        resourceMethodCalls += 1;
        if (indirect) indirectResourceAccesses += 1;
        const target = staticResourceCallTarget(
          callArguments,
          calledName,
          bindings,
        );
        if (target.isSink) {
          if (target.value === undefined) dynamicResourceTargets += 1;
          else staticResourceTargets.add(target.value);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);

  const sortedStaticResourceTargets = [...staticResourceTargets].sort();
  const sortedStaticNetworkTargets = [...staticNetworkTargets].sort();
  const externalDestinations = [
    ...new Set(
      [...sortedStaticNetworkTargets, ...sortedStaticResourceTargets].filter(
        containsExternalDestination,
      ),
    ),
  ].sort();
  return {
    dynamicResourceTargets,
    dynamicNetworkCalls,
    externalDestinations,
    indirectNetworkAccesses,
    indirectResourceAccesses,
    networkCalls,
    resourceMethodCalls,
    staticResourceTargets: sortedStaticResourceTargets,
    staticNetworkTargets: sortedStaticNetworkTargets,
    unsafeExternalDestinations: externalDestinations,
    unsafeIndirectNetworkAccesses: indirectNetworkAccesses,
    unsafeIndirectResourceAccesses: indirectResourceAccesses,
    unsafeStaticResourceTargets: sortedStaticResourceTargets.filter(
      (value) =>
        containsExternalDestination(value) && !approvedBuiltResourceTarget(value),
    ),
    unsafeStaticNetworkTargets: sortedStaticNetworkTargets.filter(
      (value) => !approvedBuiltNetworkTarget(value),
    ),
  };
}

function packageName(specifier) {
  if (specifier.startsWith("@")) return specifier.split("/", 2).join("/");
  return specifier.split("/", 1)[0];
}

export async function collectBrowserSourceGraph({
  entryPath,
  repositoryRoot,
  limits: requestedLimits,
}) {
  const root = await canonicalRepositoryRoot(repositoryRoot);
  const limits = sourceLimits(requestedLimits);
  const pending = [{ path: resolve(entryPath), depth: 0 }];
  const modules = new Map();
  const externalPackages = new Set();
  let aggregateBytes = 0;

  while (pending.length > 0) {
    const { path, depth } = pending.pop();
    if (modules.has(path)) continue;
    if (depth > limits.maxDepth) {
      throw new Error(`browser module graph exceeds the depth ceiling at ${path}`);
    }
    if (modules.size >= limits.maxModules) {
      throw new Error(`browser module graph exceeds the module-count ceiling`);
    }
    if (!insideRoot(path, root)) {
      throw new Error(`browser module escapes the repository: ${path}`);
    }
    const found = await existingGovernedFile(path, root);
    if (!found) throw new Error(`browser entry/module does not exist: ${path}`);
    if (found.bytes > limits.maxFileBytes) {
      throw new Error(`browser module exceeds the file-size ceiling: ${path}`);
    }
    aggregateBytes += found.bytes;
    if (aggregateBytes > limits.maxAggregateBytes) {
      throw new Error(`browser module graph exceeds the aggregate-byte ceiling`);
    }
    const imports = moduleImports(path, found.source);
    if (imports.length > limits.maxImportsPerModule) {
      throw new Error(`browser module exceeds the import-count ceiling: ${path}`);
    }
    modules.set(path, { path, source: found.source, imports, bytes: found.bytes, depth });
    for (const specifier of imports) {
      if (specifier.startsWith(".")) {
        const imported = await resolveLocalImport(path, specifier, root);
        pending.push({ path: imported.path, depth: depth + 1 });
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
    aggregateBytes,
    limits,
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
