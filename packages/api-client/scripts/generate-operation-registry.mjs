import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "../../..");
const sourcePath = resolve(repositoryRoot, "specs/openapi/platform-v1.yaml");
const outputPath = resolve(
  repositoryRoot,
  "packages/api-client/src/generated/platform-v1.ts",
);

const source = await readFile(sourcePath, "utf8");
const sourceSha256 = createHash("sha256").update(source).digest("hex");
const contract = parse(source);
if (!contract?.info?.version) {
  throw new Error("the Platform OpenAPI contract has no info.version");
}

const documents = new Map([[sourcePath, contract]]);

function jsonPointer(document, pointer, reference) {
  if (!pointer) return document;
  if (!pointer.startsWith("/")) {
    throw new Error(`unsupported JSON pointer in ${reference}`);
  }
  return pointer
    .slice(1)
    .split("/")
    .map((segment) => segment.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((value, segment) => {
      if (value === null || typeof value !== "object" || !(segment in value)) {
        throw new Error(`unresolved JSON pointer ${reference}`);
      }
      return value[segment];
    }, document);
}

async function readDocument(path) {
  if (documents.has(path)) return documents.get(path);
  const text = await readFile(path, "utf8");
  const document = path.endsWith(".json") ? JSON.parse(text) : parse(text);
  documents.set(path, document);
  return document;
}

async function dereference(value, documentPath = sourcePath, stack = new Set()) {
  if (Array.isArray(value)) {
    return Promise.all(value.map((item) => dereference(item, documentPath, stack)));
  }
  if (value === null || typeof value !== "object") return value;
  if (typeof value.$ref === "string") {
    const [relativePath, pointer = ""] = value.$ref.split("#", 2);
    const targetPath = relativePath
      ? resolve(dirname(documentPath), relativePath)
      : documentPath;
    const identity = `${targetPath}#${pointer}`;
    if (stack.has(identity)) {
      throw new Error(`recursive request schema reference ${identity}`);
    }
    const targetDocument = await readDocument(targetPath);
    const target = jsonPointer(targetDocument, pointer, value.$ref);
    const nextStack = new Set(stack);
    nextStack.add(identity);
    const resolved = await dereference(target, targetPath, nextStack);
    const siblings = Object.fromEntries(
      Object.entries(value).filter(([key]) => key !== "$ref"),
    );
    if (Object.keys(siblings).length === 0) return resolved;
    return {
      ...resolved,
      ...(await dereference(siblings, documentPath, stack)),
    };
  }
  return Object.fromEntries(
    await Promise.all(
      Object.entries(value).map(async ([key, nested]) => [
        key,
        await dereference(nested, documentPath, stack),
      ]),
    ),
  );
}

const HEADER_OPTION_NAMES = new Map([
  ["If-Match", "ifMatch"],
  ["Idempotency-Key", "idempotencyKey"],
]);
const SUPPORTED_REQUEST_SCHEMA_KEYWORDS = new Set([
  "type",
  "const",
  "enum",
  "pattern",
  "format",
  "minLength",
  "minimum",
  "maximum",
  "minItems",
  "minProperties",
  "required",
  "properties",
  "propertyNames",
  "additionalProperties",
  "unevaluatedProperties",
  "items",
  "uniqueItems",
  "oneOf",
  "allOf",
  "description",
]);
const SUPPORTED_SCHEMA_FORMATS = new Set([
  "date-time",
  "uri",
  "uri-reference",
]);

function assertSupportedRequestSchema(schema, location) {
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
    throw new Error(`${location} is not an object schema`);
  }
  for (const keyword of Object.keys(schema)) {
    if (!SUPPORTED_REQUEST_SCHEMA_KEYWORDS.has(keyword)) {
      throw new Error(`${location} uses unsupported schema keyword ${keyword}`);
    }
  }
  if (schema.type !== undefined && typeof schema.type !== "string") {
    throw new Error(`${location} uses an unsupported compound type`);
  }
  if (
    schema.additionalProperties !== undefined &&
    typeof schema.additionalProperties !== "boolean"
  ) {
    throw new Error(`${location} uses an unsupported additionalProperties schema`);
  }
  if (
    schema.unevaluatedProperties !== undefined &&
    typeof schema.unevaluatedProperties !== "boolean"
  ) {
    throw new Error(`${location} uses an unsupported unevaluatedProperties schema`);
  }
  if (schema.format && !SUPPORTED_SCHEMA_FORMATS.has(schema.format)) {
    throw new Error(`${location} uses unsupported format ${schema.format}`);
  }
  for (const [name, nested] of Object.entries(schema.properties ?? {})) {
    assertSupportedRequestSchema(nested, `${location}.properties.${name}`);
  }
  if (schema.propertyNames) {
    assertSupportedRequestSchema(schema.propertyNames, `${location}.propertyNames`);
  }
  if (schema.items) assertSupportedRequestSchema(schema.items, `${location}.items`);
  for (const [index, nested] of (schema.oneOf ?? []).entries()) {
    assertSupportedRequestSchema(nested, `${location}.oneOf[${index}]`);
  }
  for (const [index, nested] of (schema.allOf ?? []).entries()) {
    assertSupportedRequestSchema(nested, `${location}.allOf[${index}]`);
  }
}

async function requestDefinition(pathItem, operation) {
  const parameters = await Promise.all(
    [...(pathItem.parameters ?? []), ...(operation.parameters ?? [])].map(
      (parameter) => dereference(parameter),
    ),
  );
  const request = { path: {}, query: {}, headers: {}, body: null };
  for (const parameter of parameters) {
    if (!parameter.name || !parameter.in || !parameter.schema) {
      throw new Error("every Platform parameter must name its location and schema");
    }
    const schema = await dereference(parameter.schema);
    assertSupportedRequestSchema(
      schema,
      `${operation.operationId}.${parameter.in}.${parameter.name}`,
    );
    if (parameter.in === "path" || parameter.in === "query") {
      request[parameter.in][parameter.name] = {
        required: parameter.in === "path" || parameter.required === true,
        schema,
      };
      continue;
    }
    if (parameter.in === "header") {
      const optionName = HEADER_OPTION_NAMES.get(parameter.name);
      if (!optionName) {
        throw new Error(`unsupported browser header parameter ${parameter.name}`);
      }
      request.headers[optionName] = {
        wireName: parameter.name,
        required: parameter.required === true,
        schema,
        ...(parameter.name === "If-Match" && /strong/iu.test(parameter.description ?? "")
          ? { strongEtag: true }
          : {}),
      };
      continue;
    }
    throw new Error(`unsupported browser parameter location ${parameter.in}`);
  }

  if (operation.requestBody) {
    const body = await dereference(operation.requestBody);
    const mediaTypes = Object.keys(body.content ?? {});
    if (mediaTypes.length !== 1) {
      throw new Error("browser operations must declare exactly one request media type");
    }
    const mediaType = mediaTypes[0];
    const schema = await dereference(body.content[mediaType].schema);
    assertSupportedRequestSchema(schema, `${operation.operationId}.body`);
    request.body = {
      required: body.required === true,
      mediaType,
      schema,
    };
  }
  return request;
}

async function responseDefinition(operation) {
  const successes = [];
  const errors = [];
  for (const [status, rawResponse] of Object.entries(operation.responses ?? {})) {
    const response = await dereference(rawResponse);
    if (/^2[0-9][0-9]$/u.test(status)) {
      successes.push({ status: Number(status), response });
    }
    else errors.push({ status, response });
  }
  if (successes.length === 0) {
    throw new Error(`operation ${operation.operationId} has no success response`);
  }
  const successMediaTypes = [
    ...new Set(
      successes.flatMap(({ response }) => Object.keys(response.content ?? {})),
    ),
  ].sort();
  const errorMediaTypes = [
    ...new Set(
      errors.flatMap(({ response }) => Object.keys(response.content ?? {})),
    ),
  ].sort();
  if (successMediaTypes.length === 0 || errorMediaTypes.length === 0) {
    throw new Error(`operation ${operation.operationId} has an untyped response`);
  }

  const schemaHeaders = successes.map(
    ({ response }) => response.headers?.["Stead-Schema-Version"],
  );
  const declaresSchemaVersion = schemaHeaders.every(Boolean);
  if (!declaresSchemaVersion && schemaHeaders.some(Boolean)) {
    throw new Error(
      `operation ${operation.operationId} inconsistently declares Stead-Schema-Version`,
    );
  }
  const schemaVersion = declaresSchemaVersion
    ? {
        required: true,
        schema: (await dereference(schemaHeaders[0])).schema,
      }
    : null;
  if (schemaVersion) {
    assertSupportedRequestSchema(
      schemaVersion.schema,
      `${operation.operationId}.response.Stead-Schema-Version`,
    );
  }
  const etagHeaders = successes.map(({ response }) => response.headers?.ETag);
  const declaresEtag = etagHeaders.every(Boolean);
  if (!declaresEtag && etagHeaders.some(Boolean)) {
    throw new Error(`operation ${operation.operationId} inconsistently declares ETag`);
  }
  const etag = declaresEtag
    ? {
        schema: (await dereference(etagHeaders[0])).schema,
        strongEtag: /strong/iu.test(etagHeaders[0].description ?? ""),
      }
    : null;
  if (etag) {
    assertSupportedRequestSchema(
      etag.schema,
      `${operation.operationId}.response.ETag`,
    );
  }
  const responseSchemas = async (entries) =>
    Object.fromEntries(
      await Promise.all(
        entries.map(async ({ status, response }) => {
          const schemas = await Promise.all(
            Object.entries(response.content ?? {}).map(
              async ([mediaType, media]) => {
                const schema = await dereference(media.schema);
                assertSupportedRequestSchema(
                  schema,
                  `${operation.operationId}.response.${status}.${mediaType}`,
                );
                return [mediaType, schema];
              },
            ),
          );
          return [String(status), Object.fromEntries(schemas)];
        }),
      ),
    );
  const compatibleSchemaMajor =
    contract["x-stead-versioning"]?.compatible_schema_major;
  if (!Number.isInteger(compatibleSchemaMajor)) {
    throw new Error("x-stead-versioning.compatible_schema_major must be an integer");
  }
  return {
    successStatuses: successes.map(({ status }) => status).sort((left, right) => left - right),
    successMediaTypes,
    errorMediaTypes,
    successSchemas: await responseSchemas(successes),
    errorSchemas: await responseSchemas(errors),
    schemaVersion,
    etag,
    compatibleSchemaMajor,
  };
}

const operations = [];
for (const [path, pathItem] of Object.entries(contract.paths ?? {})) {
  for (const method of ["get", "post", "put", "patch", "delete"]) {
    const operation = pathItem[method];
    if (!operation) continue;
    if (!operation.operationId) {
      throw new Error(`${method.toUpperCase()} ${path} has no operationId`);
    }
    operations.push({
      id: operation.operationId,
      method: method.toUpperCase(),
      path,
      request: await requestDefinition(pathItem, operation),
      response: await responseDefinition(operation),
    });
  }
}
if (operations.length === 0) {
  throw new Error("the Platform OpenAPI contract contains no operations");
}
const operationIds = new Set();
for (const operation of operations) {
  if (operationIds.has(operation.id)) {
    throw new Error(`duplicate operationId ${operation.id}`);
  }
  operationIds.add(operation.id);
}

const renderedOperations = operations
  .map(
    ({ id, method, path, request, response }) =>
      `  ${JSON.stringify(id)}: ${JSON.stringify({ method, path, request, response })},`,
  )
  .join("\n");

const output = `// Generated by packages/api-client/scripts/generate-operation-registry.mjs.
// Source: specs/openapi/platform-v1.yaml
// Source SHA-256: ${sourceSha256}
// Do not edit by hand. Request constraints and transport response envelopes are
// generated from the canonical Platform contract; response data stays unknown.

export const PLATFORM_API_BASE_PATH = "/api/v1" as const;
export const PLATFORM_OPENAPI_VERSION = ${JSON.stringify(contract.info.version)} as const;
export const PLATFORM_OPENAPI_SOURCE_SHA256 = ${JSON.stringify(sourceSha256)} as const;

function deepFreezeGeneratedContract<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreezeGeneratedContract(child);
    }
    Object.freeze(value as object);
  }
  return value;
}

export const operationDefinitions = deepFreezeGeneratedContract({
${renderedOperations}
} as const);

export type PlatformOperationId = keyof typeof operationDefinitions;
export type PlatformOperationDefinition =
  (typeof operationDefinitions)[PlatformOperationId];
`;

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, output, "utf8");
