import {
  operationDefinitions,
  PLATFORM_API_BASE_PATH,
  type PlatformOperationId,
} from "./generated/platform-v1.ts";

export type JsonPrimitive = boolean | number | string | null;
export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export interface PlatformRequestOptions {
  readonly path?: Readonly<Record<string, string>>;
  readonly query?: Readonly<
    Record<string, boolean | number | string | readonly string[] | undefined>
  >;
  readonly body?: JsonValue;
  readonly ifMatch?: string;
  readonly idempotencyKey?: string;
  readonly signal?: AbortSignal;
}

export interface PlatformResponse<TData> {
  readonly data: TData;
  readonly status: number;
  readonly etag?: string;
  readonly schemaVersion?: string;
  readonly correlationId?: string;
  readonly responseBytes: number;
}

export interface NetworkObservation {
  readonly operationId: PlatformOperationId;
  readonly durationMs: number;
  readonly responseBytes: number;
  readonly status: number;
}

export interface PlatformClientOptions {
  readonly basePath?: string;
  readonly fetchImplementation?: typeof fetch;
  readonly observeNetwork?: (observation: NetworkObservation) => void;
}

export interface PlatformClient {
  request<TData = unknown>(
    operationId: PlatformOperationId,
    options?: PlatformRequestOptions,
  ): Promise<PlatformResponse<TData>>;
}

export class PlatformApiError extends Error {
  readonly status: number;
  readonly correlationId?: string;
  readonly retryable: boolean;

  constructor(status: number, correlationId?: string) {
    super("The request could not be completed.");
    this.name = "PlatformApiError";
    this.status = status;
    this.correlationId = correlationId;
    this.retryable = status === 408 || status === 429 || status >= 500;
  }
}

interface JsonSchema {
  readonly type?: string;
  readonly const?: unknown;
  readonly enum?: readonly unknown[];
  readonly pattern?: string;
  readonly minLength?: number;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly minProperties?: number;
  readonly required?: readonly string[];
  readonly properties?: Readonly<Record<string, JsonSchema>>;
  readonly additionalProperties?: boolean;
  readonly items?: JsonSchema;
  readonly uniqueItems?: boolean;
  readonly oneOf?: readonly JsonSchema[];
  readonly allOf?: readonly JsonSchema[];
}

interface ParameterDefinition {
  readonly required: boolean;
  readonly schema: JsonSchema;
}

interface HeaderDefinition extends ParameterDefinition {
  readonly wireName: string;
  readonly strongEtag?: boolean;
}

interface RequestDefinition {
  readonly path: Readonly<Record<string, ParameterDefinition>>;
  readonly query: Readonly<Record<string, ParameterDefinition>>;
  readonly headers: Readonly<Record<string, HeaderDefinition>>;
  readonly body: {
    readonly required: boolean;
    readonly mediaType: string;
    readonly schema: JsonSchema;
  } | null;
}

interface ResponseDefinition {
  readonly successMediaTypes: readonly string[];
  readonly errorMediaTypes: readonly string[];
  readonly compatibleSchemaMajor: number;
  readonly schemaVersion: {
    readonly required: boolean;
    readonly schema: JsonSchema;
  } | null;
  readonly etag: {
    readonly schema: JsonSchema;
    readonly strongEtag: boolean;
  } | null;
}

interface OperationDefinition {
  readonly method: string;
  readonly path: string;
  readonly request: RequestDefinition;
  readonly response: ResponseDefinition;
}

export const PLATFORM_MAX_RESPONSE_BYTES = 1024 * 1024;

const SAFE_CORRELATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const STRONG_ETAG_PATTERN = /^"[\x21\x23-\x7e]*"$/u;
const GENERIC_SCHEMA_VERSION_PATTERN = /^[1-9][0-9]*\.[0-9]+$/u;
const MAX_REQUEST_JSON_DEPTH = 100;
const JSON_STRINGIFY = JSON.stringify;
const REQUEST_OPTION_KEYS = new Set([
  "path",
  "query",
  "body",
  "ifMatch",
  "idempotencyKey",
  "signal",
]);

function assertCanonicalBasePath(basePath: string): void {
  if (
    !basePath.startsWith("/") ||
    basePath.startsWith("//") ||
    basePath.includes("://") ||
    !basePath.endsWith("/api/v1")
  ) {
    throw new Error(
      "The browser client may call only the same-origin Stead /api/v1 boundary.",
    );
  }
}

function schemaMatches(value: unknown, schema: JsonSchema): boolean {
  if (schema.oneOf) {
    if (schema.oneOf.filter((candidate) => schemaMatches(value, candidate)).length !== 1) {
      return false;
    }
  }
  if (schema.allOf?.some((candidate) => !schemaMatches(value, candidate))) {
    return false;
  }
  if ("const" in schema && !Object.is(value, schema.const)) return false;
  if (schema.enum && !schema.enum.some((candidate) => Object.is(value, candidate))) {
    return false;
  }

  if (schema.type === "null" && value !== null) return false;
  if (schema.type === "string" && typeof value !== "string") return false;
  if (schema.type === "integer" && !Number.isInteger(value)) return false;
  if (schema.type === "number" && typeof value !== "number") return false;
  if (schema.type === "boolean" && typeof value !== "boolean") return false;
  if (schema.type === "array" && !Array.isArray(value)) return false;
  if (
    schema.type === "object" &&
    (value === null || typeof value !== "object" || Array.isArray(value))
  ) {
    return false;
  }

  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) return false;
    if (schema.pattern && !new RegExp(schema.pattern, "u").test(value)) return false;
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) return false;
    if (schema.maximum !== undefined && value > schema.maximum) return false;
  }
  if (Array.isArray(value)) {
    if (schema.items && value.some((item) => !schemaMatches(item, schema.items!))) {
      return false;
    }
    if (
      schema.uniqueItems &&
      new Set(value.map((item) => serializeClosedJson(item as JsonValue))).size !==
        value.length
    ) {
      return false;
    }
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Readonly<Record<string, unknown>>;
    const keys = Object.keys(record);
    if (schema.minProperties !== undefined && keys.length < schema.minProperties) {
      return false;
    }
    if (schema.required?.some((name) => !(name in record))) return false;
    if (
      schema.additionalProperties === false &&
      keys.some((name) => !(name in (schema.properties ?? {})))
    ) {
      return false;
    }
    if (
      schema.properties &&
      Object.entries(schema.properties).some(
        ([name, propertySchema]) =>
          name in record && !schemaMatches(record[name], propertySchema),
      )
    ) {
      return false;
    }
  }
  return true;
}

function assertSchema(value: unknown, schema: JsonSchema, field: string): void {
  if (!schemaMatches(value, schema)) {
    throw new Error(`${field} does not satisfy the generated Platform contract`);
  }
}

function cloneJsonValueUnsafe(
  value: unknown,
  ancestors: Set<object>,
  depth: number,
): JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite JSON number");
    return value;
  }
  if (typeof value !== "object" || depth > MAX_REQUEST_JSON_DEPTH) {
    throw new Error("non-JSON value");
  }
  if (ancestors.has(value)) throw new Error("cyclic JSON value");

  const array = Array.isArray(value);
  const prototype = Reflect.getPrototypeOf(value);
  if (
    (array && prototype !== Array.prototype && prototype !== null) ||
    (!array && prototype !== Object.prototype && prototype !== null)
  ) {
    throw new Error("non-plain JSON value");
  }

  const keys = Reflect.ownKeys(value);
  ancestors.add(value);
  try {
    if (array) {
      const lengthDescriptor = Reflect.getOwnPropertyDescriptor(value, "length");
      if (!lengthDescriptor || !("value" in lengthDescriptor)) {
        throw new Error("JSON array length is not own data");
      }
      const lengthValue = lengthDescriptor.value;
      if (
        typeof lengthValue !== "number" ||
        !Number.isSafeInteger(lengthValue) ||
        lengthValue < 0
      ) {
        throw new Error("invalid JSON array length");
      }
      const length = lengthValue;
      if (
        keys.length !== length + 1 ||
        !keys.includes("length") ||
        keys.some(
          (key) =>
            typeof key !== "string" ||
            (key !== "length" && !/^(0|[1-9][0-9]*)$/u.test(key)) ||
            (key !== "length" && Number(key) >= length),
        )
      ) {
        throw new Error("sparse or extended JSON array");
      }
      const clone: JsonValue[] = [];
      for (let index = 0; index < length; index += 1) {
        const descriptor = Reflect.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
          throw new Error("JSON array element is not own data");
        }
        Object.defineProperty(clone, String(index), {
          value: cloneJsonValueUnsafe(descriptor.value, ancestors, depth + 1),
          enumerable: true,
          configurable: false,
          writable: false,
        });
      }
      return Object.freeze(clone);
    }

    const clone = Object.create(null) as Record<string, JsonValue>;
    for (const key of keys) {
      if (typeof key !== "string") throw new Error("symbol JSON property");
      const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error("JSON property is not own enumerable data");
      }
      Object.defineProperty(clone, key, {
        value: cloneJsonValueUnsafe(descriptor.value, ancestors, depth + 1),
        enumerable: true,
        configurable: false,
        writable: false,
      });
    }
    return Object.freeze(clone);
  } finally {
    ancestors.delete(value);
  }
}

function cloneJsonValue(value: unknown, field: string): JsonValue {
  try {
    return cloneJsonValueUnsafe(value, new Set(), 0);
  } catch {
    throw new Error(`${field} must contain only closed plain own-data JSON values`);
  }
}

function stringifyJsonPrimitive(value: string | number): string {
  const rendered = JSON_STRINGIFY(value);
  if (rendered === undefined) throw new Error("closed JSON serialization failed");
  return rendered;
}

function serializeClosedJson(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string" || typeof value === "number") {
    return stringifyJsonPrimitive(value);
  }
  if (Array.isArray(value)) {
    const rendered: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      rendered.push(serializeClosedJson(value[index]!));
    }
    return `[${rendered.join(",")}]`;
  }
  const record = value as Readonly<Record<string, JsonValue>>;
  const rendered = Object.keys(record).map(
    (key) => `${stringifyJsonPrimitive(key)}:${serializeClosedJson(record[key]!)}`,
  );
  return `{${rendered.join(",")}}`;
}

function snapshotParameterRecord(
  rawValues: unknown,
  location: string,
): Readonly<Record<string, unknown>> {
  if (rawValues === undefined) return Object.freeze(Object.create(null));
  try {
    if (
      rawValues === null ||
      typeof rawValues !== "object" ||
      Array.isArray(rawValues)
    ) {
      throw new Error("not an object");
    }
    const prototype = Reflect.getPrototypeOf(rawValues);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("non-plain parameter object");
    }
    const snapshot = Object.create(null) as Record<string, unknown>;
    for (const key of Reflect.ownKeys(rawValues)) {
      if (typeof key !== "string") throw new Error("symbol parameter");
      const descriptor = Reflect.getOwnPropertyDescriptor(rawValues, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error("parameter is not own enumerable data");
      }
      const value = descriptor.value;
      Object.defineProperty(snapshot, key, {
        value: value === undefined ? undefined : cloneJsonValueUnsafe(value, new Set(), 0),
        enumerable: true,
        configurable: false,
        writable: false,
      });
    }
    return Object.freeze(snapshot);
  } catch {
    throw new Error(`${location} parameters must be a plain own-data object`);
  }
}

function validateParameters(
  location: string,
  rawValues: unknown,
  definitions: Readonly<Record<string, ParameterDefinition>>,
): Readonly<Record<string, unknown>> {
  const values = snapshotParameterRecord(rawValues, location);
  for (const name of Object.keys(values)) {
    if (!(name in definitions)) throw new Error(`unexpected ${location} parameter ${name}`);
  }
  for (const [name, definition] of Object.entries(definitions)) {
    const value = values[name];
    if (value === undefined) {
      if (definition.required) throw new Error(`missing ${location} parameter ${name}`);
      continue;
    }
    assertSchema(value, definition.schema, `${location} parameter ${name}`);
  }
  return values;
}

function replacePathParameters(
  template: string,
  values: Readonly<Record<string, unknown>>,
): string {
  return template.replace(/\{([a-z_]+)\}/gu, (_placeholder, name: string) =>
    encodeURIComponent(String(values[name])),
  );
}

function appendQuery(path: string, query: Readonly<Record<string, unknown>>): string {
  const parameters = new URLSearchParams();
  for (const [name, rawValue] of Object.entries(query).sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    if (rawValue === undefined) continue;
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    for (const value of values) parameters.append(name, String(value));
  }
  const encoded = parameters.toString();
  return encoded ? `${path}?${encoded}` : path;
}

function snapshotRequestOptions(rawOptions: unknown): PlatformRequestOptions {
  try {
    if (
      rawOptions === null ||
      typeof rawOptions !== "object" ||
      Array.isArray(rawOptions)
    ) {
      throw new Error("request options are not an object");
    }
    const prototype = Reflect.getPrototypeOf(rawOptions);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("request options are not plain");
    }

    const snapshot = Object.create(null) as Record<string, unknown>;
    for (const key of Reflect.ownKeys(rawOptions)) {
      if (typeof key !== "string" || !REQUEST_OPTION_KEYS.has(key)) {
        throw new Error("unexpected request option");
      }
      const descriptor = Reflect.getOwnPropertyDescriptor(rawOptions, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error("request option is not own enumerable data");
      }
      if (
        key === "signal" &&
        descriptor.value !== undefined &&
        (typeof AbortSignal === "undefined" || !(descriptor.value instanceof AbortSignal))
      ) {
        throw new Error("request signal is not an AbortSignal");
      }
      Object.defineProperty(snapshot, key, {
        value: descriptor.value,
        enumerable: true,
        configurable: false,
        writable: false,
      });
    }
    return Object.freeze(snapshot) as PlatformRequestOptions;
  } catch {
    throw new Error("request options must be a closed plain own-data object");
  }
}

function validateRequest(
  definition: OperationDefinition,
  options: PlatformRequestOptions,
): {
  readonly path: Readonly<Record<string, unknown>>;
  readonly query: Readonly<Record<string, unknown>>;
  readonly headers: Headers;
  readonly body?: string;
  readonly signal?: AbortSignal;
} {
  const rawPath = options.path;
  const rawQuery = options.query;
  const rawBody = options.body;
  const ifMatch = options.ifMatch;
  const idempotencyKey = options.idempotencyKey;
  const signal = options.signal;
  const path = validateParameters("path", rawPath, definition.request.path);
  const query = validateParameters("query", rawQuery, definition.request.query);
  const headerValues: Readonly<Record<string, string | undefined>> = {
    ifMatch,
    idempotencyKey,
  };
  for (const [name, value] of Object.entries(headerValues)) {
    if (value !== undefined && !(name in definition.request.headers)) {
      throw new Error(`unexpected request header option ${name}`);
    }
  }
  const headers = new Headers({ Accept: "application/json, application/problem+json" });
  for (const [name, header] of Object.entries(definition.request.headers)) {
    const value = headerValues[name];
    if (value === undefined) {
      if (header.required) throw new Error(`missing request header ${header.wireName}`);
      continue;
    }
    assertSchema(value, header.schema, `request header ${header.wireName}`);
    if (header.strongEtag && !STRONG_ETAG_PATTERN.test(value)) {
      throw new Error(`request header ${header.wireName} must be a strong ETag`);
    }
    headers.set(header.wireName, value);
  }

  if (!definition.request.body) {
    if (rawBody !== undefined) throw new Error("unexpected request body");
    return { path, query, headers, ...(signal ? { signal } : {}) };
  }
  if (rawBody === undefined) {
    if (definition.request.body.required) throw new Error("missing request body");
    return { path, query, headers, ...(signal ? { signal } : {}) };
  }
  const body = cloneJsonValue(rawBody, "request body");
  assertSchema(body, definition.request.body.schema, "request body");
  headers.set("Content-Type", definition.request.body.mediaType);
  return {
    path,
    query,
    headers,
    body: serializeClosedJson(body),
    ...(signal ? { signal } : {}),
  };
}

function responseMediaType(response: Response): string {
  return ((response.headers.get("content-type") ?? "").split(";", 1)[0] ?? "")
    .trim()
    .toLowerCase();
}

function validatedCorrelationId(value: string | null): string | undefined {
  if (value === null) return undefined;
  if (!SAFE_CORRELATION_ID_PATTERN.test(value)) throw new PlatformApiError(502);
  return value;
}

function validatedSchemaVersion(
  response: Response,
  definition: ResponseDefinition,
): string | undefined {
  const value = response.headers.get("stead-schema-version");
  const contract = definition.schemaVersion;
  if (response.ok && contract?.required && value === null) {
    throw new PlatformApiError(502);
  }
  if (value === null) return undefined;
  if (!response.ok || !contract) throw new PlatformApiError(502);
  if (!GENERIC_SCHEMA_VERSION_PATTERN.test(value)) throw new PlatformApiError(502);
  if (!schemaMatches(value, contract.schema)) {
    throw new PlatformApiError(502);
  }
  if (Number(value.split(".", 1)[0]) !== definition.compatibleSchemaMajor) {
    throw new PlatformApiError(502);
  }
  return value;
}

function validatedEtag(
  response: Response,
  definition: ResponseDefinition,
): string | undefined {
  const value = response.headers.get("etag");
  if (value === null) return undefined;
  if (!response.ok || !definition.etag) throw new PlatformApiError(502);
  if (!schemaMatches(value, definition.etag.schema)) throw new PlatformApiError(502);
  if (definition.etag.strongEtag && !STRONG_ETAG_PATTERN.test(value)) {
    throw new PlatformApiError(502);
  }
  return value;
}

async function readBoundedBody(response: Response): Promise<Uint8Array> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/u.test(declaredLength)) throw new PlatformApiError(502);
    if (Number(declaredLength) > PLATFORM_MAX_RESPONSE_BYTES) {
      throw new PlatformApiError(502);
    }
  }
  if (!response.body) return new Uint8Array();
  try {
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > PLATFORM_MAX_RESPONSE_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // The public failure remains bounded even when transport cancellation fails.
        }
        throw new PlatformApiError(502);
      }
      chunks.push(value);
    }
    const result = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return result;
  } catch (error: unknown) {
    if (error instanceof PlatformApiError) throw error;
    throw new PlatformApiError(502);
  }
}

function parseJson(bytes: Uint8Array): unknown {
  if (bytes.byteLength === 0) throw new PlatformApiError(502);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch (error: unknown) {
    if (error instanceof PlatformApiError) throw error;
    throw new PlatformApiError(502);
  }
}

function bodyCorrelationId(body: unknown): string | undefined {
  if (
    typeof body === "object" &&
    body !== null &&
    "correlation_id" in body
  ) {
    if (typeof body.correlation_id !== "string") throw new PlatformApiError(502);
    return validatedCorrelationId(body.correlation_id);
  }
  return undefined;
}

export function createPlatformClient(
  options: PlatformClientOptions = {},
): PlatformClient {
  const basePath = options.basePath ?? PLATFORM_API_BASE_PATH;
  assertCanonicalBasePath(basePath);
  const fetchImplementation = options.fetchImplementation ?? globalThis.fetch;
  if (!fetchImplementation) throw new Error("fetch is unavailable");

  return {
    async request<TData = unknown>(
      operationId: PlatformOperationId,
      requestOptions: PlatformRequestOptions = {},
    ): Promise<PlatformResponse<TData>> {
      const definition = operationDefinitions[operationId] as OperationDefinition;
      if (!definition) throw new Error("unknown generated Platform operation");
      const validated = validateRequest(
        definition,
        snapshotRequestOptions(requestOptions),
      );
      const operationPath = replacePathParameters(definition.path, validated.path);
      const url = appendQuery(`${basePath}${operationPath}`, validated.query);

      const startedAt = performance.now();
      const response = await fetchImplementation(url, {
        method: definition.method,
        headers: validated.headers,
        body: validated.body,
        credentials: "same-origin",
        redirect: "error",
        signal: validated.signal,
      });

      const allowedMediaTypes = response.ok
        ? definition.response.successMediaTypes
        : definition.response.errorMediaTypes;
      if (!allowedMediaTypes.includes(responseMediaType(response))) {
        throw new PlatformApiError(502);
      }
      const schemaVersion = validatedSchemaVersion(response, definition.response);
      const etag = validatedEtag(response, definition.response);
      const headerCorrelationId = validatedCorrelationId(
        response.headers.get("x-correlation-id"),
      );
      const bytes = await readBoundedBody(response);
      const body = parseJson(bytes);
      const embeddedCorrelationId = bodyCorrelationId(body);
      const correlationId = headerCorrelationId ?? embeddedCorrelationId;

      options.observeNetwork?.({
        operationId,
        durationMs: performance.now() - startedAt,
        responseBytes: bytes.byteLength,
        status: response.status,
      });
      if (!response.ok) throw new PlatformApiError(response.status, correlationId);

      return {
        data: body as TData,
        status: response.status,
        responseBytes: bytes.byteLength,
        ...(etag ? { etag } : {}),
        ...(schemaVersion ? { schemaVersion } : {}),
        ...(correlationId ? { correlationId } : {}),
      };
    },
  };
}
