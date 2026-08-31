import {
  operationDefinitions,
  PLATFORM_API_BASE_PATH,
  type PlatformOperationId,
} from "./generated/platform-v1.ts";

export type JsonPrimitive = boolean | number | string | null;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
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
      new Set(value.map((item) => JSON.stringify(item))).size !== value.length
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

function assertRecord(
  value: unknown,
  field: string,
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value as Readonly<Record<string, unknown>>;
}

function validateParameters(
  location: string,
  rawValues: unknown,
  definitions: Readonly<Record<string, ParameterDefinition>>,
): Readonly<Record<string, unknown>> {
  const values = rawValues === undefined ? {} : assertRecord(rawValues, location);
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

function validateRequest(
  definition: OperationDefinition,
  options: PlatformRequestOptions,
): {
  readonly path: Readonly<Record<string, unknown>>;
  readonly query: Readonly<Record<string, unknown>>;
  readonly headers: Headers;
  readonly body?: string;
} {
  const path = validateParameters("path", options.path, definition.request.path);
  const query = validateParameters("query", options.query, definition.request.query);
  const headerValues: Readonly<Record<string, string | undefined>> = {
    ifMatch: options.ifMatch,
    idempotencyKey: options.idempotencyKey,
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
    if (options.body !== undefined) throw new Error("unexpected request body");
    return { path, query, headers };
  }
  if (options.body === undefined) {
    if (definition.request.body.required) throw new Error("missing request body");
    return { path, query, headers };
  }
  assertSchema(options.body, definition.request.body.schema, "request body");
  headers.set("Content-Type", definition.request.body.mediaType);
  return { path, query, headers, body: JSON.stringify(options.body) };
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
  if (!GENERIC_SCHEMA_VERSION_PATTERN.test(value)) throw new PlatformApiError(502);
  if (contract && !schemaMatches(value, contract.schema)) {
    throw new PlatformApiError(502);
  }
  if (Number(value.split(".", 1)[0]) !== definition.compatibleSchemaMajor) {
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
      const validated = validateRequest(definition, requestOptions);
      const operationPath = replacePathParameters(definition.path, validated.path);
      const url = appendQuery(`${basePath}${operationPath}`, validated.query);

      const startedAt = performance.now();
      const response = await fetchImplementation(url, {
        method: definition.method,
        headers: validated.headers,
        body: validated.body,
        credentials: "same-origin",
        redirect: "error",
        signal: requestOptions.signal,
      });

      const allowedMediaTypes = response.ok
        ? definition.response.successMediaTypes
        : definition.response.errorMediaTypes;
      if (!allowedMediaTypes.includes(responseMediaType(response))) {
        throw new PlatformApiError(502);
      }
      const schemaVersion = validatedSchemaVersion(response, definition.response);
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

      const etag = response.headers.get("etag");
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
