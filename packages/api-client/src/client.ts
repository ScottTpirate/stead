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

function replacePathParameters(
  template: string,
  values: Readonly<Record<string, string>>,
): string {
  const used = new Set<string>();
  const path = template.replace(/\{([a-z_]+)\}/gu, (_placeholder, name: string) => {
    const value = values[name];
    if (!value) throw new Error(`missing path parameter ${name}`);
    used.add(name);
    return encodeURIComponent(value);
  });

  for (const name of Object.keys(values)) {
    if (!used.has(name)) throw new Error(`unexpected path parameter ${name}`);
  }
  return path;
}

function appendQuery(
  path: string,
  query: PlatformRequestOptions["query"],
): string {
  if (!query) return path;
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

function safeCorrelationId(response: Response, body: unknown): string | undefined {
  const headerValue = response.headers.get("x-correlation-id");
  if (headerValue) return headerValue;
  if (
    typeof body === "object" &&
    body !== null &&
    "correlation_id" in body &&
    typeof body.correlation_id === "string"
  ) {
    return body.correlation_id;
  }
  return undefined;
}

function parseJson(text: string): unknown {
  if (!text) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
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
      const definition = operationDefinitions[operationId];
      const operationPath = replacePathParameters(
        definition.path,
        requestOptions.path ?? {},
      );
      const url = appendQuery(`${basePath}${operationPath}`, requestOptions.query);
      const headers = new Headers({ Accept: "application/json" });
      if (requestOptions.body !== undefined) {
        headers.set(
          "Content-Type",
          definition.method === "PATCH"
            ? "application/merge-patch+json"
            : "application/json",
        );
      }
      if (requestOptions.ifMatch) headers.set("If-Match", requestOptions.ifMatch);
      if (requestOptions.idempotencyKey) {
        headers.set("Idempotency-Key", requestOptions.idempotencyKey);
      }

      const startedAt = performance.now();
      const response = await fetchImplementation(url, {
        method: definition.method,
        headers,
        body:
          requestOptions.body === undefined
            ? undefined
            : JSON.stringify(requestOptions.body),
        credentials: "same-origin",
        redirect: "error",
        signal: requestOptions.signal,
      });
      const text = await response.text();
      const responseBytes = new TextEncoder().encode(text).byteLength;
      const body = parseJson(text);
      const correlationId = safeCorrelationId(response, body);
      options.observeNetwork?.({
        operationId,
        durationMs: performance.now() - startedAt,
        responseBytes,
        status: response.status,
      });

      if (!response.ok) throw new PlatformApiError(response.status, correlationId);
      if (text && body === undefined) throw new PlatformApiError(502, correlationId);

      return {
        data: body as TData,
        status: response.status,
        responseBytes,
        ...(response.headers.get("etag")
          ? { etag: response.headers.get("etag") ?? undefined }
          : {}),
        ...(response.headers.get("stead-schema-version")
          ? {
              schemaVersion:
                response.headers.get("stead-schema-version") ?? undefined,
            }
          : {}),
        ...(correlationId ? { correlationId } : {}),
      };
    },
  };
}
