import {
  createPlatformClient,
  operationDefinitions,
  PLATFORM_API_BASE_PATH,
  type JsonValue,
  type PlatformOperationId,
  type PlatformRequestOptions,
} from "../../../api-client/src/index.ts";

export interface ContractMockResponse {
  readonly status: number;
  readonly body?: JsonValue;
  readonly headers?: Readonly<Record<string, string>>;
}

export type ContractMockScenario = Partial<
  Record<PlatformOperationId, ContractMockResponse>
>;

export interface ContractMockObservation {
  readonly operationId: PlatformOperationId;
  readonly requestNumber: number;
}

export interface ContractMockFetch {
  readonly fetch: typeof fetch;
  readonly requestCount: () => number;
  readonly operationCount: (operationId: PlatformOperationId) => number;
}

interface ParameterDefinition {
  readonly required: boolean;
  readonly schema: {
    readonly type?: string;
    readonly items?: { readonly type?: string };
  };
}

interface OperationDefinition {
  readonly method: string;
  readonly path: string;
  readonly request: {
    readonly path: Readonly<Record<string, ParameterDefinition>>;
    readonly query: Readonly<Record<string, ParameterDefinition>>;
    readonly headers: Readonly<
      Record<string, { readonly wireName: string; readonly required: boolean }>
    >;
    readonly body: {
      readonly required: boolean;
      readonly mediaType: string;
    } | null;
  };
}

interface MatchedOperation {
  readonly operationId: PlatformOperationId;
  readonly definition: OperationDefinition;
  readonly pathValues: Readonly<Record<string, string>>;
}

interface CapturedRequest {
  readonly input: RequestInfo | URL;
  readonly init?: RequestInit;
}

const GENERIC_CORRELATION_ID = "mock-correlation-0001";
const TRUSTED_ORIGIN = "https://stead.invalid";
const CONTROL_OR_BACKSLASH = /[\u0000-\u001f\u007f\\]/u;
const REQUEST_CONTENT_FIELDS = new Set([
  "body",
  "bodyUsed",
  "headers",
  "signal",
  "url",
]);
const EFFECTIVE_TRANSPORT_FIELDS = Object.freeze([
  ...new Set([
    // Keep the standard fields explicit for auditability, then include any
    // additional native Request getters exposed by the pinned runtime.
    "attribute",
    "cache",
    "credentials",
    "destination",
    "duplex",
    "integrity",
    "isHistoryNavigation",
    "isReloadNavigation",
    "keepalive",
    "method",
    "mode",
    "priority",
    "redirect",
    "referrer",
    "referrerPolicy",
    ...Object.getOwnPropertyNames(Request.prototype).filter((field) => {
      const descriptor = Object.getOwnPropertyDescriptor(
        Request.prototype,
        field,
      );
      return (
        !REQUEST_CONTENT_FIELDS.has(field) &&
        typeof descriptor?.get === "function"
      );
    }),
  ]),
]);

const GENERATED_OPERATIONS = operationDefinitions as unknown as Readonly<
  Record<PlatformOperationId, OperationDefinition>
>;

export function nonDisclosingDenial(status = 404): ContractMockResponse {
  return {
    status,
    headers: { "content-type": "application/problem+json" },
    body: {
      type: "about:blank",
      title: "Request unavailable",
      status,
      correlation_id: GENERIC_CORRELATION_ID,
    },
  };
}

function contractError(reason: string): Error {
  return new Error(`Contract mock rejected request: ${reason}.`);
}

function parseTrustedUrl(input: RequestInfo | URL): URL {
  const rawUrl = input instanceof Request ? input.url : input.toString();
  if (CONTROL_OR_BACKSLASH.test(rawUrl)) {
    throw contractError("URL contains a control character or backslash");
  }

  let url: URL;
  try {
    url = new URL(rawUrl, TRUSTED_ORIGIN);
  } catch {
    throw contractError("URL is malformed");
  }
  if (
    url.origin !== TRUSTED_ORIGIN ||
    url.protocol !== "https:" ||
    url.hostname !== "stead.invalid" ||
    url.username !== "" ||
    url.password !== ""
  ) {
    throw contractError("URL is outside the trusted Stead origin");
  }
  if (url.hash !== "" || rawUrl.includes("#")) {
    throw contractError("URL fragments are not permitted");
  }
  return url;
}

function decodedPathValue(rawValue: string): string {
  try {
    return decodeURIComponent(rawValue);
  } catch {
    throw contractError("path contains malformed percent encoding");
  }
}

function matchOperationPath(
  template: string,
  pathname: string,
): Readonly<Record<string, string>> | undefined {
  const templateSegments = `${PLATFORM_API_BASE_PATH}${template}`.split("/");
  const pathSegments = pathname.split("/");
  if (templateSegments.length !== pathSegments.length) return undefined;

  const values = Object.create(null) as Record<string, string>;
  for (let index = 0; index < templateSegments.length; index += 1) {
    const expected = templateSegments[index]!;
    const actual = pathSegments[index]!;
    const placeholder = /^\{([a-z_]+)\}$/u.exec(expected);
    if (!placeholder) {
      if (expected !== actual) return undefined;
      continue;
    }
    if (actual.length === 0) return undefined;
    values[placeholder[1]!] = decodedPathValue(actual);
  }
  return values;
}

function identifyOperation(method: string, url: URL): MatchedOperation {
  const pathMatches: MatchedOperation[] = [];
  for (const [operationId, definition] of Object.entries(GENERATED_OPERATIONS)) {
    const pathValues = matchOperationPath(definition.path, url.pathname);
    if (pathValues) {
      pathMatches.push({
        operationId: operationId as PlatformOperationId,
        definition,
        pathValues,
      });
    }
  }
  if (pathMatches.length === 0) {
    throw contractError("path is outside generated Platform operations");
  }
  const match = pathMatches.find(({ definition }) => definition.method === method);
  if (!match) throw contractError("method is not declared for the generated path");
  return match;
}

function decodedQueryValue(
  rawValue: string,
  schema: { readonly type?: string },
): boolean | number | string {
  if (schema.type === "boolean") {
    if (rawValue === "true") return true;
    if (rawValue === "false") return false;
  }
  if (schema.type === "integer" || schema.type === "number") {
    const value = Number(rawValue);
    if (Number.isFinite(value)) return value;
  }
  return rawValue;
}

function queryOptions(
  url: URL,
  definitions: Readonly<Record<string, ParameterDefinition>>,
): Readonly<Record<string, boolean | number | string | readonly string[]>> {
  const query = Object.create(null) as Record<
    string,
    boolean | number | string | readonly string[]
  >;
  for (const name of new Set(url.searchParams.keys())) {
    if (!Object.hasOwn(definitions, name)) {
      throw contractError(`query parameter ${name} is undeclared`);
    }
  }
  for (const [name, definition] of Object.entries(definitions)) {
    const values = url.searchParams.getAll(name);
    if (values.length === 0) continue;
    if (definition.schema.type === "array") {
      query[name] = values.map((value) =>
        String(decodedQueryValue(value, definition.schema.items ?? {})),
      );
      continue;
    }
    if (values.length !== 1) {
      throw contractError(`query parameter ${name} must occur once`);
    }
    query[name] = decodedQueryValue(values[0]!, definition.schema);
  }
  return query;
}

async function effectiveRequest(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  url: URL,
): Promise<Request> {
  try {
    return input instanceof Request ? new Request(input, init) : new Request(url, init);
  } catch {
    throw contractError("request transport is malformed");
  }
}

async function requestOptions(
  request: Request,
  url: URL,
  match: MatchedOperation,
): Promise<{ readonly options: PlatformRequestOptions; readonly body?: string }> {
  const mutable = {
    path: match.pathValues,
    query: queryOptions(url, match.definition.request.query),
    signal: request.signal,
  } as Record<string, unknown>;

  for (const [optionName, header] of Object.entries(
    match.definition.request.headers,
  )) {
    const value = request.headers.get(header.wireName);
    if (value !== null) mutable[optionName] = value;
  }

  if (request.body === null) {
    return { options: mutable as unknown as PlatformRequestOptions };
  }

  let body: string;
  try {
    body = await request.text();
    mutable.body = JSON.parse(body) as JsonValue;
  } catch {
    throw contractError("request body is not valid JSON");
  }
  return { options: mutable as unknown as PlatformRequestOptions, body };
}

async function generatedRequest(
  operationId: PlatformOperationId,
  options: PlatformRequestOptions,
): Promise<CapturedRequest> {
  const capture = Symbol("generated request captured");
  let captured: CapturedRequest | undefined;
  const client = createPlatformClient({
    fetchImplementation: (async (input: RequestInfo | URL, init?: RequestInit) => {
      captured = { input, init };
      throw capture;
    }) as typeof fetch,
  });
  try {
    await client.request(operationId, options);
  } catch (error: unknown) {
    if (error !== capture) {
      throw contractError("request violates the generated Platform contract");
    }
  }
  if (!captured) throw contractError("generated request could not be captured");
  return captured;
}

function headersMatch(actual: Headers, expected: Headers): boolean {
  const actualEntries = [...actual.entries()];
  const expectedEntries = [...expected.entries()];
  return (
    actualEntries.length === expectedEntries.length &&
    actualEntries.every(
      ([name, value], index) =>
        name === expectedEntries[index]?.[0] && value === expectedEntries[index]?.[1],
    )
  );
}

function effectiveTransportMatches(actual: Request, expected: Request): boolean {
  return (
    EFFECTIVE_TRANSPORT_FIELDS.every(
      (field) => Reflect.get(actual, field) === Reflect.get(expected, field),
    ) &&
    actual.signal.aborted === expected.signal.aborted
  );
}

async function validateRequest(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<PlatformOperationId> {
  const url = parseTrustedUrl(input);
  const request = await effectiveRequest(input, init, url);
  const match = identifyOperation(request.method, url);
  const { options, body } = await requestOptions(request, url, match);
  const generated = await generatedRequest(match.operationId, options);
  const generatedUrl = new URL(generated.input.toString(), TRUSTED_ORIGIN);
  const generatedEffectiveRequest = await effectiveRequest(
    generated.input,
    generated.init,
    generatedUrl,
  );
  const generatedHeaders = new Headers(generated.init?.headers);

  if (
    `${url.pathname}${url.search}` !== `${generatedUrl.pathname}${generatedUrl.search}` ||
    request.method !== generated.init?.method ||
    request.credentials !== generated.init?.credentials ||
    request.redirect !== generated.init?.redirect ||
    body !== generated.init?.body ||
    !headersMatch(request.headers, generatedHeaders) ||
    !effectiveTransportMatches(request, generatedEffectiveRequest)
  ) {
    throw contractError("wire request differs from the generated client contract");
  }
  return match.operationId;
}

export function createContractMockFetch(
  scenario: ContractMockScenario = {},
  observe?: (observation: ContractMockObservation) => void,
): ContractMockFetch {
  let requestCount = 0;
  const operationCounts = new Map<PlatformOperationId, number>();

  const mockFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const operationId = await validateRequest(input, init);

    requestCount += 1;
    const operationCount = (operationCounts.get(operationId) ?? 0) + 1;
    operationCounts.set(operationId, operationCount);
    observe?.({ operationId, requestNumber: requestCount });
    const result = scenario[operationId] ?? {
      status: 503,
      headers: { "content-type": "application/problem+json" },
      body: {
        type: "about:blank",
        title: "Contract mock not configured",
        status: 503,
        correlation_id: GENERIC_CORRELATION_ID,
      },
    };
    const headers = new Headers(result.headers);
    if (result.body !== undefined && !headers.has("content-type")) {
      headers.set("content-type", "application/json");
    }
    return new Response(
      result.body === undefined ? undefined : JSON.stringify(result.body),
      { status: result.status, headers },
    );
  };

  return {
    fetch: mockFetch as typeof fetch,
    requestCount: () => requestCount,
    operationCount: (operationId) => operationCounts.get(operationId) ?? 0,
  };
}
