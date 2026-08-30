import {
  operationDefinitions,
  type JsonValue,
  type PlatformOperationId,
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

const GENERIC_CORRELATION_ID = "mock-correlation-0001";

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

function pathMatcher(template: string): RegExp {
  const escaped = template
    .split(/\{[a-z_]+\}/gu)
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"))
    .join("[^/]+");
  return new RegExp(`^${escaped}$`, "u");
}

function identifyOperation(method: string, url: URL): PlatformOperationId | undefined {
  for (const [operationId, definition] of Object.entries(operationDefinitions)) {
    if (
      definition.method === method.toUpperCase() &&
      pathMatcher(`/api/v1${definition.path}`).test(url.pathname)
    ) {
      return operationId as PlatformOperationId;
    }
  }
  return undefined;
}

export function createContractMockFetch(
  scenario: ContractMockScenario = {},
  observe?: (observation: ContractMockObservation) => void,
): ContractMockFetch {
  let requestCount = 0;
  const operationCounts = new Map<PlatformOperationId, number>();

  const mockFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const rawUrl =
      input instanceof Request
        ? input.url
        : input instanceof URL
          ? input.toString()
          : input;
    const url = new URL(rawUrl, "https://stead.invalid");
    const method = init?.method ?? (input instanceof Request ? input.method : "GET");
    const operationId = identifyOperation(method, url);
    if (!operationId) {
      throw new Error("Contract mock received a request outside generated Platform operations.");
    }

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
