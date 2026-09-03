export type FrontendMetricName =
  | "cold-interactive"
  | "command-open-acknowledgement"
  | "command-local-results"
  | "route-useful-content"
  | "first-contentful-paint"
  | "largest-contentful-paint"
  | "cumulative-layout-shift"
  | "interaction-next-paint"
  | "platform-request-duration"
  | "platform-response-bytes"
  | "platform-request-count"
  | "route-navigation-count"
  | "lazy-capability-chunk-count";

export interface FrontendMetric {
  readonly name: FrontendMetricName;
  readonly value: number;
  readonly unit: "bytes" | "count" | "milliseconds" | "score";
}

const METRIC_UNITS = Object.freeze({
  "cold-interactive": "milliseconds",
  "command-open-acknowledgement": "milliseconds",
  "command-local-results": "milliseconds",
  "route-useful-content": "milliseconds",
  "first-contentful-paint": "milliseconds",
  "largest-contentful-paint": "milliseconds",
  "cumulative-layout-shift": "score",
  "interaction-next-paint": "milliseconds",
  "platform-request-duration": "milliseconds",
  "platform-response-bytes": "bytes",
  "platform-request-count": "count",
  "route-navigation-count": "count",
  "lazy-capability-chunk-count": "count",
}) satisfies Readonly<Record<FrontendMetricName, FrontendMetric["unit"]>>;

const SPAN_METRIC_NAMES = new Set<FrontendMetricName>([
  "cold-interactive",
  "command-open-acknowledgement",
  "command-local-results",
  "route-useful-content",
]);

declare global {
  interface WindowEventMap {
    "stead:performance": CustomEvent<FrontendMetric>;
  }
}

const activeSpans = new Map<FrontendMetricName, number>();
let cumulativeLayoutShift = 0;
let platformRequestCount = 0;
let routeNavigationCount = 0;

function snapshotMetric(rawMetric: unknown): Readonly<FrontendMetric> {
  try {
    if (
      rawMetric === null ||
      typeof rawMetric !== "object" ||
      Array.isArray(rawMetric)
    ) {
      throw new Error("metric is not an object");
    }
    const prototype = Reflect.getPrototypeOf(rawMetric);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("metric is not plain");
    }
    const fields = new Map<string, unknown>();
    for (const key of ["name", "value", "unit"]) {
      const descriptor = Reflect.getOwnPropertyDescriptor(rawMetric, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error("metric field is not own enumerable data");
      }
      fields.set(key, descriptor.value);
    }
    const name = fields.get("name");
    const value = fields.get("value");
    const unit = fields.get("unit");
    if (
      typeof name !== "string" ||
      !Object.hasOwn(METRIC_UNITS, name) ||
      typeof value !== "number" ||
      !Number.isFinite(value) ||
      value < 0 ||
      unit !== METRIC_UNITS[name as FrontendMetricName] ||
      ((unit === "bytes" || unit === "count") && !Number.isSafeInteger(value))
    ) {
      throw new Error("invalid metric value");
    }
    return Object.freeze({
      name: name as FrontendMetricName,
      value,
      unit: unit as FrontendMetric["unit"],
    });
  } catch {
    throw new TypeError("frontend performance metric must be closed and allowlisted");
  }
}

function assertSpanMetricName(name: unknown): asserts name is FrontendMetricName {
  if (
    typeof name !== "string" ||
    !Object.hasOwn(METRIC_UNITS, name) ||
    METRIC_UNITS[name as FrontendMetricName] !== "milliseconds" ||
    !SPAN_METRIC_NAMES.has(name as FrontendMetricName)
  ) {
    throw new TypeError("frontend performance span name is not allowlisted");
  }
}

function performanceNow(): number {
  const value = performance.now();
  if (!Number.isFinite(value) || value < 0) {
    throw new TypeError("frontend performance clock returned an invalid value");
  }
  return value;
}

export function emitPerformanceMetric(metric: FrontendMetric): void {
  const detail = snapshotMetric(metric);
  window.dispatchEvent(new CustomEvent("stead:performance", { detail }));
}

export function beginPerformanceSpan(name: FrontendMetricName): void {
  assertSpanMetricName(name);
  activeSpans.set(name, performanceNow());
}

export function endPerformanceSpan(name: FrontendMetricName): void {
  assertSpanMetricName(name);
  const startedAt = activeSpans.get(name);
  if (startedAt === undefined) return;
  activeSpans.delete(name);
  const endedAt = performanceNow();
  if (endedAt < startedAt) {
    throw new TypeError("frontend performance clock moved backwards");
  }
  emitPerformanceMetric({
    name,
    value: endedAt - startedAt,
    unit: "milliseconds",
  });
}

export function observePlatformRequest(observation: {
  readonly durationMs: number;
  readonly responseBytes: number;
}): void {
  platformRequestCount += 1;
  emitPerformanceMetric({
    name: "platform-request-count",
    value: platformRequestCount,
    unit: "count",
  });
  emitPerformanceMetric({
    name: "platform-request-duration",
    value: observation.durationMs,
    unit: "milliseconds",
  });
  emitPerformanceMetric({
    name: "platform-response-bytes",
    value: observation.responseBytes,
    unit: "bytes",
  });
}

export function recordRouteNavigation(): void {
  routeNavigationCount += 1;
  emitPerformanceMetric({
    name: "route-navigation-count",
    value: routeNavigationCount,
    unit: "count",
  });
}

export function recordLazyCapabilityChunkCount(count: number): void {
  emitPerformanceMetric({
    name: "lazy-capability-chunk-count",
    value: count,
    unit: "count",
  });
}

function observeEntryType(
  type: string,
  handler: (entry: PerformanceEntry) => void,
): PerformanceObserver | undefined {
  if (!("PerformanceObserver" in window)) return undefined;
  if (!PerformanceObserver.supportedEntryTypes.includes(type)) return undefined;
  const observer = new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) handler(entry);
  });
  observer.observe({ type, buffered: true });
  return observer;
}

export function startBrowserPerformanceInstrumentation(): () => void {
  activeSpans.set("cold-interactive", 0);
  const observers = [
    observeEntryType("paint", (entry) => {
      if (entry.name === "first-contentful-paint") {
        emitPerformanceMetric({
          name: "first-contentful-paint",
          value: entry.startTime,
          unit: "milliseconds",
        });
      }
    }),
    observeEntryType("largest-contentful-paint", (entry) => {
      emitPerformanceMetric({
        name: "largest-contentful-paint",
        value: entry.startTime,
        unit: "milliseconds",
      });
    }),
    observeEntryType("layout-shift", (entry) => {
      const shift = entry as PerformanceEntry & {
        readonly value?: number;
        readonly hadRecentInput?: boolean;
      };
      if (shift.hadRecentInput || shift.value === undefined) return;
      cumulativeLayoutShift += shift.value;
      emitPerformanceMetric({
        name: "cumulative-layout-shift",
        value: cumulativeLayoutShift,
        unit: "score",
      });
    }),
    observeEntryType("event", (entry) => {
      const event = entry as PerformanceEntry & { readonly duration?: number };
      if (!event.duration || event.duration < 40) return;
      emitPerformanceMetric({
        name: "interaction-next-paint",
        value: event.duration,
        unit: "milliseconds",
      });
    }),
  ].filter((observer): observer is PerformanceObserver => observer !== undefined);

  return () => {
    for (const observer of observers) observer.disconnect();
  };
}

export interface PerformanceSummary {
  readonly count: number;
  readonly p50: number;
  readonly p95: number;
  readonly p99: number;
}

export function summarizePerformance(values: readonly number[]): PerformanceSummary {
  if (values.length === 0) return { count: 0, p50: 0, p95: 0, p99: 0 };
  const sorted = [...values].sort((left, right) => left - right);
  const percentile = (value: number) => {
    const index = Math.min(sorted.length - 1, Math.ceil(sorted.length * value) - 1);
    return sorted[index] ?? 0;
  };
  return {
    count: sorted.length,
    p50: percentile(0.5),
    p95: percentile(0.95),
    p99: percentile(0.99),
  };
}
