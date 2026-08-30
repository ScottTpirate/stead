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

declare global {
  interface WindowEventMap {
    "stead:performance": CustomEvent<FrontendMetric>;
  }
}

const activeSpans = new Map<FrontendMetricName, number>();
let cumulativeLayoutShift = 0;
let platformRequestCount = 0;
let routeNavigationCount = 0;

export function emitPerformanceMetric(metric: FrontendMetric): void {
  window.dispatchEvent(new CustomEvent("stead:performance", { detail: metric }));
}

export function beginPerformanceSpan(name: FrontendMetricName): void {
  activeSpans.set(name, performance.now());
}

export function endPerformanceSpan(name: FrontendMetricName): void {
  const startedAt = activeSpans.get(name);
  if (startedAt === undefined) return;
  activeSpans.delete(name);
  emitPerformanceMetric({
    name,
    value: performance.now() - startedAt,
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
