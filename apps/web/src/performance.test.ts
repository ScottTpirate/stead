import { describe, expect, it } from "vitest";

import {
  beginPerformanceSpan,
  emitPerformanceMetric,
  endPerformanceSpan,
} from "./performance";

describe("frontend performance boundary", () => {
  it("reconstructs an exact frozen allowlisted event detail", () => {
    let detail: unknown;
    window.addEventListener(
      "stead:performance",
      (event) => {
        detail = event.detail;
      },
      { once: true },
    );

    emitPerformanceMetric({
      name: "platform-request-count",
      value: 1,
      unit: "count",
      body: "classified-body",
    } as unknown as Parameters<typeof emitPerformanceMetric>[0]);

    expect(detail).toEqual({
      name: "platform-request-count",
      value: 1,
      unit: "count",
    });
    expect(Object.keys(detail as object)).toEqual(["name", "value", "unit"]);
    expect(Object.isFrozen(detail)).toBe(true);
    expect(JSON.stringify(detail)).not.toContain("classified-body");
  });

  it("rejects invalid metric and span inputs before dispatch", () => {
    let dispatches = 0;
    window.addEventListener("stead:performance", () => {
      dispatches += 1;
    });

    for (const metric of [
      { name: "protected-body", value: 1, unit: "count" },
      { name: "platform-request-count", value: 1.5, unit: "count" },
      { name: "platform-request-duration", value: Number.NaN, unit: "milliseconds" },
      { name: "platform-response-bytes", value: -1, unit: "bytes" },
      { name: "platform-response-bytes", value: 1, unit: "score" },
    ]) {
      expect(() =>
        emitPerformanceMetric(
          metric as unknown as Parameters<typeof emitPerformanceMetric>[0],
        ),
      ).toThrow(/closed and allowlisted/u);
    }
    expect(() =>
      beginPerformanceSpan(
        "platform-request-count" as Parameters<typeof beginPerformanceSpan>[0],
      ),
    ).toThrow(/span name is not allowlisted/u);
    expect(() =>
      endPerformanceSpan(
        "protected-body" as Parameters<typeof endPerformanceSpan>[0],
      ),
    ).toThrow(/span name is not allowlisted/u);
    expect(dispatches).toBe(0);
  });
});
