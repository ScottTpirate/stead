import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    clearMocks: true,
    environment: "happy-dom",
    fileParallelism: false,
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    isolate: true,
    maxWorkers: 1,
    mockReset: true,
    passWithNoTests: false,
    restoreMocks: true,
    testTimeout: 5_000,
  },
});
