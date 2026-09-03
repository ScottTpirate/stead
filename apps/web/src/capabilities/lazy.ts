export const lazyCapabilityLoaders = {
  docsEditor: () => import("./docs-editor"),
  code: () => import("./code"),
  delivery: () => import("./delivery"),
  administration: () => import("./administration"),
  migration: () => import("./migration"),
  analytics: () => import("./analytics"),
} as const;

export type LazyCapabilityBoundary = keyof typeof lazyCapabilityLoaders;

export function inspectLazyCapabilityBoundaries(): readonly LazyCapabilityBoundary[] {
  const entries = Object.entries(lazyCapabilityLoaders);
  if (!entries.every(([, loader]) => typeof loader === "function")) return [];
  return entries.map(([name]) => name as LazyCapabilityBoundary);
}
