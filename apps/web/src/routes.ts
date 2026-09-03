export const primaryNavigation = Object.freeze([
  Object.freeze({
    id: "home",
    label: "Home",
    href: "/",
    description: "Your authorized overview will appear here.",
  }),
  Object.freeze({
    id: "inbox",
    label: "Inbox",
    href: "/inbox",
    description: "There are no authorized updates to show.",
  }),
  Object.freeze({
    id: "my-work",
    label: "My Work",
    href: "/my-work",
    description: "Assigned Work will appear here.",
  }),
  Object.freeze({
    id: "projects",
    label: "Projects",
    href: "/projects",
    description: "Authorized Projects will appear here.",
  }),
  Object.freeze({
    id: "knowledge",
    label: "Knowledge",
    href: "/knowledge",
    description: "Authorized Documents will appear here.",
  }),
  Object.freeze({
    id: "teams",
    label: "Teams",
    href: "/teams",
    description: "Authorized Teams will appear here.",
  }),
] as const);

// Navigation validation does not trust the exported presentation records. This
// independent frozen lookup remains unchanged even if a JavaScript consumer
// attempts to mutate an erased readonly type.
const INTERNAL_NAVIGATION_HREFS = Object.freeze({
  "/": true,
  "/inbox": true,
  "/knowledge": true,
  "/my-work": true,
  "/projects": true,
  "/teams": true,
} as const);

export type PrimaryRouteId = (typeof primaryNavigation)[number]["id"];
export type PrimaryRoute = (typeof primaryNavigation)[number];

export function internalNavigationHref(value: unknown): string {
  if (
    typeof value !== "string" ||
    !Object.hasOwn(INTERNAL_NAVIGATION_HREFS, value)
  ) {
    throw new Error("navigation target is outside the canonical primary routes");
  }
  return value;
}

export interface MatchedPrimaryRoute {
  readonly kind: "primary";
  readonly route: PrimaryRoute;
}

export interface UnmatchedRoute {
  readonly kind: "unmatched";
}

export type RouteMatch = MatchedPrimaryRoute | UnmatchedRoute;

function normalizePathname(pathname: string): string {
  if (pathname === "/") return pathname;
  return pathname.replace(/\/+$/u, "") || "/";
}

export function matchRoute(pathname: string): RouteMatch {
  const normalized = normalizePathname(pathname);
  const route = primaryNavigation.find((candidate) => candidate.href === normalized);
  return route ? { kind: "primary", route } : { kind: "unmatched" };
}
