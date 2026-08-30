export const primaryNavigation = [
  {
    id: "home",
    label: "Home",
    href: "/",
    description: "Your authorized overview will appear here.",
  },
  {
    id: "inbox",
    label: "Inbox",
    href: "/inbox",
    description: "There are no authorized updates to show.",
  },
  {
    id: "my-work",
    label: "My Work",
    href: "/my-work",
    description: "Assigned Work will appear here.",
  },
  {
    id: "projects",
    label: "Projects",
    href: "/projects",
    description: "Authorized Projects will appear here.",
  },
  {
    id: "knowledge",
    label: "Knowledge",
    href: "/knowledge",
    description: "Authorized Documents will appear here.",
  },
  {
    id: "teams",
    label: "Teams",
    href: "/teams",
    description: "Authorized Teams will appear here.",
  },
] as const;

export type PrimaryRouteId = (typeof primaryNavigation)[number]["id"];
export type PrimaryRoute = (typeof primaryNavigation)[number];

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
