import { useEffect, useLayoutEffect } from "react";

import { EmptyState } from "../../../packages/design-system/src/index";

import { inspectLazyCapabilityBoundaries } from "./capabilities/lazy";
import { CommandPalette } from "./CommandPalette";
import {
  endPerformanceSpan,
  recordLazyCapabilityChunkCount,
} from "./performance";
import { platformContractVersion } from "./platform";
import {
  internalNavigationHref,
  primaryNavigation,
  type PrimaryRouteId,
  type RouteMatch,
} from "./routes";
import { ThemeControl } from "./ThemeControl";

interface AppShellProps {
  readonly route: RouteMatch;
  readonly navigate: (href: string) => void;
}

function NavigationGlyph({ route }: { readonly route: PrimaryRouteId }) {
  const glyphs: Record<PrimaryRouteId, string> = {
    home: "⌂",
    inbox: "↓",
    "my-work": "✓",
    projects: "◇",
    knowledge: "▤",
    teams: "◎",
  };
  return (
    <span className="navigation-glyph" aria-hidden="true">
      {glyphs[route]}
    </span>
  );
}

function RouteSurface({ route }: { readonly route: RouteMatch }) {
  useLayoutEffect(() => {
    endPerformanceSpan("route-useful-content");
    endPerformanceSpan("cold-interactive");
  }, [route]);

  if (route.kind === "unmatched") {
    return (
      <EmptyState
        title="This view is unavailable"
        description="Use the primary navigation to continue. No resource information was disclosed."
      />
    );
  }

  return (
    <div className="route-surface" data-route={route.route.id}>
      <header className="route-heading">
        <p>Stead</p>
        <h1>{route.route.label}</h1>
      </header>
      <EmptyState title={`No ${route.route.label.toLocaleLowerCase()} to show`} description={route.route.description} />
    </div>
  );
}

export function AppShell({ route, navigate }: AppShellProps) {
  const activeRoute = route.kind === "primary" ? route.route.id : undefined;
  const lazyBoundaries = inspectLazyCapabilityBoundaries();

  useEffect(() => {
    recordLazyCapabilityChunkCount(lazyBoundaries.length);
  }, [lazyBoundaries.length]);

  return (
    <div
      className="app-screen"
      data-api-contract={platformContractVersion}
      data-lazy-boundaries={lazyBoundaries.join(",")}
    >
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <div className="app-frame">
        <aside className="app-sidebar" aria-label="Application sidebar">
          <div className="brand">
            <span className="brand__mark" aria-hidden="true">
              S
            </span>
            <span>Stead</span>
          </div>
          <CommandPalette navigate={navigate} />
          <nav className="primary-navigation" aria-label="Primary navigation">
            {primaryNavigation.map((item) => {
              const active = item.id === activeRoute;
              const href = internalNavigationHref(item.href);
              return (
                <a
                  key={item.id}
                  href={href}
                  aria-current={active ? "page" : undefined}
                  onClick={(event) => {
                    if (
                      event.button !== 0 ||
                      event.metaKey ||
                      event.ctrlKey ||
                      event.shiftKey ||
                      event.altKey
                    ) {
                      return;
                    }
                    event.preventDefault();
                    navigate(href);
                  }}
                >
                  <NavigationGlyph route={item.id} />
                  <span>{item.label}</span>
                </a>
              );
            })}
          </nav>
          <div className="sidebar-footer">
            <p>Authorized presentation only</p>
            <ThemeControl />
          </div>
        </aside>
        <section className="app-workspace" aria-label="Workspace">
          <header className="workspace-header">
            <div>
              <span className="workspace-header__context">Organization</span>
              <span aria-hidden="true"> / </span>
              <strong>{route.kind === "primary" ? route.route.label : "Unavailable"}</strong>
            </div>
            <span className="session-indicator">Session context pending</span>
          </header>
          <main id="main-content" className="main-content" tabIndex={-1}>
            <RouteSurface route={route} />
          </main>
        </section>
      </div>
    </div>
  );
}
