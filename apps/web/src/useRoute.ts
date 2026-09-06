import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { beginPerformanceSpan, recordRouteNavigation } from "./performance";
import { internalNavigationHref, matchRoute } from "./routes";

export function useRoute() {
  const [pathname, setPathname] = useState(() => window.location.pathname);
  const currentPathname = useRef(pathname);

  useEffect(() => {
    const handlePopState = () => {
      if (window.location.pathname === currentPathname.current) return;
      currentPathname.current = window.location.pathname;
      beginPerformanceSpan("route-shell-acknowledgement");
      beginPerformanceSpan("route-useful-content");
      beginPerformanceSpan("route-interactive");
      recordRouteNavigation();
      setPathname(currentPathname.current);
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const navigate = useCallback((href: string) => {
    const target = internalNavigationHref(href);
    if (window.location.pathname === target) return;
    beginPerformanceSpan("route-shell-acknowledgement");
    beginPerformanceSpan("route-useful-content");
    beginPerformanceSpan("route-interactive");
    recordRouteNavigation();
    window.history.pushState(null, "", target);
    currentPathname.current = window.location.pathname;
    setPathname(currentPathname.current);
  }, []);

  return {
    pathname,
    match: useMemo(() => matchRoute(pathname), [pathname]),
    navigate,
  };
}
