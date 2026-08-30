import { useCallback, useEffect, useMemo, useState } from "react";

import { beginPerformanceSpan, recordRouteNavigation } from "./performance";
import { matchRoute } from "./routes";

export function useRoute() {
  const [pathname, setPathname] = useState(() => window.location.pathname);

  useEffect(() => {
    const handlePopState = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const navigate = useCallback((href: string) => {
    if (window.location.pathname === href) return;
    beginPerformanceSpan("route-useful-content");
    recordRouteNavigation();
    window.history.pushState(null, "", href);
    setPathname(window.location.pathname);
  }, []);

  return {
    pathname,
    match: useMemo(() => matchRoute(pathname), [pathname]),
    navigate,
  };
}
