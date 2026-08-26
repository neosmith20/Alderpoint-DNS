// Tiny path-based client router: /ui/{routeId}, matching the Python V2
// SPA's own URL convention. The Go static handler already falls back to
// index.html for any non-file path (internal/httpapi/static.go), so plain
// History API pushState works with no server changes.
//
// Responsibilities kept deliberately narrow: track the current route id,
// expose navigate(), and give each page a per-navigation AbortSignal so a
// page's in-flight fetches are cancelled the moment the user routes away
// (no background work continuing off-route, no stale response landing on
// the next page -- the two explicit shell requirements this exists for).
import { defaultRouteId, findItem } from "./nav";

function routeIdFromPath(path: string): string {
  const m = path.match(/^\/ui\/([a-z0-9-]+)/i);
  return m ? m[1] : defaultRouteId();
}

class Router {
  current = $state(routeIdFromPath(location.pathname));
  private controller: AbortController | undefined;

  /** AbortSignal for the currently-active route; a page's data loads should
   * pass this to fetch/api calls so navigating away cancels them. */
  signal(): AbortSignal {
    this.controller ??= new AbortController();
    return this.controller.signal;
  }

  navigate(id: string, replace = false): void {
    if (!findItem(id)) return; // unknown id, ignore rather than 404 the SPA
    const path = `/ui/${id}`;
    if (replace) history.replaceState(null, "", path);
    else history.pushState(null, "", path);
    this.setRoute(id);
  }

  private setRoute(id: string): void {
    this.controller?.abort();
    this.controller = new AbortController();
    this.current = id;
  }

  constructor() {
    window.addEventListener("popstate", () => {
      this.setRoute(routeIdFromPath(location.pathname));
    });
  }
}

export const router = new Router();
