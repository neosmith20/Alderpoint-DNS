package httpapi

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleStatic serves the compiled Svelte SPA, falling back to
// index.html for any non-API, non-existent path (client-side routing).
//
// Real deployed-integrity defect found and fixed here: this handler
// used to set no Cache-Control at all, leaving index.html subject to
// the browser's own heuristic caching. Every content-hashed chunk under
// /assets/ gets a brand-new filename on every rebuild, and this
// project's own deploy procedure replaces the whole static directory
// wholesale (old hashed files genuinely gone, not just superseded) --
// so a browser holding even a short-lived cached copy of index.html
// from before a redeploy will try to fetch JS/CSS chunk filenames that
// no longer exist on disk at all, surfacing as exactly the reported
// live failures ("CSS preload failure", "dynamic JS import failure")
// on whichever routes happened to lazy-load a chunk the old index.html
// pointed at. The fix matches standard practice for hashed-asset SPAs:
// index.html (and any other non-hashed top-level file) is always
// revalidated, never served stale from the browser's own cache;
// content-hashed files under /assets/ are safe to cache forever, since
// their filename itself changes on any real content change.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		Err(http.StatusNotFound, "not_found", "not found").WriteJSON(w)
		return
	}
	clean := filepath.Clean(r.URL.Path)
	candidate := filepath.Join(s.StaticDir, clean)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		if strings.HasPrefix(clean, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeFile(w, r, candidate)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, filepath.Join(s.StaticDir, "index.html"))
}
