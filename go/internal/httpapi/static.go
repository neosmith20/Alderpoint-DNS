package httpapi

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleStatic serves the compiled Svelte SPA, falling back to
// index.html for any non-API, non-existent path (client-side routing).
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		Err(http.StatusNotFound, "not_found", "not found").WriteJSON(w)
		return
	}
	clean := filepath.Clean(r.URL.Path)
	candidate := filepath.Join(s.StaticDir, clean)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		http.ServeFile(w, r, candidate)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.StaticDir, "index.html"))
}
