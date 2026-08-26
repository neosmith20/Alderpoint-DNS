package httpapi

import (
	"io"
	"net/http"

	"alderpointdns/go-controlplane/internal/importer"
)

// handleImportHosts accepts raw hosts-file text (Content-Type text/plain
// or similar -- matching the same "own native format, no multipart"
// design already used for handleUploadBackup) and imports it into
// internal/localdns. See internal/importer's doc comment for exactly
// what source types this does and doesn't cover.
func (s *Server) handleImportHosts(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2_000_001))
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "failed to read request body").WriteJSON(w)
		return
	}
	if len(body) > 2_000_000 {
		Err(http.StatusBadRequest, "validation_error", "hosts file exceeds the 2MB size limit").WriteJSON(w)
		return
	}
	result, err := importer.ImportHosts(r.Context(), s.LocalDNS, string(body))
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, result)
}
