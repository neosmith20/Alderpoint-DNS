// Real Pi-hole and AdGuard Home YAML import routes -- see
// internal/filterimport's own doc comment for scope and what's
// deliberately not attempted (whitelist-filter subscriptions, client/
// group translation, the live AdGuard API source).
package httpapi

import (
	"encoding/json"
	"net/http"
)

func (s *Server) filterImportUnavailable(w http.ResponseWriter) bool {
	if s.FilterImport == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "Pi-hole/AdGuard import is not configured for this deployment").WriteJSON(w)
		return true
	}
	return false
}

type piholeImportRequest struct {
	Text          string `json:"text"`
	DefaultDomain string `json:"default_domain"`
	DryRun        bool   `json:"dry_run"`
}

func (s *Server) handleImportPihole(w http.ResponseWriter, r *http.Request) {
	if s.filterImportUnavailable(w) {
		return
	}
	var req piholeImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if req.Text == "" {
		Err(http.StatusBadRequest, "validation_error", "text is required").WriteJSON(w)
		return
	}
	report, err := s.FilterImport.ImportPihole(r.Context(), req.Text, req.DefaultDomain, req.DryRun)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"report": report})
}

type adguardImportRequest struct {
	Text   string `json:"text"`
	DryRun bool   `json:"dry_run"`
}

func (s *Server) handleImportAdGuardYAML(w http.ResponseWriter, r *http.Request) {
	if s.filterImportUnavailable(w) {
		return
	}
	var req adguardImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if req.Text == "" {
		Err(http.StatusBadRequest, "validation_error", "text is required").WriteJSON(w)
		return
	}
	report, err := s.FilterImport.ImportAdGuardYAML(r.Context(), req.Text, req.DryRun)
	if err != nil {
		Err(http.StatusBadRequest, "invalid_config", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"report": report})
}
