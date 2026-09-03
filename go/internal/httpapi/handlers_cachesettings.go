package httpapi

import (
	"encoding/json"
	"net/http"

	"alderpointdns/go-controlplane/internal/cachesettings"
)

func (s *Server) handleGetCacheSettings(w http.ResponseWriter, r *http.Request) {
	if s.CacheSettings == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "cache settings not configured on this deployment").WriteJSON(w)
		return
	}
	settings, err := s.CacheSettings.Get(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load cache settings").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateCacheSettings(w http.ResponseWriter, r *http.Request) {
	if s.CacheSettings == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "cache settings not configured on this deployment").WriteJSON(w)
		return
	}
	var req cachesettings.Settings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	settings, err := s.CacheSettings.Update(r.Context(), req)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "settings": settings, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}
