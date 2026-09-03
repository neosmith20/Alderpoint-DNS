package httpapi

import (
	"encoding/json"
	"net/http"

	"alderpointdns/go-controlplane/internal/blockedservices"
)

// handleListBlockedServicesCatalog: the static catalog itself (Standard
// > Filters > Blocked Services' own grid) -- no owner data, so this
// never errors even when s.BlockedServices is nil (unlike every other
// endpoint below, which needs the real DB-backed settings).
func (s *Server) handleListBlockedServicesCatalog(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]any{"services": blockedservices.Catalog})
}

func (s *Server) handleGetBlockedServicesSettings(w http.ResponseWriter, r *http.Request) {
	if s.BlockedServices == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "blocked services not configured on this deployment").WriteJSON(w)
		return
	}
	settings, err := s.BlockedServices.GetSettings(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load blocked services settings").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, settings)
}

type setBlockedServicesRequest struct {
	ServiceIDs []string `json:"service_ids"`
}

func (s *Server) handleSetBlockedServicesEnabled(w http.ResponseWriter, r *http.Request) {
	if s.BlockedServices == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "blocked services not configured on this deployment").WriteJSON(w)
		return
	}
	var req setBlockedServicesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	settings, err := s.BlockedServices.SetEnabledServices(r.Context(), req.ServiceIDs)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "settings": settings, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleSetBlockedServicesSchedule(w http.ResponseWriter, r *http.Request) {
	if s.BlockedServices == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "blocked services not configured on this deployment").WriteJSON(w)
		return
	}
	var req blockedservices.ScheduleInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	settings, err := s.BlockedServices.SetSchedule(r.Context(), req)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "settings": settings, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}
