package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
)

type setApplianceDisplayNameRequest struct {
	DisplayName string `json:"display_name"`
}

// handleSetApplianceDisplayName backs General Settings > Appliance
// Identity's display name field -- see internal/appliancesettings' own
// doc comment for why this is the one genuinely new settings write path
// General Settings needed.
func (s *Server) handleSetApplianceDisplayName(w http.ResponseWriter, r *http.Request) {
	if s.ApplianceSettings == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "appliance settings not configured on this deployment").WriteJSON(w)
		return
	}
	var req setApplianceDisplayNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" {
		Err(http.StatusBadRequest, "validation_error", "display name is required").WriteJSON(w)
		return
	}
	if err := s.ApplianceSettings.Set(r.Context(), name); err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to save display name").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "appliance_name": name})
}
