package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"alderpointdns/go-controlplane/internal/observedretention"
)

// Observed Clients retention -- GET/PUT its settings, a live preview of
// how many clients the current (or a proposed) retention_days would
// remove, and a manual "clean now" action. See
// internal/observedretention's own doc comment for the full design;
// s.ObservedRetention is nil unless -analytics-db was given a real path
// at startup (same optional-boundary contract as s.Analytics/
// s.AnalyticsSettings), since there is nothing real to clean without a
// real analytics database.
const observedRetentionUnavailable = "Observed Clients retention is not configured for this deployment (no analytics database)"

func (s *Server) handleGetObservedRetentionSettings(w http.ResponseWriter, r *http.Request) {
	if s.ObservedRetention == nil {
		Err(http.StatusServiceUnavailable, "unavailable", observedRetentionUnavailable).WriteJSON(w)
		return
	}
	settings, err := s.ObservedRetention.GetSettings(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to read observed-client retention settings").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, settings)
}

func (s *Server) handleSetObservedRetentionSettings(w http.ResponseWriter, r *http.Request) {
	if s.ObservedRetention == nil {
		Err(http.StatusServiceUnavailable, "unavailable", observedRetentionUnavailable).WriteJSON(w)
		return
	}
	var body struct {
		RetentionDays int    `json:"retention_days"`
		Schedule      string `json:"schedule"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	if err := s.ObservedRetention.SetSettings(r.Context(), body.RetentionDays, body.Schedule); err != nil {
		if errors.Is(err, observedretention.ErrInvalidSettings) {
			Err(http.StatusBadRequest, "validation_error", "retention_days must be 1-3650 and schedule must be one of: manual, daily, weekly, monthly").WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", "failed to save observed-client retention settings").WriteJSON(w)
		return
	}
	settings, err := s.ObservedRetention.GetSettings(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to read back observed-client retention settings").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, settings)
}

// handlePreviewObservedRetention answers "how many observed clients
// would this remove" for a given retention_days WITHOUT deleting
// anything -- the clear "what will be removed" explanation the owner
// sees before running a manual clean or saving a new retention window.
// ?retention_days= is optional; omitted, it previews the currently
// persisted setting.
func (s *Server) handlePreviewObservedRetention(w http.ResponseWriter, r *http.Request) {
	if s.ObservedRetention == nil {
		Err(http.StatusServiceUnavailable, "unavailable", observedRetentionUnavailable).WriteJSON(w)
		return
	}
	var retentionDays int
	if raw := r.URL.Query().Get("retention_days"); raw != "" {
		retentionDays = intQuery(r, "retention_days", 90, 1, 3650)
	} else {
		settings, err := s.ObservedRetention.GetSettings(r.Context())
		if err != nil {
			Err(http.StatusInternalServerError, "internal_error", "failed to read observed-client retention settings").WriteJSON(w)
			return
		}
		retentionDays = settings.RetentionDays
	}
	count, err := s.ObservedRetention.Preview(r.Context(), retentionDays)
	if err != nil {
		if errors.Is(err, observedretention.ErrAnalyticsUnavailable) {
			WriteJSON(w, http.StatusOK, map[string]any{"would_remove_clients": 0, "degraded": true, "degraded_reason": err.Error()})
			return
		}
		Err(http.StatusInternalServerError, "internal_error", "failed to preview observed-client retention").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"would_remove_clients": count, "retention_days": retentionDays, "degraded": false})
}

// handleCleanObservedRetention is the owner's manual "Clean old observed
// clients" action -- runs a real cleanup immediately at the currently
// persisted retention_days, the exact same path the scheduler uses.
// Never a blanket delete: only clients whose own most recent query is
// older than retention_days are touched (see
// dnsanalytics.Reader.CleanStaleClients's own doc comment).
func (s *Server) handleCleanObservedRetention(w http.ResponseWriter, r *http.Request) {
	if s.ObservedRetention == nil {
		Err(http.StatusServiceUnavailable, "unavailable", observedRetentionUnavailable).WriteJSON(w)
		return
	}
	removed, err := s.ObservedRetention.CleanNow(r.Context())
	if err != nil {
		if errors.Is(err, observedretention.ErrAnalyticsUnavailable) {
			Err(http.StatusServiceUnavailable, "unavailable", err.Error()).WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", "failed to clean observed clients").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"removed_clients": removed})
}
