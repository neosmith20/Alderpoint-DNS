package httpapi

import "net/http"

// handleDNSRuntimeGenerations backs DNS Runtime's real "Recent
// deployment history" section -- see internal/dnsgenerations' own doc
// comment for the exact, disclosed scope (a real dnsdist config
// snapshot per promoted generation; diagnostic-only rows otherwise; no
// BIND-side file snapshot).
func (s *Server) handleDNSRuntimeGenerations(w http.ResponseWriter, r *http.Request) {
	if s.Generations == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"generations": []any{}, "available": false})
		return
	}
	history, err := s.Generations.History(r.Context(), 50)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load deployment history").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"generations": history, "available": true})
}

func (s *Server) handleDNSRuntimeInventory(w http.ResponseWriter, r *http.Request) {
	if s.DNSRuntime == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"files": []any{}, "available": false})
		return
	}
	files, err := s.DNSRuntime.ConfigInventory(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load configuration inventory").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"files": files, "available": true})
}

func (s *Server) handleDNSRuntimePendingChanges(w http.ResponseWriter, r *http.Request) {
	if s.DNSRuntime == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"known": false, "pending": false})
		return
	}
	result, err := s.DNSRuntime.PendingChanges(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to compute pending changes").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleDNSRuntimeRollback(w http.ResponseWriter, r *http.Request) {
	if s.DNSRuntime == nil {
		Err(http.StatusServiceUnavailable, "unavailable", hostagentUnavailable).WriteJSON(w)
		return
	}
	result := s.DNSRuntime.Rollback(r.Context())
	WriteJSON(w, http.StatusOK, result)
}
