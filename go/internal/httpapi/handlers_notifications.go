package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"alderpointdns/go-controlplane/internal/notifications"
)

func (s *Server) handleListNotificationProviders(w http.ResponseWriter, r *http.Request) {
	list, err := s.Notifications.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to list notification providers").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"providers": list})
}

func (s *Server) handleCreateNotificationProvider(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind        string `json:"kind"`
		DisplayName string `json:"display_name"`
		Endpoint    string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	p, err := s.Notifications.Create(r.Context(), body.Kind, body.DisplayName, body.Endpoint)
	if err != nil {
		if errors.Is(err, notifications.ErrValidation) {
			Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, p)
}

func (s *Server) handleToggleNotificationProvider(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	if err := s.Notifications.SetEnabled(r.Context(), r.PathValue("id"), body.Enabled); err != nil {
		if errors.Is(err, notifications.ErrNotFound) {
			Err(http.StatusNotFound, "not_found", "unknown provider").WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

func (s *Server) handleDeleteNotificationProvider(w http.ResponseWriter, r *http.Request) {
	if err := s.Notifications.Delete(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, notifications.ErrNotFound) {
			Err(http.StatusNotFound, "not_found", "unknown provider").WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}
