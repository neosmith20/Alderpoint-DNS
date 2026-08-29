package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"alderpointdns/go-controlplane/internal/notifications"
	"alderpointdns/go-controlplane/internal/secretstore"
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
		Kind        string          `json:"kind"`
		DisplayName string          `json:"display_name"`
		Config      json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	p, err := s.Notifications.Create(r.Context(), body.Kind, body.DisplayName, body.Config)
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

// handleSetNotificationSecret stores/replaces a provider's credential.
// Deliberately write-only: there is no corresponding GET -- once saved,
// a secret is never displayed back (see internal/secretstore's doc
// comment).
func (s *Server) handleSetNotificationSecret(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	err := s.Notifications.SetSecret(r.Context(), r.PathValue("id"), body.Value)
	if writeNotificationSecretError(w, err) {
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "set"})
}

func (s *Server) handleRevokeNotificationSecret(w http.ResponseWriter, r *http.Request) {
	err := s.Notifications.RevokeSecret(r.Context(), r.PathValue("id"))
	if writeNotificationSecretError(w, err) {
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
}

func (s *Server) handleTestNotificationProvider(w http.ResponseWriter, r *http.Request) {
	result, err := s.Notifications.Test(r.Context(), r.PathValue("id"))
	if writeNotificationSecretError(w, err) {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

// writeNotificationSecretError centralizes the shared error-shape
// mapping for every secret-touching notifications handler; returns
// true if it wrote a response (caller should return immediately).
func writeNotificationSecretError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, notifications.ErrNotFound) {
		Err(http.StatusNotFound, "not_found", "unknown provider").WriteJSON(w)
		return true
	}
	if errors.Is(err, notifications.ErrValidation) {
		Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
		return true
	}
	if errors.Is(err, secretstore.ErrUnavailable) {
		WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable", "detail": err.Error()})
		return true
	}
	Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
	return true
}

// handleListEventCategories exposes the fixed, real event vocabulary
// (internal/notifications.EventCategories) so the UI can offer a
// subscription form without hand-coding the category list twice.
func (s *Server) handleListEventCategories(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]any{"categories": notifications.EventCategories})
}

func (s *Server) handleListNotificationSubscriptions(w http.ResponseWriter, r *http.Request) {
	list, err := s.Notifications.ListSubscriptions(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to list subscriptions").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"subscriptions": list})
}

func (s *Server) handleCreateNotificationSubscription(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ProviderID      string `json:"provider_id"`
		EventCategory   string `json:"event_category"`
		MinSeverity     string `json:"min_severity"`
		Enabled         bool   `json:"enabled"`
		CooldownMinutes *int   `json:"cooldown_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	if body.MinSeverity == "" {
		body.MinSeverity = "warning"
	}
	if err := s.Notifications.SetSubscription(r.Context(), body.ProviderID, body.EventCategory, body.MinSeverity, body.Enabled, body.CooldownMinutes); err != nil {
		if writeNotificationSecretError(w, err) {
			return
		}
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created"})
}

func (s *Server) handleDeleteNotificationSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid id").WriteJSON(w)
		return
	}
	if err := s.Notifications.DeleteSubscription(r.Context(), id); err != nil {
		if writeNotificationSecretError(w, err) {
			return
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (s *Server) handleListNotificationHistory(w http.ResponseWriter, r *http.Request) {
	limit := intQuery(r, "limit", 100, 1, 500)
	list, err := s.Notifications.ListHistory(r.Context(), limit)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to list delivery history").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"history": list})
}
