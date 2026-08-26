package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/blocklists"
)

func (s *Server) handleListBlocklists(w http.ResponseWriter, r *http.Request) {
	subs, err := s.Blocklists.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "list failed").WriteJSON(w)
		return
	}
	defaultInterval, _ := s.Blocklists.DefaultInterval(r.Context())
	WriteJSON(w, http.StatusOK, map[string]any{
		"subscriptions": subs,
		"settings": map[string]any{
			"default_interval_seconds": defaultInterval,
			"interval_presets":         blocklists.IntervalPresets,
		},
	})
}

type createBlocklistRequest struct {
	SubscriptionID string `json:"subscription_id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	Category       string `json:"category"`
}

// subscriptionIDFromName derives a stable, URL/path-safe id when the
// client doesn't supply one explicitly -- same "human-editable but unique"
// intent as app/v2/webapp.py's _unique_id helper, simplified for
// Milestone 1 (a content hash suffix rather than a collision-retry loop).
func subscriptionIDFromName(name string) string {
	slug := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, strings.ToLower(name))
	sum := sha256.Sum256([]byte(name + strconv.FormatInt(time.Now().UnixNano(), 10)))
	return slug + "-" + hex.EncodeToString(sum[:4])
}

func (s *Server) handleCreateBlocklist(w http.ResponseWriter, r *http.Request) {
	var req createBlocklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.URL == "" {
		Err(http.StatusBadRequest, "validation_error", "name and url required").WriteJSON(w)
		return
	}
	subID := strings.TrimSpace(req.SubscriptionID)
	if subID == "" {
		subID = subscriptionIDFromName(req.Name)
	}
	sub, jobID, err := s.Blocklists.Create(r.Context(), subID, req.Name, req.URL, req.Category)
	if err != nil {
		Err(http.StatusConflict, "conflict", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "subscription_id": subID, "job_id": jobID, "subscription": sub})
}

type blocklistSettingsRequest struct {
	DefaultIntervalSeconds int `json:"default_interval_seconds"`
}

func (s *Server) handleBlocklistSettings(w http.ResponseWriter, r *http.Request) {
	var req blocklistSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.Blocklists.SetDefaultInterval(r.Context(), req.DefaultIntervalSeconds); err != nil {
		ErrField(http.StatusBadRequest, "validation_error", err.Error(), "default_interval_seconds").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "default_interval_seconds": req.DefaultIntervalSeconds, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

type intervalRequest struct {
	UpdateIntervalSeconds int `json:"update_interval_seconds"`
}

func (s *Server) handleSetBlocklistInterval(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req intervalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.Blocklists.SetInterval(r.Context(), id, req.UpdateIntervalSeconds); err != nil {
		ErrField(http.StatusBadRequest, "validation_error", err.Error(), "update_interval_seconds").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "update_interval_seconds": req.UpdateIntervalSeconds, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleToggleBlocklist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Blocklists.Toggle(r.Context(), id); err != nil {
		Err(http.StatusNotFound, "not_found", "unknown subscription").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleDeleteBlocklist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Blocklists.Delete(r.Context(), id); err != nil {
		Err(http.StatusNotFound, "not_found", "unknown subscription").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleRefreshOneBlocklist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	jobID, err := s.Blocklists.RefreshOne(r.Context(), id)
	if err == blocklists.ErrAlreadyRunning {
		Err(http.StatusConflict, "conflict", "update already running for this subscription").WriteJSON(w)
		return
	} else if err != nil {
		Err(http.StatusNotFound, "not_found", "unknown subscription").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "queued", "job_id": jobID})
}

func (s *Server) handleRefreshAllBlocklists(w http.ResponseWriter, r *http.Request) {
	jobID, count, err := s.Blocklists.RefreshAll(r.Context())
	if err == blocklists.ErrNothingToRefresh {
		WriteJSON(w, http.StatusOK, map[string]any{"status": "empty", "job_id": nil, "message": "no enabled blocklists"})
		return
	} else if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "refresh-all failed").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "queued", "job_id": jobID, "count": count})
}

func (s *Server) handleBlocklistJob(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid job id").WriteJSON(w)
		return
	}
	job, err := s.Blocklists.GetJob(r.Context(), id)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "job lookup failed").WriteJSON(w)
		return
	}
	if job == nil {
		Err(http.StatusNotFound, "not_found", "blocklist update job not found").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, job)
}
