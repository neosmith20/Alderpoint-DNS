// Real Go-native Replication routes -- see internal/replication's own
// doc comment for the full architecture. Field-matched against V1.1.1's
// real owner-facing workflow (app/webapp.py's /replication/* routes,
// read directly), translated from server-rendered Jinja forms to this
// app's own JSON API conventions; the actions themselves (role, token,
// enrollment revoke, replica status, connect, sync-now, drift-check,
// pause, settings) are the same real actions, not a new design.
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"alderpointdns/go-controlplane/internal/replication"
)

func (s *Server) registerReplicationRoutes(mux *http.ServeMux) {
	requireAuth := func(h http.HandlerFunc) http.HandlerFunc {
		return RequireAuth(s.Auth, s.SessionTTL, s.LastSeen, h)
	}
	mux.HandleFunc("GET /api/replication/status", requireAuth(s.handleReplicationStatus))
	mux.HandleFunc("POST /api/replication/role", requireAuth(s.audited("replication_role_create", s.handleReplicationSetRole)))
	mux.HandleFunc("POST /api/replication/token", requireAuth(s.audited("replication_token_create", s.handleReplicationGenerateToken)))
	mux.HandleFunc("POST /api/replication/enrollments/{id}/revoke", requireAuth(s.audited("replication_enrollment_revoke", s.handleReplicationRevokeEnrollment)))
	mux.HandleFunc("POST /api/replication/replicas/{id}/status", requireAuth(s.audited("replication_replica_status_set", s.handleReplicationSetReplicaStatus)))
	mux.HandleFunc("POST /api/replication/connect", requireAuth(s.audited("replication_connect_create", s.handleReplicationConnect)))
	mux.HandleFunc("POST /api/replication/sync-now", requireAuth(s.audited("replication_sync_now", s.handleReplicationSyncNow)))
	mux.HandleFunc("POST /api/replication/drift-check", requireAuth(s.audited("replication_drift_check", s.handleReplicationDriftCheck)))
	mux.HandleFunc("POST /api/replication/pause", requireAuth(s.audited("replication_pause_create", s.handleReplicationPause)))
	mux.HandleFunc("POST /api/replication/settings", requireAuth(s.audited("replication_settings_create", s.handleReplicationSettings)))
	mux.HandleFunc("POST /api/replication/generations", requireAuth(s.audited("replication_generation_publish", s.handleReplicationPublishGeneration)))
}

func (s *Server) replicationUnavailable(w http.ResponseWriter) bool {
	if s.Replication == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "replication is not configured for this deployment").WriteJSON(w)
		return true
	}
	return false
}

func (s *Server) handleReplicationStatus(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	settings, err := s.Replication.GetSettings(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	out := map[string]any{"settings": settings}
	switch settings.Role {
	case "primary":
		enrollments, err := s.Replication.ListEnrollments(r.Context())
		if err != nil {
			Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
			return
		}
		replicas, err := s.Replication.ListReplicas(r.Context())
		if err != nil {
			Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
			return
		}
		latest, err := s.Replication.LatestGeneration(r.Context(), false)
		if err != nil {
			Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
			return
		}
		out["enrollments"] = enrollments
		out["replicas"] = replicas
		out["latest_generation"] = latest
		out["listener_running"] = s.Replication.ListenerRunning()
	case "replica":
		history, err := s.Replication.SyncHistory(r.Context(), 20)
		if err != nil {
			Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
			return
		}
		out["sync_history"] = history
	}
	WriteJSON(w, http.StatusOK, out)
}

func (s *Server) handleReplicationSetRole(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	if err := s.Replication.SetRole(r.Context(), req.Role); err != nil {
		if errors.Is(err, replication.ErrValidation) {
			Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "role updated"})
}

func (s *Server) handleReplicationGenerateToken(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	var req struct {
		NodeName string `json:"node_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	if err := s.Replication.EnsurePrimaryListenerRunning(r.Context()); err != nil {
		Err(http.StatusBadRequest, "listener_failed", err.Error()).WriteJSON(w)
		return
	}
	token, err := s.Replication.GenerateEnrollmentToken(r.Context(), req.NodeName)
	if err != nil {
		if errors.Is(err, replication.ErrValidation) {
			Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, token)
}

func (s *Server) handleReplicationRevokeEnrollment(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid enrollment id").WriteJSON(w)
		return
	}
	if err := s.Replication.RevokeEnrollment(r.Context(), id); err != nil {
		if errors.Is(err, replication.ErrNotFound) {
			Err(http.StatusNotFound, "not_found", err.Error()).WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleReplicationSetReplicaStatus(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid replica id").WriteJSON(w)
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	if err := s.Replication.SetReplicaStatus(r.Context(), id, req.Status); err != nil {
		if errors.Is(err, replication.ErrValidation) {
			Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
			return
		}
		if errors.Is(err, replication.ErrNotFound) {
			Err(http.StatusNotFound, "not_found", err.Error()).WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleReplicationConnect(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	var req struct {
		PrimaryHost string `json:"primary_host"`
		PrimaryPort int    `json:"primary_port"`
		Token       string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PrimaryHost == "" || req.Token == "" {
		Err(http.StatusBadRequest, "validation_error", "primary_host and token are required").WriteJSON(w)
		return
	}
	if req.PrimaryPort == 0 {
		req.PrimaryPort = replication.DefaultListenPort
	}
	enrolled, err := s.Replication.EnrollWithPrimary(r.Context(), req.PrimaryHost, req.PrimaryPort, req.Token)
	if err != nil {
		Err(http.StatusBadRequest, "enrollment_failed", err.Error()).WriteJSON(w)
		return
	}
	primaryAddress := req.PrimaryHost + ":" + strconv.Itoa(req.PrimaryPort)
	if err := s.Replication.StoreEnrollmentMaterial(r.Context(), primaryAddress, enrolled); err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	s.Replication.StopPrimaryListener()
	s.Replication.StartPoller(r.Context())
	WriteJSON(w, http.StatusOK, map[string]string{"status": "enrolled", "node_id": enrolled.NodeID})
}

func (s *Server) handleReplicationSyncNow(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	result := s.Replication.SyncNow(r.Context())
	WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleReplicationDriftCheck(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	drifted, localHash, expectedHash, err := s.Replication.CheckDrift(r.Context())
	if err != nil {
		Err(http.StatusBadRequest, "drift_check_failed", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"drifted": drifted, "local_hash": localHash, "expected_hash": expectedHash})
}

func (s *Server) handleReplicationPause(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	var req struct {
		Paused bool `json:"paused"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	if err := s.Replication.SetPaused(r.Context(), req.Paused); err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleReplicationSettings(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	var req struct {
		ListenHost                string `json:"listen_host"`
		ListenPort                int    `json:"listen_port"`
		PollIntervalSeconds       int    `json:"poll_interval_seconds"`
		IncludeEncryptionSettings bool   `json:"include_encryption_settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	if err := s.Replication.UpdateSettings(r.Context(), req.ListenHost, req.ListenPort, req.PollIntervalSeconds, req.IncludeEncryptionSettings); err != nil {
		if errors.Is(err, replication.ErrValidation) {
			Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// handleReplicationPublishGeneration is the real "Publish Generation"
// owner action -- see internal/replication.CreateGeneration's own doc
// comment for why this is an explicit action here rather than an
// automatic post-deploy hook the way Python's on_deploy_success() is.
func (s *Server) handleReplicationPublishGeneration(w http.ResponseWriter, r *http.Request) {
	if s.replicationUnavailable(w) {
		return
	}
	gen, err := s.Replication.CreateGeneration(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	gen.Sections = nil // the list/status response never needs to carry the full payload back down
	WriteJSON(w, http.StatusCreated, gen)
}
