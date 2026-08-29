// Real Secret Backups routes -- see internal/secretbackup's own doc
// comment. Field-matched against V1.1.1's real GET/POST /api/backup/
// secrets, POST /api/backup/secrets/{name}/validate,
// POST /api/backup/secrets/{name}/restore (app/v2/webapp.py, read
// directly); DELETE is a real addition (not in V1.1.1), matching this
// app's own per-row delete convention already used by the main config
// backup grid, since backups would otherwise accumulate with no way to
// remove one.
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"alderpointdns/go-controlplane/internal/secretbackup"
)

func (s *Server) secretBackupUnavailable(w http.ResponseWriter) bool {
	if s.SecretBackup == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "secret backups are not configured for this deployment").WriteJSON(w)
		return true
	}
	return false
}

func secretBackupErrorStatus(err error) (int, string) {
	if errors.Is(err, secretbackup.ErrNotFound) {
		return http.StatusNotFound, "not_found"
	}
	if errors.Is(err, secretbackup.ErrUnavailable) {
		return http.StatusServiceUnavailable, "unavailable"
	}
	return http.StatusInternalServerError, "internal_error"
}

func (s *Server) handleListSecretBackups(w http.ResponseWriter, r *http.Request) {
	if s.secretBackupUnavailable(w) {
		return
	}
	backups, jobs, err := s.SecretBackup.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to list secret backups").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"backups": backups, "jobs": jobs})
}

func (s *Server) handleCreateSecretBackup(w http.ResponseWriter, r *http.Request) {
	if s.secretBackupUnavailable(w) {
		return
	}
	info, err := s.SecretBackup.Create(r.Context())
	if err != nil {
		status, code := secretBackupErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "backup": info})
}

func (s *Server) handleValidateSecretBackup(w http.ResponseWriter, r *http.Request) {
	if s.secretBackupUnavailable(w) {
		return
	}
	name := r.PathValue("name")
	count, err := s.SecretBackup.Validate(r.Context(), name)
	if err != nil {
		status, code := secretBackupErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "valid", "secret_count": count})
}

type restoreSecretBackupRequest struct {
	Overwrite bool `json:"overwrite"`
}

func (s *Server) handleRestoreSecretBackup(w http.ResponseWriter, r *http.Request) {
	if s.secretBackupUnavailable(w) {
		return
	}
	name := r.PathValue("name")
	var req restoreSecretBackupRequest
	json.NewDecoder(r.Body).Decode(&req) // absent/empty body is valid -- overwrite defaults false
	count, err := s.SecretBackup.Restore(r.Context(), name, req.Overwrite)
	if err != nil {
		status, code := secretBackupErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "restored", "restored_count": count})
}

func (s *Server) handleDeleteSecretBackup(w http.ResponseWriter, r *http.Request) {
	if s.secretBackupUnavailable(w) {
		return
	}
	name := r.PathValue("name")
	if err := s.SecretBackup.Delete(name); err != nil {
		status, code := secretBackupErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}
