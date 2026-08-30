package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"alderpointdns/go-controlplane/internal/backup"
)

func backupErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, backup.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, backup.ErrTooLarge):
		return http.StatusBadRequest, "archive_too_large"
	case errors.Is(err, backup.ErrInvalidArchive):
		return http.StatusBadRequest, "invalid_archive"
	case errors.Is(err, backup.ErrSchemaMismatch):
		return http.StatusConflict, "schema_mismatch"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

// handleListBackupCategories exposes internal/backup.CategoryOrder/
// Categories so the frontend's selective-restore picker reflects the
// server's real table grouping instead of a hardcoded, driftable copy.
func (s *Server) handleListBackupCategories(w http.ResponseWriter, r *http.Request) {
	type category struct {
		Name   string   `json:"name"`
		Tables []string `json:"tables"`
	}
	out := make([]category, 0, len(backup.CategoryOrder))
	for _, name := range backup.CategoryOrder {
		out = append(out, category{Name: name, Tables: backup.Categories[name]})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"categories": out})
}

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	list, err := s.Backup.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to list backups").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"backups": list})
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	info, err := s.Backup.Create(r.Context(), "manual")
	if err != nil {
		status, code := backupErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "backup": info})
}

// handleUploadBackup accepts a raw archive body (Content-Type
// application/x-tar or similar -- this is our own native format, not a
// multipart form, matching the fact there's exactly one file per
// request). Size-capped the same way Create/Preview/Restore are.
func (s *Server) handleUploadBackup(w http.ResponseWriter, r *http.Request) {
	filenameHeader := r.URL.Query().Get("filename")
	if filenameHeader == "" || strings.ContainsAny(filenameHeader, "/\\") {
		Err(http.StatusBadRequest, "validation_error", "?filename= query parameter required (no path separators)").WriteJSON(w)
		return
	}
	if err := os.MkdirAll(s.Backup.Dir, 0o750); err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to prepare upload directory").WriteJSON(w)
		return
	}
	dest := filepath.Join(s.Backup.Dir, filenameHeader)
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		Err(http.StatusConflict, "conflict", "a backup with that filename already exists").WriteJSON(w)
		return
	}
	defer f.Close()
	// LimitReader enforces the same archive-bomb size cap Create/Restore
	// use, checked during the write itself -- an oversized upload is
	// rejected (and the partial file removed) before it's ever handed to
	// the tar/manifest parser.
	n, err := io.Copy(f, io.LimitReader(r.Body, 500_000_001))
	if err != nil || n > 500_000_000 {
		f.Close()
		os.Remove(dest)
		Err(http.StatusBadRequest, "archive_too_large", "upload exceeds the size limit").WriteJSON(w)
		return
	}
	info, err := s.Backup.Preview(r.Context(), filenameHeader)
	if err != nil {
		os.Remove(dest)
		status, code := backupErrorStatus(err)
		Err(status, code, "uploaded file is not a valid backup archive: "+err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "uploaded", "backup": info})
}

func (s *Server) handlePreviewBackup(w http.ResponseWriter, r *http.Request) {
	info, err := s.Backup.Preview(r.Context(), r.PathValue("name"))
	if err != nil {
		status, code := backupErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, info)
}

// handleRestoreBackup's request body is optional -- an empty/absent body
// (or "categories": []) restores everything, matching the historical
// all-or-nothing behavior; a non-empty "categories" list restores only
// those categories (see internal/backup.Categories), leaving every other
// table's live data untouched.
func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Categories []string `json:"categories"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
			Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
			return
		}
	}
	safety, err := s.Backup.Restore(r.Context(), r.PathValue("name"), body.Categories)
	if err != nil {
		status, code := backupErrorStatus(err)
		WriteJSON(w, status, map[string]any{"error": code, "detail": err.Error(), "safety_backup": safety})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "restored", "safety_backup": safety})
}

func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	if err := s.Backup.Delete(r.PathValue("name")); err != nil {
		status, code := backupErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (s *Server) handleGetBackupSchedule(w http.ResponseWriter, r *http.Request) {
	settings, err := s.Backup.GetScheduleSettings(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to read backup schedule settings").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, settings)
}

func (s *Server) handleSetBackupSchedule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled        bool `json:"enabled"`
		IntervalHours  int  `json:"interval_hours"`
		RetentionCount int  `json:"retention_count"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	if err := s.Backup.SetScheduleSettings(r.Context(), body.Enabled, body.IntervalHours, body.RetentionCount); err != nil {
		if errors.Is(err, backup.ErrInvalidSchedule) {
			Err(http.StatusBadRequest, "validation_error", "interval_hours must be 1-720 and retention_count must be 0-100").WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", "failed to save backup schedule settings").WriteJSON(w)
		return
	}
	settings, err := s.Backup.GetScheduleSettings(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to read back backup schedule settings").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, settings)
}
