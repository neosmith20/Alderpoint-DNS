package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"alderpointdns/go-controlplane/internal/importer"
)

// handleImportHosts accepts raw hosts-file text (Content-Type text/plain
// or similar -- matching the same "own native format, no multipart"
// design already used for handleUploadBackup) and imports it into
// internal/localdns. See internal/importer's doc comment for exactly
// what source types this does and doesn't cover.
func (s *Server) handleImportHosts(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2_000_001))
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "failed to read request body").WriteJSON(w)
		return
	}
	if len(body) > 2_000_000 {
		Err(http.StatusBadRequest, "validation_error", "hosts file exceeds the 2MB size limit").WriteJSON(w)
		return
	}
	result, err := importer.ImportHosts(r.Context(), s.LocalDNS, string(body))
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

// --- the real staged preview -> apply workflow (internal/importer's
// job model) -- field-matched against Python's own real
// POST /api/import/jobs -> GET .../jobs/{id} -> POST .../jobs/{id}/apply
// shape, see internal/importer/plan.go's own doc comment. ---

type createImportJobRequest struct {
	SourceType string `json:"source_type"`
	SourceName string `json:"source_name"`
	Text       string `json:"text"`
}

func (s *Server) handleCreateImportJob(w http.ResponseWriter, r *http.Request) {
	if s.Importer == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "the import job workflow is not configured for this deployment").WriteJSON(w)
		return
	}
	var req createImportJobRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 2_000_001))
	if err != nil || json.Unmarshal(body, &req) != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if req.SourceName == "" {
		req.SourceName = "import"
	}
	job, err := s.Importer.CreateJob(r.Context(), req.SourceType, req.SourceName, req.Text)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"job_id": job.ID, "plan": job.Plan})
}

func (s *Server) handleListImportJobs(w http.ResponseWriter, r *http.Request) {
	if s.Importer == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "the import job workflow is not configured for this deployment").WriteJSON(w)
		return
	}
	jobs, err := s.Importer.ListJobs(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load import jobs").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func (s *Server) handleGetImportJob(w http.ResponseWriter, r *http.Request) {
	if s.Importer == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "the import job workflow is not configured for this deployment").WriteJSON(w)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid job id").WriteJSON(w)
		return
	}
	job, err := s.Importer.GetJob(r.Context(), id)
	var notFound importer.ErrNotFound
	if errors.As(err, &notFound) {
		Err(http.StatusNotFound, "not_found", "unknown import job").WriteJSON(w)
		return
	} else if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, job)
}

type applyImportJobRequest struct {
	SkipIndexes []int `json:"skip_indexes"`
}

func (s *Server) handleApplyImportJob(w http.ResponseWriter, r *http.Request) {
	if s.Importer == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "the import job workflow is not configured for this deployment").WriteJSON(w)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid job id").WriteJSON(w)
		return
	}
	var req applyImportJobRequest
	json.NewDecoder(r.Body).Decode(&req) // absent/empty body is valid -- skip_indexes defaults empty
	job, err := s.Importer.ApplyJob(r.Context(), id, req.SkipIndexes)
	var notFound importer.ErrNotFound
	if errors.As(err, &notFound) {
		Err(http.StatusNotFound, "not_found", "unknown import job").WriteJSON(w)
		return
	} else if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"status": "applied", "counts": job.Result, "snapshot_filename": job.SnapshotFilename,
		"dns_runtime": s.applyDNSRuntimeBestEffort(r),
	})
}

func (s *Server) handleRollbackImportJob(w http.ResponseWriter, r *http.Request) {
	if s.Importer == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "the import job workflow is not configured for this deployment").WriteJSON(w)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid job id").WriteJSON(w)
		return
	}
	safety, err := s.Importer.Rollback(r.Context(), id)
	if err != nil {
		Err(http.StatusBadRequest, "rollback_failed", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"status": "rolled_back", "safety_backup": safety.Filename,
		"dns_runtime": s.applyDNSRuntimeBestEffort(r),
	})
}
