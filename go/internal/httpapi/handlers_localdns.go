package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"alderpointdns/go-controlplane/internal/localdns"
)

func (s *Server) handleListLocalDNS(w http.ResponseWriter, r *http.Request) {
	records, err := s.LocalDNS.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "list failed").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"records": records})
}

type createLocalDNSRequest struct {
	Name       string `json:"name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	TTL        int    `json:"ttl"`
	Enabled    bool   `json:"enabled"`
}

func (s *Server) handleCreateLocalDNS(w http.ResponseWriter, r *http.Request) {
	var req createLocalDNSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if req.TTL == 0 {
		req.TTL = 300
	}
	rec, err := s.LocalDNS.Create(r.Context(), localdns.CreateInput{
		Name: req.Name, RecordType: req.RecordType, Value: req.Value, TTL: req.TTL, Enabled: req.Enabled,
	})
	if err == localdns.ErrDuplicate {
		Err(http.StatusConflict, "duplicate_record", "that Local DNS record already exists").WriteJSON(w)
		return
	} else if err != nil {
		ErrField(http.StatusBadRequest, "validation_error", err.Error(), "value").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "record": rec, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

type updateLocalDNSRequest struct {
	Value   *string `json:"value"`
	TTL     *int    `json:"ttl"`
	Enabled *bool   `json:"enabled"`
}

func (s *Server) handleUpdateLocalDNS(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid id").WriteJSON(w)
		return
	}
	var req updateLocalDNSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	rec, err := s.LocalDNS.Update(r.Context(), id, localdns.UpdateInput{Value: req.Value, TTL: req.TTL, Enabled: req.Enabled})
	if err == localdns.ErrNotFound {
		Err(http.StatusNotFound, "not_found", "unknown record").WriteJSON(w)
		return
	} else if err != nil {
		ErrField(http.StatusBadRequest, "validation_error", err.Error(), "value").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "record": rec, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleDeleteLocalDNS(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid id").WriteJSON(w)
		return
	}
	if err := s.LocalDNS.Delete(r.Context(), id); err == localdns.ErrNotFound {
		Err(http.StatusNotFound, "not_found", "unknown record").WriteJSON(w)
		return
	} else if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "delete failed").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}
