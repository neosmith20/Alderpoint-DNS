package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"alderpointdns/go-controlplane/internal/domainrouting"
)

func domainRoutingErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, domainrouting.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, domainrouting.ErrValidation):
		return http.StatusBadRequest, "validation_error"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func (s *Server) handleListDomainRoutes(w http.ResponseWriter, r *http.Request) {
	rules, err := s.DomainRouting.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load domain routing rules").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

type domainRouteRequest struct {
	MatchKind         string `json:"match_kind"`
	Domain            string `json:"domain"`
	UpstreamProfileID string `json:"upstream_profile_id"`
}

func (s *Server) handleCreateDomainRoute(w http.ResponseWriter, r *http.Request) {
	var req domainRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	rule, err := s.DomainRouting.Create(r.Context(), req.MatchKind, req.Domain, req.UpstreamProfileID)
	if err != nil {
		status, code := domainRoutingErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "rule": rule, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleDeleteDomainRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid rule id").WriteJSON(w)
		return
	}
	if err := s.DomainRouting.Delete(r.Context(), id); err != nil {
		status, code := domainRoutingErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}
