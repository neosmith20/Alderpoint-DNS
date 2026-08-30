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
	RulesetID         string `json:"ruleset_id"`
}

func (s *Server) handleCreateDomainRoute(w http.ResponseWriter, r *http.Request) {
	var req domainRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	rule, err := s.DomainRouting.Create(r.Context(), req.MatchKind, req.Domain, req.UpstreamProfileID, req.RulesetID)
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

// --- Domain Routing Rulesets: named groups of the rules above, so a
// policy scope's own domain_routing_ruleset_id can select a different
// set of routes than the global (RulesetID == "") default. ---

func (s *Server) handleListDomainRoutingRulesets(w http.ResponseWriter, r *http.Request) {
	rulesets, err := s.DomainRouting.ListRulesets(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load domain routing rulesets").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"rulesets": rulesets})
}

type domainRoutingRulesetRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handleCreateDomainRoutingRuleset(w http.ResponseWriter, r *http.Request) {
	var req domainRoutingRulesetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	ruleset, err := s.DomainRouting.CreateRuleset(r.Context(), req.ID, req.Name, req.Description)
	if err != nil {
		status, code := domainRoutingErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "ruleset": ruleset})
}

func (s *Server) handleDeleteDomainRoutingRuleset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.DomainRouting.DeleteRuleset(r.Context(), id); err != nil {
		status, code := domainRoutingErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}
