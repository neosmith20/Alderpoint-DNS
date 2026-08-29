package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"alderpointdns/go-controlplane/internal/customrules"
)

func ruleErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, customrules.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, customrules.ErrValidation):
		return http.StatusBadRequest, "validation_error"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func (s *Server) handleListCustomRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.CustomRules.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load custom rules").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

type customRuleRequest struct {
	RuleType      string  `json:"rule_type"`
	Pattern       string  `json:"pattern"`
	RewriteTarget *string `json:"rewrite_target"`
}

func (s *Server) handleCreateCustomRule(w http.ResponseWriter, r *http.Request) {
	var req customRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	id, err := s.CustomRules.Create(r.Context(), req.RuleType, req.Pattern, req.RewriteTarget)
	if err != nil {
		status, code := ruleErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "id": id, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleUpdateCustomRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid rule id").WriteJSON(w)
		return
	}
	var req customRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.CustomRules.Update(r.Context(), id, req.RuleType, req.Pattern, req.RewriteTarget); err != nil {
		status, code := ruleErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleToggleCustomRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid rule id").WriteJSON(w)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.CustomRules.SetEnabled(r.Context(), id, req.Enabled); err != nil {
		status, code := ruleErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleDeleteCustomRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid rule id").WriteJSON(w)
		return
	}
	if err := s.CustomRules.Delete(r.Context(), id); err != nil {
		status, code := ruleErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

type bulkRuleIDsRequest struct {
	IDs []int64 `json:"ids"`
}

func (s *Server) handleBulkEnableCustomRules(w http.ResponseWriter, r *http.Request) {
	s.bulkSetEnabled(w, r, true)
}
func (s *Server) handleBulkDisableCustomRules(w http.ResponseWriter, r *http.Request) {
	s.bulkSetEnabled(w, r, false)
}

func (s *Server) bulkSetEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	var req bulkRuleIDsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	n, err := s.CustomRules.BulkSetEnabled(r.Context(), req.IDs, enabled)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "bulk update failed").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "count": n, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleBulkDeleteCustomRules(w http.ResponseWriter, r *http.Request) {
	var req bulkRuleIDsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	n, err := s.CustomRules.BulkDelete(r.Context(), req.IDs)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "bulk delete failed").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "count": n, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

type reorderRulesRequest struct {
	OrderedIDs []int64 `json:"ordered_ids"`
}

func (s *Server) handleReorderCustomRules(w http.ResponseWriter, r *http.Request) {
	var req reorderRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.CustomRules.Reorder(r.Context(), req.OrderedIDs); err != nil {
		status, code := ruleErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	rules, err := s.CustomRules.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to reload rules").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "reordered", "rules": rules})
}

// handleTestDomain backs Filters' "Test a Domain": would a real query
// for the given domain be blocked, and by which real rule -- see
// internal/dnsruntime.Orchestrator.EvaluateDomain's own doc comment for
// exactly what's evaluated (global custom rules + blocklists, not yet
// per-network/per-client overrides). Reuses the same Orchestrator every
// other resolver-affecting page already depends on, so "unavailable"
// here means the same thing it does everywhere else on this server: no
// DNS runtime configured at all, not a real query failure.
func (s *Server) handleTestDomain(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		Err(http.StatusBadRequest, "validation_error", "domain is required").WriteJSON(w)
		return
	}
	if s.DNSRuntime == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "DNS runtime not configured on this deployment").WriteJSON(w)
		return
	}
	result, err := s.DNSRuntime.EvaluateDomain(r.Context(), domain)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, result)
}
