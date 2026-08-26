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
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "id": id})
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
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated"})
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
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated"})
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
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
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
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "count": n})
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
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "count": n})
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
