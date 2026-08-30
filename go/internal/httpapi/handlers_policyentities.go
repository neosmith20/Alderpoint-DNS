// HTTP CRUD for the four real owner-managed entities blocker 1's
// filtering_profile_id/parental_policy_id/security_policy_id/
// service_blocking_ruleset_id fields reference -- see
// internal/policyentities' own doc comment. Every write here re-
// applies the DNS runtime best-effort (s.applyDNSRuntimeBestEffort),
// matching the same "clear DNS-runtime result after every policy
// change" convention every other mutating policy endpoint in this
// package already follows -- a Filtering Profile's own category
// membership changing, or a Delete, can change what's actually
// enforced for every scope that references it.
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"alderpointdns/go-controlplane/internal/policyentities"
)

func policyEntityErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, policyentities.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, policyentities.ErrDuplicate):
		return http.StatusConflict, "conflict"
	case errors.Is(err, policyentities.ErrInUse):
		return http.StatusConflict, "in_use"
	case errors.Is(err, policyentities.ErrValidation):
		return http.StatusBadRequest, "validation_error"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

type categoryEntityRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
}

// --- Filtering Profiles ---

func (s *Server) handleListFilteringProfiles(w http.ResponseWriter, r *http.Request) {
	list, err := s.PolicyEntities.ListFilteringProfiles(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load filtering profiles").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"profiles": list})
}

func (s *Server) handleCreateFilteringProfile(w http.ResponseWriter, r *http.Request) {
	var req categoryEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	p, err := s.PolicyEntities.CreateFilteringProfile(r.Context(), req.ID, req.Name, req.Description, req.Categories)
	if err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "profile": p, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleUpdateFilteringProfile(w http.ResponseWriter, r *http.Request) {
	var req categoryEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	id := r.PathValue("id")
	if err := s.PolicyEntities.UpdateFilteringProfile(r.Context(), id, req.Name, req.Description, req.Categories); err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleDeleteFilteringProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.PolicyEntities.DeleteFilteringProfile(r.Context(), r.PathValue("id")); err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

// --- Security Policies (identical shape to Filtering Profiles) ---

func (s *Server) handleListSecurityPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.PolicyEntities.ListSecurityPolicies(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load security policies").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"policies": list})
}

func (s *Server) handleCreateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	var req categoryEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	p, err := s.PolicyEntities.CreateSecurityPolicy(r.Context(), req.ID, req.Name, req.Description, req.Categories)
	if err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "policy": p, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleUpdateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	var req categoryEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.PolicyEntities.UpdateSecurityPolicy(r.Context(), r.PathValue("id"), req.Name, req.Description, req.Categories); err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleDeleteSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	if err := s.PolicyEntities.DeleteSecurityPolicy(r.Context(), r.PathValue("id")); err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

// --- Parental Policies (own safesearch_mode field) ---

type parentalPolicyRequest struct {
	categoryEntityRequest
	SafesearchMode string `json:"safesearch_mode"`
}

func (s *Server) handleListParentalPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.PolicyEntities.ListParentalPolicies(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load parental policies").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"policies": list})
}

func (s *Server) handleCreateParentalPolicy(w http.ResponseWriter, r *http.Request) {
	var req parentalPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	p, err := s.PolicyEntities.CreateParentalPolicy(r.Context(), req.ID, req.Name, req.Description, req.SafesearchMode, req.Categories)
	if err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "policy": p, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleUpdateParentalPolicy(w http.ResponseWriter, r *http.Request) {
	var req parentalPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.PolicyEntities.UpdateParentalPolicy(r.Context(), r.PathValue("id"), req.Name, req.Description, req.SafesearchMode, req.Categories); err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleDeleteParentalPolicy(w http.ResponseWriter, r *http.Request) {
	if err := s.PolicyEntities.DeleteParentalPolicy(r.Context(), r.PathValue("id")); err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

// --- Service Blocking Rulesets (domain-based, not category-based) ---

type serviceBlockingRulesetRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
}

func (s *Server) handleListServiceBlockingRulesets(w http.ResponseWriter, r *http.Request) {
	list, err := s.PolicyEntities.ListServiceBlockingRulesets(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load service blocking rulesets").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"rulesets": list})
}

func (s *Server) handleCreateServiceBlockingRuleset(w http.ResponseWriter, r *http.Request) {
	var req serviceBlockingRulesetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	ruleset, err := s.PolicyEntities.CreateServiceBlockingRuleset(r.Context(), req.ID, req.Name, req.Description, req.Domains)
	if err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "ruleset": ruleset, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleUpdateServiceBlockingRuleset(w http.ResponseWriter, r *http.Request) {
	var req serviceBlockingRulesetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.PolicyEntities.UpdateServiceBlockingRuleset(r.Context(), r.PathValue("id"), req.Name, req.Description, req.Domains); err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleDeleteServiceBlockingRuleset(w http.ResponseWriter, r *http.Request) {
	if err := s.PolicyEntities.DeleteServiceBlockingRuleset(r.Context(), r.PathValue("id")); err != nil {
		status, code := policyEntityErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}
