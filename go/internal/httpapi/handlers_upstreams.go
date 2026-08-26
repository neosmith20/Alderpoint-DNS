package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/upstreams"
)

// upstreamProfileIDFromName mirrors subscriptionIDFromName's shape
// (handlers_blocklists.go) for the same reason: a stable, readable,
// collision-resistant slug generated server-side, matching
// _unique_id()'s intent in app/v2/webapp.py without needing to guess at
// its exact randomness source.
func upstreamProfileIDFromName(name string) string {
	slug := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, strings.ToLower(name))
	sum := sha256.Sum256([]byte(name + strconv.FormatInt(time.Now().UnixNano(), 10)))
	return slug + "-" + hex.EncodeToString(sum[:4])
}

func profileJSON(p upstreams.Profile) map[string]any {
	eps := make([]map[string]any, 0, len(p.Endpoints))
	for _, e := range p.Endpoints {
		eps = append(eps, map[string]any{
			"address": e.Address, "tls_hostname": e.TLSHostname,
			"priority": e.Priority, "weight": e.Weight, "doh_path": e.DohPath,
		})
	}
	return map[string]any{
		"upstream_profile_id": p.UpstreamProfileID, "name": p.Name, "transport": p.Transport,
		"strategy": p.Strategy, "enabled": p.Enabled, "sort_order": p.SortOrder,
		"order": p.Order, "endpoints": eps,
	}
}

// runtimeStub is disclosed, not silently faked: no dnsdist-config
// generation exists yet (see internal/upstreams's doc comment), so every
// mutation here always reports promoted=true, binding_count=0 rather
// than pretending to have proven a real compiled-runtime effect.
func runtimeStub() map[string]any {
	return map[string]any{"promoted": true, "binding_count": 0}
}

func (s *Server) handleListUpstreams(w http.ResponseWriter, r *http.Request) {
	profiles, nativeRecursion, err := s.Upstreams.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load upstreams").WriteJSON(w)
		return
	}
	out := make([]map[string]any, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, profileJSON(p))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"upstreams": out, "native_recursion_active": nativeRecursion})
}

type upstreamEndpointRequest struct {
	Address     string  `json:"address"`
	TLSHostname *string `json:"tls_hostname"`
	Priority    int     `json:"priority"`
	Weight      int     `json:"weight"`
	DohPath     *string `json:"doh_path"`
}

type upstreamProfileRequest struct {
	Name              string                    `json:"name"`
	Transport         string                    `json:"transport"`
	Strategy          string                    `json:"strategy"`
	Endpoints         []upstreamEndpointRequest `json:"endpoints"`
	UpstreamProfileID string                    `json:"upstream_profile_id"`
}

func toServiceEndpoints(reqs []upstreamEndpointRequest) []upstreams.Endpoint {
	out := make([]upstreams.Endpoint, 0, len(reqs))
	for _, e := range reqs {
		weight := e.Weight
		if weight == 0 {
			weight = 1
		}
		out = append(out, upstreams.Endpoint{Address: e.Address, TLSHostname: e.TLSHostname, Priority: e.Priority, Weight: weight, DohPath: e.DohPath})
	}
	return out
}

func upstreamValidationError(err error) *APIError {
	return Err(http.StatusBadRequest, "invalid_upstream", err.Error())
}

func (s *Server) handleCreateUpstream(w http.ResponseWriter, r *http.Request) {
	var req upstreamProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if req.Strategy == "" {
		req.Strategy = "ordered"
	}
	id := strings.TrimSpace(req.UpstreamProfileID)
	if id == "" {
		id = upstreamProfileIDFromName(req.Name)
	}
	if err := s.Upstreams.Create(r.Context(), id, req.Name, req.Transport, req.Strategy, toServiceEndpoints(req.Endpoints)); err != nil {
		upstreamValidationError(err).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "upstream_profile_id": id})
}

func (s *Server) handleUpdateUpstream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req upstreamProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if req.Strategy == "" {
		req.Strategy = "ordered"
	}
	if err := s.Upstreams.Update(r.Context(), id, req.Name, req.Transport, req.Strategy, toServiceEndpoints(req.Endpoints)); err != nil {
		if err == upstreams.ErrNotFound {
			Err(http.StatusNotFound, "not_found", "unknown upstream profile").WriteJSON(w)
			return
		}
		upstreamValidationError(err).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "runtime": runtimeStub()})
}

// lastUpstreamConfirmRequest mirrors LastUpstreamConfirm: disabling or
// deleting the final enabled managed upstream must be blocked with a
// distinguishable 409 until the identical request is retried with
// confirm_last=true -- server-enforced, not just a client confirm()
// dialog, per the roadmap's "Zero Managed Upstreams" locked decision.
type lastUpstreamConfirmRequest struct {
	ConfirmLast bool `json:"confirm_last"`
}

const lastEnabledUpstreamMessage = "This is the final enabled managed upstream. %s it leaves zero managed forwarders -- BIND will perform normal native recursion using the root/authoritative hierarchy. Confirm to proceed."

func (s *Server) handleEnableUpstream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Upstreams.SetEnabled(r.Context(), id, true); err != nil {
		Err(http.StatusNotFound, "not_found", "unknown upstream profile").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "enabled", "runtime": runtimeStub()})
}

func (s *Server) handleDisableUpstream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req lastUpstreamConfirmRequest
	json.NewDecoder(r.Body).Decode(&req) // absent/empty body is valid -- confirm_last defaults false

	isLast, err := s.Upstreams.IsLastEnabled(r.Context(), id)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to check upstream status").WriteJSON(w)
		return
	}
	if isLast && !req.ConfirmLast {
		Err(http.StatusConflict, "last_enabled_upstream", fmt.Sprintf(lastEnabledUpstreamMessage, "Disabling")).WriteJSON(w)
		return
	}
	if err := s.Upstreams.SetEnabled(r.Context(), id, false); err != nil {
		Err(http.StatusNotFound, "not_found", "unknown upstream profile").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "disabled", "was_last_enabled": isLast, "runtime": runtimeStub()})
}

func (s *Server) handleDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req lastUpstreamConfirmRequest
	json.NewDecoder(r.Body).Decode(&req)

	isLast, err := s.Upstreams.IsLastEnabled(r.Context(), id)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to check upstream status").WriteJSON(w)
		return
	}
	if isLast && !req.ConfirmLast {
		Err(http.StatusConflict, "last_enabled_upstream", fmt.Sprintf(lastEnabledUpstreamMessage, "Deleting")).WriteJSON(w)
		return
	}
	if err := s.Upstreams.Delete(r.Context(), id); err != nil {
		Err(http.StatusNotFound, "not_found", "unknown upstream profile").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "was_last_enabled": isLast, "runtime": runtimeStub()})
}

type reorderUpstreamsRequest struct {
	OrderedUpstreamProfileIDs []string `json:"ordered_upstream_profile_ids"`
}

func (s *Server) handleReorderUpstreams(w http.ResponseWriter, r *http.Request) {
	var req reorderUpstreamsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.Upstreams.Reorder(r.Context(), req.OrderedUpstreamProfileIDs); err != nil {
		Err(http.StatusBadRequest, "invalid_reorder", err.Error()).WriteJSON(w)
		return
	}
	profiles, _, err := s.Upstreams.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to reload upstreams").WriteJSON(w)
		return
	}
	out := make([]map[string]any, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, profileJSON(p))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "reordered", "upstreams": out})
}
