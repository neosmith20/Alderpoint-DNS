package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/dnsruntime"
	"alderpointdns/go-controlplane/internal/policy"
)

func policyErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, policy.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, policy.ErrValidation):
		return http.StatusBadRequest, "validation_error"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func (s *Server) handleGetGlobalPolicy(w http.ResponseWriter, r *http.Request) {
	l, err := s.Policy.Load(r.Context(), "global", "global")
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load global policy").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, l)
}

func (s *Server) handlePutGlobalPolicy(w http.ResponseWriter, r *http.Request) {
	s.putPolicyLayer(w, r, "global", "global")
}

func (s *Server) handlePutNetworkPolicy(w http.ResponseWriter, r *http.Request) {
	s.putPolicyLayer(w, r, "network", r.PathValue("id"))
}

func (s *Server) handlePutGroupPolicy(w http.ResponseWriter, r *http.Request) {
	s.putPolicyLayer(w, r, "group", r.PathValue("id"))
}

func (s *Server) handlePutClientPolicy(w http.ResponseWriter, r *http.Request) {
	s.putPolicyLayer(w, r, "client", r.PathValue("id"))
}

func (s *Server) putPolicyLayer(w http.ResponseWriter, r *http.Request, scope, scopeRef string) {
	var l policy.Layer
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.Policy.Save(r.Context(), scope, scopeRef, l); err != nil {
		status, code := policyErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	// global and network scopes are both real, compiled runtime effects
	// as of 2026-08-28 (internal/dnsruntime.Orchestrator.build computes
	// each network's own effective blocking_response_mode/custom_ip*
	// fields via internal/policy.MergeLayers and hands any that differ
	// from global to internal/dnscompile.NetworkOverride -- see that
	// type's own doc comment for exactly which fields, and why the
	// block/allow domain LIST itself stays global-only). group/client
	// scope saves are still honestly reported as not compiled -- no
	// per-group/per-client compiled effect exists for the general
	// policy Layer fields (blocking_response_mode etc.) at those two
	// scopes yet; Strong ClientID's own explicit domain block/allow
	// overrides are a separate, already-compiled mechanism (see
	// internal/clients, internal/dnscompile's ClientOverride), not this
	// Layer-based policy at all. This used to unconditionally claim
	// "promoted": true regardless of scope, a real fake-success bug
	// matching the exact class the old Upstreams/Custom Rules
	// "runtimeStub()" already got fixed for; see PARITY_MATRIX.md's
	// "httpapi: consistent DNS-runtime auto-apply UX" entry.
	if scope == "global" || scope == "network" {
		WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"status": "updated",
		"dns_runtime": &dnsruntime.Result{
			Attempted: false,
			Detail:    "group/client-scoped policy is not compiled into the DNS runtime yet (Strong ClientID's own explicit domain overrides are a separate, already-compiled mechanism -- see the Clients page) -- only global and network-scoped policy are (see internal/dnscompile's doc comment)",
		},
	})
}

// handlePolicyExplain mirrors GET /api/policy/explain -- a direct HTTP
// port of app/v2/policy_service.py's explain_policy_for_client (read
// directly, not guessed). See internal/policy/effective.go for the pure
// merge algorithm this wraps around real storage.
func (s *Server) handlePolicyExplain(w http.ResponseWriter, r *http.Request) {
	clientIDStr := r.URL.Query().Get("client_id")
	clientID, err := strconv.ParseInt(clientIDStr, 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "client_id is required and must be an integer").WriteJSON(w)
		return
	}
	clientIP := r.URL.Query().Get("client_ip")

	networks, err := s.Policy.ListNetworks(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load networks").WriteJSON(w)
		return
	}
	refs, err := s.Clients.GroupsForClient(r.Context(), clientID)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load client groups").WriteJSON(w)
		return
	}
	groups := make([]policy.GroupMembership, len(refs))
	for i, g := range refs {
		groups[i] = policy.GroupMembership{GroupID: g.GroupID, Priority: g.Priority}
	}

	explanation, err := policy.MergeLayersForClient(r.Context(), s.Policy, networks, clientIDStr, clientIP, groups)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}

	fields := make(map[string]any, len(explanation.Policy.Explain))
	for _, e := range explanation.Policy.Explain {
		fields[e.Field] = map[string]any{"value": e.Value, "source": e.Source}
	}
	var networkMatch any
	if explanation.NetworkMatch != "" {
		networkMatch = explanation.NetworkMatch
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"client_id":           clientID,
		"network_match":       networkMatch,
		"group_contributions": explanation.GroupContributions,
		"fields":              fields,
	})
}

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	networks, err := s.Policy.ListNetworks(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load networks").WriteJSON(w)
		return
	}
	// Matches GET /api/groups and /api/clients, which each embed their
	// own policy layer directly rather than requiring a second round
	// trip per network -- this endpoint used to omit it, an inconsistency
	// noted while building out the Clients & Access page.
	out := make([]map[string]any, 0, len(networks))
	for _, n := range networks {
		layer, err := s.Policy.Load(r.Context(), "network", n.NetworkID)
		if err != nil {
			Err(http.StatusInternalServerError, "internal_error", "failed to load network policy").WriteJSON(w)
			return
		}
		out = append(out, map[string]any{"network_id": n.NetworkID, "cidr": n.CIDR, "policy": layer})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"networks": out})
}

type createNetworkRequest struct {
	NetworkID string `json:"network_id"`
	CIDR      string `json:"cidr"`
}

func networkIDFromCIDR(cidr string) string {
	slug := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, strings.ToLower(cidr))
	sum := sha256.Sum256([]byte(cidr + strconv.FormatInt(time.Now().UnixNano(), 10)))
	return slug + "-" + hex.EncodeToString(sum[:4])
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var req createNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	id := strings.TrimSpace(req.NetworkID)
	if id == "" {
		id = networkIDFromCIDR(req.CIDR)
	}
	if err := s.Policy.CreateNetwork(r.Context(), id, req.CIDR); err != nil {
		status, code := policyErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "network_id": id})
}
