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
	// Every scope is now a real, compiled runtime effect
	// (internal/dnsruntime's computeScopeOverrides -- see that file's
	// own doc comment, 2026-08-30). "group" has no CIDR/ClientKey of
	// its own to match on directly -- a group assignment only takes
	// effect through whichever real clients are members of it (the
	// same precedence internal/policy.MergeLayersForClient/OrderGroups
	// already resolve), so a bare group save with no members yet
	// re-applies cleanly but has nothing new to compile until a client
	// actually belongs to it. This used to unconditionally claim
	// "promoted": true regardless of scope, a real fake-success bug
	// matching the exact class the old Upstreams/Custom Rules
	// "runtimeStub()" already got fixed for; see PARITY_MATRIX.md's
	// "httpapi: consistent DNS-runtime auto-apply UX" entry.
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
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
