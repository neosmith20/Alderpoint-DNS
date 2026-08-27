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
	// Only the global scope is ever consulted by the compiler today
	// (internal/dnsruntime.Orchestrator.build reads Policy.Load(ctx,
	// "global", "global") only -- no per-network/group/client effective-
	// policy resolution engine exists yet). A global save therefore
	// really can change the live runtime and gets the same real
	// dns_runtime field every other auto-applying mutation on this
	// server returns (see applyDNSRuntimeBestEffort). A network/group/
	// client save is honestly reported as not compiled -- this used to
	// unconditionally claim "promoted": true regardless of scope, a
	// real fake-success bug matching the exact class the old
	// Upstreams/Custom Rules "runtimeStub()" already got fixed for; see
	// PARITY_MATRIX.md's "httpapi: consistent DNS-runtime auto-apply UX"
	// entry.
	if scope == "global" {
		WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"status": "updated",
		"dns_runtime": &dnsruntime.Result{
			Attempted: false,
			Detail:    "network/group/client-scoped policy is not compiled into the DNS runtime yet -- only the global policy layer is (see internal/dnscompile's doc comment)",
		},
	})
}

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	networks, err := s.Policy.ListNetworks(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load networks").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"networks": networks})
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
