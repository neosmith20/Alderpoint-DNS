package httpapi

import (
	"encoding/json"
	"net/http"

	"alderpointdns/go-controlplane/internal/dnsruntime"
	"alderpointdns/go-controlplane/internal/hostagent"
)

// dnsRuntimeUnavailable matches every other optional boundary's
// nil-safe contract (Analytics, RawQueryLog, TLSCert, HostAgent).
const dnsRuntimeUnavailable = "the DNS runtime compiler is not configured for this deployment"

func (s *Server) handleDNSRuntimeStatus(w http.ResponseWriter, r *http.Request) {
	if s.DNSRuntime == nil || s.HostAgent == nil {
		WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable", "detail": dnsRuntimeUnavailable})
		return
	}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpDNSRuntimeStatus, nil)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

// handleDNSRuntimeApply is the manual "Apply Runtime Changes" action:
// recompiles current Go control-plane state and promotes it through
// the host-agent, same pipeline every automatic post-mutation trigger
// uses (see applyDNSRuntimeBestEffort). Never fails the HTTP request
// itself for a compile/promote/rollback outcome -- the result body
// reports exactly what happened (attempted/promoted/rolled_back/stage),
// matching internal/dnsruntime.Result's own contract.
func (s *Server) handleDNSRuntimeApply(w http.ResponseWriter, r *http.Request) {
	if s.DNSRuntime == nil {
		WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable", "detail": dnsRuntimeUnavailable})
		return
	}
	result := s.DNSRuntime.Apply(r.Context())
	s.notifyOnRollback(r, &result)
	WriteJSON(w, http.StatusOK, result)
}

// notifyOnRollback dispatches a real "deploy_failure" event the moment
// a promotion actually rolls back -- the one DNS Runtime outcome an
// owner unambiguously needs to know about without watching the UI.
// Never fails the caller's own request for a notification-delivery
// problem; Dispatch's own errors (misconfigured provider, secrets
// unavailable) are swallowed here on purpose, matching every other
// best-effort side effect in this file.
func (s *Server) notifyOnRollback(r *http.Request, res *dnsruntime.Result) {
	if res == nil || !res.RolledBack || s.Notifications == nil {
		return
	}
	summary := "DNS runtime promotion rolled back at stage \"" + res.Stage + "\": " + res.Detail
	s.Notifications.Dispatch(r.Context(), "deploy_failure", "critical", "dns_runtime", summary, false)
}

// applyDNSRuntimeBestEffort is called after a mutation to one of the
// areas the DNS runtime compiles (Local DNS today; see PARITY_MATRIX.md
// for which other areas still require the manual Apply action). Never
// returns an error the caller must handle specially -- a nil
// s.DNSRuntime or a real compile/promote failure both just mean "the
// saved change hasn't reached the live runtime yet," reported inline
// in the same JSON response the way internal/localdns's own
// stageAndPromote convention already reports its own runtime-generation
// failures.
func (s *Server) applyDNSRuntimeBestEffort(r *http.Request) *dnsruntime.Result {
	if s.DNSRuntime == nil {
		return nil
	}
	res := s.DNSRuntime.Apply(r.Context())
	s.notifyOnRollback(r, &res)
	return &res
}
