package httpapi

import "net/http"

// handleDashboardSummary backs the Dashboard page's *real, currently-
// available* subset: whatever the Go control plane genuinely owns today
// (blocklists, local DNS). It deliberately does NOT include analytics,
// live DNS activity, upstreams, or observed clients -- those live in
// Python's separate analytics/policy stores and are not yet reachable
// through any Go compatibility boundary. Returning fabricated numbers for
// them would violate the "no fake data" rule as surely as a hardcoded
// placeholder would, so they're simply absent rather than faked -- see
// PARITY_MATRIX.md's Dashboard row for the tracked remaining scope and
// why it isn't done here.
func (s *Server) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	subs, err := s.Blocklists.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load blocklist summary").WriteJSON(w)
		return
	}
	enabledBlocklists, attentionBlocklists, totalRules := 0, 0, 0
	for _, sub := range subs {
		if sub.Enabled {
			enabledBlocklists++
		}
		if sub.AttentionRequired {
			attentionBlocklists++
		}
		if sub.RuleCount != nil {
			totalRules += *sub.RuleCount
		}
	}

	records, err := s.LocalDNS.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load local DNS summary").WriteJSON(w)
		return
	}
	enabledRecords := 0
	for _, rec := range records {
		if rec.Enabled {
			enabledRecords++
		}
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"appliance_name": s.ApplianceName,
		"blocklists": map[string]any{
			"total":              len(subs),
			"enabled":            enabledBlocklists,
			"attention_required": attentionBlocklists,
			"total_rules":        totalRules,
		},
		"local_dns": map[string]any{
			"total":   len(records),
			"enabled": enabledRecords,
		},
	})
}
