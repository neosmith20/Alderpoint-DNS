package httpapi

import "net/http"

// handleDashboardSummary backs the Dashboard page's non-analytics cards
// (blocklists, local DNS -- what the Go control plane owns natively) plus
// a cheap analytics-reachability flag so the page can show one coherent
// degraded banner without a wasted round trip; the actual analytics data
// comes from the /api/analytics/* endpoints in handlers_analytics.go via
// the pyanalytics compatibility boundary -- see that package's doc
// comment for its exact, deliberately limited scope.
func (s *Server) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	analyticsAvailable := false
	if s.Analytics != nil {
		analyticsAvailable = s.Analytics.Ping(r.Context()) == nil
	}

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
		"appliance_name":      s.ApplianceName,
		"analytics_available": analyticsAvailable,
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
