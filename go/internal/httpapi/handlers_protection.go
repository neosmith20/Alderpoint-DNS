package httpapi

import "net/http"

// Protection Control: the Dashboard's global filtering on/off switch,
// matching V1.1.1's real POST /protection/toggle (webapp.py:
// protection_toggle) -- bulk-enables or bulk-disables every blocklist
// subscription and every custom rule in one action, then re-applies the
// DNS runtime so the change takes effect immediately, the same
// "Update, Compile, Deploy" pipeline every other filtering mutation
// already goes through on this appliance. V1.1.1 additionally folded in
// systemd service health (BIND/dnsdist/collector state) when deciding
// the displayed label ("Active"/"Degraded"/"Disabled") -- that broader
// service-health signal already exists separately on this appliance via
// GET /api/health, so protectionStatus here reports the one thing V1's
// toggle itself actually controlled: whether filtering sources are
// enabled at all.
func protectionActive(s *Server, r *http.Request) (bool, int, int, error) {
	subs, err := s.Blocklists.List(r.Context())
	if err != nil {
		return false, 0, 0, err
	}
	enabledBlocklists := 0
	for _, sub := range subs {
		if sub.Enabled {
			enabledBlocklists++
		}
	}
	rules, err := s.CustomRules.List(r.Context())
	if err != nil {
		return false, 0, 0, err
	}
	enabledRules := 0
	for _, rule := range rules {
		if rule.Enabled {
			enabledRules++
		}
	}
	return enabledBlocklists > 0 || enabledRules > 0, enabledBlocklists, enabledRules, nil
}

func (s *Server) handleProtectionStatus(w http.ResponseWriter, r *http.Request) {
	active, enabledBlocklists, enabledRules, err := protectionActive(s, r)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load protection status").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"active":             active,
		"enabled_blocklists": enabledBlocklists,
		"enabled_rules":      enabledRules,
	})
}

func (s *Server) handleProtectionToggle(w http.ResponseWriter, r *http.Request) {
	active, _, _, err := protectionActive(s, r)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load protection status").WriteJSON(w)
		return
	}
	enable := !active
	if _, err := s.Blocklists.SetAllEnabled(r.Context(), enable); err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to update blocklists").WriteJSON(w)
		return
	}
	if _, err := s.CustomRules.SetAllEnabled(r.Context(), enable); err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to update custom rules").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"active":      enable,
		"dns_runtime": s.applyDNSRuntimeBestEffort(r),
	})
}
