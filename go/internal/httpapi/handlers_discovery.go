package httpapi

import (
	"net"
	"net/http"
	"time"
)

// handleListObservedClients is a real, narrower substitute for V1/V2
// Python's dedicated discovery worker (see internal/clients's package
// doc comment for the disclosed scope difference: no first-seen/
// last-seen history, no hostname resolution, no vendor/OS
// fingerprinting -- just real, live "who has actually queried recently"
// data). It reads the "client" dimension straight from
// internal/pyanalytics's already-safe analytics snapshot boundary
// (never Python's control.db), truthfully reports degraded/unavailable
// exactly like every other analytics-backed endpoint, and cross-
// references each observed address against already-managed IP/CIDR
// identifiers so the UI can tell a genuinely new address apart from one
// that already belongs to a managed client -- the "Manage Client" flow
// the owner asked for hangs off that distinction.
func (s *Server) handleListObservedClients(w http.ResponseWriter, r *http.Request) {
	minutes := floatQuery(r, "minutes", 60, 1, 31*24*60)
	limit := intQuery(r, "limit", 50, 1, 500)
	now := float64(time.Now().Unix())
	start := now - minutes*60
	granularity := "minute"
	if minutes > 120 {
		granularity = "hour"
	}

	if s.Analytics == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"observed": []any{}, "degraded": true, "degraded_reason": analyticsUnavailable})
		return
	}
	rows, err := s.Analytics.TopDimension(r.Context(), "client", start, now, granularity, limit)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"observed": []any{}, "degraded": true, "degraded_reason": err.Error()})
		return
	}

	managed := map[string]int64{} // observed address -> owning client id, for every ipv4/ipv6 identifier already stored
	if s.Clients != nil {
		list, err := s.Clients.ListClients(r.Context())
		if err != nil {
			Err(http.StatusInternalServerError, "internal_error", "failed to load clients").WriteJSON(w)
			return
		}
		for _, c := range list {
			for _, id := range c.Identifiers {
				if id.Kind == "ipv4" || id.Kind == "ipv6" {
					managed[id.Value] = c.ID
				}
			}
		}
	}

	out := make([]map[string]any, 0, len(rows))
	for _, d := range rows {
		// Loopback/unspecified never identifies a real host -- truthfully
		// exclude rather than present it as one (this is the exact "no
		// loopback/prefix presented as a host" requirement).
		if ip := net.ParseIP(d.Value); ip != nil {
			if ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
		} else {
			// Not a parseable IP at all (e.g. a Strong ClientID hex value
			// already resolved to its own identity by the query layer) --
			// still real data, just not an address-based observation this
			// grid's "new host" flow applies to.
			continue
		}
		entry := map[string]any{"address": d.Value, "query_count": d.Count}
		if clientID, ok := managed[d.Value]; ok {
			entry["managed"] = true
			entry["client_id"] = clientID
		} else {
			entry["managed"] = false
		}
		out = append(out, entry)
	}

	degraded, reason := writerDegraded(s.Analytics.Health(r.Context()))
	WriteJSON(w, http.StatusOK, map[string]any{
		"observed": out, "degraded": degraded, "degraded_reason": reason,
		"window": map[string]any{"start": start, "end": now, "minutes": minutes},
	})
}
