package httpapi

import (
	"context"
	"net"
	"net/http"
	"time"

	"alderpointdns/go-controlplane/internal/clientalias"
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

	managed, err := s.managedAddressLookup(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load clients").WriteJSON(w)
		return
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
		if m, ok := managed[d.Value]; ok {
			entry["managed"] = true
			entry["client_id"] = m.ID
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

// managedAddress is what managedAddressLookup resolves one exact ipv4/
// ipv6 identifier value to.
type managedAddress struct {
	ID   int64
	Name string
}

// managedAddressLookup cross-references a real client address against
// every managed client's own ipv4/ipv6 identifiers (exact-value match
// only -- CIDR identifiers are deliberately not expanded here, same
// disclosed scope as Observed Clients has always had). Shared by
// Observed Clients (handleListObservedClients) and the Clients page's
// Client analytics table (handleAnalyticsTopClients), so both features
// resolve "is this address already a named client" the exact same way
// rather than drifting into two subtly different answers.
func (s *Server) managedAddressLookup(ctx context.Context) (map[string]managedAddress, error) {
	out := map[string]managedAddress{}
	if s.Clients == nil {
		return out, nil
	}
	list, err := s.Clients.ListClients(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range list {
		for _, id := range c.Identifiers {
			if id.Kind == "ipv4" || id.Kind == "ipv6" {
				out[id.Value] = managedAddress{ID: c.ID, Name: c.Name}
			}
		}
	}
	return out, nil
}

// aliasResolver returns a real clientalias.Resolver built from this
// deployment's current Client Aliases, or an empty one (ResolveLabel
// always "") when aliases aren't configured or fail to load -- label
// resolution degrading to "no alias match" must never become a hard
// error for an unrelated page like Client analytics.
func (s *Server) aliasResolver(ctx context.Context) *clientalias.Resolver {
	if s.ClientAliases == nil {
		return clientalias.NewResolver(nil)
	}
	list, err := s.ClientAliases.List(ctx)
	if err != nil {
		return clientalias.NewResolver(nil)
	}
	return clientalias.NewResolver(list)
}
