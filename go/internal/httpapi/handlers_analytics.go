package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/pyanalytics"
	"alderpointdns/go-controlplane/internal/rawquerylog"
)

// analyticsUnavailable is the shared "no reader configured at all" reason
// -- distinct from a reader that exists but errored on this particular
// query (handled per-call below), so an operator/log can tell "never
// wired up" from "wired up but broken right now" apart.
const analyticsUnavailable = "analytics reader not configured (no -analytics-db path given at startup)"

func bucketsJSON(buckets []pyanalytics.Bucket) []map[string]any {
	out := make([]map[string]any, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, map[string]any{
			"bucket_start":     b.BucketStart,
			"bucket_start_iso": time.Unix(b.BucketStart, 0).UTC().Format(time.RFC3339),
			"total_queries":    b.TotalQueries,
			"blocked_queries":  b.Blocked,
			"cache_hits":       b.CacheHits,
			"cache_misses":     b.CacheMisses,
		})
	}
	return out
}

func floatQuery(r *http.Request, key string, def, min, max float64) float64 {
	v := def
	if s := r.URL.Query().Get(key); s != "" {
		if parsed, err := strconv.ParseFloat(s, 64); err == nil {
			v = parsed
		}
	}
	if v < min {
		v = min
	}
	if v > max {
		v = max
	}
	return v
}

func intQuery(r *http.Request, key string, def, min, max int) int {
	v := def
	if s := r.URL.Query().Get(key); s != "" {
		if parsed, err := strconv.Atoi(s); err == nil {
			v = parsed
		}
	}
	if v < min {
		v = min
	}
	if v > max {
		v = max
	}
	return v
}

// handleAnalyticsTimeseries mirrors GET /api/analytics/timeseries's
// response shape (window/degraded/buckets), reading from the
// pyanalytics compatibility boundary instead of Python's own service --
// see that package's doc comment for exactly what this boundary is and
// isn't.
func (s *Server) handleAnalyticsTimeseries(w http.ResponseWriter, r *http.Request) {
	granularity := r.URL.Query().Get("granularity")
	if granularity == "" {
		granularity = "hour"
	}
	if !pyanalytics.ValidGranularity(granularity) {
		Err(http.StatusBadRequest, "validation_error", "granularity must be one of minute, hour, day").WriteJSON(w)
		return
	}
	minutes := floatQuery(r, "minutes", 1440, 1, 31*24*60)
	now := float64(time.Now().Unix())
	start := now - minutes*60

	if s.Analytics == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"buckets": []any{}, "granularity": granularity, "degraded": true, "degraded_reason": analyticsUnavailable})
		return
	}
	rows, err := s.Analytics.TimeSeries(r.Context(), start, now, granularity)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"buckets": []any{}, "granularity": granularity, "degraded": true, "degraded_reason": err.Error()})
		return
	}
	filled := pyanalytics.FillGaps(rows, start, now, granularity)
	degraded, reason := writerDegraded(s.Analytics.Health(r.Context()))
	WriteJSON(w, http.StatusOK, map[string]any{
		"granularity":     granularity,
		"degraded":        degraded,
		"degraded_reason": reason,
		"window":          map[string]any{"start": start, "end": now, "minutes": minutes},
		"buckets":         bucketsJSON(filled),
	})
}

// writerDegraded translates an AnalyticsHealth into the (degraded,
// degraded_reason) shape every analytics endpoint's response already
// carries -- the fix for the exact failure class the governing task
// names: a SQL read against aggregates.db can succeed (real committed
// rows, no Go error) while the writer that's supposed to be adding new
// rows is actually dead, which must surface as "Analytics Degraded",
// not as a query that silently looks like real zero traffic. Only a
// non-"ok" health ever sets degraded=true here -- an "ok" health never
// overrides a caller's own success response.
func writerDegraded(h pyanalytics.AnalyticsHealth) (bool, string) {
	if h.Status == "ok" {
		return false, ""
	}
	return true, h.Reason
}

// handleAnalyticsLiveActivity mirrors GET /api/analytics/live-activity.
func (s *Server) handleAnalyticsLiveActivity(w http.ResponseWriter, r *http.Request) {
	seconds := floatQuery(r, "seconds", 180, 30, 900)
	now := float64(time.Now().Unix())
	start := now - seconds

	if s.Analytics == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"buckets": []any{}, "degraded": true, "degraded_reason": analyticsUnavailable})
		return
	}
	rows, err := s.Analytics.Live(r.Context(), start, now)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"buckets": []any{}, "degraded": true, "degraded_reason": err.Error()})
		return
	}
	filled := pyanalytics.FillLiveGaps(rows, start, now)

	var recentTotal, recentBlocked int
	if len(filled) > 0 {
		last := filled[len(filled)-1]
		recentTotal, recentBlocked = last.TotalQueries, last.Blocked
	}
	rollingTotal, rollingBlocked, n := 0, 0, 0
	for i := len(filled) - 1; i >= 0 && n < 10; i-- {
		rollingTotal += filled[i].TotalQueries
		rollingBlocked += filled[i].Blocked
		n++
	}
	blockedPercent := 0.0
	if recentTotal > 0 {
		blockedPercent = round1(float64(recentBlocked) / float64(recentTotal) * 100)
	}
	rollingQPS := 0.0
	if n > 0 {
		rollingQPS = float64(rollingTotal) / float64(n)
	}
	rollingBlockedPercent := 0.0
	if rollingTotal > 0 {
		rollingBlockedPercent = round1(float64(rollingBlocked) / float64(rollingTotal) * 100)
	}
	degraded, reason := writerDegraded(s.Analytics.Health(r.Context()))

	WriteJSON(w, http.StatusOK, map[string]any{
		"degraded":                    degraded,
		"degraded_reason":             reason,
		"transport":                   "bounded_polling",
		"poll_seconds":                1,
		"bucket_seconds":              1,
		"window":                      map[string]any{"start": start, "end": now, "seconds": seconds},
		"current_bucket_count":        recentTotal,
		"current_qps":                 float64(recentTotal),
		"current_blocked_percent":     blockedPercent,
		"rolling_10s_qps":             rollingQPS,
		"rolling_10s_blocked_percent": rollingBlockedPercent,
		"buckets":                     bucketsJSON(filled),
	})
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

// handleAnalyticsTopDomains mirrors GET /api/analytics/top-domains for
// the aggregates-backed window (Python switches to raw Parquet beyond
// 120 minutes; this reader has no Parquet access, so it always uses
// aggregates -- hour-granularity buckets beyond 120 minutes, same
// pattern, coarser resolution for a long window, disclosed via
// "aggregation_note" rather than silently matching Python's exact cutover
// behavior).
func (s *Server) handleAnalyticsTopDomains(w http.ResponseWriter, r *http.Request) {
	minutes := floatQuery(r, "minutes", 60, 1, 31*24*60)
	limit := intQuery(r, "limit", 20, 1, 500)
	now := float64(time.Now().Unix())
	start := now - minutes*60
	granularity := "minute"
	if minutes > 120 {
		granularity = "hour"
	}

	if s.Analytics == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"rows": []any{}, "columns": []string{"domain", "count"}, "degraded": true, "degraded_reason": analyticsUnavailable})
		return
	}
	rows, err := s.Analytics.TopDimension(r.Context(), "domain", start, now, granularity, limit)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"rows": []any{}, "columns": []string{"domain", "count"}, "degraded": true, "degraded_reason": err.Error()})
		return
	}
	out := make([][2]any, 0, len(rows))
	for _, d := range rows {
		out = append(out, [2]any{d.Value, d.Count})
	}
	degraded, reason := writerDegraded(s.Analytics.Health(r.Context()))
	resp := map[string]any{
		"rows": out, "columns": []string{"domain", "count"}, "degraded": degraded, "degraded_reason": reason,
		"window": map[string]any{"start": start, "end": now, "minutes": minutes},
	}
	if granularity == "hour" {
		resp["aggregation_note"] = "windows over 120 minutes are summed from hour buckets, not per-query detail"
	}
	WriteJSON(w, http.StatusOK, resp)
}

// handleAnalyticsTopUpstreams backs Dashboard's real "Top Upstream
// Resolvers" panel -- V1.1.1 parity (dashboard.html's own
// analytics.top_upstreams panel, backed by real dnsdist backend
// counters, read directly from the shipped package) via
// internal/dnsanalytics's own dnsdist-webserver-API-backed telemetry,
// not the "configured profiles only" Upstreams mini-panel this
// deployment already had. Same degraded-not-hidden contract as every
// other analytics handler here: a nil/failing reader reports
// degraded=true with a real reason, never a silently empty "everything
// is fine" response.
func (s *Server) handleAnalyticsTopUpstreams(w http.ResponseWriter, r *http.Request) {
	minutes := floatQuery(r, "minutes", 60, 1, 31*24*60)
	limit := intQuery(r, "limit", 10, 1, 50)
	since := time.Now().Add(-time.Duration(minutes * float64(time.Minute)))

	if s.Analytics == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"resolvers": []any{}, "degraded": true, "degraded_reason": analyticsUnavailable})
		return
	}
	rows, err := s.Analytics.TopUpstreams(r.Context(), since, limit)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"resolvers": []any{}, "degraded": true, "degraded_reason": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"resolver_key":         row.ResolverKey,
			"protocol":             row.Protocol,
			"address":              row.Address,
			"health_state":         row.HealthState,
			"queries_attempted":    row.QueriesAttempted,
			"successful_responses": row.SuccessfulResp,
			"failures":             row.Failures,
			"timeouts":             row.Timeouts,
			"avg_latency_ms":       round1(row.AvgLatencyMS),
		})
	}
	degraded, reason := writerDegraded(s.Analytics.Health(r.Context()))
	WriteJSON(w, http.StatusOK, map[string]any{
		"resolvers": out, "degraded": degraded, "degraded_reason": reason,
		"window": map[string]any{"minutes": minutes},
	})
}

// handleAnalyticsBreakdown backs the Dashboard's Query Types/Response
// Codes/Protocol Usage ranked lists (V1.1.1 dashboard.html's qtypes/
// rcodes/protocols panels, read directly from analytics.* -- see
// dashboard.html in the shipped V1.1.1 package). Same TopDimension
// reader as handleAnalyticsTopDomains, just a different allowlisted
// column; dimension is restricted to a fixed set, never passed through
// to SQL directly (see dnsanalytics.dimensionColumns).
func (s *Server) handleAnalyticsBreakdown(w http.ResponseWriter, r *http.Request) {
	dimension := r.URL.Query().Get("dimension")
	switch dimension {
	case "qtype", "rcode", "protocol":
	default:
		Err(http.StatusBadRequest, "validation_error", "dimension must be one of: qtype, rcode, protocol").WriteJSON(w)
		return
	}
	minutes := floatQuery(r, "minutes", 60, 1, 31*24*60)
	limit := intQuery(r, "limit", 20, 1, 500)
	now := float64(time.Now().Unix())
	start := now - minutes*60
	granularity := "minute"
	if minutes > 120 {
		granularity = "hour"
	}
	columns := []string{dimension, "count"}

	if s.Analytics == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"rows": []any{}, "columns": columns, "degraded": true, "degraded_reason": analyticsUnavailable})
		return
	}
	rows, err := s.Analytics.TopDimension(r.Context(), dimension, start, now, granularity, limit)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"rows": []any{}, "columns": columns, "degraded": true, "degraded_reason": err.Error()})
		return
	}
	out := make([][2]any, 0, len(rows))
	for _, d := range rows {
		out = append(out, [2]any{d.Value, d.Count})
	}
	degraded, reason := writerDegraded(s.Analytics.Health(r.Context()))
	WriteJSON(w, http.StatusOK, map[string]any{
		"rows": out, "columns": columns, "degraded": degraded, "degraded_reason": reason,
		"window": map[string]any{"start": start, "end": now, "minutes": minutes},
	})
}

// handleAnalyticsTopClients backs the Clients page's Client analytics
// table (V1.1.1's app/analytics.py `clients_data()`, read directly):
// every client seen in the window ranked by query volume, each with its
// own blocked count/percent and last-seen timestamp. "label" resolution
// mirrors Python's own resolve_client_name() fallback chain: the owning
// managed client's name when the raw address matches one of its exact
// ipv4/ipv6 identifiers (see managedAddressLookup), else the most
// specific matching Client Alias CIDR (internal/clientalias, added
// 2026-08-28 -- V1.1.1's local_dns.py alias_for_client, read directly),
// else the raw address itself.
func (s *Server) handleAnalyticsTopClients(w http.ResponseWriter, r *http.Request) {
	minutes := floatQuery(r, "minutes", 1440, 1, 31*24*60)
	limit := intQuery(r, "limit", 200, 1, 2000)

	if s.Analytics == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"clients": []any{}, "total": 0, "degraded": true, "degraded_reason": analyticsUnavailable})
		return
	}
	rows, err := s.Analytics.ClientAnalytics(r.Context(), minutes, limit)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"clients": []any{}, "total": 0, "degraded": true, "degraded_reason": err.Error()})
		return
	}
	managed, err := s.managedAddressLookup(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load clients").WriteJSON(w)
		return
	}
	aliases := s.aliasResolver(r.Context())
	var total int64
	for _, row := range rows {
		total += row.Total
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		label := row.Client
		if m, ok := managed[row.Client]; ok && m.Name != "" {
			label = m.Name
		} else if alias := aliases.ResolveLabel(row.Client); alias != "" {
			label = alias
		}
		var share, blockedPercent float64
		if total > 0 {
			share = round1(float64(row.Total) / float64(total) * 100)
		}
		if row.Total > 0 {
			blockedPercent = round1(float64(row.Blocked) / float64(row.Total) * 100)
		}
		out = append(out, map[string]any{
			"raw_client":      row.Client,
			"label":           label,
			"value":           row.Total,
			"share":           share,
			"blocked":         row.Blocked,
			"blocked_percent": blockedPercent,
			"last_seen":       row.LastSeen,
			"last_seen_iso":   time.Unix(row.LastSeen, 0).UTC().Format(time.RFC3339),
		})
	}
	degraded, reason := writerDegraded(s.Analytics.Health(r.Context()))
	WriteJSON(w, http.StatusOK, map[string]any{
		"clients": out, "total": total, "degraded": degraded, "degraded_reason": reason,
		"window": map[string]any{"minutes": minutes},
	})
}

// rawQueryLogUnavailable mirrors analyticsUnavailable for the second,
// narrower compatibility boundary (see internal/rawquerylog).
const rawQueryLogUnavailable = "raw query-log reader not configured (no -query-log-dir path given at startup)"

// handleAnalyticsTopBlockedDomains reads real per-query domain detail
// from internal/dnsanalytics's own query_events table (s.RawQueryLog is
// wired to the exact same *dnsanalytics.Reader as s.Analytics -- see
// main.go's "RawQueryLog: analyticsReader" -- this is no longer a
// separate Python-Parquet compatibility boundary, that architecture is
// fully gone, see CUTOVER.md). Honestly degraded (not silently hidden)
// when that reader isn't wired up, same as every other analytics
// handler's nil-reader contract.
//
// A real, previously-undisclosed inconsistency fixed here: unlike
// handleAnalyticsTopDomains (its sibling Dashboard card, reading the
// exact same underlying data), this handler used to report
// degraded:false unconditionally on any successful query, never
// consulting the analytics writer/dnstap-ingestion health check at
// all -- the precise "DNS kept running while the analytics writer
// died and the page kept showing a convincing chart" failure class
// internal/pyanalytics/health.go was built to close everywhere else.
// Now checked the same way, via the same s.Analytics.Health.
func (s *Server) handleAnalyticsTopBlockedDomains(w http.ResponseWriter, r *http.Request) {
	minutes := floatQuery(r, "minutes", 60, 1, 31*24*60)
	limit := intQuery(r, "limit", 20, 1, 500)

	if s.RawQueryLog == nil {
		WriteJSON(w, http.StatusOK, map[string]any{
			"rows": []any{}, "columns": []string{"domain", "count"}, "degraded": true,
			"degraded_reason": "blocked-domain breakdown needs the raw query-log reader (-query-log-dir); " + rawQueryLogUnavailable,
		})
		return
	}
	counts, filesConsidered, err := s.RawQueryLog.TopDomains(r.Context(), minutes, true, limit)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"rows": []any{}, "columns": []string{"domain", "count"}, "degraded": true, "degraded_reason": err.Error()})
		return
	}
	out := make([][2]any, 0, len(counts))
	for _, c := range counts {
		out = append(out, [2]any{c.Domain, c.Count})
	}
	degraded, reason := false, ""
	if s.Analytics != nil {
		degraded, reason = writerDegraded(s.Analytics.Health(r.Context()))
	}
	now := float64(time.Now().Unix())
	WriteJSON(w, http.StatusOK, map[string]any{
		"rows": out, "columns": []string{"domain", "count"}, "degraded": degraded, "degraded_reason": reason,
		"window":           map[string]any{"start": now - minutes*60, "end": now, "minutes": minutes},
		"files_considered": filesConsidered,
	})
}

// handleAnalyticsQueryLog mirrors GET /api/analytics/query-log's contract
// (filters/limit/offset/degraded shape). s.RawQueryLog reads real
// per-query rows from internal/dnsanalytics's own query_events table --
// the same reader as s.Analytics (see main.go's "RawQueryLog:
// analyticsReader"), not a separate Python-Parquet compatibility
// boundary; that architecture is fully gone, see CUTOVER.md. search is
// an optional post-scan substring match across every returned row's
// string fields, matching Python's own "intentionally post-query and
// bounded" design (the allowlisted equality filters narrow the actual
// scan; search never widens it).
//
// Same real writer-health consistency fix as handleAnalyticsTopBlocked
// Domains: this used to report degraded:false on any successful query,
// never checking the analytics writer/dnstap-ingestion health -- of
// every page on this appliance, Query Log is the one an owner is most
// likely to check first during an actual writer outage, so silently
// looking "healthy" here was the worst place for that gap to exist.
func (s *Server) handleAnalyticsQueryLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	minutes := floatQuery(r, "minutes", 1440, 1, 31*24*60)
	// Statistics settings' recent_query_limit (V1.1.1 parity, see
	// dnsanalytics.Settings) is this endpoint's own default page size
	// whenever the caller doesn't explicitly pass ?limit= -- an explicit
	// value (e.g. the Query Log page's own page-size control) always
	// wins, matching how every other owner-configurable default on this
	// appliance behaves.
	defaultLimit := rawquerylog.DefaultLimit
	if s.AnalyticsSettings != nil {
		defaultLimit = s.AnalyticsSettings.Load().RecentQueryLimit
	}
	limit := intQuery(r, "limit", defaultLimit, 1, rawquerylog.MaxLimit)
	offset := intQuery(r, "offset", 0, 0, rawquerylog.MaxOffset)
	search := strings.TrimSpace(q.Get("search"))

	filters := rawquerylog.Filters{
		Client:      q.Get("client"),
		Domain:      q.Get("domain"),
		QType:       q.Get("qtype"),
		Protocol:    q.Get("protocol"),
		RCode:       q.Get("rcode"),
		Upstream:    q.Get("upstream"),
		CacheStatus: q.Get("cache_status"),
		BlockedOnly: q.Get("blocked_only") == "true" || q.Get("blocked_only") == "1",
	}
	filtersJSON := map[string]any{"minutes": minutes, "search": search}
	for key, value := range map[string]string{
		"client": filters.Client, "domain": filters.Domain, "qtype": filters.QType,
		"protocol": filters.Protocol, "rcode": filters.RCode, "upstream": filters.Upstream,
		"cache_status": filters.CacheStatus,
	} {
		if value != "" {
			filtersJSON[key] = value
		}
	}
	if filters.BlockedOnly {
		filtersJSON["blocked"] = true
	}

	if s.RawQueryLog == nil {
		WriteJSON(w, http.StatusOK, map[string]any{
			"rows": []any{}, "degraded": true, "degraded_reason": rawQueryLogUnavailable,
			"limit": limit, "offset": offset, "filters": filtersJSON,
		})
		return
	}
	result, err := s.RawQueryLog.RecentQueryLog(r.Context(), minutes, filters, limit, offset)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{
			"rows": []any{}, "degraded": true, "degraded_reason": err.Error(),
			"limit": limit, "offset": offset, "filters": filtersJSON,
		})
		return
	}
	rows := result.Rows
	if search != "" {
		needle := strings.ToLower(search)
		filtered := make([]rawquerylog.LogRow, 0, len(rows))
		for _, row := range rows {
			if strings.Contains(strings.ToLower(rowSearchText(row)), needle) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}

	// Resolve each row's raw client address to a friendly name, same
	// fallback chain (managed client's own name, else the most specific
	// Client Alias, else the raw address) as the Clients page's own
	// Client analytics table (handleAnalyticsTopClients) -- closing the
	// "raw Query Log grid never resolves aliases" gap this row's own
	// PARITY_MATRIX.md entry used to disclose. Best-effort: a lookup
	// failure degrades to "no resolved name" (the frontend already falls
	// back to the raw address), never a hard error for the whole grid.
	if managed, err := s.managedAddressLookup(r.Context()); err == nil {
		aliases := s.aliasResolver(r.Context())
		for i := range rows {
			if m, ok := managed[rows[i].Client]; ok && m.Name != "" {
				rows[i].ClientName = m.Name
			} else if alias := aliases.ResolveLabel(rows[i].Client); alias != "" {
				rows[i].ClientName = alias
			}
		}
	}

	degraded, reason := false, ""
	if s.Analytics != nil {
		degraded, reason = writerDegraded(s.Analytics.Health(r.Context()))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"rows": rows, "degraded": degraded, "degraded_reason": reason, "files_considered": result.FilesConsidered,
		"limit": limit, "offset": offset, "filters": filtersJSON,
	})
}

// handleStatisticsExport mirrors GET /api/statistics/export: a
// downloadable JSON dump of the aggregates store's own two tables.
// Deliberately does not include raw per-query history (same as Python's
// own export) -- that's already exportable via the Query Log's filters.
func (s *Server) handleStatisticsExport(w http.ResponseWriter, r *http.Request) {
	if s.Analytics == nil {
		Err(http.StatusServiceUnavailable, "unavailable", analyticsUnavailable).WriteJSON(w)
		return
	}
	buckets, dims, err := s.Analytics.ExportAll(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="alderpointdns-go-statistics-export.json"`)
	WriteJSON(w, http.StatusOK, map[string]any{
		"format_version": 1, "generated_at": time.Now().UTC().Format(time.RFC3339),
		"aggregate_time_buckets": buckets, "aggregate_dimension_counts": dims,
		"raw_query_history_included": false,
	})
}

// handleStatisticsClear mirrors POST /api/statistics/clear: a real
// DELETE against this process's own Go-native query_events table
// (internal/dnsanalytics.Reader.ClearAll) -- see that method's own doc
// comment for why this no longer routes through apdns-hostagent the way
// it did against Python's aggregates.db (that bridge is now permanently
// inert; see CUTOVER.md). Requires the same server-side "type CLEAR to
// confirm" check the original Python route enforced (never just a
// client-side-only confirm dialog); an operator who bypasses the UI and
// calls this directly still cannot clear anything without it.
// include_raw_history is still accepted (and ignored) for backward
// request-shape compatibility with the existing frontend -- this
// schema has exactly one table, so there is no longer a separate "raw
// history" to optionally spare.
func (s *Server) handleStatisticsClear(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Confirmation      string `json:"confirmation"`
		IncludeRawHistory *bool  `json:"include_raw_history"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	if in.Confirmation != "CLEAR" {
		Err(http.StatusBadRequest, "confirmation_required", "type CLEAR to confirm clearing statistics").WriteJSON(w)
		return
	}
	if s.Analytics == nil {
		Err(http.StatusServiceUnavailable, "unavailable", analyticsUnavailable).WriteJSON(w)
		return
	}
	rowsCleared, err := s.Analytics.ClearAll(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"status":               "cleared",
		"query_events_cleared": rowsCleared,
	})
}

// rowSearchText concatenates a row's string fields for the optional
// post-scan "search" filter -- matching Python's own `" ".join(str(v) for
// v in row)` behavior applied to every column, not just a chosen few.
func rowSearchText(row rawquerylog.LogRow) string {
	return strings.Join([]string{
		row.Client, row.ClientName, row.Domain, row.QType, row.Protocol, row.RCode,
		row.BlockReason, row.Upstream, row.CacheStatus, row.CacheProfileID,
	}, " ")
}
