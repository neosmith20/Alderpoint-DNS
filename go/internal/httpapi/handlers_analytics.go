package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"alderpointdns/go-controlplane/internal/pyanalytics"
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
	WriteJSON(w, http.StatusOK, map[string]any{
		"granularity": granularity,
		"degraded":    false,
		"window":      map[string]any{"start": start, "end": now, "minutes": minutes},
		"buckets":     bucketsJSON(filled),
	})
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

	WriteJSON(w, http.StatusOK, map[string]any{
		"degraded":                    false,
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
	resp := map[string]any{
		"rows": out, "columns": []string{"domain", "count"}, "degraded": false,
		"window": map[string]any{"start": start, "end": now, "minutes": minutes},
	}
	if granularity == "hour" {
		resp["aggregation_note"] = "windows over 120 minutes are summed from hour buckets (coarser than Python's raw-Parquet path for the same window)"
	}
	WriteJSON(w, http.StatusOK, resp)
}

// handleAnalyticsTopBlockedDomains is honestly, permanently unavailable
// through this compatibility boundary -- see pyanalytics's doc comment.
// Returns the same degraded shape Python's endpoints use so a frontend
// that already handles a Python-style degraded response needs no special
// case for this one.
func (s *Server) handleAnalyticsTopBlockedDomains(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]any{
		"rows": []any{}, "columns": []string{"domain", "count"}, "degraded": true,
		"degraded_reason": "blocked-domain breakdown requires Python's raw Parquet/DuckDB query path, which this pure-Go (CGO_ENABLED=0) compatibility boundary deliberately does not include -- see PARITY_MATRIX.md",
	})
}
