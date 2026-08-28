package dnsanalytics

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"alderpointdns/go-controlplane/internal/pyanalytics"
	"alderpointdns/go-controlplane/internal/rawquerylog"
)

// Reader answers every /api/analytics/* and /api/statistics/* query
// against query_events. It deliberately reuses pyanalytics.Bucket /
// pyanalytics.DimensionCount / pyanalytics.AnalyticsHealth and
// rawquerylog.LogRow / rawquerylog.Result / rawquerylog.Filters as
// plain data shapes -- not by depending on either package's own
// Python-reading logic -- so every existing httpapi handler and the
// already-shipped frontend keep the exact response contract they were
// built against, backed now by this process's own real data instead of
// a bridge to a process that no longer exists.
type Reader struct {
	DB     *sql.DB
	Writer *Writer // for Health's liveness signal; nil is a valid "no writer wired" state
}

func (r *Reader) queryBuckets(ctx context.Context, query string, args ...any) ([]pyanalytics.Bucket, error) {
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pyanalytics.Bucket
	for rows.Next() {
		var b pyanalytics.Bucket
		if err := rows.Scan(&b.BucketStart, &b.TotalQueries, &b.Blocked); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// TimeSeries aggregates real query_events rows into fixed-width buckets
// at the given granularity. CacheHits/CacheMisses are always 0: dnstap's
// CLIENT_RESPONSE message carries no cache-hit signal from dnsdist's
// packet cache today -- a disclosed gap, not fabricated data.
func (r *Reader) TimeSeries(ctx context.Context, start, end float64, granularity string) ([]pyanalytics.Bucket, error) {
	step, ok := pyanalytics.StepSeconds[granularity]
	if !ok {
		return nil, fmt.Errorf("invalid granularity %q", granularity)
	}
	return r.queryBuckets(ctx, `
		SELECT (ts/?)*? AS bucket_start,
		       COUNT(*) AS total,
		       SUM(CASE WHEN outcome=? THEN 1 ELSE 0 END) AS blocked
		FROM query_events
		WHERE ts >= ? AND ts < ?
		GROUP BY bucket_start
		ORDER BY bucket_start`,
		step, step, OutcomeBlocked, int64(start), int64(end))
}

// Live is TimeSeries's 1-second-bucket equivalent for the Dashboard's
// live activity strip.
func (r *Reader) Live(ctx context.Context, start, end float64) ([]pyanalytics.Bucket, error) {
	return r.queryBuckets(ctx, `
		SELECT ts AS bucket_start,
		       COUNT(*) AS total,
		       SUM(CASE WHEN outcome=? THEN 1 ELSE 0 END) AS blocked
		FROM query_events
		WHERE ts >= ? AND ts <= ?
		GROUP BY ts
		ORDER BY ts`,
		OutcomeBlocked, int64(start), int64(end))
}

// TopDimension supports dimension="domain" only today (the one caller,
// handleAnalyticsTopDomains, never asks for another) -- across every
// outcome, matching Python's own "top domains overall" semantics
// (top-blocked-only is the separate TopDomains method below).
func (r *Reader) TopDimension(ctx context.Context, dimension string, start, end float64, granularity string, limit int) ([]pyanalytics.DimensionCount, error) {
	if dimension != "domain" {
		return nil, fmt.Errorf("unsupported dimension %q", dimension)
	}
	rows, err := r.DB.QueryContext(ctx, `
		SELECT domain, COUNT(*) AS total FROM query_events
		WHERE ts >= ? AND ts < ?
		GROUP BY domain ORDER BY total DESC LIMIT ?`,
		int64(start), int64(end), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pyanalytics.DimensionCount
	for rows.Next() {
		var d pyanalytics.DimensionCount
		if err := rows.Scan(&d.Value, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// TopDomains backs handleAnalyticsTopBlockedDomains's s.RawQueryLog
// interface (blockedOnly=true is its only real caller; supported for
// both values for interface parity with rawquerylog.Reader.TopDomains).
func (r *Reader) TopDomains(ctx context.Context, minutes float64, blockedOnly bool, limit int) ([]rawquerylog.DomainCount, int, error) {
	now := float64(time.Now().Unix())
	start := now - minutes*60
	query := `SELECT domain, COUNT(*) AS total FROM query_events WHERE ts >= ?`
	args := []any{int64(start)}
	if blockedOnly {
		query += ` AND outcome = ?`
		args = append(args, OutcomeBlocked)
	}
	query += ` GROUP BY domain ORDER BY total DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []rawquerylog.DomainCount
	for rows.Next() {
		var d rawquerylog.DomainCount
		if err := rows.Scan(&d.Domain, &d.Count); err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, 1, rows.Err() // filesConsidered has no SQLite-backed meaning; 1 signals "the store was queried"
}

// RecentQueryLog backs handleAnalyticsQueryLog's s.RawQueryLog
// interface: real per-query rows, newest first, with the same
// allowlisted equality filters rawquerylog.Filters already defines.
func (r *Reader) RecentQueryLog(ctx context.Context, minutes float64, filters rawquerylog.Filters, limit, offset int) (rawquerylog.Result, error) {
	now := float64(time.Now().Unix())
	start := now - minutes*60
	query := `SELECT id, ts, client, domain, qtype, protocol, rcode, latency_ms, outcome
		FROM query_events WHERE ts >= ?`
	args := []any{int64(start)}
	if filters.Client != "" {
		query += ` AND client = ?`
		args = append(args, filters.Client)
	}
	if filters.Domain != "" {
		query += ` AND domain = ?`
		args = append(args, filters.Domain)
	}
	if filters.QType != "" {
		query += ` AND qtype = ?`
		args = append(args, filters.QType)
	}
	if filters.Protocol != "" {
		query += ` AND protocol = ?`
		args = append(args, filters.Protocol)
	}
	if filters.RCode != "" {
		query += ` AND rcode = ?`
		args = append(args, filters.RCode)
	}
	if filters.BlockedOnly {
		query += ` AND outcome = ?`
		args = append(args, OutcomeBlocked)
	}
	query += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return rawquerylog.Result{}, err
	}
	defer rows.Close()
	out := rawquerylog.Result{Rows: []rawquerylog.LogRow{}}
	for rows.Next() {
		var lr rawquerylog.LogRow
		var outcome string
		if err := rows.Scan(&lr.ID, &lr.TS, &lr.Client, &lr.Domain, &lr.QType, &lr.Protocol, &lr.RCode, &lr.LatencyMs, &outcome); err != nil {
			return rawquerylog.Result{}, err
		}
		lr.Blocked = outcome == OutcomeBlocked
		out.Rows = append(out.Rows, lr)
	}
	out.FilesConsidered = 1
	return out, rows.Err()
}

// ExportAll backs GET /api/statistics/export. There are no separate
// time_buckets/dimension_counts tables in this schema (see the package
// doc comment) -- both exported "tables" are computed the same way the
// live dashboard computes them, over this store's entire real history.
func (r *Reader) ExportAll(ctx context.Context) ([]pyanalytics.ExportRow, []pyanalytics.ExportRow, error) {
	var minTS sql.NullInt64
	if err := r.DB.QueryRowContext(ctx, `SELECT MIN(ts) FROM query_events`).Scan(&minTS); err != nil {
		return nil, nil, err
	}
	start := float64(0)
	if minTS.Valid {
		start = float64(minTS.Int64)
	}
	end := float64(time.Now().Unix()) + 1
	buckets, err := r.TimeSeries(ctx, start, end, "hour")
	if err != nil {
		return nil, nil, err
	}
	bucketRows := make([]pyanalytics.ExportRow, 0, len(buckets))
	for _, b := range buckets {
		bucketRows = append(bucketRows, pyanalytics.ExportRow{
			"bucket_start": b.BucketStart, "granularity": "hour",
			"total_queries": b.TotalQueries, "blocked_queries": b.Blocked,
			"cache_hits": b.CacheHits, "cache_misses": b.CacheMisses,
		})
	}
	dims, err := r.TopDimension(ctx, "domain", start, end, "hour", 10000)
	if err != nil {
		return nil, nil, err
	}
	dimRows := make([]pyanalytics.ExportRow, 0, len(dims))
	for _, d := range dims {
		dimRows = append(dimRows, pyanalytics.ExportRow{"dimension": "domain", "value": d.Value, "count": d.Count})
	}
	return bucketRows, dimRows, nil
}

// Ping proves the database is reachable right now -- Health's first
// tier.
func (r *Reader) Ping(ctx context.Context) error {
	return r.DB.PingContext(ctx)
}

// Health is the single real-liveness probe the Dashboard and System
// Status pages call, matching pyanalytics.AnalyticsHealth's shape (see
// that type's own doc comment for what each tier means) but evaluated
// against this store's actual architecture: there is no separate
// snapshot/heartbeat/inbox pipeline to go stale independently of the
// data -- the Writer IS this process. Two independent liveness signals
// feed this, deliberately not collapsed into one:
//
//   - Writer.Heartbeat: "is the accept/decode loop still running at
//     all" (ticks every second regardless of query volume).
//   - Writer.Ingestion: "is it still actually receiving real dnstap
//     frames, cross-checked against independent real DNS traffic" (see
//     writer.go's watchdog doc comment) -- this is what closes the real
//     failure class this whole package was hardened against: a silent,
//     one-sided fstrm stall where the accept/decode loop's own
//     heartbeat keeps ticking forever while zero frames arrive. Without
//     this check, Health would report "ok" throughout a known stall --
//     exactly the false-positive the governing task named.
func (r *Reader) Health(ctx context.Context) pyanalytics.AnalyticsHealth {
	h := pyanalytics.AnalyticsHealth{}
	if err := r.Ping(ctx); err != nil {
		h.DBReachable = false
		h.Status = "failed"
		h.Reason = fmt.Sprintf("analytics store unreachable: %s", err)
		return h
	}
	h.DBReachable = true

	if r.Writer == nil {
		h.Status = "degraded"
		h.Reason = "no dnstap writer configured for this process"
		return h
	}
	last, started := r.Writer.Heartbeat()
	h.WriterConfigured = true
	if !started {
		h.Status = "degraded"
		h.WriterStatus = "not_started"
		h.WriterStale = true
		h.Reason = "dnstap listener has not started"
		return h
	}
	age := time.Since(time.Unix(last, 0))
	lastF := float64(last)
	h.WriterLastSuccessAt = &lastF
	if age > 30*time.Second {
		h.Status = "degraded"
		h.WriterStatus = "stale"
		h.WriterStale = true
		h.Reason = fmt.Sprintf("dnstap listener heartbeat is %.0fs old", age.Seconds())
		return h
	}

	ing := r.Writer.Ingestion()
	frameAge := ing.FrameAgeSeconds
	h.IngestionStalled = ing.Stalled
	h.IngestionFrameAgeSeconds = &frameAge
	h.IngestionRecoveryCount = ing.RecoveryCount
	h.IngestionTrafficProbeConfigured = ing.TrafficProbeConfigured
	h.IngestionTrafficProbeOK = ing.TrafficProbeOK
	if ing.LastRecoveryAt != 0 {
		lr := float64(ing.LastRecoveryAt)
		h.IngestionLastRecoveryAt = &lr
	}
	if ing.Stalled {
		h.Status = "degraded"
		h.WriterStatus = "stalled"
		h.WriterStale = true
		if ing.TrafficProbeConfigured && !ing.TrafficProbeOK {
			h.Reason = fmt.Sprintf("no dnstap frames for %.0fs and the independent BIND traffic probe could not be reached to confirm real traffic -- reporting degraded rather than assuming ok", frameAge)
		} else if ing.TrafficProbeConfigured {
			h.Reason = fmt.Sprintf("dnstap ingestion stalled: no frames for %.0fs while real DNS traffic kept flowing (confirmed via BIND's own query counters, independent of dnsdist/dnstap) -- %d automatic recovery attempt(s) made so far", frameAge, ing.RecoveryCount)
		} else {
			h.Reason = fmt.Sprintf("no dnstap frames for %.0fs and no traffic probe is configured to confirm whether this is a real stall or a quiet network -- reporting degraded rather than assuming ok", frameAge)
		}
		return h
	}

	h.Status = "ok"
	h.WriterStatus = "ok"
	inserted, decodeErrs := r.Writer.Stats()
	if decodeErrs > 0 && inserted == 0 {
		// Real signal worth surfacing even though it doesn't demote
		// status: frames are arriving but none have decoded yet.
		h.Reason = fmt.Sprintf("%d dnstap frames failed to decode, 0 inserted so far", decodeErrs)
	}
	return h
}
