// Package pyanalytics is the temporary Go->Python compatibility boundary
// for Dashboard analytics data, per the governing task's explicit
// allowance ("the Go control plane may communicate with the existing
// runtime service through a clear, tested compatibility boundary") and
// PARITY_MATRIX.md's "Sequencing note".
//
// Shape of the boundary (deliberately the narrowest one that's both safe
// and real, not a shortcut):
//
//   - Read-only. This package never executes anything but SELECT.
//   - A direct SQLite read of Python's own aggregates store
//     (/var/lib/alderpointdns-v2/analytics/aggregates.db), not an HTTP
//     proxy: the two backends' sessions are not interchangeable (same
//     cookie name, independent session tables), so a cookie-forwarding
//     proxy can't authenticate without its own separate design; a direct
//     read of an already-durable SQLite store needs no new auth surface
//     at all. Verified safe against the live preview: aggregates.db is
//     WAL-mode (concurrent readers never block Python's writer), and this
//     reader was proven against the actual running preview's live,
//     actively-written database before being wired in.
//   - Least-privilege: only the analytics/ subdirectory is ever mounted
//     into the Go container (read-only), never control.db (admins,
//     secrets, policy) or the secrets/ directory.
//   - Not authoritative and not duplicated: this package never writes,
//     never caches to Go's own control.db, and always re-reads live --
//     there is exactly one copy of this data, owned by Python, for as
//     long as this boundary exists.
//   - Deliberately incomplete: aggregates.db has pre-aggregated
//     total/blocked/cache counts per time bucket and per-dimension
//     counts (client/domain/protocol/qtype/rcode/upstream), which covers
//     time-series charts, live activity, and "Top Domains". It does NOT
//     have a blocked-domain breakdown (that requires Python's raw
//     Parquet query history via DuckDB, which itself requires a C
//     toolchain -- incompatible with this project's CGO_ENABLED=0 /
//     pure-Go build requirement without its own separate design). "Top
//     Blocked Domains" is therefore honestly reported as unavailable
//     (TopBlockedDomainsUnavailable below), not faked and not silently
//     dropped from the API surface -- see PARITY_MATRIX.md.
//   - Removal plan: once Milestone 2+ ports the analytics ingestion
//     pipeline natively to Go, this entire package is deleted and the
//     handlers switch to native Go queries -- tracked as this package's
//     sole reason to exist.
package pyanalytics

import (
	"context"
	"database/sql"
	"fmt"
)

// StepSeconds mirrors app/v2/webapp.py's _TIMESERIES_STEP_SECONDS exactly
// -- the two implementations must bucket-align identically or a chart
// comparing Python and Go data would silently disagree.
var StepSeconds = map[string]int64{"minute": 60, "hour": 3600, "day": 86400}

var Granularities = []string{"minute", "hour", "day"}

func ValidGranularity(g string) bool {
	step, ok := StepSeconds[g]
	return ok && step > 0
}

// AlignedBucketStart mirrors _aligned_bucket_start.
func AlignedBucketStart(ts float64, granularity string) int64 {
	step := StepSeconds[granularity]
	return (int64(ts) / step) * step
}

type Bucket struct {
	BucketStart  int64 `json:"bucket_start"`
	TotalQueries int   `json:"total_queries"`
	Blocked      int   `json:"blocked_queries"`
	CacheHits    int   `json:"cache_hits"`
	CacheMisses  int   `json:"cache_misses"`
}

type DimensionCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type Reader struct {
	db *sql.DB
}

// Open connects to Python's aggregates.db read-only mount. It does not
// fail if the file is temporarily missing/locked at open time (SQLite
// lazily opens on first query) -- callers must still treat any query
// error as "analytics degraded", never as a fatal startup condition, per
// "DNS works if analytics is dead" applying equally to this dashboard.
func Open(path string) (*Reader, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(2000)")
	if err != nil {
		return nil, fmt.Errorf("open analytics reader: %w", err)
	}
	db.SetMaxOpenConns(1)
	return &Reader{db: db}, nil
}

func (r *Reader) Close() error { return r.db.Close() }

// Ping proves the store is actually reachable right now (used for the
// dashboard's degraded/available status) -- a successful Open() alone
// doesn't guarantee the file is still there or readable.
func (r *Reader) Ping(ctx context.Context) error {
	var v string
	return r.db.QueryRowContext(ctx, `SELECT value FROM schema_meta LIMIT 1`).Scan(&v)
}

func (r *Reader) queryBuckets(ctx context.Context, query string, args ...any) ([]Bucket, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Bucket
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.BucketStart, &b.TotalQueries, &b.Blocked, &b.CacheHits, &b.CacheMisses); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// TimeSeries mirrors AnalyticsService.time_series_totals: real buckets
// from time_buckets in [start, end) at the given granularity, unfilled
// (the caller fills gaps -- see FillGaps -- exactly like
// _fill_timeseries_buckets does in Python).
func (r *Reader) TimeSeries(ctx context.Context, start, end float64, granularity string) ([]Bucket, error) {
	return r.queryBuckets(ctx,
		`SELECT bucket_start, total_queries, blocked_queries, cache_hits, cache_misses
		 FROM time_buckets WHERE granularity=? AND bucket_start>=? AND bucket_start<?
		 ORDER BY bucket_start`,
		granularity, int64(start), int64(end))
}

// Live mirrors AnalyticsService.live_totals: per-second live_buckets in
// [start, end].
func (r *Reader) Live(ctx context.Context, start, end float64) ([]Bucket, error) {
	return r.queryBuckets(ctx,
		`SELECT bucket_start, total_queries, blocked_queries, cache_hits, cache_misses
		 FROM live_buckets WHERE bucket_start>=? AND bucket_start<=?
		 ORDER BY bucket_start`,
		int64(start), int64(end))
}

// TopDimension mirrors AnalyticsService.top_dimension_from_aggregates:
// summed dimension_counts for one dimension (e.g. "domain") across every
// bucket of the given granularity in [start, end), highest count first.
func (r *Reader) TopDimension(ctx context.Context, dimension string, start, end float64, granularity string, limit int) ([]DimensionCount, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT value, SUM(count) AS total FROM dimension_counts
		 WHERE dimension=? AND granularity=? AND bucket_start>=? AND bucket_start<?
		 GROUP BY value ORDER BY total DESC LIMIT ?`,
		dimension, granularity, int64(start), int64(end), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DimensionCount
	for rows.Next() {
		var d DimensionCount
		if err := rows.Scan(&d.Value, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// FillGaps mirrors _fill_timeseries_buckets: a real bucket for every
// aligned step across [start, end], zero-filled where no data exists --
// a chart must never silently skip a quiet period.
func FillGaps(rows []Bucket, start, end float64, granularity string) []Bucket {
	step := StepSeconds[granularity]
	byBucket := make(map[int64]Bucket, len(rows))
	for _, b := range rows {
		byBucket[b.BucketStart] = b
	}
	startBucket := AlignedBucketStart(start, granularity)
	endBucket := AlignedBucketStart(end, granularity)
	out := make([]Bucket, 0, (endBucket-startBucket)/step+1)
	for bucket := startBucket; bucket <= endBucket; bucket += step {
		if b, ok := byBucket[bucket]; ok {
			out = append(out, b)
		} else {
			out = append(out, Bucket{BucketStart: bucket})
		}
	}
	return out
}

// FillLiveGaps is FillGaps's 1-second-bucket equivalent for live_buckets,
// matching analytics_live_activity's inline fill loop (every whole
// second in range gets a bucket, not just every step-th one).
func FillLiveGaps(rows []Bucket, start, end float64) []Bucket {
	byBucket := make(map[int64]Bucket, len(rows))
	for _, b := range rows {
		byBucket[b.BucketStart] = b
	}
	startBucket, endBucket := int64(start), int64(end)
	out := make([]Bucket, 0, endBucket-startBucket+1)
	for bucket := startBucket; bucket <= endBucket; bucket++ {
		if b, ok := byBucket[bucket]; ok {
			out = append(out, b)
		} else {
			out = append(out, Bucket{BucketStart: bucket})
		}
	}
	return out
}
