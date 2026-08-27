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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
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
	// mu guards db/path across a reset() -- every query takes a read
	// lock to snapshot the current *sql.DB pointer; reset() takes a
	// write lock to swap it out for a freshly reopened one. Ordinary
	// concurrent queries never contend on this (RLock is shared); it
	// only serializes against the rare corrupt-retry path.
	mu   sync.RWMutex
	db   *sql.DB
	path string

	// WorkerHeartbeatsDir and InboxDir are optional, set by the caller
	// after Open (main.go, from its own -analytics-worker-heartbeats-dir
	// / -analytics-inbox-dir flags) -- empty means that half of Health's
	// signal is reported as "not configured" rather than degraded, so a
	// deployment that hasn't wired the extra read-only mount up yet
	// doesn't get a false "writer dead" report. See health.go.
	WorkerHeartbeatsDir string
	InboxDir            string

	// consecutiveFailures counts Ping failures in a row across calls to
	// Health -- reset to 0 the instant a read succeeds again, so it is
	// always an accurate "how many of the most recent probes failed
	// before this one", not a value that requires a restart to recover
	// (see health.go's Health doc comment).
	consecutiveFailures atomic.Int64

	// CorruptRetries counts how many times a query hit a transient
	// SQLITE_CORRUPT-class read and was retried once after resetting the
	// connection (see run() below) -- exposed by Health as a diagnostic
	// signal (never hidden), so a real recurrence is visible in
	// GET /api/health even on the calls where the retry itself
	// succeeded and the caller never saw an error.
	CorruptRetries atomic.Int64
}

// Open connects to Python's aggregates.db read-only mount. It does not
// fail if the file is temporarily missing/locked at open time (SQLite
// lazily opens on first query) -- callers must still treat any query
// error as "analytics degraded", never as a fatal startup condition, per
// "DNS works if analytics is dead" applying equally to this dashboard.
//
// Real defect found live once this control plane's own container
// actually ran as its unprivileged UID instead of root (see
// internal/deployperm's regression test): without an explicit "mode=ro"
// URI parameter, SQLite's default open mode is read-write -- needed even
// for a plain SELECT, since the rollback-journal locking protocol may
// create/delete a "-journal" sidecar file next to the database on every
// transaction. "mode=ro" (matching internal/hostagentd/
// ops_replication.go's control.db reader) fixes that.
//
// Does NOT use "immutable=1" -- an earlier version of this reader did,
// on the theory that Python's aggregates.db runs in WAL mode and
// immutable=1 is WAL-safe. A live P0 ("database disk image is malformed
// (11)" on Top Domains) proved that theory wrong, and a real concurrent
// reproduction (internal/pyanalytics/repro_walcorrupt_test.go,
// TestWALCorruptionRepro_Matrix) proved exactly why: immutable=1 with a
// short-lived (per-query) connection produced real, repeated
// SQLITE_CORRUPT reads against an actively, structurally mutating file
// in BOTH DELETE *and* WAL journal mode (~5.5% of queries under
// concurrent stress in this harness) -- a WAL database is still mutable
// (checkpoints rewrite the main file in place), so "it reports wal" was
// never actually a safety proof, exactly as flagged in the incident's
// follow-up correction. A long-lived immutable=1 connection didn't
// reproduce the crash in that same matrix, but a dedicated follow-up
// (TestImmutableLongLivedConnectionIsStaleNotSafe) proved that's because
// it goes stale, not because it's safe: it observed zero of 576 real
// committed writes during the same test window a fresh connection saw
// immediately. Plain "mode=ro" (no immutable), by contrast, produced
// zero corrupt reads across all combinations tested (DELETE/WAL journal
// mode x long/short-lived connections, thousands of queries each,
// concurrent structural writer churn) -- real SQLite locking is what
// actually keeps a reader consistent against a live mutable database,
// not a flag that tells SQLite to stop checking.
func Open(path string) (*Reader, error) {
	db, err := openReaderDB(path)
	if err != nil {
		return nil, err
	}
	return &Reader{db: db, path: path}, nil
}

func openReaderDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open analytics reader: %w", err)
	}
	// A handful of real connections, matching the dashboard's real
	// access pattern of several analytics endpoints firing close
	// together on page load (see AGENT_PROGRESS.md's timing evidence) --
	// real SQLite locking (proven safe above) lets these run
	// concurrently without serializing every query through one
	// connection the way the old immutable=1 design did.
	db.SetMaxOpenConns(4)
	return db, nil
}

func (r *Reader) Close() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.db.Close()
}

// isTransientCorrupt classifies an error as the specific transient,
// retryable read hazard proven above (SQLITE_CORRUPT / "database disk
// image is malformed") as opposed to any other failure (including a
// genuinely, permanently corrupt file -- see reset()'s doc comment for
// why that distinction matters and why it's still safe not to make it
// perfectly).
func isTransientCorrupt(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CORRUPT {
		return true
	}
	// Fallback substring match: modernc.org/sqlite wraps some errors
	// (e.g. surfaced through database/sql's own error path) in ways
	// errors.As may not unwrap to *sqlite.Error, so the exact reported
	// text from the live incident is matched directly too.
	msg := err.Error()
	return strings.Contains(msg, "malformed") || strings.Contains(msg, "SQLITE_CORRUPT")
}

// reset closes the current connection pool and opens a fresh one at the
// same path. This does NOT re-validate that the file is actually fine --
// a genuinely, permanently corrupt file will simply fail again on the
// retry after reset (see run() below), which is exactly the intended
// behavior: reset only ever buys one clean-slate attempt against
// whatever transient, connection-local state (a cached schema/page read
// mid-tear) caused the first failure; it never masks a real, persistent
// SQLITE_CORRUPT by silently retrying forever or substituting empty
// data.
func (r *Reader) reset(reason error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	slog.Warn("pyanalytics: resetting reader connection after a transient corrupt-class read",
		"path", r.path, "error", reason)
	r.CorruptRetries.Add(1)
	_ = r.db.Close()
	db, err := openReaderDB(r.path)
	if err != nil {
		return err
	}
	r.db = db
	return nil
}

// run executes op against the current connection; on the specific
// transient-corrupt class of error (see isTransientCorrupt), it resets
// the connection and retries exactly once, recording the retry
// diagnostically (CorruptRetries, a structured slog.Warn) either way --
// a caller that ultimately still fails sees the real error and the
// dashboard reports degraded, honestly, never silently substituted with
// empty/zero data. Any other error (a genuine query error, a real
// permanently-corrupt file, SQLITE_BUSY that outlasted busy_timeout) is
// returned as-is on the first attempt, not retried -- this path exists
// solely for the one proven-transient failure mode, not as a general
// retry-everything policy.
func (r *Reader) run(ctx context.Context, op func(db *sql.DB) error) error {
	r.mu.RLock()
	db := r.db
	r.mu.RUnlock()

	err := op(db)
	if !isTransientCorrupt(err) {
		return err
	}
	if rerr := r.reset(err); rerr != nil {
		return fmt.Errorf("reader reset after corrupt read failed: %w (original: %v)", rerr, err)
	}
	r.mu.RLock()
	db = r.db
	r.mu.RUnlock()
	retryErr := op(db)
	if retryErr != nil {
		slog.Warn("pyanalytics: retry after connection reset still failed -- remaining degraded",
			"path", r.path, "original_error", err, "retry_error", retryErr)
	}
	return retryErr
}

// Ping proves the store is actually reachable right now (used for the
// dashboard's degraded/available status) -- a successful Open() alone
// doesn't guarantee the file is still there or readable.
func (r *Reader) Ping(ctx context.Context) error {
	return r.run(ctx, func(db *sql.DB) error {
		var v string
		return db.QueryRowContext(ctx, `SELECT value FROM schema_meta LIMIT 1`).Scan(&v)
	})
}

func (r *Reader) queryBuckets(ctx context.Context, query string, args ...any) ([]Bucket, error) {
	var out []Bucket
	err := r.run(ctx, func(db *sql.DB) error {
		out = nil // a retried attempt must not append to a partial result from the failed one
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b Bucket
			if err := rows.Scan(&b.BucketStart, &b.TotalQueries, &b.Blocked, &b.CacheHits, &b.CacheMisses); err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
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
	var out []DimensionCount
	err := r.run(ctx, func(db *sql.DB) error {
		out = nil
		rows, err := db.QueryContext(ctx,
			`SELECT value, SUM(count) AS total FROM dimension_counts
			 WHERE dimension=? AND granularity=? AND bucket_start>=? AND bucket_start<?
			 GROUP BY value ORDER BY total DESC LIMIT ?`,
			dimension, granularity, int64(start), int64(end), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d DimensionCount
			if err := rows.Scan(&d.Value, &d.Count); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
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

// ExportRow is one row of ExportAll's output -- every column of
// time_buckets or dimension_counts, named, matching
// app/v2/statistics_control.py's export_statistics shape (a full,
// unfiltered dump of both tables) closely enough for the same "download
// everything the aggregate store has" purpose. Deliberately a generic
// map, not a fixed struct: time_buckets and dimension_counts have
// different columns, and this is a one-off export path, not a query hot
// path worth a typed schema for.
type ExportRow = map[string]any

// ExportAll dumps every row of time_buckets and dimension_counts,
// unfiltered -- the Go-native equivalent of Python's statistics export
// (GET /api/statistics/export). Raw per-query history is deliberately
// NOT included here either, same as Python's own export: it's already
// exportable via the Query Log's own filters (internal/rawquerylog), and
// including it here would make this export's size unbounded.
func (r *Reader) ExportAll(ctx context.Context) (buckets []ExportRow, dims []ExportRow, err error) {
	err = r.run(ctx, func(db *sql.DB) error {
		var ierr error
		buckets, ierr = queryAllRows(ctx, db, `SELECT * FROM time_buckets ORDER BY bucket_start`)
		if ierr != nil {
			return ierr
		}
		dims, ierr = queryAllRows(ctx, db, `SELECT * FROM dimension_counts ORDER BY bucket_start`)
		return ierr
	})
	if err != nil {
		return nil, nil, err
	}
	return buckets, dims, nil
}

func queryAllRows(ctx context.Context, db *sql.DB, query string) ([]ExportRow, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []ExportRow{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(ExportRow, len(cols))
		for i, c := range cols {
			row[c] = vals[i]
		}
		out = append(out, row)
	}
	return out, rows.Err()
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
