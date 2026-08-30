// Package pyanalytics is the temporary Go->Python compatibility boundary
// for Dashboard analytics data, per the governing task's explicit
// allowance ("the Go control plane may communicate with the existing
// runtime service through a clear, tested compatibility boundary") and
// PARITY_MATRIX.md's "Sequencing note".
//
// Shape of the boundary (deliberately the narrowest one that's both safe
// and real, not a shortcut):
//
//   - Read-only. This package never executes anything but SELECT, and
//     never even holds a mount of Python's live aggregates.db at all
//     (see below).
//   - NOT a direct read of Python's live aggregates.db. An earlier
//     version of this reader was, and hit a real, live P0 ("database
//     disk image is malformed (11)") -- root-caused (see
//     AGENT_PROGRESS.md's incident writeup) to a genuine, structural
//     conflict between two real constraints that cannot both be
//     satisfied by reading the live file directly: (a) the real
//     deployed mount is a genuine kernel-enforced read-only bind mount,
//     under which SQLite's own rollback-journal read path needs a
//     write-class open() (to check for a hot journal) that a real
//     read-only mount refuses outright regardless of permission bits --
//     so plain "mode=ro" cannot even open the file there; (b) the only
//     URI option that CAN open it there, "immutable=1", is unsafe
//     against a database still being actively written (a live WAL
//     database is still mutable -- periodic checkpoints rewrite the
//     main file in place -- so "it reports wal" was never proof
//     immutable=1 was safe; a real concurrent reproduction,
//     internal/pyanalytics/repro_walcorrupt_test.go, produced real
//     SQLITE_CORRUPT reads with immutable=1 in both DELETE and WAL
//     journal mode). This package resolves that tension instead of
//     picking a horn of it: see internal/analyticssnapshot's own doc
//     comment for the real fix -- apdns-hostagent (root, real
//     unrestricted access to the actual host directory, no read-only
//     mount involved) periodically publishes a real, consistent,
//     write-once copy of aggregates.db via SQLite's own "VACUUM INTO",
//     and this reader only ever reads THAT published snapshot, through
//     its own still-genuinely-read-only mount. Once published, a
//     generation's files are never written again, so "immutable=1" is
//     no longer a lie told to SQLite about a live database -- it is the
//     literal truth about a file that has already been fully written.
//   - Least-privilege: this process never mounts Python's live
//     analytics/ directory at all (a real, structural narrowing versus
//     the earlier design, not just a policy one) -- only
//     apdns-hostagent's own published-snapshot directory, and never
//     control.db (admins, secrets, policy) or the secrets/ directory.
//   - Not authoritative and not duplicated: this package never writes,
//     never caches to Go's own control.db, and always re-resolves the
//     current published snapshot on every query (see Reader.currentDB)
//     -- there is exactly one copy of this data, owned by Python, for
//     as long as this boundary exists; this reader is at most one
//     publish-interval behind it, and says so explicitly (see
//     AnalyticsHealth's snapshot-age fields in health.go) rather than
//     silently presenting a stale read as current.
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
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"alderpointdns/go-controlplane/internal/analyticssnapshot"
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

// ClientRow is the plain data shape for one ranked row of the Clients
// page's Client analytics table (see internal/dnsanalytics.Reader's real
// implementation, and internal/httpapi.AnalyticsReader, which both refer
// to this type -- kept here, next to Bucket/DimensionCount, for the same
// reason those live here: a shared shape both the real Go-native reader
// and this legacy, Python-decommission-era reader can refer to without
// an import cycle).
type ClientRow struct {
	Client   string
	Total    int64
	Blocked  int64
	LastSeen int64
}

// UpstreamResolverSummary is one resolver's real activity summed over a
// requested time window -- see internal/dnsanalytics/upstreamstats.go's
// TopUpstreams for the real (Go-native) implementation. Lives here
// (like ClientRow above) purely so both internal/pyanalytics.Reader's
// legacy stub and internal/dnsanalytics.Reader's real implementation
// can share one type without an import cycle (dnsanalytics already
// imports pyanalytics for Bucket/DimensionCount; the reverse is not
// true).
type UpstreamResolverSummary struct {
	ResolverKey      string
	Protocol         string
	Address          string
	HealthState      string
	QueriesAttempted int64
	SuccessfulResp   int64
	Failures         int64
	Timeouts         int64
	AvgLatencyMS     float64
}

type Reader struct {
	// mu guards db/openGenDir across currentDB's generation swaps --
	// every query takes a read lock to snapshot the current *sql.DB
	// pointer; a generation swap takes a write lock. Ordinary concurrent
	// queries never contend on this (RLock is shared); it only
	// serializes against a new-generation reopen or a corrupt-retry
	// reopen.
	mu           sync.RWMutex
	db           *sql.DB
	openGenDir   string // the resolved generation directory `db` currently points at ("" = none open yet)
	publishedDir string // apdns-hostagent's published-snapshot directory (see internal/analyticssnapshot)

	// lastManifest is the most recently resolved generation's manifest
	// (analyticssnapshot.Manifest) -- read by Health to report snapshot
	// freshness. Stored via atomic.Value so Health never has to take mu
	// just to report age.
	lastManifest atomic.Value

	// StaleAfter bounds how old a resolved snapshot's generated_at may
	// be before Health reports "degraded: snapshot stale" -- the
	// snapshot-pipeline analog of WriterStale below. Zero means use
	// DefaultStaleAfter.
	StaleAfter time.Duration

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
	// SQLITE_CORRUPT-class read and was retried once after reopening the
	// connection (see run() below) -- exposed by Health as a diagnostic
	// signal (never hidden), so a real recurrence is visible in
	// GET /api/health even on the calls where the retry itself
	// succeeded and the caller never saw an error. Expected to stay at
	// 0 in normal operation now that every read targets a genuinely
	// write-once published snapshot (see this package's own doc
	// comment) -- kept as defense in depth, not because it's expected
	// to fire.
	CorruptRetries atomic.Int64
}

// DefaultStaleAfter is used whenever Reader.StaleAfter is left zero.
// apdns-hostagent's own default publish interval is 15s (see
// internal/hostagentd/ops_analyticssnapshot.go); 3x that mirrors the
// same staleness-grace-multiple convention health.go's writer-heartbeat
// check already uses.
const DefaultStaleAfter = 45 * time.Second

// Open sets up a reader against apdns-hostagent's published analytics
// snapshot directory (see internal/analyticssnapshot's doc comment for
// the full design and why this reader no longer touches Python's live
// aggregates.db at all). Never fails just because nothing has been
// published yet -- resolution happens lazily on first query, and a
// caller must already treat every query error as "analytics degraded",
// never a fatal startup condition, per "DNS works if analytics is dead"
// applying equally to this dashboard.
func Open(publishedDir string) (*Reader, error) {
	return &Reader{publishedDir: publishedDir}, nil
}

func (r *Reader) Close() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.db == nil {
		return nil
	}
	return r.db.Close()
}

// isTransientCorrupt classifies an error as the specific transient,
// retryable read hazard the earlier direct-live-file design proved
// possible (SQLITE_CORRUPT / "database disk image is malformed") as
// opposed to any other failure (including a genuinely, permanently
// corrupt snapshot -- see currentDB's doc comment for why that
// distinction matters and why it's still safe not to make it
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

// currentDB resolves apdns-hostagent's "current" published generation
// (analyticssnapshot.ResolveCurrent) and returns a connection open
// against it, reopening only when the resolved generation has actually
// changed since the last call -- so a burst of requests between two
// publishes shares one connection (cheap), while a new publish is
// picked up within one resolution (near-real-time, bounded by
// apdns-hostagent's own publish interval). Uses "immutable=1"
// deliberately and safely here: unlike the earlier direct-live-file
// design, the file this opens is a genuinely, permanently write-once
// snapshot the instant it's published (see internal/analyticssnapshot's
// doc comment) -- immutable=1 is no longer a lie told to SQLite about a
// live database.
func (r *Reader) currentDB(ctx context.Context) (*sql.DB, error) {
	resolved, err := analyticssnapshot.ResolveCurrent(r.publishedDir)
	if err != nil {
		return nil, err
	}

	r.mu.RLock()
	if r.db != nil && r.openGenDir == resolved.GenDir {
		db := r.db
		r.mu.RUnlock()
		r.lastManifest.Store(resolved.Manifest)
		return db, nil
	}
	r.mu.RUnlock()

	return r.reopen(resolved)
}

// reopen swaps in a connection to the given resolved generation,
// closing whatever was open before. Always takes the write lock and
// re-checks under it (another goroutine may have already performed the
// same swap between currentDB's RUnlock and this call) to avoid two
// goroutines opening redundant connections for the same generation.
func (r *Reader) reopen(resolved analyticssnapshot.Resolved) (*sql.DB, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db != nil && r.openGenDir == resolved.GenDir {
		r.lastManifest.Store(resolved.Manifest)
		return r.db, nil
	}
	db, err := sql.Open("sqlite", "file:"+resolved.DBPath+"?mode=ro&immutable=1")
	if err != nil {
		return nil, fmt.Errorf("opening published analytics snapshot: %w", err)
	}
	if r.db != nil {
		_ = r.db.Close()
	}
	r.db = db
	r.openGenDir = resolved.GenDir
	r.lastManifest.Store(resolved.Manifest)
	return db, nil
}

// forceReopen discards whatever connection/generation is currently
// cached, forcing the next currentDB call to re-resolve and open fresh
// -- used only by run()'s corrupt-retry path below.
func (r *Reader) forceReopen(reason error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	slog.Warn("pyanalytics: forcing a fresh connection after a transient corrupt-class read against the published snapshot",
		"published_dir", r.publishedDir, "generation", r.openGenDir, "error", reason)
	r.CorruptRetries.Add(1)
	if r.db != nil {
		_ = r.db.Close()
	}
	r.db = nil
	r.openGenDir = ""
}

// run resolves/opens the current published snapshot and executes op
// against it; on the specific transient-corrupt class of error (see
// isTransientCorrupt), it forces a fresh resolve+reopen and retries
// exactly once, recording the retry diagnostically (CorruptRetries, a
// structured slog.Warn) either way -- a caller that ultimately still
// fails sees the real error and the dashboard reports degraded,
// honestly, never silently substituted with empty/zero data. Any other
// error (a genuine query error, a real permanently-corrupt snapshot, no
// snapshot published yet, SQLITE_BUSY that outlasted busy_timeout) is
// returned as-is on the first attempt, not retried -- this path exists
// solely for the one proven-transient failure mode, not as a general
// retry-everything policy.
func (r *Reader) run(ctx context.Context, op func(db *sql.DB) error) error {
	db, err := r.currentDB(ctx)
	if err != nil {
		return err
	}
	err = op(db)
	if !isTransientCorrupt(err) {
		return err
	}
	r.forceReopen(err)
	db, rerr := r.currentDB(ctx)
	if rerr != nil {
		return fmt.Errorf("reopening after corrupt read failed: %w (original: %v)", rerr, err)
	}
	retryErr := op(db)
	if retryErr != nil {
		slog.Warn("pyanalytics: retry after reopening still failed -- remaining degraded",
			"published_dir", r.publishedDir, "original_error", err, "retry_error", retryErr)
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

// ClientAnalytics exists only so *Reader still satisfies
// internal/httpapi.AnalyticsReader (some pre-existing tests construct a
// real *pyanalytics.Reader to exercise other handler behavior). It is
// never wired into production as the live Analytics reader -- see
// cmd/alderpointdns-go/main.go, which always uses
// *dnsanalytics.Reader's real implementation -- and this package's own
// snapshot schema (time_buckets/dimension_counts) never stored a
// per-client blocked-count/last-seen breakdown even before Python's
// decommission, so an honest "not supported" is correct here, not a
// regression.
func (r *Reader) ClientAnalytics(ctx context.Context, minutes float64, limit int) ([]ClientRow, error) {
	return nil, fmt.Errorf("client analytics not supported by the legacy pyanalytics reader (never wired into production; see internal/dnsanalytics.Reader)")
}

// ClearAll exists only so *Reader still satisfies
// internal/httpapi.AnalyticsReader (see ClientAnalytics's own doc
// comment for why -- same reasoning applies here).
func (r *Reader) ClearAll(ctx context.Context) (int64, error) {
	return 0, fmt.Errorf("clear not supported by the legacy pyanalytics reader (never wired into production; see internal/dnsanalytics.Reader)")
}

// TopUpstreams exists only so *Reader still satisfies
// internal/httpapi.AnalyticsReader (see ClientAnalytics's own doc
// comment for why -- same reasoning applies here: this snapshot
// schema never stored per-resolver counters either).
func (r *Reader) TopUpstreams(ctx context.Context, since time.Time, limit int) ([]UpstreamResolverSummary, error) {
	return nil, fmt.Errorf("top upstreams not supported by the legacy pyanalytics reader (never wired into production; see internal/dnsanalytics.Reader)")
}

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
