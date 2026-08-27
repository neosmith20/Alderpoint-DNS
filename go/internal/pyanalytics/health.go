// Analytics writer/receiver health -- the fix for a real V1.1.1 failure
// class named directly in the governing task: V1 could leave DNS running
// fine while its analytics writer thread died (typically on
// SQLITE_BUSY, a real SQLite error under write contention), and the
// Dashboard/Top Domains kept showing a *convincing* all-zeros chart --
// indistinguishable from genuinely quiet traffic -- rather than any
// indication that analytics itself had stopped. A plain SQL read against
// aggregates.db (Ping/TimeSeries/Live/TopDimension elsewhere in this
// package) cannot catch this: WAL mode lets reads keep succeeding
// against whatever was last durably committed even while the one
// process that ever writes to it is stuck or dead, so "the query
// succeeded" proves nothing about whether new data is still arriving.
//
// This file adds the other half: reading the *writer's own* real
// liveness signal, independent of whatever the data file currently
// contains. Two real, already-durable, already-tested facts, both
// read-only and requiring zero Python changes:
//
//   - app/v2/worker_heartbeat.py already writes a small JSON heartbeat
//     record to STATE_DIR/worker-heartbeats/analytics-worker.json before
//     and after every tick of the real writer loop (status
//     "running"/"ok"/"tick_failed", last_success_at, last_error). This
//     file already exists on the live host, already updates every ~15s,
//     and already has exactly the SQLITE_BUSY-class failure surfaced in
//     last_error the moment a tick fails -- ReadHeartbeat/IsStale below
//     are a direct Go port of that module's own read_heartbeat/is_stale.
//   - analytics-protobuf-receiver (the separate process that feeds the
//     writer) drops one file per received batch into
//     STATE_DIR/analytics/inbox/ for the writer to drain -- already
//     inside the analytics/ subdirectory this package's Reader already
//     mounts read-only (see the package doc comment's "least-privilege"
//     bullet), so queue depth needs no new mount at all, only the
//     heartbeats directory does.
package pyanalytics

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// analyticsWorkerName and analyticsWorkerIntervalSeconds mirror
// app/v2/worker_heartbeat.py's own WORKER_INTERVALS_SECONDS entry for
// "analytics-worker" exactly -- staleness must use the same interval
// Python's own health check uses, or the two could disagree about
// whether the same real heartbeat file is stale.
const (
	analyticsWorkerName            = "analytics-worker"
	analyticsWorkerIntervalSeconds = 15.0
	// defaultStallGraceSeconds mirrors DEFAULT_STALL_GRACE_SECONDS.
	defaultStallGraceSeconds = 120.0
	// maxSanitizedErrorLen bounds how much of last_error is ever
	// forwarded to the browser -- these are short SQLite/Python
	// exception strings by construction upstream, never secrets, but an
	// unbounded string from a file this process doesn't control still
	// has no business reaching an HTTP response unbounded.
	maxSanitizedErrorLen = 300
)

// WorkerHeartbeat is a direct field-for-field port of
// worker_heartbeat.HeartbeatState.
type WorkerHeartbeat struct {
	Worker        string
	Status        string // "running" | "ok" | "tick_failed" | "unknown"
	TickCount     int64
	TickStartedAt *float64
	LastSuccessAt *float64
	LastResult    *int64
	LastError     *string
}

// ReadHeartbeat is a direct port of read_heartbeat: a missing or
// unparsable file is reported as (nil, nil) -- "unknown", exactly like
// Python's own read_heartbeat returning None, never a hard error (a
// health probe must always produce a rendered answer, never fail
// outright because one optional side-channel file is absent on a
// deployment that hasn't wired the mount up yet).
func ReadHeartbeat(dir, worker string) *WorkerHeartbeat {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, worker+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var parsed struct {
		Worker        string   `json:"worker"`
		Status        string   `json:"status"`
		TickCount     int64    `json:"tick_count"`
		TickStartedAt *float64 `json:"tick_started_at"`
		LastSuccessAt *float64 `json:"last_success_at"`
		LastResult    *int64   `json:"last_result"`
		LastError     *string  `json:"last_error"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	if parsed.Worker == "" {
		parsed.Worker = worker
	}
	if parsed.Status == "" {
		parsed.Status = "unknown"
	}
	return &WorkerHeartbeat{
		Worker: parsed.Worker, Status: parsed.Status, TickCount: parsed.TickCount,
		TickStartedAt: parsed.TickStartedAt, LastSuccessAt: parsed.LastSuccessAt,
		LastResult: parsed.LastResult, LastError: parsed.LastError,
	}
}

// IsStale is a direct port of HeartbeatState.is_stale (see that
// docstring for the exact two conditions). nil (no heartbeat file at
// all/unreadable) is always stale, matching Python's "unknown" case.
func (hb *WorkerHeartbeat) IsStale(intervalSeconds float64, now time.Time) bool {
	if hb == nil || hb.Status == "unknown" {
		return true
	}
	nowUnix := float64(now.Unix())
	grace := defaultStallGraceSeconds
	if g := 3 * intervalSeconds; g > grace {
		grace = g
	}
	if hb.Status == "running" && hb.TickStartedAt != nil {
		if nowUnix-*hb.TickStartedAt > grace {
			return true
		}
	}
	if hb.LastSuccessAt == nil {
		return hb.TickStartedAt != nil && nowUnix-*hb.TickStartedAt > grace
	}
	return nowUnix-*hb.LastSuccessAt > grace
}

// sanitizedError truncates an upstream error string for safe display --
// see maxSanitizedErrorLen's own comment.
func sanitizedError(s *string) string {
	if s == nil {
		return ""
	}
	v := *s
	if len(v) > maxSanitizedErrorLen {
		v = v[:maxSanitizedErrorLen] + "…"
	}
	return v
}

// AnalyticsHealth is the one shape both the Dashboard's per-widget
// degraded banners and the System Status page's Analytics component
// consume -- see this file's own doc comment for what each field is
// evidence of and why.
type AnalyticsHealth struct {
	// Status is "ok", "degraded", or "failed" -- see Reader.Health's own
	// doc comment for exactly what separates the three.
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`

	DBReachable             bool `json:"db_reachable"`
	ConsecutiveReadFailures int  `json:"consecutive_read_failures"`

	// CorruptRetryCount is a cumulative, process-lifetime diagnostic
	// counter (see Reader.run's doc comment): how many times a query hit
	// the proven-transient SQLITE_CORRUPT-class read and was retried
	// once after a connection reset. Non-zero is worth an operator's
	// attention even when every individual retry succeeded and no
	// request ever surfaced an error -- "retried but recovered" must
	// still be visible, never silently absorbed.
	CorruptRetryCount int64 `json:"corrupt_retry_count"`

	WriterConfigured    bool     `json:"writer_heartbeat_configured"`
	WriterStatus        string   `json:"writer_status,omitempty"`
	WriterStale         bool     `json:"writer_stale"`
	WriterTickCount     int64    `json:"writer_tick_count,omitempty"`
	WriterLastSuccessAt *float64 `json:"writer_last_success_at,omitempty"`
	WriterLastError     string   `json:"writer_last_error,omitempty"`

	QueueDepth          int    `json:"queue_depth"`
	QueueDepthAvailable bool   `json:"queue_depth_available"`
	LastCommittedBucket *int64 `json:"last_committed_bucket,omitempty"`
}

// Health is the single real-liveness probe both the Dashboard and
// System Status pages call. Three-tier result, deliberately never
// collapsed to a bool:
//
//   - "failed": the aggregates.db file itself is not reachable at all
//     right now (this reader's own Ping failed) -- there is no data to
//     even show as possibly-stale.
//   - "degraded": the DB read succeeded (so whatever is displayed is at
//     least a real read of real committed rows) but the writer itself
//     is not currently trustworthy -- its heartbeat is stale, missing,
//     or its last tick recorded a real failure (the SQLITE_BUSY case
//     this whole file exists for). This is the exact "DNS fine, writer
//     dead, chart looks like real zero traffic" scenario: it must never
//     collapse to "ok" just because the file still opens.
//   - "ok": DB reachable and the writer's own heartbeat is fresh and
//     its last tick succeeded.
//
// Never returns a Go error: a health probe must always produce a
// rendered answer, including when the very thing it's reporting on is
// broken.
func (r *Reader) Health(ctx context.Context) AnalyticsHealth {
	h := AnalyticsHealth{CorruptRetryCount: r.CorruptRetries.Load()}

	if err := r.Ping(ctx); err != nil {
		n := r.consecutiveFailures.Add(1)
		h.DBReachable = false
		h.ConsecutiveReadFailures = int(n)
		h.Status = "failed"
		h.Reason = fmt.Sprintf("analytics store unreachable (%d consecutive failed reads): %s", n, sanitizeErrString(err))
		// Still report writer/queue facts below even though the DB read
		// itself failed -- an operator diagnosing "is it the file or the
		// writer" needs both independent signals in one place.
	} else {
		r.consecutiveFailures.Store(0)
		h.DBReachable = true
	}

	if r.WorkerHeartbeatsDir != "" {
		h.WriterConfigured = true
		hb := ReadHeartbeat(r.WorkerHeartbeatsDir, analyticsWorkerName)
		h.WriterStale = hb.IsStale(analyticsWorkerIntervalSeconds, time.Now())
		if hb != nil {
			h.WriterStatus = hb.Status
			h.WriterTickCount = hb.TickCount
			h.WriterLastSuccessAt = hb.LastSuccessAt
			h.WriterLastError = sanitizedError(hb.LastError)
		} else {
			h.WriterStatus = "unknown"
		}
	}

	if r.InboxDir != "" {
		if n, err := countRegularFiles(r.InboxDir); err == nil {
			h.QueueDepthAvailable = true
			h.QueueDepth = n
		}
	}

	if h.DBReachable {
		var last int64
		var hasRow bool
		// Routed through run() like every other query in this package --
		// touching r.db directly here would both skip the transient-
		// corrupt retry and race against reset()'s connection swap (see
		// reader.go's mu doc comment).
		_ = r.run(ctx, func(db *sql.DB) error {
			var nullable *int64
			if err := db.QueryRowContext(ctx, `SELECT MAX(bucket_start) FROM live_buckets`).Scan(&nullable); err != nil {
				return err
			}
			if nullable != nil {
				last, hasRow = *nullable, true
			}
			return nil
		})
		if hasRow {
			h.LastCommittedBucket = &last
		}
	}

	if h.Status == "failed" {
		return h
	}

	switch {
	case h.WriterConfigured && (h.WriterStale || h.WriterStatus == "tick_failed"):
		h.Status = "degraded"
		reason := "analytics writer heartbeat is stale or its last tick failed"
		if h.WriterLastError != "" {
			reason = fmt.Sprintf("%s (last error: %s)", reason, h.WriterLastError)
		}
		h.Reason = reason + " -- DNS is unaffected, but displayed analytics may be stale or incomplete, not confirmed zero traffic"
	default:
		h.Status = "ok"
	}
	return h
}

func sanitizeErrString(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > maxSanitizedErrorLen {
		s = s[:maxSanitizedErrorLen] + "…"
	}
	return s
}

// countRegularFiles counts plain files directly inside dir (not
// recursive -- the inbox is a flat directory of batch files) -- used
// for queue depth. A missing directory is a real error (distinct from
// "genuinely empty"), which the caller treats as "queue depth
// unavailable" rather than reporting a false zero.
func countRegularFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.Type().IsRegular() {
			n++
		}
	}
	return n, nil
}
