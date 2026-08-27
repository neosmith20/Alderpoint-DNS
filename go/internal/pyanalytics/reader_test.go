package pyanalytics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// newTestReader creates a throwaway sqlite db with the exact schema
// Python's app/v2/aggregates_db.py creates (verified directly against a
// running preview's real aggregates.db, not guessed from source alone)
// and seeds it, so this test breaks the moment either schema drifts.
func newTestReader(t *testing.T) *Reader {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aggregates.db")
	setup, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setup.Close() })
	_, err = setup.Exec(`
		CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO schema_meta VALUES ('version', '1');
		CREATE TABLE time_buckets (
			bucket_start INTEGER NOT NULL, granularity TEXT NOT NULL,
			total_queries INTEGER NOT NULL DEFAULT 0, blocked_queries INTEGER NOT NULL DEFAULT 0,
			cache_hits INTEGER NOT NULL DEFAULT 0, cache_misses INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (bucket_start, granularity)
		);
		CREATE TABLE dimension_counts (
			bucket_start INTEGER NOT NULL, granularity TEXT NOT NULL, dimension TEXT NOT NULL,
			value TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (bucket_start, granularity, dimension, value)
		);
		CREATE TABLE live_buckets (
			bucket_start INTEGER PRIMARY KEY, total_queries INTEGER NOT NULL DEFAULT 0,
			blocked_queries INTEGER NOT NULL DEFAULT 0, cache_hits INTEGER NOT NULL DEFAULT 0,
			cache_misses INTEGER NOT NULL DEFAULT 0, updated_at REAL NOT NULL
		);
		INSERT INTO time_buckets VALUES (60, 'minute', 10, 2, 3, 7);
		INSERT INTO time_buckets VALUES (120, 'minute', 20, 4, 6, 14);
		-- bucket 180 deliberately absent -- proves FillGaps zero-fills it
		INSERT INTO dimension_counts VALUES (60, 'minute', 'domain', 'a.example.', 7);
		INSERT INTO dimension_counts VALUES (60, 'minute', 'domain', 'b.example.', 3);
		INSERT INTO dimension_counts VALUES (120, 'minute', 'domain', 'a.example.', 5);
		INSERT INTO live_buckets VALUES (1000, 3, 1, 1, 2, 1000.5);
		INSERT INTO live_buckets VALUES (1002, 1, 0, 1, 0, 1002.1);
	`)
	if err != nil {
		t.Fatal(err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestExportAllReturnsEveryRowOfBothTables(t *testing.T) {
	r := newTestReader(t)
	buckets, dims, err := r.ExportAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 2 {
		t.Fatalf("expected 2 time_buckets rows, got %d: %+v", len(buckets), buckets)
	}
	if len(dims) != 3 {
		t.Fatalf("expected 3 dimension_counts rows, got %d: %+v", len(dims), dims)
	}
	// Spot-check real column values came through, not just row counts.
	found := false
	for _, b := range buckets {
		if b["bucket_start"] == int64(60) && b["total_queries"] == int64(10) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected to find the bucket_start=60 row with total_queries=10, got %+v", buckets)
	}
}

func TestPingSucceedsAgainstARealSchema(t *testing.T) {
	r := newTestReader(t)
	if err := r.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestTimeSeriesAndFillGapsZeroFillsAMissingBucket(t *testing.T) {
	r := newTestReader(t)
	rows, err := r.TimeSeries(context.Background(), 60, 240, "minute")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 real rows before filling, got %d", len(rows))
	}
	filled := FillGaps(rows, 60, 180, "minute")
	if len(filled) != 3 {
		t.Fatalf("expected 3 buckets (60,120,180) after filling, got %d", len(filled))
	}
	if filled[2].BucketStart != 180 || filled[2].TotalQueries != 0 {
		t.Fatalf("expected bucket 180 to be zero-filled, got %+v", filled[2])
	}
	if filled[0].TotalQueries != 10 || filled[1].TotalQueries != 20 {
		t.Fatalf("real buckets should be unchanged: %+v", filled)
	}
}

func TestTopDimensionSumsAcrossBucketsNotJustOne(t *testing.T) {
	r := newTestReader(t)
	rows, err := r.TopDimension(context.Background(), "domain", 0, 300, "minute", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 distinct domains, got %d: %+v", len(rows), rows)
	}
	// a.example. appears in both buckets (7+5=12), b.example. only once (3).
	if rows[0].Value != "a.example." || rows[0].Count != 12 {
		t.Fatalf("expected a.example. summed to 12 first, got %+v", rows[0])
	}
	if rows[1].Value != "b.example." || rows[1].Count != 3 {
		t.Fatalf("expected b.example. at 3, got %+v", rows[1])
	}
}

func TestLiveAndFillLiveGapsZeroFillsEverySecond(t *testing.T) {
	r := newTestReader(t)
	rows, err := r.Live(context.Background(), 1000, 1002)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 real rows (1000, 1002), got %d", len(rows))
	}
	filled := FillLiveGaps(rows, 1000, 1002)
	if len(filled) != 3 {
		t.Fatalf("expected 3 seconds (1000,1001,1002), got %d", len(filled))
	}
	if filled[1].BucketStart != 1001 || filled[1].TotalQueries != 0 {
		t.Fatalf("expected second 1001 to be zero-filled, got %+v", filled[1])
	}
}

// TestGenuinelyCorruptFileStaysDegradedNeverMasked is the owner-required
// proof that this reader's transient-corrupt retry (see reader.go's
// run/isTransientCorrupt/reset) never turns real, permanent corruption
// into a false "ok" -- a file that is corrupt on every single attempt
// (not just the first, mid-write one) must still surface as an error
// after the one retry, not a silently-empty success.
func TestGenuinelyCorruptFileStaysDegradedNeverMasked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aggregates.db")
	// A real SQLite file (valid header, magic bytes) whose page content
	// past the header is truncated/garbage -- genuinely, permanently
	// corrupt, not a timing artifact: every single read of it fails the
	// same way, no matter how many times or how the connection is
	// reopened.
	setup, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO schema_meta VALUES ('version','1');`); err != nil {
		t.Fatal(err)
	}
	setup.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 4096 {
		t.Fatalf("fixture too small to meaningfully corrupt: %d bytes", len(raw))
	}
	// Smash the rest of page 1 (past the 100-byte file header) --
	// corrupts sqlite_master's own real b-tree page structure without
	// touching the leading magic-string bytes SQLite checks first,
	// matching the real "database disk image is malformed" failure mode
	// (verified directly with the real sqlite3 CLI + PRAGMA
	// integrity_check against this exact byte range before writing this
	// test) rather than an unrelated "not a database" error.
	for i := 150; i < 4096 && i < len(raw); i++ {
		raw[i] = 0xFF
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	err = r.Ping(context.Background())
	if err == nil {
		t.Fatal("expected Ping against a genuinely corrupt file to fail even after the one automatic retry -- got nil error (would render as a false 'ok')")
	}
	t.Logf("genuinely corrupt file correctly still failed after retry: %v", err)

	h := r.Health(context.Background())
	if h.Status != "failed" {
		t.Fatalf("expected Health status %q for an unreachable/corrupt store, got %q (reason=%q) -- corruption must never be masked as ok/degraded-with-data", "failed", h.Status, h.Reason)
	}
	if !strings.Contains(h.Reason, "malformed") && !strings.Contains(h.Reason, "corrupt") {
		t.Fatalf("expected Health.Reason to mention the real underlying error, got %q", h.Reason)
	}
}

// TestTransientCorruptReadRecoversAfterOneRetry proves the other half:
// a query that fails ONCE with the transient SQLITE_CORRUPT-class error
// (simulated directly, not by racing a real writer, so this test is
// fast and deterministic) is retried exactly once against a reset
// connection and succeeds -- CorruptRetries records that it happened.
func TestTransientCorruptReadRecoversAfterOneRetry(t *testing.T) {
	r := newTestReader(t)
	simulated := 0
	err := r.run(context.Background(), func(db *sql.DB) error {
		simulated++
		if simulated == 1 {
			return fmt.Errorf("query: %s", "database disk image is malformed (11)")
		}
		return db.PingContext(context.Background())
	})
	if err != nil {
		t.Fatalf("expected the second attempt (after reset) to succeed, got: %v", err)
	}
	if simulated != 2 {
		t.Fatalf("expected exactly 2 attempts (1 fail + 1 retry), got %d", simulated)
	}
	if got := r.CorruptRetries.Load(); got != 1 {
		t.Fatalf("expected CorruptRetries=1 after one transient-corrupt retry, got %d", got)
	}

	h := r.Health(context.Background())
	if h.CorruptRetryCount != 1 {
		t.Fatalf("expected Health.CorruptRetryCount=1 (diagnostic visibility even when the retry itself succeeded), got %d", h.CorruptRetryCount)
	}
}

// TestNonCorruptErrorIsNeverRetried proves run() doesn't quietly become
// a general retry-everything policy -- an ordinary query error (not the
// proven transient-corrupt class) must be returned on the first attempt.
func TestNonCorruptErrorIsNeverRetried(t *testing.T) {
	r := newTestReader(t)
	attempts := 0
	wantErr := errors.New("boom: not a corruption error")
	err := r.run(context.Background(), func(db *sql.DB) error {
		attempts++
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the original non-corrupt error back unchanged, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected exactly 1 attempt for a non-corrupt error (no retry), got %d", attempts)
	}
	if r.CorruptRetries.Load() != 0 {
		t.Fatalf("expected CorruptRetries=0 for a non-corrupt error, got %d", r.CorruptRetries.Load())
	}
}

func TestAlignedBucketStartMatchesPythonSemantics(t *testing.T) {
	cases := []struct {
		ts          float64
		granularity string
		want        int64
	}{
		{125, "minute", 120},
		{3700, "hour", 3600},
		{90000, "day", 86400},
	}
	for _, c := range cases {
		if got := AlignedBucketStart(c.ts, c.granularity); got != c.want {
			t.Errorf("AlignedBucketStart(%v, %q) = %d, want %d", c.ts, c.granularity, got, c.want)
		}
	}
}
