package pyanalytics

import (
	"context"
	"database/sql"
	"path/filepath"
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
