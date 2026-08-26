package rawquerylog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parquet-go/parquet-go"
)

// writeSegment writes one real (compressed, schema-matching) Parquet
// segment at root/YYYY/MM/DD/HH-<name>.parquet -- the exact layout
// app/v2/parquet_writer.py produces -- so these tests exercise the real
// partition-pruning and decoding path, not a mocked one.
func writeSegment(t *testing.T, root string, ts time.Time, name string, rows []Row) string {
	t.Helper()
	dir := filepath.Join(root, ts.Format("2006"), ts.Format("01"), ts.Format("02"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ts.Format("15")+"-"+name+".parquet")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	writer := parquet.NewGenericWriter[Row](f, parquet.Compression(&parquet.Zstd))
	if _, err := writer.Write(rows); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func strp(s string) *string   { return &s }
func f64p(f float64) *float64 { return &f }
func i64p(i int64) *int64     { return &i }
func boolp(b bool) *bool      { return &b }

func TestRecentQueryLogReadsRealSegmentAndFilters(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()

	writeSegment(t, root, now, "000001", []Row{
		{ID: i64p(1), TS: f64p(float64(now.Add(-30 * time.Second).Unix())), Domain: strp("blocked.example.com"), Client: strp("10.0.0.5"), QType: strp("A"), Protocol: strp("udp"), RCode: strp("NXDOMAIN"), Blocked: boolp(true), Upstream: strp("1.1.1.1"), CacheStatus: strp("miss"), LatencyMs: f64p(1.2)},
		{ID: i64p(2), TS: f64p(float64(now.Add(-20 * time.Second).Unix())), Domain: strp("allowed.example.com"), Client: strp("10.0.0.6"), QType: strp("AAAA"), Protocol: strp("udp"), RCode: strp("NOERROR"), Blocked: boolp(false), Upstream: strp("1.1.1.1"), CacheStatus: strp("hit"), LatencyMs: f64p(0.4)},
		{ID: i64p(3), TS: f64p(float64(now.Add(-10 * time.Second).Unix())), Domain: strp("allowed2.example.com"), Client: strp("10.0.0.5"), QType: strp("A"), Protocol: strp("tcp"), RCode: strp("NOERROR"), Blocked: boolp(false), Upstream: strp("8.8.8.8"), CacheStatus: strp("miss"), LatencyMs: f64p(3.0)},
	})

	r := &Reader{Root: root}
	ctx := context.Background()

	t.Run("returns rows most-recent-first within the window", func(t *testing.T) {
		result, err := r.RecentQueryLog(ctx, 5, Filters{}, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rows) != 3 {
			t.Fatalf("expected 3 rows, got %d: %+v", len(result.Rows), result.Rows)
		}
		if result.Rows[0].Domain != "allowed2.example.com" || result.Rows[2].Domain != "blocked.example.com" {
			t.Fatalf("expected most-recent-first ordering, got %+v", result.Rows)
		}
	})

	t.Run("blocked_only filter", func(t *testing.T) {
		result, err := r.RecentQueryLog(ctx, 5, Filters{BlockedOnly: true}, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rows) != 1 || result.Rows[0].Domain != "blocked.example.com" {
			t.Fatalf("expected exactly the blocked row, got %+v", result.Rows)
		}
	})

	t.Run("client exact-match filter", func(t *testing.T) {
		result, err := r.RecentQueryLog(ctx, 5, Filters{Client: "10.0.0.5"}, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rows) != 2 {
			t.Fatalf("expected 2 rows for client=10.0.0.5, got %d: %+v", len(result.Rows), result.Rows)
		}
	})

	t.Run("limit and offset", func(t *testing.T) {
		result, err := r.RecentQueryLog(ctx, 5, Filters{}, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rows) != 1 || result.Rows[0].Domain != "allowed.example.com" {
			t.Fatalf("expected the second-most-recent row via offset=1, got %+v", result.Rows)
		}
	})

	t.Run("rows outside the window are excluded", func(t *testing.T) {
		// minutes is clamped to a 1-minute floor (matching Python's own
		// `max(1.0, ...)`), so the exclusion case has to use rows old
		// enough to fall outside even that floor.
		oldRoot := t.TempDir()
		writeSegment(t, oldRoot, now.Add(-2*time.Hour), "000001", []Row{
			{ID: i64p(9), TS: f64p(float64(now.Add(-2 * time.Hour).Unix())), Domain: strp("old.example.com")},
		})
		oldR := &Reader{Root: oldRoot}
		result, err := oldR.RecentQueryLog(ctx, 1, Filters{}, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rows) != 0 {
			t.Fatalf("expected a 2-hour-old row to be excluded by a 1-minute window, got %+v", result.Rows)
		}
	})
}

func TestTopDomainsAggregatesRealCounts(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()

	writeSegment(t, root, now, "000001", []Row{
		{ID: i64p(1), TS: f64p(float64(now.Add(-10 * time.Second).Unix())), Domain: strp("ads.example.com"), Blocked: boolp(true)},
		{ID: i64p(2), TS: f64p(float64(now.Add(-9 * time.Second).Unix())), Domain: strp("ads.example.com"), Blocked: boolp(true)},
		{ID: i64p(3), TS: f64p(float64(now.Add(-8 * time.Second).Unix())), Domain: strp("ads.example.com"), Blocked: boolp(true)},
		{ID: i64p(4), TS: f64p(float64(now.Add(-7 * time.Second).Unix())), Domain: strp("tracker.example.com"), Blocked: boolp(true)},
		{ID: i64p(5), TS: f64p(float64(now.Add(-6 * time.Second).Unix())), Domain: strp("safe.example.com"), Blocked: boolp(false)},
		{ID: i64p(6), TS: f64p(float64(now.Add(-5 * time.Second).Unix())), Domain: strp("safe.example.com"), Blocked: boolp(false)},
	})

	r := &Reader{Root: root}
	ctx := context.Background()

	t.Run("all domains, highest count first", func(t *testing.T) {
		counts, _, err := r.TopDomains(ctx, 5, false, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(counts) != 3 {
			t.Fatalf("expected 3 distinct domains, got %+v", counts)
		}
		if counts[0].Domain != "ads.example.com" || counts[0].Count != 3 {
			t.Fatalf("expected ads.example.com=3 to lead, got %+v", counts)
		}
	})

	t.Run("blocked-only resolves the previously-disclosed Top Blocked Domains gap", func(t *testing.T) {
		counts, _, err := r.TopDomains(ctx, 5, true, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(counts) != 2 {
			t.Fatalf("expected 2 blocked domains (safe.example.com must be excluded), got %+v", counts)
		}
		for _, c := range counts {
			if c.Domain == "safe.example.com" {
				t.Fatalf("blocked_only=true must exclude a domain with zero blocked queries, got %+v", counts)
			}
		}
	})

	t.Run("limit truncates", func(t *testing.T) {
		counts, _, err := r.TopDomains(ctx, 5, false, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(counts) != 1 {
			t.Fatalf("expected exactly 1 row with limit=1, got %+v", counts)
		}
	})
}

func TestRecentQueryLogNeverReturnsNilRowsOnEmpty(t *testing.T) {
	r := &Reader{Root: t.TempDir()} // real dir, zero segments
	result, err := r.RecentQueryLog(context.Background(), 60, Filters{}, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rows == nil {
		t.Fatal("expected an empty slice, not nil (would JSON-marshal to null and break the frontend grid)")
	}
}

func TestRecentQueryLogOfMissingRootIsEmptyNotError(t *testing.T) {
	r := &Reader{Root: filepath.Join(t.TempDir(), "does-not-exist")}
	result, err := r.RecentQueryLog(context.Background(), 60, Filters{}, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 0 {
		t.Fatalf("expected 0 rows for a missing root, got %+v", result.Rows)
	}
}

func TestOneCorruptSegmentDoesNotBreakTheRestOfTheQuery(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()

	writeSegment(t, root, now, "000001", []Row{
		{ID: i64p(1), TS: f64p(float64(now.Add(-5 * time.Second).Unix())), Domain: strp("good.example.com")},
	})
	// A second, corrupt "segment" in the same hour partition -- not a
	// real Parquet file at all.
	dir := filepath.Join(root, now.Format("2006"), now.Format("01"), now.Format("02"))
	if err := os.WriteFile(filepath.Join(dir, now.Format("15")+"-corrupt.parquet"), []byte("not parquet"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &Reader{Root: root}
	result, err := r.RecentQueryLog(context.Background(), 5, Filters{}, 100, 0)
	if err != nil {
		t.Fatalf("a corrupt segment must not fail the whole query: %v", err)
	}
	if len(result.Rows) != 1 || result.Rows[0].Domain != "good.example.com" {
		t.Fatalf("expected the good segment's row despite the corrupt one, got %+v", result.Rows)
	}
}

func TestEnumeratePartitionFilesPrunesOutsideTheDateRange(t *testing.T) {
	root := t.TempDir()
	inRange := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	farPast := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	farFuture := time.Date(2027, 1, 1, 10, 0, 0, 0, time.UTC)

	writeSegment(t, root, inRange, "000001", []Row{{ID: i64p(1), TS: f64p(float64(inRange.Unix()))}})
	writeSegment(t, root, farPast, "000001", []Row{{ID: i64p(2), TS: f64p(float64(farPast.Unix()))}})
	writeSegment(t, root, farFuture, "000001", []Row{{ID: i64p(3), TS: f64p(float64(farFuture.Unix()))}})

	start := float64(inRange.Add(-time.Hour).Unix())
	end := float64(inRange.Add(time.Hour).Unix())
	files, err := enumeratePartitionFiles(root, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected exactly 1 file (the in-range one), got %d: %v", len(files), files)
	}
}
