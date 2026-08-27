package hostagentd

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// newTestAggregatesDB creates a throwaway aggregates.db with the exact
// two real tables Python's own aggregate store uses (time_buckets,
// dimension_counts -- read directly from app/v2/aggregates_db.py's
// schema, not guessed), seeded with real rows so a clear that finds
// nothing wouldn't accidentally pass.
func newTestAggregatesDB(t *testing.T, buckets, dims int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aggregates.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`
		CREATE TABLE time_buckets (bucket_start INTEGER PRIMARY KEY, total_queries INTEGER NOT NULL, blocked_queries INTEGER NOT NULL);
		CREATE TABLE dimension_counts (bucket_start INTEGER NOT NULL, dimension TEXT NOT NULL, value TEXT NOT NULL, count INTEGER NOT NULL);
	`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < buckets; i++ {
		if _, err := db.Exec("INSERT INTO time_buckets (bucket_start, total_queries, blocked_queries) VALUES (?, ?, ?)", i*60, i+1, i); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < dims; i++ {
		if _, err := db.Exec("INSERT INTO dimension_counts (bucket_start, dimension, value, count) VALUES (?, 'domain', ?, 1)", i*60, "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestClearAnalyticsAggregatesOnly(t *testing.T) {
	dbPath := newTestAggregatesDB(t, 5, 12)
	result, err := clearAnalytics(context.Background(), AnalyticsClearConfig{AggregatesDBPath: dbPath}, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.AggregateBucketsCleared != 5 || result.AggregateDimensionRowsCleared != 12 {
		t.Errorf("counts = %+v, want 5/12", result)
	}
	if result.RawHistoryCleared {
		t.Error("raw_history_cleared should be false when not requested")
	}

	// The real proof: the rows are actually gone, not just counted.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var remainingBuckets, remainingDims int
	db.QueryRow("SELECT COUNT(*) FROM time_buckets").Scan(&remainingBuckets)
	db.QueryRow("SELECT COUNT(*) FROM dimension_counts").Scan(&remainingDims)
	if remainingBuckets != 0 || remainingDims != 0 {
		t.Errorf("rows remain after clear: buckets=%d dims=%d", remainingBuckets, remainingDims)
	}
}

func TestClearAnalyticsIncludesRawHistoryWhenRequested(t *testing.T) {
	dbPath := newTestAggregatesDB(t, 1, 1)
	rawRoot := t.TempDir()
	// Real Parquet-shaped partition layout (YYYY/MM/DD/HH-*.parquet),
	// content irrelevant -- this proves file removal, not Parquet
	// parsing.
	dayDir := filepath.Join(rawRoot, "2026", "08", "27")
	if err := os.MkdirAll(dayDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f1 := filepath.Join(dayDir, "00-abc.parquet")
	f2 := filepath.Join(dayDir, "01-def.parquet")
	if err := os.WriteFile(f1, []byte("not a real parquet file, contents irrelevant"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("not a real parquet file, contents irrelevant"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-parquet file in the same tree must survive untouched.
	other := filepath.Join(dayDir, "manifest.json")
	if err := os.WriteFile(other, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := clearAnalytics(context.Background(), AnalyticsClearConfig{AggregatesDBPath: dbPath, RawHistoryRoot: rawRoot}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.RawHistoryCleared {
		t.Error("raw_history_cleared should be true when requested")
	}
	if result.RawPartitionFilesRemoved != 2 {
		t.Errorf("raw_partition_files_removed = %d, want 2", result.RawPartitionFilesRemoved)
	}
	if _, err := os.Stat(f1); !os.IsNotExist(err) {
		t.Error("f1 should have been removed")
	}
	if _, err := os.Stat(f2); !os.IsNotExist(err) {
		t.Error("f2 should have been removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("non-parquet file should have survived the clear")
	}
}

func TestClearAnalyticsMissingAggregatesDBIsNotAnError(t *testing.T) {
	// A fresh appliance with no traffic yet has no aggregates.db at all
	// -- matches Python's own os.path.exists guard, not an error.
	result, err := clearAnalytics(context.Background(), AnalyticsClearConfig{AggregatesDBPath: filepath.Join(t.TempDir(), "does-not-exist.db")}, false)
	if err != nil {
		t.Fatalf("missing aggregates db should not error, got: %v", err)
	}
	if result.AggregateBucketsCleared != 0 || result.AggregateDimensionRowsCleared != 0 {
		t.Errorf("expected zero counts for a missing db, got %+v", result)
	}
}

func TestClearAnalyticsOpRefusesWhenUnconfigured(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterAnalyticsClearOps(s, AnalyticsClearConfig{})
	res, err := s.handlers["analytics.clear"](context.Background(), nil)
	if err == nil {
		t.Fatal("expected an error for an unconfigured agent, got nil")
	}
	if res != nil {
		t.Errorf("expected no result on error, got %v", res)
	}
}

func TestClearAnalyticsOpRealDeleteThroughRegisteredHandler(t *testing.T) {
	dbPath := newTestAggregatesDB(t, 3, 7)
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterAnalyticsClearOps(s, AnalyticsClearConfig{AggregatesDBPath: dbPath})
	res, err := s.handlers["analytics.clear"](context.Background(), json.RawMessage(`{"include_raw_history":false}`))
	if err != nil {
		t.Fatal(err)
	}
	result, ok := res.(AnalyticsClearResult)
	if !ok {
		t.Fatalf("unexpected result type %T", res)
	}
	if result.AggregateBucketsCleared != 3 || result.AggregateDimensionRowsCleared != 7 {
		t.Errorf("counts = %+v, want 3/7", result)
	}
}
