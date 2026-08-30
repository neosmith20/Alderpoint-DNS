package dnsanalytics

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestPruneWriter(t *testing.T) (*Writer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "analytics.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &Writer{DB: db, DBPath: path}, path
}

func insertTestRow(t *testing.T, wtr *Writer, ts int64, domain string) {
	t.Helper()
	_, err := wtr.DB.Exec(`INSERT INTO query_events (ts, domain, qtype, rcode, protocol, client, latency_ms, outcome)
		VALUES (?, ?, 'A', 'NOERROR', 'udp', '203.0.113.9', 1.0, 'allowed')`, ts, domain)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
}

func countRows(t *testing.T, wtr *Writer) int {
	t.Helper()
	var n int
	if err := wtr.DB.QueryRow(`SELECT count(*) FROM query_events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPruneOldHonorsConfiguredRetentionWhenStricterThanCeiling(t *testing.T) {
	wtr, _ := newTestPruneWriter(t)
	now := time.Now().Unix()
	insertTestRow(t, wtr, now-2*86400, "old.example.com.")  // 2 days old
	insertTestRow(t, wtr, now-10*86400, "older.example.com.") // 10 days old
	wtr.Settings = NewSettingsHolder(Settings{DetailedRetentionDays: 5}) // stricter than the 35-day ceiling

	wtr.pruneOld(context.Background())

	if got := countRows(t, wtr); got != 1 {
		t.Fatalf("expected only the 2-day-old row to survive a 5-day configured retention, got %d rows", got)
	}
}

func TestPruneOldNeverExceedsHardCeilingRegardlessOfConfiguredRetention(t *testing.T) {
	wtr, _ := newTestPruneWriter(t)
	now := time.Now().Unix()
	insertTestRow(t, wtr, now-10*86400, "within-ceiling.example.com.") // 10 days old
	// A misconfigured huge retention must never let rows outlive the
	// package's own 35-day safety ceiling.
	wtr.Settings = NewSettingsHolder(Settings{DetailedRetentionDays: 9999})

	wtr.pruneOld(context.Background())

	if got := countRows(t, wtr); got != 1 {
		t.Fatalf("expected the 10-day-old row to survive (well within the 35-day ceiling), got %d rows", got)
	}
}

func TestPruneOldZeroRetentionDeletesEverythingNotFromThisInstant(t *testing.T) {
	wtr, _ := newTestPruneWriter(t)
	now := time.Now().Unix()
	insertTestRow(t, wtr, now-3600, "an-hour-ago.example.com.")
	wtr.Settings = NewSettingsHolder(Settings{DetailedRetentionDays: 0})

	wtr.pruneOld(context.Background())

	if got := countRows(t, wtr); got != 0 {
		t.Fatalf("expected detailed_retention_days=0 to prune everything not from this exact instant (matching V1.1.1's own semantics), got %d rows", got)
	}
}

func TestEnforceSizeLimitPrunesOldestQuarterOnBreach(t *testing.T) {
	wtr, _ := newTestPruneWriter(t)
	now := time.Now().Unix()
	for i := 0; i < 8; i++ {
		insertTestRow(t, wtr, now-int64(8-i), "example.com.")
	}
	// An impossibly tiny limit -- guaranteed to be "over" regardless of
	// the real on-disk file size, so this test exercises the prune path
	// deterministically rather than depending on actual SQLite file
	// sizing behavior.
	wtr.Settings = NewSettingsHolder(Settings{DBSizeLimitBytes: 1})

	wtr.enforceSizeLimit(context.Background())

	got := countRows(t, wtr)
	if got != 6 {
		t.Fatalf("expected the oldest 8/4=2 rows pruned (6 remaining), got %d rows", got)
	}
}

func TestEnforceSizeLimitNoopWhenUnderLimit(t *testing.T) {
	wtr, _ := newTestPruneWriter(t)
	insertTestRow(t, wtr, time.Now().Unix(), "example.com.")
	wtr.Settings = NewSettingsHolder(Settings{DBSizeLimitBytes: 1 << 40}) // 1 TiB, nowhere close

	wtr.enforceSizeLimit(context.Background())

	if got := countRows(t, wtr); got != 1 {
		t.Fatalf("expected no pruning while comfortably under the limit, got %d rows", got)
	}
}
