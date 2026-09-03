package updatehistory

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"alderpointdns/go-controlplane/internal/dbmigrate"

	_ "modernc.org/sqlite"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Service{DB: db}
}

func TestRecordAndListRoundTrip(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	s.Record(ctx, RecordInput{FromVersion: "1.0.0", ToVersion: "1.1.0", Source: "manual", Result: "success", BackupRef: "backup-1.apdnsbak"})
	s.Record(ctx, RecordInput{FromVersion: "1.1.0", ToVersion: "1.2.0", Source: "channel", Result: "failed", Error: "health check timed out"})

	entries, err := s.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// Most recent first.
	if entries[0].ToVersion != "1.2.0" || entries[0].Result != "failed" || entries[0].Error == "" {
		t.Fatalf("expected the most recent (failed) entry first with its error, got %+v", entries[0])
	}
	if entries[1].ToVersion != "1.1.0" || entries[1].Result != "success" || entries[1].BackupRef == "" {
		t.Fatalf("expected the earlier (successful) entry second with its backup ref, got %+v", entries[1])
	}
}

func TestNilServiceRecordIsSafe(t *testing.T) {
	var s *Service
	s.Record(context.Background(), RecordInput{FromVersion: "1.0.0", ToVersion: "1.1.0"})
}
