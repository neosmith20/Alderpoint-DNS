package hostagentd

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/analyticssnapshot"
)

func newSourceFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aggregates.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO schema_meta VALUES ('version','1');`); err != nil {
		t.Fatal(err)
	}
	return path
}

func newSnapshotTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// TestAnalyticsSnapshotOpsPublishAndReportStatus is the real end-to-end
// proof of this file's own job: registering the ops starts a real
// periodic publisher (internal/analyticssnapshot.Refresh against a real
// source db), analytics_snapshot.status reports it accurately, and
// analytics_snapshot.refresh can force one on demand.
func TestAnalyticsSnapshotOpsPublishAndReportStatus(t *testing.T) {
	source := newSourceFixture(t)
	dir := t.TempDir()
	s := newSnapshotTestServer(t)

	stop := RegisterAnalyticsSnapshotOps(s, AnalyticsSnapshotConfig{
		SourcePath:   source,
		PublishedDir: filepath.Join(dir, "published"),
		StagingDir:   filepath.Join(dir, "staging"),
		Interval:     50 * time.Millisecond,
		Retain:       3,
	})
	defer stop()

	// The startup refresh (see RegisterAnalyticsSnapshotOps's own doc
	// comment: "publish one generation immediately") should complete
	// almost immediately -- poll briefly rather than sleeping a fixed
	// guess.
	deadline := time.Now().Add(2 * time.Second)
	var status AnalyticsSnapshotStatus
	for time.Now().Before(deadline) {
		result, err := s.handlers["analytics_snapshot.status"](context.Background(), nil)
		if err != nil {
			t.Fatalf("analytics_snapshot.status: %v", err)
		}
		status = result.(AnalyticsSnapshotStatus)
		if status.LastRefreshOK {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !status.Configured {
		t.Fatal("expected Configured=true")
	}
	if !status.LastRefreshOK {
		t.Fatalf("expected the startup refresh to succeed within 2s, got %+v", status)
	}
	if status.LastGeneration == 0 {
		t.Fatal("expected a non-zero generation number")
	}

	resolved, err := analyticssnapshot.ResolveCurrent(filepath.Join(dir, "published"))
	if err != nil {
		t.Fatalf("ResolveCurrent against the real published dir: %v", err)
	}
	if resolved.Manifest.Generation != status.LastGeneration {
		t.Fatalf("status generation %d != resolved generation %d", status.LastGeneration, resolved.Manifest.Generation)
	}

	// Force a second refresh via the op directly (not the ticker) --
	// proves analytics_snapshot.refresh works standalone.
	before := status.RefreshCount
	result, err := s.handlers["analytics_snapshot.refresh"](context.Background(), nil)
	if err != nil {
		t.Fatalf("analytics_snapshot.refresh: %v", err)
	}
	after := result.(AnalyticsSnapshotStatus)
	if after.RefreshCount <= before {
		t.Fatalf("expected RefreshCount to increase (was %d, now %d)", before, after.RefreshCount)
	}
	if after.LastGeneration <= status.LastGeneration {
		t.Fatalf("expected a newer generation after a forced refresh (was %d, now %d)", status.LastGeneration, after.LastGeneration)
	}
}

// TestAnalyticsSnapshotOpsSurviveARefreshFailureWithoutCrashing proves a
// broken/removed source doesn't take the daemon down -- matches "DNS
// works if analytics is dead" applying to apdns-hostagent itself too.
func TestAnalyticsSnapshotOpsSurviveARefreshFailureWithoutCrashing(t *testing.T) {
	dir := t.TempDir()
	s := newSnapshotTestServer(t)

	stop := RegisterAnalyticsSnapshotOps(s, AnalyticsSnapshotConfig{
		SourcePath:   filepath.Join(dir, "does-not-exist.db"),
		PublishedDir: filepath.Join(dir, "published"),
		StagingDir:   filepath.Join(dir, "staging"),
		Interval:     50 * time.Millisecond,
		Retain:       3,
	})
	defer stop()

	time.Sleep(150 * time.Millisecond) // outlive a couple of failed tick attempts

	result, err := s.handlers["analytics_snapshot.status"](context.Background(), nil)
	if err != nil {
		t.Fatalf("analytics_snapshot.status itself must never error: %v", err)
	}
	status := result.(AnalyticsSnapshotStatus)
	if status.LastRefreshOK {
		t.Fatal("expected LastRefreshOK=false against a nonexistent source")
	}
	if status.LastError == "" {
		t.Fatal("expected a non-empty LastError")
	}
	if status.FailureCount == 0 {
		t.Fatal("expected FailureCount > 0")
	}
}
