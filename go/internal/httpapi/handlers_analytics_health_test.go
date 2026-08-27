package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/analyticssnapshot"
	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/pyanalytics"
)

// newAnalyticsFixtureReader creates a throwaway source aggregates.db
// with the exact schema pyanalytics.Reader expects (same shape as
// internal/pyanalytics/reader_test.go's own fixture), publishes it as a
// real snapshot generation (internal/analyticssnapshot -- the real
// mechanism apdns-hostagent uses live, see that package's doc comment),
// and opens a Reader against the published directory.
func newAnalyticsFixtureReader(t *testing.T) *pyanalytics.Reader {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "aggregates.db")
	setup, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = setup.Exec(`
		CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO schema_meta VALUES ('version', '1');
		CREATE TABLE time_buckets (bucket_start INTEGER, granularity TEXT, total_queries INTEGER, blocked_queries INTEGER, cache_hits INTEGER, cache_misses INTEGER);
		CREATE TABLE dimension_counts (bucket_start INTEGER, granularity TEXT, dimension TEXT, value TEXT, count INTEGER);
		CREATE TABLE live_buckets (bucket_start INTEGER PRIMARY KEY, total_queries INTEGER, blocked_queries INTEGER, cache_hits INTEGER, cache_misses INTEGER, updated_at REAL);
		INSERT INTO live_buckets VALUES (1000, 5, 1, 3, 2, 1000.0);
	`)
	if err != nil {
		t.Fatal(err)
	}
	setup.Close()

	published := filepath.Join(dir, "published")
	staging := filepath.Join(dir, "staging")
	if _, err := analyticssnapshot.Refresh(context.Background(), source, published, staging, 3); err != nil {
		t.Fatal(err)
	}

	r, err := pyanalytics.Open(published)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func newHealthTestServer(t *testing.T, analytics *pyanalytics.Reader) *Server {
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
	return &Server{
		DB:         db,
		Blocklists: &blocklists.Service{DB: db},
		LocalDNS:   &localdns.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()},
		Analytics:  analytics,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func writeTestHeartbeat(t *testing.T, dir string, status string, lastSuccessAt time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"worker": "analytics-worker", "status": status, "tick_count": 10,
		"tick_started_at": float64(lastSuccessAt.Unix()), "last_success_at": float64(lastSuccessAt.Unix()),
		"last_result": 0, "last_error": nil,
	})
	if err := os.WriteFile(filepath.Join(dir, "analytics-worker.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHandleHealthReportsAnalyticsComponentAsOkWithAFreshWriter(t *testing.T) {
	analytics := newAnalyticsFixtureReader(t)
	hbDir := t.TempDir()
	writeTestHeartbeat(t, hbDir, "ok", time.Now())
	analytics.WorkerHeartbeatsDir = hbDir
	s := newHealthTestServer(t, analytics)

	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest("GET", "/api/health", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	components := body["components"].(map[string]any)
	analyticsComponent := components["analytics"].(map[string]any)
	if analyticsComponent["status"] != "ok" {
		t.Fatalf("expected analytics component status ok, got %+v", analyticsComponent)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected overall status ok, got %+v", body)
	}
}

// TestHandleHealthDemotesOverallStatusOnADeadWriter is the HTTP-level
// proof of the governing task's exact acceptance rule: a stale/dead
// analytics writer must make /api/health (and therefore the System
// Status page) say "degraded", not silently "ok", even though nothing
// about DNS or the control_db component changed at all.
func TestHandleHealthDemotesOverallStatusOnADeadWriter(t *testing.T) {
	analytics := newAnalyticsFixtureReader(t)
	hbDir := t.TempDir()
	writeTestHeartbeat(t, hbDir, "ok", time.Now().Add(-1*time.Hour)) // long stale
	analytics.WorkerHeartbeatsDir = hbDir
	s := newHealthTestServer(t, analytics)

	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest("GET", "/api/health", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "degraded" {
		t.Fatalf("expected overall status degraded on a stale writer, got %+v", body)
	}
	components := body["components"].(map[string]any)
	analyticsComponent := components["analytics"].(map[string]any)
	if analyticsComponent["status"] != "degraded" {
		t.Fatalf("expected analytics component status degraded, got %+v", analyticsComponent)
	}
	if analyticsComponent["reason"] == "" || analyticsComponent["reason"] == nil {
		t.Fatal("expected an explicit, non-empty degraded reason")
	}
}

// TestHandleAnalyticsTimeseriesFlagsDegradedOnADeadWriterDespiteRealData
// proves the Dashboard-facing endpoint itself: a real, successful SQL
// read (real committed buckets, no Go error) must still come back
// degraded=true when the writer behind it is not trustworthy -- this is
// what stops a dead writer from rendering as convincing zero traffic.
func TestHandleAnalyticsTimeseriesFlagsDegradedOnADeadWriterDespiteRealData(t *testing.T) {
	analytics := newAnalyticsFixtureReader(t)
	hbDir := t.TempDir()
	writeTestHeartbeat(t, hbDir, "tick_failed", time.Now())
	analytics.WorkerHeartbeatsDir = hbDir
	s := newHealthTestServer(t, analytics)

	rec := httptest.NewRecorder()
	s.handleAnalyticsTimeseries(rec, httptest.NewRequest("GET", "/api/analytics/timeseries?granularity=minute&minutes=5", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if degraded, _ := body["degraded"].(bool); !degraded {
		t.Fatalf("expected degraded=true for a tick_failed writer even though the query succeeded, got %+v", body)
	}
	if reason, _ := body["degraded_reason"].(string); reason == "" {
		t.Fatal("expected a non-empty degraded_reason")
	}
}

func TestHandleAnalyticsTimeseriesIsNotDegradedWithAHealthyWriter(t *testing.T) {
	analytics := newAnalyticsFixtureReader(t)
	hbDir := t.TempDir()
	writeTestHeartbeat(t, hbDir, "ok", time.Now())
	analytics.WorkerHeartbeatsDir = hbDir
	s := newHealthTestServer(t, analytics)

	rec := httptest.NewRecorder()
	s.handleAnalyticsTimeseries(rec, httptest.NewRequest("GET", "/api/analytics/timeseries?granularity=minute&minutes=5", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if degraded, _ := body["degraded"].(bool); degraded {
		t.Fatalf("expected degraded=false with a healthy writer, got %+v", body)
	}
}

func TestHandleDashboardSummaryIncludesAnalyticsHealth(t *testing.T) {
	analytics := newAnalyticsFixtureReader(t)
	hbDir := t.TempDir()
	writeTestHeartbeat(t, hbDir, "ok", time.Now())
	analytics.WorkerHeartbeatsDir = hbDir
	s := newHealthTestServer(t, analytics)

	rec := httptest.NewRecorder()
	s.handleDashboardSummary(rec, httptest.NewRequest("GET", "/api/dashboard/summary", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["analytics_available"] != true {
		t.Fatalf("expected analytics_available=true with a healthy writer, got %+v", body)
	}
	if _, ok := body["analytics_health"].(map[string]any); !ok {
		t.Fatalf("expected an analytics_health object in the dashboard summary, got %+v", body)
	}
}
