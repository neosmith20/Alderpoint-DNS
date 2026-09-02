package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnsanalytics"
	"alderpointdns/go-controlplane/internal/observedretention"
)

func newObservedRetentionTestServer(t *testing.T) (*Server, *dnsanalytics.Reader) {
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
	analyticsDB, err := dnsanalytics.Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { analyticsDB.Close() })
	reader := &dnsanalytics.Reader{DB: analyticsDB}
	return &Server{
		ObservedRetention: &observedretention.Service{DB: db, Analytics: reader},
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, reader
}

func insertObservedQuery(t *testing.T, db *sql.DB, ts int64, client string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO query_events (ts, domain, qtype, rcode, protocol, client, latency_ms, outcome)
		VALUES (?, 'example.com', 'A', 'NOERROR', 'udp', ?, 1.5, 'allowed')`, ts, client)
	if err != nil {
		t.Fatal(err)
	}
}

func TestObservedRetentionSettingsGetReturnsSafeDefaults(t *testing.T) {
	s, _ := newObservedRetentionTestServer(t)
	code, body := doHandler(t, s.handleGetObservedRetentionSettings, "GET", "", nil)
	if code != 200 {
		t.Fatalf("code=%d body=%+v", code, body)
	}
	if body["schedule"] != "manual" {
		t.Errorf("expected schedule=manual by default, got %+v", body)
	}
	if body["retention_days"] != float64(90) {
		t.Errorf("expected retention_days=90 by default, got %+v", body)
	}
}

func TestObservedRetentionSettingsPutPersistsAndValidates(t *testing.T) {
	s, _ := newObservedRetentionTestServer(t)
	code, body := doHandler(t, s.handleSetObservedRetentionSettings, "PUT", `{"retention_days":30,"schedule":"weekly"}`, nil)
	if code != 200 {
		t.Fatalf("put: code=%d body=%+v", code, body)
	}
	if body["retention_days"] != float64(30) || body["schedule"] != "weekly" {
		t.Fatalf("put response did not reflect saved settings: %+v", body)
	}

	for _, tc := range []string{
		`{"retention_days":0,"schedule":"weekly"}`,
		`{"retention_days":30,"schedule":"hourly"}`,
	} {
		code, _ := doHandler(t, s.handleSetObservedRetentionSettings, "PUT", tc, nil)
		if code != 400 {
			t.Errorf("body=%s: expected 400, got %d", tc, code)
		}
	}
	// A rejected update must not have changed the real, previously-saved settings.
	code, body = doHandler(t, s.handleGetObservedRetentionSettings, "GET", "", nil)
	if code != 200 || body["retention_days"] != float64(30) || body["schedule"] != "weekly" {
		t.Fatalf("a rejected PUT changed the stored settings: %+v", body)
	}
}

func TestObservedRetentionPreviewDoesNotDeleteAnything(t *testing.T) {
	s, reader := newObservedRetentionTestServer(t)
	now := time.Now().Unix()
	insertObservedQuery(t, reader.DB, now-200*24*60*60, "10.0.0.1") // stale
	insertObservedQuery(t, reader.DB, now, "10.0.0.2")              // recent

	req := httptest.NewRequest("GET", "/?retention_days=90", nil)
	rec := httptest.NewRecorder()
	s.handlePreviewObservedRetention(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	body := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["would_remove_clients"] != float64(1) {
		t.Fatalf("expected would_remove_clients=1, got %+v", body)
	}
	var count int
	if err := reader.DB.QueryRow(`SELECT COUNT(*) FROM query_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("preview must never delete anything, expected 2 rows still present, got %d", count)
	}
}

func TestObservedRetentionCleanOnlyRemovesStaleClients(t *testing.T) {
	s, reader := newObservedRetentionTestServer(t)
	ctx := context.Background()
	now := time.Now().Unix()
	insertObservedQuery(t, reader.DB, now-200*24*60*60, "10.0.0.1") // stale
	insertObservedQuery(t, reader.DB, now, "10.0.0.2")              // recent
	if err := s.ObservedRetention.SetSettings(ctx, 90, "manual"); err != nil {
		t.Fatal(err)
	}

	code, body := doHandler(t, s.handleCleanObservedRetention, "POST", "", nil)
	if code != 200 {
		t.Fatalf("code=%d body=%+v", code, body)
	}
	if body["removed_clients"] != float64(1) {
		t.Fatalf("expected removed_clients=1, got %+v", body)
	}

	var staleCount, recentCount int
	reader.DB.QueryRow(`SELECT COUNT(*) FROM query_events WHERE client=?`, "10.0.0.1").Scan(&staleCount)
	reader.DB.QueryRow(`SELECT COUNT(*) FROM query_events WHERE client=?`, "10.0.0.2").Scan(&recentCount)
	if staleCount != 0 {
		t.Errorf("expected the stale client's rows gone, found %d", staleCount)
	}
	if recentCount != 1 {
		t.Errorf("expected the recently-seen client's row untouched, found %d, want 1", recentCount)
	}
}

func TestObservedRetentionHandlersUnavailableWithoutAnalytics(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	code, _ := doHandler(t, s.handleGetObservedRetentionSettings, "GET", "", nil)
	if code != 503 {
		t.Errorf("GET settings: expected 503 without ObservedRetention wired, got %d", code)
	}
	code, _ = doHandler(t, s.handleCleanObservedRetention, "POST", "", nil)
	if code != 503 {
		t.Errorf("POST clean: expected 503 without ObservedRetention wired, got %d", code)
	}
}
