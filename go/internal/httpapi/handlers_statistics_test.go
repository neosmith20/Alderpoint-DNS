package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dnsanalytics"
)

func TestHandleStatisticsClearRequiresConfirmation(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodPost, "/api/statistics/clear", strings.NewReader(`{"confirmation":"nope"}`))
	w := httptest.NewRecorder()
	s.handleStatisticsClear(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "confirmation_required" {
		t.Errorf("error = %v, want confirmation_required", body["error"])
	}
}

func TestHandleStatisticsClearReportsUnavailableWithNoAnalyticsReader(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodPost, "/api/statistics/clear", strings.NewReader(`{"confirmation":"CLEAR"}`))
	w := httptest.NewRecorder()
	s.handleStatisticsClear(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

// TestHandleStatisticsClearRealEndToEnd proves the full real path (as of
// 2026-08-28: HTTP request -> httpapi handler -> a real SQLite DELETE
// against this process's own analytics.db, no hostagent round-trip
// needed any more -- see internal/dnsanalytics.Reader.ClearAll's own
// doc comment for why the old Python-era privilege boundary this used
// to route through no longer applies).
func TestHandleStatisticsClearRealEndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "analytics.db")
	db, err := dnsanalytics.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO query_events (ts, domain, qtype, rcode, protocol, client, latency_ms, outcome) VALUES
		(?, 'example.com', 'A', 'NOERROR', 'udp', '192.0.2.1', 1.2, 'allowed'),
		(?, 'ads.example.com', 'A', 'NOERROR', 'udp', '192.0.2.1', 1.2, 'blocked')`, now, now); err != nil {
		t.Fatal(err)
	}

	s := &Server{Analytics: &dnsanalytics.Reader{DB: db}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodPost, "/api/statistics/clear", strings.NewReader(`{"confirmation":"CLEAR"}`))
	w := httptest.NewRecorder()
	s.handleStatisticsClear(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "cleared" {
		t.Errorf("status field = %v, want cleared", body["status"])
	}
	if body["query_events_cleared"] != float64(2) {
		t.Errorf("query_events_cleared = %v, want 2", body["query_events_cleared"])
	}

	// Real proof the rows are actually gone, not just in the reported count.
	var remaining int
	if err := db.QueryRow("SELECT COUNT(*) FROM query_events").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Errorf("query_events still has %d rows after clear", remaining)
	}
}
