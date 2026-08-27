package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
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

func TestHandleStatisticsClearReportsUnavailableWithNoHostAgent(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodPost, "/api/statistics/clear", strings.NewReader(`{"confirmation":"CLEAR"}`))
	w := httptest.NewRecorder()
	s.handleStatisticsClear(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

// TestHandleStatisticsClearRealEndToEnd proves the full real path: HTTP
// request -> httpapi handler -> real unix-socket hostagent client ->
// real hostagentd.Server -> a real SQLite DELETE against a real
// aggregates.db file -- not a mock at any layer.
func TestHandleStatisticsClearRealEndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "aggregates.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE time_buckets (bucket_start INTEGER PRIMARY KEY, total_queries INTEGER NOT NULL, blocked_queries INTEGER NOT NULL);
		CREATE TABLE dimension_counts (bucket_start INTEGER NOT NULL, dimension TEXT NOT NULL, value TEXT NOT NULL, count INTEGER NOT NULL);
		INSERT INTO time_buckets VALUES (0, 5, 1), (60, 3, 0);
		INSERT INTO dimension_counts VALUES (0, 'domain', 'example.com', 5);
	`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	agent := &hostagentd.Server{SocketPath: sockPath, AllowedUID: uint32(os.Getuid()), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	hostagentd.RegisterAnalyticsClearOps(agent, hostagentd.AnalyticsClearConfig{AggregatesDBPath: dbPath})
	agentCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go agent.Serve(agentCtx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	s := &Server{HostAgent: hostagent.NewClient(sockPath), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodPost, "/api/statistics/clear", strings.NewReader(`{"confirmation":"CLEAR","include_raw_history":false}`))
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
	if body["aggregate_buckets_cleared"] != float64(2) {
		t.Errorf("aggregate_buckets_cleared = %v, want 2", body["aggregate_buckets_cleared"])
	}
	if body["aggregate_dimension_rows_cleared"] != float64(1) {
		t.Errorf("aggregate_dimension_rows_cleared = %v, want 1", body["aggregate_dimension_rows_cleared"])
	}

	// Real proof the rows are actually gone in the underlying file, not
	// just in the reported counts.
	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var remaining int
	db2.QueryRow("SELECT COUNT(*) FROM time_buckets").Scan(&remaining)
	if remaining != 0 {
		t.Errorf("time_buckets still has %d rows after clear", remaining)
	}
}
