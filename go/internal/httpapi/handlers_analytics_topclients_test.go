package httpapi

// HTTP-layer proof for GET /api/analytics/top-clients (the Clients
// page's Client analytics table): real ranking by query volume, real
// blocked count/percent, real label resolution against an already-
// managed client's exact ipv4 identifier, and a real degraded-with-empty
// contract when no analytics reader is configured at all -- mirrors
// handlers_clients_lifecycle_test.go's TestHandleListObservedClients
// pattern (same managedAddressLookup helper backs both).
import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnsanalytics"
	"alderpointdns/go-controlplane/internal/policy"
)

func TestHandleAnalyticsTopClients(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	clientsSvc := &clients.Service{DB: db}
	clientID, err := clientsSvc.CreateClient(context.Background(), "Kid's Tablet", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := clientsSvc.AddIdentifier(context.Background(), clientID, "ipv4", "192.168.1.50"); err != nil {
		t.Fatal(err)
	}

	analyticsDB, err := dnsanalytics.Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { analyticsDB.Close() })
	now := time.Now().Unix()
	insertTopClientsEvent(t, analyticsDB, now, "192.168.1.50", "a.example.com", "allowed")
	insertTopClientsEvent(t, analyticsDB, now, "192.168.1.50", "ads.example.com", "blocked")
	insertTopClientsEvent(t, analyticsDB, now, "192.168.1.99", "a.example.com", "allowed")

	s := &Server{
		DB:        db,
		Policy:    &policy.Service{DB: db},
		Clients:   clientsSvc,
		Analytics: &dnsanalytics.Reader{DB: analyticsDB},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	code, body := doHandler(t, s.handleAnalyticsTopClients, "GET", "", nil)
	if code != 200 {
		t.Fatalf("code = %d, body = %+v", code, body)
	}
	// "degraded" here only reflects Health()'s writer-liveness signal
	// (no *dnsanalytics.Writer is wired in this fixture, matching
	// TestHandleListObservedClients' own fixture) -- it does not mean the
	// query itself failed; the rows below are asserted as real data
	// regardless.
	rows, _ := body["clients"].([]any)
	if len(rows) != 2 {
		t.Fatalf("clients = %+v, want 2 rows", rows)
	}
	top, _ := rows[0].(map[string]any)
	if top["raw_client"] != "192.168.1.50" {
		t.Fatalf("top row = %+v, want raw_client 192.168.1.50 first (highest volume)", top)
	}
	if top["label"] != "Kid's Tablet" {
		t.Errorf("label = %v, want the managed client's own name (exact ipv4 identifier match)", top["label"])
	}
	if v, _ := top["value"].(float64); v != 2 {
		t.Errorf("value = %v, want 2", top["value"])
	}
	if v, _ := top["blocked"].(float64); v != 1 {
		t.Errorf("blocked = %v, want 1", top["blocked"])
	}
	if v, _ := top["blocked_percent"].(float64); v != 50 {
		t.Errorf("blocked_percent = %v, want 50", top["blocked_percent"])
	}

	other, _ := rows[1].(map[string]any)
	if other["label"] != "192.168.1.99" {
		t.Errorf("unmanaged address should fall back to its raw value as the label, got %v", other["label"])
	}
}

func TestHandleAnalyticsTopClientsDegradedWithNoReader(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	code, body := doHandler(t, s.handleAnalyticsTopClients, "GET", "", nil)
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	if degraded, _ := body["degraded"].(bool); !degraded {
		t.Fatalf("expected degraded:true with no analytics reader configured, got %+v", body)
	}
	rows, _ := body["clients"].([]any)
	if len(rows) != 0 {
		t.Fatalf("expected an honest empty result, got %+v", rows)
	}
}

func insertTopClientsEvent(t *testing.T, db *sql.DB, ts int64, client, domain, outcome string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO query_events (ts, domain, qtype, rcode, protocol, client, latency_ms, outcome)
		VALUES (?, ?, 'A', 'NOERROR', 'udp', ?, 1.5, ?)`, ts, domain, client, outcome)
	if err != nil {
		t.Fatal(err)
	}
}
