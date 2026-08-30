package httpapi

// Real proof that the raw Query Log grid resolves a client address to a
// friendly name the same way the Clients page's own Client analytics
// table already does (handleAnalyticsTopClients) -- closing the "raw
// Query Log grid never resolves aliases" gap PARITY_MATRIX.md's Local
// DNS row used to disclose.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/clientalias"
	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnsanalytics"
)

func TestHandleAnalyticsQueryLogResolvesClientNameFromManagedAndAlias(t *testing.T) {
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
	knownID, err := clientsSvc.CreateClient(context.Background(), "Kitchen Echo", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := clientsSvc.AddIdentifier(context.Background(), knownID, "ipv4", "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	aliasSvc := &clientalias.Service{DB: db}
	if _, err := aliasSvc.Create(context.Background(), "10.0.0.16/28", "Guest devices", ""); err != nil {
		t.Fatal(err)
	}

	analyticsDB, err := dnsanalytics.Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { analyticsDB.Close() })
	now := time.Now().Unix()
	for _, row := range []struct {
		client string
		domain string
	}{
		{"10.0.0.5", "managed.example.com."},
		{"10.0.0.20", "aliased.example.com."},
		{"10.0.0.99", "unknown.example.com."},
	} {
		if _, err := analyticsDB.Exec(
			`INSERT INTO query_events (ts, domain, qtype, rcode, protocol, client, latency_ms, outcome) VALUES (?, ?, 'A', 'NOERROR', 'udp', ?, 1.0, 'allowed')`,
			now, row.domain, row.client,
		); err != nil {
			t.Fatal(err)
		}
	}

	reader := &dnsanalytics.Reader{DB: analyticsDB}
	s := &Server{DB: db, Clients: clientsSvc, ClientAliases: aliasSvc, Analytics: reader, RawQueryLog: reader}

	req := httptest.NewRequest("GET", "/api/analytics/query-log?minutes=60", nil)
	rec := httptest.NewRecorder()
	s.handleAnalyticsQueryLog(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Rows []struct {
			Client     string `json:"client"`
			ClientName string `json:"client_name"`
			Domain     string `json:"domain"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	byClient := map[string]string{}
	for _, r := range out.Rows {
		byClient[r.Client] = r.ClientName
	}
	if got := byClient["10.0.0.5"]; got != "Kitchen Echo" {
		t.Errorf("managed client's own name should win: got client_name=%q, want \"Kitchen Echo\"", got)
	}
	if got := byClient["10.0.0.20"]; got != "Guest devices" {
		t.Errorf("unmanaged-but-aliased address should resolve to the alias: got client_name=%q, want \"Guest devices\"", got)
	}
	if got := byClient["10.0.0.99"]; got != "" {
		t.Errorf("an address matching neither should carry no client_name (frontend falls back to the raw address): got %q", got)
	}
}
