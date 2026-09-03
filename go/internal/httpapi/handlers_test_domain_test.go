package httpapi

// HTTP-layer proof for GET /api/custom-rules/test-domain (Filters'
// "Test a Domain"): real evaluation against real stored custom rules
// and a real blocklist subscription's compiled .rpz output -- not a
// hand-rolled fixture of internal/dnscompile.EvaluationResult.

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

	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnsruntime"
)

func newTestDomainTestServer(t *testing.T) *Server {
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
	runtimeDir := t.TempDir()
	blSvc := &blocklists.Service{DB: db, RuntimeDir: runtimeDir}
	crSvc := &customrules.Service{DB: db}
	orch := &dnsruntime.Orchestrator{CustomRules: crSvc, Blocklists: blSvc}
	return &Server{DB: db, CustomRules: crSvc, Blocklists: blSvc, DNSRuntime: orch, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func testDomainReq(t *testing.T, s *Server, domain string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/custom-rules/test-domain?domain="+domain, nil)
	rec := httptest.NewRecorder()
	s.handleTestDomain(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("invalid JSON: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, body
}

func TestHandleTestDomainNoMatch(t *testing.T) {
	s := newTestDomainTestServer(t)
	code, body := testDomainReq(t, s, "safe.example.com")
	if code != 200 {
		t.Fatalf("code = %d, body = %+v", code, body)
	}
	if blocked, _ := body["blocked"].(bool); blocked {
		t.Fatalf("expected unblocked, got %+v", body)
	}
	if body["reason"] != "no_match" {
		t.Errorf("reason = %v, want no_match", body["reason"])
	}
}

func TestHandleTestDomainMatchesRealCustomRule(t *testing.T) {
	s := newTestDomainTestServer(t)
	if _, err := s.CustomRules.Create(context.Background(), "block", "ads.example.com", nil); err != nil {
		t.Fatal(err)
	}
	code, body := testDomainReq(t, s, "ads.example.com")
	if code != 200 {
		t.Fatalf("code = %d, body = %+v", code, body)
	}
	if blocked, _ := body["blocked"].(bool); !blocked {
		t.Fatalf("expected blocked by the real stored custom rule, got %+v", body)
	}
	if body["reason"] != "blocklist" {
		t.Errorf("reason = %v, want blocklist", body["reason"])
	}
}

// TestHandleTestDomainMatchesRealBlocklistSubscriptionFile proves the
// evaluation reads a real compiled .rpz file on disk (the same one the
// runtime compiler itself reads), not just the custom-rules table.
func TestHandleTestDomainMatchesRealBlocklistSubscriptionFile(t *testing.T) {
	s := newTestDomainTestServer(t)
	if _, _, err := s.Blocklists.Create(context.Background(), "test-sub", "Test List", "https://example.test/list.txt", "custom", "block"); err != nil {
		t.Fatal(err)
	}
	rpzPath := filepath.Join(s.Blocklists.RuntimeDir, "test-sub.rpz")
	if err := os.WriteFile(rpzPath, []byte("tracker.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, body := testDomainReq(t, s, "sub.tracker.example.net")
	if code != 200 {
		t.Fatalf("code = %d, body = %+v", code, body)
	}
	if blocked, _ := body["blocked"].(bool); !blocked {
		t.Fatalf("expected blocked by the real compiled blocklist file, got %+v", body)
	}
	if body["matched"] != "tracker.example.net" {
		t.Errorf("matched = %v, want the real blocklist entry", body["matched"])
	}
}

func TestHandleTestDomainRequiresDomainParam(t *testing.T) {
	s := newTestDomainTestServer(t)
	code, _ := testDomainReq(t, s, "")
	if code != 400 {
		t.Fatalf("code = %d, want 400", code)
	}
}

func TestHandleTestDomainUnavailableWithNoRuntime(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	code, _ := testDomainReq(t, s, "example.com")
	if code != 503 {
		t.Fatalf("code = %d, want 503", code)
	}
}
