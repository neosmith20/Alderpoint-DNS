package httpapi

// HTTP-layer proof for the real .apdnsbak import route -- builds a real
// archive with the actual Python app/v2/backup_restore.py module (same
// approach as internal/apdnsbak's own tests) and drives it through the
// real handler end to end.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/upstreams"
)

func newApdnsbakTestServer(t *testing.T) *Server {
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
		LocalDNS:      &localdns.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()},
		Upstreams:     &upstreams.Service{DB: db},
		DNSTransports: &dnstransports.Service{DB: db},
		Policy:        &policy.Service{DB: db},
		Blocklists:    &blocklists.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()},
		Backup:        &backup.Service{DB: db, Dir: t.TempDir(), Version: "test"},
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func buildApdnsbakHTTPFixture(t *testing.T, passphrase string) []byte {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "control.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	schema := `
CREATE TABLE local_dns_records (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, record_type TEXT NOT NULL,
    value TEXT NOT NULL, ttl INTEGER NOT NULL DEFAULT 300, enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(name, record_type, value)
);
CREATE TABLE upstream_profiles (
    id INTEGER PRIMARY KEY, upstream_profile_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    transport TEXT NOT NULL, strategy TEXT NOT NULL DEFAULT 'ordered', created_at TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE upstream_endpoints (
    id INTEGER PRIMARY KEY, upstream_profile_row_id INTEGER NOT NULL, address TEXT NOT NULL,
    tls_hostname TEXT, priority INTEGER NOT NULL DEFAULT 0, weight INTEGER NOT NULL DEFAULT 1,
    secret_ref TEXT, doh_path TEXT
);
CREATE TABLE dns_transport_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1), dot_enabled INTEGER NOT NULL DEFAULT 0,
    dot_port INTEGER NOT NULL DEFAULT 853, updated_at TEXT NOT NULL,
    doh_enabled INTEGER NOT NULL DEFAULT 0, doh_port INTEGER NOT NULL DEFAULT 443,
    doh_path TEXT NOT NULL DEFAULT '/dns-query', doq_enabled INTEGER NOT NULL DEFAULT 0,
    doq_port INTEGER NOT NULL DEFAULT 853, doh3_enabled INTEGER NOT NULL DEFAULT 0, doh3_port INTEGER NOT NULL DEFAULT 443
);
CREATE TABLE policy_layers (
    id INTEGER PRIMARY KEY, scope TEXT NOT NULL, scope_ref TEXT NOT NULL,
    filtering_profile_id TEXT, safesearch_mode TEXT, parental_policy_id TEXT, security_policy_id TEXT,
    service_blocking_ruleset_id TEXT, blocking_response_mode TEXT, custom_ipv4 TEXT, custom_ipv6 TEXT,
    upstream_profile_id TEXT, fallback_strategy TEXT, fallback_upstream_profile_id TEXT, ecs_mode TEXT,
    domain_routing_ruleset_id TEXT, query_log_enabled INTEGER, statistics_enabled INTEGER,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(scope, scope_ref)
);
CREATE TABLE blocklist_subscriptions (
    id INTEGER PRIMARY KEY, subscription_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, url TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
    last_refresh_at TEXT, last_status TEXT NOT NULL DEFAULT 'never_refreshed', last_error TEXT NOT NULL DEFAULT '',
    rule_count INTEGER NOT NULL DEFAULT 0, update_interval_seconds INTEGER
);
`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO local_dns_records(name, record_type, value, ttl, enabled, created_at, updated_at)
		VALUES('apdnsbak-http-printer.lan','A','10.0.0.89',300,1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	backupPath := filepath.Join(dir, "fixture.apdnsbak")
	repoRoot, err := filepath.Abs("../../../")
	if err != nil {
		t.Fatal(err)
	}
	script := `
import sys
sys.path.insert(0, sys.argv[5])
from pathlib import Path
from app.v2.backup_restore import create_appliance_backup
from app.v2.secret_store import SecretStore

store = SecretStore(Path(sys.argv[3]))
create_appliance_backup(
    control_db_path=Path(sys.argv[1]), secret_store=store,
    key=b"unused-in-passphrase-mode-000000", backup_path=Path(sys.argv[2]),
    source_version="v2-test", passphrase=sys.argv[4], source_node_id="fixture-node",
)
`
	cmd := exec.Command("python3", "-c", script, dbPath, backupPath, filepath.Join(dir, "secretstore"), passphrase, repoRoot)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("building real .apdnsbak fixture (python deps missing?): %v: %s", err, out)
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestApdnsbakImportDryRunReportsWithoutWriting(t *testing.T) {
	s := newApdnsbakTestServer(t)
	archive := buildApdnsbakHTTPFixture(t, "test-passphrase")

	req := httptest.NewRequest("POST", "/api/import/apdnsbak?filename=appliance-123.apdnsbak&dry_run=true", bytes.NewReader(archive))
	req.Header.Set("X-Apdnsbak-Passphrase", "test-passphrase")
	rec := httptest.NewRecorder()
	s.handleImportApdnsbak(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	report := out["report"].(map[string]any)
	if report["dry_run"] != true {
		t.Fatalf("expected dry_run=true, got %+v", report)
	}

	recs, _ := s.LocalDNS.List(context.Background())
	if len(recs) != 0 {
		t.Fatalf("dry run must never write, found %d records", len(recs))
	}
}

func TestApdnsbakImportRealApplyImportsRealRows(t *testing.T) {
	s := newApdnsbakTestServer(t)
	archive := buildApdnsbakHTTPFixture(t, "test-passphrase")

	req := httptest.NewRequest("POST", "/api/import/apdnsbak?filename=appliance-123.apdnsbak&dry_run=false", bytes.NewReader(archive))
	req.Header.Set("X-Apdnsbak-Passphrase", "test-passphrase")
	rec := httptest.NewRecorder()
	s.handleImportApdnsbak(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	recs, _ := s.LocalDNS.List(context.Background())
	if len(recs) != 1 || recs[0].Name != "apdnsbak-http-printer.lan" {
		t.Fatalf("expected the real row to be imported, got %+v", recs)
	}
}

func TestApdnsbakImportWithWrongPassphraseFails(t *testing.T) {
	s := newApdnsbakTestServer(t)
	archive := buildApdnsbakHTTPFixture(t, "test-passphrase")

	req := httptest.NewRequest("POST", "/api/import/apdnsbak?filename=appliance-123.apdnsbak", bytes.NewReader(archive))
	req.Header.Set("X-Apdnsbak-Passphrase", "wrong")
	rec := httptest.NewRecorder()
	s.handleImportApdnsbak(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"] != "wrong_passphrase" {
		t.Fatalf("expected error=wrong_passphrase, got %+v", out)
	}
}

func TestApdnsbakImportRejectsUnrecognizedFilename(t *testing.T) {
	s := newApdnsbakTestServer(t)
	req := httptest.NewRequest("POST", "/api/import/apdnsbak?filename=random.zip", bytes.NewReader([]byte("nope")))
	rec := httptest.NewRecorder()
	s.handleImportApdnsbak(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestApdnsbakImportRouteWhenUnconfiguredReturnsUnavailable(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest("POST", "/api/import/apdnsbak?filename=x.apdnsbak", bytes.NewReader(nil))
	rec := httptest.NewRecorder()
	s.handleImportApdnsbak(rec, req)
	if rec.Code != 503 {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}
