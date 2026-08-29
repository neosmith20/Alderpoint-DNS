package httpapi

// HTTP-layer proof for the V1.1.1 legacy-appliance-backup import route --
// builds a real archive with the real `tar`/`openssl` binaries (same
// approach as internal/legacyimport's own tests) and drives it through
// the actual handler, proving the whole chain (upload -> extract ->
// decrypt -> pymigrate.Importer -> real Go-native rows) end to end.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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

func newLegacyImportTestServer(t *testing.T) *Server {
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

// buildLegacyFixtureArchive is the HTTP-layer twin of
// internal/legacyimport's own buildFixtureArchive -- a real V1.1.1-shaped
// SQLite db (same schema as pymigrate's own fixture), real tar+gzip, and
// optionally real openssl encryption.
func buildLegacyFixtureArchive(t *testing.T, password string) []byte {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// The full schema pymigrate.Importer.Run unconditionally reads (not
	// just local_dns_records) -- matching internal/pymigrate's own
	// fixture schema exactly, since this test exercises pymigrate
	// itself through the HTTP handler, not a stand-in for it.
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
		VALUES('printer.lan','A','10.0.0.50',300,1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	sumBytes := sha256.Sum256(dbBytes)
	sum := hex.EncodeToString(sumBytes[:])
	manifest, _ := json.Marshal(map[string]any{
		"backup_format_version": 1,
		"sha256_checksums":      map[string]string{"var/lib/alderpointdns/alderpointdns.db": sum},
	})

	stage := t.TempDir()
	os.WriteFile(filepath.Join(stage, "manifest.json"), manifest, 0o644)
	dbDir := filepath.Join(stage, "var", "lib", "alderpointdns")
	os.MkdirAll(dbDir, 0o755)
	os.WriteFile(filepath.Join(dbDir, "alderpointdns.db"), dbBytes, 0o644)

	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	if out, err := exec.Command("tar", "-czf", archivePath, "-C", stage, "manifest.json", "var/lib/alderpointdns/alderpointdns.db").CombinedOutput(); err != nil {
		t.Fatalf("tar: %v: %s", err, out)
	}
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if password == "" {
		return data
	}
	encPath := archivePath + ".enc"
	cmd := exec.Command("openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt", "-pass", "stdin", "-in", archivePath, "-out", encPath)
	cmd.Stdin = bytes.NewBufferString(password)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl enc: %v: %s", err, out)
	}
	encData, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	return encData
}

func TestLegacyImportDryRunReportsWithoutWriting(t *testing.T) {
	s := newLegacyImportTestServer(t)
	archive := buildLegacyFixtureArchive(t, "")

	req := httptest.NewRequest("POST", "/api/import/legacy-appliance?filename=alderpointdns-backup-20260101-000000%2B0000.tar.gz&dry_run=true", bytes.NewReader(archive))
	rec := httptest.NewRecorder()
	s.handleImportLegacyAppliance(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	report := out["report"].(map[string]any)
	if report["dry_run"] != true {
		t.Fatalf("expected dry_run=true in report, got %+v", report)
	}

	recs, err := s.LocalDNS.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("dry run must never write -- found %d local DNS records", len(recs))
	}
}

func TestLegacyImportRealApplyActuallyImportsRealRows(t *testing.T) {
	s := newLegacyImportTestServer(t)
	archive := buildLegacyFixtureArchive(t, "")

	req := httptest.NewRequest("POST", "/api/import/legacy-appliance?filename=alderpointdns-backup-20260101-000000%2B0000.tar.gz&dry_run=false", bytes.NewReader(archive))
	rec := httptest.NewRecorder()
	s.handleImportLegacyAppliance(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	recs, err := s.LocalDNS.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Name != "printer.lan" {
		t.Fatalf("expected the real legacy row to be imported, got %+v", recs)
	}
}

func TestLegacyImportWithEncryptedArchiveAndRealPasswordHeader(t *testing.T) {
	s := newLegacyImportTestServer(t)
	archive := buildLegacyFixtureArchive(t, "correct-password")

	req := httptest.NewRequest("POST", "/api/import/legacy-appliance?filename=alderpointdns-backup-20260101-000000%2B0000.tar.gz.enc&dry_run=true", bytes.NewReader(archive))
	req.Header.Set("X-Legacy-Backup-Password", "correct-password")
	rec := httptest.NewRecorder()
	s.handleImportLegacyAppliance(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLegacyImportWithMissingPasswordOnEncryptedArchiveFails(t *testing.T) {
	s := newLegacyImportTestServer(t)
	archive := buildLegacyFixtureArchive(t, "correct-password")

	req := httptest.NewRequest("POST", "/api/import/legacy-appliance?filename=alderpointdns-backup-20260101-000000%2B0000.tar.gz.enc", bytes.NewReader(archive))
	rec := httptest.NewRecorder()
	s.handleImportLegacyAppliance(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"] != "password_required" {
		t.Fatalf("expected error=password_required, got %+v", out)
	}
}

func TestLegacyImportRejectsAnUnrecognizedFilename(t *testing.T) {
	s := newLegacyImportTestServer(t)
	req := httptest.NewRequest("POST", "/api/import/legacy-appliance?filename=random.zip", bytes.NewReader([]byte("not an archive")))
	rec := httptest.NewRecorder()
	s.handleImportLegacyAppliance(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestLegacyImportRouteWhenUnconfiguredReturnsUnavailable(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest("POST", "/api/import/legacy-appliance?filename=alderpointdns-backup-x.tar.gz", bytes.NewReader(nil))
	rec := httptest.NewRecorder()
	s.handleImportLegacyAppliance(rec, req)
	if rec.Code != 503 {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}
