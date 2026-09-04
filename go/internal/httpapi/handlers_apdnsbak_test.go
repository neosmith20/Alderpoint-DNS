package httpapi

// HTTP-layer proof for the real .apdnsbak import route -- reads a real
// archive that was once built with the actual (now-decommissioned)
// Python app/v2/backup_restore.py module (same approach as
// internal/apdnsbak's own tests -- see testdata/apdnsbak_fixture.apdnsbak's
// own generation, recorded in this repo's history) and drives it through
// the real handler end to end. Checked in as a static fixture rather
// than generated per-run: see the 2026-09-04 zero-Python audit
// (internal/apdnsbak/apdnsbak_test.go's own comment has the full
// rationale).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
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

// buildApdnsbakHTTPFixture returns the checked-in static fixture's bytes
// (testdata/apdnsbak_fixture.apdnsbak -- its own DB seeded exactly one
// row, local_dns_records name='apdnsbak-http-printer.lan', under
// passphrase "test-passphrase", matching every call site below). The
// passphrase parameter is kept only so call sites read the same as
// before; the fixture itself is fixed, not regenerated per-passphrase.
func buildApdnsbakHTTPFixture(t *testing.T, passphrase string) []byte {
	t.Helper()
	if passphrase != "test-passphrase" {
		t.Fatalf("testdata/apdnsbak_fixture.apdnsbak was sealed under \"test-passphrase\" -- got %q", passphrase)
	}
	data, err := os.ReadFile("testdata/apdnsbak_fixture.apdnsbak")
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
