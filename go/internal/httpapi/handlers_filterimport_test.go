package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/filterimport"
	"alderpointdns/go-controlplane/internal/localdns"
)

func newFilterImportTestServer(t *testing.T) *Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	dir := t.TempDir()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	return &Server{
		FilterImport: &filterimport.Service{
			Blocklists:  &blocklists.Service{DB: db, HTTPClient: client, StagingDir: filepath.Join(dir, "bl-staging"), RuntimeDir: filepath.Join(dir, "bl-runtime"), MaxConcurrent: 3},
			CustomRules: &customrules.Service{DB: db},
			LocalDNS:    &localdns.Service{DB: db, StagingDir: filepath.Join(dir, "ld-staging"), RuntimeDir: filepath.Join(dir, "ld-runtime")},
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestImportPiholeHTTPRealApply(t *testing.T) {
	s := newFilterImportTestServer(t)
	body, _ := json.Marshal(map[string]any{"text": "blacklist ads.example.com\n", "default_domain": "lan", "dry_run": false})
	rec := httptest.NewRecorder()
	s.handleImportPihole(rec, httptest.NewRequest("POST", "/api/import/pihole", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	report := out["report"].(map[string]any)
	counts := report["counts"].(map[string]any)
	if counts["imported"] != float64(1) {
		t.Fatalf("expected 1 imported, got %+v", report)
	}
}

func TestImportPiholeHTTPRequiresText(t *testing.T) {
	s := newFilterImportTestServer(t)
	rec := httptest.NewRecorder()
	s.handleImportPihole(rec, httptest.NewRequest("POST", "/api/import/pihole", bytes.NewReader([]byte(`{"text":""}`))))
	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestImportAdGuardYAMLHTTPRealApply(t *testing.T) {
	s := newFilterImportTestServer(t)
	body, _ := json.Marshal(map[string]any{"text": "user_rules:\n  - \"||ads.example.com^\"\n", "dry_run": false})
	rec := httptest.NewRecorder()
	s.handleImportAdGuardYAML(rec, httptest.NewRequest("POST", "/api/import/adguard-yaml", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestImportAdGuardYAMLHTTPRejectsInvalidYAML(t *testing.T) {
	s := newFilterImportTestServer(t)
	body, _ := json.Marshal(map[string]any{"text": "not: valid: yaml: [[", "dry_run": true})
	rec := httptest.NewRecorder()
	s.handleImportAdGuardYAML(rec, httptest.NewRequest("POST", "/api/import/adguard-yaml", bytes.NewReader(body)))
	if rec.Code != 400 {
		t.Fatalf("expected 400 for invalid YAML, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestFilterImportRoutesWhenUnconfiguredReturnUnavailable(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rec := httptest.NewRecorder()
	s.handleImportPihole(rec, httptest.NewRequest("POST", "/api/import/pihole", bytes.NewReader([]byte(`{"text":"x"}`))))
	if rec.Code != 503 {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	s.handleImportAdGuardYAML(rec2, httptest.NewRequest("POST", "/api/import/adguard-yaml", bytes.NewReader([]byte(`{"text":"x"}`))))
	if rec2.Code != 503 {
		t.Fatalf("expected 503, got %d", rec2.Code)
	}
}
