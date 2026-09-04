package httpapi

// HTTP-layer proof for the import job workflow -- in particular the
// zone source type's default_domain plumbing, since ParseToPlan
// rejects a zone import with none.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/importer"
	"alderpointdns/go-controlplane/internal/localdns"
)

func newImportTestServer(t *testing.T) *Server {
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
	localDNS := &localdns.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()}
	return &Server{
		Importer: &importer.Service{DB: db, LocalDNS: localDNS, Backup: &backup.Service{DB: db, Dir: t.TempDir(), Version: "test"}},
		LocalDNS: localDNS,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestCreateImportJobZoneRequiresDefaultDomain(t *testing.T) {
	s := newImportTestServer(t)
	body, _ := json.Marshal(map[string]string{"source_type": "zone", "text": "www IN A 10.0.0.5"})
	rec := httptest.NewRecorder()
	s.handleCreateImportJob(rec, httptest.NewRequest("POST", "/api/import/jobs", bytes.NewReader(body)))
	if rec.Code != 400 {
		t.Fatalf("expected 400 for a zone import with no default_domain, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateImportJobZoneWithDefaultDomainSucceeds(t *testing.T) {
	s := newImportTestServer(t)
	body, _ := json.Marshal(map[string]string{"source_type": "zone", "text": "www IN A 10.0.0.5", "default_domain": "example.com"})
	rec := httptest.NewRecorder()
	s.handleCreateImportJob(rec, httptest.NewRequest("POST", "/api/import/jobs", bytes.NewReader(body)))
	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	json.Unmarshal(rec.Body.Bytes(), &result)
	plan, _ := result["plan"].(map[string]any)
	rows, _ := plan["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("expected 1 real plan row, got %+v", result)
	}
	row := rows[0].(map[string]any)
	if row["name"] != "www.example.com" {
		t.Fatalf("expected the name to be qualified against default_domain, got %+v", row)
	}
}

func TestCreateImportJobXLSXDecodesBase64AndImportsReal(t *testing.T) {
	s := newImportTestServer(t)
	// A real .xlsx, once built with the real openpyxl library and
	// checked in as a static fixture -- see
	// internal/apdnsbak/apdnsbak_test.go's own comment for the full
	// zero-Python-test-requirement rationale (2026-09-04 audit).
	xlsxBytes, err := os.ReadFile("testdata/import_fixture.xlsx")
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(xlsxBytes)
	body, _ := json.Marshal(map[string]string{"source_type": "xlsx", "text": encoded})
	rec := httptest.NewRecorder()
	s.handleCreateImportJob(rec, httptest.NewRequest("POST", "/api/import/jobs", bytes.NewReader(body)))
	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	json.Unmarshal(rec.Body.Bytes(), &result)
	plan, _ := result["plan"].(map[string]any)
	rows, _ := plan["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("expected 1 real row from the real xlsx file, got %+v", plan)
	}
}
