package httpapi

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/auditlog"
	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/dbmigrate"
)

func newAuditMiddlewareTestServer(t *testing.T) (*Server, int64) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// A real admin row is required by admin_audit_log's own FK
	// (matching V1.1.1's real schema) -- insert one directly.
	res, err := db.Exec(`INSERT INTO admins (username, password_hash, created_at) VALUES ('tester', 'x', datetime('now'))`)
	if err != nil {
		t.Fatal(err)
	}
	adminID, _ := res.LastInsertId()
	return &Server{DB: db, AuditLog: &auditlog.Service{DB: db}}, adminID
}

func withSession(r *http.Request, adminID int64, username string) *http.Request {
	sess := &auth.Session{AdminID: adminID, Username: username}
	return r.WithContext(auth.WithSession(r.Context(), sess))
}

func TestAuditedRecordsASuccessfulMutation(t *testing.T) {
	s, adminID := newAuditMiddlewareTestServer(t)
	handler := s.audited("widget_create", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	req := withSession(httptest.NewRequest("POST", "/api/widgets", nil), adminID, "tester")
	handler(httptest.NewRecorder(), req)

	entries, err := s.AuditLog.List(context.Background(), adminID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "widget_create" || !entries[0].Success {
		t.Fatalf("expected one successful widget_create entry, got %+v", entries)
	}
}

func TestAuditedRecordsAFailedMutationAsUnsuccessful(t *testing.T) {
	s, adminID := newAuditMiddlewareTestServer(t)
	handler := s.audited("widget_delete", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	req := withSession(httptest.NewRequest("DELETE", "/api/widgets/1", nil), adminID, "tester")
	handler(httptest.NewRecorder(), req)

	entries, _ := s.AuditLog.List(context.Background(), adminID, 10)
	if len(entries) != 1 || entries[0].Success {
		t.Fatalf("expected one FAILED widget_delete entry, got %+v", entries)
	}
}

func TestAuditedDefaultsToSuccessWhenHandlerNeverCallsWriteHeader(t *testing.T) {
	// A handler that just calls Write() (implicit 200) must still be
	// recorded as a success -- WriteHeader is never called explicitly
	// in that real, common case.
	s, adminID := newAuditMiddlewareTestServer(t)
	handler := s.audited("widget_update", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})
	req := withSession(httptest.NewRequest("PUT", "/api/widgets/1", nil), adminID, "tester")
	handler(httptest.NewRecorder(), req)

	entries, _ := s.AuditLog.List(context.Background(), adminID, 10)
	if len(entries) != 1 || !entries[0].Success {
		t.Fatalf("expected a successful entry for an implicit 200, got %+v", entries)
	}
}

func TestAuditedIsANoOpWithoutARealSession(t *testing.T) {
	s, adminID := newAuditMiddlewareTestServer(t)
	handler := s.audited("widget_create", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// No session in context at all.
	handler(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/widgets", nil))

	entries, _ := s.AuditLog.List(context.Background(), adminID, 10)
	if len(entries) != 0 {
		t.Fatalf("expected no audit entry without a real session, got %+v", entries)
	}
}

func TestAuditedIsANoOpWithNilAuditLog(t *testing.T) {
	s := &Server{} // AuditLog is nil
	called := false
	handler := s.audited("widget_create", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := withSession(httptest.NewRequest("POST", "/api/widgets", nil), 1, "tester")
	// Must not panic.
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("expected the real handler to still run even with AuditLog nil")
	}
}
