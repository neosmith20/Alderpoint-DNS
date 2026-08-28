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

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/bootstrap"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/localdns"
)

func newSetupTestServer(t *testing.T) (*Server, *bootstrap.Manager) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mgr := &bootstrap.Manager{TokenPath: filepath.Join(t.TempDir(), "bootstrap-token"), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := mgr.Init(true); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: db, Auth: &auth.Store{DB: db}, Bootstrap: mgr, LocalDNS: &localdns.Service{DB: db}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return s, mgr
}

func realTokenFrom(t *testing.T, mgr *bootstrap.Manager) string {
	t.Helper()
	data, err := os.ReadFile(mgr.TokenPath)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func doBootstrapRequest(t *testing.T, s *Server, token string) (*httptest.ResponseRecorder, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/setup/bootstrap", strings.NewReader(`{"token":"`+token+`"}`))
	w := httptest.NewRecorder()
	s.handleSetupBootstrap(w, req)
	return w, w.Result().Cookies()
}

func TestSetupWithoutBootstrapSessionIsRejected(t *testing.T) {
	s, _ := newSetupTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(`{"username":"owner","password":"a-real-password-123","confirm_password":"a-real-password-123"}`))
	w := httptest.NewRecorder()
	s.handleSetup(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no bootstrap session presented)", w.Code)
	}
	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "setup_session_required" {
		t.Errorf("error = %v, want setup_session_required", body["error"])
	}
	// Confirm no admin was actually created.
	var count int
	s.DB.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	if count != 0 {
		t.Fatal("an admin account must never be created without a valid bootstrap session")
	}
}

func TestBootstrapWithWrongTokenIsRejected(t *testing.T) {
	s, _ := newSetupTestServer(t)
	w, _ := doBootstrapRequest(t, s, "not-the-real-token")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestBootstrapWithRealTokenThenSetupSucceeds(t *testing.T) {
	s, mgr := newSetupTestServer(t)
	token := realTokenFrom(t, mgr)

	w, cookies := doBootstrapRequest(t, s, token)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d, body=%s", w.Code, w.Body.String())
	}
	var bootResp map[string]any
	json.NewDecoder(w.Body).Decode(&bootResp)
	csrf, _ := bootResp["csrf"].(string)
	if csrf == "" {
		t.Fatal("expected a real csrf token from bootstrap")
	}
	var setupCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == setupSessionCookieName {
			setupCookie = c
		}
	}
	if setupCookie == nil {
		t.Fatal("expected a real setup-session cookie")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(`{"username":"owner","password":"a-real-password-123","confirm_password":"a-real-password-123","create_local_dns":false}`))
	req.AddCookie(setupCookie)
	req.Header.Set("X-CSRF-Token", csrf)
	w2 := httptest.NewRecorder()
	s.handleSetup(w2, req)
	if w2.Code != http.StatusOK {
		t.Fatalf("setup status = %d, body=%s", w2.Code, w2.Body.String())
	}

	var count int
	s.DB.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	if count != 1 {
		t.Fatalf("expected exactly 1 admin created, got %d", count)
	}

	// The bootstrap mechanism must now be permanently disabled.
	if mgr.Active() {
		t.Fatal("expected bootstrap to be consumed (inactive) after a real admin was created")
	}
	if _, err := os.Stat(mgr.TokenPath); !os.IsNotExist(err) {
		t.Fatal("expected the token file to be deleted after successful setup")
	}
}

func TestSecondSetupAttemptAfterCompletionIsRejected(t *testing.T) {
	s, mgr := newSetupTestServer(t)
	token := realTokenFrom(t, mgr)
	w, cookies := doBootstrapRequest(t, s, token)
	var setupCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == setupSessionCookieName {
			setupCookie = c
		}
	}
	var bootResp map[string]any
	json.NewDecoder(w.Body).Decode(&bootResp)
	csrf, _ := bootResp["csrf"].(string)

	req := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(`{"username":"owner","password":"a-real-password-123","confirm_password":"a-real-password-123","create_local_dns":false}`))
	req.AddCookie(setupCookie)
	req.Header.Set("X-CSRF-Token", csrf)
	w2 := httptest.NewRecorder()
	s.handleSetup(w2, req)
	if w2.Code != http.StatusOK {
		t.Fatalf("first setup failed: status=%d body=%s", w2.Code, w2.Body.String())
	}

	// A second attempt, even with the ORIGINAL real token, must fail --
	// bootstrap was permanently consumed.
	w3, _ := doBootstrapRequest(t, s, token)
	if w3.Code == http.StatusOK {
		t.Fatal("expected the bootstrap token to be permanently disabled after setup completed")
	}

	// And POST /api/setup itself refuses too (defense in depth: even a
	// forged/leaked old setup-session cookie can't be replayed).
	req2 := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(`{"username":"second","password":"a-real-password-123","confirm_password":"a-real-password-123","create_local_dns":false}`))
	if setupCookie != nil {
		req2.AddCookie(setupCookie)
	}
	req2.Header.Set("X-CSRF-Token", csrf)
	w4 := httptest.NewRecorder()
	s.handleSetup(w4, req2)
	if w4.Code == http.StatusOK {
		t.Fatal("expected a second setup attempt to be rejected")
	}
	var count int
	s.DB.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	if count != 1 {
		t.Fatalf("expected exactly 1 admin to ever exist, got %d", count)
	}
}

func TestBootstrapLockoutAfterRepeatedFailures(t *testing.T) {
	s, _ := newSetupTestServer(t)
	var lastCode int
	for i := 0; i < 6; i++ {
		w, _ := doBootstrapRequest(t, s, "wrong-token")
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated failures, got %d", lastCode)
	}
}

func TestBootstrapWhenNoTokenActiveReportsAlreadyConfigured(t *testing.T) {
	s, mgr := newSetupTestServer(t)
	mgr.Consume() // simulate setup already completed
	w, _ := doBootstrapRequest(t, s, "anything")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

func TestSetupResponseNeverContainsTheBootstrapToken(t *testing.T) {
	s, mgr := newSetupTestServer(t)
	token := realTokenFrom(t, mgr)
	w, _ := doBootstrapRequest(t, s, token)
	if strings.Contains(w.Body.String(), token) {
		t.Fatal("the bootstrap token must never be echoed back in any API response")
	}
}
