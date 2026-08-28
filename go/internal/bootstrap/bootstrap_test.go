package bootstrap

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	return &Manager{TokenPath: filepath.Join(t.TempDir(), "bootstrap-token"), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestInitGeneratesTokenWhenSetupRequired(t *testing.T) {
	m := newTestManager(t)
	if err := m.Init(true); err != nil {
		t.Fatal(err)
	}
	if !m.Active() {
		t.Fatal("expected Active() to be true after Init(true)")
	}
	data, err := os.ReadFile(m.TokenPath)
	if err != nil {
		t.Fatalf("expected a real token file, got: %v", err)
	}
	info, err := os.Stat(m.TokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %o, want 0600", info.Mode().Perm())
	}
	if len(data) < 32 {
		t.Fatalf("token file looks too short to be real: %d bytes", len(data))
	}
}

func TestInitRemovesStaleTokenWhenSetupNotRequired(t *testing.T) {
	m := newTestManager(t)
	if err := m.Init(true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.TokenPath); err != nil {
		t.Fatal("expected token file to exist after Init(true)")
	}
	if err := m.Init(false); err != nil {
		t.Fatal(err)
	}
	if m.Active() {
		t.Fatal("expected Active() to be false after Init(false)")
	}
	if _, err := os.Stat(m.TokenPath); !os.IsNotExist(err) {
		t.Fatal("expected the stale token file to be removed when setup is no longer required")
	}
}

func TestVerifyTokenRejectsWrongToken(t *testing.T) {
	m := newTestManager(t)
	m.Init(true)
	if _, _, err := m.VerifyToken("not-the-real-token", "10.0.0.1"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyTokenAcceptsRealTokenAndIssuesSession(t *testing.T) {
	m := newTestManager(t)
	m.Init(true)
	real, err := os.ReadFile(m.TokenPath)
	if err != nil {
		t.Fatal(err)
	}
	token := string(real[:len(real)-1]) // strip trailing newline
	sessID, csrf, err := m.VerifyToken(token, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if sessID == "" || csrf == "" {
		t.Fatal("expected a real session id and csrf token")
	}
	if err := m.CheckSession(sessID, csrf); err != nil {
		t.Fatalf("expected the freshly issued session to check out, got %v", err)
	}
}

func TestVerifyTokenLocksOutAfterMaxAttempts(t *testing.T) {
	m := newTestManager(t)
	m.Init(true)
	for i := 0; i < maxAttempts; i++ {
		if _, _, err := m.VerifyToken("wrong", "10.0.0.2"); err != ErrInvalidToken {
			t.Fatalf("attempt %d: expected ErrInvalidToken, got %v", i, err)
		}
	}
	if _, _, err := m.VerifyToken("wrong", "10.0.0.2"); err != ErrLockedOut {
		t.Fatalf("expected ErrLockedOut after %d failed attempts, got %v", maxAttempts, err)
	}
	// A DIFFERENT client IP must not be affected by another IP's lockout.
	if _, _, err := m.VerifyToken("wrong", "10.0.0.3"); err != ErrInvalidToken {
		t.Fatalf("expected an unrelated IP to get its own attempt budget, got %v", err)
	}
}

func TestVerifyTokenWithNoActiveTokenReportsNoActiveToken(t *testing.T) {
	m := newTestManager(t)
	m.Init(false)
	if _, _, err := m.VerifyToken("anything", "10.0.0.1"); err != ErrNoActiveToken {
		t.Fatalf("expected ErrNoActiveToken, got %v", err)
	}
}

func TestCheckSessionRejectsExpiredSession(t *testing.T) {
	m := newTestManager(t)
	m.Init(true)
	real, _ := os.ReadFile(m.TokenPath)
	token := string(real[:len(real)-1])
	sessID, csrf, err := m.VerifyToken(token, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Force expiry by manipulating internal state directly (no exported
	// clock injection -- this is the one place a test reaches past the
	// public API, deliberately, to prove the expiry path without
	// sleeping 15 real minutes).
	m.mu.Lock()
	s := m.sessions[sessID]
	s.expiresAt = time.Now().Add(-time.Second)
	m.sessions[sessID] = s
	m.mu.Unlock()

	if err := m.CheckSession(sessID, csrf); err != ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestCheckSessionRejectsWrongCSRF(t *testing.T) {
	m := newTestManager(t)
	m.Init(true)
	real, _ := os.ReadFile(m.TokenPath)
	token := string(real[:len(real)-1])
	sessID, _, err := m.VerifyToken(token, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.CheckSession(sessID, "wrong-csrf"); err != ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired for a CSRF mismatch, got %v", err)
	}
}

func TestConsumeDisablesEverything(t *testing.T) {
	m := newTestManager(t)
	m.Init(true)
	real, _ := os.ReadFile(m.TokenPath)
	token := string(real[:len(real)-1])
	sessID, csrf, err := m.VerifyToken(token, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	m.Consume()

	if m.Active() {
		t.Fatal("expected Active() false after Consume")
	}
	if _, err := os.Stat(m.TokenPath); !os.IsNotExist(err) {
		t.Fatal("expected the token file to be deleted after Consume")
	}
	if err := m.CheckSession(sessID, csrf); err != ErrSessionExpired {
		t.Fatalf("expected the previously-valid session to be invalidated by Consume, got %v", err)
	}
	if _, _, err := m.VerifyToken(token, "10.0.0.1"); err != ErrNoActiveToken {
		t.Fatalf("expected re-verifying the OLD token after Consume to fail, got %v", err)
	}
}

func TestSecondSessionDoesNotInterfereWithFirst(t *testing.T) {
	// Two "browser tabs" both hold the same real token (plausible if an
	// operator copy-pasted it twice) -- each gets its OWN session/csrf
	// pair, and one completing setup (Consume) invalidates the other's
	// session too (see TestConsumeDisablesEverything) -- this test just
	// confirms two independently issued sessions are both valid until then.
	m := newTestManager(t)
	m.Init(true)
	real, _ := os.ReadFile(m.TokenPath)
	token := string(real[:len(real)-1])
	sess1, csrf1, err := m.VerifyToken(token, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	sess2, csrf2, err := m.VerifyToken(token, "10.0.0.4")
	if err != nil {
		t.Fatal(err)
	}
	if sess1 == sess2 {
		t.Fatal("expected two distinct sessions")
	}
	if err := m.CheckSession(sess1, csrf1); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckSession(sess2, csrf2); err != nil {
		t.Fatal(err)
	}
}
