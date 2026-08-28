// Package bootstrap protects first-run owner setup with a real one-time
// capability -- not just "zero admins exist yet" (the pattern
// app/v2/webapp.py's own setup() uses, by explicit prior owner
// decision documented in that file's own comment: a race-based gate
// alone). For the Go control plane's real, network-reachable owner
// cutover, that gate is deliberately strengthened: the setup route is
// USABLE only by whoever can present a real one-time token this
// process generates and delivers only through its own stdout/log
// stream and a root-only file -- never over the network, never in any
// API response, never guessable -- so an unauthenticated LAN client
// racing to POST /api/setup first cannot claim the appliance.
//
// The token gates a short-lived, single-purpose "setup session"
// (separate from internal/auth's real post-login session -- this one
// exists only to bridge "I proved I hold the bootstrap token" to "I am
// now allowed to call the real account-creation endpoint", nothing
// else is ever authorized with it). Rate-limited, expires quickly,
// permanently consumed (token file deleted, session cleared) the
// moment a real admin account is actually created -- so this whole
// mechanism can only ever be used once, successfully, by one browser
// session, in this process's lifetime.
package bootstrap

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrInvalidToken   = errors.New("invalid or expired bootstrap token")
	ErrLockedOut      = errors.New("too many failed bootstrap attempts; locked out temporarily")
	ErrNoActiveToken  = errors.New("no bootstrap token is active (setup may already be complete)")
	ErrSessionExpired = errors.New("setup session expired or invalid; request a new bootstrap token")
)

const (
	sessionTTL      = 15 * time.Minute
	maxAttempts     = 5
	lockoutDuration = 15 * time.Minute
	tokenBytes      = 32
)

type session struct {
	csrf      string
	expiresAt time.Time
}

type attemptRecord struct {
	count       int
	lockedUntil time.Time
}

// Manager owns the one-time token file and every in-memory setup
// session/rate-limit state. All state is process-lifetime only --
// deliberate: a restart mid-setup means the operator re-reads a fresh
// token from the new process's own log, never a token that outlives
// the process that issued it.
type Manager struct {
	TokenPath string
	Log       *slog.Logger

	mu       sync.Mutex
	token    string // empty once consumed or never generated
	sessions map[string]session
	attempts map[string]*attemptRecord
}

// Init generates a fresh token IF setupRequired is true and persists
// it to TokenPath (0600, this process's own UID only) and to this
// process's own log (the "controlled deployment path" delivery --
// whoever has log/console access to the real appliance, e.g. `podman
// logs` or journald, the same access level already required to do
// anything else privileged on this host). If setupRequired is false,
// any leftover token file from a prior run is removed instead --
// defense in depth so a stale token can never outlive the setup it was
// meant to gate.
func (m *Manager) Init(setupRequired bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = map[string]session{}
	m.attempts = map[string]*attemptRecord{}

	if !setupRequired {
		if m.TokenPath != "" {
			os.Remove(m.TokenPath)
		}
		m.token = ""
		return nil
	}

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generating bootstrap token: %w", err)
	}
	token := hex.EncodeToString(raw)
	m.token = token

	if m.TokenPath != "" {
		if dir := filepath.Dir(m.TokenPath); dir != "" {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return fmt.Errorf("creating bootstrap token directory: %w", err)
			}
		}
		if err := os.WriteFile(m.TokenPath, []byte(token+"\n"), 0o600); err != nil {
			return fmt.Errorf("writing bootstrap token file: %w", err)
		}
	}
	if m.Log != nil {
		m.Log.Info("first-run setup requires this one-time bootstrap token -- present it once at the setup screen; it is never sent to any browser, never logged again after this line, and expires the moment setup completes",
			"bootstrap_token", token, "token_file", m.TokenPath, "expires_after", "first successful setup, or process restart")
	}
	return nil
}

// Active reports whether a bootstrap token currently exists (setup is
// still open). Safe to expose publicly -- it reveals no secret, only
// the same "is setup still open" fact GET /api/setup/status already
// answers a different way.
func (m *Manager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token != ""
}

// VerifyToken checks a caller-presented token against the real one.
// Rate-limited per client IP (maxAttempts before a lockoutDuration
// cooldown) so this cannot be brute-forced -- tokenBytes*8 bits of
// entropy makes that infeasible anyway, but the lockout means even a
// scripted guesser gets nowhere fast, not just "eventually nowhere".
// On success, issues a new short-lived setup session (sessionID, csrf)
// -- constant-time comparison throughout, and the error returned never
// distinguishes "wrong token" from "locked out" in a way a caller
// could use to fingerprint remaining attempts.
func (m *Manager) VerifyToken(token, clientIP string) (sessionID, csrf string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec := m.attempts[clientIP]
	if rec == nil {
		rec = &attemptRecord{}
		m.attempts[clientIP] = rec
	}
	if !rec.lockedUntil.IsZero() && time.Now().Before(rec.lockedUntil) {
		return "", "", ErrLockedOut
	}

	if m.token == "" {
		return "", "", ErrNoActiveToken
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(m.token)) != 1 {
		rec.count++
		if rec.count >= maxAttempts {
			rec.lockedUntil = time.Now().Add(lockoutDuration)
			rec.count = 0
		}
		return "", "", ErrInvalidToken
	}

	rec.count = 0
	rec.lockedUntil = time.Time{}

	sessionID, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	m.sessions[sessionID] = session{csrf: csrf, expiresAt: time.Now().Add(sessionTTL)}
	return sessionID, csrf, nil
}

// CheckSession validates a setup-session id + its CSRF token together
// -- both must match and the session must not have expired. Called
// immediately before allowing the real POST /api/setup to proceed.
func (m *Manager) CheckSession(sessionID, csrfHeader string) error {
	if sessionID == "" || csrfHeader == "" {
		return ErrSessionExpired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionID]
	if !ok || time.Now().After(sess.expiresAt) {
		delete(m.sessions, sessionID)
		return ErrSessionExpired
	}
	if subtle.ConstantTimeCompare([]byte(csrfHeader), []byte(sess.csrf)) != 1 {
		return ErrSessionExpired
	}
	return nil
}

// Consume permanently disables the whole bootstrap mechanism -- called
// exactly once, immediately after a real admin account is actually
// created. Deletes the token file (so even a leaked/logged copy of it
// is inert afterward) and clears every in-memory session -- a second
// browser tab mid-race loses its own setup session too, matching
// "only one browser session should ever complete this".
func (m *Manager) Consume() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = ""
	m.sessions = map[string]session{}
	if m.TokenPath != "" {
		os.Remove(m.TokenPath)
	}
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
