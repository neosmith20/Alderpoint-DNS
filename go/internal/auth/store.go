package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

const SessionCookieName = "alderpointdns_v2_session" // same name as app/v2/webapp.py's SESSION_COOKIE_NAME

const (
	LoginFailureWindow = 15 * time.Minute
	LoginFailureMax    = 5
)

var ErrRateLimited = errors.New("too many failed login attempts; try again later")
var ErrInvalidCredentials = errors.New("invalid username or password")
var ErrAlreadyConfigured = errors.New("initial setup has already been completed")

type Store struct {
	DB *sql.DB
}

func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SetupRequired reports whether zero admin accounts exist yet -- the same
// real, transactional condition CreateFirstAdmin re-checks inside its own
// transaction (app/v2/webapp.py's setup_status()/setup() pattern: no
// separate token gate on top of this).
func (s *Store) SetupRequired(ctx context.Context) (bool, error) {
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM admins`).Scan(&count); err != nil {
		return false, err
	}
	return count == 0, nil
}

func (s *Store) CreateFirstAdmin(ctx context.Context, username, password string) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM admins`).Scan(&count); err != nil {
		return 0, err
	}
	if count > 0 {
		return 0, ErrAlreadyConfigured
	}
	hash, err := HashPassword(password)
	if err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO admins(username, password_hash, created_at) VALUES(?,?,?)`,
		username, hash, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func (s *Store) recentLoginFailures(ctx context.Context, ip string) (int, error) {
	cutoff := time.Now().UTC().Add(-LoginFailureWindow).Format(time.RFC3339)
	var count int
	err := s.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM login_attempts WHERE ip=? AND success=0 AND attempted_at >= ?`, ip, cutoff).Scan(&count)
	return count, err
}

func (s *Store) recordLoginAttempt(ctx context.Context, ip string, success bool) {
	now := time.Now().UTC()
	s.DB.ExecContext(ctx, `INSERT INTO login_attempts(ip, attempted_at, success) VALUES(?,?,?)`,
		ip, now.Format(time.RFC3339), boolToInt(success))
	// Bounded table: prune anything older than 4x the failure window,
	// same principle as app/v2/webapp.py's _record_login_attempt.
	cutoff := now.Add(-LoginFailureWindow * 4).Format(time.RFC3339)
	s.DB.ExecContext(ctx, `DELETE FROM login_attempts WHERE attempted_at < ?`, cutoff)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type Session struct {
	ID       string
	AdminID  int64
	Username string
	CSRF     string
}

// Login validates credentials, rate-limited per IP, and on success creates
// a new session row (with its own CSRF token) and records the attempt.
func (s *Store) Login(ctx context.Context, username, password, ip, userAgent string) (*Session, error) {
	failures, err := s.recentLoginFailures(ctx, ip)
	if err != nil {
		return nil, err
	}
	if failures >= LoginFailureMax {
		return nil, ErrRateLimited
	}

	var adminID int64
	var hash string
	err = s.DB.QueryRowContext(ctx, `SELECT id, password_hash FROM admins WHERE username=?`, username).Scan(&adminID, &hash)
	ok := err == nil && VerifyPassword(hash, password)

	s.recordLoginAttempt(ctx, ip, ok)
	if !ok {
		return nil, ErrInvalidCredentials
	}

	sessionID, err := randomToken(24)
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken(24)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES(?,?,?,?,?,?,?)`,
		sessionID, adminID, now, now, ip, userAgent, csrf)
	if err != nil {
		return nil, err
	}
	return &Session{ID: sessionID, AdminID: adminID, Username: username, CSRF: csrf}, nil
}

func (s *Store) Logout(ctx context.Context, sessionID string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, sessionID)
	return err
}

// ValidateSession looks up a session by cookie value, checking TTL
// expiry, and performs a bounded last-seen update: only writes
// last_seen_at when it's staler than lastSeenInterval, so a busy admin
// doesn't cause a DB write on every single request.
func (s *Store) ValidateSession(ctx context.Context, sessionID string, ttl, lastSeenInterval time.Duration) (*Session, error) {
	var adminID int64
	var username, createdAt, lastSeenAt, csrf string
	err := s.DB.QueryRowContext(ctx,
		`SELECT s.admin_id, a.username, s.created_at, s.last_seen_at, s.csrf
		 FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.id=?`, sessionID).
		Scan(&adminID, &username, &createdAt, &lastSeenAt, &csrf)
	if err != nil {
		return nil, err
	}
	created, _ := time.Parse(time.RFC3339, createdAt)
	if time.Now().UTC().After(created.Add(ttl)) {
		return nil, sql.ErrNoRows
	}
	lastSeen, _ := time.Parse(time.RFC3339, lastSeenAt)
	if time.Since(lastSeen) > lastSeenInterval {
		s.DB.ExecContext(ctx, `UPDATE sessions SET last_seen_at=? WHERE id=?`,
			time.Now().UTC().Format(time.RFC3339), sessionID)
	}
	return &Session{ID: sessionID, AdminID: adminID, Username: username, CSRF: csrf}, nil
}

// RevokeOtherSessions deletes every session for adminID except keepID.
func (s *Store) RevokeOtherSessions(ctx context.Context, adminID int64, keepID string) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE admin_id=? AND id<>?`, adminID, keepID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SessionRow is one row of the Administration page's Sessions table,
// matching V1.1.1's own real administration_context() query
// (webapp.py, read directly): every session belonging to this admin,
// most recently active first.
type SessionRow struct {
	ID          string `json:"-"`
	CreatedAt   string `json:"created_at"`
	LastSeenAt  string `json:"last_seen_at"`
	IP          string `json:"ip"`
	UserAgent   string `json:"user_agent"`
	IsCurrent   bool   `json:"is_current"`
}

// ListSessions mirrors V1.1.1's own real query field-for-field:
// `SELECT id, created_at, last_seen_at, ip, user_agent FROM sessions
// WHERE admin_id=? ORDER BY last_seen_at DESC`.
func (s *Store) ListSessions(ctx context.Context, adminID int64, currentSessionID string) ([]SessionRow, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, created_at, last_seen_at, ip, user_agent FROM sessions WHERE admin_id=? ORDER BY last_seen_at DESC`,
		adminID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var row SessionRow
		if err := rows.Scan(&row.ID, &row.CreatedAt, &row.LastSeenAt, &row.IP, &row.UserAgent); err != nil {
			return nil, err
		}
		if row.IP == "" {
			row.IP = "unknown"
		}
		if row.UserAgent == "" {
			row.UserAgent = "unknown"
		}
		row.IsCurrent = row.ID == currentSessionID
		out = append(out, row)
	}
	return out, rows.Err()
}

// ChangePassword verifies currentPassword against the stored hash before
// setting newPassword -- same "must prove you know the current password"
// contract as app/v2/webapp.py's POST /api/session/password. The calling
// session (and any other session belonging to this admin) is left alone;
// the caller decides separately whether to also revoke other sessions.
func (s *Store) ChangePassword(ctx context.Context, adminID int64, currentPassword, newPassword string) error {
	var hash string
	if err := s.DB.QueryRowContext(ctx, `SELECT password_hash FROM admins WHERE id=?`, adminID).Scan(&hash); err != nil {
		return err
	}
	if !VerifyPassword(hash, currentPassword) {
		return ErrInvalidCredentials
	}
	newHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE admins SET password_hash=? WHERE id=?`, newHash, adminID)
	return err
}
