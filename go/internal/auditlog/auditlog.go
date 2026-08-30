// Package auditlog is Administration's "Recent Administrative Activity"
// table, matching V1.1.1's own real admin_audit_log table
// (webapp.py's audit_log()/administration_context(), read directly
// from the shipped V1.1.1 package) field-for-field: at/admin_id/
// username/action/success/ip/detail, admin-scoped, most recent first.
//
// Deliberately scoped, disclosed rather than silently partial: V1.1.1
// recorded dozens of distinct action kinds across nearly every mutating
// endpoint in the whole appliance (client CRUD, policy changes, access
// rules, software updates, ...). Retrofitting a Record call into every
// one of those V2 handlers is a real, substantial cross-cutting change
// this pass does not attempt. What IS wired here (see each call site's
// own comment): login/logout, password change, session revocation,
// Protection Control toggle, Statistics settings save, and Software
// Update apply -- the security-relevant/session-relevant actions this
// very Administration page is otherwise silent about, not an
// appliance-wide activity log yet.
package auditlog

import (
	"context"
	"database/sql"
	"time"
)

type Service struct {
	DB *sql.DB
}

// Entry is one row of GET /api/administration/audit-log.
type Entry struct {
	At       string `json:"at"`
	Action   string `json:"action"`
	Success  bool   `json:"success"`
	IP       string `json:"ip"`
	Detail   string `json:"detail"`
}

// Record is best-effort: a failure to write an audit row must never fail
// the real action it's describing (matching V1.1.1's own audit_log(),
// which never raises). Callers pass 0 for adminID when the actor isn't
// yet authenticated (a failed login attempt) -- see the admin_id column
// being nullable-in-spirit even though a real admin row is required by
// the FK for a successful login's own entry.
func (s *Service) Record(ctx context.Context, adminID int64, username, action string, success bool, ip, detail string) {
	if s == nil || s.DB == nil || adminID <= 0 {
		return
	}
	s.DB.ExecContext(ctx,
		`INSERT INTO admin_audit_log (at, admin_id, username, action, success, ip, detail) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), adminID, username, action, boolToInt(success), ip, detail)
}

// List mirrors V1.1.1's own real query:
// `SELECT at, action, success, ip, detail FROM admin_audit_log WHERE
// admin_id=? ORDER BY id DESC LIMIT 25`.
func (s *Service) List(ctx context.Context, adminID int64, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 25
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT at, action, success, ip, detail FROM admin_audit_log WHERE admin_id=? ORDER BY id DESC LIMIT ?`,
		adminID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var success int
		if err := rows.Scan(&e.At, &e.Action, &success, &e.IP, &e.Detail); err != nil {
			return nil, err
		}
		e.Success = success != 0
		if e.IP == "" {
			e.IP = "unknown"
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
