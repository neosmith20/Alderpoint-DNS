// Package auditlog is Administration's "Recent Administrative Activity"
// table, matching V1.1.1's own real admin_audit_log table
// (webapp.py's audit_log()/administration_context(), read directly
// from the shipped V1.1.1 package) field-for-field: at/admin_id/
// username/action/success/ip/detail, admin-scoped, most recent first.
//
// 2026-08-30: closed the real gap this comment used to disclose.
// internal/httpapi's audited() route-registration wrapper (see that
// file's own doc comment) now records EVERY mutating endpoint in the
// appliance -- client/group/policy CRUD, blocklists/custom rules,
// backup/import/restore, network config, replication, TLS/encryption,
// notifications, upstreams, local DNS -- not a hand-picked subset. A
// handful of security-relevant actions (login, password change,
// session revoke, Protection Control, Statistics settings save,
// Software Update apply) are recorded directly at their own call
// sites instead, with a richer, hand-written detail string than the
// generic wrapper can produce -- audited() is deliberately not applied
// to those same routes, so nothing is ever recorded twice.
package auditlog

import (
	"context"
	"database/sql"
	"time"
)

type Service struct {
	DB *sql.DB
}

// Entry is one row of GET /api/administration/audit-log or
// /api/administration/audit-log/all. Username is only populated by
// ListAll -- List's own admin-scoped callers already know whose entries
// they're looking at, and every existing row on disk before this field
// existed still has a real value in the `username` column (it's been
// written on every Record() call since the table was created), so
// there's no backfill gap.
type Entry struct {
	At       string `json:"at"`
	Username string `json:"username,omitempty"`
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

// ListAll backs the Advanced > Operations > Audit Log page: every
// administrator's recorded activity, most recent first, not just the
// calling admin's own (List's scope, kept as-is for backward
// compatibility -- see that method's own callers). This is the real,
// disclosed ceiling of what this appliance's audit trail can show today:
// at/username/action/success/ip/detail, exactly the columns admin_audit_log
// has -- no resource/correlation-id/before-after-diff columns exist yet
// (see the frontend page's own doc comment for the exact gap this leaves
// against the fuller Audit Log spec).
func (s *Service) ListAll(ctx context.Context, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT at, username, action, success, ip, detail FROM admin_audit_log ORDER BY id DESC LIMIT ?`,
		limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var success int
		if err := rows.Scan(&e.At, &e.Username, &e.Action, &success, &e.IP, &e.Detail); err != nil {
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
