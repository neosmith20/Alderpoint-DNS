// Package updatehistory backs Software Updates' real "Update History"
// section -- previously only the current version and the most recently
// staged candidate were tracked anywhere, with no record of past apply
// attempts at all.
package updatehistory

import (
	"context"
	"database/sql"
	"time"
)

type Entry struct {
	ID          int64  `json:"id"`
	At          string `json:"at"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	Source      string `json:"source"`
	Result      string `json:"result"`
	BackupRef   string `json:"backup_ref"`
	Error       string `json:"error"`
}

type RecordInput struct {
	FromVersion, ToVersion, Source, Result, BackupRef, Error string
}

type Service struct {
	DB *sql.DB
}

// Record is best-effort: a failure to log history must never fail the
// real update it's describing (matching internal/auditlog.Record's own
// contract).
func (s *Service) Record(ctx context.Context, in RecordInput) {
	if s == nil || s.DB == nil {
		return
	}
	s.DB.ExecContext(ctx,
		`INSERT INTO update_history (at, from_version, to_version, source, result, backup_ref, error) VALUES (?,?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339), in.FromVersion, in.ToVersion, in.Source, in.Result, in.BackupRef, in.Error)
}

func (s *Service) List(ctx context.Context, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, at, from_version, to_version, source, result, backup_ref, error FROM update_history ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.At, &e.FromVersion, &e.ToVersion, &e.Source, &e.Result, &e.BackupRef, &e.Error); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
