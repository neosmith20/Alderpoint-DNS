// Package dbmigrate applies versioned SQLite migrations, each inside its
// own transaction, and proves that a failed migration rolls back cleanly
// rather than leaving the schema half-applied.
package dbmigrate

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Migration struct {
	Version int
	Name    string
	SQL     string
}

func Load(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		versionStr, _, _ := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(versionStr)
		if err != nil {
			return nil, fmt.Errorf("bad migration filename %q: %w", e.Name(), err)
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, Migration{Version: v, Name: e.Name(), SQL: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// CurrentVersion returns 0 if schema_migrations doesn't exist yet.
func CurrentVersion(ctx context.Context, db *sql.DB) (int, error) {
	var exists int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'`).Scan(&exists)
	if err != nil {
		return 0, err
	}
	if exists == 0 {
		return 0, nil
	}
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

// Up applies every migration in dir with version > current, each inside
// its own transaction. On failure it rolls back that one transaction
// (leaving the DB exactly at the last successful version) and returns the
// error -- this is the guarantee tests/acceptance.py's rollback test
// exercises against schema/rollback_test/0003_bad_migration.sql.
func Up(ctx context.Context, db *sql.DB, dir string) (int, error) {
	migs, err := Load(dir)
	if err != nil {
		return 0, err
	}
	cur, err := CurrentVersion(ctx, db)
	if err != nil {
		return 0, err
	}
	for _, m := range migs {
		if m.Version <= cur {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return cur, err
		}
		if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
			tx.Rollback()
			return cur, fmt.Errorf("migration %s failed (rolled back): %w", m.Name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`,
			m.Version, time.Now().UTC().Format(time.RFC3339)); err != nil {
			tx.Rollback()
			return cur, fmt.Errorf("migration %s record failed (rolled back): %w", m.Name, err)
		}
		if err := tx.Commit(); err != nil {
			return cur, fmt.Errorf("migration %s commit failed: %w", m.Name, err)
		}
		cur = m.Version
	}
	return cur, nil
}
