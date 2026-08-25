package dbmigrate

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func writeMigration(t *testing.T, dir, filename, sql string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(sql), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUpAppliesInOrderAndIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	writeMigration(t, dir, "0001_init.sql", `
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
`)
	writeMigration(t, dir, "0002_add_col.sql", `ALTER TABLE t ADD COLUMN extra TEXT;`)

	ctx := context.Background()
	v, err := Up(ctx, db, dir)
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if v != 2 {
		t.Fatalf("version = %d, want 2", v)
	}

	// Idempotent: running again applies nothing further and doesn't error.
	v2, err := Up(ctx, db, dir)
	if err != nil {
		t.Fatalf("second Up: %v", err)
	}
	if v2 != 2 {
		t.Fatalf("second version = %d, want 2", v2)
	}
}

func TestUpRollsBackFailedMigrationCleanly(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	writeMigration(t, dir, "0001_init.sql", `
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
`)
	ctx := context.Background()
	if _, err := Up(ctx, db, dir); err != nil {
		t.Fatalf("Up (0001): %v", err)
	}

	// Seed one row so the NOT-NULL-no-default ALTER below actually
	// violates a constraint (SQLite allows it silently on an empty table).
	if _, err := db.ExecContext(ctx, `INSERT INTO t(name) VALUES('seed')`); err != nil {
		t.Fatal(err)
	}

	dir2 := t.TempDir()
	writeMigration(t, dir2, "0002_bad.sql", `ALTER TABLE t ADD COLUMN required_field TEXT NOT NULL;`)

	if _, err := Up(ctx, db, dir2); err == nil {
		t.Fatal("expected the deliberately-invalid migration to fail")
	}

	v, err := CurrentVersion(ctx, db)
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if v != 1 {
		t.Fatalf("schema_migrations version after failed migration = %d, want 1 (unchanged)", v)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('t') WHERE name='required_field'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("required_field column should not exist after rollback")
	}

	var name string
	if err := db.QueryRowContext(ctx, `SELECT name FROM t WHERE id=1`).Scan(&name); err != nil {
		t.Fatalf("seed row should still exist after rollback: %v", err)
	}
	if name != "seed" {
		t.Fatalf("seed row corrupted: got %q", name)
	}
}
