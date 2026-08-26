package backup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/dbmigrate"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Service{DB: db, Dir: t.TempDir(), Version: "test"}
}

func seedOneLocalDNSRecord(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	now := "2026-01-01T00:00:00Z"
	_, err := db.Exec(`INSERT INTO local_dns_records(name, record_type, value, ttl, enabled, created_at, updated_at) VALUES(?,?,?,?,1,?,?)`,
		name, "A", "10.0.0.1", 300, now, now)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateProducesAListableBackup(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "host1.lan")

	info, err := s.Create(ctx, "manual")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if info.Reason != "manual" || info.Product != productID {
		t.Fatalf("unexpected manifest: %+v", info)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Filename != info.Filename {
		t.Fatalf("expected the new backup to be listed: %+v", list)
	}
}

func TestPreviewReadsManifestWithoutModifyingLiveData(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "host1.lan")
	info, err := s.Create(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := s.Preview(ctx, info.Filename)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if preview.ControlDBSchemaVersion != info.ControlDBSchemaVersion {
		t.Fatalf("preview manifest mismatch: %+v vs %+v", preview, info)
	}
	// Live data must be completely unaffected by a mere preview.
	var count int
	s.DB.QueryRowContext(ctx, `SELECT count(*) FROM local_dns_records`).Scan(&count)
	if count != 1 {
		t.Fatalf("expected live data untouched by Preview, got count=%d", count)
	}
}

func TestPreviewUnknownFileReturnsNotFound(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Preview(context.Background(), "does-not-exist.tar"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRestoreRoundTripsData(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "original.lan")
	backupOfOriginal, err := s.Create(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}

	// Change the live data after the backup was taken.
	if _, err := s.DB.Exec(`DELETE FROM local_dns_records`); err != nil {
		t.Fatal(err)
	}
	seedOneLocalDNSRecord(t, s.DB, "changed.lan")

	safety, err := s.Restore(ctx, backupOfOriginal.Filename)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if safety.Reason != "pre-restore-safety" {
		t.Fatalf("expected a real pre-restore safety backup, got %+v", safety)
	}
	// The safety backup itself must be listed too -- it's not a
	// throwaway, it's the operator's undo path.
	list, _ := s.List(ctx)
	if len(list) != 2 { // the original manual backup, plus the pre-restore safety backup
		t.Fatalf("expected 2 stored backups (manual + safety), got %d: %+v", len(list), list)
	}

	var name string
	if err := s.DB.QueryRowContext(ctx, `SELECT name FROM local_dns_records`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "original.lan" {
		t.Fatalf("expected the restored record to be 'original.lan', got %q", name)
	}
}

func TestRestoreOfMissingArchiveReturnsNotFound(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Restore(context.Background(), "no-such-file.tar"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound for a missing archive, got %v", err)
	}
}

func TestRestoreOfCorruptArchiveLeavesLiveDataUntouched(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "must-survive.lan")

	// A file that exists but isn't a valid tar archive at all.
	if err := s.ensureDir(); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(s.Dir, "corrupt.tar")
	if err := os.WriteFile(badPath, []byte("not a tar archive"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, err := s.Restore(ctx, "corrupt.tar")
	if err == nil {
		t.Fatal("expected an error restoring a corrupt archive")
	}

	// The live data must be completely unaffected -- this is the actual
	// "transactional restore" proof: a failure partway (here, at the
	// extraction step, before any transaction even begins) never
	// touches the live database.
	var name string
	if err := s.DB.QueryRowContext(ctx, `SELECT name FROM local_dns_records`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "must-survive.lan" {
		t.Fatalf("live data was corrupted by a failed restore attempt: got %q", name)
	}
}
