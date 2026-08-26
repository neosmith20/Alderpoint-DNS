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

	safety, err := s.Restore(ctx, backupOfOriginal.Filename, nil)
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

func TestEveryBackedUpTableBelongsToExactlyOneCategory(t *testing.T) {
	seen := map[string]int{}
	for _, tabs := range Categories {
		for _, tab := range tabs {
			seen[tab]++
		}
	}
	for _, table := range tablesToBackUp {
		if seen[table] != 1 {
			t.Fatalf("table %q belongs to %d categories, want exactly 1", table, seen[table])
		}
	}
	for table := range seen {
		found := false
		for _, t2 := range tablesToBackUp {
			if t2 == table {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("category table %q is not in tablesToBackUp", table)
		}
	}
}

func TestCreateManifestReportsRealTableCounts(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "host1.lan")
	seedOneLocalDNSRecord(t, s.DB, "host2.lan")

	info, err := s.Create(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if info.TableCounts["local_dns_records"] != 2 {
		t.Fatalf("expected local_dns_records count=2 in manifest, got %+v", info.TableCounts)
	}
	if info.TableCounts["custom_rules"] != 0 {
		t.Fatalf("expected custom_rules count=0, got %d", info.TableCounts["custom_rules"])
	}
}

func seedOneCustomRule(t *testing.T, db *sql.DB, pattern string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO custom_rules(rule_type, pattern, enabled, priority, created_at) VALUES('block', ?, 1, 0, '2026-01-01T00:00:00Z')`, pattern)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSelectiveRestoreOnlyTouchesChosenCategory(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "original.lan")
	seedOneCustomRule(t, s.DB, "original.example.com")
	backupOfOriginal, err := s.Create(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}

	// Change both categories' live data after the backup.
	if _, err := s.DB.Exec(`DELETE FROM local_dns_records`); err != nil {
		t.Fatal(err)
	}
	seedOneLocalDNSRecord(t, s.DB, "changed.lan")
	if _, err := s.DB.Exec(`DELETE FROM custom_rules`); err != nil {
		t.Fatal(err)
	}
	seedOneCustomRule(t, s.DB, "changed.example.com")

	// Restore only local_dns -- custom_rules must be left exactly as it
	// is now ("changed.example.com"), not rolled back to the backup.
	if _, err := s.Restore(ctx, backupOfOriginal.Filename, []string{"local_dns"}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	var dnsName string
	if err := s.DB.QueryRowContext(ctx, `SELECT name FROM local_dns_records`).Scan(&dnsName); err != nil {
		t.Fatal(err)
	}
	if dnsName != "original.lan" {
		t.Fatalf("expected local_dns restored to 'original.lan', got %q", dnsName)
	}

	var rulePattern string
	if err := s.DB.QueryRowContext(ctx, `SELECT pattern FROM custom_rules`).Scan(&rulePattern); err != nil {
		t.Fatal(err)
	}
	if rulePattern != "changed.example.com" {
		t.Fatalf("selective restore touched an unselected category: custom_rules pattern is %q, want unchanged 'changed.example.com'", rulePattern)
	}
}

func TestRestoreRejectsUnknownCategory(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "host1.lan")
	backupOfOriginal, err := s.Create(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Restore(ctx, backupOfOriginal.Filename, []string{"not_a_real_category"}); err == nil {
		t.Fatal("expected an error for an unknown category")
	}
}

func TestRetentionMaxCountPrunesOldestManualBackupsOnly(t *testing.T) {
	s := newTestService(t)
	s.RetentionMaxCount = 2
	ctx := context.Background()
	seedOneLocalDNSRecord(t, s.DB, "host1.lan")

	var last BackupInfo
	for i := 0; i < 4; i++ {
		info, err := s.Create(ctx, "manual")
		if err != nil {
			t.Fatal(err)
		}
		last = info
	}
	// A safety backup must never be pruned by manual-backup retention.
	safety, err := s.Restore(ctx, last.Filename, nil)
	if err != nil {
		t.Fatal(err)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manualCount, safetyFound := 0, false
	for _, b := range list {
		if b.Reason == "manual" {
			manualCount++
		}
		if b.Filename == safety.Filename {
			safetyFound = true
		}
	}
	if manualCount > s.RetentionMaxCount {
		t.Fatalf("expected at most %d manual backups after retention, got %d: %+v", s.RetentionMaxCount, manualCount, list)
	}
	if !safetyFound {
		t.Fatalf("expected the pre-restore safety backup to survive retention pruning, got %+v", list)
	}
}

func TestRestoreOfMissingArchiveReturnsNotFound(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Restore(context.Background(), "no-such-file.tar", nil); err != ErrNotFound {
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

	_, err := s.Restore(ctx, "corrupt.tar", nil)
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
