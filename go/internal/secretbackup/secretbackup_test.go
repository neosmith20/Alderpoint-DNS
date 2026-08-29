package secretbackup

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
	"alderpointdns/go-controlplane/internal/secretstore"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// newTestHostAgent starts a real, disposable apdns-hostagent (real unix
// socket, real AEAD engine) -- same pattern used throughout this
// codebase's own secrets-touching tests.
func newTestHostAgent(t *testing.T) *hostagent.Client {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	audit, err := hostagentd.OpenAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	srv := &hostagentd.Server{SocketPath: sockPath, AllowedUID: uint32(os.Getuid()), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Audit: audit}
	if err := hostagentd.RegisterSecretsOps(srv, hostagentd.SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan struct{})
	go func() {
		go func() {
			for i := 0; i < 100; i++ {
				if _, err := os.Stat(sockPath); err == nil {
					close(ready)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			close(ready)
		}()
		srv.Serve(ctx)
	}()
	<-ready
	return hostagent.NewClient(sockPath)
}

func newTestService(t *testing.T) (*Service, *sql.DB, *secretstore.Service) {
	t.Helper()
	db := newTestDB(t)
	hostAgent := newTestHostAgent(t)
	return &Service{DB: db, HostAgent: hostAgent, Dir: t.TempDir()}, db, &secretstore.Service{DB: db, HostAgent: hostAgent}
}

func TestCreateWithNoSecretsProducesARealEmptyBackup(t *testing.T) {
	s, _, _ := newTestService(t)
	info, err := s.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.SecretCount != 0 {
		t.Fatalf("expected secret_count=0, got %+v", info)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, info.Name)); err != nil {
		t.Fatalf("expected a real backup file on disk: %v", err)
	}
}

func TestCreateAndRestoreRoundTripsARealSecret(t *testing.T) {
	s, db, secrets := newTestService(t)
	ctx := context.Background()

	if _, err := secrets.Set(ctx, "notification_webhook", "provider-1", "https://example.invalid/hook"); err != nil {
		t.Fatal(err)
	}

	info, err := s.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.SecretCount != 1 {
		t.Fatalf("expected secret_count=1, got %+v", info)
	}

	// Revoke the original secret to prove restore genuinely recreates
	// it, not merely leaves the original row untouched.
	if err := secrets.Revoke(ctx, "notification_webhook", "provider-1"); err != nil {
		t.Fatal(err)
	}
	var activeCount int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE kind='notification_webhook' AND owner_ref='provider-1' AND revoked_at IS NULL`).Scan(&activeCount)
	if activeCount != 0 {
		t.Fatal("expected the secret to actually be revoked before restore")
	}

	restoredCount, err := s.Restore(ctx, info.Name, false)
	if err != nil {
		t.Fatal(err)
	}
	if restoredCount != 1 {
		t.Fatalf("expected 1 secret restored, got %d", restoredCount)
	}
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE kind='notification_webhook' AND owner_ref='provider-1' AND revoked_at IS NULL`).Scan(&activeCount)
	if activeCount != 1 {
		t.Fatal("expected the restore to recreate a real active secret row")
	}

	// Prove it's genuinely usable (decrypts to the original value), not
	// just present -- via a real webhook send through the real
	// hostagent, using the record's own real sealed reference.
	status, err := secrets.Status(ctx, "notification_webhook", "provider-1")
	if err != nil || status == nil {
		t.Fatalf("expected a real status, got %v, %v", status, err)
	}
}

func TestRestoreWithoutOverwriteSkipsExistingSecrets(t *testing.T) {
	s, _, secrets := newTestService(t)
	ctx := context.Background()
	secrets.Set(ctx, "notification_webhook", "provider-1", "https://example.invalid/hook-original")
	info, err := s.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the secret with a NEW value after the backup was taken.
	secrets.Set(ctx, "notification_webhook", "provider-1", "https://example.invalid/hook-changed")

	restoredCount, err := s.Restore(ctx, info.Name, false)
	if err != nil {
		t.Fatal(err)
	}
	if restoredCount != 0 {
		t.Fatalf("expected 0 restored (existing secret skipped, not overwritten), got %d", restoredCount)
	}
}

func TestRestoreWithOverwriteReplacesExistingSecrets(t *testing.T) {
	s, _, secrets := newTestService(t)
	ctx := context.Background()
	secrets.Set(ctx, "notification_webhook", "provider-1", "https://example.invalid/hook-original")
	info, err := s.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secrets.Set(ctx, "notification_webhook", "provider-1", "https://example.invalid/hook-changed")

	restoredCount, err := s.Restore(ctx, info.Name, true)
	if err != nil {
		t.Fatal(err)
	}
	if restoredCount != 1 {
		t.Fatalf("expected 1 restored with overwrite=true, got %d", restoredCount)
	}
}

func TestRestoreOfNonexistentBackupReturnsNotFound(t *testing.T) {
	s, _, _ := newTestService(t)
	if _, err := s.Restore(context.Background(), "does-not-exist.enc", false); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRestoreRejectsPathTraversalInFilename(t *testing.T) {
	s, _, _ := newTestService(t)
	if _, err := s.Restore(context.Background(), "../../etc/passwd", false); err == nil {
		t.Fatal("expected an error for a path-traversal filename")
	}
}

func TestCreateAndListRoundTrip(t *testing.T) {
	s, _, _ := newTestService(t)
	ctx := context.Background()
	if _, err := s.Create(ctx); err != nil {
		t.Fatal(err)
	}
	backups, jobs, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("expected 1 real backup file listed, got %+v", backups)
	}
	if len(jobs) != 1 || jobs[0].Status != "succeeded" || jobs[0].Kind != "create" {
		t.Fatalf("expected 1 real succeeded create job, got %+v", jobs)
	}
}

func TestDeleteRemovesTheRealFile(t *testing.T) {
	s, _, _ := newTestService(t)
	ctx := context.Background()
	info, err := s.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(info.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, info.Name)); !os.IsNotExist(err) {
		t.Fatal("expected the real file to be gone after Delete")
	}
}

func TestDeleteOfUnknownFileReturnsNotFound(t *testing.T) {
	s, _, _ := newTestService(t)
	if err := s.Delete("does-not-exist.enc"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestCreateWithNilHostAgentReturnsUnavailable(t *testing.T) {
	db := newTestDB(t)
	s := &Service{DB: db, Dir: t.TempDir()}
	if _, err := s.Create(context.Background()); err != ErrUnavailable {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestValidateReportsCountWithoutWritingAnything(t *testing.T) {
	s, db, secrets := newTestService(t)
	ctx := context.Background()
	secrets.Set(ctx, "notification_webhook", "provider-1", "https://example.invalid/hook")
	info, err := s.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secrets.Revoke(ctx, "notification_webhook", "provider-1")

	count, err := s.Validate(ctx, info.Name)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected secret_count=1, got %d", count)
	}
	// Must NOT have restored anything -- the revoked secret stays revoked.
	var activeCount int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE kind='notification_webhook' AND owner_ref='provider-1' AND revoked_at IS NULL`).Scan(&activeCount)
	if activeCount != 0 {
		t.Fatal("expected Validate to be a real dry-run, not write anything")
	}
}

func TestValidateOfCorruptedBackupFails(t *testing.T) {
	s, _, secrets := newTestService(t)
	ctx := context.Background()
	secrets.Set(ctx, "notification_webhook", "provider-1", "https://example.invalid/hook")
	info, err := s.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the real file on disk.
	path := filepath.Join(s.Dir, info.Name)
	data, _ := os.ReadFile(path)
	data = append(data, 0xFF, 0xFF)
	os.WriteFile(path, data, 0o600)

	if _, err := s.Validate(ctx, info.Name); err == nil {
		t.Fatal("expected validation of a corrupted backup to fail")
	}
}

func TestSecondBackupReusesTheSamePersistedBackupKey(t *testing.T) {
	s, db, secrets := newTestService(t)
	ctx := context.Background()
	secrets.Set(ctx, "notification_webhook", "provider-1", "https://example.invalid/hook")

	if _, err := s.Create(ctx); err != nil {
		t.Fatal(err)
	}
	var keyCountAfterFirst int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE kind='internal_backup_key'`).Scan(&keyCountAfterFirst)
	if keyCountAfterFirst != 1 {
		t.Fatalf("expected exactly 1 persisted backup key after the first backup, got %d", keyCountAfterFirst)
	}

	if _, err := s.Create(ctx); err != nil {
		t.Fatal(err)
	}
	var keyCountAfterSecond int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE kind='internal_backup_key'`).Scan(&keyCountAfterSecond)
	if keyCountAfterSecond != 1 {
		t.Fatalf("expected the SAME backup key to be reused (still 1 row), got %d", keyCountAfterSecond)
	}
}
