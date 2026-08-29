package httpapi

// HTTP-layer proof for the real Secret Backups routes.

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
	"alderpointdns/go-controlplane/internal/secretbackup"
	"alderpointdns/go-controlplane/internal/secretstore"
)

func newSecretBackupTestHostAgent(t *testing.T) *hostagent.Client {
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

func newSecretBackupTestServer(t *testing.T) (*Server, *secretstore.Service) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	hostAgent := newSecretBackupTestHostAgent(t)
	return &Server{
		SecretBackup: &secretbackup.Service{DB: db, HostAgent: hostAgent, Dir: t.TempDir()},
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, &secretstore.Service{DB: db, HostAgent: hostAgent}
}

func TestSecretBackupFullLifecycleHTTP(t *testing.T) {
	s, secrets := newSecretBackupTestServer(t)
	ctx := context.Background()
	if _, err := secrets.Set(ctx, "notification_webhook", "provider-1", "https://example.invalid/hook"); err != nil {
		t.Fatal(err)
	}

	code, body := doHandler(t, s.handleCreateSecretBackup, "POST", "", nil)
	if code != 201 {
		t.Fatalf("create: code=%d body=%+v", code, body)
	}
	backupInfo := body["backup"].(map[string]any)
	name := backupInfo["name"].(string)
	if backupInfo["secret_count"] != float64(1) {
		t.Fatalf("expected secret_count=1, got %+v", backupInfo)
	}

	code, body = doHandler(t, s.handleListSecretBackups, "GET", "", nil)
	if code != 200 {
		t.Fatalf("list: code=%d", code)
	}
	backups, _ := body["backups"].([]any)
	if len(backups) != 1 {
		t.Fatalf("expected 1 real backup listed, got %+v", backups)
	}

	code, body = doHandler(t, s.handleValidateSecretBackup, "POST", "", map[string]string{"name": name})
	if code != 200 {
		t.Fatalf("validate: code=%d body=%+v", code, body)
	}
	if body["secret_count"] != float64(1) {
		t.Fatalf("expected secret_count=1 from validate, got %+v", body)
	}

	secrets.Revoke(ctx, "notification_webhook", "provider-1")
	code, body = doHandler(t, s.handleRestoreSecretBackup, "POST", `{"overwrite":false}`, map[string]string{"name": name})
	if code != 200 {
		t.Fatalf("restore: code=%d body=%+v", code, body)
	}
	if body["restored_count"] != float64(1) {
		t.Fatalf("expected restored_count=1, got %+v", body)
	}

	code, _ = doHandler(t, s.handleDeleteSecretBackup, "DELETE", "", map[string]string{"name": name})
	if code != 200 {
		t.Fatalf("delete: code=%d", code)
	}
	code, body = doHandler(t, s.handleListSecretBackups, "GET", "", nil)
	backups, _ = body["backups"].([]any)
	if len(backups) != 0 {
		t.Fatalf("expected the backup to be gone after delete, got %+v", backups)
	}
}

func TestSecretBackupRestoreOfUnknownNameReturnsNotFound(t *testing.T) {
	s, _ := newSecretBackupTestServer(t)
	code, _ := doHandler(t, s.handleRestoreSecretBackup, "POST", "{}", map[string]string{"name": "does-not-exist.enc"})
	if code != 404 {
		t.Fatalf("expected 404, got %d", code)
	}
}

func TestSecretBackupRouteWhenUnconfiguredReturnsUnavailable(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	code, _ := doHandler(t, s.handleListSecretBackups, "GET", "", nil)
	if code != 503 {
		t.Fatalf("expected 503, got %d", code)
	}
}

func TestSecretBackupRestoreRejectsPathTraversalHTTP(t *testing.T) {
	s, _ := newSecretBackupTestServer(t)
	code, body := doHandler(t, s.handleRestoreSecretBackup, "POST", "{}", map[string]string{"name": "../../etc/passwd"})
	if code == 200 {
		t.Fatalf("expected a real rejection for a path-traversal name, not a silent 200: %+v", body)
	}
}
