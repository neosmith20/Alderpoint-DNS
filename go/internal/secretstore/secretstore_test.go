package secretstore

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE secrets (
			id TEXT PRIMARY KEY, kind TEXT NOT NULL, owner_ref TEXT NOT NULL,
			key_version INTEGER NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
			created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revoked_at TEXT NULL
		);
	`); err != nil {
		t.Fatal(err)
	}
	return db
}

// newTestHostAgent starts a real hostagentd.Server with the real
// secrets engine over a real unix socket -- this package's tests prove
// the full real round trip, not a mocked hostagent.Client.
func newTestHostAgent(t *testing.T) *hostagent.Client {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := hostagentd.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	s := &hostagentd.Server{SocketPath: sockPath, AllowedUID: uint32(os.Getuid()), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Audit: audit}
	if err := hostagentd.RegisterSecretsOps(s, hostagentd.SecretsConfig{KeyDir: t.TempDir()}); err != nil {
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
		s.Serve(ctx)
	}()
	<-ready
	return hostagent.NewClient(sockPath)
}

func TestSetStoresOnlyCiphertextNeverPlaintext(t *testing.T) {
	db := newTestDB(t)
	svc := &Service{DB: db, HostAgent: newTestHostAgent(t)}

	rec, err := svc.Set(context.Background(), "notification_secret", "provider-1", "https://hooks.example.com/very-secret-path")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID == "" || rec.KeyVersion == 0 {
		t.Fatalf("unexpected record: %+v", rec)
	}

	var ciphertext []byte
	if err := db.QueryRow(`SELECT ciphertext FROM secrets WHERE id=?`, rec.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}
	if strings.Contains(string(ciphertext), "hooks.example.com") {
		t.Fatal("stored row must never contain the plaintext value")
	}
}

func TestSetRevokesPriorVersionKeepingHistory(t *testing.T) {
	db := newTestDB(t)
	svc := &Service{DB: db, HostAgent: newTestHostAgent(t)}
	ctx := context.Background()

	first, err := svc.Set(ctx, "notification_secret", "provider-1", "old-value")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Set(ctx, "notification_secret", "provider-1", "new-value")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("expected a new secret row, not an in-place update")
	}

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM secrets WHERE kind='notification_secret' AND owner_ref='provider-1'`).Scan(&count)
	if count != 2 {
		t.Fatalf("expected both old and new rows kept (revoked, not deleted), got %d rows", count)
	}

	var revokedAt *string
	db.QueryRow(`SELECT revoked_at FROM secrets WHERE id=?`, first.ID).Scan(&revokedAt)
	if revokedAt == nil {
		t.Fatal("expected the first secret to be revoked after Set replaced it")
	}

	status, err := svc.Status(ctx, "notification_secret", "provider-1")
	if err != nil {
		t.Fatal(err)
	}
	if status == nil || status.ID != second.ID {
		t.Fatalf("expected Status to report the current (second) record, got %+v", status)
	}
}

func TestStatusReturnsNilNotErrorWhenNeverSet(t *testing.T) {
	db := newTestDB(t)
	svc := &Service{DB: db, HostAgent: newTestHostAgent(t)}
	status, err := svc.Status(context.Background(), "notification_secret", "nonexistent")
	if err != nil || status != nil {
		t.Fatalf("expected nil,nil for a never-set secret, got %+v, %v", status, err)
	}
}

func TestRevokeThenStatusReportsAbsent(t *testing.T) {
	db := newTestDB(t)
	svc := &Service{DB: db, HostAgent: newTestHostAgent(t)}
	ctx := context.Background()
	if _, err := svc.Set(ctx, "notification_secret", "provider-9", "value"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, "notification_secret", "provider-9"); err != nil {
		t.Fatal(err)
	}
	status, err := svc.Status(ctx, "notification_secret", "provider-9")
	if err != nil || status != nil {
		t.Fatalf("expected no current secret after Revoke, got %+v, %v", status, err)
	}
}

func TestRevokeOfNeverSetSecretIsNotAnError(t *testing.T) {
	db := newTestDB(t)
	svc := &Service{DB: db, HostAgent: newTestHostAgent(t)}
	if err := svc.Revoke(context.Background(), "notification_secret", "nonexistent"); err != nil {
		t.Fatalf("revoking a secret that was never set must not error: %v", err)
	}
}

func TestSetWithoutHostAgentReportsUnavailable(t *testing.T) {
	db := newTestDB(t)
	svc := &Service{DB: db}
	_, err := svc.Set(context.Background(), "k", "o", "v")
	if err != ErrUnavailable {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestSetRejectsEmptyValue(t *testing.T) {
	db := newTestDB(t)
	svc := &Service{DB: db, HostAgent: newTestHostAgent(t)}
	if _, err := svc.Set(context.Background(), "k", "o", ""); err == nil {
		t.Fatal("expected empty value to be rejected")
	}
}

func TestSealedParamsResolvesRealCiphertextForUse(t *testing.T) {
	db := newTestDB(t)
	agent := newTestHostAgent(t)
	svc := &Service{DB: db, HostAgent: agent}
	ctx := context.Background()
	if _, err := svc.Set(ctx, "notification_secret", "provider-1", "https://example.com/hook"); err != nil {
		t.Fatal(err)
	}
	params, err := svc.SealedParams(ctx, "notification_secret", "provider-1", map[string]any{"notify_kind": "webhook"})
	if err != nil {
		t.Fatal(err)
	}
	if params["ciphertext_b64"] == "" || params["nonce_b64"] == "" || params["notify_kind"] != "webhook" {
		t.Fatalf("unexpected params: %+v", params)
	}

	// Prove the params round-trip through the real hostagent's
	// notify_test op end-to-end (not just that fields are non-empty).
	var out map[string]any
	if err := agent.Call(ctx, hostagent.OpSecretsNotifyTest, params, &out); err != nil {
		t.Fatal(err)
	}
}

func TestSealedParamsErrorsWhenNoSecretSet(t *testing.T) {
	db := newTestDB(t)
	svc := &Service{DB: db, HostAgent: newTestHostAgent(t)}
	_, err := svc.SealedParams(context.Background(), "notification_secret", "nonexistent", nil)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
