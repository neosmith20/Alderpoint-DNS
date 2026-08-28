package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func newTestService(t *testing.T) *Service {
	return &Service{DB: newTestDB(t)}
}

// newTestServiceWithSecrets wires a real apdns-hostagent (real unix
// socket, real AEAD engine) so secret-touching tests prove the full
// real path, not a mock.
func newTestServiceWithSecrets(t *testing.T) *Service {
	t.Helper()
	db := newTestDB(t)
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	audit, err := hostagentd.OpenAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
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
	return &Service{DB: db, Secrets: &secretstore.Service{DB: db, HostAgent: hostagent.NewClient(sockPath)}}
}

func rawConfig(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func TestListNeverReturnsNilOnEmpty(t *testing.T) {
	s := newTestService(t)
	list, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if list == nil {
		t.Fatal("expected an empty slice, not nil (would JSON-marshal to null and break the frontend grid)")
	}
}

func TestCreateValidatesKind(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Create(context.Background(), "carrier-pigeon", "Test", nil); err == nil {
		t.Fatal("expected an error for an invalid kind")
	}
}

func TestCreateValidatesDisplayName(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Create(context.Background(), "webhook", "  ", nil); err == nil {
		t.Fatal("expected an error for an empty display_name")
	}
}

func TestCreateRejectsIncompleteSMTPConfig(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Create(context.Background(), "email_smtp", "Alerts", rawConfig(map[string]any{"host": "smtp.example.com"})); err == nil {
		t.Fatal("expected an error for an SMTP config missing port/from_addr/to_addr")
	}
}

func TestCreateAcceptsCompleteSMTPConfig(t *testing.T) {
	s := newTestService(t)
	p, err := s.Create(context.Background(), "email_smtp", "Alerts", rawConfig(SMTPConfig{
		Host: "smtp.example.com", Port: 587, FromAddr: "alerts@example.com", ToAddr: "owner@example.com", Username: "alerts",
	}))
	if err != nil {
		t.Fatal(err)
	}
	var cfg SMTPConfig
	if err := json.Unmarshal(p.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "smtp.example.com" || cfg.Port != 587 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestCreateAndListRoundTrip(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "slack", "Ops Slack", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProviderID == "" || !p.Enabled || p.HasSecret {
		t.Fatalf("unexpected created provider: %+v", p)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ProviderID != p.ProviderID || list[0].Kind != "slack" {
		t.Fatalf("expected the created provider in the list, got %+v", list)
	}
}

func TestSetEnabledTogglesAndPersists(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnabled(ctx, p.ProviderID, false); err != nil {
		t.Fatal(err)
	}
	list, _ := s.List(ctx)
	if list[0].Enabled {
		t.Fatalf("expected the provider to be disabled, got %+v", list[0])
	}
}

func TestSetEnabledOfUnknownProviderReturnsNotFound(t *testing.T) {
	s := newTestService(t)
	if err := s.SetEnabled(context.Background(), "does-not-exist", true); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteRemovesTheProvider(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "pushover", "On-call", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, p.ProviderID); err != nil {
		t.Fatal(err)
	}
	list, _ := s.List(ctx)
	if len(list) != 0 {
		t.Fatalf("expected the provider to be gone, got %+v", list)
	}
}

func TestDeleteOfUnknownProviderReturnsNotFound(t *testing.T) {
	s := newTestService(t)
	if err := s.Delete(context.Background(), "does-not-exist"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestTwoProvidersGetDistinctIDs(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	a, err := s.Create(ctx, "webhook", "A", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Create(ctx, "webhook", "B", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.ProviderID == b.ProviderID {
		t.Fatalf("expected distinct provider ids, got %q twice", a.ProviderID)
	}
}

// --- secret-backed workflow (real hostagent) ----------------------------

func TestSetSecretMarksHasSecretAndNeverExposesValue(t *testing.T) {
	s := newTestServiceWithSecrets(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret(ctx, p.ProviderID, "https://hooks.example.com/super-secret"); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !list[0].HasSecret {
		t.Fatal("expected has_secret=true after SetSecret")
	}
	raw, _ := json.Marshal(list[0])
	if strings.Contains(string(raw), "super-secret") {
		t.Fatal("List() response must never contain the plaintext secret value")
	}
}

func TestSetSecretOfUnknownProviderReturnsNotFound(t *testing.T) {
	s := newTestServiceWithSecrets(t)
	if err := s.SetSecret(context.Background(), "does-not-exist", "value"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSetSecretRejectsEmptyValue(t *testing.T) {
	s := newTestServiceWithSecrets(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret(ctx, p.ProviderID, "   "); err == nil {
		t.Fatal("expected empty secret value to be rejected")
	}
}

func TestRevokeSecretClearsHasSecret(t *testing.T) {
	s := newTestServiceWithSecrets(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret(ctx, p.ProviderID, "https://hooks.example.com/x"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSecret(ctx, p.ProviderID); err != nil {
		t.Fatal(err)
	}
	list, _ := s.List(ctx)
	if list[0].HasSecret {
		t.Fatal("expected has_secret=false after RevokeSecret")
	}
	if _, err := s.Test(ctx, p.ProviderID); err == nil {
		t.Fatal("expected Test to fail after the secret was revoked")
	}
}

func TestDeleteProviderRevokesItsSecret(t *testing.T) {
	s := newTestServiceWithSecrets(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret(ctx, p.ProviderID, "https://hooks.example.com/x"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, p.ProviderID); err != nil {
		t.Fatal(err)
	}
	status, err := s.Secrets.Status(ctx, SecretKind, p.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	if status != nil {
		t.Fatal("expected the secret to be revoked once its owning provider is deleted")
	}
}

func TestTestSendsRealWebhookUsingStoredSecret(t *testing.T) {
	var receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newTestServiceWithSecrets(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret(ctx, p.ProviderID, srv.URL); err != nil {
		t.Fatal(err)
	}
	result, err := s.Test(ctx, p.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("expected ok=true, got %+v", result)
	}
	if receivedBody == "" {
		t.Fatal("the real disposable webhook server never received a request")
	}
}

func TestTestWithoutSecretIsRejected(t *testing.T) {
	s := newTestServiceWithSecrets(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Test(ctx, p.ProviderID); err == nil {
		t.Fatal("expected Test to be rejected before any secret is configured")
	}
}
