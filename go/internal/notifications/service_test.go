package notifications

import (
	"context"
	"database/sql"
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
	return &Service{DB: db}
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
	if _, err := s.Create(context.Background(), "carrier-pigeon", "Test", "https://example.com"); err == nil {
		t.Fatal("expected an error for an invalid kind")
	}
}

func TestCreateValidatesDisplayName(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Create(context.Background(), "webhook", "  ", "https://example.com"); err == nil {
		t.Fatal("expected an error for an empty display_name")
	}
}

func TestCreateAndListRoundTrip(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "slack", "Ops Slack", "https://hooks.slack.example/xyz")
	if err != nil {
		t.Fatal(err)
	}
	if p.ProviderID == "" || !p.Enabled {
		t.Fatalf("unexpected created provider: %+v", p)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ProviderID != p.ProviderID || list[0].Kind != "slack" || list[0].Endpoint != "https://hooks.slack.example/xyz" {
		t.Fatalf("expected the created provider in the list, got %+v", list)
	}
}

func TestSetEnabledTogglesAndPersists(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Test", "https://example.com/hook")
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
	p, err := s.Create(ctx, "pushover", "On-call", "user-key-placeholder")
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
	a, err := s.Create(ctx, "webhook", "A", "https://a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Create(ctx, "webhook", "B", "https://b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a.ProviderID == b.ProviderID {
		t.Fatalf("expected distinct provider ids, got %q twice", a.ProviderID)
	}
}
