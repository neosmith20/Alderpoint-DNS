package appliancesettings

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"alderpointdns/go-controlplane/internal/dbmigrate"

	_ "modernc.org/sqlite"
)

func newTestService(t *testing.T) *Service {
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
	return &Service{DB: db}
}

func TestGetReturnsEmptyUntilSet(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	name, err := s.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if name != "" {
		t.Fatalf("expected no override before Set, got %q", name)
	}
	if err := s.Set(ctx, "Front Office DNS"); err != nil {
		t.Fatal(err)
	}
	name, err = s.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if name != "Front Office DNS" {
		t.Fatalf("Get = %q, want the real saved value", name)
	}
}
