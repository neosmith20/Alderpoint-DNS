package clientalias

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

func TestCreateListDeleteAlias(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	a, err := s.Create(ctx, "192.168.1.0/24", "Kids devices", "living room")
	if err != nil {
		t.Fatal(err)
	}
	if a.CIDR != "192.168.1.0/24" || a.DisplayName != "Kids devices" {
		t.Fatalf("unexpected alias = %+v", a)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != a.ID {
		t.Fatalf("List = %+v, want 1 entry matching created alias", list)
	}

	if err := s.Delete(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	list, err = s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list after delete, got %+v", list)
	}
}

func TestCreateRejectsDuplicateCIDR(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, "10.0.0.0/8", "Corp", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, "10.0.0.0/8", "Corp again", ""); err == nil {
		t.Fatal("expected an error for a duplicate CIDR")
	}
}

func TestCreateAcceptsBareIPAsSlash32(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	a, err := s.Create(ctx, "192.168.1.50", "Kitchen tablet", "")
	if err != nil {
		t.Fatal(err)
	}
	if a.CIDR != "192.168.1.50/32" {
		t.Errorf("CIDR = %q, want a real /32", a.CIDR)
	}
}

func TestCreateRejectsMissingDisplayName(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Create(context.Background(), "10.0.0.0/8", "", ""); err == nil {
		t.Fatal("expected an error for an empty display_name")
	}
}

func TestCreateRejectsInvalidCIDR(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Create(context.Background(), "not-a-cidr", "X", ""); err == nil {
		t.Fatal("expected an error for an invalid CIDR")
	}
}

func TestUpdateAndNotFound(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	a, err := s.Create(ctx, "172.16.0.0/12", "Guest", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, a.ID, "Guest network", "renamed"); err != nil {
		t.Fatal(err)
	}
	list, _ := s.List(ctx)
	if list[0].DisplayName != "Guest network" || list[0].Description != "renamed" {
		t.Fatalf("update did not persist: %+v", list[0])
	}
	if err := s.Update(ctx, 99999, "X", ""); err != ErrNotFound {
		t.Errorf("Update on missing id = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, 99999); err != ErrNotFound {
		t.Errorf("Delete on missing id = %v, want ErrNotFound", err)
	}
}

// TestResolverMostSpecificWins is the real precedence proof: a /32 host
// alias inside a broader /24 network alias must win for that one
// address, matching V1.1.1's own alias_for_client "most specific match"
// contract.
func TestResolverMostSpecificWins(t *testing.T) {
	r := NewResolver([]Alias{
		{CIDR: "192.168.1.0/24", DisplayName: "LAN"},
		{CIDR: "192.168.1.50/32", DisplayName: "Kitchen Tablet"},
	})
	if got := r.ResolveLabel("192.168.1.50"); got != "Kitchen Tablet" {
		t.Errorf("ResolveLabel(192.168.1.50) = %q, want the more specific alias", got)
	}
	if got := r.ResolveLabel("192.168.1.99"); got != "LAN" {
		t.Errorf("ResolveLabel(192.168.1.99) = %q, want the broader alias", got)
	}
	if got := r.ResolveLabel("10.0.0.1"); got != "" {
		t.Errorf("ResolveLabel(10.0.0.1) = %q, want empty (no match)", got)
	}
}

func TestResolverIgnoresUnparseableAddress(t *testing.T) {
	r := NewResolver([]Alias{{CIDR: "192.168.1.0/24", DisplayName: "LAN"}})
	if got := r.ResolveLabel("not-an-ip"); got != "" {
		t.Errorf("ResolveLabel(garbage) = %q, want empty", got)
	}
}
