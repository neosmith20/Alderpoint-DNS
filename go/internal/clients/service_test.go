package clients

import (
	"context"
	"database/sql"
	"errors"
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

func TestCreateClientAndList(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, err := s.CreateClient(ctx, "Alice's Laptop", "Alice's personal machine")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != id || list[0].Name != "Alice's Laptop" || !list[0].Enabled {
		t.Fatalf("unexpected list: %+v", list)
	}
	if len(list[0].Identifiers) != 0 || len(list[0].Groups) != 0 {
		t.Fatalf("expected empty identifiers/groups initially: %+v", list[0])
	}
}

func TestAddIdentifierValidatesFormat(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, _ := s.CreateClient(ctx, "X", "")

	cases := []struct {
		kind, value string
		wantErr     bool
	}{
		{"ipv4", "192.168.1.5", false},
		{"ipv4", "not-an-ip", true},
		{"ipv4", "::1", true}, // ipv6 value under ipv4 kind must be rejected
		{"ipv6", "2001:db8::1", false},
		{"ipv6", "192.168.1.5", true},
		{"ipv4_cidr", "192.168.0.0/24", false},
		{"ipv4_cidr", "2001:db8::/32", true},
		{"ipv6_cidr", "2001:db8::/32", false},
		{"clientid", "anything-opaque", false},
		{"bogus-kind", "x", true},
	}
	for _, c := range cases {
		err := s.AddIdentifier(ctx, id, c.kind, c.value)
		if (err != nil) != c.wantErr {
			t.Errorf("AddIdentifier(%q, %q): err=%v, wantErr=%v", c.kind, c.value, err, c.wantErr)
		}
	}
}

func TestAddIdentifierRejectsDuplicateAndUnknownClient(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, _ := s.CreateClient(ctx, "X", "")
	if err := s.AddIdentifier(ctx, id, "ipv4", "10.0.0.5"); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := s.AddIdentifier(ctx, id, "ipv4", "10.0.0.5"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate identifier should be ErrConflict, got %v", err)
	}
	if err := s.AddIdentifier(ctx, 99999, "ipv4", "10.0.0.6"); err != ErrNotFound {
		t.Fatalf("unknown client should be ErrNotFound, got %v", err)
	}
}

func TestCreateGroupAndMembership(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.CreateGroup(ctx, "kids", "Kids", 10); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	clientID, _ := s.CreateClient(ctx, "Tablet", "")
	if err := s.AddToGroup(ctx, clientID, "kids"); err != nil {
		t.Fatalf("AddToGroup: %v", err)
	}
	// Idempotent: adding the same client to the same group twice must not error.
	if err := s.AddToGroup(ctx, clientID, "kids"); err != nil {
		t.Fatalf("re-adding to the same group should be a no-op, got %v", err)
	}

	groups, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].Members) != 1 || groups[0].Members[0].Name != "Tablet" {
		t.Fatalf("unexpected groups: %+v", groups)
	}

	clientList, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientList[0].Groups) != 1 || clientList[0].Groups[0].GroupID != "kids" {
		t.Fatalf("expected the client to show its group membership: %+v", clientList[0])
	}
}

func TestAddToGroupRejectsUnknownClientOrGroup(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.CreateGroup(ctx, "g1", "G1", 0); err != nil {
		t.Fatal(err)
	}
	clientID, _ := s.CreateClient(ctx, "X", "")

	if err := s.AddToGroup(ctx, 99999, "g1"); err != ErrNotFound {
		t.Fatalf("unknown client should be ErrNotFound, got %v", err)
	}
	if err := s.AddToGroup(ctx, clientID, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown group should be ErrNotFound, got %v", err)
	}
}

// TestListMethodsNeverReturnNilOnEmpty guards against a real bug found by
// the Chromium suite: Go's encoding/json marshals a nil slice as JSON
// `null`, not `[]`; the frontend's shared DataGrid crashes on
// `null.length`. A `var x []T` that's never appended to is nil even
// though the JSON contract promises an array -- ListGroups/ListClients
// must always return a non-nil (possibly empty) slice.
func TestListMethodsNeverReturnNilOnEmpty(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	groups, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if groups == nil {
		t.Fatal("ListGroups on an empty table must return a non-nil empty slice, not nil (would marshal to JSON null)")
	}
	clientList, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if clientList == nil {
		t.Fatal("ListClients on an empty table must return a non-nil empty slice, not nil (would marshal to JSON null)")
	}
}

func TestCreateGroupRejectsDuplicateName(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.CreateGroup(ctx, "a", "Same", 0); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateGroup(ctx, "b", "Same", 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate group name should be ErrConflict, got %v", err)
	}
}
