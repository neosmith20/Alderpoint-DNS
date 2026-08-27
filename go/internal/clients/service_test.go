package clients

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/clientid"
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
		{"clientid", "anything-opaque", true},                                   // no longer opaque -- see TestAddIdentifierValidatesClientIDFormat
		{"clientid", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false}, // real 48-hex
		{"clientid", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false}, // real 64-hex
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

func TestAddIdentifierValidatesClientIDFormat(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, _ := s.CreateClient(ctx, "X", "")

	bad := []string{
		"", "short", strings.Repeat("a", 47), strings.Repeat("a", 49),
		strings.Repeat("a", 65), strings.ToUpper(strings.Repeat("a", 48)),
		strings.Repeat("g", 48), // 'g' not hex
	}
	for _, v := range bad {
		if err := s.AddIdentifier(ctx, id, "clientid", v); !errors.Is(err, ErrValidation) {
			t.Errorf("AddIdentifier(clientid, %q): expected ErrValidation, got %v", v, err)
		}
	}
}

func TestGenerateClientIDProducesRealDistinctValuesAndPersists(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, _ := s.CreateClient(ctx, "Phone", "")

	a, err := s.GenerateClientID(ctx, id, clientid.Bits192, "primary")
	if err != nil {
		t.Fatalf("GenerateClientID(192): %v", err)
	}
	if len(a.Value) != 48 {
		t.Fatalf("expected 48-hex value, got %d chars: %q", len(a.Value), a.Value)
	}
	if a.DoHPath == "" || a.SNIHostname == "" {
		t.Fatalf("expected DoHPath/SNIHostname to be populated, got %+v", a)
	}

	b, err := s.GenerateClientID(ctx, id, clientid.Bits256, "backup")
	if err != nil {
		t.Fatalf("GenerateClientID(256): %v", err)
	}
	if len(b.Value) != 64 {
		t.Fatalf("expected 64-hex value, got %d chars: %q", len(b.Value), b.Value)
	}
	if a.Value == b.Value {
		t.Fatal("two generated ClientIDs must not collide")
	}

	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list[0].Identifiers) != 2 {
		t.Fatalf("expected 2 persisted identifiers, got %+v", list[0].Identifiers)
	}
}

func TestRevokeIdentifierStopsItFromCountingAsActiveButKeepsTheRow(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, _ := s.CreateClient(ctx, "X", "")
	c, err := s.GenerateClientID(ctx, id, clientid.Bits192, "")
	if err != nil {
		t.Fatal(err)
	}

	active, err := s.AllActiveClientIdentities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("expected 1 active identity before revoke, got %d", len(active))
	}

	if err := s.RevokeIdentifier(ctx, c.ID); err != nil {
		t.Fatalf("RevokeIdentifier: %v", err)
	}

	active, err = s.AllActiveClientIdentities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("expected 0 active identities after revoke, got %+v", active)
	}

	// The row itself must still exist, with revoked_at set (not deleted).
	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list[0].Identifiers) != 1 {
		t.Fatalf("expected the revoked row to still be present, got %+v", list[0].Identifiers)
	}
	if list[0].Identifiers[0].RevokedAt == "" {
		t.Fatal("expected revoked_at to be set")
	}

	if err := s.RevokeIdentifier(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking an already-revoked identifier should be ErrNotFound (no active row matched), got %v", err)
	}
}

func TestRegenerateIdentifierIsAtomicOldRevokedNewActive(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, _ := s.CreateClient(ctx, "X", "")
	original, err := s.GenerateClientID(ctx, id, clientid.Bits256, "primary")
	if err != nil {
		t.Fatal(err)
	}

	fresh, err := s.RegenerateIdentifier(ctx, original.ID)
	if err != nil {
		t.Fatalf("RegenerateIdentifier: %v", err)
	}
	if fresh.Value == original.Value {
		t.Fatal("regenerated value must differ from the original")
	}
	if len(fresh.Value) != 64 {
		t.Fatalf("expected regeneration to preserve the original's bit strength (64-hex), got %d chars", len(fresh.Value))
	}
	if fresh.Label != "primary" {
		t.Fatalf("expected the label to carry over, got %q", fresh.Label)
	}

	active, err := s.AllActiveClientIdentities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].Value != fresh.Value {
		t.Fatalf("expected exactly the new value to be active, got %+v", active)
	}

	if _, err := s.RegenerateIdentifier(ctx, original.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("regenerating an already-revoked identifier should be ErrNotFound, got %v", err)
	}
}

func TestDeleteIdentifierHardDeletesTheRow(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, _ := s.CreateClient(ctx, "X", "")
	c, err := s.GenerateClientID(ctx, id, clientid.Bits192, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteIdentifier(ctx, c.ID); err != nil {
		t.Fatalf("DeleteIdentifier: %v", err)
	}
	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list[0].Identifiers) != 0 {
		t.Fatalf("expected the row to be gone entirely, got %+v", list[0].Identifiers)
	}
	if err := s.DeleteIdentifier(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting a non-existent identifier should be ErrNotFound, got %v", err)
	}
}

func TestDomainOverridesCRUDAndCompileInput(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, _ := s.CreateClient(ctx, "X", "")
	if _, err := s.GenerateClientID(ctx, id, clientid.Bits192, ""); err != nil {
		t.Fatal(err)
	}

	if _, err := s.AddDomainOverride(ctx, id, "block", "Blocked.Example.com"); err != nil {
		t.Fatalf("AddDomainOverride(block): %v", err)
	}
	if _, err := s.AddDomainOverride(ctx, id, "allow", "allowed.example.com"); err != nil {
		t.Fatalf("AddDomainOverride(allow): %v", err)
	}
	if _, err := s.AddDomainOverride(ctx, id, "bogus", "x.example.com"); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for a bogus override_type, got %v", err)
	}

	overrides, err := s.DomainOverridesForClient(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(overrides) != 2 {
		t.Fatalf("expected 2 overrides, got %+v", overrides)
	}
	// Domain stored lowercased -- proven, not assumed.
	found := false
	for _, o := range overrides {
		if o.OverrideType == "block" && o.Pattern == "blocked.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the block override to be stored lowercased, got %+v", overrides)
	}

	active, err := s.AllActiveClientIdentities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || len(active[0].Overrides) != 2 {
		t.Fatalf("expected the active identity to carry both overrides, got %+v", active)
	}

	if err := s.DeleteDomainOverride(ctx, overrides[0].ID); err != nil {
		t.Fatalf("DeleteDomainOverride: %v", err)
	}
	overrides, err = s.DomainOverridesForClient(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(overrides) != 1 {
		t.Fatalf("expected 1 override after delete, got %+v", overrides)
	}
}

// TestClientIDPersistsAcrossAFreshOpen is the "restart-persistence"
// proof: a brand-new *Service (fresh sql.Open against the same on-disk
// file, exactly what a real process restart does) must see everything
// a prior Service instance wrote, unchanged.
func TestClientIDPersistsAcrossAFreshOpen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db1, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dbmigrate.Up(context.Background(), db1, "../../schema/migrations"); err != nil {
		t.Fatal(err)
	}
	s1 := &Service{DB: db1}
	ctx := context.Background()
	clientID, _ := s1.CreateClient(ctx, "X", "")
	c, err := s1.GenerateClientID(ctx, clientID, clientid.Bits256, "survives-restart")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.AddDomainOverride(ctx, clientID, "block", "blocked.example."); err != nil {
		t.Fatal(err)
	}
	db1.Close()

	db2, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db2.Close() })
	s2 := &Service{DB: db2}

	list, err := s2.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || len(list[0].Identifiers) != 1 || list[0].Identifiers[0].Value != c.Value {
		t.Fatalf("expected the ClientID to survive a fresh Open, got %+v", list)
	}
	if list[0].Identifiers[0].Label != "survives-restart" {
		t.Fatalf("expected the label to survive too, got %+v", list[0].Identifiers[0])
	}
	overrides, err := s2.DomainOverridesForClient(ctx, clientID)
	if err != nil {
		t.Fatal(err)
	}
	if len(overrides) != 1 {
		t.Fatalf("expected the domain override to survive too, got %+v", overrides)
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

func TestUpdateClientEditsNameAndDescription(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, _ := s.CreateClient(ctx, "Old Name", "old desc")

	if err := s.UpdateClient(ctx, id, "New Name", "new desc"); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if list[0].Name != "New Name" || list[0].Description != "new desc" {
		t.Fatalf("expected edited fields to persist, got %+v", list[0])
	}

	if err := s.UpdateClient(ctx, id, "", "x"); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for an empty name, got %v", err)
	}
	if err := s.UpdateClient(ctx, 99999, "X", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an unknown client, got %v", err)
	}
}

func TestSetClientEnabledTogglesRealState(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id, _ := s.CreateClient(ctx, "X", "")

	if err := s.SetClientEnabled(ctx, id, false); err != nil {
		t.Fatalf("SetClientEnabled(false): %v", err)
	}
	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if list[0].Enabled {
		t.Fatal("expected the client to be disabled")
	}

	if err := s.SetClientEnabled(ctx, id, true); err != nil {
		t.Fatalf("SetClientEnabled(true): %v", err)
	}
	list, _ = s.ListClients(ctx)
	if !list[0].Enabled {
		t.Fatal("expected the client to be re-enabled")
	}

	if err := s.SetClientEnabled(ctx, 99999, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an unknown client, got %v", err)
	}
}

// TestDeleteClientRemovesEverythingScopedToIt is also the real
// regression proof for a latent bug found while writing DeleteClient:
// the schema's ON DELETE CASCADE annotations are inert (nothing in
// this codebase's real connection setup enables
// "PRAGMA foreign_keys=ON") -- a naive `DELETE FROM clients` alone
// would have left every child row (identifiers, group membership,
// domain overrides) orphaned. This proves the explicit transactional
// deletes actually clean up all three.
func TestDeleteClientRemovesEverythingScopedToIt(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.CreateGroup(ctx, "g1", "G1", 0); err != nil {
		t.Fatal(err)
	}
	id, _ := s.CreateClient(ctx, "X", "")
	if err := s.AddIdentifier(ctx, id, "ipv4", "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GenerateClientID(ctx, id, clientid.Bits192, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.AddToGroup(ctx, id, "g1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddDomainOverride(ctx, id, "block", "x.example."); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteClient(ctx, id); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}

	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected the client itself to be gone, got %+v", list)
	}

	// Direct table checks -- proves the child rows are ACTUALLY gone,
	// not just unreachable through ListClients's own join.
	for _, table := range []string{"client_identifiers", "client_group_members", "client_domain_overrides"} {
		var n int
		if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE client_id=?`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("expected 0 orphaned rows in %s after DeleteClient, got %d", table, n)
		}
	}

	groups, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups[0].Members) != 0 {
		t.Fatalf("expected the group's own member list to reflect the deletion too, got %+v", groups[0])
	}

	if err := s.DeleteClient(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound deleting an already-deleted client, got %v", err)
	}
}

func TestRemoveFromGroupIsIdempotentAndReflectedInMembership(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.CreateGroup(ctx, "g1", "G1", 0); err != nil {
		t.Fatal(err)
	}
	id, _ := s.CreateClient(ctx, "X", "")
	if err := s.AddToGroup(ctx, id, "g1"); err != nil {
		t.Fatal(err)
	}

	groups, err := s.GroupsForClient(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group membership, got %+v", groups)
	}

	if err := s.RemoveFromGroup(ctx, id, "g1"); err != nil {
		t.Fatalf("RemoveFromGroup: %v", err)
	}
	groups, err = s.GroupsForClient(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 0 {
		t.Fatalf("expected 0 group memberships after removal, got %+v", groups)
	}

	// Idempotent: removing an already-removed membership is not an error.
	if err := s.RemoveFromGroup(ctx, id, "g1"); err != nil {
		t.Fatalf("expected removing a non-existent membership to be a no-op, got %v", err)
	}
}
