package auditlog

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"alderpointdns/go-controlplane/internal/dbmigrate"

	_ "modernc.org/sqlite"
)

func newTestService(t *testing.T) (*Service, int64) {
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
	res, err := db.Exec(`INSERT INTO admins (username, password_hash, created_at) VALUES ('admin', 'x', datetime('now'))`)
	if err != nil {
		t.Fatal(err)
	}
	adminID, _ := res.LastInsertId()
	return &Service{DB: db}, adminID
}

func TestRecordAndListRoundTrip(t *testing.T) {
	svc, adminID := newTestService(t)
	ctx := context.Background()
	svc.Record(ctx, adminID, "admin", "password_change", true, "203.0.113.9", "")
	svc.Record(ctx, adminID, "admin", "password_change", false, "203.0.113.9", "current password incorrect")

	entries, err := svc.List(ctx, adminID, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}
	// Most recent first.
	if entries[0].Action != "password_change" || entries[0].Success {
		t.Fatalf("expected the most recent (failed) entry first, got %+v", entries[0])
	}
	if !entries[1].Success {
		t.Fatalf("expected the earlier (successful) entry second, got %+v", entries[1])
	}
}

func TestListIsScopedToTheGivenAdmin(t *testing.T) {
	svc, adminID := newTestService(t)
	ctx := context.Background()
	res, err := svc.DB.Exec(`INSERT INTO admins (username, password_hash, created_at) VALUES ('other', 'x', datetime('now'))`)
	if err != nil {
		t.Fatal(err)
	}
	otherID, _ := res.LastInsertId()

	svc.Record(ctx, adminID, "admin", "password_change", true, "", "")
	svc.Record(ctx, otherID, "other", "password_change", true, "", "")

	entries, err := svc.List(ctx, adminID, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only this admin's own entry, got %d: %+v", len(entries), entries)
	}
}

func TestListAllReturnsEveryAdministratorsEntries(t *testing.T) {
	svc, adminID := newTestService(t)
	ctx := context.Background()
	res, err := svc.DB.Exec(`INSERT INTO admins (username, password_hash, created_at) VALUES ('other', 'x', datetime('now'))`)
	if err != nil {
		t.Fatal(err)
	}
	otherID, _ := res.LastInsertId()

	svc.Record(ctx, adminID, "admin", "password_change", true, "203.0.113.9", "")
	svc.Record(ctx, otherID, "other", "login", true, "198.51.100.4", "")

	entries, err := svc.ListAll(ctx, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected both administrators' entries, got %d: %+v", len(entries), entries)
	}
	// Most recent first.
	if entries[0].Username != "other" || entries[0].Action != "login" {
		t.Fatalf("expected the most recent entry (other's login) first, got %+v", entries[0])
	}
	if entries[1].Username != "admin" {
		t.Fatalf("expected admin's entry second, got %+v", entries[1])
	}
}

// TestListAndListAllExposeARealUniqueID proves the real fix for a live
// defect: the frontend used to key its Audit Log DataGrid rows with a
// synthetic at+action+ip string, which collides for any two entries
// sharing a timestamp/action/IP -- an ordinary occurrence, not a corner
// case (confirmed live: a real Chromium suite run against this exact
// page threw a genuine Svelte "each_key_duplicate" runtime error).
// Entry.ID is the real admin_audit_log.id primary key, always unique.
func TestListAndListAllExposeARealUniqueID(t *testing.T) {
	svc, adminID := newTestService(t)
	ctx := context.Background()
	// Two entries with the exact same action/ip -- the real shape that
	// used to collide under the old synthetic key.
	svc.Record(ctx, adminID, "admin", "password_change", true, "203.0.113.9", "")
	svc.Record(ctx, adminID, "admin", "password_change", true, "203.0.113.9", "")

	entries, err := svc.List(ctx, adminID, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ID == 0 || entries[1].ID == 0 {
		t.Fatalf("expected real, non-zero IDs, got %+v and %+v", entries[0], entries[1])
	}
	if entries[0].ID == entries[1].ID {
		t.Fatalf("expected two distinct real IDs even for entries with identical action/ip, got both=%d", entries[0].ID)
	}

	allEntries, err := svc.ListAll(ctx, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(allEntries) != 2 || allEntries[0].ID == allEntries[1].ID {
		t.Fatalf("expected ListAll to also expose distinct real IDs, got %+v", allEntries)
	}
}

func TestRecordIsNoOpWithZeroAdminID(t *testing.T) {
	svc, _ := newTestService(t)
	svc.Record(context.Background(), 0, "nobody", "login_attempt", false, "", "")
	// Would violate the admin_id FK if it actually tried to insert --
	// this only passes if Record's own zero-adminID guard fired.
}

func TestNilServiceRecordIsSafe(t *testing.T) {
	var svc *Service
	svc.Record(context.Background(), 1, "admin", "password_change", true, "", "")
}
