package customrules

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

func strp(s string) *string { return &s }

func TestCreateRejectsInvalidRuleType(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Create(context.Background(), "bogus", "example.com", nil); err == nil {
		t.Fatal("expected an error for an invalid rule_type")
	}
}

func TestCreateRewriteRequiresTarget(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Create(context.Background(), "rewrite", "example.com", nil); err == nil {
		t.Fatal("expected an error for rewrite with no rewrite_target")
	}
	if _, err := s.Create(context.Background(), "rewrite", "example.com", strp("10.0.0.5")); err != nil {
		t.Fatalf("valid rewrite should succeed: %v", err)
	}
}

func TestCreateAssignsIncreasingPriorityAndListOrdersByIt(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id1, _ := s.Create(ctx, "block", "ads.example.com", nil)
	id2, _ := s.Create(ctx, "allow", "safe.example.com", nil)
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != id1 || list[1].ID != id2 {
		t.Fatalf("expected creation order by priority, got %+v", list)
	}
}

func TestUpdateAndDeleteRejectUnknownID(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.Update(ctx, 99999, "block", "x", nil); err != ErrNotFound {
		t.Fatalf("Update(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, 99999); err != ErrNotFound {
		t.Fatalf("Delete(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.SetEnabled(ctx, 99999, false); err != ErrNotFound {
		t.Fatalf("SetEnabled(unknown) = %v, want ErrNotFound", err)
	}
}

func TestBulkSetEnabledAndBulkDelete(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	id1, _ := s.Create(ctx, "block", "a.example.com", nil)
	id2, _ := s.Create(ctx, "block", "b.example.com", nil)
	id3, _ := s.Create(ctx, "block", "c.example.com", nil)

	n, err := s.BulkSetEnabled(ctx, []int64{id1, id2}, false)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 rows affected, got %d", n)
	}
	list, _ := s.List(ctx)
	for _, r := range list {
		if (r.ID == id1 || r.ID == id2) && r.Enabled {
			t.Fatalf("expected id %d to be disabled: %+v", r.ID, r)
		}
		if r.ID == id3 && !r.Enabled {
			t.Fatalf("id3 should be untouched (still enabled): %+v", r)
		}
	}

	n, err = s.BulkDelete(ctx, []int64{id1, id3})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 rows deleted, got %d", n)
	}
	list, _ = s.List(ctx)
	if len(list) != 1 || list[0].ID != id2 {
		t.Fatalf("expected only id2 to remain, got %+v", list)
	}
}

func TestReorderChangesListOrderAndRejectsUnknownID(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	idA, _ := s.Create(ctx, "block", "a.example.com", nil)
	idB, _ := s.Create(ctx, "block", "b.example.com", nil)
	idC, _ := s.Create(ctx, "block", "c.example.com", nil)

	if err := s.Reorder(ctx, []int64{idC, idA, idB}); err != nil {
		t.Fatalf("Reorder: %v", err)
	}
	list, _ := s.List(ctx)
	if list[0].ID != idC || list[1].ID != idA || list[2].ID != idB {
		t.Fatalf("unexpected order after reorder: %+v", list)
	}

	if err := s.Reorder(ctx, []int64{99999}); err == nil {
		t.Fatal("expected an error for an unknown id in the reorder request")
	}
}
