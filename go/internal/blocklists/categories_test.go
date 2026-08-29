package blocklists

import (
	"context"
	"testing"
)

func TestCreateListCategory(t *testing.T) {
	s := newTestService(t)
	cat, err := s.CreateCategory(context.Background(), "  Kids Safe  ")
	if err != nil {
		t.Fatal(err)
	}
	if cat.Name != "Kids Safe" {
		t.Fatalf("expected trimmed name, got %q", cat.Name)
	}
	cats, err := s.ListCategories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cats) != 1 || cats[0].ID != cat.ID {
		t.Fatalf("expected the created category to be listed, got %+v", cats)
	}
}

func TestCreateCategoryRejectsEmptyName(t *testing.T) {
	s := newTestService(t)
	if _, err := s.CreateCategory(context.Background(), "   "); err == nil {
		t.Fatal("expected an error for an empty name")
	}
}

func TestCreateCategoryRejectsDuplicateName(t *testing.T) {
	s := newTestService(t)
	if _, err := s.CreateCategory(context.Background(), "standard"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateCategory(context.Background(), "standard"); err == nil {
		t.Fatal("expected a duplicate-name error")
	}
}

// TestRenameCategoryUpdatesReferencingSubscriptions proves the rename is
// real referential-integrity maintenance, not just a label edit -- this
// schema never enables PRAGMA foreign_keys=ON, so blocklist_subscriptions
// rows would otherwise be silently left pointing at a category name that
// no longer exists.
func TestRenameCategoryUpdatesReferencingSubscriptions(t *testing.T) {
	s := newTestService(t)
	cat, err := s.CreateCategory(context.Background(), "privacy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(context.Background(),
		`INSERT INTO blocklist_subscriptions (subscription_id, name, url, category, created_at) VALUES ('sub1', 'Sub 1', 'https://example.com/list.txt', 'privacy', '2024-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	if err := s.RenameCategory(context.Background(), cat.ID, "privacy-plus"); err != nil {
		t.Fatal(err)
	}

	var gotCategory string
	if err := s.DB.QueryRowContext(context.Background(), `SELECT category FROM blocklist_subscriptions WHERE subscription_id = 'sub1'`).Scan(&gotCategory); err != nil {
		t.Fatal(err)
	}
	if gotCategory != "privacy-plus" {
		t.Fatalf("expected the subscription's category to follow the rename, got %q", gotCategory)
	}
}

func TestRenameCategoryNotFound(t *testing.T) {
	s := newTestService(t)
	if err := s.RenameCategory(context.Background(), 9999, "new-name"); err != ErrCategoryNotFound {
		t.Fatalf("expected ErrCategoryNotFound, got %v", err)
	}
}

func TestRenameCategoryRejectsDuplicateName(t *testing.T) {
	s := newTestService(t)
	if _, err := s.CreateCategory(context.Background(), "standard"); err != nil {
		t.Fatal(err)
	}
	cat2, err := s.CreateCategory(context.Background(), "aggressive")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RenameCategory(context.Background(), cat2.ID, "standard"); err == nil {
		t.Fatal("expected a duplicate-name error")
	}
}

func TestDeleteCategoryRefusesWhenInUse(t *testing.T) {
	s := newTestService(t)
	cat, err := s.CreateCategory(context.Background(), "privacy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(context.Background(),
		`INSERT INTO blocklist_subscriptions (subscription_id, name, url, category, created_at) VALUES ('sub1', 'Sub 1', 'https://example.com/list.txt', 'privacy', '2024-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCategory(context.Background(), cat.ID); err != ErrCategoryInUse {
		t.Fatalf("expected ErrCategoryInUse, got %v", err)
	}
}

func TestDeleteCategorySucceedsWhenUnused(t *testing.T) {
	s := newTestService(t)
	cat, err := s.CreateCategory(context.Background(), "unused-category")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCategory(context.Background(), cat.ID); err != nil {
		t.Fatal(err)
	}
	cats, err := s.ListCategories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cats) != 0 {
		t.Fatalf("expected the category to be gone, got %+v", cats)
	}
}

func TestDeleteCategoryNotFound(t *testing.T) {
	s := newTestService(t)
	if err := s.DeleteCategory(context.Background(), 9999); err != ErrCategoryNotFound {
		t.Fatalf("expected ErrCategoryNotFound, got %v", err)
	}
}
