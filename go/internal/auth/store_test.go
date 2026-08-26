package auth

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/dbmigrate"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// Real migrations, not a hand-copied schema -- this test breaks the
	// moment the real admins table shape drifts, which is the point.
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Store{DB: db}
}

func TestChangePasswordRequiresCorrectCurrentPassword(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	adminID, err := s.CreateFirstAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}

	if err := s.ChangePassword(ctx, adminID, "wrong current password", "new password twelve+"); err != ErrInvalidCredentials {
		t.Fatalf("ChangePassword with wrong current password: got %v, want ErrInvalidCredentials", err)
	}

	// The old password must still work -- a rejected change must not have
	// partially applied.
	if _, err := s.Login(ctx, "admin", "correct horse battery staple", "127.0.0.1", "test"); err != nil {
		t.Fatalf("old password should still work after a rejected change attempt: %v", err)
	}
}

func TestChangePasswordSucceedsAndOldPasswordStopsWorking(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	adminID, err := s.CreateFirstAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("CreateFirstAdmin: %v", err)
	}

	if err := s.ChangePassword(ctx, adminID, "correct horse battery staple", "new password twelve+"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if _, err := s.Login(ctx, "admin", "correct horse battery staple", "127.0.0.1", "test"); err != ErrInvalidCredentials {
		t.Fatalf("old password should no longer work: got %v", err)
	}
	if _, err := s.Login(ctx, "admin", "new password twelve+", "127.0.0.1", "test"); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}
