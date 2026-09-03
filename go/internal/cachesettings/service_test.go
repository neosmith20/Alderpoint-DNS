package cachesettings

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

func TestGetReturnsRealBINDDefaults(t *testing.T) {
	s := newTestService(t)
	got, err := s.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxCacheTTLSeconds != 604800 || got.MaxNegativeTTLSeconds != 10800 || !got.PrefetchEnabled {
		t.Fatalf("expected real BIND defaults before any Update, got %+v", got)
	}
}

func TestUpdateRoundTrips(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	in := Settings{MaxCacheTTLSeconds: 3600, MaxNegativeTTLSeconds: 300, PrefetchEnabled: false, ServeStaleEnabled: true, MaxStaleTTLSeconds: 7200}
	if _, err := s.Update(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxCacheTTLSeconds != 3600 || got.MaxNegativeTTLSeconds != 300 || got.PrefetchEnabled || !got.ServeStaleEnabled || got.MaxStaleTTLSeconds != 7200 {
		t.Fatalf("Update did not round-trip, got %+v", got)
	}
	if got.UpdatedAt == "" {
		t.Fatal("expected a real updated_at timestamp to be set")
	}
}

func TestUpdateRejectsOutOfRangeValues(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	cases := []Settings{
		{MaxCacheTTLSeconds: 0, MaxNegativeTTLSeconds: 300},
		{MaxCacheTTLSeconds: 3600, MaxNegativeTTLSeconds: 30 * 86400},
		{MaxCacheTTLSeconds: 3600, MaxNegativeTTLSeconds: 300, ServeStaleEnabled: true, MaxStaleTTLSeconds: 0},
	}
	for i, c := range cases {
		if _, err := s.Update(ctx, c); err == nil {
			t.Fatalf("case %d: expected validation to reject %+v", i, c)
		}
	}
}
