package upstreams

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

func plainEndpoint(addr string) []Endpoint {
	return []Endpoint{{Address: addr, Weight: 1}}
}

func TestCreateRejectsInvalidTransport(t *testing.T) {
	s := newTestService(t)
	err := s.Create(context.Background(), "x", "X", "carrier-pigeon", "ordered", plainEndpoint("1.1.1.1"))
	if err == nil {
		t.Fatal("expected an error for an invalid transport")
	}
}

func TestCreateRejectsEmptyEndpoints(t *testing.T) {
	s := newTestService(t)
	err := s.Create(context.Background(), "x", "X", "plain", "ordered", nil)
	if err == nil {
		t.Fatal("expected an error for zero endpoints")
	}
}

func TestCreateRejectsDoHWithoutTLSHostname(t *testing.T) {
	s := newTestService(t)
	err := s.Create(context.Background(), "x", "X", "doh", "ordered", []Endpoint{{Address: "1.1.1.1", Weight: 1}})
	if err == nil {
		t.Fatal("expected an error for a DoH endpoint with no tls_hostname")
	}
}

// TestListNeverReturnsNilOnEmpty guards against the same real bug found
// (and fixed) in the sibling internal/clients package: a nil Go slice
// marshals to JSON `null`, which crashes the frontend's shared DataGrid
// on `null.length`. See that package's identical test for the full story.
func TestListNeverReturnsNilOnEmpty(t *testing.T) {
	s := newTestService(t)
	profiles, _, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if profiles == nil {
		t.Fatal("List on an empty table must return a non-nil empty slice, not nil (would marshal to JSON null)")
	}
}

func TestCreateAndListRoundTrip(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	tlsHost := "dns.example.com"
	err := s.Create(ctx, "primary", "Primary", "dot", "ordered", []Endpoint{
		{Address: "1.1.1.1", TLSHostname: &tlsHost, Priority: 0, Weight: 1},
		{Address: "1.0.0.1", TLSHostname: &tlsHost, Priority: 1, Weight: 1},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	profiles, nativeRecursion, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	p := profiles[0]
	if p.Name != "Primary" || p.Transport != "dot" || !p.Enabled {
		t.Fatalf("unexpected profile: %+v", p)
	}
	if len(p.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d: %+v", len(p.Endpoints), p.Endpoints)
	}
	if p.Endpoints[0].TLSHostname == nil || *p.Endpoints[0].TLSHostname != tlsHost {
		t.Fatalf("tls_hostname round-trip failed: %+v", p.Endpoints[0])
	}
	if nativeRecursion {
		t.Fatal("native_recursion_active should be false when a profile is enabled")
	}
}

func TestSetEnabledFalseMakesNativeRecursionActive(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.Create(ctx, "only", "Only", "plain", "ordered", plainEndpoint("9.9.9.9")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnabled(ctx, "only", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	_, nativeRecursion, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !nativeRecursion {
		t.Fatal("expected native_recursion_active=true once the only profile is disabled")
	}
}

func TestIsLastEnabledOnlyTrueForTheSoleEnabledProfile(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.Create(ctx, "a", "A", "plain", "ordered", plainEndpoint("1.1.1.1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, "b", "B", "plain", "ordered", plainEndpoint("8.8.8.8")); err != nil {
		t.Fatal(err)
	}
	// Two enabled profiles: neither is "the last enabled one".
	isLast, err := s.IsLastEnabled(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if isLast {
		t.Fatal("with two enabled profiles, IsLastEnabled should be false")
	}

	if err := s.SetEnabled(ctx, "b", false); err != nil {
		t.Fatal(err)
	}
	isLast, err = s.IsLastEnabled(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if !isLast {
		t.Fatal("with only 'a' enabled, IsLastEnabled(a) should be true")
	}
	isLast, err = s.IsLastEnabled(ctx, "b")
	if err != nil {
		t.Fatal(err)
	}
	if isLast {
		t.Fatal("IsLastEnabled(b) should be false -- b is already disabled, not enabled-and-alone")
	}
}

func TestReorderPersistsSortOrderAndRejectsUnknownID(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		if err := s.Create(ctx, id, id, "plain", "ordered", plainEndpoint("1.2.3.4")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Reorder(ctx, []string{"c", "a", "b"}); err != nil {
		t.Fatalf("Reorder: %v", err)
	}
	profiles, _, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{profiles[0].UpstreamProfileID, profiles[1].UpstreamProfileID, profiles[2].UpstreamProfileID}
	want := []string{"c", "a", "b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order after reorder = %v, want %v", got, want)
		}
	}

	if err := s.Reorder(ctx, []string{"c", "does-not-exist"}); err == nil {
		t.Fatal("expected an error when the reorder list references an unknown id")
	}
}

func TestDeleteAndUpdateReportNotFoundForUnknownID(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.Delete(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("Delete(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.Update(ctx, "nope", "X", "plain", "ordered", plainEndpoint("1.1.1.1")); err != ErrNotFound {
		t.Fatalf("Update(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.SetEnabled(ctx, "nope", true); err != ErrNotFound {
		t.Fatalf("SetEnabled(unknown) = %v, want ErrNotFound", err)
	}
}

func TestUpdateReplacesEndpointsNotAppends(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.Create(ctx, "x", "X", "plain", "ordered", []Endpoint{{Address: "1.1.1.1", Weight: 1}, {Address: "8.8.8.8", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, "x", "X", "plain", "ordered", []Endpoint{{Address: "9.9.9.9", Weight: 1}}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	profiles, _, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles[0].Endpoints) != 1 || profiles[0].Endpoints[0].Address != "9.9.9.9" {
		t.Fatalf("expected exactly the new single endpoint, got %+v", profiles[0].Endpoints)
	}
}
