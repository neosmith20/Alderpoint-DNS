package policy

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
func boolp(b bool) *bool    { return &b }

func TestLoadUnsetScopeReturnsZeroValueNotError(t *testing.T) {
	s := newTestService(t)
	l, err := s.Load(context.Background(), "global", "global")
	if err != nil {
		t.Fatal(err)
	}
	if l.SafesearchMode != nil || l.QueryLogEnabled != nil {
		t.Fatalf("expected an all-nil zero-value layer, got %+v", l)
	}
}

func TestSaveAndLoadRoundTripsAllFieldsIncludingTriStateBools(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	in := Layer{
		SafesearchMode:       strp("strict"),
		BlockingResponseMode: strp("nxdomain"),
		QueryLogEnabled:      boolp(true),
		StatisticsEnabled:    boolp(false),
	}
	if err := s.Save(ctx, "global", "global", in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := s.Load(ctx, "global", "global")
	if err != nil {
		t.Fatal(err)
	}
	if out.SafesearchMode == nil || *out.SafesearchMode != "strict" {
		t.Fatalf("safesearch_mode round-trip failed: %+v", out)
	}
	if out.QueryLogEnabled == nil || *out.QueryLogEnabled != true {
		t.Fatalf("query_log_enabled=true round-trip failed: %+v", out)
	}
	// The real reason this is tri-state, not a plain bool: false must
	// round-trip as false, not be indistinguishable from unset (nil).
	if out.StatisticsEnabled == nil || *out.StatisticsEnabled != false {
		t.Fatalf("statistics_enabled=false must round-trip as false, not nil/inherit: %+v", out)
	}
}

func TestSaveTwiceReplacesTheWholeLayerNotMerge(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.Save(ctx, "client", "42", Layer{SafesearchMode: strp("moderate"), ECSMode: strp("preserve")}); err != nil {
		t.Fatal(err)
	}
	// Second save omits ecs_mode -- it must become nil (inherit again), not keep the old value.
	if err := s.Save(ctx, "client", "42", Layer{SafesearchMode: strp("off")}); err != nil {
		t.Fatal(err)
	}
	out, err := s.Load(ctx, "client", "42")
	if err != nil {
		t.Fatal(err)
	}
	if out.SafesearchMode == nil || *out.SafesearchMode != "off" {
		t.Fatalf("expected updated safesearch_mode=off, got %+v", out)
	}
	if out.ECSMode != nil {
		t.Fatalf("expected ecs_mode to revert to nil (inherit) on the second save, got %+v", out.ECSMode)
	}
}

func TestScopesAreIndependent(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.Save(ctx, "client", "1", Layer{SafesearchMode: strp("strict")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "client", "2", Layer{SafesearchMode: strp("off")}); err != nil {
		t.Fatal(err)
	}
	l1, _ := s.Load(ctx, "client", "1")
	l2, _ := s.Load(ctx, "client", "2")
	if *l1.SafesearchMode != "strict" || *l2.SafesearchMode != "off" {
		t.Fatalf("scope_ref isolation failed: client 1=%v client 2=%v", *l1.SafesearchMode, *l2.SafesearchMode)
	}
}

func TestSaveRejectsInvalidScope(t *testing.T) {
	s := newTestService(t)
	if err := s.Save(context.Background(), "bogus", "x", Layer{}); err == nil {
		t.Fatal("expected an error for an invalid scope")
	}
}

func TestCreateNetworkAndList(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.CreateNetwork(ctx, "lan", "192.168.1.0/24"); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	networks, err := s.ListNetworks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 1 || networks[0].CIDR != "192.168.1.0/24" {
		t.Fatalf("unexpected networks: %+v", networks)
	}
	if err := s.CreateNetwork(ctx, "lan2", "192.168.1.0/24"); err == nil {
		t.Fatal("expected a conflict error for a duplicate CIDR")
	}
}
