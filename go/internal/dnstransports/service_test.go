package dnstransports

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

func TestGetReturnsRealDefaultsOnAnEmptyDatabase(t *testing.T) {
	s := newTestService(t)
	got, err := s.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := defaults()
	if got != want {
		t.Fatalf("expected defaults %+v, got %+v", want, got)
	}
	if got.DNSCryptIdentityProvisioned {
		t.Fatal("DNSCryptIdentityProvisioned must be false -- no secrets store exists to provision it")
	}
}

func TestUpdateRoundTripsEverySettingIncludingDnscrypt(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	in := Settings{
		DotEnabled: true, DotPort: 8853,
		DohEnabled: true, DohPort: 8443, DohPath: "/custom-query",
		DoqEnabled: true, DoqPort: 8854,
		Doh3Enabled: true, Doh3Port: 8444,
		DNSCryptEnabled: true, DNSCryptPort: 5444, DNSCryptProviderName: "custom.provider.example",
	}
	updated, err := s.Update(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	in.DNSCryptIdentityProvisioned = false // never set by Update
	if updated != in {
		t.Fatalf("expected round-tripped settings %+v, got %+v", in, updated)
	}

	reloaded, err := s.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded != in {
		t.Fatalf("expected reload to match what was saved %+v, got %+v", in, reloaded)
	}
}

func TestUpdateValidatesPortsAndPaths(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	base := defaults()

	cases := []struct {
		name   string
		mutate func(*Settings)
	}{
		{"dot_port too low", func(s *Settings) { s.DotPort = 0 }},
		{"doh_port too high", func(s *Settings) { s.DohPort = 70000 }},
		{"doh_path missing leading slash", func(s *Settings) { s.DohPath = "dns-query" }},
		{"doq_port zero", func(s *Settings) { s.DoqPort = 0 }},
		{"doh3_port negative", func(s *Settings) { s.Doh3Port = -1 }},
		{"dnscrypt_port too high", func(s *Settings) { s.DNSCryptPort = 99999 }},
		{"empty dnscrypt provider name", func(s *Settings) { s.DNSCryptProviderName = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.mutate(&in)
			if _, err := s.Update(ctx, in); err == nil {
				t.Fatalf("expected a validation error for %s", tc.name)
			}
		})
	}
}

func TestUpdateIsAtomicAcrossBothTables(t *testing.T) {
	// A valid dns_transport_settings half combined with an invalid
	// dnscrypt half must leave the whole update rejected, not half-applied.
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.Update(ctx, Settings{DotPort: 853, DohPort: 443, DohPath: "/dns-query", DoqPort: 853, Doh3Port: 443, DNSCryptPort: -1, DNSCryptProviderName: "x"}); err == nil {
		t.Fatal("expected the invalid dnscrypt_port to reject the whole update")
	}
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != defaults() {
		t.Fatalf("expected settings to remain at defaults after a rejected update, got %+v", got)
	}
}
