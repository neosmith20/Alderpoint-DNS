package dnstransports

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
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
		// DNSCryptEnabled is deliberately NOT set here -- Update rejects
		// enabling DNSCrypt before a provider identity is provisioned
		// (see TestUpdateRejectsEnablingDnscryptBeforeProvisioning and
		// TestRotateDNSCryptThenEnableSucceeds), so this round-trip
		// proof only covers the always-updatable port/provider_name
		// fields for DNSCrypt.
		DNSCryptPort: 5444, DNSCryptProviderName: "custom.provider.example",
	}
	updated, err := s.Update(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	in.DNSCryptIdentityProvisioned = false // never set by Update
	in.ClientFacingPrefer = "auto"         // Update defaults an empty value to "auto"
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
		{"invalid client_facing_prefer", func(s *Settings) { s.ClientFacingPrefer = "bogus" }},
		// The exact real-world defect this rejects: a container-internal
		// address (here, Podman's own default bridge subnet -- see
		// migration 0027's doc comment) saved as if it were the
		// appliance's real client-facing LAN IP.
		{"client_facing_ip inside podman bridge range", func(s *Settings) { s.ClientFacingIP = "10.88.0.15" }},
		{"client_facing_ip loopback", func(s *Settings) { s.ClientFacingIP = "127.0.0.1" }},
		{"client_facing_hostname loopback", func(s *Settings) { s.ClientFacingHostname = "localhost" }},
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

// TestUpdateAcceptsRealLANClientFacingAddress is the positive-path
// sibling of the container-bridge-rejection cases above: a real LAN
// address (this live appliance's own actual DHCP address, per the
// owner's report) must be accepted and round-trip cleanly.
func TestUpdateAcceptsRealLANClientFacingAddress(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	in := defaults()
	in.ClientFacingIP = "172.16.43.100"
	in.ClientFacingPrefer = "ip"
	updated, err := s.Update(ctx, in)
	if err != nil {
		t.Fatalf("expected a real LAN IP to be accepted: %v", err)
	}
	if updated.ClientFacingIP != "172.16.43.100" || updated.ClientFacingPrefer != "ip" {
		t.Fatalf("expected client-facing IP/prefer to round-trip, got %+v", updated)
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

func TestUpdateRejectsEnablingDnscryptBeforeProvisioning(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	_, err := s.Update(ctx, Settings{
		DotPort: 853, DohPort: 443, DohPath: "/dns-query", DoqPort: 853, Doh3Port: 443,
		DNSCryptEnabled: true, DNSCryptPort: 5443, DNSCryptProviderName: "x.example",
	})
	if err != ErrDNSCryptNotProvisioned {
		t.Fatalf("expected ErrDNSCryptNotProvisioned, got %v", err)
	}
}

func requireDnsdistBinary(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("dnsdist")
	if err != nil {
		t.Skip("dnsdist not installed, skipping real DNSCrypt provisioning test")
	}
	return bin
}

// TestRotateDNSCryptProvisionsThenEnableSucceeds proves the full real
// workflow: RotateDNSCrypt actually writes real key/cert files and
// records enough state that Update then allows enabling DNSCrypt.
func TestRotateDNSCryptProvisionsThenEnableSucceeds(t *testing.T) {
	bin := requireDnsdistBinary(t)
	s := newTestService(t)
	ctx := context.Background()
	keyDir := t.TempDir()

	updated, fingerprint, err := s.RotateDNSCrypt(ctx, false, bin, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.DNSCryptIdentityProvisioned {
		t.Fatal("expected DNSCryptIdentityProvisioned=true after rotation")
	}
	if fingerprint == "" {
		t.Fatal("expected a real fingerprint")
	}
	if updated.DNSCryptCertSerial != 1 {
		t.Fatalf("expected the first cert to have serial 1, got %d", updated.DNSCryptCertSerial)
	}
	for _, p := range []string{updated.DNSCryptProviderKeyPath, updated.DNSCryptCertPath, updated.DNSCryptKeyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected real file at %s: %v", p, err)
		}
	}

	if _, err := s.Update(ctx, Settings{
		DotPort: 853, DohPort: 443, DohPath: "/dns-query", DoqPort: 853, Doh3Port: 443,
		DNSCryptEnabled: true, DNSCryptPort: 5443, DNSCryptProviderName: "x.example",
	}); err != nil {
		t.Fatalf("expected enabling DNSCrypt to succeed once provisioned, got %v", err)
	}
}

// TestRotateDNSCryptCertOnlyKeepsSameProviderIncrementsSerial proves the
// routine (rotateProvider=false) path reuses the SAME provider identity
// (same fingerprint, same provider key file) while still issuing a new
// resolver certificate with an incremented serial -- rotating the
// provider identity must never happen as a side effect of a routine
// cert renewal.
func TestRotateDNSCryptCertOnlyKeepsSameProviderIncrementsSerial(t *testing.T) {
	bin := requireDnsdistBinary(t)
	s := newTestService(t)
	ctx := context.Background()
	keyDir := t.TempDir()

	first, fp1, err := s.RotateDNSCrypt(ctx, false, bin, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	second, fp2, err := s.RotateDNSCrypt(ctx, false, bin, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatalf("expected the same provider fingerprint across a cert-only rotation, got %q then %q", fp1, fp2)
	}
	if first.DNSCryptProviderKeyPath != second.DNSCryptProviderKeyPath {
		t.Fatalf("expected the same provider key file to be reused, got %q then %q", first.DNSCryptProviderKeyPath, second.DNSCryptProviderKeyPath)
	}
	if second.DNSCryptCertSerial != first.DNSCryptCertSerial+1 {
		t.Fatalf("expected the cert serial to increment (from %d), got %d", first.DNSCryptCertSerial, second.DNSCryptCertSerial)
	}
}

// TestRotateDNSCryptRotateProviderChangesFingerprintAndResetsSerial
// proves the explicit rotateProvider=true path genuinely replaces the
// provider identity (a different fingerprint) and restarts the
// resolver-cert serial sequence at 1, matching Python's own documented
// behavior for the same real workflow.
func TestRotateDNSCryptRotateProviderChangesFingerprintAndResetsSerial(t *testing.T) {
	bin := requireDnsdistBinary(t)
	s := newTestService(t)
	ctx := context.Background()
	keyDir := t.TempDir()

	first, fp1, err := s.RotateDNSCrypt(ctx, false, bin, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	second, fp2, err := s.RotateDNSCrypt(ctx, true, bin, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp2 {
		t.Fatal("expected a different provider fingerprint after rotate_provider=true")
	}
	if second.DNSCryptCertSerial != 1 {
		t.Fatalf("expected the cert serial to restart at 1 after a provider rotation, got %d", second.DNSCryptCertSerial)
	}
	_ = first
}
