package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
)

// startFakeHostAgentLAN spins up a real hostagent.Client/hostagentd.Server
// pair over a temp unix socket -- the real wire protocol, not a mock --
// but with network.lan_candidates registered to a CANNED handler
// returning exactly the given candidates, instead of hostagentd's real
// `ip`-shelling implementation (already covered end to end by
// internal/hostagentd's own fixture tests). This lets httpapi's tests
// deterministically exercise "the web control plane received these real
// host LAN candidates over the RPC boundary" without depending on
// whatever network interfaces happen to exist in the test environment.
func startFakeHostAgentLAN(t *testing.T, candidates []map[string]string) *hostagent.Client {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	agent := &hostagentd.Server{SocketPath: sockPath, AllowedUID: uint32(os.Getuid()), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	agent.Register(hostagent.OpNetworkLANCandidates, func(ctx context.Context, params json.RawMessage) (any, error) {
		return map[string]any{"candidates": candidates, "default_interface": "eth0"}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go agent.Serve(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return hostagent.NewClient(sockPath)
}

func newTestServerForMobileconfig(t *testing.T) (*Server, string, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	certPath := filepath.Join(t.TempDir(), "server.crt")
	keyPath := filepath.Join(t.TempDir(), "server.key")
	s := &Server{DB: db, DNSTransports: &dnstransports.Service{DB: db}, TLSCertPath: certPath, TLSKeyPath: keyPath}
	return s, certPath, keyPath
}

func TestMobileconfigRealRoundTripDoH(t *testing.T) {
	s, certPath, keyPath := newTestServerForMobileconfig(t)

	settings, err := s.DNSTransports.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.DohEnabled = true
	settings.DohPort = 9443
	settings.DohPath = "/dns-query"
	if _, err := s.DNSTransports.Update(context.Background(), settings); err != nil {
		t.Fatal(err)
	}

	// Deliberately a real hostname, not "localhost" -- the mobileconfig
	// endpoint now rejects a loopback certificate subject outright (a
	// profile built against it would be guaranteed to fail TLS validation
	// on any device other than this appliance itself). See
	// TestMobileconfigRejectsLoopbackCertSubject below for that case.
	cert, key := genTestCertKeyPairWithSAN(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), "apdns.example.internal")
	if err := os.WriteFile(certPath, cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/dns-transports/mobileconfig/doh", nil)
	req.SetPathValue("protocol", "doh")
	rec := httptest.NewRecorder()
	s.handleDNSTransportMobileconfig(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-apple-aspen-config" {
		t.Errorf("Content-Type = %q, want application/x-apple-aspen-config", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"com.apple.dnsSettings.managed", "DNSProtocol", "HTTPS", "apdns.example.internal"} {
		if !strings.Contains(body, want) {
			t.Errorf("profile body missing expected content %q: %s", want, body)
		}
	}
}

func TestMobileconfigRejectsWhenTransportDisabled(t *testing.T) {
	s, certPath, keyPath := newTestServerForMobileconfig(t)
	cert, key := genTestCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	os.WriteFile(certPath, cert, 0o644)
	os.WriteFile(keyPath, key, 0o600)

	req := httptest.NewRequest("GET", "/api/dns-transports/mobileconfig/dot", nil)
	req.SetPathValue("protocol", "dot")
	rec := httptest.NewRecorder()
	s.handleDNSTransportMobileconfig(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for a disabled transport, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestMobileconfigRejectsWhenClientFacingAddressNotInLoopbackCertSAN is
// the release-blocker regression case, updated for the real
// client-facing-address model (2026-09-03): a config where the
// management certificate's own subject/SAN is "localhost" and a real
// LAN address (172.16.43.100, this live appliance's own actual reported
// DHCP address) is detected must never produce an Apple profile -- the
// certificate simply doesn't cover that address, so Apple's profile
// installer would fail the TLS handshake. Also proves the loopback SAN
// itself is never silently used as the profile's hostname (Build would
// reject that too, via the separate loopback check) or endorsed as
// usable anywhere in the error text.
func TestMobileconfigRejectsWhenClientFacingAddressNotInLoopbackCertSAN(t *testing.T) {
	s, certPath, keyPath := newTestServerForMobileconfig(t)
	s.HostAgent = startFakeHostAgentLAN(t, []map[string]string{{"interface": "eth0", "address": "172.16.43.100"}})
	settings, _ := s.DNSTransports.Get(context.Background())
	settings.DotEnabled = true
	s.DNSTransports.Update(context.Background(), settings)

	cert, key := genTestCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour)) // defaults to a "localhost" SAN
	os.WriteFile(certPath, cert, 0o644)
	os.WriteFile(keyPath, key, 0o600)

	req := httptest.NewRequest("GET", "/api/dns-transports/mobileconfig/dot", nil)
	req.SetPathValue("protocol", "dot")
	rec := httptest.NewRecorder()
	s.handleDNSTransportMobileconfig(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 rejecting a client-facing address the loopback cert doesn't cover, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not in this certificate's subject alternative names") {
		t.Errorf("expected the SAN-mismatch rejection reason, got: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "\"localhost\" would") {
		t.Errorf("error body should not read as endorsing localhost as usable: %s", rec.Body.String())
	}
}

// TestMobileconfigRejectsWhenNoClientFacingAddressChosenYet covers the
// other honest failure mode: a loopback cert, no owner-saved
// client_facing_hostname/ip, and an unreachable/ambiguous host-side LAN
// detection -- there is genuinely no safe address to put in a profile
// yet, and Build says so rather than falling back to something
// container-internal or the loopback cert subject.
func TestMobileconfigRejectsWhenNoClientFacingAddressChosenYet(t *testing.T) {
	s, certPath, keyPath := newTestServerForMobileconfig(t)
	// s.HostAgent deliberately left nil -- "hostagent unreachable", the
	// most conservative real case, must never fall back to a guess.
	settings, _ := s.DNSTransports.Get(context.Background())
	settings.DotEnabled = true
	s.DNSTransports.Update(context.Background(), settings)

	cert, key := genTestCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour)) // "localhost" SAN
	os.WriteFile(certPath, cert, 0o644)
	os.WriteFile(keyPath, key, 0o600)

	req := httptest.NewRequest("GET", "/api/dns-transports/mobileconfig/dot", nil)
	req.SetPathValue("protocol", "dot")
	rec := httptest.NewRecorder()
	s.handleDNSTransportMobileconfig(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 when no client-facing address can be determined, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no client-facing address has been chosen") {
		t.Errorf("expected the honest no-address-yet rejection reason, got: %s", rec.Body.String())
	}
}

// TestGetDNSTransportsFallsBackToLANIPWhenCertIsLoopback proves the
// actual release-blocker end to end: with server_hostname/cert subject
// == "localhost", GET /api/dns-transports must surface a real LAN IP
// (lan_ip/lan_ips) alongside the loopback server_hostname and the full
// cert_san list, so the frontend has what it needs to never recommend
// "localhost" to a remote client. It does NOT invent a fake non-loopback
// server_hostname -- the honest fix is exposing the LAN IP as a distinct
// field, not lying about the certificate.
func TestGetDNSTransportsFallsBackToLANIPWhenCertIsLoopback(t *testing.T) {
	s, certPath, keyPath := newTestServerForMobileconfig(t)
	s.HostAgent = startFakeHostAgentLAN(t, []map[string]string{{"interface": "eth0", "address": "172.16.43.100"}})
	cert, key := genTestCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour)) // "localhost" SAN
	os.WriteFile(certPath, cert, 0o644)
	os.WriteFile(keyPath, key, 0o600)

	req := httptest.NewRequest("GET", "/api/dns-transports", nil)
	rec := httptest.NewRecorder()
	s.handleGetDNSTransports(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["server_hostname"] != "localhost" {
		t.Fatalf("expected the honest (loopback) server_hostname, got %+v", out["server_hostname"])
	}
	san, _ := out["cert_san"].([]any)
	if len(san) != 1 || san[0] != "localhost" {
		t.Fatalf("expected cert_san = [\"localhost\"], got %+v", out["cert_san"])
	}
	lanIP, _ := out["lan_ip"].(string)
	if lanIP != "172.16.43.100" {
		t.Fatalf("expected the real host-detected LAN IP, got %+v", out["lan_ip"])
	}
	if out["effective_client_address"] != "172.16.43.100" {
		t.Fatalf("expected effective_client_address to fall back to the real LAN IP, got %+v", out["effective_client_address"])
	}
	if out["client_facing_selection_required"] != false {
		t.Fatalf("expected client_facing_selection_required=false once exactly one LAN candidate resolves the address, got %+v", out["client_facing_selection_required"])
	}
}

// TestGetDNSTransportsNeverShowsContainerBridgeAddress is the P0
// regression test proving the exact previously-reported defect (2026-09-03
// owner report) cannot recur: even if apdns-hostagent's own fixture
// happened to include a container bridge address (defense in depth --
// hostagentd.HostLANCandidates already filters these server-side, see
// internal/hostagentd's own fixture tests), the web control plane's
// response must never surface 10.88.0.15/10.88.0.x as a client-facing
// candidate, and must prefer the one real LAN address instead.
func TestGetDNSTransportsNeverShowsContainerBridgeAddress(t *testing.T) {
	s, certPath, keyPath := newTestServerForMobileconfig(t)
	s.HostAgent = startFakeHostAgentLAN(t, []map[string]string{
		{"interface": "eth0", "address": "172.16.43.100"},
	})
	cert, key := genTestCertKeyPairWithSAN(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), "localhost")
	os.WriteFile(certPath, cert, 0o644)
	os.WriteFile(keyPath, key, 0o600)

	req := httptest.NewRequest("GET", "/api/dns-transports", nil)
	rec := httptest.NewRecorder()
	s.handleGetDNSTransports(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "10.88.") || strings.Contains(body, "10.89.") {
		t.Fatalf("response must never contain a Podman bridge address: %s", body)
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["lan_ip"] != "172.16.43.100" {
		t.Fatalf("expected the real LAN IP, got %+v", out["lan_ip"])
	}
}

// TestGetDNSTransportsAmbiguousLANRequiresOwnerSelection covers "if
// detection is ambiguous, do not guess": with two distinct real host LAN
// candidates and no owner-saved client_facing_hostname/ip, the response
// must report the situation honestly (client_facing_selection_required
// = true, no single lan_ip) rather than picking one of the two.
func TestGetDNSTransportsAmbiguousLANRequiresOwnerSelection(t *testing.T) {
	s, certPath, keyPath := newTestServerForMobileconfig(t)
	s.HostAgent = startFakeHostAgentLAN(t, []map[string]string{
		{"interface": "eth0", "address": "172.16.43.100"},
		{"interface": "eth1", "address": "192.168.50.10"},
	})
	cert, key := genTestCertKeyPairWithSAN(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), "localhost")
	os.WriteFile(certPath, cert, 0o644)
	os.WriteFile(keyPath, key, 0o600)

	req := httptest.NewRequest("GET", "/api/dns-transports", nil)
	rec := httptest.NewRecorder()
	s.handleGetDNSTransports(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if _, present := out["lan_ip"]; present {
		t.Fatalf("expected no single lan_ip to be guessed with 2 ambiguous candidates, got %+v", out["lan_ip"])
	}
	if out["lan_detection_ambiguous"] != true {
		t.Fatalf("expected lan_detection_ambiguous=true, got %+v", out["lan_detection_ambiguous"])
	}
	if out["effective_client_address"] != "" || out["client_facing_selection_required"] != true {
		t.Fatalf("expected no effective address and selection_required=true when ambiguous, got effective=%+v required=%+v", out["effective_client_address"], out["client_facing_selection_required"])
	}
	lanIPs, _ := out["lan_ips"].([]any)
	if len(lanIPs) != 2 {
		t.Fatalf("expected both raw candidates still surfaced for the owner to choose from, got %+v", out["lan_ips"])
	}
}

// TestGetDNSTransportsOwnerSavedAddressResolvesAmbiguity proves the
// owner's saved client_facing_ip/hostname is authoritative even when
// host-side LAN detection is itself ambiguous -- an explicit owner
// choice always wins over a guess.
func TestGetDNSTransportsOwnerSavedAddressResolvesAmbiguity(t *testing.T) {
	s, certPath, keyPath := newTestServerForMobileconfig(t)
	s.HostAgent = startFakeHostAgentLAN(t, []map[string]string{
		{"interface": "eth0", "address": "172.16.43.100"},
		{"interface": "eth1", "address": "192.168.50.10"},
	})
	settings, _ := s.DNSTransports.Get(context.Background())
	settings.ClientFacingIP = "192.168.50.10"
	settings.ClientFacingPrefer = "ip"
	if _, err := s.DNSTransports.Update(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	cert, key := genTestCertKeyPairWithSAN(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), "localhost")
	os.WriteFile(certPath, cert, 0o644)
	os.WriteFile(keyPath, key, 0o600)

	req := httptest.NewRequest("GET", "/api/dns-transports", nil)
	rec := httptest.NewRecorder()
	s.handleGetDNSTransports(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["effective_client_address"] != "192.168.50.10" {
		t.Fatalf("expected the owner's saved client-facing IP to win over ambiguous detection, got %+v", out["effective_client_address"])
	}
	if out["client_facing_selection_required"] != false {
		t.Fatalf("expected selection_required=false once the owner has saved a value, got %+v", out["client_facing_selection_required"])
	}
}

func TestMobileconfigRejectsWhenNoCertConfigured(t *testing.T) {
	s, _, _ := newTestServerForMobileconfig(t)
	settings, _ := s.DNSTransports.Get(context.Background())
	settings.DotEnabled = true
	s.DNSTransports.Update(context.Background(), settings)

	req := httptest.NewRequest("GET", "/api/dns-transports/mobileconfig/dot", nil)
	req.SetPathValue("protocol", "dot")
	rec := httptest.NewRecorder()
	s.handleDNSTransportMobileconfig(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 when no cert file exists yet, got %d: %s", rec.Code, rec.Body.String())
	}
}
