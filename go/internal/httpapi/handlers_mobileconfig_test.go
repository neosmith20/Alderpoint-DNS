package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnstransports"
)

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

// TestMobileconfigRejectsLoopbackCertSubject is the release-blocker
// regression case: a config where the management certificate's own
// subject/SAN is "localhost" must never produce an Apple profile telling
// a remote device to trust "localhost" -- that profile would install
// successfully and then simply never validate.
func TestMobileconfigRejectsLoopbackCertSubject(t *testing.T) {
	s, certPath, keyPath := newTestServerForMobileconfig(t)
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
		t.Fatalf("expected 400 rejecting a loopback cert subject, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "only ever validates for a client running on this appliance itself") {
		t.Errorf("expected the honest loopback-rejection reason, got: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "\"localhost\" would") {
		t.Errorf("error body should not read as endorsing localhost as usable: %s", rec.Body.String())
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
	// lan_ip must be present (this test environment always has a
	// non-loopback interface address) and must not itself be a loopback
	// value -- that's the actual field the frontend uses instead of the
	// cert's own loopback hostname.
	lanIP, _ := out["lan_ip"].(string)
	if lanIP == "" || lanIP == "localhost" || lanIP == "127.0.0.1" {
		t.Fatalf("expected a real non-loopback lan_ip, got %+v", out["lan_ip"])
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
