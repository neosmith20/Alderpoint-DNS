package httpapi

import (
	"context"
	"database/sql"
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

	cert, key := genTestCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
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
	for _, want := range []string{"com.apple.dnsSettings.managed", "DNSProtocol", "HTTPS", "localhost"} {
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
