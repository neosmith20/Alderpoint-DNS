package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnstransports"
)

func genTestCertKeyPair(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	return genTestCertKeyPairWithSAN(t, notBefore, notAfter, "localhost")
}

// genTestCertKeyPairWithSAN is genTestCertKeyPair with an explicit SAN --
// used by tests that specifically need a real (non-loopback) hostname,
// e.g. anything exercising the client-facing-address logic that now
// deliberately rejects "localhost" as a client setup target.
func genTestCertKeyPairWithSAN(t *testing.T, notBefore, notAfter time.Time, dnsName string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: notBefore, NotAfter: notAfter, DNSNames: []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestTLSReplaceRealRoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	s := &Server{TLSCertPath: certPath, TLSKeyPath: keyPath}

	// No cert yet -- status must honestly report inactive, not error.
	rec := httptest.NewRecorder()
	s.handleTLSStatus(rec, httptest.NewRequest("GET", "/api/tls/status", nil))
	var status map[string]any
	json.Unmarshal(rec.Body.Bytes(), &status)
	if status["active"] != false {
		t.Fatalf("expected inactive before any cert is uploaded, got %v", status)
	}

	cert, key := genTestCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	body, _ := json.Marshal(map[string]string{"certificate_pem": string(cert), "private_key_pem": string(key)})
	rec2 := httptest.NewRecorder()
	s.handleTLSReplace(rec2, httptest.NewRequest("POST", "/api/tls/replace", bytes.NewReader(body)))
	if rec2.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var replaceResult map[string]any
	json.Unmarshal(rec2.Body.Bytes(), &replaceResult)
	if replaceResult["restart_required"] != true {
		t.Fatalf("expected restart_required=true, got %v", replaceResult)
	}

	// The real file must now exist with the real uploaded content.
	onDisk, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, cert) {
		t.Fatal("promoted cert content does not match what was uploaded")
	}

	// Status now reports it as active.
	rec3 := httptest.NewRecorder()
	s.handleTLSStatus(rec3, httptest.NewRequest("GET", "/api/tls/status", nil))
	var status2 map[string]any
	json.Unmarshal(rec3.Body.Bytes(), &status2)
	if status2["active"] != true {
		t.Fatalf("expected active after a real promoted cert, got %v", status2)
	}
}

func TestTLSReplaceRejectsAMismatchedPairWithoutTouchingLiveFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	s := &Server{TLSCertPath: certPath, TLSKeyPath: keyPath}

	goodCert, goodKey := genTestCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	body, _ := json.Marshal(map[string]string{"certificate_pem": string(goodCert), "private_key_pem": string(goodKey)})
	s.handleTLSReplace(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/tls/replace", bytes.NewReader(body)))

	badCert, _ := genTestCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	_, badKey := genTestCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	badBody, _ := json.Marshal(map[string]string{"certificate_pem": string(badCert), "private_key_pem": string(badKey)})
	rec := httptest.NewRecorder()
	s.handleTLSReplace(rec, httptest.NewRequest("POST", "/api/tls/replace", bytes.NewReader(badBody)))
	if rec.Code != 400 {
		t.Fatalf("expected 400 for a mismatched pair, got %d", rec.Code)
	}

	stillThere, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stillThere, goodCert) {
		t.Fatal("the previously-working certificate must be untouched after a rejected replacement")
	}
}

func newDNSCryptTestServer(t *testing.T) *Server {
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
	// Real management TLS cert path (never actually needs a cert on disk
	// for this handler -- it only reuses the directory), matching the
	// real deployment convention (internal/tlscert lives alongside it).
	certDir := t.TempDir()
	return &Server{
		DNSTransports: &dnstransports.Service{DB: db},
		TLSCertPath:   filepath.Join(certDir, "server.crt"),
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestDNSCryptRotateThenEnableHTTP(t *testing.T) {
	if _, err := exec.LookPath("dnsdist"); err != nil {
		t.Skip("dnsdist not installed, skipping real DNSCrypt provisioning test")
	}
	s := newDNSCryptTestServer(t)

	rec := httptest.NewRecorder()
	s.handleDNSCryptRotate(rec, httptest.NewRequest("POST", "/api/dns-transports/dnscrypt/rotate", nil))
	if rec.Code != 200 {
		t.Fatalf("rotate: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	json.Unmarshal(rec.Body.Bytes(), &result)
	if result["status"] != "rotated" || result["rotated_provider"] != true {
		t.Fatalf("expected a fresh provider on first rotation, got %+v", result)
	}
	if result["fingerprint"] == "" || result["fingerprint"] == nil {
		t.Fatalf("expected a real fingerprint, got %+v", result)
	}

	// GET should now show it provisioned.
	rec2 := httptest.NewRecorder()
	s.handleGetDNSTransports(rec2, httptest.NewRequest("GET", "/api/dns-transports", nil))
	var got map[string]any
	json.Unmarshal(rec2.Body.Bytes(), &got)
	if got["dnscrypt_identity_provisioned"] != true {
		t.Fatalf("expected dnscrypt_identity_provisioned=true after rotation, got %+v", got)
	}

	// A routine cert-only rotation should keep the same fingerprint.
	rec3 := httptest.NewRecorder()
	s.handleDNSCryptRotate(rec3, httptest.NewRequest("POST", "/api/dns-transports/dnscrypt/rotate", bytes.NewReader([]byte(`{"rotate_provider":false}`))))
	var result3 map[string]any
	json.Unmarshal(rec3.Body.Bytes(), &result3)
	if result3["rotated_provider"] != false {
		t.Fatalf("expected rotated_provider=false on a routine cert renewal, got %+v", result3)
	}
	if result3["fingerprint"] != result["fingerprint"] {
		t.Fatalf("expected the same fingerprint across a cert-only rotation, got %v then %v", result["fingerprint"], result3["fingerprint"])
	}
}

func TestDNSCryptEnableWithoutProvisioningReturnsClearError(t *testing.T) {
	s := newDNSCryptTestServer(t)
	body, _ := json.Marshal(map[string]any{
		"dot_port": 853, "doh_port": 443, "doh_path": "/dns-query", "doq_port": 853, "doh3_port": 443,
		"dnscrypt_enabled": true, "dnscrypt_port": 5443, "dnscrypt_provider_name": "x.example",
	})
	rec := httptest.NewRecorder()
	s.handleUpdateDNSTransports(rec, httptest.NewRequest("PUT", "/api/dns-transports", bytes.NewReader(body)))
	if rec.Code != 409 {
		t.Fatalf("expected 409 for enabling DNSCrypt before provisioning, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestGetDNSTransportsIncludesServerHostnameFromActiveCert is the real
// regression test for the live Encryption/DNS Transports UX defect: an
// owner had no way to see manual (non-Apple) connection details for
// DoT/DoH/DoQ/DoH3/DNSCrypt -- this proves the API now surfaces the
// same real hostname source (the active management cert's own SAN) the
// .mobileconfig endpoint already uses, so the frontend can build a real
// "tls://<host>:<port>" etc. string for every enabled transport.
func TestGetDNSTransportsIncludesServerHostnameFromActiveCert(t *testing.T) {
	certDir := t.TempDir()
	certPath := filepath.Join(certDir, "server.crt")
	keyPath := filepath.Join(certDir, "server.key")
	certPEM, keyPEM := genTestCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	os.WriteFile(certPath, certPEM, 0o600)
	os.WriteFile(keyPath, keyPEM, 0o600)

	dbPath := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	s := &Server{
		DNSTransports: &dnstransports.Service{DB: db},
		TLSCertPath:   certPath, TLSKeyPath: keyPath,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	rec := httptest.NewRecorder()
	s.handleGetDNSTransports(rec, httptest.NewRequest("GET", "/api/dns-transports", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["server_hostname"] != "localhost" {
		t.Fatalf("expected server_hostname=%q (the test cert's own SAN), got %+v", "localhost", out)
	}
}

func TestGetDNSTransportsOmitsServerHostnameWithoutACert(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	s := &Server{DNSTransports: &dnstransports.Service{DB: db}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rec := httptest.NewRecorder()
	s.handleGetDNSTransports(rec, httptest.NewRequest("GET", "/api/dns-transports", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if _, present := out["server_hostname"]; present {
		t.Fatalf("expected no server_hostname field when no TLS cert is configured, got %+v", out)
	}
}
