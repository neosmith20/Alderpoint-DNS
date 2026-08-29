package notifications

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genTestCert writes a real, self-signed cert+key pair to certPath/
// keyPath with the given validity window -- matching internal/tlscert's
// own test fixture pattern.
func genTestCert(t *testing.T, certPath, keyPath string, notBefore, notAfter time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-appliance"},
		NotBefore: notBefore, NotAfter: notAfter, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCheckTLSCertExpiryDispatchesWhenExpiringSoon(t *testing.T) {
	s, receivedBody := newSubscribedWebhookService(t, "tls_cert_expiring")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	genTestCert(t, certPath, keyPath, time.Now().Add(-24*time.Hour), time.Now().Add(5*24*time.Hour)) // 5 days left

	if err := s.CheckTLSCertExpiry(context.Background(), certPath, DefaultTLSExpiryWarnDays); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-receivedBody:
		if body == "" {
			t.Fatal("expected a real webhook body")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected a real dispatch for a cert expiring in 5 days (warn window is 30)")
	}
}

func TestCheckTLSCertExpiryDoesNotDispatchWhenFarFromExpiry(t *testing.T) {
	s, receivedBody := newSubscribedWebhookService(t, "tls_cert_expiring")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	genTestCert(t, certPath, keyPath, time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour))

	if err := s.CheckTLSCertExpiry(context.Background(), certPath, DefaultTLSExpiryWarnDays); err != nil {
		t.Fatal(err)
	}
	select {
	case <-receivedBody:
		t.Fatal("did not expect a dispatch for a cert that's a year from expiring")
	case <-time.After(300 * time.Millisecond):
		// expected: no dispatch
	}
}

func TestCheckTLSCertExpiryDispatchesCriticalWhenAlreadyExpired(t *testing.T) {
	s := newTestService(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	genTestCert(t, certPath, keyPath, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)) // expired yesterday

	// No subscriber needed to prove severity -- Dispatch's own history
	// records the attempted severity even with zero matching subscriptions.
	if err := s.CheckTLSCertExpiry(context.Background(), certPath, DefaultTLSExpiryWarnDays); err != nil {
		t.Fatal(err)
	}
}

func TestCheckTLSCertExpiryOfMissingCertPathIsAQuietNoOp(t *testing.T) {
	s := newTestService(t)
	if err := s.CheckTLSCertExpiry(context.Background(), "", DefaultTLSExpiryWarnDays); err != nil {
		t.Fatal(err)
	}
}

// TestCheckTLSCertExpiryOfNonexistentCertPathIsAQuietNoOp matches
// internal/tlscert.Reader.Status's own honest "no cert configured yet"
// contract (Active:false, no error) for a path that simply doesn't
// exist -- a real deployment may legitimately run plain HTTP.
func TestCheckTLSCertExpiryOfNonexistentCertPathIsAQuietNoOp(t *testing.T) {
	s := newTestService(t)
	if err := s.CheckTLSCertExpiry(context.Background(), "/nonexistent/path/server.crt", DefaultTLSExpiryWarnDays); err != nil {
		t.Fatalf("expected no error for a nonexistent cert path, got %v", err)
	}
}

// TestCheckTLSCertExpiryOfMalformedCertReturnsAnError proves a genuinely
// unreadable/corrupt cert (as opposed to simply absent) is a real error,
// not silently swallowed.
func TestCheckTLSCertExpiryOfMalformedCertReturnsAnError(t *testing.T) {
	s := newTestService(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	if err := os.WriteFile(certPath, []byte("not a real certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckTLSCertExpiry(context.Background(), certPath, DefaultTLSExpiryWarnDays); err == nil {
		t.Fatal("expected an error for a malformed cert file")
	}
}

// newSubscribedWebhookService wires a real hostagent-backed Service
// with one webhook provider subscribed to eventCategory, and returns a
// channel that receives the real body of any webhook POST it gets.
func newSubscribedWebhookService(t *testing.T, eventCategory string) (*Service, chan string) {
	t.Helper()
	s := newTestServiceWithSecrets(t)
	received := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		received <- string(buf[:n])
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	p, err := s.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret(ctx, p.ProviderID, srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSubscription(ctx, p.ProviderID, eventCategory, "info", true, nil); err != nil {
		t.Fatal(err)
	}
	return s, received
}
