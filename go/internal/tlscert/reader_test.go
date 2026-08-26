package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSignedCert(t *testing.T, path string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.alderpointdns.local"},
		DNSNames:     []string{"test.alderpointdns.local", "alt.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestStatusOfMissingFileReportsInactiveNotError(t *testing.T) {
	r := &Reader{CertPath: filepath.Join(t.TempDir(), "does-not-exist.crt")}
	status, err := r.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.Active {
		t.Fatal("expected Active=false for a missing certificate file")
	}
}

func TestStatusParsesARealSelfSignedCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.crt")
	notBefore := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	notAfter := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	writeSelfSignedCert(t, path, notBefore, notAfter)

	r := &Reader{CertPath: path}
	status, err := r.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !status.Active {
		t.Fatal("expected Active=true for a real certificate file")
	}
	if !status.IsSelfSigned {
		t.Fatal("expected a self-signed cert to be reported as such")
	}
	if !status.NotBefore.Equal(notBefore) || !status.NotAfter.Equal(notAfter) {
		t.Fatalf("expected validity window %v..%v, got %v..%v", notBefore, notAfter, status.NotBefore, status.NotAfter)
	}
	wantSAN := map[string]bool{"test.alderpointdns.local": true, "alt.example.com": true, "127.0.0.1": true}
	if len(status.SAN) != len(wantSAN) {
		t.Fatalf("expected %d SAN entries, got %+v", len(wantSAN), status.SAN)
	}
	for _, s := range status.SAN {
		if !wantSAN[s] {
			t.Fatalf("unexpected SAN entry %q, want one of %+v", s, wantSAN)
		}
	}
}

func TestIsSelfSignedRejectsADifferentSubjectAndIssuer(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "leaf.example.com"},
		Issuer:  pkix.Name{CommonName: "some-ca.example.com"},
	}
	if isSelfSigned(cert) {
		t.Fatal("a cert with a different subject/issuer must never be reported self-signed")
	}
}

func TestStatusRejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.crt")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Reader{CertPath: path}
	if _, err := r.Status(); err == nil {
		t.Fatal("expected an error for a file that isn't valid PEM")
	}
}
