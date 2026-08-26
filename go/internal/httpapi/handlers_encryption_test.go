package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func genTestCertKeyPair(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
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
