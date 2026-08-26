package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genCertKeyPair builds a real, self-signed EC P-256 cert+key pair with
// the given validity window -- the same shape a real uploaded
// certificate has, not a canned fixture string.
func genCertKeyPair(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestValidateCertKeyPairAcceptsARealMatchingPair(t *testing.T) {
	cert, key := genCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	info, err := ValidateCertKeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Active || !info.IsSelfSigned {
		t.Fatalf("expected an active, self-signed result, got %+v", info)
	}
}

func TestValidateCertKeyPairRejectsAMismatchedKey(t *testing.T) {
	cert, _ := genCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, otherKey := genCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if _, err := ValidateCertKeyPair(cert, otherKey); err == nil {
		t.Fatal("expected a key-mismatch error")
	}
}

func TestValidateCertKeyPairRejectsAnExpiredCert(t *testing.T) {
	cert, key := genCertKeyPair(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	if _, err := ValidateCertKeyPair(cert, key); err == nil {
		t.Fatal("expected an expired-certificate error")
	}
}

func TestValidateCertKeyPairRejectsANotYetValidCert(t *testing.T) {
	cert, key := genCertKeyPair(t, time.Now().Add(time.Hour), time.Now().Add(48*time.Hour))
	if _, err := ValidateCertKeyPair(cert, key); err == nil {
		t.Fatal("expected a not-yet-valid error")
	}
}

func TestValidateCertKeyPairRejectsGarbage(t *testing.T) {
	if _, err := ValidateCertKeyPair([]byte("not a cert"), []byte("not a key")); err == nil {
		t.Fatal("expected an unparsable-certificate error")
	}
}

func TestStageValidatePromoteWritesRealFilesWithCorrectModes(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	cert, key := genCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	info, err := StageValidatePromote(cert, key, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Active {
		t.Fatalf("expected an active result, got %+v", info)
	}

	certOnDisk, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(certOnDisk) != string(cert) {
		t.Fatal("promoted certificate content does not match")
	}
	keyStat, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if keyStat.Mode().Perm() != 0o600 {
		t.Fatalf("expected the private key file to be mode 0600, got %o", keyStat.Mode().Perm())
	}
	certStat, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if certStat.Mode().Perm() != 0o644 {
		t.Fatalf("expected the certificate file to be mode 0644, got %o", certStat.Mode().Perm())
	}
}

// TestStageValidatePromoteNeverTouchesLiveFilesOnValidationFailure is the
// real safety proof: a bad replacement (real §5 requirement, matching
// Python's own contract exactly) must never destroy the currently
// working certificate.
func TestStageValidatePromoteNeverTouchesLiveFilesOnValidationFailure(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	goodCert, goodKey := genCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if _, err := StageValidatePromote(goodCert, goodKey, certPath, keyPath); err != nil {
		t.Fatal(err)
	}

	expiredCert, _ := genCertKeyPair(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	_, badKey := genCertKeyPair(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if _, err := StageValidatePromote(expiredCert, badKey, certPath, keyPath); err == nil {
		t.Fatal("expected the bad replacement to be rejected")
	}

	stillThere, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(stillThere) != string(goodCert) {
		t.Fatal("the currently-working certificate must be completely untouched after a rejected replacement")
	}
}
