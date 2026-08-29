package dnscryptprovision

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func requireDnsdist(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("dnsdist")
	if err != nil {
		t.Skip("dnsdist not installed, skipping real DNSCrypt provisioning test")
	}
	return bin
}

func TestGenerateProviderKeypairProducesRealCorrectlySizedKeys(t *testing.T) {
	bin := requireDnsdist(t)
	pub, priv, err := GenerateProviderKeypair(bin)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ProviderPublicKeyLength {
		t.Fatalf("public key length = %d, want %d", len(pub), ProviderPublicKeyLength)
	}
	if len(priv) != ProviderPrivateKeyLength {
		t.Fatalf("private key length = %d, want %d", len(priv), ProviderPrivateKeyLength)
	}
}

func TestGenerateProviderKeypairIsNotDeterministic(t *testing.T) {
	bin := requireDnsdist(t)
	pub1, _, err := GenerateProviderKeypair(bin)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := GenerateProviderKeypair(bin)
	if err != nil {
		t.Fatal(err)
	}
	if string(pub1) == string(pub2) {
		t.Fatal("expected two independent generations to produce different keys")
	}
}

func TestGenerateResolverCertificateProducesRealCorrectlySizedMaterial(t *testing.T) {
	bin := requireDnsdist(t)
	_, providerPriv, err := GenerateProviderKeypair(bin)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	cert, resolverKey, err := GenerateResolverCertificate(bin, providerPriv, 1, now, now+86400)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert) != DNSCryptCertLength {
		t.Fatalf("cert length = %d, want %d", len(cert), DNSCryptCertLength)
	}
	if len(resolverKey) != ResolverPrivateKeyLength {
		t.Fatalf("resolver key length = %d, want %d", len(resolverKey), ResolverPrivateKeyLength)
	}
}

func TestGenerateResolverCertificateRejectsBadProviderKeyLength(t *testing.T) {
	bin := requireDnsdist(t)
	now := time.Now().Unix()
	if _, _, err := GenerateResolverCertificate(bin, []byte("too short"), 1, now, now+86400); err == nil {
		t.Fatal("expected an error for a wrong-length provider private key")
	}
}

func TestGenerateResolverCertificateRejectsInvalidValidity(t *testing.T) {
	bin := requireDnsdist(t)
	_, providerPriv, err := GenerateProviderKeypair(bin)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, _, err := GenerateResolverCertificate(bin, providerPriv, 1, now, now-1); err == nil {
		t.Fatal("expected an error when valid_until <= valid_from")
	}
	if _, _, err := GenerateResolverCertificate(bin, providerPriv, 0, now, now+86400); err == nil {
		t.Fatal("expected an error for a non-positive serial")
	}
}

func TestProviderFingerprintFormat(t *testing.T) {
	pub := make([]byte, ProviderPublicKeyLength)
	for i := range pub {
		pub[i] = byte(i)
	}
	fp, err := ProviderFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	// 32 bytes -> 64 hex chars -> 16 groups of 4, joined by ':' -> 16*4 + 15 = 79 chars.
	if len(fp) != 79 {
		t.Fatalf("fingerprint %q has length %d, want 79", fp, len(fp))
	}
	if fp[:9] != "0001:0203" {
		t.Fatalf("fingerprint %q does not start with the expected first two groups", fp)
	}
}

func TestProviderFingerprintRejectsWrongLength(t *testing.T) {
	if _, err := ProviderFingerprint([]byte("short")); err == nil {
		t.Fatal("expected an error for a wrong-length public key")
	}
}

// TestGeneratedResolverCertificateValidatesAgainstRealDnsdistCheckConfig
// proves the end-to-end generated material is genuinely accepted by
// addDNSCryptBind on the real installed dnsdist -- the same
// proof-against-the-real-target-runtime standard every compiler in this
// codebase uses.
func TestGeneratedResolverCertificateValidatesAgainstRealDnsdistCheckConfig(t *testing.T) {
	bin := requireDnsdist(t)
	dir := t.TempDir()

	_, providerPriv, err := GenerateProviderKeypair(bin)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	cert, key, err := GenerateResolverCertificate(bin, providerPriv, 1, now, now+86400)
	if err != nil {
		t.Fatal(err)
	}
	certPath := dir + "/resolver.cert"
	keyPath := dir + "/resolver.key"
	if err := os.WriteFile(certPath, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}

	config := `addDNSCryptBind("127.0.0.1:35443", "2.dnscrypt-cert.test", "` + certPath + `", "` + keyPath + `")`
	confPath := dir + "/dnsdist.conf"
	if err := os.WriteFile(confPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-C", confPath, "--check-config").CombinedOutput()
	if err != nil {
		t.Fatalf("dnsdist --check-config rejected generated config: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "Error adding DNSCrypt frontend") {
		t.Fatalf("dnsdist reported an error adding the DNSCrypt frontend with real generated material:\n%s", out)
	}
}
