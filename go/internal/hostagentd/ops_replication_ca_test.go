package hostagentd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"alderpointdns/go-controlplane/internal/hostagent"
)

func TestReplicationEnsureCAProducesARealSelfSignedCACert(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	var out map[string]any
	if err := c.Call(context.Background(), hostagent.OpReplicationEnsureCA, nil, &out); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := out["ca_cert_pem"].(string)
	if certPEM == "" {
		t.Fatal("expected a real ca_cert_pem")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("ca_cert_pem is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ca_cert_pem does not parse as a real certificate: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("expected a real CA certificate (IsCA=true)")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("expected a genuinely self-signed certificate, signature check failed: %v", err)
	}
	if out["ciphertext_b64"] == "" || out["nonce_b64"] == "" {
		t.Fatalf("expected the CA private key to come back sealed, got %+v", out)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("OpReplicationEnsureCA's response must never contain the plaintext CA private key")
	}
}

func TestReplicationEnsureCAProducesADifferentCAEachCall(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	var out1, out2 map[string]any
	c.Call(context.Background(), hostagent.OpReplicationEnsureCA, nil, &out1)
	c.Call(context.Background(), hostagent.OpReplicationEnsureCA, nil, &out2)
	if out1["ca_cert_pem"] == out2["ca_cert_pem"] {
		t.Fatal("expected two independent calls to generate two different CAs")
	}
}

// TestReplicationIssueCertSignsARealLeafCertVerifiableAgainstTheCA proves
// the full real chain: generate a CA (sealed key), issue a server leaf
// and a client leaf, and verify both actually chain to the CA using
// Go's own x509 verification -- not just "some bytes came back".
func TestReplicationIssueCertSignsARealLeafCertVerifiableAgainstTheCA(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	var ca map[string]any
	if err := c.Call(context.Background(), hostagent.OpReplicationEnsureCA, nil, &ca); err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(ca["ca_cert_pem"].(string))) {
		t.Fatal("failed to load the generated CA cert into a pool")
	}

	for _, tc := range []struct {
		keyUsage string
		extUsage x509.ExtKeyUsage
	}{
		{"server", x509.ExtKeyUsageServerAuth},
		{"client", x509.ExtKeyUsageClientAuth},
	} {
		var leaf map[string]any
		params := map[string]any{
			"ca": map[string]any{
				"kind": "replication_ca_key", "owner_ref": "replication",
				"ciphertext_b64": ca["ciphertext_b64"], "nonce_b64": ca["nonce_b64"], "key_version": ca["key_version"],
			},
			"ca_cert_pem": ca["ca_cert_pem"],
			"cn":          "test-node-" + tc.keyUsage,
			"sans":        []string{"127.0.0.1", "alderpointdns-primary"},
			"key_usage":   tc.keyUsage,
			"days":        30,
		}
		if err := c.Call(context.Background(), hostagent.OpReplicationIssueCert, params, &leaf); err != nil {
			t.Fatalf("%s: %v", tc.keyUsage, err)
		}
		certPEM, _ := leaf["cert_pem"].(string)
		keyPEM, _ := leaf["key_pem"].(string)
		if certPEM == "" || keyPEM == "" {
			t.Fatalf("%s: expected real cert_pem and key_pem, got %+v", tc.keyUsage, leaf)
		}
		block, _ := pem.Decode([]byte(certPEM))
		leafCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", tc.keyUsage, err)
		}
		if _, err := leafCert.Verify(x509.VerifyOptions{
			Roots: pool, KeyUsages: []x509.ExtKeyUsage{tc.extUsage},
		}); err != nil {
			t.Fatalf("%s: leaf cert did not verify against the real CA: %v", tc.keyUsage, err)
		}
		if leaf["fingerprint"] == "" || leaf["serial"] == "" {
			t.Fatalf("%s: expected real fingerprint/serial, got %+v", tc.keyUsage, leaf)
		}
	}
}

func TestReplicationIssueCertRejectsMissingCN(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	var ca map[string]any
	c.Call(context.Background(), hostagent.OpReplicationEnsureCA, nil, &ca)
	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpReplicationIssueCert, map[string]any{
		"ca": map[string]any{
			"kind": "replication_ca_key", "owner_ref": "replication",
			"ciphertext_b64": ca["ciphertext_b64"], "nonce_b64": ca["nonce_b64"], "key_version": ca["key_version"],
		},
		"ca_cert_pem": ca["ca_cert_pem"], "key_usage": "server",
	}, &out)
	if err == nil {
		t.Fatal("expected an error for a missing cn")
	}
}

func TestReplicationIssueCertRejectsBadKeyUsage(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	var ca map[string]any
	c.Call(context.Background(), hostagent.OpReplicationEnsureCA, nil, &ca)
	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpReplicationIssueCert, map[string]any{
		"ca": map[string]any{
			"kind": "replication_ca_key", "owner_ref": "replication",
			"ciphertext_b64": ca["ciphertext_b64"], "nonce_b64": ca["nonce_b64"], "key_version": ca["key_version"],
		},
		"ca_cert_pem": ca["ca_cert_pem"], "cn": "x", "key_usage": "not-a-real-usage",
	}, &out)
	if err == nil {
		t.Fatal("expected an error for an invalid key_usage")
	}
}

func TestReplicationIssueCertRejectsWrongSealedOwner(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	var ca map[string]any
	c.Call(context.Background(), hostagent.OpReplicationEnsureCA, nil, &ca)
	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpReplicationIssueCert, map[string]any{
		"ca": map[string]any{
			// Wrong owner_ref -- the AAD binding must reject this even
			// though ciphertext/nonce/key_version are all otherwise real.
			"kind": "replication_ca_key", "owner_ref": "not-replication",
			"ciphertext_b64": ca["ciphertext_b64"], "nonce_b64": ca["nonce_b64"], "key_version": ca["key_version"],
		},
		"ca_cert_pem": ca["ca_cert_pem"], "cn": "x", "key_usage": "server",
	}, &out)
	if err == nil {
		t.Fatal("expected the wrong owner_ref to fail AEAD authentication")
	}
}
