package replication

import (
	"context"
	"fmt"

	"alderpointdns/go-controlplane/internal/hostagent"
)

// sealedCARef is what every hostagent op that needs to USE the CA key
// (never read it) is given -- the same ciphertext/nonce/key_version
// shape internal/hostagentd's sealedIn already expects.
type sealedCARef struct {
	Kind          string `json:"kind"`
	OwnerRef      string `json:"owner_ref"`
	CiphertextB64 string `json:"ciphertext_b64"`
	NonceB64      string `json:"nonce_b64"`
	KeyVersion    int    `json:"key_version"`
}

const caSealKind = "replication_ca_key"
const caSealOwnerRef = "replication"

// EnsureCA returns this node's own replication CA certificate,
// generating one (entirely inside apdns-hostagent -- the plaintext
// private key never exists anywhere else, at rest or in memory) the
// first time this is ever called. Idempotent: a CA already recorded in
// replication_settings is returned as-is, never regenerated (that would
// invalidate every previously-issued cert).
func (s *Service) EnsureCA(ctx context.Context) (string, error) {
	settings, err := s.GetSettings(ctx)
	if err != nil {
		return "", err
	}
	if settings.CACertPEM != "" {
		return settings.CACertPEM, nil
	}
	var out struct {
		CACertPEM     string `json:"ca_cert_pem"`
		CiphertextB64 string `json:"ciphertext_b64"`
		NonceB64      string `json:"nonce_b64"`
		KeyVersion    int    `json:"key_version"`
	}
	if err := s.hostAgentCall(ctx, hostagent.OpReplicationEnsureCA, nil, &out); err != nil {
		return "", fmt.Errorf("generating replication CA: %w", err)
	}
	for k, v := range map[string]string{
		"ca_cert_pem": out.CACertPEM, "ca_key_ciphertext_b64": out.CiphertextB64,
		"ca_key_nonce_b64": out.NonceB64, "ca_key_version": fmt.Sprintf("%d", out.KeyVersion),
	} {
		if err := s.setSetting(ctx, k, v); err != nil {
			return "", err
		}
	}
	return out.CACertPEM, nil
}

// issuedCert is the real, freshly-signed material apdns-hostagent hands
// back -- cert_pem/key_pem are meant to be handed to a replica (client
// cert) or written to this node's own server-cert files (server cert),
// never a secret this process itself must protect at rest.
type issuedCert struct {
	CertPEM     string `json:"cert_pem"`
	KeyPEM      string `json:"key_pem"`
	Fingerprint string `json:"fingerprint"`
	Serial      string `json:"serial"`
}

// issueCert signs a fresh leaf certificate from this node's own CA.
// keyUsage is "server" or "client". EnsureCA must have already been
// called (a real CA cert/sealed key must exist in settings).
func (s *Service) issueCert(ctx context.Context, cn string, sans []string, keyUsage string, days int) (issuedCert, error) {
	settings, err := s.GetSettings(ctx)
	if err != nil {
		return issuedCert{}, err
	}
	if settings.CACertPEM == "" {
		return issuedCert{}, fmt.Errorf("no replication CA exists yet")
	}
	if days <= 0 {
		days = DefaultCertDays
	}
	var out issuedCert
	err = s.hostAgentCall(ctx, hostagent.OpReplicationIssueCert, map[string]any{
		"ca": sealedCARef{
			Kind: caSealKind, OwnerRef: caSealOwnerRef,
			CiphertextB64: settings.CAKeyCiphertextB64, NonceB64: settings.CAKeyNonceB64, KeyVersion: settings.CAKeyVersion,
		},
		"ca_cert_pem": settings.CACertPEM,
		"cn":          cn, "sans": sans, "key_usage": keyUsage, "days": days,
	}, &out)
	if err != nil {
		return issuedCert{}, fmt.Errorf("issuing certificate: %w", err)
	}
	return out, nil
}
