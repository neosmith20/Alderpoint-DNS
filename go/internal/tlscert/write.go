// This file adds the write side to package tlscert: upload/replace for
// this control plane's OWN management TLS certificate (the one
// configured as web.tls_cert_path/tls_key_path in appliance.yaml,
// which this control plane's own HTTPS listener actually serves, and
// which internal/dnscompile's DoT/DoH listeners now reuse too -- the
// same real architecture Python's own DotConfig/DohConfig doc comment
// describes: "a single appliance-wide cert used for DoH/DoT alike").
//
// This supersedes this package's original read-only-mirror-of-Python's-
// cert role (see the doc comment history in git log) now that this
// control plane owns and can actually replace its own certificate --
// the whole point of "upload/replace" only makes sense against
// something this process can actually promote. Field-matched against
// Python's own real app/v2/tls_cert.py (read directly, not guessed):
// same validation rules (parsable cert/key, key's public component
// matches the cert's, validity window covers "now"), same atomic
// stage -> validate -> promote contract (a bad replacement never
// touches the live paths at all), same file modes (key 0600, cert
// 0644), and the same honest "restart_required: true" contract --
// Python's own comment on this is explicit: "the running uvicorn
// process does not hot-reload TLS material... this is standard
// behavior for a process-level TLS listener, not a defect." This
// package makes the identical choice rather than building a more
// complex hot-reload path Python's own reference doesn't have either.
package tlscert

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrUnparsableCertificate = errors.New("unparsable certificate")
	ErrUnparsableKey         = errors.New("unparsable private key")
	ErrKeyMismatch           = errors.New("private key does not match certificate public key")
	ErrNotYetValid           = errors.New("certificate is not yet valid")
	ErrExpired               = errors.New("certificate has expired")
)

const (
	keyFileMode  = 0o600
	certFileMode = 0o644
)

// ValidateCertKeyPair parses both PEM blobs, confirms the key's public
// component matches the certificate's, and checks the validity window
// covers now. Never returns a partial/best-effort result -- an error
// here means neither is trusted at all.
func ValidateCertKeyPair(certPEM, keyPEM []byte) (Status, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return Status{}, fmt.Errorf("%w: not valid PEM", ErrUnparsableCertificate)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Status{}, fmt.Errorf("%w: %v", ErrUnparsableCertificate, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return Status{}, fmt.Errorf("%w: not valid PEM", ErrUnparsableKey)
	}
	priv, err := parsePrivateKey(keyBlock)
	if err != nil {
		return Status{}, fmt.Errorf("%w: %v", ErrUnparsableKey, err)
	}

	type equaler interface{ Equal(x crypto.PublicKey) bool }
	certPub, ok := cert.PublicKey.(equaler)
	if !ok || !certPub.Equal(priv.Public()) {
		return Status{}, ErrKeyMismatch
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return Status{}, fmt.Errorf("%w (not_before=%s)", ErrNotYetValid, cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return Status{}, fmt.Errorf("%w (not_after=%s)", ErrExpired, cert.NotAfter.Format(time.RFC3339))
	}

	san := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		san = append(san, ip.String())
	}
	return Status{
		Active: true, Subject: cert.Subject.String(),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		SAN: san, IsSelfSigned: isSelfSigned(cert),
	}, nil
}

// StageValidatePromote validates the pair first (no disk I/O on the
// live paths yet); only on success are both files atomically promoted,
// key written before cert so a partially-promoted pair (cert present,
// key not yet) is never observable. On validation failure the
// currently-active certificate/key are completely untouched.
func StageValidatePromote(certPEM, keyPEM []byte, liveCertPath, liveKeyPath string) (Status, error) {
	info, err := ValidateCertKeyPair(certPEM, keyPEM)
	if err != nil {
		return Status{}, err
	}
	if err := os.MkdirAll(filepath.Dir(liveCertPath), 0o750); err != nil {
		return Status{}, err
	}
	if err := os.MkdirAll(filepath.Dir(liveKeyPath), 0o750); err != nil {
		return Status{}, err
	}
	if err := atomicWriteFile(liveKeyPath, keyPEM, keyFileMode); err != nil {
		return Status{}, fmt.Errorf("writing key: %w", err)
	}
	if err := atomicWriteFile(liveCertPath, certPEM, certFileMode); err != nil {
		return Status{}, fmt.Errorf("writing certificate: %w", err)
	}
	return info, nil
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + fmt.Sprintf(".tmp.%d", os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// parsePrivateKey tries every private-key PEM encoding a real uploaded
// key is plausibly in (PKCS8 -- what this package's own generated keys
// and most modern tooling produce -- then the older EC- and RSA-
// specific encodings), matching the effective coverage of Python's
// `cryptography.load_pem_private_key`, which auto-detects among the
// same formats.
func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported PKCS8 key type %T", k)
		}
		return signer, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("not a recognized PKCS8/EC/PKCS1 private key")
}
