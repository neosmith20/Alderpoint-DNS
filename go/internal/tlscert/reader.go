// Package tlscert is a third, read-only Go->Python compatibility
// boundary, this time over Python's DNS-transport TLS certificate file
// (analytics_v2/../certs/server.crt -- the cert dnsdist's DoT/DoH/DoQ/
// DoH3 listeners present to clients, a different cert from either this
// Go control plane's own admin-UI TLS cert or the aggregates.db/Parquet
// analytics stores the other two boundaries read).
//
// Deliberately narrow, matching the pattern already established by
// internal/pyanalytics and internal/rawquerylog:
//
//   - Read-only, and only ever the public certificate (server.crt).
//     Never the private key (server.key) -- there is no legitimate
//     reason for this control plane to read Python's DNS-listener
//     private key, and this package's Open never even tries.
//   - Least-privilege: whatever directory is mounted in should be
//     certs/ only, never control.db or secrets/.
//   - Status-only. There is no "replace" here: promoting a new
//     certificate for Python's own dnsdist listener needs a live
//     restart of a process this Go control plane cannot reach (see
//     PARITY_MATRIX.md's Cache row for the identical, already-
//     documented network-isolation reason) -- so writing a new
//     cert here would silently do nothing. Better to not build a
//     button that lies.
package tlscert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"
)

var ErrNotProvisioned = errors.New("no certificate file present at the configured path")

type Status struct {
	Active       bool      `json:"active"`
	Subject      string    `json:"subject,omitempty"`
	NotBefore    time.Time `json:"not_valid_before,omitzero"`
	NotAfter     time.Time `json:"not_valid_after,omitzero"`
	SAN          []string  `json:"san,omitempty"`
	IsSelfSigned bool      `json:"is_self_signed,omitempty"`
}

type Reader struct {
	// CertPath is a read-only mount of Python's DNS-transport
	// server.crt (PEM). Never the key.
	CertPath string
}

// Status reads and parses the certificate at CertPath. A missing file is
// not an error -- it means "no certificate provisioned yet", matching
// Python's own tls_status endpoint returning {"active": false} rather
// than a 404/500 for the same case.
func (r *Reader) Status() (Status, error) {
	data, err := os.ReadFile(r.CertPath)
	if os.IsNotExist(err) {
		return Status{Active: false}, nil
	}
	if err != nil {
		return Status{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return Status{}, errors.New("certificate file is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Status{}, err
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

// isSelfSigned mirrors Python's own check (app/tls_cert.py): issuer ==
// subject and the certificate's own signature verifies against its own
// public key.
//
// Deliberately uses the low-level CheckSignature, not CheckSignatureFrom
// -- a real bug caught by this package's own test, not assumed away:
// CheckSignatureFrom additionally requires the signing certificate to be
// marked as a CA (BasicConstraintsValid + IsCA), which an ordinary
// self-signed *server* certificate (the kind this appliance actually
// generates -- CN-only, no CA extension) is not. CheckSignature verifies
// only the cryptographic signature itself, which is the actual
// definition of "self-signed" here, independent of CA capability.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}
