// Package dnstransports is a native Go implementation of the Encryption
// page's DNS Transport settings storage, matching
// app/v2/policy_store.py's dns_transport_settings/dnscrypt_settings
// tables and load/save_*_settings field-for-field for the parts this
// package actually stores.
//
// Corrected stale disclosure (2026-08-28): this package's settings ARE
// compiled into the real, live Go-managed dnsdist listener -- see
// internal/dnscompile.CompileDnsdist's addTLSLocal/addDOHLocal/
// addDOQLocal calls, driven by internal/dnsruntime.Orchestrator.build()
// reading this package's Get() output. Enabling DoT/DoH/DoQ here and
// applying (either explicitly or via any other DNS-runtime-affecting
// mutation's auto-apply) genuinely starts that transport answering real
// queries against the appliance's own TLS cert. Proven end-to-end by
// internal/dnsperf's DoT/DoH benchmark cases (System Status's Safe DNS
// Benchmark), which exchange real TLS-wrapped DNS packets against
// exactly these compiled listeners.
//
// Deliberately not included here, disclosed rather than hidden:
//
//   - No port-conflict-with-a-live-listener detection (Python's
//     _RESERVED_APPLIANCE_PORTS check) -- this package validates the
//     port range only. A conflicting port IS now reachable at apply
//     time (dnsdist itself will simply fail to (re)start), surfaced as
//     an honest Apply failure/rollback, not caught earlier at Update
//     time the way Python's check does.
//   - DNSCrypt identity/certificate provisioning: real as of
//     0017_dnscrypt_identity.sql -- see RotateDNSCrypt and
//     internal/dnscryptprovision. The private provider key and the
//     resolver's short-term private key are real FILES on disk (the
//     same "a real file path, not a DB blob" convention
//     internal/tlscert already uses for the management TLS key dnsdist
//     itself also reuses), never stored in this table; only the
//     resulting file paths and the genuinely non-sensitive metadata
//     (the public key -- it IS the fingerprint clients pin -- and the
//     certificate serial/validity window) live here.
package dnstransports

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"alderpointdns/go-controlplane/internal/dnscryptprovision"
	"alderpointdns/go-controlplane/internal/hostagentd"
)

var ErrValidation = errors.New("validation failed")
var ErrDNSCryptNotProvisioned = errors.New("DNSCrypt has no provider identity/certificate yet -- rotate first")

// isLoopbackHostname matches internal/httpapi's and internal/mobileconfig's
// own definition -- a value that only ever means something to a client
// running ON this appliance itself, never a remote device.
func isLoopbackHostname(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// Settings mirrors DnsTransportSettings + the non-secret subset of
// DnscryptSettings.
type Settings struct {
	DotEnabled  bool   `json:"dot_enabled"`
	DotPort     int    `json:"dot_port"`
	DohEnabled  bool   `json:"doh_enabled"`
	DohPort     int    `json:"doh_port"`
	DohPath     string `json:"doh_path"`
	DoqEnabled  bool   `json:"doq_enabled"`
	DoqPort     int    `json:"doq_port"`
	Doh3Enabled bool   `json:"doh3_enabled"`
	Doh3Port    int    `json:"doh3_port"`

	// ClientFacing*: the owner's own record of what a REMOTE client
	// should actually be told to connect to -- see migration
	// 0027_client_facing_address.sql's doc comment for the exact defect
	// this exists to fix (a container bridge address auto-detected from
	// the web process's own isolated network namespace, shown to owners
	// as if it were a usable client-setup address). ClientFacingPrefer
	// is "auto" (prefer a real cert hostname, else the IP), "hostname",
	// or "ip".
	ClientFacingHostname string `json:"client_facing_hostname"`
	ClientFacingIP       string `json:"client_facing_ip"`
	ClientFacingPrefer   string `json:"client_facing_prefer"`

	DNSCryptEnabled      bool   `json:"dnscrypt_enabled"`
	DNSCryptPort         int    `json:"dnscrypt_port"`
	DNSCryptProviderName string `json:"dnscrypt_provider_name"`
	// True once RotateDNSCrypt has generated a real provider identity --
	// a real field, not a decorative placeholder: the frontend uses it
	// to show "not yet provisioned" rather than implying a working
	// DNSCrypt listener before one is.
	DNSCryptIdentityProvisioned  bool   `json:"dnscrypt_identity_provisioned"`
	DNSCryptProviderPublicKeyB64 string `json:"dnscrypt_provider_public_key_b64,omitempty"`
	DNSCryptFingerprint          string `json:"dnscrypt_fingerprint,omitempty"`
	DNSCryptProviderKeyPath      string `json:"-"` // never serialized -- a path to real key material
	DNSCryptCertPath             string `json:"-"`
	DNSCryptKeyPath              string `json:"-"`
	DNSCryptCertSerial           int64  `json:"dnscrypt_cert_serial,omitempty"`
	DNSCryptCertValidFrom        int64  `json:"dnscrypt_cert_valid_from,omitempty"`
	DNSCryptCertValidUntil       int64  `json:"dnscrypt_cert_valid_until,omitempty"`
}

func defaults() Settings {
	return Settings{
		DotPort: 853, DohPort: 443, DohPath: "/dns-query", DoqPort: 853, Doh3Port: 443,
		ClientFacingPrefer: "auto",
		DNSCryptPort:       5443, DNSCryptProviderName: "2.dnscrypt-cert.alderpointdns-go.local",
	}
}

type Service struct {
	DB *sql.DB
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	out := defaults()
	err := s.DB.QueryRowContext(ctx, `SELECT dot_enabled, dot_port, doh_enabled, doh_port, doh_path, doq_enabled, doq_port, doh3_enabled, doh3_port, client_facing_hostname, client_facing_ip, client_facing_prefer FROM dns_transport_settings WHERE id=1`).
		Scan(&out.DotEnabled, &out.DotPort, &out.DohEnabled, &out.DohPort, &out.DohPath, &out.DoqEnabled, &out.DoqPort, &out.Doh3Enabled, &out.Doh3Port,
			&out.ClientFacingHostname, &out.ClientFacingIP, &out.ClientFacingPrefer)
	if err != nil && err != sql.ErrNoRows {
		return Settings{}, err
	}
	if out.ClientFacingPrefer == "" {
		out.ClientFacingPrefer = "auto"
	}
	err = s.DB.QueryRowContext(ctx, `SELECT enabled, port, provider_name, provider_public_key_b64, provider_key_path, cert_path, key_path, cert_serial, cert_valid_from, cert_valid_until FROM dnscrypt_settings WHERE id=1`).
		Scan(&out.DNSCryptEnabled, &out.DNSCryptPort, &out.DNSCryptProviderName, &out.DNSCryptProviderPublicKeyB64,
			&out.DNSCryptProviderKeyPath, &out.DNSCryptCertPath, &out.DNSCryptKeyPath,
			&out.DNSCryptCertSerial, &out.DNSCryptCertValidFrom, &out.DNSCryptCertValidUntil)
	if err != nil && err != sql.ErrNoRows {
		return Settings{}, err
	}
	out.DNSCryptIdentityProvisioned = out.DNSCryptProviderKeyPath != ""
	if out.DNSCryptProviderPublicKeyB64 != "" {
		if pub, decErr := base64.StdEncoding.DecodeString(out.DNSCryptProviderPublicKeyB64); decErr == nil {
			if fp, fpErr := dnscryptprovision.ProviderFingerprint(pub); fpErr == nil {
				out.DNSCryptFingerprint = fp
			}
		}
	}
	return out, nil
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

func (s *Service) Update(ctx context.Context, in Settings) (Settings, error) {
	switch {
	case !validPort(in.DotPort):
		return Settings{}, fmt.Errorf("%w: invalid dot_port", ErrValidation)
	case !validPort(in.DohPort):
		return Settings{}, fmt.Errorf("%w: invalid doh_port", ErrValidation)
	case in.DohPath == "" || in.DohPath[0] != '/':
		return Settings{}, fmt.Errorf("%w: doh_path must start with /", ErrValidation)
	case !validPort(in.DoqPort):
		return Settings{}, fmt.Errorf("%w: invalid doq_port", ErrValidation)
	case !validPort(in.Doh3Port):
		return Settings{}, fmt.Errorf("%w: invalid doh3_port", ErrValidation)
	case !validPort(in.DNSCryptPort):
		return Settings{}, fmt.Errorf("%w: invalid dnscrypt_port", ErrValidation)
	case in.DNSCryptProviderName == "":
		return Settings{}, fmt.Errorf("%w: dnscrypt_provider_name must not be empty", ErrValidation)
	case in.ClientFacingPrefer != "" && in.ClientFacingPrefer != "auto" && in.ClientFacingPrefer != "hostname" && in.ClientFacingPrefer != "ip":
		return Settings{}, fmt.Errorf("%w: client_facing_prefer must be auto, hostname, or ip", ErrValidation)
	}
	if in.ClientFacingPrefer == "" {
		in.ClientFacingPrefer = "auto"
	}
	// Never let an owner accidentally save the exact defect this feature
	// exists to prevent: a loopback address, or a Podman/Docker default
	// bridge-network address, as the deliberate client-facing IP. A real
	// LAN address a client can actually reach is never inside these
	// ranges in practice.
	if in.ClientFacingIP != "" {
		if isLoopbackHostname(in.ClientFacingIP) {
			return Settings{}, fmt.Errorf("%w: client_facing_ip must not be localhost/loopback -- that only ever validates for a client running on this appliance itself", ErrValidation)
		}
		if hostagentd.IsContainerBridgeAddress(in.ClientFacingIP) {
			return Settings{}, fmt.Errorf("%w: client_facing_ip %q falls inside a Podman/Docker default bridge-network range, not a real LAN -- this is almost always a container-internal address a client can never reach; enter the appliance's real LAN IP instead", ErrValidation, in.ClientFacingIP)
		}
	}
	if in.ClientFacingHostname != "" && isLoopbackHostname(in.ClientFacingHostname) {
		return Settings{}, fmt.Errorf("%w: client_facing_hostname must not be localhost -- that only ever validates for a client running on this appliance itself", ErrValidation)
	}

	if in.DNSCryptEnabled {
		existing, err := s.Get(ctx)
		if err != nil {
			return Settings{}, err
		}
		// Real, deliberate guard, matching this appliance's established
		// posture for consequential crypto/trust actions: enabling
		// DNSCrypt before a provider identity has ever been issued is
		// rejected with a clear error rather than silently
		// auto-generating one as a side effect of a checkbox toggle --
		// generate it explicitly via RotateDNSCrypt first.
		if !existing.DNSCryptIdentityProvisioned {
			return Settings{}, ErrDNSCryptNotProvisioned
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Settings{}, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dns_transport_settings (id, dot_enabled, dot_port, doh_enabled, doh_port, doh_path, doq_enabled, doq_port, doh3_enabled, doh3_port, client_facing_hostname, client_facing_ip, client_facing_prefer, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			dot_enabled=excluded.dot_enabled, dot_port=excluded.dot_port,
			doh_enabled=excluded.doh_enabled, doh_port=excluded.doh_port, doh_path=excluded.doh_path,
			doq_enabled=excluded.doq_enabled, doq_port=excluded.doq_port,
			doh3_enabled=excluded.doh3_enabled, doh3_port=excluded.doh3_port,
			client_facing_hostname=excluded.client_facing_hostname, client_facing_ip=excluded.client_facing_ip, client_facing_prefer=excluded.client_facing_prefer,
			updated_at=excluded.updated_at`,
		in.DotEnabled, in.DotPort, in.DohEnabled, in.DohPort, in.DohPath, in.DoqEnabled, in.DoqPort, in.Doh3Enabled, in.Doh3Port,
		in.ClientFacingHostname, in.ClientFacingIP, in.ClientFacingPrefer, now,
	); err != nil {
		return Settings{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dnscrypt_settings (id, enabled, port, provider_name, updated_at)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, port=excluded.port, provider_name=excluded.provider_name, updated_at=excluded.updated_at`,
		in.DNSCryptEnabled, in.DNSCryptPort, in.DNSCryptProviderName, now,
	); err != nil {
		return Settings{}, err
	}
	if err := tx.Commit(); err != nil {
		return Settings{}, err
	}
	return s.Get(ctx)
}

const dnscryptCertValidityDays = 397 // matches internal/tlscert's own bounded-but-not-forever rationale

// RotateDNSCrypt issues real DNSCrypt provider/resolver key material via
// the real dnsdist binary (internal/dnscryptprovision) -- see that
// package's doc comment for the full design and why generation always
// goes through dnsdist itself. rotateProvider defaults to false (issue
// a fresh resolver certificate under the EXISTING provider identity --
// the routine action, e.g. before the current certificate expires)
// since rotating the provider identity itself invalidates every
// previously-pinned client's stamp and should never happen as a side
// effect of a routine cert renewal.
//
// keyDir is the directory real key/cert files are written to (0600,
// atomic rename) -- callers pass the same directory the management TLS
// cert/key already live in (internal/tlscert), so this reuses
// infrastructure the appliance already has a writable, dnsdist-
// readable mount for, rather than needing a new one.
func (s *Service) RotateDNSCrypt(ctx context.Context, rotateProvider bool, dnsdistBinary, keyDir string) (Settings, string, error) {
	existing, err := s.Get(ctx)
	if err != nil {
		return Settings{}, "", err
	}

	needNewProvider := rotateProvider || !existing.DNSCryptIdentityProvisioned
	var providerPrivateKey []byte
	var providerPublicKeyB64 string
	var providerKeyPath string
	if needNewProvider {
		pub, priv, err := dnscryptprovision.GenerateProviderKeypair(dnsdistBinary)
		if err != nil {
			return Settings{}, "", fmt.Errorf("generating provider keypair: %w", err)
		}
		providerPrivateKey = priv
		providerPublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
		providerKeyPath = filepath.Join(keyDir, "dnscrypt-provider.private")
		if err := atomicWriteFile(providerKeyPath, priv, 0o600); err != nil {
			return Settings{}, "", fmt.Errorf("writing provider key: %w", err)
		}
	} else {
		if existing.DNSCryptProviderKeyPath == "" {
			return Settings{}, "", ErrDNSCryptNotProvisioned
		}
		key, err := os.ReadFile(existing.DNSCryptProviderKeyPath)
		if err != nil {
			return Settings{}, "", fmt.Errorf("reading existing provider key: %w", err)
		}
		providerPrivateKey = key
		providerPublicKeyB64 = existing.DNSCryptProviderPublicKeyB64
		providerKeyPath = existing.DNSCryptProviderKeyPath
	}

	serial := existing.DNSCryptCertSerial + 1
	if needNewProvider {
		serial = 1 // a new provider identity restarts the resolver-cert serial sequence
	}
	now := time.Now().Unix()
	validUntil := now + dnscryptCertValidityDays*86400
	cert, resolverKey, err := dnscryptprovision.GenerateResolverCertificate(dnsdistBinary, providerPrivateKey, serial, now, validUntil)
	if err != nil {
		return Settings{}, "", fmt.Errorf("generating resolver certificate: %w", err)
	}
	certPath := filepath.Join(keyDir, "dnscrypt-resolver.cert")
	keyPath := filepath.Join(keyDir, "dnscrypt-resolver.key")
	if err := atomicWriteFile(certPath, cert, 0o644); err != nil {
		return Settings{}, "", fmt.Errorf("writing resolver certificate: %w", err)
	}
	if err := atomicWriteFile(keyPath, resolverKey, 0o600); err != nil {
		return Settings{}, "", fmt.Errorf("writing resolver key: %w", err)
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.DB.ExecContext(ctx, `
		INSERT INTO dnscrypt_settings (id, enabled, port, provider_name, provider_public_key_b64, provider_key_path, cert_path, key_path, cert_serial, cert_valid_from, cert_valid_until, updated_at)
		VALUES (1, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			provider_public_key_b64=excluded.provider_public_key_b64, provider_key_path=excluded.provider_key_path,
			cert_path=excluded.cert_path, key_path=excluded.key_path, cert_serial=excluded.cert_serial,
			cert_valid_from=excluded.cert_valid_from, cert_valid_until=excluded.cert_valid_until, updated_at=excluded.updated_at`,
		defaults().DNSCryptPort, defaults().DNSCryptProviderName, providerPublicKeyB64, providerKeyPath, certPath, keyPath, serial, now, validUntil, nowStr,
	); err != nil {
		return Settings{}, "", err
	}

	updated, err := s.Get(ctx)
	if err != nil {
		return Settings{}, "", err
	}
	return updated, updated.DNSCryptFingerprint, nil
}

// atomicWriteFile writes to a temp file in the same directory then
// renames over the target -- a reader (dnsdist reloading, or this
// service's own next Get/rotate) never observes a partially-written
// file, the same discipline internal/tlscert's own cert/key writer uses.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
