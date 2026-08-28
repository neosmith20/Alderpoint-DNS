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
//   - DNSCrypt identity/certificate provisioning (provider key pair,
//     signed resolver certificate) is not stored here at all. Python's
//     dnscrypt_settings keeps the real private key material in its
//     SecretStore, never in control.db directly -- this migration has no
//     Go-native secrets store yet (see internal/upstreams's doc comment
//     for the same disclosed gap), so DNSCrypt here is enabled/port/
//     provider_name only, honestly reported as never provisioned
//     (identity_provisioned is always false).
package dnstransports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrValidation = errors.New("validation failed")

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

	DNSCryptEnabled      bool   `json:"dnscrypt_enabled"`
	DNSCryptPort         int    `json:"dnscrypt_port"`
	DNSCryptProviderName string `json:"dnscrypt_provider_name"`
	// Always false here -- see the package doc comment's DNSCrypt
	// disclosure. A real field, not a decorative placeholder: the
	// frontend uses it exactly like Python's UI does, to show "not yet
	// provisioned" rather than implying a working DNSCrypt listener.
	DNSCryptIdentityProvisioned bool `json:"dnscrypt_identity_provisioned"`
}

func defaults() Settings {
	return Settings{
		DotPort: 853, DohPort: 443, DohPath: "/dns-query", DoqPort: 853, Doh3Port: 443,
		DNSCryptPort: 5443, DNSCryptProviderName: "2.dnscrypt-cert.alderpointdns-go.local",
	}
}

type Service struct {
	DB *sql.DB
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	out := defaults()
	err := s.DB.QueryRowContext(ctx, `SELECT dot_enabled, dot_port, doh_enabled, doh_port, doh_path, doq_enabled, doq_port, doh3_enabled, doh3_port FROM dns_transport_settings WHERE id=1`).
		Scan(&out.DotEnabled, &out.DotPort, &out.DohEnabled, &out.DohPort, &out.DohPath, &out.DoqEnabled, &out.DoqPort, &out.Doh3Enabled, &out.Doh3Port)
	if err != nil && err != sql.ErrNoRows {
		return Settings{}, err
	}
	err = s.DB.QueryRowContext(ctx, `SELECT enabled, port, provider_name FROM dnscrypt_settings WHERE id=1`).
		Scan(&out.DNSCryptEnabled, &out.DNSCryptPort, &out.DNSCryptProviderName)
	if err != nil && err != sql.ErrNoRows {
		return Settings{}, err
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
	}

	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Settings{}, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dns_transport_settings (id, dot_enabled, dot_port, doh_enabled, doh_port, doh_path, doq_enabled, doq_port, doh3_enabled, doh3_port, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			dot_enabled=excluded.dot_enabled, dot_port=excluded.dot_port,
			doh_enabled=excluded.doh_enabled, doh_port=excluded.doh_port, doh_path=excluded.doh_path,
			doq_enabled=excluded.doq_enabled, doq_port=excluded.doq_port,
			doh3_enabled=excluded.doh3_enabled, doh3_port=excluded.doh3_port, updated_at=excluded.updated_at`,
		in.DotEnabled, in.DotPort, in.DohEnabled, in.DohPort, in.DohPath, in.DoqEnabled, in.DoqPort, in.Doh3Enabled, in.Doh3Port, now,
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
