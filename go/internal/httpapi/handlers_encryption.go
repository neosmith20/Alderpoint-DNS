package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/mobileconfig"
	"alderpointdns/go-controlplane/internal/tlscert"
)

// isLoopbackHostname matches mobileconfig's own definition -- a
// certificate subject that only ever means something to a client running
// ON this appliance itself, never a remote device.
func isLoopbackHostname(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func transportsJSON(s dnstransports.Settings) map[string]any {
	return map[string]any{
		"dot_enabled": s.DotEnabled, "dot_port": s.DotPort,
		"doh_enabled": s.DohEnabled, "doh_port": s.DohPort, "doh_path": s.DohPath,
		"doq_enabled": s.DoqEnabled, "doq_port": s.DoqPort,
		"doh3_enabled": s.Doh3Enabled, "doh3_port": s.Doh3Port,
		"dnscrypt_enabled": s.DNSCryptEnabled, "dnscrypt_port": s.DNSCryptPort,
		"dnscrypt_provider_name": s.DNSCryptProviderName, "dnscrypt_identity_provisioned": s.DNSCryptIdentityProvisioned,
		"dnscrypt_fingerprint": s.DNSCryptFingerprint, "dnscrypt_cert_serial": s.DNSCryptCertSerial,
		"dnscrypt_cert_valid_from": s.DNSCryptCertValidFrom, "dnscrypt_cert_valid_until": s.DNSCryptCertValidUntil,
	}
}

func (s *Server) handleGetDNSTransports(w http.ResponseWriter, r *http.Request) {
	settings, err := s.DNSTransports.Get(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load transport settings").WriteJSON(w)
		return
	}
	out := transportsJSON(settings)
	// The same hostname source the Apple .mobileconfig profile already
	// uses (the active HTTPS cert's own first SAN entry) -- surfaced
	// here too so the UI can show real manual connection details
	// (server address:port) for every transport, not just an
	// Apple-specific downloadable profile for DoT/DoH. cert_san is the
	// FULL SAN list (not just the first entry) so the frontend can
	// actually check "would a client validating this address against the
	// cert succeed" instead of guessing.
	var san []string
	if s.TLSCertPath != "" {
		if status, err := (&tlscert.Reader{CertPath: s.TLSCertPath}).Status(); err == nil && status.Active && len(status.SAN) > 0 {
			out["server_hostname"] = status.SAN[0]
			san = status.SAN
		}
	}
	out["cert_san"] = san

	// lan_ip(s): a real, separately-sourced client-facing candidate --
	// the appliance's own detected LAN address(es) -- distinct from
	// whatever this process happens to bind/listen on (which is
	// frequently 0.0.0.0/::, itself never something to hand a client).
	// The frontend falls back to this when the certificate's own
	// hostname is only "localhost"/loopback, so setup guidance never
	// recommends an address that only means something on this box.
	lanIPs := detectServerIPs()
	out["lan_ips"] = lanIPs
	if len(lanIPs) > 0 {
		out["lan_ip"] = lanIPs[0]
	}

	// DNSCrypt's real sdns:// stamp, once a provider identity actually
	// exists -- built from the same client-facing address resolution
	// (real hostname if the cert has one and it isn't loopback,
	// otherwise the detected LAN IP): unlike DoT/DoH/DoQ/DoH3, DNSCrypt
	// doesn't use the TLS certificate as its trust anchor at all (the
	// provider public key pinned in the stamp is), so this has no
	// certificate-validity gate.
	if settings.DNSCryptIdentityProvisioned && settings.DNSCryptProviderPublicKeyB64 != "" {
		addr := clientFacingAddress(san, lanIPs)
		if addr != "" {
			if pub, err := base64.StdEncoding.DecodeString(settings.DNSCryptProviderPublicKeyB64); err == nil {
				stampAddr := fmt.Sprintf("%s:%d", addr, settings.DNSCryptPort)
				out["dnscrypt_stamp"] = dnstransports.BuildDNSCryptStamp(stampAddr, pub, settings.DNSCryptProviderName)
			}
		}
	}

	WriteJSON(w, http.StatusOK, out)
}

// clientFacingAddress picks the same "what should a client actually be
// told" candidate the frontend derives independently for display: the
// certificate's own hostname when it's real (not loopback), else the
// first detected LAN IP, else nothing.
func clientFacingAddress(san, lanIPs []string) string {
	if len(san) > 0 && !isLoopbackHostname(san[0]) {
		return san[0]
	}
	if len(lanIPs) > 0 {
		return lanIPs[0]
	}
	return ""
}

func (s *Server) handleUpdateDNSTransports(w http.ResponseWriter, r *http.Request) {
	var in dnstransports.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	updated, err := s.DNSTransports.Update(r.Context(), in)
	if err != nil {
		if errors.Is(err, dnstransports.ErrValidation) {
			Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
			return
		}
		if errors.Is(err, dnstransports.ErrDNSCryptNotProvisioned) {
			Err(http.StatusConflict, "dnscrypt_not_provisioned", err.Error()).WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	out := transportsJSON(updated)
	out["dns_runtime"] = s.applyDNSRuntimeBestEffort(r)
	WriteJSON(w, http.StatusOK, out)
}

// handleTLSStatus reports this control plane's OWN real, currently-
// configured management TLS certificate (TLSCertPath/TLSKeyPath) --
// {"active": false} when neither is configured (an appliance running
// plain HTTP, or the fields aren't wired at this deployment), matching
// Python's own shape for "no certificate provisioned" rather than a
// 500.
func (s *Server) handleTLSStatus(w http.ResponseWriter, r *http.Request) {
	if s.TLSCertPath == "" || s.TLSKeyPath == "" {
		WriteJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	status, err := (&tlscert.Reader{CertPath: s.TLSCertPath}).Status()
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"active": false, "error": err.Error()})
		return
	}
	WriteJSON(w, http.StatusOK, status)
}

type tlsReplaceRequest struct {
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
}

// handleTLSReplace is the real upload/replace workflow, field-matched
// against Python's own POST /api/tls/replace (app/v2/webapp.py's
// tls_replace, read directly): validate first (nothing touched on
// failure), atomically promote on success, and report
// restart_required=true -- the same honest contract Python's own
// comment gives for exactly the same reason (a process-level TLS
// listener does not hot-reload its certificate; this is standard
// behavior, not a defect, so this handler doesn't pretend otherwise).
func (s *Server) handleTLSReplace(w http.ResponseWriter, r *http.Request) {
	if s.TLSCertPath == "" || s.TLSKeyPath == "" {
		Err(http.StatusServiceUnavailable, "unavailable", "this deployment has no management TLS cert/key path configured").WriteJSON(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap -- a cert+key pair is a few KB
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	var req tlsReplaceRequest
	if err := json.Unmarshal(body, &req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	info, err := tlscert.StageValidatePromote([]byte(req.CertificatePEM), []byte(req.PrivateKeyPEM), s.TLSCertPath, s.TLSKeyPath)
	if err != nil {
		Err(http.StatusBadRequest, "invalid_certificate", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"status": "promoted", "restart_required": true,
		"subject": info.Subject, "not_valid_after": info.NotAfter,
	})
}

// handleDNSTransportMobileconfig mirrors GET
// /api/dns-transports/mobileconfig/{protocol}: a real Apple
// com.apple.dnsSettings.managed configuration profile, built entirely
// from this control plane's own native state (internal/dnstransports +
// internal/tlscert, both already real Go-owned data -- no new
// compatibility boundary, no new mount).
func (s *Server) handleDNSTransportMobileconfig(w http.ResponseWriter, r *http.Request) {
	protocol := r.PathValue("protocol")
	transport, err := s.DNSTransports.Get(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load transport settings").WriteJSON(w)
		return
	}
	var cert mobileconfig.CertInput
	if s.TLSCertPath != "" {
		if status, err := (&tlscert.Reader{CertPath: s.TLSCertPath}).Status(); err == nil {
			cert = mobileconfig.CertInput{Active: status.Active, SAN: status.SAN}
		}
	}
	profile, err := mobileconfig.Build(protocol, mobileconfig.TransportInput{
		DotEnabled: transport.DotEnabled, DohEnabled: transport.DohEnabled,
		DohPort: transport.DohPort, DohPath: transport.DohPath,
	}, cert, randomUUID)
	if err != nil {
		Err(http.StatusBadRequest, "unavailable", err.Error()).WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="alderpointdns-v2-%s.mobileconfig"`, protocol))
	w.WriteHeader(http.StatusOK)
	w.Write(profile)
}

type dnscryptRotateRequest struct {
	RotateProvider bool `json:"rotate_provider"`
}

// handleDNSCryptRotate issues real DNSCrypt provider/resolver key
// material via the real dnsdist binary (internal/dnscryptprovision) --
// field-matched against Python's own POST /api/dns-transports/dnscrypt/
// rotate. rotate_provider defaults to false (issue a fresh resolver
// certificate under the EXISTING provider identity -- the routine
// action) since rotating the provider identity itself invalidates every
// previously-pinned client's stamp.
func (s *Server) handleDNSCryptRotate(w http.ResponseWriter, r *http.Request) {
	if s.TLSCertPath == "" {
		Err(http.StatusServiceUnavailable, "unavailable", "this deployment has no management TLS cert path configured -- DNSCrypt key material reuses that directory").WriteJSON(w)
		return
	}
	var req dnscryptRotateRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
			return
		}
	}
	dnsdistBinary := s.DNSCryptBinary
	if dnsdistBinary == "" {
		dnsdistBinary = "dnsdist"
	}
	before, err := s.DNSTransports.Get(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load transport settings").WriteJSON(w)
		return
	}
	rotatedProvider := req.RotateProvider || !before.DNSCryptIdentityProvisioned

	keyDir := filepath.Dir(s.TLSCertPath)
	updated, fingerprint, err := s.DNSTransports.RotateDNSCrypt(r.Context(), req.RotateProvider, dnsdistBinary, keyDir)
	if err != nil {
		Err(http.StatusInternalServerError, "provisioning_failed", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"status": "rotated", "rotated_provider": rotatedProvider,
		"fingerprint": fingerprint, "cert_serial": updated.DNSCryptCertSerial, "cert_valid_until": updated.DNSCryptCertValidUntil,
	})
}

// randomUUID generates a real RFC 4122 v4 UUID via crypto/rand (never
// math/rand) -- matches this codebase's existing CSPRNG discipline
// (internal/clientid's own doc comment states the same rule), no new
// dependency needed for a one-off UUID string.
func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failing is a fatal environment problem, not something to silently paper over
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
