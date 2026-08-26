package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"alderpointdns/go-controlplane/internal/dnstransports"
)

func transportsJSON(s dnstransports.Settings) map[string]any {
	return map[string]any{
		"dot_enabled": s.DotEnabled, "dot_port": s.DotPort,
		"doh_enabled": s.DohEnabled, "doh_port": s.DohPort, "doh_path": s.DohPath,
		"doq_enabled": s.DoqEnabled, "doq_port": s.DoqPort,
		"doh3_enabled": s.Doh3Enabled, "doh3_port": s.Doh3Port,
		"dnscrypt_enabled": s.DNSCryptEnabled, "dnscrypt_port": s.DNSCryptPort,
		"dnscrypt_provider_name": s.DNSCryptProviderName, "dnscrypt_identity_provisioned": s.DNSCryptIdentityProvisioned,
	}
}

func (s *Server) handleGetDNSTransports(w http.ResponseWriter, r *http.Request) {
	settings, err := s.DNSTransports.Get(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load transport settings").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, transportsJSON(settings))
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
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	out := transportsJSON(updated)
	out["dns_runtime"] = s.applyDNSRuntimeBestEffort(r)
	WriteJSON(w, http.StatusOK, out)
}

// handleTLSStatus is nil-reader-safe like every other optional
// compatibility boundary (Analytics, RawQueryLog): {"active": false}
// when -tls-cert-path wasn't configured, matching Python's own shape for
// "no certificate provisioned" rather than a 500.
func (s *Server) handleTLSStatus(w http.ResponseWriter, r *http.Request) {
	if s.TLSCert == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	status, err := s.TLSCert.Status()
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"active": false, "error": err.Error()})
		return
	}
	WriteJSON(w, http.StatusOK, status)
}
