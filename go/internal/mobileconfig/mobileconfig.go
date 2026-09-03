// Package mobileconfig generates real Apple `com.apple.dnsSettings.managed`
// configuration profiles (the same format V1.1.1 generated, and the same
// shape app/v2/mobileconfig.py builds via plistlib -- field-matched
// against that file, read directly, not guessed). Inputs come entirely
// from this Go control plane's own native state: internal/dnstransports'
// Settings (is this transport actually enabled) and internal/tlscert's
// Status (the real active certificate's own SAN, which is also the only
// hostname a client can actually validate the connection against --
// never a hostname the profile author merely typed in, and never any
// key material).
package mobileconfig

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// SupportedProtocols matches Python's own SUPPORTED_PROTOCOLS -- Apple's
// managed DNS profile format has no DoQ/DoH3 protocol value.
var SupportedProtocols = map[string]bool{"doh": true, "dot": true}

type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func errf(format string, args ...any) error { return &Error{fmt.Sprintf(format, args...)} }

func isLoopbackHostname(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// TransportInput is the subset of dnstransports.Settings this package
// needs -- kept narrow and decoupled rather than importing that package
// directly, matching this codebase's existing preference for small,
// independently testable packages.
type TransportInput struct {
	DotEnabled bool
	DohEnabled bool
	DohPort    int
	DohPath    string
}

// CertInput is the subset of tlscert.Status this package needs.
type CertInput struct {
	Active bool
	SAN    []string
}

// UUIDFunc lets callers inject a real UUID generator (crypto/rand-backed,
// see internal/httpapi's wiring) without this package taking a direct
// dependency on any specific UUID library -- tests supply a
// deterministic one.
type UUIDFunc func() string

// Build generates the real .mobileconfig XML bytes, or a real, actionable
// error matching Python's own MobileconfigError messages exactly (field
// for field) when the requested transport isn't actually enabled or no
// certificate is configured yet -- never a fabricated profile.
//
// clientFacingAddress is the owner's own selected/saved/detected
// client-facing hostname or IP (internal/httpapi's clientFacingAddress) --
// NOT necessarily cert.SAN[0]. This is the backend half of "Apple profile
// generation must be blocked when the selected client-facing name does
// not match the cert": Build refuses to emit a profile at all unless
// clientFacingAddress is both non-loopback AND actually present in the
// certificate's own SAN list, since Apple's profile installer performs a
// real TLS handshake against exactly that ServerName/ServerURL from
// another device -- a mismatch here is not a cosmetic warning, it is a
// profile guaranteed to fail with a certificate error the moment a client
// installs it.
func Build(protocol string, transport TransportInput, cert CertInput, clientFacingAddress string, newUUID UUIDFunc) ([]byte, error) {
	if !SupportedProtocols[protocol] {
		return nil, errf("unsupported protocol: %q (supported: doh, dot)", protocol)
	}
	if protocol == "doh" && !transport.DohEnabled {
		return nil, errf("DNS-over-HTTPS is not enabled on this appliance -- enable it before generating a profile for it")
	}
	if protocol == "dot" && !transport.DotEnabled {
		return nil, errf("DNS-over-TLS is not enabled on this appliance -- enable it before generating a profile for it")
	}
	if !cert.Active || len(cert.SAN) == 0 {
		return nil, errf("no active HTTPS certificate with a subject alternative name is configured yet")
	}
	if clientFacingAddress == "" {
		return nil, errf("no client-facing address has been chosen for this appliance yet -- set one in Encryption > DNS Transports before generating a profile")
	}
	// Real, deliberate block (not just a UI hint the caller could route
	// around): "localhost"/loopback only ever validates for a client
	// running ON this appliance itself. Apple's profile installer does a
	// normal TLS handshake against ServerName/ServerURL from another
	// device, so shipping a loopback hostname here would silently hand
	// out a profile guaranteed to fail with a certificate error.
	if isLoopbackHostname(clientFacingAddress) {
		return nil, errf("this appliance's client-facing address (%q) only ever validates for a client running on this appliance itself -- it cannot be used in a configuration profile for another device; configure a real client-facing hostname or LAN IP first", clientFacingAddress)
	}
	matches := false
	for _, s := range cert.SAN {
		if s == clientFacingAddress {
			matches = true
			break
		}
	}
	if !matches {
		return nil, errf("the selected client-facing address (%q) is not in this certificate's subject alternative names (%s) -- Apple's profile installer would fail the TLS handshake; replace the certificate with one covering %q, or choose a different client-facing address that the current certificate already covers", clientFacingAddress, strings.Join(cert.SAN, ", "), clientFacingAddress)
	}
	hostname := clientFacingAddress
	payloadUUID := strings.ToUpper(newUUID())
	profileUUID := strings.ToUpper(newUUID())

	var dnsProtocol, serverURL, label string
	if protocol == "doh" {
		dnsProtocol = "HTTPS"
		serverURL = fmt.Sprintf("https://%s:%d%s", hostname, transport.DohPort, transport.DohPath)
		label = "DNS-over-HTTPS"
	} else {
		dnsProtocol = "TLS"
		label = "DNS-over-TLS"
	}

	payload := plistDict{
		{"PayloadType", plistString("com.apple.dnsSettings.managed")},
		{"PayloadIdentifier", plistString("appliance.alderpointdns-v2.dns." + protocol)},
		{"PayloadUUID", plistString(payloadUUID)},
		{"PayloadVersion", plistInt(1)},
		{"PayloadDisplayName", plistString("Alderpoint DNS V2 " + label)},
	}
	dnsSettings := plistDict{{"DNSProtocol", plistString(dnsProtocol)}}
	if protocol == "doh" {
		dnsSettings = append(dnsSettings, plistEntry{"ServerURL", plistString(serverURL)})
	}
	dnsSettings = append(dnsSettings, plistEntry{"ServerName", plistString(hostname)})
	// Python builds one flat dict (payload fields merged with dns_settings
	// fields via **dns_settings); mirror that exact flat shape here too.
	payload = append(payload, dnsSettings...)

	profile := plistDict{
		{"PayloadContent", plistArray{payload}},
		{"PayloadDisplayName", plistString(fmt.Sprintf("Alderpoint DNS V2 %s (%s)", label, hostname))},
		{"PayloadIdentifier", plistString("appliance.alderpointdns-v2.profile." + protocol)},
		{"PayloadRemovalDisallowed", plistBool(false)},
		{"PayloadType", plistString("Configuration")},
		{"PayloadUUID", plistString(profileUUID)},
		{"PayloadVersion", plistInt(1)},
	}

	return renderPlist(profile), nil
}

// --- a minimal, purpose-built Apple XML plist writer --------------------
//
// Not a general-purpose plist library -- just enough to emit the exact
// element shapes (dict/array/string/integer/boolean) this one profile
// needs, in a valid Apple-plist-DTD document. Deterministic key order
// (unlike a generic map) so output is stable and diffable.

type plistValue interface{ writePlist(b *strings.Builder) }

type plistEntry struct {
	Key   string
	Value plistValue
}
type plistDict []plistEntry
type plistArray []plistValue
type plistString string
type plistInt int
type plistBool bool

func (d plistDict) writePlist(b *strings.Builder) {
	b.WriteString("<dict>\n")
	for _, e := range d {
		fmt.Fprintf(b, "<key>%s</key>\n", xmlEscape(e.Key))
		e.Value.writePlist(b)
	}
	b.WriteString("</dict>\n")
}

func (a plistArray) writePlist(b *strings.Builder) {
	b.WriteString("<array>\n")
	for _, v := range a {
		v.writePlist(b)
	}
	b.WriteString("</array>\n")
}

func (s plistString) writePlist(b *strings.Builder) {
	fmt.Fprintf(b, "<string>%s</string>\n", xmlEscape(string(s)))
}

func (i plistInt) writePlist(b *strings.Builder) {
	fmt.Fprintf(b, "<integer>%d</integer>\n", int(i))
}

func (bv plistBool) writePlist(b *strings.Builder) {
	if bv {
		b.WriteString("<true/>\n")
	} else {
		b.WriteString("<false/>\n")
	}
}

func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func renderPlist(root plistDict) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	root.writePlist(&b)
	b.WriteString("</plist>\n")
	return []byte(b.String())
}
