package mobileconfig

import (
	"encoding/xml"
	"strings"
	"testing"
)

func fixedUUIDs(vals ...string) UUIDFunc {
	i := 0
	return func() string {
		v := vals[i%len(vals)]
		i++
		return v
	}
}

func TestBuildDoHProducesValidXMLWithExpectedFields(t *testing.T) {
	profile, err := Build("doh",
		TransportInput{DohEnabled: true, DohPort: 9443, DohPath: "/dns-query"},
		CertInput{Active: true, SAN: []string{"apdns.example.internal", "10.0.0.1"}},
		"apdns.example.internal",
		fixedUUIDs("aaaa", "bbbb"),
	)
	if err != nil {
		t.Fatal(err)
	}
	// Must be well-formed XML -- a real Apple .mobileconfig is parsed by
	// iOS/macOS's own profile installer, so this is the actual usability
	// bar, not just "some bytes came back". A streaming token walk
	// proves well-formedness without needing a DOCTYPE-aware unmarshaler.
	dec := xml.NewDecoder(strings.NewReader(string(profile)))
	for {
		if _, err := dec.Token(); err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("profile is not well-formed XML: %v", err)
		}
	}
	s := string(profile)
	for _, want := range []string{
		"<key>DNSProtocol</key>", "<string>HTTPS</string>",
		"<key>ServerURL</key>", "<string>https://apdns.example.internal:9443/dns-query</string>",
		"<key>ServerName</key>", "<string>apdns.example.internal</string>",
		"<key>PayloadType</key>", "<string>com.apple.dnsSettings.managed</string>",
		"<key>PayloadUUID</key>", "<string>AAAA</string>", // uppercased
		"com.apple.dnsSettings.managed",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("profile missing expected content %q\n---\n%s", want, s)
		}
	}
}

func TestBuildDoTHasNoServerURL(t *testing.T) {
	profile, err := Build("dot",
		TransportInput{DotEnabled: true},
		CertInput{Active: true, SAN: []string{"apdns.example.internal"}},
		"apdns.example.internal",
		fixedUUIDs("cccc", "dddd"),
	)
	if err != nil {
		t.Fatal(err)
	}
	s := string(profile)
	if strings.Contains(s, "ServerURL") {
		t.Error("DoT profile should not include ServerURL (that's DoH-only)")
	}
	if !strings.Contains(s, "<string>TLS</string>") {
		t.Error("expected DNSProtocol=TLS")
	}
}

func TestBuildRejectsDisabledTransport(t *testing.T) {
	_, err := Build("doh", TransportInput{DohEnabled: false}, CertInput{Active: true, SAN: []string{"x"}}, "x", fixedUUIDs("a"))
	if err == nil {
		t.Fatal("expected an error for a disabled transport")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("error = %v, want an 'not enabled' message matching Python's own", err)
	}
}

func TestBuildRejectsNoCertificate(t *testing.T) {
	_, err := Build("dot", TransportInput{DotEnabled: true}, CertInput{Active: false}, "x", fixedUUIDs("a"))
	if err == nil {
		t.Fatal("expected an error when no certificate is active")
	}
}

func TestBuildRejectsUnsupportedProtocol(t *testing.T) {
	_, err := Build("doq", TransportInput{}, CertInput{Active: true, SAN: []string{"x"}}, "x", fixedUUIDs("a"))
	if err == nil {
		t.Fatal("expected an error for doq (not in Apple's managed DNS profile format)")
	}
}

// TestBuildUsesGivenClientFacingAddressAsHostname documents the current
// contract (2026-09-03 rewrite): the profile's hostname is the CALLER-
// supplied clientFacingAddress -- the owner's real client-facing
// selection -- not simply cert.SAN[0]. See
// TestBuildRejectsClientFacingAddressNotInCertSAN below for the paired
// guarantee that this can never be a value the cert won't validate.
func TestBuildUsesGivenClientFacingAddressAsHostname(t *testing.T) {
	profile, err := Build("dot", TransportInput{DotEnabled: true}, CertInput{Active: true, SAN: []string{"first.example", "second.example"}}, "second.example", fixedUUIDs("a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(profile)
	if !strings.Contains(s, "second.example") {
		t.Error("expected the given clientFacingAddress to be used as the hostname")
	}
	if strings.Contains(s, "first.example") {
		t.Error("should not reference a SAN entry that wasn't the selected client-facing address")
	}
}

// TestBuildRejectsClientFacingAddressNotInCertSAN is the backend half of
// "Apple .mobileconfig generation must be blocked when the selected
// client-facing name does not match the cert": a profile pinned to a
// ServerName the certificate doesn't actually cover is guaranteed to
// fail the TLS handshake the moment a real device installs it, so Build
// refuses to emit one at all rather than emit a profile known to be
// broken.
func TestBuildRejectsClientFacingAddressNotInCertSAN(t *testing.T) {
	_, err := Build("dot", TransportInput{DotEnabled: true}, CertInput{Active: true, SAN: []string{"apdns.example.internal"}}, "172.16.43.100", fixedUUIDs("a"))
	if err == nil {
		t.Fatal("expected an error when the client-facing address isn't in the cert's SAN list")
	}
	if !strings.Contains(err.Error(), "not in this certificate's subject alternative names") {
		t.Errorf("error = %v, want a SAN-mismatch message", err)
	}
}

func TestBuildRejectsEmptyClientFacingAddress(t *testing.T) {
	_, err := Build("dot", TransportInput{DotEnabled: true}, CertInput{Active: true, SAN: []string{"apdns.example.internal"}}, "", fixedUUIDs("a"))
	if err == nil {
		t.Fatal("expected an error when no client-facing address has been chosen yet")
	}
}

func TestBuildRejectsLoopbackClientFacingAddress(t *testing.T) {
	_, err := Build("dot", TransportInput{DotEnabled: true}, CertInput{Active: true, SAN: []string{"localhost"}}, "localhost", fixedUUIDs("a"))
	if err == nil {
		t.Fatal("expected an error when the client-facing address is localhost, even if the cert (also loopback) technically contains it")
	}
	if !strings.Contains(err.Error(), "only ever validates for a client running on this appliance itself") {
		t.Errorf("error = %v, want the loopback-specific message", err)
	}
}
