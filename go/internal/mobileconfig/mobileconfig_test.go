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
	_, err := Build("doh", TransportInput{DohEnabled: false}, CertInput{Active: true, SAN: []string{"x"}}, fixedUUIDs("a"))
	if err == nil {
		t.Fatal("expected an error for a disabled transport")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("error = %v, want an 'not enabled' message matching Python's own", err)
	}
}

func TestBuildRejectsNoCertificate(t *testing.T) {
	_, err := Build("dot", TransportInput{DotEnabled: true}, CertInput{Active: false}, fixedUUIDs("a"))
	if err == nil {
		t.Fatal("expected an error when no certificate is active")
	}
}

func TestBuildRejectsUnsupportedProtocol(t *testing.T) {
	_, err := Build("doq", TransportInput{}, CertInput{Active: true, SAN: []string{"x"}}, fixedUUIDs("a"))
	if err == nil {
		t.Fatal("expected an error for doq (not in Apple's managed DNS profile format)")
	}
}

func TestBuildUsesFirstSANEntryAsHostname(t *testing.T) {
	profile, err := Build("dot", TransportInput{DotEnabled: true}, CertInput{Active: true, SAN: []string{"first.example", "second.example"}}, fixedUUIDs("a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(profile)
	if !strings.Contains(s, "first.example") {
		t.Error("expected the first SAN entry to be used as the hostname")
	}
	if strings.Contains(s, "second.example") {
		t.Error("should not reference the second SAN entry")
	}
}
