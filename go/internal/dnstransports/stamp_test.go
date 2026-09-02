package dnstransports

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildDNSCryptStampShapeAndDecodability(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	stamp := BuildDNSCryptStamp("192.0.2.10:5443", pubKey, "2.dnscrypt-cert.example")

	if !strings.HasPrefix(stamp, "sdns://") {
		t.Fatalf("expected sdns:// prefix, got %q", stamp)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stamp, "sdns://"))
	if err != nil {
		t.Fatalf("stamp body isn't valid base64url: %v", err)
	}
	if raw[0] != 0x01 {
		t.Fatalf("expected protocol byte 0x01 (DNSCrypt), got 0x%02x", raw[0])
	}
	for i := 1; i < 9; i++ {
		if raw[i] != 0 {
			t.Fatalf("expected an all-zero properties bitfield, got byte %d = 0x%02x", i, raw[i])
		}
	}
	pos := 9
	addrLen := int(raw[pos])
	pos++
	if got := string(raw[pos : pos+addrLen]); got != "192.0.2.10:5443" {
		t.Fatalf("addr field = %q, want 192.0.2.10:5443", got)
	}
	pos += addrLen
	pkLen := int(raw[pos])
	pos++
	if pkLen != 32 {
		t.Fatalf("pk field length = %d, want 32", pkLen)
	}
	for i := 0; i < 32; i++ {
		if raw[pos+i] != byte(i) {
			t.Fatalf("pk field byte %d = 0x%02x, want 0x%02x", i, raw[pos+i], byte(i))
		}
	}
	pos += pkLen
	nameLen := int(raw[pos])
	pos++
	if got := string(raw[pos : pos+nameLen]); got != "2.dnscrypt-cert.example" {
		t.Fatalf("provider name field = %q, want 2.dnscrypt-cert.example", got)
	}
	pos += nameLen
	if pos != len(raw) {
		t.Fatalf("trailing garbage after provider name: %d bytes left", len(raw)-pos)
	}
}

func TestBuildDNSCryptStampNeverEmbedsLoopbackAsAddrSilently(t *testing.T) {
	// This function itself has no opinion about loopback -- it encodes
	// exactly what it's given. The "never localhost" guarantee belongs to
	// the caller (internal/httpapi's clientFacingAddress, which only ever
	// passes a real hostname or a detected LAN IP). This test documents
	// that division of responsibility so a future caller doesn't assume
	// the stamp builder itself guards against it.
	stamp := BuildDNSCryptStamp("localhost:5443", []byte("x"), "p")
	if !strings.Contains(stamp, "sdns://") {
		t.Fatal("expected a well-formed stamp regardless of the addr's content")
	}
}
