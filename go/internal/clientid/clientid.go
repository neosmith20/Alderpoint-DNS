// Package clientid is the pure, dependency-free core of Strong ClientID:
// OS-backed CSPRNG generation, exact (never normalizing/truncating)
// format validation, and the two real dnsdist-facing identity
// encodings this feature needs -- a DoH URL path (full canonical hex,
// no encoding needed) and a DNS-label-safe SNI hostname for DoT/DoQ
// (hex is already label-safe alphabet-wise, but a 256-bit/64-hex value
// is one byte over a single DNS label's 63-byte limit, so it must be
// split across labels losslessly). No I/O, no database -- mirrors
// internal/dnscompile's own "pure function, its own tests prove byte-
// exact behavior directly" convention.
//
// Accepted ClientID values are exactly 48 lowercase hex characters
// (192-bit) or exactly 64 lowercase hex characters (256-bit) -- nothing
// shorter, nothing malformed, and nothing else is silently lowercased/
// trimmed/truncated into shape. A value that doesn't match one of those
// two exact shapes is rejected outright (ValidateHex returns an error);
// this package never "fixes" an almost-valid value, because doing so
// would silently downgrade whatever entropy the operator (or another
// tool) actually generated.
package clientid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// sniSuffixDomain is a fixed, compile-time-constant label appended to
// every encoded SNI hostname -- never a real, resolvable domain (this
// identity is only ever inspected via dnsdist's SNIRule against the TLS
// ClientHello's SNI extension value as a literal string match; it is
// never looked up in DNS). "internal" is IANA's own reserved-for-
// private-use TLD (RFC 8375 lineage), so this can never collide with a
// real registered name.
const sniSuffixDomain = "cid.apdns-clientid.internal"

// sniLabelChunkSize is the hex-character width of each DNS label the
// encoded SNI hostname is split into -- well under the 63-byte-per-
// label limit for both supported ClientID lengths (48 and 64 hex
// chars), and evenly divides 64 (two labels for a 256-bit ID) while
// still being small enough that a 192-bit ID's 48 hex chars split into
// a clean 32+16 rather than needing a third, near-empty label.
const sniLabelChunkSize = 32

var (
	// ErrInvalidLength is returned when the value's length is neither
	// 48 nor 64 hex characters.
	ErrInvalidLength = fmt.Errorf("clientid: value must be exactly 48 (192-bit) or 64 (256-bit) lowercase hex characters")
	// ErrInvalidFormat is returned when the length is right but the
	// content isn't exactly lowercase hex (uppercase, non-hex
	// characters, or any surrounding whitespace).
	ErrInvalidFormat = fmt.Errorf("clientid: value must contain only lowercase hex characters (0-9, a-f), no whitespace")
)

// Bits192 and Bits256 are the only two accepted ClientID sizes.
const (
	Bits192 = 192
	Bits256 = 256
)

// ValidateHex enforces the exact accepted shape -- see the package doc
// comment. Deliberately does NOT trim, lowercase, or otherwise
// normalize its input first: a caller that passes "  aabb...  " or
// "AABB..." gets a real rejection, not a silent fix, because either
// would mean this validator accepted something other than what the
// caller actually has (and, more subtly, could mask a caller that
// meant to send a full 64-hex value but truncated it and got lucky
// with 48 by accident -- treating the two lengths as interchangeable
// would defeat the point of choosing one deliberately).
func ValidateHex(v string) error {
	switch len(v) {
	case 48, 64:
	default:
		return ErrInvalidLength
	}
	for _, r := range v {
		if r < '0' || r > 'f' || (r > '9' && r < 'a') {
			return ErrInvalidFormat
		}
	}
	return nil
}

// GenerateHex generates a new ClientID using the OS-backed CSPRNG
// (crypto/rand, never math/rand) at the given bit strength (Bits192 or
// Bits256), returned as exact lowercase hex -- always passes
// ValidateHex on its own output.
func GenerateHex(bits int) (string, error) {
	var n int
	switch bits {
	case Bits192:
		n = 24 // 192 bits = 24 bytes = 48 hex chars
	case Bits256:
		n = 32 // 256 bits = 32 bytes = 64 hex chars
	default:
		return "", fmt.Errorf("clientid: unsupported bit strength %d (must be %d or %d)", bits, Bits192, Bits256)
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("clientid: reading from OS CSPRNG: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// DoHPath returns the full-entropy DoH URL path this exact ClientID is
// bound to -- the canonical hex value verbatim, no encoding needed
// (hex is already URL-path-safe), so DoH always carries the complete
// identity, 192-bit or 256-bit alike, never truncated or downgraded.
func DoHPath(hex string) string {
	return "/dns-query/cid/" + hex
}

// EncodeSNILabel losslessly encodes a validated hex ClientID into a
// DNS-label-safe SNI hostname for DoT/DoQ: the hex string is split into
// sniLabelChunkSize-character labels (each well under the 63-byte
// label limit), joined by ".", with sniSuffixDomain appended. Every hex
// character survives -- DecodeSNILabel is the exact inverse.
func EncodeSNILabel(hexValue string) string {
	var labels []string
	for i := 0; i < len(hexValue); i += sniLabelChunkSize {
		end := i + sniLabelChunkSize
		if end > len(hexValue) {
			end = len(hexValue)
		}
		labels = append(labels, hexValue[i:end])
	}
	labels = append(labels, sniSuffixDomain)
	return strings.Join(labels, ".")
}

// DecodeSNILabel is EncodeSNILabel's exact inverse: strips the fixed
// suffix, rejoins the remaining labels, and validates the result is a
// real ClientID shape. Returns ("", false) for anything that isn't a
// genuine encoded ClientID SNI (wrong suffix, malformed hex after
// rejoining) -- never a partial/best-effort decode.
func DecodeSNILabel(sni string) (string, bool) {
	suffix := "." + sniSuffixDomain
	if !strings.HasSuffix(sni, suffix) {
		return "", false
	}
	prefix := strings.TrimSuffix(sni, suffix)
	hexValue := strings.ReplaceAll(prefix, ".", "")
	if ValidateHex(hexValue) != nil {
		return "", false
	}
	return hexValue, true
}
