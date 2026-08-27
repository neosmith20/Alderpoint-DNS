package clientid

import (
	"strings"
	"testing"
)

func TestGenerateHexProducesExactlyValidValues(t *testing.T) {
	cases := []struct {
		bits    int
		wantLen int
	}{{Bits192, 48}, {Bits256, 64}}
	for _, c := range cases {
		v, err := GenerateHex(c.bits)
		if err != nil {
			t.Fatalf("GenerateHex(%d): %v", c.bits, err)
		}
		if len(v) != c.wantLen {
			t.Fatalf("GenerateHex(%d): expected length %d, got %d (%q)", c.bits, c.wantLen, len(v), v)
		}
		if err := ValidateHex(v); err != nil {
			t.Fatalf("GenerateHex(%d) produced a value that fails its own ValidateHex: %v", c.bits, err)
		}
		for _, r := range v {
			if !strings.ContainsRune("0123456789abcdef", r) {
				t.Fatalf("GenerateHex(%d): non-hex/uppercase character %q in %q", c.bits, r, v)
			}
		}
	}
}

func TestGenerateHexIsActuallyRandomNotConstant(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		v, err := GenerateHex(Bits256)
		if err != nil {
			t.Fatal(err)
		}
		if seen[v] {
			t.Fatalf("GenerateHex produced a duplicate within 20 calls: %q -- CSPRNG not actually being used", v)
		}
		seen[v] = true
	}
}

func TestGenerateHexRejectsUnsupportedBitStrength(t *testing.T) {
	if _, err := GenerateHex(128); err == nil {
		t.Fatal("expected an error for an unsupported bit strength")
	}
}

func TestValidateHexAcceptsExactly48And64LowercaseHex(t *testing.T) {
	v48, _ := GenerateHex(Bits192)
	v64, _ := GenerateHex(Bits256)
	for _, v := range []string{v48, v64} {
		if err := ValidateHex(v); err != nil {
			t.Fatalf("ValidateHex(%q): %v", v, err)
		}
	}
}

// TestValidateHexRejectsShorterMalformedOrSilentlyNormalizedValues is
// the owner-required proof: shorter, malformed, and would-be-normalized
// values must all be rejected outright, never silently accepted after
// an implicit fix.
func TestValidateHexRejectsShorterMalformedOrSilentlyNormalizedValues(t *testing.T) {
	v64, _ := GenerateHex(Bits256)
	cases := map[string]string{
		"too short (47 chars)":          v64[:47],
		"one char too long (49)":        v64[:48] + "a",
		"one char too long for 64 (65)": v64 + "a",
		"uppercase hex":                 strings.ToUpper(v64),
		"mixed case":                    v64[:32] + strings.ToUpper(v64[32:]),
		"leading whitespace":            " " + v64,
		"trailing whitespace":           v64 + " ",
		"non-hex character":             v64[:63] + "g",
		"empty string":                  "",
		"totally different length (16)": v64[:16],
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateHex(v); err == nil {
				t.Fatalf("expected %s (%q) to be rejected, got nil error", name, v)
			}
		})
	}
}

func TestValidateHexTruncatedTo48IsActuallyValidNotAcceptedAsARepairOf64(t *testing.T) {
	v64, _ := GenerateHex(Bits256)
	truncated := v64[:48]
	// This must pass ValidateHex (it's a real, well-formed 48-char
	// value) -- the point being made in the test above: this package
	// has no way to know this WAS a truncation, and must not invent
	// one. The actual "never silently truncate" guarantee lives at the
	// call site (internal/clients.AddIdentifier passes the caller's
	// string through unmodified -- see that package's own tests).
	if err := ValidateHex(truncated); err != nil {
		t.Fatalf("a genuine, well-formed 48-char value must validate: %v", err)
	}
}

func TestDoHPathCarriesTheFullCanonicalHexVerbatim(t *testing.T) {
	v64, _ := GenerateHex(Bits256)
	path := DoHPath(v64)
	if path != "/dns-query/cid/"+v64 {
		t.Fatalf("expected the full hex verbatim in the path, got %q", path)
	}
	if !strings.Contains(path, v64) {
		t.Fatal("DoH path must contain the complete, untruncated identity")
	}
}

func TestEncodeSNILabelRoundTripsLosslesslyForBothLengths(t *testing.T) {
	v48, _ := GenerateHex(Bits192)
	v64, _ := GenerateHex(Bits256)
	for _, v := range []string{v48, v64} {
		sni := EncodeSNILabel(v)
		for _, label := range strings.Split(sni, ".") {
			if len(label) > 63 {
				t.Fatalf("EncodeSNILabel(%q) produced a label over the 63-byte DNS limit: %q (%d bytes)", v, label, len(label))
			}
		}
		if len(sni) > 253 {
			t.Fatalf("EncodeSNILabel(%q) produced a hostname over the 253-byte total DNS name limit: %d bytes", v, len(sni))
		}
		decoded, ok := DecodeSNILabel(sni)
		if !ok {
			t.Fatalf("DecodeSNILabel(%q) failed to decode its own EncodeSNILabel output", sni)
		}
		if decoded != v {
			t.Fatalf("round-trip mismatch: encoded %q, decoded back to %q -- entropy was not preserved losslessly", v, decoded)
		}
	}
}

func TestEncodeSNILabelNeverTruncatesA256BitIdentity(t *testing.T) {
	v64, _ := GenerateHex(Bits256)
	sni := EncodeSNILabel(v64)
	decoded, ok := DecodeSNILabel(sni)
	if !ok || decoded != v64 {
		t.Fatalf("a 256-bit identity must survive SNI encoding completely -- got decoded=%q ok=%v, want %q", decoded, ok, v64)
	}
	// Direct proof of the "one byte over a single label" reasoning in
	// the package doc comment: the raw hex alone would be 64 bytes,
	// over the 63-byte single-label limit, so it MUST have been split.
	firstLabel := strings.SplitN(sni, ".", 2)[0]
	if len(firstLabel) >= 64 {
		t.Fatalf("expected the 64-hex value to be split across multiple labels, got one label of length %d", len(firstLabel))
	}
}

func TestDecodeSNILabelRejectsAnythingNotAGenuineEncodedClientID(t *testing.T) {
	cases := []string{
		"not-a-clientid.example.com",
		"aabbcc.cid.apdns-clientid.internal",           // too short to be real hex-decoded ClientID (6 hex chars)
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.cid.apdns-clientid.internal", // right length, not hex
		"",
		"cid.apdns-clientid.internal", // suffix alone, no identity labels
	}
	for _, sni := range cases {
		if _, ok := DecodeSNILabel(sni); ok {
			t.Fatalf("expected DecodeSNILabel(%q) to fail, got a false success", sni)
		}
	}
}

func TestEncodeSNILabelDifferentInputsNeverCollide(t *testing.T) {
	v1, _ := GenerateHex(Bits256)
	v2, _ := GenerateHex(Bits256)
	if EncodeSNILabel(v1) == EncodeSNILabel(v2) {
		t.Fatal("two different ClientIDs encoded to the same SNI hostname -- collision")
	}
}
