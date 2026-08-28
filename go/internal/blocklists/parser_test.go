package blocklists

import (
	"strings"
	"testing"
)

func TestParseAcceptedFormats(t *testing.T) {
	input := strings.Join([]string{
		"# comment",
		"! adblock comment",
		"",
		"0.0.0.0 ads.example.com",
		"127.0.0.1 tracker.example.com",
		"||adnet.example.com^",
		"bare.example.com",
		"0.0.0.0 ADS.EXAMPLE.COM", // duplicate, case-insensitive
		"not a domain at all",     // invalid
		"",
	}, "\n")

	result := Parse(strings.NewReader(input))
	if len(result.Domains) != 4 {
		t.Fatalf("domains = %v, want 4 unique", result.Domains)
	}
	if result.Duplicate != 1 {
		t.Errorf("duplicate = %d, want 1", result.Duplicate)
	}
	if result.Invalid != 1 {
		t.Errorf("invalid = %d, want 1", result.Invalid)
	}
}

func TestParseSortedAndDeterministic(t *testing.T) {
	input := "0.0.0.0 zzz.example.com\n0.0.0.0 aaa.example.com\n"
	result := Parse(strings.NewReader(input))
	if result.Domains[0] != "aaa.example.com" {
		t.Errorf("expected sorted output, got %v", result.Domains)
	}
}

// Real-world fixture shape from WindowsSpyBlocker's spy_v6.txt /
// extra_v6.txt: "::" (the unspecified IPv6 address) followed by two
// spaces and a single hostname, plus a "###"-commented header block.
func TestParseIPv6HostsDoubleColonForm(t *testing.T) {
	input := strings.Join([]string{
		"### WindowsSpyBlocker - Hosts IPv6 spy rules",
		"### License: MIT",
		"",
		":: a.ads2.msads.net",
		":: ads.msn.com",
	}, "\n")

	result := Parse(strings.NewReader(input))
	want := []string{"a.ads2.msads.net", "ads.msn.com"}
	if len(result.Domains) != len(want) {
		t.Fatalf("domains = %v, want %v", result.Domains, want)
	}
	for i, d := range want {
		if result.Domains[i] != d {
			t.Errorf("domains[%d] = %q, want %q", i, result.Domains[i], d)
		}
	}
	if result.Invalid != 0 {
		t.Errorf("invalid = %d, want 0", result.Invalid)
	}
}

func TestParseIPv6OtherAddressForms(t *testing.T) {
	input := strings.Join([]string{
		"::1 localhost.example.com",      // loopback
		"fe80::1 link-local.example.com", // link-local, non-compressed head
		"2001:db8::1 full.example.com",   // documentation prefix
		"::ffff:0:0 mapped.example.com",  // IPv4-mapped form
	}, "\n")

	result := Parse(strings.NewReader(input))
	want := map[string]bool{
		"localhost.example.com":  true,
		"link-local.example.com": true,
		"full.example.com":       true,
		"mapped.example.com":     true,
	}
	if len(result.Domains) != len(want) {
		t.Fatalf("domains = %v, want %d entries matching %v", result.Domains, len(want), want)
	}
	for _, d := range result.Domains {
		if !want[d] {
			t.Errorf("unexpected domain %q", d)
		}
	}
	if result.Invalid != 0 {
		t.Errorf("invalid = %d, want 0", result.Invalid)
	}
}

func TestParseHostsMultipleAliasesPerLine(t *testing.T) {
	input := "0.0.0.0 primary.example.com alias.example.com\n"
	result := Parse(strings.NewReader(input))
	want := []string{"alias.example.com", "primary.example.com"}
	if len(result.Domains) != 2 {
		t.Fatalf("domains = %v, want %v", result.Domains, want)
	}
}

func TestParseInlineHostsComment(t *testing.T) {
	input := "0.0.0.0 ads.example.com # ad network\n"
	result := Parse(strings.NewReader(input))
	if len(result.Domains) != 1 || result.Domains[0] != "ads.example.com" {
		t.Fatalf("domains = %v, want [ads.example.com]", result.Domains)
	}
}

func TestParseIPLiteralsAreNotDomains(t *testing.T) {
	input := strings.Join([]string{
		"0.0.0.0",         // address with nothing after it
		"0.0.0.0 0.0.0.0", // "domain" field is itself an IP literal
		"::",              // bare address, nothing after it
		"192.0.2.1",       // bare IPv4 literal as its own line
	}, "\n")

	result := Parse(strings.NewReader(input))
	if len(result.Domains) != 0 {
		t.Fatalf("domains = %v, want none", result.Domains)
	}
	if result.Invalid != 4 {
		t.Errorf("invalid = %d, want 4, got domains=%v", result.Invalid, result.Domains)
	}
}

func TestParseMalformedAndWhitespaceLines(t *testing.T) {
	input := strings.Join([]string{
		"   ", // whitespace-only
		"\t",  // tab-only
		"   # indented comment",
		"just some words", // no recognizable domain shape
		"..",              // empty labels
		"-bad-.example.com",
	}, "\n")

	result := Parse(strings.NewReader(input))
	if len(result.Domains) != 0 {
		t.Fatalf("domains = %v, want none", result.Domains)
	}
	if result.Invalid != 3 {
		t.Errorf("invalid = %d, want 3 (the 3 non-blank, non-comment malformed lines), got domains=%v", result.Invalid, result.Domains)
	}
}

func TestParseAdblockWithModifiers(t *testing.T) {
	input := "||adnet.example.com^$important\n||adnet.example.com^\n"
	result := Parse(strings.NewReader(input))
	if len(result.Domains) != 1 || result.Domains[0] != "adnet.example.com" {
		t.Fatalf("domains = %v, want [adnet.example.com]", result.Domains)
	}
	if result.Duplicate != 1 {
		t.Errorf("duplicate = %d, want 1", result.Duplicate)
	}
}
