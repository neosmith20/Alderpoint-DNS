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
