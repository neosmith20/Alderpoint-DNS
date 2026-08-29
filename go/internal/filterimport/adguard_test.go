package filterimport

import "testing"

const realAdGuardYAML = `
filters:
  - name: "AdGuard DNS filter"
    url: "https://example.invalid/adguard.txt"
    enabled: true
  - name: "Malware domains"
    url: "https://example.invalid/malware.txt"
    enabled: true
whitelist_filters:
  - name: "My allowlist"
    url: "https://example.invalid/allow.txt"
user_rules:
  - "! a comment"
  - "||ads.example.com^"
  - "@@||good.example.com^"
  - "/^track\\./"
filtering:
  rewrites_enabled: true
  rewrites:
    - domain: "printer.lan"
      answer: "10.0.0.50"
    - domain: "alias.lan"
      answer: "target.lan"
    - domain: "*.wild.lan"
      answer: "10.0.0.99"
    - domain: "excluded.lan"
      answer: "A"
`

func TestParseAdGuardYAMLFilters(t *testing.T) {
	p, err := ParseAdGuardYAML(realAdGuardYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Blocklists) != 2 {
		t.Fatalf("expected 2 blocklist candidates, got %+v", p.Blocklists)
	}
	if p.Blocklists[1].Category != "malware" {
		t.Fatalf("expected the malware-named filter to map to category=malware, got %+v", p.Blocklists[1])
	}
}

func TestParseAdGuardYAMLWhitelistFilterIsUnsupported(t *testing.T) {
	p, err := ParseAdGuardYAML(realAdGuardYAML)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range p.Unsupported {
		if contains(u, "My allowlist") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the whitelist filter to be an explicit unsupported finding, got %+v", p.Unsupported)
	}
}

func TestParseAdGuardYAMLUserRules(t *testing.T) {
	p, err := ParseAdGuardYAML(realAdGuardYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 3 {
		t.Fatalf("expected 3 real rules (comment skipped), got %+v", p.Rules)
	}
	if p.Rules[0].RuleType != "block" || p.Rules[0].Pattern != "ads.example.com" {
		t.Fatalf("expected ||domain^ to become a block rule, got %+v", p.Rules[0])
	}
	if p.Rules[1].RuleType != "allow" || p.Rules[1].Pattern != "good.example.com" {
		t.Fatalf("expected @@||domain^ to become an allow rule, got %+v", p.Rules[1])
	}
	if p.Rules[2].RuleType != "regex_block" || p.Rules[2].Pattern != `^track\.` {
		t.Fatalf("expected /regex/ to become a regex_block rule, got %+v", p.Rules[2])
	}
}

func TestParseAdGuardYAMLRewritesToLocalDNS(t *testing.T) {
	p, err := ParseAdGuardYAML(realAdGuardYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.LocalDNS) != 2 {
		t.Fatalf("expected 2 real local DNS rows (A + CNAME), got %+v", p.LocalDNS)
	}
	if p.LocalDNS[0].Name != "printer.lan" || p.LocalDNS[0].RecordType != "A" || p.LocalDNS[0].Value != "10.0.0.50" {
		t.Fatalf("expected the IP rewrite to become an A record, got %+v", p.LocalDNS[0])
	}
	if p.LocalDNS[1].Name != "alias.lan" || p.LocalDNS[1].RecordType != "CNAME" || p.LocalDNS[1].Value != "target.lan" {
		t.Fatalf("expected the domain rewrite to become a CNAME record, got %+v", p.LocalDNS[1])
	}
}

func TestParseAdGuardYAMLWildcardIPRewriteBecomesARewriteRule(t *testing.T) {
	p, err := ParseAdGuardYAML(realAdGuardYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.RewriteRules) != 1 {
		t.Fatalf("expected 1 rewrite rule, got %+v", p.RewriteRules)
	}
	if p.RewriteRules[0].Pattern != "wild.lan" || p.RewriteRules[0].RewriteTarget != "10.0.0.99" {
		t.Fatalf("expected the wildcard IP rewrite to target wild.lan -> 10.0.0.99, got %+v", p.RewriteRules[0])
	}
}

func TestParseAdGuardYAMLPassthroughSentinelIsUnsupported(t *testing.T) {
	p, err := ParseAdGuardYAML(realAdGuardYAML)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range p.Unsupported {
		if contains(u, "excluded.lan") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the A/AAAA passthrough sentinel to be an explicit unsupported finding, got %+v", p.Unsupported)
	}
}

func TestParseAdGuardYAMLRejectsNonYAMLInput(t *testing.T) {
	if _, err := ParseAdGuardYAML("not: valid: yaml: at: all: [["); err == nil {
		t.Fatal("expected an error for invalid YAML")
	}
}

func TestParseAdblockRuleModifierIsUnsupported(t *testing.T) {
	if _, ok := parseAdblockRule("||ads.example.com^$important", true); ok {
		t.Fatal("expected a modifier rule to be rejected (unsupported), not silently accepted")
	}
}

func TestParseAdblockRuleCosmeticIsUnsupported(t *testing.T) {
	if _, ok := parseAdblockRule("example.com##.ad-banner", true); ok {
		t.Fatal("expected a cosmetic rule to be rejected (unsupported)")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
