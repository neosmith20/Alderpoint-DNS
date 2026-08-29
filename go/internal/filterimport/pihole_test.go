package filterimport

import "testing"

func TestParsePiholeAdlistURL(t *testing.T) {
	p := ParsePihole("https://example.invalid/hosts.txt\n", "lan")
	if len(p.Blocklists) != 1 || p.Blocklists[0].URL != "https://example.invalid/hosts.txt" || p.Blocklists[0].Name != "hosts.txt" {
		t.Fatalf("expected 1 blocklist candidate, got %+v", p.Blocklists)
	}
}

func TestParsePiholeExactBlacklistAndWhitelistKeywords(t *testing.T) {
	p := ParsePihole("blacklist ads.example.com\nwhitelist good.example.com\n", "lan")
	if len(p.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %+v", p.Rules)
	}
	if p.Rules[0].RuleType != "block" || p.Rules[0].Pattern != "ads.example.com" {
		t.Fatalf("expected block rule, got %+v", p.Rules[0])
	}
	if p.Rules[1].RuleType != "allow" || p.Rules[1].Pattern != "good.example.com" {
		t.Fatalf("expected allow rule, got %+v", p.Rules[1])
	}
}

func TestParsePiholeSectionScopedDomains(t *testing.T) {
	p := ParsePihole("[whitelist]\ngood.example.com\n[blacklist]\nbad.example.com\n", "lan")
	if len(p.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %+v", p.Rules)
	}
	if p.Rules[0].RuleType != "allow" || p.Rules[0].Pattern != "good.example.com" {
		t.Fatalf("expected section-scoped allow, got %+v", p.Rules[0])
	}
	if p.Rules[1].RuleType != "block" || p.Rules[1].Pattern != "bad.example.com" {
		t.Fatalf("expected section-scoped block, got %+v", p.Rules[1])
	}
}

func TestParsePiholeCommentSectionMarker(t *testing.T) {
	// A common Pi-hole export style: "# blacklist #" as a comment-style
	// section header instead of "[blacklist]".
	p := ParsePihole("# blacklist #\nbad.example.com\n", "lan")
	if len(p.Rules) != 1 || p.Rules[0].RuleType != "block" {
		t.Fatalf("expected the comment-marker section header to be recognized, got %+v", p.Rules)
	}
}

func TestParsePiholeRegexBlockAndAllow(t *testing.T) {
	p := ParsePihole("regex ^ads\\.\nregex whitelist ^good\\.\n", "lan")
	if len(p.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %+v", p.Rules)
	}
	if p.Rules[0].RuleType != "regex_block" || p.Rules[0].Pattern != `^ads\.` {
		t.Fatalf("expected regex_block, got %+v", p.Rules[0])
	}
	if p.Rules[1].RuleType != "regex_allow" || p.Rules[1].Pattern != `^good\.` {
		t.Fatalf("expected regex_allow, got %+v", p.Rules[1])
	}
}

func TestParsePiholeWildcardRegexIdiomBecomesADomainRule(t *testing.T) {
	// `pihole -wild example.com` stores this exact regex -- must
	// translate to a plain block rule on the domain, not a regex rule.
	p := ParsePihole(`regex (\.|^)example\.com$`+"\n", "lan")
	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %+v", p.Rules)
	}
	if p.Rules[0].RuleType != "block" || p.Rules[0].Pattern != "example.com" {
		t.Fatalf("expected the wildcard idiom to become a plain block rule on example.com, got %+v", p.Rules[0])
	}
}

func TestParsePiholeCnameRewrite(t *testing.T) {
	p := ParsePihole("cname=alias,target.lan,600\n", "lan")
	if len(p.LocalDNS) != 1 {
		t.Fatalf("expected 1 local DNS row, got %+v", p.LocalDNS)
	}
	r := p.LocalDNS[0]
	if r.Name != "alias.lan" || r.RecordType != "CNAME" || r.Value != "target.lan" || r.TTL != 600 {
		t.Fatalf("expected a real CNAME rewrite, got %+v", r)
	}
}

func TestParsePiholeCustomListHostsLine(t *testing.T) {
	p := ParsePihole("10.0.0.50 printer printer.lan\n", "lan")
	if len(p.LocalDNS) != 2 {
		t.Fatalf("expected 2 local DNS rows (one per hostname), got %+v", p.LocalDNS)
	}
	if p.LocalDNS[0].RecordType != "A" || p.LocalDNS[0].Value != "10.0.0.50" {
		t.Fatalf("expected an A record, got %+v", p.LocalDNS[0])
	}
}

func TestParsePiholeGroupAssignmentIsUnsupportedNotSilentlyDropped(t *testing.T) {
	p := ParsePihole("group 1,ads.example.com\n", "lan")
	if len(p.Unsupported) != 1 {
		t.Fatalf("expected 1 unsupported finding, got %+v", p.Unsupported)
	}
	if len(p.Rules) != 0 && len(p.LocalDNS) != 0 {
		t.Fatal("a group assignment must never become a rule or DNS record")
	}
}

func TestParsePiholeCommentLinesAreSkipped(t *testing.T) {
	p := ParsePihole("# just a comment, not a section header\n", "lan")
	if len(p.Rules) != 0 || len(p.Unsupported) != 0 {
		t.Fatalf("expected a bare comment to be silently skipped, got rules=%+v unsupported=%+v", p.Rules, p.Unsupported)
	}
}

func TestParsePiholeUnrecognizedLineIsDisclosed(t *testing.T) {
	p := ParsePihole("!!! not a domain or url ???\n", "lan")
	if len(p.Unsupported) != 1 {
		t.Fatalf("expected 1 unsupported finding, got %+v", p.Unsupported)
	}
}
