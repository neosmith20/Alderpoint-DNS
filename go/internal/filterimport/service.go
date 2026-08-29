package filterimport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/localdns"
)

// Service applies a parsed Pi-hole (or AdGuard, see adguard.go) result
// against the three real Go-native subsystems it actually spans --
// blocklist subscriptions, Local DNS records, and custom filter rules.
// Every write goes through those services' own real Create methods (the
// same ones the owner-facing UI pages use), never a raw INSERT, so
// every existing invariant (URL/domain normalization, RPZ/dnsdist
// recompilation on Local DNS change, etc.) is preserved automatically.
type Service struct {
	Blocklists  *blocklists.Service
	CustomRules *customrules.Service
	LocalDNS    *localdns.Service
}

type ItemOutcome struct {
	Kind   string `json:"kind"` // "blocklist" | "rule" | "local_dns"
	Text   string `json:"text"`
	Status string `json:"status"` // "would_import" | "imported" | "skipped_duplicate" | "failed"
	Detail string `json:"detail,omitempty"`
}

type Report struct {
	DryRun      bool           `json:"dry_run"`
	SourceType  string         `json:"source_type"` // "pihole" | "adguard_yaml"
	Items       []ItemOutcome  `json:"items"`
	Unsupported []string       `json:"unsupported"`
	Counts      map[string]int `json:"counts"` // "imported"/"skipped_duplicate"/"would_import"/"failed" -> count
}

func (r *Report) record(kind, text, status, detail string) {
	r.Items = append(r.Items, ItemOutcome{Kind: kind, Text: text, Status: status, Detail: detail})
	r.Counts[status]++
}

func randSlug() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ImportPihole parses a Pi-hole export and either previews (dry_run) or
// really applies it. Real duplicate detection against EXISTING data
// (not just within-the-import) so a second run of the same source never
// silently piles up duplicate rows -- internal/customrules and
// internal/blocklists have no unique constraint on
// pattern/URL themselves, so this is checked here explicitly, matching
// this codebase's established "never silently duplicate on re-import"
// convention (see internal/pymigrate's own skipped_duplicate handling).
func (s *Service) ImportPihole(ctx context.Context, text, defaultDomain string, dryRun bool) (Report, error) {
	parsed := ParsePihole(text, defaultDomain)
	return s.apply(ctx, "pihole", parsed, dryRun)
}

// ImportAdGuardYAML parses a real AdGuard Home YAML configuration and
// either previews (dry_run) or really applies it -- same duplicate-
// detection discipline as ImportPihole.
func (s *Service) ImportAdGuardYAML(ctx context.Context, text string, dryRun bool) (Report, error) {
	parsed, err := ParseAdGuardYAML(text)
	if err != nil {
		return Report{}, err
	}
	report, err := s.apply(ctx, "adguard_yaml", PiholeParsed{
		Blocklists:  parsed.Blocklists,
		Rules:       parsed.Rules,
		LocalDNS:    parsed.LocalDNS,
		Unsupported: parsed.Unsupported,
	}, dryRun)
	if err != nil {
		return report, err
	}

	existingRules, err := s.CustomRules.List(ctx)
	if err != nil {
		return report, fmt.Errorf("listing existing custom rules: %w", err)
	}
	existingRewrite := map[string]bool{}
	for _, r := range existingRules {
		if r.RuleType == "rewrite" && r.RewriteTarget != nil {
			existingRewrite[r.Pattern+"->"+*r.RewriteTarget] = true
		}
	}
	for _, rw := range parsed.RewriteRules {
		key := rw.Pattern + "->" + rw.RewriteTarget
		if existingRewrite[key] {
			report.record("rule", rw.Text, "skipped_duplicate", "an identical rewrite rule already exists")
			continue
		}
		if dryRun {
			report.record("rule", rw.Text, "would_import", fmt.Sprintf("rewrite %s -> %s", rw.Pattern, rw.RewriteTarget))
			continue
		}
		target := rw.RewriteTarget
		if _, err := s.CustomRules.Create(ctx, "rewrite", rw.Pattern, &target); err != nil {
			report.record("rule", rw.Text, "failed", err.Error())
			continue
		}
		existingRewrite[key] = true
		report.record("rule", rw.Text, "imported", fmt.Sprintf("rewrite %s -> %s", rw.Pattern, rw.RewriteTarget))
	}
	return report, nil
}

func (s *Service) apply(ctx context.Context, sourceType string, parsed PiholeParsed, dryRun bool) (Report, error) {
	unsupported := parsed.Unsupported
	if unsupported == nil {
		// A nil slice marshals to JSON `null`, not `[]` -- the Svelte
		// side always does `report.unsupported.length`/`.map`, never a
		// null-guard, matching every other real-typed list in this API
		// (PlanRow's own ParseErrors is initialized the same way).
		unsupported = []string{}
	}
	report := Report{DryRun: dryRun, SourceType: sourceType, Counts: map[string]int{}, Items: []ItemOutcome{}, Unsupported: unsupported}

	existingSubs, err := s.Blocklists.List(ctx)
	if err != nil {
		return report, fmt.Errorf("listing existing blocklist subscriptions: %w", err)
	}
	existingURLs := map[string]bool{}
	for _, sub := range existingSubs {
		existingURLs[sub.URL] = true
	}
	for _, bl := range parsed.Blocklists {
		if existingURLs[bl.URL] {
			report.record("blocklist", bl.URL, "skipped_duplicate", "a subscription with this URL already exists")
			continue
		}
		if dryRun {
			report.record("blocklist", bl.URL, "would_import", bl.Name)
			continue
		}
		if _, _, err := s.Blocklists.Create(ctx, "pihole-"+randSlug(), bl.Name, bl.URL, bl.Category); err != nil {
			report.record("blocklist", bl.URL, "failed", err.Error())
			continue
		}
		existingURLs[bl.URL] = true
		report.record("blocklist", bl.URL, "imported", bl.Name)
	}

	existingRules, err := s.CustomRules.List(ctx)
	if err != nil {
		return report, fmt.Errorf("listing existing custom rules: %w", err)
	}
	type ruleKey struct{ ruleType, pattern string }
	existingRuleSet := map[ruleKey]bool{}
	for _, r := range existingRules {
		existingRuleSet[ruleKey{r.RuleType, r.Pattern}] = true
	}
	for _, rc := range parsed.Rules {
		key := ruleKey{rc.RuleType, rc.Pattern}
		if existingRuleSet[key] {
			report.record("rule", rc.Text, "skipped_duplicate", "an identical rule already exists")
			continue
		}
		if dryRun {
			report.record("rule", rc.Text, "would_import", fmt.Sprintf("%s: %s", rc.RuleType, rc.Pattern))
			continue
		}
		if _, err := s.CustomRules.Create(ctx, rc.RuleType, rc.Pattern, nil); err != nil {
			report.record("rule", rc.Text, "failed", err.Error())
			continue
		}
		existingRuleSet[key] = true
		report.record("rule", rc.Text, "imported", fmt.Sprintf("%s: %s", rc.RuleType, rc.Pattern))
	}

	existingRecords, err := s.LocalDNS.List(ctx)
	if err != nil {
		return report, fmt.Errorf("listing existing local DNS records: %w", err)
	}
	type dnsKey struct{ name, rtype, value string }
	existingDNSSet := map[dnsKey]bool{}
	for _, r := range existingRecords {
		existingDNSSet[dnsKey{r.Name, r.RecordType, r.Value}] = true
	}
	for _, ld := range parsed.LocalDNS {
		key := dnsKey{ld.Name, ld.RecordType, ld.Value}
		text := fmt.Sprintf("%s %s %s", ld.Name, ld.RecordType, ld.Value)
		if existingDNSSet[key] {
			report.record("local_dns", text, "skipped_duplicate", "an identical Local DNS record already exists")
			continue
		}
		if dryRun {
			report.record("local_dns", text, "would_import", ld.Origin)
			continue
		}
		if _, err := s.LocalDNS.Create(ctx, localdns.CreateInput{Name: ld.Name, RecordType: ld.RecordType, Value: ld.Value, TTL: ld.TTL, Enabled: true}); err != nil {
			report.record("local_dns", text, "failed", err.Error())
			continue
		}
		existingDNSSet[key] = true
		report.record("local_dns", text, "imported", ld.Origin)
	}

	return report, nil
}
