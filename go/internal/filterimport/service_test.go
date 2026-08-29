package filterimport

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/localdns"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	dir := t.TempDir()
	return &Service{
		Blocklists:  &blocklists.Service{DB: db, HTTPClient: client, StagingDir: filepath.Join(dir, "staging"), RuntimeDir: filepath.Join(dir, "runtime"), MaxConcurrent: 3},
		CustomRules: &customrules.Service{DB: db},
		LocalDNS:    &localdns.Service{DB: db, StagingDir: filepath.Join(dir, "ld-staging"), RuntimeDir: filepath.Join(dir, "ld-runtime")},
	}
}

func TestImportPiholeDryRunNeverWrites(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	text := "blacklist ads.example.com\ncname=alias,target.lan,600\nhttps://example.invalid/hosts.txt\n"

	report, err := s.ImportPihole(ctx, text, "lan", true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.DryRun {
		t.Fatal("expected DryRun=true")
	}
	if report.Counts["would_import"] != 3 {
		t.Fatalf("expected 3 would_import, got %+v", report.Counts)
	}

	rules, _ := s.CustomRules.List(ctx)
	if len(rules) != 0 {
		t.Fatalf("dry run must never write a real rule, got %+v", rules)
	}
	records, _ := s.LocalDNS.List(ctx)
	if len(records) != 0 {
		t.Fatalf("dry run must never write a real local DNS record, got %+v", records)
	}
	subs, _ := s.Blocklists.List(ctx)
	if len(subs) != 0 {
		t.Fatalf("dry run must never write a real blocklist subscription, got %+v", subs)
	}
}

func TestImportPiholeRealApplyWritesAllThreeSubsystems(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	text := "blacklist ads.example.com\ncname=alias,target.lan,600\nhttps://example.invalid/hosts.txt\n"

	report, err := s.ImportPihole(ctx, text, "lan", false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Counts["imported"] != 3 {
		t.Fatalf("expected 3 imported, got %+v (%+v)", report.Counts, report.Items)
	}

	rules, err := s.CustomRules.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].RuleType != "block" || rules[0].Pattern != "ads.example.com" {
		t.Fatalf("expected the real block rule, got %+v", rules)
	}

	records, err := s.LocalDNS.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Name != "alias.lan" || records[0].RecordType != "CNAME" {
		t.Fatalf("expected the real CNAME record, got %+v", records)
	}

	subs, err := s.Blocklists.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0].URL != "https://example.invalid/hosts.txt" {
		t.Fatalf("expected the real blocklist subscription, got %+v", subs)
	}
}

func TestImportPiholeSecondRunSkipsDuplicates(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	text := "blacklist ads.example.com\n"

	if _, err := s.ImportPihole(ctx, text, "lan", false); err != nil {
		t.Fatal(err)
	}
	report2, err := s.ImportPihole(ctx, text, "lan", false)
	if err != nil {
		t.Fatal(err)
	}
	if report2.Counts["skipped_duplicate"] != 1 || report2.Counts["imported"] != 0 {
		t.Fatalf("expected the second import to skip the duplicate rule, got %+v", report2.Counts)
	}

	rules, _ := s.CustomRules.List(ctx)
	if len(rules) != 1 {
		t.Fatalf("expected exactly 1 rule after two identical imports, got %+v", rules)
	}
}

func TestImportPiholeUnsupportedFindingsSurfaceInReport(t *testing.T) {
	s := newTestService(t)
	report, err := s.ImportPihole(context.Background(), "group 1,ads.example.com\n", "lan", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Unsupported) != 1 {
		t.Fatalf("expected 1 unsupported finding in the report, got %+v", report.Unsupported)
	}
}

func TestImportPiholeAgainstARealHTTPTestBlocklistURL(t *testing.T) {
	// Proves the imported subscription is genuinely usable, not just a
	// row -- a real httptest server stands in for the real blocklist
	// host, and the subscription's own background refresh (kicked off
	// by blocklists.Service.Create) is allowed to run for real.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0.0.0.0 ads.example.invalid\n"))
	}))
	t.Cleanup(srv.Close)

	s := newTestService(t)
	report, err := s.ImportPihole(context.Background(), srv.URL+"\n", "lan", false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Counts["imported"] != 1 {
		t.Fatalf("expected 1 imported blocklist, got %+v", report.Counts)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		subs, _ := s.Blocklists.List(context.Background())
		if len(subs) == 1 && subs[0].LastStatus != nil && *subs[0].LastStatus != "" && *subs[0].LastStatus != "pending" {
			if *subs[0].LastStatus != "ok" {
				t.Fatalf("expected the real refresh to succeed, got status=%q err=%v", *subs[0].LastStatus, subs[0].LastError)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the real background refresh to complete")
}

func TestImportAdGuardYAMLRealApplyWritesAllTargets(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	report, err := s.ImportAdGuardYAML(ctx, realAdGuardYAML, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Counts["imported"] == 0 {
		t.Fatalf("expected real imports, got %+v", report.Counts)
	}

	subs, _ := s.Blocklists.List(ctx)
	if len(subs) != 2 {
		t.Fatalf("expected 2 real blocklist subscriptions, got %+v", subs)
	}
	rules, _ := s.CustomRules.List(ctx)
	var haveBlock, haveAllow, haveRegex, haveRewrite bool
	for _, r := range rules {
		switch r.RuleType {
		case "block":
			haveBlock = true
		case "allow":
			haveAllow = true
		case "regex_block":
			haveRegex = true
		case "rewrite":
			haveRewrite = true
			if r.RewriteTarget == nil || *r.RewriteTarget != "10.0.0.99" {
				t.Fatalf("expected the rewrite rule to target 10.0.0.99, got %+v", r)
			}
		}
	}
	if !haveBlock || !haveAllow || !haveRegex || !haveRewrite {
		t.Fatalf("expected block+allow+regex+rewrite rules, got %+v", rules)
	}
	records, _ := s.LocalDNS.List(ctx)
	if len(records) != 2 {
		t.Fatalf("expected 2 real local DNS records, got %+v", records)
	}
}

func TestImportAdGuardYAMLDryRunNeverWrites(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	report, err := s.ImportAdGuardYAML(ctx, realAdGuardYAML, true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.DryRun {
		t.Fatal("expected DryRun=true")
	}
	subs, _ := s.Blocklists.List(ctx)
	rules, _ := s.CustomRules.List(ctx)
	records, _ := s.LocalDNS.List(ctx)
	if len(subs) != 0 || len(rules) != 0 || len(records) != 0 {
		t.Fatalf("dry run must never write anything real, got subs=%+v rules=%+v records=%+v", subs, rules, records)
	}
}

func TestImportAdGuardYAMLSecondRunSkipsDuplicateRewrite(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.ImportAdGuardYAML(ctx, realAdGuardYAML, false); err != nil {
		t.Fatal(err)
	}
	report2, err := s.ImportAdGuardYAML(ctx, realAdGuardYAML, false)
	if err != nil {
		t.Fatal(err)
	}
	if report2.Counts["imported"] != 0 {
		t.Fatalf("expected the second run to import nothing new, got %+v", report2.Counts)
	}
}

func TestReportNeverMarshalsNullSlicesForItemsOrUnsupported(t *testing.T) {
	// Regression: a nil Go slice marshals to JSON `null`, not `[]`, and
	// the real Svelte page does `report.unsupported.length`/
	// `report.items.map(...)` with no null-guard (matching every other
	// real-typed list in this API) -- caught live via a real Chromium
	// click-through ("Cannot read properties of null (reading 'length')")
	// when a real import had zero unsupported findings.
	s := newTestService(t)
	report, err := s.ImportPihole(context.Background(), "blacklist ads.example.com\n", "lan", false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"unsupported":null`)) {
		t.Fatalf("unsupported must never marshal to null: %s", data)
	}
	if bytes.Contains(data, []byte(`"items":null`)) {
		t.Fatalf("items must never marshal to null: %s", data)
	}
}
