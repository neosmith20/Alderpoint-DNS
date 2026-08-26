package pymigrate

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/upstreams"
)

// newFixturePythonDB creates a real SQLite file with Python's actual
// control.db schema for the five migrated tables (read directly from
// the live schema via "select sql from sqlite_master", not guessed --
// see this package's own doc comment for the exact source), seeded
// with representative rows.
func newFixturePythonDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	schema := `
CREATE TABLE local_dns_records (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, record_type TEXT NOT NULL,
    value TEXT NOT NULL, ttl INTEGER NOT NULL DEFAULT 300, enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(name, record_type, value)
);
CREATE TABLE upstream_profiles (
    id INTEGER PRIMARY KEY, upstream_profile_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    transport TEXT NOT NULL, strategy TEXT NOT NULL DEFAULT 'ordered', created_at TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE upstream_endpoints (
    id INTEGER PRIMARY KEY, upstream_profile_row_id INTEGER NOT NULL, address TEXT NOT NULL,
    tls_hostname TEXT, priority INTEGER NOT NULL DEFAULT 0, weight INTEGER NOT NULL DEFAULT 1,
    secret_ref TEXT, doh_path TEXT
);
CREATE TABLE dns_transport_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1), dot_enabled INTEGER NOT NULL DEFAULT 0,
    dot_port INTEGER NOT NULL DEFAULT 853, updated_at TEXT NOT NULL,
    doh_enabled INTEGER NOT NULL DEFAULT 0, doh_port INTEGER NOT NULL DEFAULT 443,
    doh_path TEXT NOT NULL DEFAULT '/dns-query', doq_enabled INTEGER NOT NULL DEFAULT 0,
    doq_port INTEGER NOT NULL DEFAULT 853, doh3_enabled INTEGER NOT NULL DEFAULT 0, doh3_port INTEGER NOT NULL DEFAULT 443
);
CREATE TABLE policy_layers (
    id INTEGER PRIMARY KEY, scope TEXT NOT NULL, scope_ref TEXT NOT NULL,
    filtering_profile_id TEXT, safesearch_mode TEXT, parental_policy_id TEXT, security_policy_id TEXT,
    service_blocking_ruleset_id TEXT, blocking_response_mode TEXT, custom_ipv4 TEXT, custom_ipv6 TEXT,
    upstream_profile_id TEXT, fallback_strategy TEXT, fallback_upstream_profile_id TEXT, ecs_mode TEXT,
    domain_routing_ruleset_id TEXT, query_log_enabled INTEGER, statistics_enabled INTEGER,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(scope, scope_ref)
);
CREATE TABLE blocklist_subscriptions (
    id INTEGER PRIMARY KEY, subscription_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, url TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
    last_refresh_at TEXT, last_status TEXT NOT NULL DEFAULT 'never_refreshed', last_error TEXT NOT NULL DEFAULT '',
    rule_count INTEGER NOT NULL DEFAULT 0, update_interval_seconds INTEGER
);
`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	seed := `
INSERT INTO local_dns_records(name, record_type, value, ttl, enabled, created_at, updated_at)
  VALUES('printer.lan','A','10.0.0.50',300,1,datetime('now'),datetime('now')),
        ('nas.lan','A','10.0.0.60',300,0,datetime('now'),datetime('now'));

INSERT INTO upstream_profiles(upstream_profile_id, name, transport, strategy, created_at, enabled, sort_order)
  VALUES('quad9','Quad9','plain','ordered',datetime('now'),1,0),
        ('disabled-profile','Disabled','plain','ordered',datetime('now'),0,1);
INSERT INTO upstream_endpoints(upstream_profile_row_id, address, priority, weight)
  VALUES(1,'9.9.9.9:53',0,1), (2,'1.0.0.1:53',0,1);

INSERT INTO dns_transport_settings(id, dot_enabled, dot_port, updated_at, doh_enabled, doh_port, doh_path)
  VALUES(1, 1, 8853, datetime('now'), 0, 443, '/dns-query');

-- scope_ref='singleton' for the global row deliberately matches the
-- REAL live owner-preview control.db's own actual value (confirmed
-- live: not 'global', which Go's own convention uses) -- a real
-- discrepancy this fixture is written to catch, not just a plausible
-- guess.
INSERT INTO policy_layers(scope, scope_ref, blocking_response_mode, created_at, updated_at)
  VALUES('global','singleton','refused',datetime('now'),datetime('now')),
        ('network','lan',NULL,datetime('now'),datetime('now'));

INSERT INTO blocklist_subscriptions(subscription_id, name, url, category, enabled, created_at, update_interval_seconds)
  VALUES('stevenblack','StevenBlack Unified','https://example.invalid/hosts','ads',1,datetime('now'),3600);
`
	if _, err := db.Exec(seed); err != nil {
		t.Fatal(err)
	}
	return path
}

type testTarget struct {
	db            *sql.DB
	localDNS      *localdns.Service
	upstreamsSvc  *upstreams.Service
	dnsTransports *dnstransports.Service
	policySvc     *policy.Service
	blocklistsSvc *blocklists.Service
	backupSvc     *backup.Service
}

func newTestTarget(t *testing.T) *testTarget {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "go.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &testTarget{
		db:            db,
		localDNS:      &localdns.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()},
		upstreamsSvc:  &upstreams.Service{DB: db},
		dnsTransports: &dnstransports.Service{DB: db},
		policySvc:     &policy.Service{DB: db},
		blocklistsSvc: &blocklists.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()},
		backupSvc:     &backup.Service{DB: db, Dir: t.TempDir(), Version: "test"},
	}
}

func (tt *testTarget) importer(pyPath, auditPath string) *Importer {
	return &Importer{
		PythonControlDBPath: pyPath,
		LocalDNS:            tt.localDNS, Upstreams: tt.upstreamsSvc, DNSTransports: tt.dnsTransports,
		Policy: tt.policySvc, Blocklists: tt.blocklistsSvc, Backup: tt.backupSvc, AuditLogPath: auditPath,
	}
}

func TestDryRunNeverWritesAnything(t *testing.T) {
	pyPath := newFixturePythonDB(t)
	tt := newTestTarget(t)
	im := tt.importer(pyPath, filepath.Join(t.TempDir(), "audit.jsonl"))

	report, err := im.Run(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.DryRun {
		t.Fatal("expected DryRun=true in the report")
	}
	if report.SnapshotFilename != "" {
		t.Fatal("dry run must never take a snapshot")
	}
	recs, _ := tt.localDNS.List(context.Background())
	if len(recs) != 0 {
		t.Fatalf("dry run must never write -- found %d local DNS records", len(recs))
	}
	profiles, _, _ := tt.upstreamsSvc.List(context.Background())
	if len(profiles) != 0 {
		t.Fatalf("dry run must never write -- found %d upstream profiles", len(profiles))
	}

	// Every seeded row should be reported as "would_import".
	wantCounts := map[string]int{
		"local_dns_records": 2, "upstream_profiles": 2, "dns_transport_settings": 1,
		"policy_layers": 1, "blocklist_subscriptions": 1,
	}
	for table, want := range wantCounts {
		got := report.Tables[table].Imported // "would_import" counted the same as "imported" in TableSummary
		if got != want {
			t.Errorf("table %s: expected %d would_import, got %d (results: %+v)", table, want, got, report.Results)
		}
	}
	// The non-global policy row must be reported, not silently dropped.
	foundNonGlobalNote := false
	for _, r := range report.Results {
		if r.Table == "policy_layers" && r.Action == "skipped_unsupported" {
			foundNonGlobalNote = true
		}
	}
	if !foundNonGlobalNote {
		t.Error("expected the non-global policy_layers row to be reported as skipped_unsupported")
	}
}

func TestRealImportActuallyCreatesRealRows(t *testing.T) {
	pyPath := newFixturePythonDB(t)
	tt := newTestTarget(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	im := tt.importer(pyPath, auditPath)

	report, err := im.Run(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if report.SnapshotFilename == "" {
		t.Fatal("expected a real import to take a pre-migration snapshot")
	}

	recs, err := tt.localDNS.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 real local DNS records after import, got %d", len(recs))
	}
	var nas *localdns.Record
	for i := range recs {
		if recs[i].Name == "nas.lan" {
			nas = &recs[i]
		}
	}
	if nas == nil || nas.Enabled {
		t.Fatalf("expected nas.lan to be imported as disabled (matching the source), got %+v", nas)
	}

	profiles, _, err := tt.upstreamsSvc.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 real upstream profiles after import, got %d", len(profiles))
	}
	var disabled *upstreams.Profile
	for i := range profiles {
		if profiles[i].UpstreamProfileID == "disabled-profile" {
			disabled = &profiles[i]
		}
	}
	if disabled == nil || disabled.Enabled {
		t.Fatalf("expected disabled-profile to be imported as disabled (matching the source), got %+v", disabled)
	}

	settings, err := tt.dnsTransports.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !settings.DotEnabled || settings.DotPort != 8853 {
		t.Fatalf("expected DoT settings to be imported, got %+v", settings)
	}

	layer, err := tt.policySvc.Load(context.Background(), "global", "global")
	if err != nil {
		t.Fatal(err)
	}
	if layer.BlockingResponseMode == nil || *layer.BlockingResponseMode != "refused" {
		t.Fatalf("expected the global policy layer to be imported, got %+v", layer)
	}

	subs, err := tt.blocklistsSvc.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0].SubscriptionID != "stevenblack" {
		t.Fatalf("expected the blocklist subscription to be registered, got %+v", subs)
	}

	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(auditBytes) == 0 {
		t.Fatal("expected a real, non-empty audit log")
	}
}

func TestRunningImportTwiceSkipsDuplicatesTheSecondTime(t *testing.T) {
	pyPath := newFixturePythonDB(t)
	tt := newTestTarget(t)
	im := tt.importer(pyPath, "")

	if _, err := im.Run(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	report2, err := im.Run(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := tt.localDNS.List(context.Background())
	if len(recs) != 2 {
		t.Fatalf("running the import twice must never duplicate rows, got %d local DNS records", len(recs))
	}
	if report2.Tables["local_dns_records"].Skipped != 2 {
		t.Fatalf("expected the second run to report both local DNS rows as skipped duplicates, got %+v", report2.Tables["local_dns_records"])
	}
}

func TestRollbackRestoresThePreMigrationState(t *testing.T) {
	pyPath := newFixturePythonDB(t)
	tt := newTestTarget(t)
	im := tt.importer(pyPath, "")

	report, err := im.Run(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := tt.localDNS.List(context.Background())
	if len(recs) == 0 {
		t.Fatal("expected the import to have written real rows before testing rollback")
	}

	if _, err := im.Rollback(context.Background(), report.SnapshotFilename); err != nil {
		t.Fatal(err)
	}
	recsAfter, err := tt.localDNS.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recsAfter) != 0 {
		t.Fatalf("expected rollback to restore the pre-migration (empty) state, got %d local DNS records", len(recsAfter))
	}
	profilesAfter, _, _ := tt.upstreamsSvc.List(context.Background())
	if len(profilesAfter) != 0 {
		t.Fatalf("expected rollback to restore the pre-migration (empty) state, got %d upstream profiles", len(profilesAfter))
	}
}

// TestDryRunAgainstTheRealLiveControlDB proves this tool against the
// actual real owner-preview appliance's own control.db -- read-only,
// never written to, matching this session's established standard for
// every compatibility boundary (pyanalytics/rawquerylog/tlscert/
// ops_replication.go all have an equivalent real-live-data test).
// Skips if that file isn't present in the environment running the test.
func TestDryRunAgainstTheRealLiveControlDB(t *testing.T) {
	const real = "/root/apdns-v2-preview-state/var-lib/control.db"
	if _, err := os.Stat(real); err != nil {
		t.Skip("real live control.db not present in this environment")
	}
	tt := newTestTarget(t)
	im := tt.importer(real, "")
	report, err := im.Run(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if report.Tables["local_dns_records"].SourceCount == 0 {
		t.Error("expected the real live control.db to have at least one local DNS record")
	}
	t.Logf("real live control.db dry-run: %+v", report.Tables)
	recs, _ := tt.localDNS.List(context.Background())
	if len(recs) != 0 {
		t.Fatal("dry run against the real live control.db must never write to this test's own throwaway target DB")
	}
}
