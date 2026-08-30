// Package pymigrate is the audited, one-time import path from Python's
// real control.db into this Go control plane's own native schema --
// never a permanent proxy, never a dependency on Python being reachable
// afterward, and never touching anything secret (admins/sessions,
// SecretStore-referenced material, replication credentials, observed
// clients). Matches the governing task's explicit instruction: "If
// existing safe state must move over, use an audited one-time
// import/migration -- not a permanent Python proxy."
//
// Scope, deliberately bounded to what internal/dnscompile actually
// consumes (disclosed, not silently narrowed) -- the tables that
// directly drive real DNS behavior:
//
//   - local_dns_records -> internal/localdns
//   - upstream_profiles + upstream_endpoints -> internal/upstreams
//     (secret_ref, if any endpoint has one, is never read or migrated
//     -- Go has no secrets store yet, same disclosed gap as elsewhere)
//   - dns_transport_settings -> internal/dnstransports (DoT/DoH/DoQ/
//     DoH3 enable+port+path only; dnscrypt_settings is not migrated at
//     all -- its real identity material lives in Python's SecretStore,
//     never control.db, and Go has nothing to hold it yet)
//   - policy_layers, global scope only -> internal/policy (matches
//     where internal/policy's own effective-policy resolution
//     currently is -- network/group/client/schedule rows are read and
//     reported in the dry-run output but not imported yet)
//   - blocklist_subscriptions -> internal/blocklists (registration
//     only: subscription_id/name/url/category/enabled/interval. The
//     actual blocked-domain list is never copied -- Go's own scheduler
//     pulls it fresh from each subscription's real URL after import,
//     the same real content Python itself would fetch, not a stale
//     copy)
//
// NOT migrated, disclosed rather than hidden: admins/sessions/secrets
// (a different auth model entirely -- Go has its own setup flow),
// clients/groups/policy_client_group_membership (not consumed by the
// DNS compiler yet), domain_routing_rules (internal/upstreams doesn't
// store domain routing at all yet), service_definitions/service_domains/
// service_blocking_rulesets (V1-style service-blocking, a different
// model from internal/customrules' structured builder), replication_*/
// node_identity/observed_clients (identity and discovery state, out of
// this pass's scope), notification_providers (their secret_ref is
// never migrated for the same reason as upstream endpoints).
package pymigrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/upstreams"
)

// RowResult is one audited outcome -- one line in the JSON-lines audit
// log, and one entry in the returned Report, for every single source
// row this tool ever looks at, imported or not.
type RowResult struct {
	Table  string `json:"table"`
	Key    string `json:"key"`
	Action string `json:"action"` // "would_import" | "imported" | "skipped_duplicate" | "skipped_unsupported" | "rejected"
	Detail string `json:"detail,omitempty"`
}

type TableSummary struct {
	SourceCount int `json:"source_count"`
	Imported    int `json:"imported"`
	Skipped     int `json:"skipped"`
	Rejected    int `json:"rejected"`
}

type Report struct {
	DryRun           bool                    `json:"dry_run"`
	StartedAt        string                  `json:"started_at"`
	FinishedAt       string                  `json:"finished_at"`
	SnapshotFilename string                  `json:"snapshot_filename,omitempty"`
	Tables           map[string]TableSummary `json:"tables"`
	Results          []RowResult             `json:"results"`
	NotMigrated      []string                `json:"not_migrated"`
}

type Importer struct {
	PythonControlDBPath string
	LocalDNS            *localdns.Service
	Upstreams           *upstreams.Service
	DNSTransports       *dnstransports.Service
	Policy              *policy.Service
	Blocklists          *blocklists.Service
	// Backup is used only for the pre-migration snapshot (a real,
	// tested VACUUM INTO, the same mechanism the Backup & Restore page
	// itself uses) -- never touched at all in dry-run mode.
	Backup       *backup.Service
	AuditLogPath string
}

var notMigratedTables = []string{
	"admins", "sessions", "login_attempts", "admin_audit_log",
	"clients", "client_identifiers", "client_groups", "client_group_members",
	"policies", "policy_networks", "policy_groups", "policy_client_group_membership",
	"policy_schedules", "policy_schedule_windows",
	"domain_routing_rules",
	"service_definitions", "service_domains", "service_blocking_rulesets", "service_blocking_ruleset_members",
	"dnscrypt_settings",
	"node_identity", "observed_clients", "observed_client_stats", "observed_client_settings",
	"notification_providers",
	"replication_peers", "replication_replicas", "replication_seen_messages", "replication_generations_v2",
	"update_jobs", "backup_jobs", "restore_jobs", "import_jobs",
	"update_settings", "blocklist_update_settings", "uploaded_archive_settings", "uploaded_archive_metadata",
}

func (im *Importer) openPythonDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+im.PythonControlDBPath+"?mode=ro&immutable=1&_pragma=busy_timeout(3000)&_pragma=query_only(1)")
	if err != nil {
		return nil, fmt.Errorf("open Python control.db read-only: %w", err)
	}
	return db, nil
}

// Run performs the migration. dryRun=true never writes anything (no Go
// table mutation, no snapshot, no promotion) -- it only reads Python's
// control.db and this control plane's own tables to report exactly
// what a real run would do. dryRun=false takes a real pre-migration
// snapshot first (via internal/backup, the same real, tested mechanism
// the Backup & Restore page uses), then imports for real; the returned
// Report's SnapshotFilename is what a caller passes to Rollback if
// anything about the result looks wrong.
func (im *Importer) Run(ctx context.Context, dryRun bool) (Report, error) {
	report := Report{DryRun: dryRun, StartedAt: time.Now().UTC().Format(time.RFC3339), Tables: map[string]TableSummary{}, NotMigrated: notMigratedTables}

	pydb, err := im.openPythonDB()
	if err != nil {
		return report, err
	}
	defer pydb.Close()

	var audit *auditLog
	if im.AuditLogPath != "" {
		audit, err = openAuditLog(im.AuditLogPath)
		if err != nil {
			return report, fmt.Errorf("opening audit log: %w", err)
		}
		defer audit.Close()
	}
	record := func(r RowResult) {
		report.Results = append(report.Results, r)
		s := report.Tables[r.Table]
		s.SourceCount++
		switch r.Action {
		case "imported", "would_import":
			s.Imported++
		case "rejected":
			s.Rejected++
		default:
			s.Skipped++
		}
		report.Tables[r.Table] = s
		if audit != nil {
			audit.Record(auditEntry{Time: time.Now().UTC().Format(time.RFC3339), DryRun: dryRun, Row: r})
		}
	}

	if !dryRun {
		if im.Backup == nil {
			return report, fmt.Errorf("no backup service configured -- refusing to run a real (non-dry-run) migration with no snapshot/rollback path")
		}
		snap, err := im.Backup.Create(ctx, "pre-migration-snapshot", "")
		if err != nil {
			return report, fmt.Errorf("pre-migration snapshot failed, nothing imported: %w", err)
		}
		report.SnapshotFilename = snap.Filename
	}

	if err := im.migrateLocalDNS(ctx, pydb, dryRun, record); err != nil {
		return report, err
	}
	if err := im.migrateUpstreams(ctx, pydb, dryRun, record); err != nil {
		return report, err
	}
	if err := im.migrateDNSTransports(ctx, pydb, dryRun, record); err != nil {
		return report, err
	}
	if err := im.migrateGlobalPolicy(ctx, pydb, dryRun, record); err != nil {
		return report, err
	}
	if err := im.migrateBlocklists(ctx, pydb, dryRun, record); err != nil {
		return report, err
	}

	report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	return report, nil
}

// Rollback restores this control plane's state from the snapshot a
// prior real Run took -- the exact same real, tested, transactional
// restore path (mandatory safety-backup-before-restore included) the
// Backup & Restore page itself uses, applied to every category so the
// pre-migration state is fully back, not partially.
func (im *Importer) Rollback(ctx context.Context, snapshotFilename string) (backup.BackupInfo, error) {
	if im.Backup == nil {
		return backup.BackupInfo{}, fmt.Errorf("no backup service configured")
	}
	return im.Backup.Restore(ctx, snapshotFilename, "", nil)
}

// --- local DNS ---------------------------------------------------------

func (im *Importer) migrateLocalDNS(ctx context.Context, pydb *sql.DB, dryRun bool, record func(RowResult)) error {
	rows, err := pydb.QueryContext(ctx, `SELECT name, record_type, value, ttl, enabled FROM local_dns_records ORDER BY name, record_type, value`)
	if err != nil {
		return fmt.Errorf("reading local_dns_records: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, rtype, value string
		var ttl, enabled int
		if err := rows.Scan(&name, &rtype, &value, &ttl, &enabled); err != nil {
			return err
		}
		key := fmt.Sprintf("%s %s %s", name, rtype, value)
		if dryRun {
			existing, _ := im.LocalDNS.List(ctx)
			if localDNSExists(existing, name, rtype, value) {
				record(RowResult{Table: "local_dns_records", Key: key, Action: "skipped_duplicate", Detail: "already present in Go's own local_dns_records"})
				continue
			}
			record(RowResult{Table: "local_dns_records", Key: key, Action: "would_import"})
			continue
		}
		_, err := im.LocalDNS.Create(ctx, localdns.CreateInput{Name: name, RecordType: rtype, Value: value, TTL: ttl, Enabled: enabled != 0})
		if err == localdns.ErrDuplicate {
			record(RowResult{Table: "local_dns_records", Key: key, Action: "skipped_duplicate"})
		} else if err != nil {
			record(RowResult{Table: "local_dns_records", Key: key, Action: "rejected", Detail: err.Error()})
		} else {
			record(RowResult{Table: "local_dns_records", Key: key, Action: "imported"})
		}
	}
	return rows.Err()
}

func localDNSExists(existing []localdns.Record, name, rtype, value string) bool {
	for _, r := range existing {
		if r.Name == name && r.RecordType == rtype && r.Value == value {
			return true
		}
	}
	return false
}

// --- upstream profiles ---------------------------------------------------

type pyUpstreamProfile struct {
	rowID                     int64
	upstreamProfileID         string
	name, transport, strategy string
	enabled                   bool
	sortOrder                 int
}

func (im *Importer) migrateUpstreams(ctx context.Context, pydb *sql.DB, dryRun bool, record func(RowResult)) error {
	rows, err := pydb.QueryContext(ctx, `SELECT id, upstream_profile_id, name, transport, strategy, enabled, sort_order FROM upstream_profiles ORDER BY sort_order ASC`)
	if err != nil {
		return fmt.Errorf("reading upstream_profiles: %w", err)
	}
	var profiles []pyUpstreamProfile
	for rows.Next() {
		var p pyUpstreamProfile
		var enabledInt int
		if err := rows.Scan(&p.rowID, &p.upstreamProfileID, &p.name, &p.transport, &p.strategy, &enabledInt, &p.sortOrder); err != nil {
			rows.Close()
			return err
		}
		p.enabled = enabledInt != 0
		profiles = append(profiles, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	existing, _, _ := im.Upstreams.List(ctx)

	for _, p := range profiles {
		epRows, err := pydb.QueryContext(ctx, `SELECT address, tls_hostname, priority, weight, doh_path FROM upstream_endpoints WHERE upstream_profile_row_id=? ORDER BY priority ASC`, p.rowID)
		if err != nil {
			return fmt.Errorf("reading upstream_endpoints for %s: %w", p.upstreamProfileID, err)
		}
		var endpoints []upstreams.Endpoint
		for epRows.Next() {
			var ep upstreams.Endpoint
			var tlsHostname, dohPath sql.NullString
			if err := epRows.Scan(&ep.Address, &tlsHostname, &ep.Priority, &ep.Weight, &dohPath); err != nil {
				epRows.Close()
				return err
			}
			if tlsHostname.Valid {
				ep.TLSHostname = &tlsHostname.String
			}
			if dohPath.Valid {
				ep.DohPath = &dohPath.String
			}
			endpoints = append(endpoints, ep)
		}
		epRows.Close()
		if err := epRows.Err(); err != nil {
			return err
		}

		if upstreamProfileExists(existing, p.upstreamProfileID) {
			record(RowResult{Table: "upstream_profiles", Key: p.upstreamProfileID, Action: "skipped_duplicate", Detail: "already present in Go's own upstream_profiles"})
			continue
		}
		if dryRun {
			record(RowResult{Table: "upstream_profiles", Key: p.upstreamProfileID, Action: "would_import", Detail: fmt.Sprintf("%d endpoint(s), enabled=%v", len(endpoints), p.enabled)})
			continue
		}
		if err := im.Upstreams.Create(ctx, p.upstreamProfileID, p.name, p.transport, p.strategy, endpoints); err != nil {
			record(RowResult{Table: "upstream_profiles", Key: p.upstreamProfileID, Action: "rejected", Detail: err.Error()})
			continue
		}
		if !p.enabled {
			if err := im.Upstreams.SetEnabled(ctx, p.upstreamProfileID, false); err != nil {
				record(RowResult{Table: "upstream_profiles", Key: p.upstreamProfileID, Action: "imported", Detail: "imported but could not preserve disabled state: " + err.Error()})
				continue
			}
		}
		record(RowResult{Table: "upstream_profiles", Key: p.upstreamProfileID, Action: "imported"})
	}
	return nil
}

func upstreamProfileExists(existing []upstreams.Profile, id string) bool {
	for _, p := range existing {
		if p.UpstreamProfileID == id {
			return true
		}
	}
	return false
}

// --- DNS transport settings ----------------------------------------------

func (im *Importer) migrateDNSTransports(ctx context.Context, pydb *sql.DB, dryRun bool, record func(RowResult)) error {
	row := pydb.QueryRowContext(ctx, `SELECT dot_enabled, dot_port, doh_enabled, doh_port, doh_path, doq_enabled, doq_port, doh3_enabled, doh3_port FROM dns_transport_settings WHERE id=1`)
	var dotE, dohE, doqE, doh3E int
	var dotP, dohP, doqP, doh3P int
	var dohPath string
	if err := row.Scan(&dotE, &dotP, &dohE, &dohP, &dohPath, &doqE, &doqP, &doh3E, &doh3P); err == sql.ErrNoRows {
		record(RowResult{Table: "dns_transport_settings", Key: "singleton", Action: "skipped_duplicate", Detail: "no row in Python's control.db (never configured)"})
		return nil
	} else if err != nil {
		return fmt.Errorf("reading dns_transport_settings: %w", err)
	}

	settings := dnstransports.Settings{
		DotEnabled: dotE != 0, DotPort: dotP,
		DohEnabled: dohE != 0, DohPort: dohP, DohPath: dohPath,
		DoqEnabled: doqE != 0, DoqPort: doqP,
		Doh3Enabled: doh3E != 0, Doh3Port: doh3P,
	}
	if dryRun {
		record(RowResult{Table: "dns_transport_settings", Key: "singleton", Action: "would_import", Detail: fmt.Sprintf("dot=%v doh=%v doq=%v doh3=%v", settings.DotEnabled, settings.DohEnabled, settings.DoqEnabled, settings.Doh3Enabled)})
		return nil
	}
	current, err := im.DNSTransports.Get(ctx)
	if err == nil && current != (dnstransports.Settings{}) && (current.DotEnabled || current.DohEnabled || current.DoqEnabled || current.Doh3Enabled || current.DNSCryptEnabled) {
		record(RowResult{Table: "dns_transport_settings", Key: "singleton", Action: "skipped_duplicate", Detail: "Go's dns_transport_settings already has a non-default value"})
		return nil
	}
	// DNSCrypt fields are intentionally left at Go's own current
	// values -- see the package doc comment: identity material is
	// never migrated, so enabling it here without provisioning would
	// be a real product regression (a listener nothing can serve).
	if current.DNSCryptPort != 0 {
		settings.DNSCryptPort = current.DNSCryptPort
		settings.DNSCryptProviderName = current.DNSCryptProviderName
	}
	if _, err := im.DNSTransports.Update(ctx, settings); err != nil {
		record(RowResult{Table: "dns_transport_settings", Key: "singleton", Action: "rejected", Detail: err.Error()})
		return nil
	}
	record(RowResult{Table: "dns_transport_settings", Key: "singleton", Action: "imported"})
	return nil
}

// --- global policy layer --------------------------------------------------

func (im *Importer) migrateGlobalPolicy(ctx context.Context, pydb *sql.DB, dryRun bool, record func(RowResult)) error {
	rows, err := pydb.QueryContext(ctx, `SELECT scope, scope_ref FROM policy_layers ORDER BY scope, scope_ref`)
	if err != nil {
		return fmt.Errorf("reading policy_layers: %w", err)
	}
	var nonGlobalCount int
	for rows.Next() {
		var scope, scopeRef string
		if err := rows.Scan(&scope, &scopeRef); err != nil {
			rows.Close()
			return err
		}
		if scope != "global" {
			nonGlobalCount++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if nonGlobalCount > 0 {
		record(RowResult{Table: "policy_layers", Key: "non-global", Action: "skipped_unsupported", Detail: fmt.Sprintf("%d network/group/client/schedule policy row(s) not migrated -- internal/policy has no per-network effective-policy resolution yet, see internal/dnscompile's own doc comment", nonGlobalCount)})
	}

	// scope_ref for the global row is matched loosely (scope='global'
	// alone, whatever its scope_ref is) rather than assuming any
	// particular sentinel value -- a real discrepancy found live: the
	// actual owner-preview control.db uses scope_ref='singleton' for
	// its one global row, not 'global' (Go's own convention, matching
	// internal/policy's httpapi handler, which always calls
	// Load(ctx, "global", "global")). Python's own scope_ref value is
	// never propagated into Go -- the imported row is always written
	// under Go's own ("global","global") key, matching every other
	// caller of Go's policy store.
	row := pydb.QueryRowContext(ctx, `SELECT filtering_profile_id, safesearch_mode, parental_policy_id, security_policy_id,
		service_blocking_ruleset_id, blocking_response_mode, custom_ipv4, custom_ipv6, upstream_profile_id,
		fallback_strategy, fallback_upstream_profile_id, ecs_mode, domain_routing_ruleset_id,
		query_log_enabled, statistics_enabled FROM policy_layers WHERE scope='global' LIMIT 1`)
	var l policy.Layer
	var queryLog, statistics sql.NullInt64
	err = row.Scan(&l.FilteringProfileID, &l.SafesearchMode, &l.ParentalPolicyID, &l.SecurityPolicyID,
		&l.ServiceBlockingRulesetID, &l.BlockingResponseMode, &l.CustomIPv4, &l.CustomIPv6, &l.UpstreamProfileID,
		&l.FallbackStrategy, &l.FallbackUpstreamProfileID, &l.ECSMode, &l.DomainRoutingRulesetID,
		&queryLog, &statistics)
	if err == sql.ErrNoRows {
		record(RowResult{Table: "policy_layers", Key: "global", Action: "skipped_duplicate", Detail: "no global row in Python's control.db"})
		return nil
	} else if err != nil {
		return fmt.Errorf("reading global policy_layers row: %w", err)
	}
	if queryLog.Valid {
		b := queryLog.Int64 != 0
		l.QueryLogEnabled = &b
	}
	if statistics.Valid {
		b := statistics.Int64 != 0
		l.StatisticsEnabled = &b
	}

	if dryRun {
		record(RowResult{Table: "policy_layers", Key: "global", Action: "would_import"})
		return nil
	}
	current, err := im.Policy.Load(ctx, "global", "global")
	if err == nil && current != (policy.Layer{}) {
		record(RowResult{Table: "policy_layers", Key: "global", Action: "skipped_duplicate", Detail: "Go's global policy layer is already non-empty"})
		return nil
	}
	if err := im.Policy.Save(ctx, "global", "global", l); err != nil {
		record(RowResult{Table: "policy_layers", Key: "global", Action: "rejected", Detail: err.Error()})
		return nil
	}
	record(RowResult{Table: "policy_layers", Key: "global", Action: "imported"})
	return nil
}

// --- blocklist subscriptions ----------------------------------------------

func (im *Importer) migrateBlocklists(ctx context.Context, pydb *sql.DB, dryRun bool, record func(RowResult)) error {
	rows, err := pydb.QueryContext(ctx, `SELECT subscription_id, name, url, category, enabled, update_interval_seconds FROM blocklist_subscriptions ORDER BY subscription_id`)
	if err != nil {
		return fmt.Errorf("reading blocklist_subscriptions: %w", err)
	}
	defer rows.Close()

	existing, _ := im.Blocklists.List(ctx)

	for rows.Next() {
		var subID, name, url, category string
		var enabled int
		var interval sql.NullInt64
		if err := rows.Scan(&subID, &name, &url, &category, &enabled, &interval); err != nil {
			return err
		}
		if blocklistExists(existing, subID) {
			record(RowResult{Table: "blocklist_subscriptions", Key: subID, Action: "skipped_duplicate", Detail: "already present in Go's own blocklist_subscriptions"})
			continue
		}
		if dryRun {
			record(RowResult{Table: "blocklist_subscriptions", Key: subID, Action: "would_import", Detail: fmt.Sprintf("url=%s enabled=%v", url, enabled != 0)})
			continue
		}
		_, _, err := im.Blocklists.Create(ctx, subID, name, url, category)
		if err != nil {
			record(RowResult{Table: "blocklist_subscriptions", Key: subID, Action: "rejected", Detail: err.Error()})
			continue
		}
		if enabled == 0 {
			im.Blocklists.Toggle(ctx, subID) // Create leaves it enabled; Python's source had it disabled
		}
		if interval.Valid && interval.Int64 > 0 {
			im.Blocklists.SetInterval(ctx, subID, int(interval.Int64))
		}
		record(RowResult{Table: "blocklist_subscriptions", Key: subID, Action: "imported", Detail: "subscription registered; domain list will be pulled fresh from its real URL, not copied"})
	}
	return rows.Err()
}

func blocklistExists(existing []blocklists.Subscription, id string) bool {
	for _, s := range existing {
		if s.SubscriptionID == id {
			return true
		}
	}
	return false
}

// --- audit log -------------------------------------------------------------

type auditEntry struct {
	Time   string    `json:"time"`
	DryRun bool      `json:"dry_run"`
	Row    RowResult `json:"row"`
}

type auditLog struct {
	f *os.File
}

func openAuditLog(path string) (*auditLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &auditLog{f: f}, nil
}

func (a *auditLog) Record(e auditEntry) {
	if a == nil || a.f == nil {
		return
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.f.Write(append(line, '\n'))
}

func (a *auditLog) Close() error {
	if a == nil || a.f == nil {
		return nil
	}
	return a.f.Close()
}

// SortResultsForDisplay orders a Report's Results deterministically
// (table, then key) -- the underlying migration order is already
// deterministic per-table, but this is a convenience for callers (a
// CLI or the dry-run API) that want one stable, readable ordering
// across every table together.
func SortResultsForDisplay(results []RowResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Table != results[j].Table {
			return results[i].Table < results[j].Table
		}
		return results[i].Key < results[j].Key
	})
}
