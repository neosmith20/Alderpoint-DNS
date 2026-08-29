// Command alderpointdns-go is the single native binary for the Go
// control-plane migration: one binary, subcommands for logically
// separate roles (currently "web" and "migrate"; Milestone 1 scope is
// the web control plane only -- see the migration report for the
// deferred worker roles: analytics, discovery, replication, schedule,
// tierb, protobuf-receiver).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/bootstrap"
	"alderpointdns/go-controlplane/internal/clientalias"
	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/config"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnsperf"
	"alderpointdns/go-controlplane/internal/dnsruntime"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/domainrouting"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/httpapi"
	"alderpointdns/go-controlplane/internal/importer"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/notifications"
	"alderpointdns/go-controlplane/internal/replication"
	"alderpointdns/go-controlplane/internal/dnsanalytics"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/pymigrate"
	"alderpointdns/go-controlplane/internal/secretstore"
	"alderpointdns/go-controlplane/internal/upstreams"
)

// Version is overridden at build time: -ldflags "-X main.Version=..."
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: alderpointdns-go <web|migrate> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "web":
		runWeb(os.Args[2:])
	case "migrate":
		runMigrate(os.Args[2:])
	case "import-python":
		runImportPython(os.Args[2:])
	case "dns-promote":
		runDNSPromote(os.Args[2:])
	case "blocklist-refresh":
		runBlocklistRefresh(os.Args[2:])
	case "version":
		// Plain stdout, nothing else -- Software Updates' staged-package
		// verification (internal/hostagentd's ops_update.go) execs a
		// staged candidate binary with exactly this subcommand to
		// confirm its self-reported version actually matches what the
		// caller claimed before ever trusting it as an update target.
		fmt.Println(Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q (want: web, migrate, import-python, dns-promote, blocklist-refresh, version)\n", os.Args[1])
		os.Exit(2)
	}
}

// runBlocklistRefresh is a one-shot, non-interactive trigger for
// exactly the same fetch -> validate -> compile -> promote pipeline the
// owner UI's "Refresh Now" action uses (internal/blocklists.Service.
// RefreshAll), built directly against the database. No HTTP server, no
// session, no login, no password, ever -- the same "named internal job"
// pattern as dns-promote, for the same reason: a scheduled/administrative
// refresh must never depend on a human's browser session. Waits
// synchronously for the job to finish (RefreshAll itself only enqueues
// and returns), then prints the FULL real per-subscription outcome
// array as JSON -- every success/failure, rule count, and error -- so a
// caller can never mistake "the job finished" for "every subscription
// succeeded." Wires OnJobComplete to the real DNS runtime promotion
// (Orchestrator.Apply, not a dry run) exactly like the "web" process
// does at startup, so a completed refresh reaches the live runtime
// atomically without this command ever touching :53 or :8443 itself --
// apdns-hostagent-live's own stage->validate->promote->reload->
// health-check->rollback pipeline does that, the same pipeline dns-
// promote already exercises. Exits non-zero if the job could not even
// be started, or if ANY subscription failed -- never silently reports a
// partial refresh as a full success.
func runBlocklistRefresh(args []string) {
	fs := flag.NewFlagSet("blocklist-refresh", flag.ExitOnError)
	dbPath := fs.String("db", "./data/alderpointdns-go.db", "sqlite database path (the exact live database)")
	cfgPath := fs.String("config", "./config/appliance.yaml", "appliance.yaml path -- read for blocklists.staging_dir/runtime_dir and pull_timeout_seconds/max_concurrent_pulls, the same source of truth the real 'web' process uses")
	migrationsDir := fs.String("migrations", "./schema/migrations", "migrations directory")
	hostagentSocket := fs.String("hostagent-socket", "", "unix socket path for apdns-hostagent (required -- used to promote the refreshed policy live)")
	dnsRuntimeDnsdistAddr := fs.String("dns-runtime-dnsdist-addr", "", "the real dnsdist listen address this deployment's apdns-hostagent was started with (required)")
	dnsRuntimeBindProxyAddr := fs.String("dns-runtime-bind-proxy-addr", "", "the real BIND PROXYv2 backend address this deployment's apdns-hostagent compiles named.conf to listen on (required)")
	dnstapSocketPath := fs.String("dns-runtime-dnstap-socket", "", "the path dnsdist itself will dial for real query-event logging (see internal/dnscompile's DnstapSocketPath); empty compiles no dnstap logging, matching this command's prior behavior exactly")
	timeoutSeconds := fs.Int("timeout-seconds", 300, "give up waiting for the refresh job to finish after this many seconds (the job itself keeps running server-side; this only bounds how long this command waits)")
	fs.Parse(args)

	if *hostagentSocket == "" || *dnsRuntimeDnsdistAddr == "" || *dnsRuntimeBindProxyAddr == "" {
		fmt.Fprintln(os.Stderr, "-hostagent-socket, -dns-runtime-dnsdist-addr, and -dns-runtime-bind-proxy-addr are all required")
		os.Exit(2)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx := context.Background()

	cfg, _, err := config.LoadOrMigrate(*cfgPath)
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	db, err := openDB(ctx, *dbPath, *migrationsDir, logger)
	if err != nil {
		logger.Error("db init failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	httpClient := &http.Client{Timeout: time.Duration(cfg.Blocklists.PullTimeoutSeconds) * time.Second}
	blSvc := &blocklists.Service{
		DB: db, HTTPClient: httpClient,
		StagingDir: cfg.Blocklists.StagingDir, RuntimeDir: cfg.Blocklists.RuntimeDir,
		MaxConcurrent: cfg.Blocklists.MaxConcurrentPulls, Log: logger,
	}

	orch := &dnsruntime.Orchestrator{
		LocalDNS:             &localdns.Service{DB: db},
		CustomRules:          &customrules.Service{DB: db},
		Blocklists:           blSvc,
		Upstreams:            &upstreams.Service{DB: db},
		DNSTransports:        &dnstransports.Service{DB: db},
		Policy:               &policy.Service{DB: db},
		DomainRouting:        &domainrouting.Service{DB: db},
		Clients:              &clients.Service{DB: db},
		HostAgent:            newPromoteHostAgentClient(*hostagentSocket),
		DnsdistListenAddress: *dnsRuntimeDnsdistAddr, BindBackendAddress: *dnsRuntimeBindProxyAddr,
		TLSCertPath: cfg.Web.TLSCertPath, TLSKeyPath: cfg.Web.TLSKeyPath,
		DnstapSocketPath: *dnstapSocketPath,
	}

	var promoteResult *dnsruntime.Result
	promoteDone := make(chan struct{})
	blSvc.OnJobComplete = func() {
		r := orch.Apply(context.Background())
		promoteResult = &r
		close(promoteDone)
	}

	jobID, count, err := blSvc.RefreshAll(ctx)
	if err != nil {
		logger.Error("could not start refresh", "err", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "refresh job %d started for %d enabled subscription(s)\n", jobID, count)

	deadline := time.Now().Add(time.Duration(*timeoutSeconds) * time.Second)
	var job *blocklists.Job
	for time.Now().Before(deadline) {
		job, err = blSvc.GetJob(ctx, jobID)
		if err != nil {
			logger.Error("polling job status failed", "err", err)
			os.Exit(1)
		}
		if job != nil && job.FinishedAt != nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if job == nil || job.FinishedAt == nil {
		fmt.Fprintf(os.Stderr, "refresh job %d did not finish within %ds -- it may still be running server-side\n", jobID, *timeoutSeconds)
		os.Exit(1)
	}

	// The job finishing fires OnJobComplete synchronously (runJob calls
	// it directly before returning), so promoteResult is already set by
	// the time GetJob observes finished_at -- but wait on the channel
	// too (bounded) rather than assume, in case of a future change to
	// that ordering.
	select {
	case <-promoteDone:
	case <-time.After(30 * time.Second):
		fmt.Fprintln(os.Stderr, "WARNING: refresh job finished but the DNS runtime promotion callback did not complete within 30s")
	}

	var outcomes []struct {
		SubscriptionID string `json:"subscription_id"`
		Status         string `json:"status"`
		RuleCount      int    `json:"rule_count,omitempty"`
		Error          string `json:"error,omitempty"`
		DurationMs     int    `json:"duration_ms"`
	}
	if err := json.Unmarshal(job.Results, &outcomes); err != nil {
		logger.Error("could not parse job results", "err", err)
		os.Exit(1)
	}

	report := map[string]any{
		"job_id":            job.ID,
		"subscriptions":     outcomes,
		"dns_runtime_apply": promoteResult,
	}
	body, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(body))

	failed := 0
	totalDomains := 0
	for _, o := range outcomes {
		if o.Status != "ok" {
			failed++
		} else {
			totalDomains += o.RuleCount
		}
	}
	fmt.Fprintf(os.Stderr, "\n--- summary: %d/%d subscriptions ok, %d failed, %d total domains ---\n", len(outcomes)-failed, len(outcomes), failed, totalDomains)

	ok := failed == 0 && promoteResult != nil && promoteResult.Attempted && promoteResult.Promoted
	if !ok {
		os.Exit(1)
	}
}

// runDNSPromote is a one-shot, non-interactive trigger for exactly the
// same compile -> validate -> promote pipeline the web UI's "Apply
// Runtime Changes" button uses (internal/dnsruntime.Orchestrator) --
// built directly against the database, with no HTTP server, no
// session, no login, no password, ever. This exists specifically so a
// live cutover can bring the DNS runtime up automatically: -dry-run
// (the default) only compiles and validates (named-checkconf, dnsdist
// --check-config) -- nothing live is touched, no socket is bound, safe
// to run while another process still owns the real DNS port. Passing
// -dry-run=false performs the real promotion (stages, validates, backs
// up, writes live, reloads, health-checks, and auto-rolls-back on any
// failure -- see internal/hostagentd/ops_dnsruntime.go) and must only
// be run once whatever currently owns the real DNS port has released
// it. Always prints the full Result as JSON to stdout; exits 0 only on
// real success (dry-run: Attempted && Error == ""; real: Promoted),
// non-zero otherwise -- a caller (scripts/v2/cutover.sh) can treat this
// exit code as the single source of truth without parsing JSON itself.
// newPromoteHostAgentClient is hostagent.NewClient with a real, observed
// timeout instead of the library default (10s). A real Apply through
// apdns-hostagent -- stage, validate, promote, reload, health-check --
// has been directly measured taking 10-13s, occasionally up to ~13.4s
// (see hostagent.log's own "operation completed" dur_ms). The default
// 10s client-side read timeout was shorter than that, so this CLI could
// print a false "hostagent unavailable: ... i/o timeout" for a call that
// completed successfully seconds later server-side -- a real bug (the
// CLI's own result must reflect the actual completed job, not require
// log archaeology), not a change to any query-hot-path timeout.
func newPromoteHostAgentClient(socketPath string) *hostagent.Client {
	c := hostagent.NewClient(socketPath)
	c.Timeout = 45 * time.Second
	return c
}

func runDNSPromote(args []string) {
	fs := flag.NewFlagSet("dns-promote", flag.ExitOnError)
	dbPath := fs.String("db", "./data/alderpointdns-go.db", "sqlite database path (the exact staged/live database -- opened read-only in effect, since this command never writes to it)")
	cfgPath := fs.String("config", "./config/appliance.yaml", "appliance.yaml path -- read for blocklists.runtime_dir and web.tls_cert_path/tls_key_path, the same source of truth the real 'web' process uses, so this one-shot command can never disagree with it")
	migrationsDir := fs.String("migrations", "./schema/migrations", "migrations directory")
	hostagentSocket := fs.String("hostagent-socket", "", "unix socket path for apdns-hostagent (required)")
	dnsRuntimeDnsdistAddr := fs.String("dns-runtime-dnsdist-addr", "", "the real dnsdist listen address this deployment's apdns-hostagent was started with (required)")
	dnsRuntimeBindProxyAddr := fs.String("dns-runtime-bind-proxy-addr", "", "the real BIND PROXYv2 backend address this deployment's apdns-hostagent compiles named.conf to listen on (required)")
	dnstapSocketPath := fs.String("dns-runtime-dnstap-socket", "", "the path dnsdist itself will dial for real query-event logging (see internal/dnscompile's DnstapSocketPath, and the 'web' subcommand's own two-flag doc comment for why this is a HOST path, distinct from wherever the 'web' process itself listens); empty compiles no dnstap logging at all, matching this command's prior behavior exactly")
	dryRun := fs.Bool("dry-run", true, "compile and validate only, no live change (default true -- pass -dry-run=false to actually promote for real)")
	fs.Parse(args)

	if *hostagentSocket == "" || *dnsRuntimeDnsdistAddr == "" || *dnsRuntimeBindProxyAddr == "" {
		fmt.Fprintln(os.Stderr, "-hostagent-socket, -dns-runtime-dnsdist-addr, and -dns-runtime-bind-proxy-addr are all required")
		os.Exit(2)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx := context.Background()

	cfg, _, err := config.LoadOrMigrate(*cfgPath)
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	db, err := openDB(ctx, *dbPath, *migrationsDir, logger)
	if err != nil {
		logger.Error("db init failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	orch := &dnsruntime.Orchestrator{
		LocalDNS:             &localdns.Service{DB: db},
		CustomRules:          &customrules.Service{DB: db},
		Blocklists:           &blocklists.Service{DB: db, RuntimeDir: cfg.Blocklists.RuntimeDir},
		Upstreams:            &upstreams.Service{DB: db},
		DNSTransports:        &dnstransports.Service{DB: db},
		Policy:               &policy.Service{DB: db},
		DomainRouting:        &domainrouting.Service{DB: db},
		Clients:              &clients.Service{DB: db},
		HostAgent:            newPromoteHostAgentClient(*hostagentSocket),
		DnsdistListenAddress: *dnsRuntimeDnsdistAddr, BindBackendAddress: *dnsRuntimeBindProxyAddr,
		TLSCertPath: cfg.Web.TLSCertPath, TLSKeyPath: cfg.Web.TLSKeyPath,
		DnstapSocketPath: *dnstapSocketPath,
	}

	var result dnsruntime.Result
	if *dryRun {
		result = orch.Validate(ctx)
	} else {
		result = orch.Apply(ctx)
	}

	body, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(body))

	ok := result.Attempted && result.Error == "" && (*dryRun || result.Promoted)
	if !ok {
		os.Exit(1)
	}
}

// runImportPython is the CLI entry point for internal/pymigrate -- the
// audited, one-time import from Python's real control.db into this
// control plane's own native schema. See that package's own doc
// comment for exactly what is and isn't migrated. Always prints the
// full report as JSON to stdout (for scripting/audit) and a short
// human summary to stderr.
func runImportPython(args []string) {
	fs := flag.NewFlagSet("import-python", flag.ExitOnError)
	dbPath := fs.String("db", "./data/alderpointdns-go.db", "this control plane's own sqlite database path")
	migrationsDir := fs.String("migrations", "./schema/migrations", "migrations directory")
	pythonControlDB := fs.String("python-control-db", "", "path to Python's real control.db (read-only; required)")
	dryRun := fs.Bool("dry-run", true, "report what would be imported without writing anything (default true -- pass -dry-run=false to actually import)")
	auditLogPath := fs.String("audit-log", "./data/import-python-audit.jsonl", "append-only JSON-lines audit log path")
	blocklistsStagingDir := fs.String("blocklists-staging-dir", "./data/blocklists/staging", "")
	blocklistsRuntimeDir := fs.String("blocklists-runtime-dir", "./data/blocklists/runtime", "")
	localDNSStagingDir := fs.String("local-dns-staging-dir", "./data/local-dns/staging", "")
	localDNSRuntimeDir := fs.String("local-dns-runtime-dir", "./data/local-dns/runtime", "")
	backupsDir := fs.String("backups-dir", "./data/backups", "directory for the pre-migration snapshot (real, restorable via the Backup & Restore page too)")
	rollbackFilename := fs.String("rollback", "", "instead of importing, roll back to this previously-taken snapshot filename and exit")
	fs.Parse(args)

	if *pythonControlDB == "" && *rollbackFilename == "" {
		fmt.Fprintln(os.Stderr, "-python-control-db is required (unless -rollback is given)")
		os.Exit(2)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx := context.Background()

	db, err := openDB(ctx, *dbPath, *migrationsDir, logger)
	if err != nil {
		logger.Error("db init failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	im := &pymigrate.Importer{
		PythonControlDBPath: *pythonControlDB,
		LocalDNS:            &localdns.Service{DB: db, StagingDir: *localDNSStagingDir, RuntimeDir: *localDNSRuntimeDir},
		Upstreams:           &upstreams.Service{DB: db},
		DNSTransports:       &dnstransports.Service{DB: db},
		Policy:              &policy.Service{DB: db},
		Blocklists:          &blocklists.Service{DB: db, HTTPClient: http.DefaultClient, StagingDir: *blocklistsStagingDir, RuntimeDir: *blocklistsRuntimeDir, MaxConcurrent: 3, Log: logger},
		Backup:              &backup.Service{DB: db, Dir: *backupsDir, Version: Version},
		AuditLogPath:        *auditLogPath,
	}

	if *rollbackFilename != "" {
		safety, err := im.Rollback(ctx, *rollbackFilename)
		if err != nil {
			logger.Error("rollback failed", "err", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "rolled back to %q -- a safety backup of the pre-rollback state was taken: %s\n", *rollbackFilename, safety.Filename)
		return
	}

	report, err := im.Run(ctx, *dryRun)
	if err != nil {
		logger.Error("import failed", "err", err)
		os.Exit(1)
	}
	pymigrate.SortResultsForDisplay(report.Results)
	body, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(body))

	fmt.Fprintf(os.Stderr, "\n--- %s summary ---\n", map[bool]string{true: "DRY RUN (nothing written)", false: "REAL IMPORT"}[*dryRun])
	for _, table := range []string{"local_dns_records", "upstream_profiles", "dns_transport_settings", "policy_layers", "blocklist_subscriptions"} {
		s := report.Tables[table]
		fmt.Fprintf(os.Stderr, "%-24s source=%-4d imported=%-4d skipped=%-4d rejected=%d\n", table, s.SourceCount, s.Imported, s.Skipped, s.Rejected)
	}
	if !*dryRun {
		fmt.Fprintf(os.Stderr, "\npre-migration snapshot: %s\n", report.SnapshotFilename)
		fmt.Fprintf(os.Stderr, "to roll back: alderpointdns-go import-python -db %s -rollback %s\n", *dbPath, report.SnapshotFilename)
	}
}

// dbFileMode/dbDirMode are the least-privilege permissions app.db (and
// its containing directory) actually need for the real deployed
// posture: only this process's own UID ever opens this file (no other
// service on the appliance shares its group), so even group-read is
// tighter than strictly required -- but 0640/0750 is the same
// convention internal/backup already uses for backup archives, and
// removes the world-readable bit the database previously had (0644),
// which was wider than needed even though today's actual exposure was
// moot (the parent directory was already 0700-equivalent via the
// container bind mount). See PARITY_MATRIX.md's database-at-rest audit.
const (
	dbFileMode = 0o640
	dbDirMode  = 0o750
)

func openDB(ctx context.Context, dbPath, migrationsDir string, logger *slog.Logger) (*sql.DB, error) {
	dir := parentDir(dbPath)
	if dir != "" {
		if err := os.MkdirAll(dir, dbDirMode); err != nil {
			return nil, err
		}
		if err := os.Chmod(dir, dbDirMode); err != nil {
			logger.Warn("could not tighten database directory permissions", "dir", dir, "err", err)
		}
	}
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single-writer SQLite; simplest correct answer for this scale
	if _, err := dbmigrate.Up(ctx, db, migrationsDir); err != nil {
		return nil, fmt.Errorf("startup migration failed: %w", err)
	}
	// Tighten the real database file (and its WAL/SHM siblings, which
	// carry real row data in WAL mode) AFTER open+migrate actually
	// created it -- sql.Open's file creation follows the process umask,
	// which on a real deployed container is not guaranteed to already
	// be this strict. Best-effort: a chmod failure here is logged, not
	// fatal -- a running appliance must never refuse to start over a
	// permission-tightening step that isn't itself a security hole.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chmod(dbPath+suffix, dbFileMode); err != nil && !os.IsNotExist(err) {
			logger.Warn("could not tighten database file permissions", "path", dbPath+suffix, "err", err)
		}
	}
	return db, nil
}

func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return ""
}

func runMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	dbPath := fs.String("db", "./data/alderpointdns-go.db", "sqlite database path")
	migrationsDir := fs.String("migrations", "./schema/migrations", "migrations directory")
	cmd := fs.String("cmd", "up", "up|status")
	fs.Parse(args)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx := context.Background()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		logger.Error("open db", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	switch *cmd {
	case "status":
		v, err := dbmigrate.CurrentVersion(ctx, db)
		if err != nil {
			logger.Error("status", "err", err)
			os.Exit(1)
		}
		fmt.Println("schema_version:", v)
	case "up":
		v, err := dbmigrate.Up(ctx, db, *migrationsDir)
		if err != nil {
			logger.Error("migrate up failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("migrated to:", v)
	default:
		fmt.Fprintf(os.Stderr, "unknown -cmd %q (want: up, status)\n", *cmd)
		os.Exit(2)
	}
}

func runWeb(args []string) {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	dbPath := fs.String("db", "./data/alderpointdns-go.db", "sqlite database path")
	cfgPath := fs.String("config", "./config/appliance.yaml", "appliance.yaml path")
	staticDir := fs.String("static", "./frontend/dist", "compiled frontend dist dir")
	migrationsDir := fs.String("migrations", "./schema/migrations", "migrations directory")
	addr := fs.String("addr", "", "listen address override (host:port); defaults to config web.listen_address:listen_port")
	analyticsDBPath := fs.String("analytics-db", "", "REQUIRED: path to the Go-native analytics database (see internal/dnsanalytics) -- this process both writes and reads it; there is no longer a separate Python writer to bridge to (see CUTOVER.md). Startup fails clearly if this is empty; DNS answering itself is unaffected either way, since named/dnsdist/apdns-hostagent are separate OS processes.")
	// Two distinct flags, deliberately not one, because dnsdist (a real
	// dnsdist Lua config value, dialed by dnsdist itself -- a separate
	// host process, possibly in a separate mount namespace from this
	// "web" process, e.g. the live container) and this process (which
	// must bind/listen on that same underlying file from its OWN
	// filesystem view) can each need a different path to the same
	// bind-mounted socket file -- exactly the same reason -hostagent-
	// socket's container path and apdns-hostagent's own -socket host
	// path are already two separately-configured values elsewhere in
	// this deployment, not one shared flag.
	dnstapDialPath := fs.String("dns-runtime-dnstap-socket", "", "the path dnsdist itself will dial to reach this process's dnstap listener -- compiled verbatim into dnsdist.conf (see internal/dnscompile's DnstapSocketPath). On a real container deployment this is the HOST-side path of the bind mount; see -dns-runtime-dnstap-listen-socket for this process's own (possibly container-internal) bind path to the same file.")
	dnstapListenPath := fs.String("dns-runtime-dnstap-listen-socket", "", "the path THIS process binds/listens on for dnsdist's real dnstap stream (see internal/dnsanalytics.Writer). Defaults to -dns-runtime-dnstap-socket's value when empty -- the common case where this process and dnsdist share one filesystem namespace (no container boundary between them). Required together with -analytics-db whenever a DNS runtime (-hostagent-socket + -dns-runtime-dnsdist-addr + -dns-runtime-bind-proxy-addr) is also configured -- otherwise there would be a durable analytics store with nothing ever feeding it real traffic.")
	backupsDir := fs.String("backups-dir", "./data/backups", "directory for stored/uploaded appliance backups (see internal/backup)")
	bootstrapTokenPath := fs.String("bootstrap-token-path", "./data/bootstrap-token", "where the one-time first-run setup token is written (0600); also logged once at startup when setup is required -- see internal/bootstrap")
	backupRetentionMaxCount := fs.Int("backup-retention-max-count", 0, "keep at most N manual backups, oldest pruned first (0 = unlimited; the pre-restore safety backup is never pruned)")
	backupRetentionMaxAgeDays := fs.Int("backup-retention-max-age-days", 0, "prune manual backups older than N days (0 = unlimited)")
	hostagentSocket := fs.String("hostagent-socket", "", "unix socket path for apdns-hostagent (see internal/hostagent, internal/hostagentd); empty = Cache/Replication/Network/Logs/Software-Updates all report unavailable")
	dnsRuntimeDnsdistAddr := fs.String("dns-runtime-dnsdist-addr", "", "the real dnsdist listen address apdns-hostagent was started with for this deployment (see internal/dnscompile, internal/dnsruntime); empty = DNS Runtime compilation is unavailable, matching -hostagent-socket's own contract")
	dnsRuntimeBindProxyAddr := fs.String("dns-runtime-bind-proxy-addr", "", "the real BIND PROXYv2 backend address apdns-hostagent compiles named.conf to listen on (127.0.0.1:<bind-proxy-port>); required together with -dns-runtime-dnsdist-addr")
	dnsPerfBindPlainAddr := fs.String("dns-perf-bind-plain-addr", "", "BIND's own unproxied loopback listener address for this deployment (127.0.0.1:<bind-plain-port>), for System Status's Safe DNS Benchmark's 'BIND direct' case display only -- the real dialing happens entirely inside apdns-hostagent; empty = that one case is omitted")
	dnsPerfReportPath := fs.String("dns-perf-report-path", "./data/dns-performance/latest-report.json", "path to persist the Safe DNS Benchmark's latest report (see internal/dnsperf)")
	replicationCertDir := fs.String("replication-cert-dir", "./data/replication/certs", "directory for this node's own real replication mTLS certificate material (server cert/key as primary, or client cert/key/CA cert as an enrolled replica) -- see internal/replication; only CA generation/signing needs -hostagent-socket, the listener/poller themselves need no privilege")
	fs.Parse(args)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	startedAt := time.Now()
	ctx := context.Background()

	cfg, migrated, err := config.LoadOrMigrate(*cfgPath)
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}
	if migrated {
		logger.Info("config migrated to current schema_version", "path", *cfgPath)
	}

	db, err := openDB(ctx, *dbPath, *migrationsDir, logger)
	if err != nil {
		logger.Error("db init failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	httpClient := &http.Client{Timeout: time.Duration(cfg.Blocklists.PullTimeoutSeconds) * time.Second}

	blSvc := &blocklists.Service{
		DB: db, HTTPClient: httpClient,
		StagingDir: cfg.Blocklists.StagingDir, RuntimeDir: cfg.Blocklists.RuntimeDir,
		MaxConcurrent: cfg.Blocklists.MaxConcurrentPulls, Log: logger,
	}
	ldSvc := &localdns.Service{DB: db, StagingDir: cfg.LocalDNS.StagingDir, RuntimeDir: cfg.LocalDNS.RuntimeDir}
	clientAliasSvc := &clientalias.Service{DB: db}
	upSvc := &upstreams.Service{DB: db}
	domainRoutingSvc := &domainrouting.Service{DB: db}
	clientsSvc := &clients.Service{DB: db}
	policySvc := &policy.Service{DB: db}
	customRulesSvc := &customrules.Service{DB: db}
	dnsTransportsSvc := &dnstransports.Service{DB: db}
	notificationsSvc := &notifications.Service{DB: db}
	replicationSvc := &replication.Service{DB: db, CertDir: *replicationCertDir, Log: logger}
	backupSvc := &backup.Service{
		DB: db, Dir: *backupsDir, Version: Version,
		RetentionMaxCount: *backupRetentionMaxCount, RetentionMaxAgeDays: *backupRetentionMaxAgeDays,
	}
	importerSvc := &importer.Service{DB: db, LocalDNS: ldSvc, Backup: backupSvc}

	// Host-agent client: same "optional, never fatal" contract. No
	// connection is opened at startup -- hostagent.Client dials fresh
	// per call, so an agent that isn't running yet (or ever) never
	// blocks this process from starting; every hostagent-backed handler
	// already treats a dial failure as "unavailable", not an error.
	// Created here (rather than immediately before its other uses
	// below) so the analytics Writer's TrafficProbe -- see immediately
	// below -- can be wired in before Run starts, not raced against it.
	var hostAgentClient *hostagent.Client
	if *hostagentSocket != "" {
		hostAgentClient = hostagent.NewClient(*hostagentSocket)
	}

	// Go-native analytics: REQUIRED, unlike every other optional
	// boundary in this function -- the owner's explicit standing
	// requirement is that missing required analytics configuration
	// fails startup clearly rather than run degraded indefinitely.
	// Strict here is safe precisely because it's scoped to this one
	// process: named/dnsdist/apdns-hostagent are separate OS processes
	// this exiting never touches, so "DNS must never depend on
	// analytics" and "analytics config must fail loudly if broken" are
	// both true at once, not in tension.
	if *analyticsDBPath == "" {
		logger.Error("-analytics-db is required (see internal/dnsanalytics; Python's analytics bridge was removed at cutover, see CUTOVER.md)")
		os.Exit(1)
	}
	analyticsDB, err := dnsanalytics.Open(*analyticsDBPath)
	if err != nil {
		logger.Error("analytics db preflight failed", "path", *analyticsDBPath, "err", err)
		os.Exit(1)
	}
	defer analyticsDB.Close()
	analyticsWriter := &dnsanalytics.Writer{DB: analyticsDB, Log: logger}
	if hostAgentClient != nil {
		// Real, independent-of-dnstap traffic signal for the stall
		// watchdog (see dnsanalytics.TrafficProbe's doc comment): reuse
		// the exact same cache.status RPC handleCacheStatus already
		// exposes at /api/cache/status (internal/hostagentd's
		// fetchBindCacheStats reading BIND's own statistics-channel),
		// summing hits+misses across every BIND context as one
		// monotonic "real queries reached the backend" counter. This
		// never touches dnsdist/dnstap, which is exactly why it can
		// tell a real stall apart from a quiet network.
		analyticsWriter.TrafficProbe = func(ctx context.Context) (int64, bool) {
			var out struct {
				Bind []struct {
					CacheStats *struct {
						Available bool  `json:"available"`
						Hits      int64 `json:"hits"`
						Misses    int64 `json:"misses"`
					} `json:"cache_stats"`
				} `json:"bind"`
			}
			if err := hostAgentClient.Call(ctx, hostagent.OpCacheStatus, nil, &out); err != nil {
				return 0, false
			}
			var total int64
			anyAvailable := false
			for _, c := range out.Bind {
				if c.CacheStats != nil && c.CacheStats.Available {
					anyAvailable = true
					total += c.CacheStats.Hits + c.CacheStats.Misses
				}
			}
			return total, anyAvailable
		}
	}
	analyticsReader := &dnsanalytics.Reader{DB: analyticsDB, Writer: analyticsWriter}
	listenPath := *dnstapListenPath
	if listenPath == "" {
		listenPath = *dnstapDialPath
	}
	if listenPath != "" {
		dnstapCtx, cancelDnstap := context.WithCancel(context.Background())
		defer cancelDnstap()
		go func() {
			if err := analyticsWriter.Run(dnstapCtx, listenPath); err != nil {
				logger.Error("dnstap listener exited (analytics will report degraded; DNS answering is unaffected)", "socket", listenPath, "err", err)
			}
		}()
	} else {
		logger.Warn("-dns-runtime-dnstap-socket / -dns-runtime-dnstap-listen-socket are empty: analytics db is open but nothing will ever write real query events to it")
	}

	// Native Go secrets subsystem: same "optional, never fatal"
	// contract as every other host-agent-backed boundary. See
	// internal/secretstore's doc comment -- this process only ever
	// holds ciphertext; the master key lives solely in apdns-hostagent.
	secretsSvc := &secretstore.Service{DB: db, HostAgent: hostAgentClient}
	notificationsSvc.Secrets = secretsSvc
	replicationSvc.HostAgent = hostAgentClient
	if hostAgentClient == nil {
		logger.Info("secrets subsystem not wired: -hostagent-socket is empty; provider secrets (Notifications) will report unavailable")
		logger.Info("replication CA generation/signing not wired: -hostagent-socket is empty; Replication will report unavailable as soon as a CA operation is attempted")
	}

	// Real dispatch call site #1: a blocklist subscription crossing the
	// AttentionThreshold is a real, owner-actionable incident -- see
	// blocklists.Service.OnAttentionRequired's own doc comment for why
	// this fires exactly once per incident, not once per failed pull.
	blSvc.OnAttentionRequired = func(ctx context.Context, subscriptionID string, failureCount int, lastError string) {
		summary := fmt.Sprintf("blocklist subscription %q failed %d consecutive times: %s", subscriptionID, failureCount, lastError)
		notificationsSvc.Dispatch(ctx, "blocklist_update_failure", "warning", "blocklists", summary, false)
	}

	// DNS runtime compiler: same "optional, never fatal" contract as
	// every other boundary above. Requires both a host-agent AND the
	// dnsdist/BIND deployment addresses that agent was configured with
	// -- see internal/dnsruntime's doc comment for why the two sides
	// must agree on these fixed values.
	var dnsRuntimeOrch *dnsruntime.Orchestrator
	if hostAgentClient != nil && *dnsRuntimeDnsdistAddr != "" && *dnsRuntimeBindProxyAddr != "" {
		dnsRuntimeOrch = &dnsruntime.Orchestrator{
			LocalDNS: ldSvc, CustomRules: customRulesSvc, Blocklists: blSvc, Upstreams: upSvc, DNSTransports: dnsTransportsSvc, Policy: policySvc,
			DomainRouting: domainRoutingSvc, Clients: clientsSvc,
			HostAgent: hostAgentClient, DnsdistListenAddress: *dnsRuntimeDnsdistAddr, BindBackendAddress: *dnsRuntimeBindProxyAddr,
			TLSCertPath: cfg.Web.TLSCertPath, TLSKeyPath: cfg.Web.TLSKeyPath,
			DnstapSocketPath: *dnstapDialPath,
		}
		if *dnstapDialPath == "" {
			logger.Warn("DNS runtime is configured but -dns-runtime-dnstap-socket is empty: the compiled dnsdist config will not log any real query events")
		}
	} else if *dnsRuntimeDnsdistAddr != "" || *dnsRuntimeBindProxyAddr != "" {
		logger.Warn("DNS runtime compiler not wired: -dns-runtime-dnsdist-addr, -dns-runtime-bind-proxy-addr, and -hostagent-socket must all be set together")
	}
	if dnsRuntimeOrch != nil {
		// A completed blocklist pull job is the moment a subscription's
		// domain list may have actually changed -- unlike its own HTTP
		// handler, which returns before the background pull finishes.
		// Applying here (not from the handler) is what makes Blocklists
		// consistent with every other DNS-runtime-affecting mutation:
		// auto-applies once the change is actually real, never a
		// separate manual step a caller has to remember.
		blSvc.OnJobComplete = func() {
			res := dnsRuntimeOrch.Apply(context.Background())
			if res.Attempted && !res.Promoted {
				logger.Warn("DNS runtime apply after blocklist refresh did not promote", "rolled_back", res.RolledBack, "stage", res.Stage, "detail", res.Detail, "error", res.Error)
			}
		}
	}

	authStore := &auth.Store{DB: db}
	setupRequired, err := authStore.SetupRequired(ctx)
	if err != nil {
		logger.Error("checking setup status for bootstrap init", "err", err)
		os.Exit(1)
	}
	bootstrapMgr := &bootstrap.Manager{TokenPath: *bootstrapTokenPath, Log: logger}
	if err := bootstrapMgr.Init(setupRequired); err != nil {
		logger.Error("bootstrap init failed", "err", err)
		os.Exit(1)
	}

	srv := &httpapi.Server{
		DB: db, Auth: authStore, Bootstrap: bootstrapMgr, Blocklists: blSvc, LocalDNS: ldSvc, ClientAliases: clientAliasSvc, Upstreams: upSvc, DomainRouting: domainRoutingSvc, Clients: clientsSvc, Policy: policySvc, CustomRules: customRulesSvc, Backup: backupSvc,
		DNSTransports: dnsTransportsSvc, Notifications: notificationsSvc, Importer: importerSvc,
		StaticDir: *staticDir, Log: logger, Version: Version, StartedAt: startedAt,
		SessionTTL: cfg.SessionTTL(), LastSeen: cfg.LastSeenUpdateInterval(),
		ApplianceName: cfg.Appliance.Name, ApplianceTimezone: cfg.Appliance.Timezone,
		Analytics: analyticsReader, RawQueryLog: analyticsReader, HostAgent: hostAgentClient,
		DNSRuntime: dnsRuntimeOrch, TLSCertPath: cfg.Web.TLSCertPath, TLSKeyPath: cfg.Web.TLSKeyPath,
		DNSPerfBindPlainAddr: *dnsPerfBindPlainAddr,
		Secrets:              secretsSvc,
		Replication:          replicationSvc,
	}

	// DNS Performance benchmark: same "optional, never fatal" contract
	// as DNS Runtime above -- needs both a configured DNS runtime (to
	// know the real dnsdist address to build cases against) and a
	// reachable host-control agent (to actually run them).
	if dnsRuntimeOrch != nil && hostAgentClient != nil {
		srv.DNSPerf = &dnsperf.Service{
			ReportPath: *dnsPerfReportPath,
			Querier:    dnsperf.HostAgentQuerier{Client: hostAgentClient},
			BuildCases: srv.BuildDNSPerfCases,
		}
	} else {
		logger.Info("DNS performance benchmark not wired: needs both DNS runtime and -hostagent-socket configured")
	}

	listenAddr := *addr
	if listenAddr == "" {
		listenAddr = fmt.Sprintf("%s:%d", cfg.Web.ListenAddress, cfg.Web.ListenPort)
	}

	schedulerCtx, cancelScheduler := context.WithCancel(context.Background())
	go blSvc.RunScheduler(schedulerCtx, time.Duration(cfg.Blocklists.SchedulerTickSeconds)*time.Second)

	// Real dispatch call site #3: the tls_cert_expiring health-check
	// category, closing one of the five disclosed-but-unwired
	// notification categories -- see internal/notifications/tlscheck.go.
	// A daily tick is plenty for a warning window measured in days; the
	// per-subscription cooldown (internal/notifications' own Dispatch)
	// still applies on top of it.
	notificationsSvc.Log = logger
	go notificationsSvc.RunTLSExpiryScheduler(schedulerCtx, cfg.Web.TLSCertPath, notifications.DefaultTLSExpiryWarnDays, 24*time.Hour)

	// Real DNS-runtime recompilation after a successful replica apply --
	// see internal/replication.SyncOnce's own doc comment for why this
	// hook is injected here rather than internal/replication importing
	// internal/dnsruntime directly. Nil-safe: if this deployment has no
	// DNS runtime configured (dnsRuntimeOrch nil), a replica sync still
	// applies at the database level, just without a live reload attempt.
	if dnsRuntimeOrch != nil {
		replicationSvc.DeployFn = func(ctx context.Context) (bool, string) {
			result := dnsRuntimeOrch.Apply(ctx)
			if !result.Attempted {
				return true, "no DNS runtime configured for this deployment"
			}
			if result.RolledBack || result.Error != "" {
				return false, fmt.Sprintf("stage=%s detail=%s error=%s", result.Stage, result.Detail, result.Error)
			}
			return true, "promoted"
		}
	}
	// Re-establish whichever role was previously configured on every
	// process restart, without any admin action -- matches Python's own
	// autostart() exactly. Never fatal: a role that can't actually start
	// (e.g. a primary whose CA/cert issuance needs -hostagent-socket,
	// which isn't configured in this deployment) is surfaced the next
	// time an owner takes an explicit action on the Replication page,
	// not at boot.
	if replicationSettings, err := replicationSvc.GetSettings(context.Background()); err == nil {
		switch replicationSettings.Role {
		case "primary":
			if err := replicationSvc.EnsurePrimaryListenerRunning(context.Background()); err != nil {
				logger.Warn("replication: primary listener did not start at boot", "err", err)
			}
		case "replica":
			replicationSvc.StartPoller(schedulerCtx)
		}
	}

	httpSrv := &http.Server{Addr: listenAddr, Handler: srv.Routes()}

	if cfg.Web.TLSCertPath != "" && cfg.Web.TLSKeyPath != "" {
		go func() {
			logger.Info("ready", "addr", listenAddr, "tls", true, "elapsed_ms", time.Since(startedAt).Milliseconds())
			if err := httpSrv.ListenAndServeTLS(cfg.Web.TLSCertPath, cfg.Web.TLSKeyPath); err != nil && err != http.ErrServerClosed {
				logger.Error("listen failed", "err", err)
				os.Exit(1)
			}
		}()
	} else {
		go func() {
			logger.Info("ready", "addr", listenAddr, "tls", false, "elapsed_ms", time.Since(startedAt).Milliseconds())
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("listen failed", "err", err)
				os.Exit(1)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	shutdownStart := time.Now()
	cancelScheduler()
	replicationSvc.StopPrimaryListener()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)
	logger.Info("shutdown complete", "elapsed_ms", time.Since(shutdownStart).Milliseconds())
}
