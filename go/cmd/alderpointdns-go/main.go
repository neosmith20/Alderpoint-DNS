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
	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/config"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnsruntime"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/httpapi"
	"alderpointdns/go-controlplane/internal/importer"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/notifications"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/pyanalytics"
	"alderpointdns/go-controlplane/internal/pymigrate"
	"alderpointdns/go-controlplane/internal/rawquerylog"
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
	case "version":
		// Plain stdout, nothing else -- Software Updates' staged-package
		// verification (internal/hostagentd's ops_update.go) execs a
		// staged candidate binary with exactly this subcommand to
		// confirm its self-reported version actually matches what the
		// caller claimed before ever trusting it as an update target.
		fmt.Println(Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q (want: web, migrate, import-python, version)\n", os.Args[1])
		os.Exit(2)
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

func openDB(ctx context.Context, dbPath, migrationsDir string, logger *slog.Logger) (*sql.DB, error) {
	if dir := parentDir(dbPath); dir != "" {
		os.MkdirAll(dir, 0o755)
	}
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single-writer SQLite; simplest correct answer for this scale
	if _, err := dbmigrate.Up(ctx, db, migrationsDir); err != nil {
		return nil, fmt.Errorf("startup migration failed: %w", err)
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
	analyticsDBPath := fs.String("analytics-db", "", "optional read-only path to Python's analytics/aggregates.db (compatibility boundary, see internal/pyanalytics); empty = Dashboard analytics reports degraded")
	queryLogDir := fs.String("query-log-dir", "", "optional read-only path to Python's analytics/queries/ raw Parquet history (compatibility boundary, see internal/rawquerylog); empty = Query Log reports degraded")
	backupsDir := fs.String("backups-dir", "./data/backups", "directory for stored/uploaded appliance backups (see internal/backup)")
	backupRetentionMaxCount := fs.Int("backup-retention-max-count", 0, "keep at most N manual backups, oldest pruned first (0 = unlimited; the pre-restore safety backup is never pruned)")
	backupRetentionMaxAgeDays := fs.Int("backup-retention-max-age-days", 0, "prune manual backups older than N days (0 = unlimited)")
	hostagentSocket := fs.String("hostagent-socket", "", "unix socket path for apdns-hostagent (see internal/hostagent, internal/hostagentd); empty = Cache/Replication/Network/Logs/Software-Updates all report unavailable")
	dnsRuntimeDnsdistAddr := fs.String("dns-runtime-dnsdist-addr", "", "the real dnsdist listen address apdns-hostagent was started with for this deployment (see internal/dnscompile, internal/dnsruntime); empty = DNS Runtime compilation is unavailable, matching -hostagent-socket's own contract")
	dnsRuntimeBindProxyAddr := fs.String("dns-runtime-bind-proxy-addr", "", "the real BIND PROXYv2 backend address apdns-hostagent compiles named.conf to listen on (127.0.0.1:<bind-proxy-port>); required together with -dns-runtime-dnsdist-addr")
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
	upSvc := &upstreams.Service{DB: db}
	clientsSvc := &clients.Service{DB: db}
	policySvc := &policy.Service{DB: db}
	customRulesSvc := &customrules.Service{DB: db}
	dnsTransportsSvc := &dnstransports.Service{DB: db}
	notificationsSvc := &notifications.Service{DB: db}
	backupSvc := &backup.Service{
		DB: db, Dir: *backupsDir, Version: Version,
		RetentionMaxCount: *backupRetentionMaxCount, RetentionMaxAgeDays: *backupRetentionMaxAgeDays,
	}
	importerSvc := &importer.Service{DB: db, LocalDNS: ldSvc, Backup: backupSvc}

	// Analytics compatibility boundary: optional, never fatal. A missing
	// or unreadable path means Dashboard analytics reports degraded, not
	// a startup crash -- "DNS works if analytics is dead" applies to this
	// control plane's own dashboard too.
	var analyticsReader *pyanalytics.Reader
	if *analyticsDBPath != "" {
		reader, err := pyanalytics.Open(*analyticsDBPath)
		if err != nil {
			logger.Warn("analytics reader unavailable at startup; dashboard analytics will report degraded", "path", *analyticsDBPath, "err", err)
		} else {
			analyticsReader = reader
			defer reader.Close()
		}
	}

	// Raw query-log compatibility boundary: same "optional, never fatal"
	// contract as Analytics above. No Open()/connection step needed --
	// internal/rawquerylog.Reader is a stateless directory-path wrapper
	// that tolerates a not-yet-existing root (nothing ingested there yet)
	// the same way it tolerates one that exists.
	var rawQueryLogReader *rawquerylog.Reader
	if *queryLogDir != "" {
		rawQueryLogReader = &rawquerylog.Reader{Root: *queryLogDir}
	}

	// Host-agent client: same "optional, never fatal" contract. No
	// connection is opened at startup -- hostagent.Client dials fresh
	// per call, so an agent that isn't running yet (or ever) never
	// blocks this process from starting; every hostagent-backed handler
	// already treats a dial failure as "unavailable", not an error.
	var hostAgentClient *hostagent.Client
	if *hostagentSocket != "" {
		hostAgentClient = hostagent.NewClient(*hostagentSocket)
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
			HostAgent: hostAgentClient, DnsdistListenAddress: *dnsRuntimeDnsdistAddr, BindBackendAddress: *dnsRuntimeBindProxyAddr,
			TLSCertPath: cfg.Web.TLSCertPath, TLSKeyPath: cfg.Web.TLSKeyPath,
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

	srv := &httpapi.Server{
		DB: db, Auth: &auth.Store{DB: db}, Blocklists: blSvc, LocalDNS: ldSvc, Upstreams: upSvc, Clients: clientsSvc, Policy: policySvc, CustomRules: customRulesSvc, Backup: backupSvc,
		DNSTransports: dnsTransportsSvc, Notifications: notificationsSvc, Importer: importerSvc,
		StaticDir: *staticDir, Log: logger, Version: Version, StartedAt: startedAt,
		SessionTTL: cfg.SessionTTL(), LastSeen: cfg.LastSeenUpdateInterval(),
		ApplianceName: cfg.Appliance.Name, ApplianceTimezone: cfg.Appliance.Timezone,
		Analytics: analyticsReader, RawQueryLog: rawQueryLogReader, HostAgent: hostAgentClient,
		DNSRuntime: dnsRuntimeOrch, TLSCertPath: cfg.Web.TLSCertPath, TLSKeyPath: cfg.Web.TLSKeyPath,
	}

	listenAddr := *addr
	if listenAddr == "" {
		listenAddr = fmt.Sprintf("%s:%d", cfg.Web.ListenAddress, cfg.Web.ListenPort)
	}

	schedulerCtx, cancelScheduler := context.WithCancel(context.Background())
	go blSvc.RunScheduler(schedulerCtx, time.Duration(cfg.Blocklists.SchedulerTickSeconds)*time.Second)

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
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)
	logger.Info("shutdown complete", "elapsed_ms", time.Since(shutdownStart).Milliseconds())
}
