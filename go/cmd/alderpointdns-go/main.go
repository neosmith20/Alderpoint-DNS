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
	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/config"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/httpapi"
	"alderpointdns/go-controlplane/internal/localdns"
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
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q (want: web, migrate)\n", os.Args[1])
		os.Exit(2)
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

	srv := &httpapi.Server{
		DB: db, Auth: &auth.Store{DB: db}, Blocklists: blSvc, LocalDNS: ldSvc,
		StaticDir: *staticDir, Log: logger, Version: Version, StartedAt: startedAt,
		SessionTTL: cfg.SessionTTL(), LastSeen: cfg.LastSeenUpdateInterval(),
		ApplianceName: cfg.Appliance.Name, ApplianceTimezone: cfg.Appliance.Timezone,
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
