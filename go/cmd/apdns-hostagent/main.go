// Command apdns-hostagent is the root-owned privileged operations
// daemon for the Go control plane -- see internal/hostagent's doc
// comment for the protocol/design and internal/hostagentd for the
// actual operation implementations. This binary is deliberately tiny:
// parse flags, discover real BIND contexts, wire the allowlisted
// operations, serve. All the actual logic lives in internal/hostagentd
// so it can be unit-tested without a running daemon.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
)

func main() {
	socketPath := flag.String("socket", hostagent.DefaultSocketPath, "unix socket to listen on")
	allowedUID := flag.Uint("allowed-uid", 0, "UID of the only process permitted to connect (the web control plane's own UID)")
	auditLogPath := flag.String("audit-log", "/var/log/apdns-hostagent/audit.jsonl", "append-only audit log path")

	bindNamedConfDir := flag.String("bind-compiled-dir", "", "directory containing one <context>/named.conf per compiled BIND context (empty = Cache reports no BIND contexts)")
	rndcConfPath := flag.String("rndc-conf", "", "path to rndc.conf (empty = Cache/rndc operations unavailable)")

	controlDBPath := flag.String("control-db", "", "path to Python's control.db, read-only (empty = Replication reports unavailable)")

	journalDir := flag.String("journal-dir", "", "explicit journal directory for logs.read (empty = the host's own default journal)")
	logUnits := flag.String("log-units", strings.Join(hostagentd.LogUnits, ","), "comma-separated allowlist of logical unit names")
	logUnitMap := flag.String("log-unit-map", "", "comma-separated logical=real name overrides -- a systemd unit name by default, or a container name / file path for names listed in -log-container-units / -log-file-units")
	logContainerUnits := flag.String("log-container-units", "", "comma-separated subset of logical units that are podman/docker containers (matched via journald's CONTAINER_NAME= field, not -u)")
	logFileUnits := flag.String("log-file-units", "", "comma-separated subset of logical units read from a plain slog-JSON log file instead of the journal")

	currentBinaryPath := flag.String("current-binary", "", "path to the live web control-plane binary this agent may update (empty = Software Updates unavailable)")
	updateStagingDir := flag.String("update-staging-dir", "/var/lib/apdns-hostagent/update-staging", "staging directory for a candidate update")
	updateBackupPath := flag.String("update-backup", "/var/lib/apdns-hostagent/previous-binary", "where the pre-update binary is backed up")
	webServiceUnit := flag.String("web-service-unit", "", "systemd unit to restart on update apply (empty = Software Updates apply unavailable)")
	webHealthURL := flag.String("web-health-url", "", "URL to poll after a restart to confirm health (empty = Software Updates apply unavailable)")

	analyticsSnapshotSource := flag.String("analytics-snapshot-source", "", "Python's real, live aggregates.db host path (empty = analytics snapshot publishing disabled -- Dashboard analytics reports degraded, see internal/analyticssnapshot)")
	analyticsSnapshotPublishedDir := flag.String("analytics-snapshot-published-dir", "/var/lib/apdns-hostagent/analytics-snapshot/published", "directory this agent publishes completed snapshot generations into -- the web container mounts this read-only")
	analyticsSnapshotStagingDir := flag.String("analytics-snapshot-staging-dir", "/var/lib/apdns-hostagent/analytics-snapshot/staging", "scratch directory (same filesystem as -analytics-snapshot-published-dir) this agent uses while building a generation, before the atomic publish")
	analyticsSnapshotIntervalSeconds := flag.Int("analytics-snapshot-interval-seconds", 15, "how often to refresh the published analytics snapshot")
	analyticsSnapshotRetain := flag.Int("analytics-snapshot-retain", 3, "how many past snapshot generations to keep (minimum 2)")

	dnsRuntimeStagingDir := flag.String("dns-runtime-staging-dir", "/var/lib/apdns-hostagent/dns-staging", "staging directory for compiled BIND/dnsdist config (see internal/hostagentd/ops_dnsruntime.go)")
	dnsRuntimeBindLivePath := flag.String("dns-runtime-bind-conf", "", "live named.conf path this agent manages (empty = DNS Runtime unavailable)")
	dnsRuntimeDnsdistLivePath := flag.String("dns-runtime-dnsdist-conf", "", "live dnsdist.conf path this agent manages (empty = DNS Runtime unavailable)")
	dnsRuntimeBindDir := flag.String("dns-runtime-bind-dir", "", "BIND's own working directory (named.conf's directory clause) -- must be a real, writable, AppArmor-allowed path (e.g. under /var/lib/bind)")
	dnsRuntimeBindPlainPort := flag.Int("dns-runtime-bind-plain-port", 15453, "BIND's unproxied loopback listener port")
	dnsRuntimeBindProxyPort := flag.Int("dns-runtime-bind-proxy-port", 15553, "BIND's PROXYv2 listener port -- dnsdist's default pool forwards here")
	dnsRuntimeBindStatsPort := flag.Int("dns-runtime-bind-stats-port", 18153, "BIND's statistics-channels port")
	dnsRuntimeBindRNDCPort := flag.Int("dns-runtime-bind-rndc-port", 19553, "BIND's rndc control-channel port")
	dnsRuntimeDnsdistListenAddr := flag.String("dns-runtime-dnsdist-listen-addr", "", "the real address dnsdist listens on for this deployment (empty = DNS Runtime unavailable)")

	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if *allowedUID == 0 {
		logger.Error("-allowed-uid is required (refusing to run with an unset/UID-0 allowlist -- that would authorize root itself, defeating the point of this boundary)")
		os.Exit(2)
	}

	audit, err := hostagentd.OpenAuditLog(*auditLogPath)
	if err != nil {
		logger.Error("opening audit log", "err", err)
		os.Exit(1)
	}
	defer audit.Close()

	s := &hostagentd.Server{
		SocketPath: *socketPath,
		AllowedUID: uint32(*allowedUID),
		Log:        logger,
		Audit:      audit,
	}

	hostagentd.RegisterLogsOps(s, hostagentd.LogsConfig{
		Units:            strings.Split(*logUnits, ","),
		JournalDir:       *journalDir,
		UnitNameOverride: parseUnitMap(*logUnitMap),
		ContainerUnits:   parseUnitSet(*logContainerUnits),
		FileUnits:        parseUnitSet(*logFileUnits),
	})

	hostagentd.RegisterCacheOps(s, hostagentd.CacheConfig{
		RNDCConfPath: *rndcConfPath,
		Contexts:     discoverBindContexts(*bindNamedConfDir, logger),
	})

	hostagentd.RegisterReplicationOps(s, hostagentd.ReplicationConfig{ControlDBPath: *controlDBPath})

	hostagentd.RegisterNetworkOps(s, hostagentd.NetworkConfig{})

	if *analyticsSnapshotSource != "" {
		// The returned stop func is intentionally discarded here, same
		// reasoning as DNS Runtime below: this process's job is to keep
		// publishing for its own lifetime; only tests call it.
		hostagentd.RegisterAnalyticsSnapshotOps(s, hostagentd.AnalyticsSnapshotConfig{
			SourcePath:   *analyticsSnapshotSource,
			PublishedDir: *analyticsSnapshotPublishedDir,
			StagingDir:   *analyticsSnapshotStagingDir,
			Interval:     time.Duration(*analyticsSnapshotIntervalSeconds) * time.Second,
			Retain:       *analyticsSnapshotRetain,
		})
	} else {
		logger.Info("analytics snapshot publishing not configured -- -analytics-snapshot-source is required; Dashboard analytics will report degraded")
	}

	updateCfg := hostagentd.UpdateConfig{
		CurrentBinaryPath: *currentBinaryPath,
		StagingDir:        *updateStagingDir,
		BackupPath:        *updateBackupPath,
	}
	if *webServiceUnit != "" {
		updateCfg.Restart = func(ctx context.Context) error {
			return exec.CommandContext(ctx, "systemctl", "restart", *webServiceUnit).Run()
		}
	}
	if *webHealthURL != "" {
		updateCfg.HealthCheck = healthCheckFunc(*webHealthURL)
	}
	hostagentd.RegisterUpdateOps(s, updateCfg)

	if *dnsRuntimeBindLivePath != "" && *dnsRuntimeDnsdistLivePath != "" && *dnsRuntimeBindDir != "" && *dnsRuntimeDnsdistListenAddr != "" {
		// The returned stop func is intentionally discarded here: this
		// process's whole job is to keep the real named/dnsdist runtime
		// alive across its own restarts and updates (see
		// RegisterDNSRuntimeOps's doc comment). Only tests call it.
		if _, err := hostagentd.RegisterDNSRuntimeOps(s, hostagentd.DNSRuntimeConfig{
			StagingDir: *dnsRuntimeStagingDir, BindLivePath: *dnsRuntimeBindLivePath, DnsdistLivePath: *dnsRuntimeDnsdistLivePath,
			BindDirectory: *dnsRuntimeBindDir, BindLogPath: filepath.Join(*dnsRuntimeBindDir, "named.log"),
			BindPlainPort: *dnsRuntimeBindPlainPort, BindProxyPort: *dnsRuntimeBindProxyPort, BindStatsPort: *dnsRuntimeBindStatsPort, BindRNDCPort: *dnsRuntimeBindRNDCPort,
			DnsdistListenAddress: *dnsRuntimeDnsdistListenAddr,
		}); err != nil {
			logger.Error("DNS runtime ops not registered", "err", err)
			os.Exit(1)
		}
	} else {
		logger.Info("DNS runtime compilation not configured -- -dns-runtime-bind-conf, -dns-runtime-dnsdist-conf, -dns-runtime-bind-dir, and -dns-runtime-dnsdist-listen-addr are all required together")
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()

	if err := s.Serve(ctx); err != nil {
		logger.Error("serve failed", "err", err)
		os.Exit(1)
	}
}

func parseUnitSet(spec string) map[string]bool {
	if spec == "" {
		return nil
	}
	out := map[string]bool{}
	for _, name := range strings.Split(spec, ",") {
		if name != "" {
			out[name] = true
		}
	}
	return out
}

func parseUnitMap(spec string) map[string]string {
	if spec == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}

// discoverBindContexts mirrors app/v2/webapp.py's _bind_context_ports():
// one context per subdirectory of the compiled BIND directory that has
// a named.conf, with the same 8153+idx/9553+idx port convention.
func discoverBindContexts(compiledDir string, logger *slog.Logger) []hostagentd.BindContext {
	if compiledDir == "" {
		return nil
	}
	entries, err := os.ReadDir(compiledDir)
	if err != nil {
		logger.Warn("could not read compiled BIND directory; Cache will report no contexts", "dir", compiledDir, "err", err)
		return nil
	}
	var out []hostagentd.BindContext
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(compiledDir, e.Name(), "named.conf")); err != nil {
			continue
		}
		idx := 0
		if strings.HasPrefix(e.Name(), "ctx") {
			if n, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "ctx")); err == nil {
				idx = n
			}
		}
		out = append(out, hostagentd.BindContext{Name: e.Name(), StatsPort: 8153 + idx, RNDCPort: 9553 + idx})
	}
	return out
}

// healthCheckFunc polls a fixed, configured URL (never caller-supplied)
// after an update apply's restart. The web control plane's own TLS cert
// is appliance-generated (self-signed) -- skipping verification here is
// the same trust boundary this project's own local test tooling already
// uses for the same appliance-local self-signed cert (curl --insecure
// against 127.0.0.1 throughout go/tests/), not a new one, and this
// client only ever talks to the one fixed URL passed in at agent
// startup.
func healthCheckFunc(url string) func(ctx context.Context) (bool, error) {
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	return func(ctx context.Context) (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
	}
}
