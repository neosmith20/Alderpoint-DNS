// The Go-native DNS runtime: root-owned stage -> validate -> promote ->
// reload pipeline for BIND + dnsdist, with automatic rollback to the
// last known-good runtime on any validation, promotion, or reload
// failure. The web process (unprivileged) compiles the dnsdist config
// itself via internal/dnscompile (a pure function, no secrets, no root
// needed) and sends the resulting text here as a named, typed
// operation's params -- never a path, never a shell command. BIND's own
// config is compiled entirely on this side of the boundary instead,
// because it needs an rndc HMAC key: a real, if low-value (loopback-
// only, this migration's own disposable runtime, never Python's
// control.db-referenced secrets), piece of key material this process
// generates itself at startup and never hands to the unprivileged web
// process.
package hostagentd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"alderpointdns/go-controlplane/internal/dnscompile"
	"alderpointdns/go-controlplane/internal/hostagent"
)

type DNSRuntimeConfig struct {
	StagingDir      string
	BindLivePath    string
	DnsdistLivePath string
	BindDirectory   string // named.conf's own "directory" clause target; created if missing
	BindLogPath     string

	BindPlainPort, BindProxyPort, BindStatsPort, BindRNDCPort int

	// DnsdistListenAddress must match whatever address the web side
	// compiled into the dnsdist config's own setLocal() -- this side
	// trusts the deployment's own fixed configuration for the health
	// check's dial target, never anything parsed back out of the
	// received config text.
	DnsdistListenAddress string

	NamedBinary           string
	DnsdistBinary         string
	RNDCBinary            string
	NamedCheckconfBinary  string
	DigBinary             string
	HealthCheckTimeout    time.Duration
	HealthCheckRetryDelay time.Duration
}

func (c *DNSRuntimeConfig) applyDefaults() {
	if c.NamedBinary == "" {
		c.NamedBinary = "named"
	}
	if c.DnsdistBinary == "" {
		c.DnsdistBinary = "dnsdist"
	}
	if c.RNDCBinary == "" {
		c.RNDCBinary = "rndc"
	}
	if c.NamedCheckconfBinary == "" {
		c.NamedCheckconfBinary = "named-checkconf"
	}
	if c.DigBinary == "" {
		c.DigBinary = "dig"
	}
	if c.HealthCheckTimeout <= 0 {
		c.HealthCheckTimeout = 5 * time.Second
	}
	if c.HealthCheckRetryDelay <= 0 {
		c.HealthCheckRetryDelay = 200 * time.Millisecond
	}
}

type dnsRuntimeState struct {
	mu            sync.Mutex
	cfg           DNSRuntimeConfig
	bindCmd       *exec.Cmd
	dnsdistCmd    *exec.Cmd
	rndcKeySecret string // generated once, kept only in this process's memory
	prevNamedConf string
	prevDnsdist   string
	havePrev      bool
}

type DNSRuntimeStatus struct {
	BindRunning    bool   `json:"bind_running"`
	DnsdistRunning bool   `json:"dnsdist_running"`
	LastPromotedAt string `json:"last_promoted_at,omitempty"`
}

type DNSPromoteParams struct {
	DnsdistConf     string   `json:"dnsdist_conf"`
	BindForwarders  []string `json:"bind_forwarders"`
	BindTLSHostname string   `json:"bind_tls_hostname"`
	// DryRun compiles and validates (named-checkconf, dnsdist
	// --check-config) without ever touching BindLivePath/DnsdistLivePath
	// or starting/reloading anything -- proof the exact config that WILL
	// be promoted is valid, safely callable while another process (e.g.
	// Python, during a cutover) still owns the real DNS port, since
	// nothing here binds a socket. See cmd/alderpointdns-go's
	// "dns-promote -dry-run" subcommand, used by scripts/v2/cutover.sh
	// to prove the staged runtime BEFORE Python is stopped -- Alex's
	// explicit requirement that live cutover never depend on a human
	// clicking Apply in an authenticated browser session.
	DryRun bool `json:"dry_run"`
}

type DNSPromoteResult struct {
	Promoted    bool   `json:"promoted"`
	RolledBack  bool   `json:"rolled_back"`
	Stage       string `json:"stage"`
	Detail      string `json:"detail,omitempty"`
	HealthyAtMS int64  `json:"healthy_after_ms,omitempty"`
}

// RegisterDNSRuntimeOps wires dns.status/dns.promote. Generates a fresh
// random rndc HMAC key for this process's own lifetime -- never
// persisted, never returned in any API response.
//
// Returns a stop func that terminates whatever real named/dnsdist
// processes this runtime has started. The production agent
// (cmd/apdns-hostagent) intentionally never calls it -- the whole point
// of this runtime is that the live DNS processes outlive the agent's
// own restarts/updates. Tests that promote a real runtime MUST call it
// via t.Cleanup, or the named/dnsdist processes it starts are orphaned
// (reparented to init) once the test exits, silently leaking real
// daemons and their memory across every test run.
func RegisterDNSRuntimeOps(s *Server, cfg DNSRuntimeConfig) (func(), error) {
	cfg.applyDefaults()
	if cfg.StagingDir == "" || cfg.BindLivePath == "" || cfg.DnsdistLivePath == "" || cfg.BindDirectory == "" {
		return nil, fmt.Errorf("dns runtime: StagingDir, BindLivePath, DnsdistLivePath, and BindDirectory are required")
	}
	if err := os.MkdirAll(cfg.StagingDir, 0o750); err != nil {
		return nil, fmt.Errorf("dns runtime: creating staging dir: %w", err)
	}
	if err := os.MkdirAll(cfg.BindDirectory, 0o750); err != nil {
		return nil, fmt.Errorf("dns runtime: creating BIND directory: %w", err)
	}
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("dns runtime: generating rndc key: %w", err)
	}
	st := &dnsRuntimeState{cfg: cfg, rndcKeySecret: base64.StdEncoding.EncodeToString(keyBytes)}

	s.Register(hostagent.OpDNSRuntimeStatus, func(ctx context.Context, params json.RawMessage) (any, error) {
		st.mu.Lock()
		defer st.mu.Unlock()
		return DNSRuntimeStatus{
			BindRunning:    st.bindCmd != nil && st.bindCmd.Process != nil && processAlive(st.bindCmd.Process.Pid),
			DnsdistRunning: st.dnsdistCmd != nil && st.dnsdistCmd.Process != nil && processAlive(st.dnsdistCmd.Process.Pid),
		}, nil
	})

	s.Register(hostagent.OpDNSRuntimePromote, func(ctx context.Context, params json.RawMessage) (any, error) {
		var p DNSPromoteParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if strings.TrimSpace(p.DnsdistConf) == "" {
			return nil, fmt.Errorf("dnsdist_conf is required")
		}
		return st.promote(ctx, p)
	})
	return func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		st.stopBind()
		st.stopDnsdist()
	}, nil
}

func (st *dnsRuntimeState) promote(ctx context.Context, p DNSPromoteParams) (*DNSPromoteResult, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	namedConf, err := dnscompile.CompileNamedConf(dnscompile.NamedConfInput{
		Forwarders: p.BindForwarders, TLSHostname: p.BindTLSHostname,
		PlainPort: st.cfg.BindPlainPort, ProxyPort: st.cfg.BindProxyPort, StatsPort: st.cfg.BindStatsPort,
		RNDCPort: st.cfg.BindRNDCPort, RNDCKey: st.rndcKeySecret,
		Directory: st.cfg.BindDirectory, LogPath: st.cfg.BindLogPath,
	})
	if err != nil {
		return nil, fmt.Errorf("compiling named.conf: %w", err)
	}

	// --- stage ---
	namedStagePath := filepath.Join(st.cfg.StagingDir, "named.conf.staged")
	dnsdistStagePath := filepath.Join(st.cfg.StagingDir, "dnsdist.conf.staged")
	if err := atomicWrite(namedStagePath, namedConf); err != nil {
		return nil, fmt.Errorf("staging named.conf: %w", err)
	}
	if err := atomicWrite(dnsdistStagePath, p.DnsdistConf); err != nil {
		return nil, fmt.Errorf("staging dnsdist.conf: %w", err)
	}

	// --- validate (both must pass before either promotes) ---
	if out, err := exec.CommandContext(ctx, st.cfg.NamedCheckconfBinary, namedStagePath).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("named-checkconf rejected the compiled BIND config, nothing promoted: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, st.cfg.DnsdistBinary, "-C", dnsdistStagePath, "--check-config").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("dnsdist --check-config rejected the compiled config, nothing promoted: %s", strings.TrimSpace(string(out)))
	}

	if p.DryRun {
		// Proof the exact config is valid -- nothing live touched, no
		// socket bound, safe to call while another process still owns
		// the real DNS port.
		return &DNSPromoteResult{Promoted: false, Stage: "validated"}, nil
	}

	// --- back up whatever is currently live, then promote atomically ---
	prevNamed, prevNamedExisted := readIfExists(st.cfg.BindLivePath)
	prevDnsdist, prevDnsdistExisted := readIfExists(st.cfg.DnsdistLivePath)
	havePrev := prevNamedExisted || prevDnsdistExisted

	if err := atomicWrite(st.cfg.BindLivePath, namedConf); err != nil {
		return nil, fmt.Errorf("promoting named.conf: %w", err)
	}
	if err := atomicWrite(st.cfg.DnsdistLivePath, p.DnsdistConf); err != nil {
		// Best-effort: restore BIND's live file since dnsdist's failed.
		if prevNamedExisted {
			atomicWrite(st.cfg.BindLivePath, prevNamed)
		}
		return nil, fmt.Errorf("promoting dnsdist.conf: %w", err)
	}

	// --- reload ---
	if err := st.reloadBind(ctx); err != nil {
		return st.rollback(ctx, "bind_reload", err.Error(), prevNamed, prevDnsdist, havePrev)
	}
	if err := st.reloadDnsdist(ctx); err != nil {
		return st.rollback(ctx, "dnsdist_reload", err.Error(), prevNamed, prevDnsdist, havePrev)
	}

	// --- health check: prove THIS promotion is actually live ---
	started := time.Now()
	if err := st.waitHealthy(ctx); err != nil {
		return st.rollback(ctx, "health_check", err.Error(), prevNamed, prevDnsdist, havePrev)
	}

	st.prevNamedConf, st.prevDnsdist, st.havePrev = namedConf, p.DnsdistConf, true
	return &DNSPromoteResult{Promoted: true, Stage: "healthy", HealthyAtMS: time.Since(started).Milliseconds()}, nil
}

// rollback restores whatever was live before this promotion attempt
// (or removes the just-written files if nothing was live yet), reloads
// with it, and reports the exact stage/error that triggered the
// rollback. Never returns a Go error itself -- a rollback that
// succeeds is a successful *operation*, even though the requested
// config was rejected.
func (st *dnsRuntimeState) rollback(ctx context.Context, stage, detail, prevNamed, prevDnsdist string, havePrev bool) (*DNSPromoteResult, error) {
	if havePrev {
		atomicWrite(st.cfg.BindLivePath, prevNamed)
		atomicWrite(st.cfg.DnsdistLivePath, prevDnsdist)
		st.reloadBind(ctx)
		st.reloadDnsdist(ctx)
	} else {
		os.Remove(st.cfg.BindLivePath)
		os.Remove(st.cfg.DnsdistLivePath)
		st.stopBind()
		st.stopDnsdist()
	}
	return &DNSPromoteResult{Promoted: false, RolledBack: true, Stage: stage, Detail: detail}, nil
}

func (st *dnsRuntimeState) reloadBind(ctx context.Context) error {
	if st.bindCmd != nil && st.bindCmd.Process != nil && processAlive(st.bindCmd.Process.Pid) {
		rndcConfPath := filepath.Join(st.cfg.StagingDir, "rndc.conf")
		rndcConf := fmt.Sprintf("key \"apdns-go-rndc-key\" {\n\talgorithm hmac-sha256;\n\tsecret %q;\n};\noptions {\n\tdefault-key \"apdns-go-rndc-key\";\n\tdefault-server 127.0.0.1;\n\tdefault-port %d;\n};\n", st.rndcKeySecret, st.cfg.BindRNDCPort)
		if err := atomicWrite(rndcConfPath, rndcConf); err != nil {
			return fmt.Errorf("writing rndc.conf: %w", err)
		}
		out, err := exec.CommandContext(ctx, st.cfg.RNDCBinary, "-c", rndcConfPath, "reconfig").CombinedOutput()
		if err != nil {
			return fmt.Errorf("rndc reconfig: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	cmd := exec.CommandContext(context.Background(), st.cfg.NamedBinary, "-g", "-c", st.cfg.BindLivePath)
	logPath := filepath.Join(st.cfg.StagingDir, "named.startup.log")
	logFile, err := os.Create(logPath)
	if err == nil {
		cmd.Stdout, cmd.Stderr = logFile, logFile
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting named: %w", err)
	}
	st.bindCmd = cmd
	go cmd.Wait() // reap; we track liveness via processAlive, not Wait's return
	// Give named a brief moment to bind its listeners before the caller
	// proceeds to the dnsdist reload/health-check stage.
	time.Sleep(300 * time.Millisecond)
	if !processAlive(cmd.Process.Pid) {
		return fmt.Errorf("named exited immediately after start (see %s)", logPath)
	}
	return nil
}

func (st *dnsRuntimeState) reloadDnsdist(ctx context.Context) error {
	st.stopDnsdist()
	cmd := exec.CommandContext(context.Background(), st.cfg.DnsdistBinary, "-C", st.cfg.DnsdistLivePath, "--supervised")
	logPath := filepath.Join(st.cfg.StagingDir, "dnsdist.startup.log")
	logFile, err := os.Create(logPath)
	if err == nil {
		cmd.Stdout, cmd.Stderr = logFile, logFile
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting dnsdist: %w", err)
	}
	st.dnsdistCmd = cmd
	go cmd.Wait()
	time.Sleep(200 * time.Millisecond)
	if !processAlive(cmd.Process.Pid) {
		return fmt.Errorf("dnsdist exited immediately after start (see %s)", logPath)
	}
	return nil
}

func (st *dnsRuntimeState) stopBind() {
	stopCmd(st.bindCmd)
	st.bindCmd = nil
}

func (st *dnsRuntimeState) stopDnsdist() {
	stopCmd(st.dnsdistCmd)
	st.dnsdistCmd = nil
}

func stopCmd(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
	}
}

// waitHealthy polls with real `dig` queries for the fixed
// dnscompile.HealthMarkerDomain marker record until it gets the exact
// expected answer or the configured timeout elapses -- proof the
// currently-running dnsdist process is actually serving the
// just-promoted config, not merely that its process is still alive.
func (st *dnsRuntimeState) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(st.cfg.HealthCheckTimeout)
	host, port := splitHostPort(st.cfg.DnsdistListenAddress)
	var lastErr error
	for time.Now().Before(deadline) {
		out, err := exec.CommandContext(ctx, st.cfg.DigBinary,
			"+time=1", "+tries=1", "+short",
			"@"+host, "-p", port, dnscompile.HealthMarkerDomain, "A",
		).Output()
		if err == nil && strings.TrimSpace(string(out)) == dnscompile.HealthMarkerIP {
			return nil
		}
		lastErr = fmt.Errorf("marker query did not return the expected answer (got %q, err=%v)", strings.TrimSpace(string(out)), err)
		time.Sleep(st.cfg.HealthCheckRetryDelay)
	}
	return lastErr
}

func splitHostPort(addr string) (string, string) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, "53"
	}
	return addr[:idx], addr[idx+1:]
}

func atomicWrite(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	if err := os.WriteFile(tmp, []byte(content), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readIfExists(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
