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
	"strconv"
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
		// 60s, not the originally-shipped 5s (nor the first-attempt fix
		// of 30s -- see the durability-pass diagnostic trail below for
		// why 30s still wasn't enough). A realistic, blocklist-heavy
		// compiled dnsdist config (~855k domains, a single large inline
		// Lua table) measured 5.8s to parse and start listening in
		// isolation, but a REAL promote's own reload (which stops the
		// prior live dnsdist first) was measured, with temporary timing
		// instrumentation, taking dnsdist's own process a further ~30s+
		// past a first 30s health-check budget before it logged its own
		// "Listening on Do53 frontend" -- confirmed to complete only
		// ~4s after a 30s-budget health check had already given up and
		// triggered a real (safe, auto-rolled-back, but unnecessary)
		// rollback. 60s leaves real margin above that measured worst
		// case. See cmd/apdns-hostagent's own
		// -dns-runtime-health-check-timeout-seconds flag, which this
		// default matches.
		c.HealthCheckTimeout = 60 * time.Second
	}
	if c.HealthCheckRetryDelay <= 0 {
		c.HealthCheckRetryDelay = 200 * time.Millisecond
	}
}

// trackedProcess is a real named/dnsdist OS process this dnsRuntimeState
// is responsible for -- either one it started itself (cmd != nil, so
// stopping it can Wait() for a clean exit) or one it ADOPTED from a PID
// file left by a PRIOR generation of this same hostagent process, after
// a restart (cmd == nil, pid only).
//
// This adoption path is not optional polish: a real, previously-
// undisclosed bug (found live, 2026-08-29, during a routine web
// container redeploy that triggered a burst of blocklist-refresh
// auto-promotes) -- without it, the very first dns_runtime.promote
// after ANY hostagent restart found bindCmd/dnsdistCmd nil (a fresh
// dnsRuntimeState has no memory of what the PREVIOUS hostagent
// generation started) and unconditionally spawned a brand-new named
// process, permanently orphaning the one already live and answering
// real queries -- two named processes bound to the same ports,
// confirmed live via `ss -ltnp`. dnsdist's own always-restart-on-
// promote design (see reloadDnsdist) has the identical exposure. PID
// files under cfg.StagingDir close this gap: whichever hostagent
// generation is currently running always knows the real PID of
// whatever it (or a predecessor) left running, so "is it already
// alive" is answered by checking the real OS process, never assumed
// false just because this particular Go struct is new.
type trackedProcess struct {
	cmd *exec.Cmd // nil for an adopted process this state didn't start
	pid int
}

func (p *trackedProcess) alive() bool {
	return p != nil && p.pid != 0 && processAlive(p.pid)
}

// stop terminates the tracked process, waiting for a clean exit via
// cmd.Wait() when this state started it itself, or via a raw signal +
// poll loop when it was only adopted (no Cmd to Wait() on -- adopting a
// process never fakes ownership of its exit-code plumbing).
func (p *trackedProcess) stop() {
	if p == nil || p.pid == 0 {
		return
	}
	if p.cmd != nil && p.cmd.Process != nil {
		stopCmd(p.cmd)
		return
	}
	syscall.Kill(p.pid, syscall.SIGTERM)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(p.pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	syscall.Kill(p.pid, syscall.SIGKILL)
}

type dnsRuntimeState struct {
	mu            sync.Mutex
	cfg           DNSRuntimeConfig
	bind          *trackedProcess
	dnsdist       *trackedProcess
	rndcKeySecret string // generated once, kept only in this process's memory
	prevNamedConf string
	prevDnsdist   string
	havePrev      bool
}

func bindPIDFile(cfg DNSRuntimeConfig) string    { return filepath.Join(cfg.StagingDir, "named.pid") }
func dnsdistPIDFile(cfg DNSRuntimeConfig) string { return filepath.Join(cfg.StagingDir, "dnsdist.pid") }

// adoptFromPIDFile reads a real PID left by a prior generation of this
// same hostagent process and adopts it if (and only if) that PID is
// still actually alive -- a stale/missing PID file correctly yields
// nil, which reloadBind/reloadDnsdist's "not tracked, start fresh"
// branch already handles safely (the normal cold-start case).
func adoptFromPIDFile(path string) *trackedProcess {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return nil
	}
	if !processAlive(pid) {
		return nil
	}
	return &trackedProcess{pid: pid}
}

// loadOrGenerateRNDCKey returns the same rndc HMAC key across hostagent
// restarts -- see RegisterDNSRuntimeOps's own doc comment for why a
// fresh random key on every restart breaks rndc reconfig against an
// ADOPTED (already-running, not started by this generation) named
// process. The file lives under StagingDir (root-owned, 0600, never
// world-readable) -- a real, if low-value (loopback-only, this
// migration's own disposable runtime, never Python's control.db-
// referenced secrets), piece of key material, same posture the
// original comment already disclosed for the key itself.
func loadOrGenerateRNDCKey(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		key := strings.TrimSpace(string(data))
		if key != "" {
			return key, nil
		}
	}
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", fmt.Errorf("generating rndc key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		return "", fmt.Errorf("persisting rndc key: %w", err)
	}
	return key, nil
}

func writePIDFile(path string, pid int) {
	atomicWrite(path, strconv.Itoa(pid))
}

func removePIDFile(path string) {
	os.Remove(path)
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
	// The rndc HMAC key must survive a hostagent restart, not just the
	// PID -- a real, second bug this adoption logic surfaced (found
	// live, 2026-08-29, immediately after fixing the duplicate-process
	// incident): an ADOPTED named process is still running with the
	// PREVIOUS generation's key baked into its currently-loaded
	// named.conf `controls` clause; `rndc reconfig` authenticates
	// against that ALREADY-LOADED key, not whatever key the new
	// named.conf this generation is about to write contains -- a fresh
	// random key here would make every reconfig against an adopted
	// process fail with "connection to remote host closed" (confirmed
	// live). Reusing the same key file this generation may have
	// inherited keeps the adopted process's real, currently-trusted key
	// stable across restarts.
	rndcKeySecret, err := loadOrGenerateRNDCKey(filepath.Join(cfg.StagingDir, "rndc.key.secret"))
	if err != nil {
		return nil, fmt.Errorf("dns runtime: rndc key: %w", err)
	}
	st := &dnsRuntimeState{cfg: cfg, rndcKeySecret: rndcKeySecret}
	// Adopt whatever a PRIOR generation of this same hostagent process
	// left running -- see trackedProcess's own doc comment for the real
	// duplicate-process incident this prevents.
	st.bind = adoptFromPIDFile(bindPIDFile(cfg))
	st.dnsdist = adoptFromPIDFile(dnsdistPIDFile(cfg))

	s.Register(hostagent.OpDNSRuntimeStatus, func(ctx context.Context, params json.RawMessage) (any, error) {
		st.mu.Lock()
		defer st.mu.Unlock()
		return DNSRuntimeStatus{
			BindRunning:    st.bind.alive(),
			DnsdistRunning: st.dnsdist.alive(),
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
	if st.bind.alive() {
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
	st.bind = &trackedProcess{cmd: cmd, pid: cmd.Process.Pid}
	writePIDFile(bindPIDFile(st.cfg), cmd.Process.Pid)
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

	// A real live defect found during a durability pass: restarting
	// dnsdist immediately after stopping the previous instance --
	// exactly what this function used to do, with no gap at all --
	// reliably crashed the new process with a "Fatal Lua error:
	// FrameStreamLogger: setting outputQueueSize failed: 1" the instant
	// dnstap logging is enabled (dnscompile always compiles it in when
	// -dns-runtime-dnstap-socket is set). Root-caused by direct
	// reproduction: killing dnsdist and restarting it seconds later
	// (by hand, well outside this function) always succeeded; the ONLY
	// difference from this function's own behavior was elapsed time
	// between stop and start -- the dnstap receiver's just-closed
	// accept-loop connection evidently needs a moment to fully settle
	// before a brand new connection to the same unix socket path can
	// succeed. A single retry after a short backoff, rather than an
	// unconditional fixed delay on every reload, keeps the common case
	// (receiver already settled) fast and self-heals the race when it
	// does occur instead of guessing a magic number that could still be
	// too short under different load.
	const maxAttempts = 2
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		cmd := exec.CommandContext(context.Background(), st.cfg.DnsdistBinary, "-C", st.cfg.DnsdistLivePath, "--supervised")
		logPath := filepath.Join(st.cfg.StagingDir, "dnsdist.startup.log")
		logFile, err := os.Create(logPath)
		if err == nil {
			cmd.Stdout, cmd.Stderr = logFile, logFile
		}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("starting dnsdist: %w", err)
		}
		st.dnsdist = &trackedProcess{cmd: cmd, pid: cmd.Process.Pid}
		writePIDFile(dnsdistPIDFile(st.cfg), cmd.Process.Pid)
		go cmd.Wait()
		time.Sleep(200 * time.Millisecond)
		if processAlive(cmd.Process.Pid) {
			return nil
		}
		lastErr = fmt.Errorf("dnsdist exited immediately after start (see %s)", logPath)
		removePIDFile(dnsdistPIDFile(st.cfg))
		st.dnsdist = nil
		if attempt < maxAttempts {
			time.Sleep(2 * time.Second)
		}
	}
	return lastErr
}

func (st *dnsRuntimeState) stopBind() {
	st.bind.stop()
	st.bind = nil
	removePIDFile(bindPIDFile(st.cfg))
}

func (st *dnsRuntimeState) stopDnsdist() {
	st.dnsdist.stop()
	st.dnsdist = nil
	removePIDFile(dnsdistPIDFile(st.cfg))
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
	// A real, previously-undisclosed bug (found live, 2026-08-28: a
	// genuine ~3-minute DNS outage during a routine apdns-hostagent
	// restart, recovered via dns-promote -- see AGENT_PROGRESS.md):
	// dnsdist's configured listen address is "0.0.0.0:53" on every real
	// deployment (it must bind every interface for real LAN clients),
	// but dialing "0.0.0.0" as a DESTINATION is not a valid loopback
	// alias on this host and was silently getting "connection refused"
	// -- so this health check reported a false rolled_back on real,
	// genuinely healthy promotions, invisible to every existing test
	// (they all use a real 127.0.0.1:<port> listen address, since a
	// test fixture has no LAN clients to serve). "0.0.0.0" and "::"
	// both mean "every interface, including loopback" when BINDING;
	// dial the real loopback address instead of the bind wildcard.
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	} else if host == "::" {
		host = "::1"
	}
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
