package main

// Real, black-box regression proof for the 2026-08-28 incident (see
// AGENT_PROGRESS.md): a routine apdns-hostagent restart must NEVER take
// down the real named/dnsdist processes it started -- previously, this
// binary's own SIGTERM/SIGINT handler unconditionally called the
// returned dnsRuntimeStop() func, on the false premise that a signal
// can only ever mean "exiting forever, hand :53 back to Python" (a
// scenario that no longer exists -- Python is fully decommissioned).
//
// This test builds and runs the ACTUAL compiled cmd/apdns-hostagent
// binary (not just the internal/hostagentd package in-process) against
// a real disposable named/dnsdist pair, promotes a real config through
// it via the real cmd/alderpointdns-go "dns-promote" CLI (the same
// tool used for live recovery), sends the running hostagent process a
// real SIGTERM, and proves named/dnsdist are still alive and still
// answering real DNS queries afterward -- the exact failure mode of
// the real incident, reproduced and proven fixed.
import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireRealBinariesOrSkip(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"named", "rndc", "dnsdist", "dig"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available in this environment", bin)
		}
	}
	if os.Getuid() != 0 {
		t.Skip("requires root (to run the real hostagent + spawn a real named/dnsdist pair, matching the live deployment's own topology)")
	}
}

func buildBinary(t *testing.T, pkg, name string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, pkg)
	cmd.Dir = repoGoRoot(t)
	cmd.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	if outb, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v: %s", pkg, err, outb)
	}
	return out
}

// repoGoRoot walks up from this test file's own package directory to
// the go/ module root (two levels up from cmd/apdns-hostagent).
func repoGoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..")
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func digShort(t *testing.T, addr, port string) (string, error) {
	t.Helper()
	out, err := exec.Command("dig", "+time=2", "+tries=2", "+short", "@"+addr, "-p", port, "ads.example.test", "A").Output()
	return strings.TrimSpace(string(out)), err
}

// TestHostagentRestartDoesNotKillLiveDNS is the direct regression proof
// for the incident: promote a real runtime, confirm it answers, SIGTERM
// the real hostagent process, confirm named/dnsdist are STILL running
// and STILL answering -- both UDP and TCP -- with no duplicate/orphan
// processes left behind by either the restart or this test's own
// cleanup.
func TestHostagentRestartDoesNotKillLiveDNS(t *testing.T) {
	requireRealBinariesOrSkip(t)

	// t.TempDir() is root-owned/0700 by default and unreachable for the
	// unprivileged client spawned below (a unix socket connect needs
	// traversal permission on every parent directory, and the client
	// needs to exec mainBin directly) -- use one dedicated, explicitly
	// world-traversable work dir under os.TempDir() for everything both
	// sides touch, instead of Go's own per-test temp dirs.
	clientWorkDir := filepath.Join(os.TempDir(), fmt.Sprintf("hostagent-restart-test-client-%d", os.Getpid()))
	if err := os.MkdirAll(clientWorkDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(clientWorkDir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(clientWorkDir) })

	hostagentBin := buildBinary(t, "./cmd/apdns-hostagent", "hostagent-under-test")
	mainBin := filepath.Join(clientWorkDir, "main-under-test")
	if err := copyFile(buildBinary(t, "./cmd/alderpointdns-go", "main-under-test-src"), mainBin, 0o755); err != nil {
		t.Fatal(err)
	}

	bindDir := filepath.Join("/var/lib/bind", fmt.Sprintf("hostagent-restart-test-%d", os.Getpid()))
	if err := os.MkdirAll(bindDir, 0o755); err != nil {
		t.Skipf("cannot create test dir under /var/lib/bind: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(bindDir) })

	stagingDir := t.TempDir()
	secretsKeyDir := t.TempDir()
	socketPath := filepath.Join(clientWorkDir, "agent.sock")
	auditLog := filepath.Join(t.TempDir(), "audit.jsonl")
	dnsdistPort := freePort(t)
	dnsdistListenAddr := fmt.Sprintf("127.0.0.1:%d", dnsdistPort)
	bindPlainPort := freePort(t)
	bindProxyPort := freePort(t)
	bindStatsPort := freePort(t)
	bindRNDCPort := freePort(t)

	// This test's own promote CLI call below needs to authenticate as
	// the exact -allowed-uid configured for the hostagent -- since this
	// test process itself runs as root (uid 0) and the hostagent CLI
	// refuses -allowed-uid=0 outright (a real, deliberate security
	// check, not worked around here), run the promote CLI call under a
	// real different UID via `runuser`, and configure the hostagent to
	// allow exactly that UID. apdns-browsertest (a real, pre-existing
	// unprivileged system account used throughout this project's own
	// disposable-fixture tests) is reused here for the same reason.
	const testClientUser = "apdns-browsertest"
	clientUID, err := lookupUID(testClientUser)
	if err != nil {
		t.Skipf("%s system account not available in this environment: %v", testClientUser, err)
	}

	// Start the REAL compiled hostagent binary as root (matching the
	// live deployment's own topology: apdns-hostagent runs as root;
	// -allowed-uid governs who may CONNECT to it, not what it runs as).
	hostagentCmd := exec.Command(hostagentBin,
		"-socket", socketPath,
		"-allowed-uid", strconv.Itoa(clientUID),
		"-audit-log", auditLog,
		"-secrets-key-dir", secretsKeyDir,
		"-dns-runtime-staging-dir", stagingDir,
		"-dns-runtime-bind-conf", filepath.Join(bindDir, "named.conf"),
		"-dns-runtime-dnsdist-conf", filepath.Join(stagingDir, "dnsdist.conf"),
		"-dns-runtime-bind-dir", bindDir,
		"-dns-runtime-bind-plain-port", strconv.Itoa(bindPlainPort),
		"-dns-runtime-bind-proxy-port", strconv.Itoa(bindProxyPort),
		"-dns-runtime-bind-stats-port", strconv.Itoa(bindStatsPort),
		"-dns-runtime-bind-rndc-port", strconv.Itoa(bindRNDCPort),
		"-dns-runtime-dnsdist-listen-addr", dnsdistListenAddr,
	)
	hostagentCmd.Stdout = os.Stderr
	hostagentCmd.Stderr = os.Stderr
	if err := hostagentCmd.Start(); err != nil {
		t.Fatalf("starting hostagent: %v", err)
	}
	hostagentExited := make(chan error, 1)
	go func() { hostagentExited <- hostagentCmd.Wait() }()

	// Whatever named/dnsdist processes get promoted below must never
	// survive this test -- clean up explicitly and unconditionally,
	// regardless of how the test itself concludes (this is deliberately
	// NOT relying on the fixed shutdown behavior under test to clean up
	// after us).
	t.Cleanup(func() {
		exec.Command("pkill", "-9", "-f", "named -g -c "+filepath.Join(bindDir, "named.conf")).Run()
		exec.Command("pkill", "-9", "-f", "dnsdist -C "+filepath.Join(stagingDir, "dnsdist.conf")).Run()
		hostagentCmd.Process.Kill()
	})

	// Wait for the real socket to appear.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := os.Chmod(socketPath, 0o666); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}

	dbPath := filepath.Join(clientWorkDir, "app.db")
	// config.LoadOrMigrate requires a real, existing appliance.yaml --
	// seed one from the repo's own real default rather than pointing at
	// a path that doesn't exist.
	cfgPath := filepath.Join(clientWorkDir, "appliance.yaml")
	defaultCfg, err := os.ReadFile(filepath.Join(repoGoRoot(t), "config", "appliance.yaml"))
	if err != nil {
		t.Fatalf("reading default appliance.yaml: %v", err)
	}
	if err := os.WriteFile(cfgPath, defaultCfg, 0o666); err != nil {
		t.Fatal(err)
	}
	// The repo's own schema/migrations dir lives under /root, not
	// reachable by the unprivileged client -- copy it into the shared
	// world-readable work dir instead.
	migrationsDir := filepath.Join(clientWorkDir, "migrations")
	if err := copyDir(filepath.Join(repoGoRoot(t), "schema", "migrations"), migrationsDir); err != nil {
		t.Fatal(err)
	}
	// Real promotion via the real dns-promote CLI, run as the real
	// configured allowed uid -- the same tool and technique used for
	// the actual live incident recovery.
	promoteOut, err := exec.Command("runuser", "-u", testClientUser, "--",
		mainBin, "dns-promote",
		"-db", dbPath,
		"-config", cfgPath,
		"-migrations", migrationsDir,
		"-hostagent-socket", socketPath,
		"-dns-runtime-dnsdist-addr", dnsdistListenAddr,
		"-dns-runtime-bind-proxy-addr", fmt.Sprintf("127.0.0.1:%d", bindProxyPort),
		"-dry-run=false",
	).CombinedOutput()
	t.Logf("dns-promote output: %s", promoteOut)
	if err != nil {
		t.Fatalf("real promotion failed: %v: %s", err, promoteOut)
	}
	if !strings.Contains(string(promoteOut), `"promoted": true`) {
		t.Fatalf("expected a real successful promotion, got: %s", promoteOut)
	}

	// Confirm the real, freshly-promoted dnsdist actually answers, both
	// UDP and TCP, before we touch the hostagent process at all.
	if out, err := digShort(t, "127.0.0.1", strconv.Itoa(dnsdistPort)); err != nil {
		t.Fatalf("pre-restart UDP query failed: %v (%s)", err, out)
	}
	if out, err := exec.Command("dig", "+tcp", "+time=2", "+tries=2", "+short", "@127.0.0.1", "-p", strconv.Itoa(dnsdistPort), "ads.example.test", "A").Output(); err != nil {
		t.Fatalf("pre-restart TCP query failed: %v (%s)", err, out)
	}

	namedPIDBefore := pgrepOne(t, "named -g -c "+filepath.Join(bindDir, "named.conf"))
	dnsdistPIDBefore := pgrepOne(t, "dnsdist -C "+filepath.Join(stagingDir, "dnsdist.conf"))
	if namedPIDBefore == "" || dnsdistPIDBefore == "" {
		t.Fatalf("expected real named and dnsdist processes to be running after promotion (named=%q dnsdist=%q)", namedPIDBefore, dnsdistPIDBefore)
	}

	// The actual regression proof: SIGTERM the real hostagent process,
	// exactly what a routine binary-swap restart does.
	if err := hostagentCmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signaling hostagent: %v", err)
	}
	select {
	case <-hostagentExited:
	case <-time.After(5 * time.Second):
		t.Fatal("hostagent did not exit within 5s of SIGTERM")
	}

	// named/dnsdist must be the SAME processes, still running, still
	// answering -- not restarted, not killed, not duplicated.
	namedPIDAfter := pgrepOne(t, "named -g -c "+filepath.Join(bindDir, "named.conf"))
	dnsdistPIDAfter := pgrepOne(t, "dnsdist -C "+filepath.Join(stagingDir, "dnsdist.conf"))
	if namedPIDAfter != namedPIDBefore {
		t.Errorf("named PID changed across hostagent restart: before=%q after=%q (want identical -- it must never be touched)", namedPIDBefore, namedPIDAfter)
	}
	if dnsdistPIDAfter != dnsdistPIDBefore {
		t.Errorf("dnsdist PID changed across hostagent restart: before=%q after=%q (want identical -- it must never be touched)", dnsdistPIDBefore, dnsdistPIDAfter)
	}

	if out, err := digShort(t, "127.0.0.1", strconv.Itoa(dnsdistPort)); err != nil {
		t.Errorf("UDP query failed AFTER hostagent restart -- the real incident this test reproduces: %v (%s)", err, out)
	}
	if out, err := exec.Command("dig", "+tcp", "+time=2", "+tries=2", "+short", "@127.0.0.1", "-p", strconv.Itoa(dnsdistPort), "ads.example.test", "A").Output(); err != nil {
		t.Errorf("TCP query failed AFTER hostagent restart: %v (%s)", err, out)
	}
}

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o777); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o777); err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := copyFile(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), 0o666); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode)
}

func lookupUID(username string) (int, error) {
	out, err := exec.Command("id", "-u", username).Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

// pgrepOne returns the single PID matching pattern via `pgrep -f`, or
// "" if none/more than one (ambiguous -- callers treat that as "not
// found" rather than guessing).
func pgrepOne(t *testing.T, pattern string) string {
	t.Helper()
	out, err := exec.Command("pgrep", "-f", pattern).Output()
	if err != nil {
		return ""
	}
	lines := strings.Fields(strings.TrimSpace(string(out)))
	if len(lines) != 1 {
		return ""
	}
	return lines[0]
}
