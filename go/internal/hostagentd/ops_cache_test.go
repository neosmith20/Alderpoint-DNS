package hostagentd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// startTestBind launches a real, throwaway `named` process (a
// completely separate instance from anything this appliance runs,
// listening only on 127.0.0.1 with a random free port) so this
// package's rndc-flush code can be proven against a genuine BIND
// control channel, not a mock. Skips if named/rndc/rndc-confgen aren't
// available.
func startTestBind(t *testing.T) (rndcConfPath string, rndcPort int) {
	t.Helper()
	for _, bin := range []string{"named", "rndc", "rndc-confgen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available in this environment", bin)
		}
	}
	// named runs under this host's own AppArmor profile regardless of
	// how it's invoked, confined to a fixed allowlist of paths
	// (/var/lib/bind/**, /etc/bind/**, ...) that does not include
	// /tmp -- a real environment constraint this test hit directly, not
	// a Go testing convention. /var/lib/bind is real, read-write, and
	// already allowed, so the disposable test instance's files live
	// there instead of t.TempDir().
	dir := filepath.Join("/var/lib/bind", fmt.Sprintf("hostagentd-test-%d", os.Getpid()), t.Name())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot create test dir under /var/lib/bind (no permission in this environment?): %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	// A random high port for both the DNS listener (unused by these
	// tests but named needs one) and the rndc control channel.
	dnsPort := freeTCPPort(t)
	rndcPort = freeTCPPort(t)

	keyOut, err := exec.Command("rndc-confgen", "-a", "-c", filepath.Join(dir, "rndc.key"), "-A", "hmac-sha256").CombinedOutput()
	if err != nil {
		t.Skipf("rndc-confgen failed (no permission in this environment?): %v: %s", err, keyOut)
	}

	namedConf := fmt.Sprintf(`
options {
    directory %q;
    listen-on port %d { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    pid-file %q;
};
include %q;
controls {
    inet 127.0.0.1 port %d allow { 127.0.0.1; } keys { "rndc-key"; };
};
`, dir, dnsPort, filepath.Join(dir, "named.pid"), filepath.Join(dir, "rndc.key"), rndcPort)
	namedConfPath := filepath.Join(dir, "named.conf")
	if err := os.WriteFile(namedConfPath, []byte(namedConf), 0o644); err != nil {
		t.Fatal(err)
	}

	rndcConf := fmt.Sprintf(`
include %q;
options {
    default-server 127.0.0.1;
    default-port %d;
    default-key "rndc-key";
};
`, filepath.Join(dir, "rndc.key"), rndcPort)
	rndcConfPath = filepath.Join(dir, "rndc.conf")
	if err := os.WriteFile(rndcConfPath, []byte(rndcConf), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("named", "-c", namedConfPath, "-g", "-f")
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start a real test named instance: %v", err)
	}
	go io.Copy(io.Discard, stderr)
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if probeTCP(rndcPort, 200*time.Millisecond) {
			return rndcConfPath, rndcPort
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Skip("test named instance never became reachable on its rndc port")
	return "", 0
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestCacheStatusReportsRealReachabilityAndRNDCStatus(t *testing.T) {
	rndcConfPath, rndcPort := startTestBind(t)

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterCacheOps(s, CacheConfig{
		RNDCConfPath: rndcConfPath,
		Contexts:     []BindContext{{Name: "ctx0", RNDCPort: rndcPort, StatsPort: 0}},
	})

	result, err := s.handlers["cache.status"](context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	var decoded struct {
		Bind []BindContext `json:"bind"`
	}
	json.Unmarshal(encoded, &decoded)
	if len(decoded.Bind) != 1 || !decoded.Bind[0].Reachable {
		t.Fatalf("expected the real test BIND instance to be reported reachable, got %+v", decoded.Bind)
	}
	if decoded.Bind[0].RNDCStatus == "" {
		t.Fatalf("expected a real rndc status line, got empty: %+v", decoded.Bind[0])
	}
}

func TestCacheStatusOfAnUnreachableContextReportsFalseHonestly(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterCacheOps(s, CacheConfig{
		RNDCConfPath: "/nonexistent/rndc.conf",
		Contexts:     []BindContext{{Name: "ctx0", RNDCPort: freeTCPPort(t)}}, // a real free port -- genuinely nothing listening
	})
	result, err := s.handlers["cache.status"](context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	var decoded struct {
		Bind []BindContext `json:"bind"`
	}
	json.Unmarshal(encoded, &decoded)
	if decoded.Bind[0].Reachable {
		t.Fatal("expected Reachable=false for a port nothing is listening on")
	}
}

func TestCacheFlushPerformsARealFlushAgainstTheTestBindInstance(t *testing.T) {
	rndcConfPath, rndcPort := startTestBind(t)

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterCacheOps(s, CacheConfig{
		RNDCConfPath: rndcConfPath,
		Contexts:     []BindContext{{Name: "ctx0", RNDCPort: rndcPort}},
	})

	result, err := s.handlers["cache.flush"](context.Background(), json.RawMessage(`{"layer":"bind","scope":"all"}`))
	if err != nil {
		t.Fatalf("expected a real successful flush against the test instance, got: %v", err)
	}
	encoded, _ := json.Marshal(result)
	var decoded struct {
		Results []struct {
			Context string `json:"context"`
			OK      bool   `json:"ok"`
		} `json:"results"`
	}
	json.Unmarshal(encoded, &decoded)
	if len(decoded.Results) != 1 || !decoded.Results[0].OK {
		t.Fatalf("expected a real successful flush result, got %+v", decoded.Results)
	}
}

func TestCacheFlushRejectsAnUnknownContext(t *testing.T) {
	rndcConfPath, rndcPort := startTestBind(t)
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterCacheOps(s, CacheConfig{RNDCConfPath: rndcConfPath, Contexts: []BindContext{{Name: "ctx0", RNDCPort: rndcPort}}})

	_, err := s.handlers["cache.flush"](context.Background(), json.RawMessage(`{"layer":"bind","context":"not-a-real-context"}`))
	if err == nil {
		t.Fatal("expected an error for an unknown context")
	}
}

func TestCacheFlushRejectsInvalidScope(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterCacheOps(s, CacheConfig{RNDCConfPath: "/x", Contexts: []BindContext{{Name: "ctx0", RNDCPort: 1}}})
	_, err := s.handlers["cache.flush"](context.Background(), json.RawMessage(`{"layer":"bind","scope":"everything"}`))
	if err == nil {
		t.Fatal("expected an error for an invalid scope")
	}
}

func TestCacheFlushOfDnsdistIsHonestlyDeniedNotFaked(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterCacheOps(s, CacheConfig{})
	_, err := s.handlers["cache.flush"](context.Background(), json.RawMessage(`{"layer":"dnsdist"}`))
	if err == nil {
		t.Fatal("expected dnsdist flush to be denied, not silently succeed")
	}
}

func TestCacheFlushRejectsUnknownLayer(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterCacheOps(s, CacheConfig{})
	_, err := s.handlers["cache.flush"](context.Background(), json.RawMessage(`{"layer":"named"}`))
	if err == nil {
		t.Fatal("expected an error for an unknown layer")
	}
}
