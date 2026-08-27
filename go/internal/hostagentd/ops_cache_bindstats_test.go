package hostagentd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// startTestBindWithStats is a minimal real named instance with
// statistics-channels enabled -- separate from startTestBind (which
// doesn't need it and every other cache test already depends on its
// exact shape) -- proving fetchBindCacheStats against BIND's own real
// JSON endpoint, not a synthetic HTTP server standing in for it.
func startTestBindWithStats(t *testing.T) (statsPort int) {
	t.Helper()
	for _, bin := range []string{"named"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available in this environment", bin)
		}
	}
	dir := filepath.Join("/var/lib/bind", fmt.Sprintf("hostagentd-bindstats-test-%d", os.Getpid()), t.Name())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot create test dir under /var/lib/bind: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	dnsPort := freeTCPPort(t)
	statsPort = freeTCPPort(t)

	namedConf := fmt.Sprintf(`
options {
    directory %q;
    listen-on port %d { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    pid-file %q;
};
statistics-channels {
    inet 127.0.0.1 port %d allow { 127.0.0.1; };
};
`, dir, dnsPort, filepath.Join(dir, "named.pid"), statsPort)
	namedConfPath := filepath.Join(dir, "named.conf")
	if err := os.WriteFile(namedConfPath, []byte(namedConf), 0o644); err != nil {
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
		if probeTCP(statsPort, 200*time.Millisecond) {
			return statsPort
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Skip("test named instance's statistics-channel never became reachable")
	return 0
}

func TestFetchBindCacheStatsAgainstARealNamedInstance(t *testing.T) {
	statsPort := startTestBindWithStats(t)
	stats := fetchBindCacheStats(context.Background(), statsPort, 2*time.Second)
	if !stats.Available {
		t.Fatalf("expected available=true, got error: %s", stats.Error)
	}
	// A freshly started named with recursion off and no queries yet has
	// zero hits/misses -- proving real parsing of the real JSON shape
	// (not that any particular count appears), same as any other
	// "reports real state, whatever it is" contract in this codebase.
	if stats.Hits < 0 || stats.Misses < 0 {
		t.Errorf("unexpected negative counters: hits=%d misses=%d", stats.Hits, stats.Misses)
	}
	if stats.Hits+stats.Misses == 0 && stats.HitRatio != nil {
		t.Errorf("hit_ratio should be nil when total is zero, got %v", *stats.HitRatio)
	}
}

func TestFetchBindCacheStatsUnreachablePortReportsHonestlyUnavailable(t *testing.T) {
	port := freeTCPPort(t) // nothing listening
	stats := fetchBindCacheStats(context.Background(), port, 300*time.Millisecond)
	if stats.Available {
		t.Error("expected available=false for an unreachable port")
	}
	if stats.Error == "" {
		t.Error("expected a real error message, got empty string")
	}
}

func TestCacheStatusIncludesRealCacheStats(t *testing.T) {
	rndcConfPath, rndcPort := startTestBind(t)
	statsPort := freeTCPPort(t) // startTestBind's own fixture has no statistics-channels -- this proves the honest-unavailable path through the full cache.status op, complementing the real-named proof above

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterCacheOps(s, CacheConfig{
		RNDCConfPath: rndcConfPath,
		Contexts:     []BindContext{{Name: "ctx0", RNDCPort: rndcPort, StatsPort: statsPort}},
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
	if len(decoded.Bind) != 1 {
		t.Fatalf("expected 1 context, got %d", len(decoded.Bind))
	}
	if decoded.Bind[0].CacheStats == nil {
		t.Fatal("expected a non-nil CacheStats field")
	}
	if decoded.Bind[0].CacheStats.Available {
		t.Error("expected CacheStats.Available=false against a port with no statistics-channel listening")
	}
}
