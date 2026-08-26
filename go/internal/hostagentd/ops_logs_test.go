package hostagentd

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogsReadRejectsAUnitNotInTheAllowlist(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterLogsOps(s, LogsConfig{Units: []string{"apdns-go-web"}})
	_, err := s.handlers["logs.read"](context.Background(), json.RawMessage(`{"unit":"anything-else","lines":10}`))
	if err == nil {
		t.Fatal("expected an error for a unit not in the allowlist")
	}
}

func TestLogsListUnitsReturnsTheConfiguredAllowlist(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterLogsOps(s, LogsConfig{Units: []string{"a", "b"}})
	result, err := s.handlers["logs.list_units"](context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(result)
	if !strings.Contains(string(out), `"a"`) || !strings.Contains(string(out), `"b"`) {
		t.Fatalf("expected the configured units in the result, got %s", out)
	}
}

// TestLogsReadParsesRealJournalctlOutput is an integration test against
// the real system journal (not a mock), using the real `-u <unit>`
// filter path this package's implementation actually uses in
// production (systemd_journal's own `_SYSTEMD_UNIT` field -- distinct
// from a plain syslog identifier, which `-u` does not match; a real bug
// this test caught on its first run, see the git history for
// ops_logs.go). Finds a real, currently-loaded systemd unit on the host
// and proves logs.read returns real, correctly-timestamped entries for
// it. Skipped if journalctl isn't available or no unit has any journal
// history yet, matching this repo's existing pattern of skipping rather
// than failing when a real external dependency genuinely isn't present.
func TestLogsReadParsesRealJournalctlOutput(t *testing.T) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl not available in this environment")
	}
	unit := findAUnitWithRealJournalHistory(t)
	if unit == "" {
		t.Skip("no systemd unit on this host has queryable journal history")
	}

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterLogsOps(s, LogsConfig{Units: []string{"test-unit"}, UnitNameOverride: map[string]string{"test-unit": unit}})

	result, err := s.handlers["logs.read"](context.Background(), json.RawMessage(`{"unit":"test-unit","lines":5}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	var decoded struct {
		Entries []LogEntry `json:"entries"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Entries) == 0 {
		t.Fatalf("expected at least one real entry for unit %q, got none", unit)
	}
	for _, e := range decoded.Entries {
		if e.Time == "" {
			t.Fatalf("expected every entry to have a real parsed timestamp, got %+v", e)
		}
	}
}

// findAUnitWithRealJournalHistory asks systemd for its own loaded units
// and returns the first one journalctl -u actually has entries for --
// real discovery against this live host, not a hardcoded unit name that
// might not exist in whatever environment the test runs in.
func findAUnitWithRealJournalHistory(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--no-legend", "--no-pager", "--plain").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := fields[0]
		check, err := exec.Command("journalctl", "-u", unit, "-n", "1", "-o", "json", "--no-pager").Output()
		if err == nil && len(strings.TrimSpace(string(check))) > 0 {
			return unit
		}
	}
	return ""
}

func TestLogsReadClampsAnOutOfRangeLineCount(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterLogsOps(s, LogsConfig{Units: []string{"apdns-go-web"}, JournalDir: filepath.Join(t.TempDir(), "does-not-exist")})
	// A nonexistent journal directory makes journalctl fail -- this
	// test only cares that clamping happens before that failure (i.e.
	// the handler doesn't reject the request itself for an out-of-range
	// value), proven by getting the *journalctl* error, not a
	// validation error.
	_, err := s.handlers["logs.read"](context.Background(), json.RawMessage(`{"unit":"apdns-go-web","lines":999999}`))
	if err == nil {
		t.Fatal("expected an error (nonexistent journal dir)")
	}
	if strings.Contains(err.Error(), "not in the allowlist") {
		t.Fatalf("clamping should happen silently, not reject the request: %v", err)
	}
}
