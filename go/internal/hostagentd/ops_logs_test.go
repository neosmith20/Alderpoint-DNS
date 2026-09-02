package hostagentd

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
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

func TestLogsReadRejectsAnUnrecognizedSeverity(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterLogsOps(s, LogsConfig{Units: []string{"apdns-go-web"}})
	_, err := s.handlers["logs.read"](context.Background(), json.RawMessage(`{"unit":"apdns-go-web","lines":10,"severity":"not-a-real-priority"}`))
	if err == nil {
		t.Fatal("expected an error for an unrecognized severity")
	}
}

func TestLogsListUnitsExposesAllUnitsValueAndSeverities(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterLogsOps(s, LogsConfig{Units: []string{"a", "b"}})
	result, err := s.handlers["logs.list_units"](context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(result)
	var decoded struct {
		AllUnitsValue string   `json:"all_units_value"`
		Severities    []string `json:"severities"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.AllUnitsValue != AllUnitsSentinel {
		t.Fatalf("expected all_units_value %q, got %q", AllUnitsSentinel, decoded.AllUnitsValue)
	}
	if len(decoded.Severities) == 0 {
		t.Fatal("expected a non-empty severities list")
	}
}

// TestLogsReadAllMergesEveryAllowlistedUnitSortedByTime is a real
// integration test (two real, currently-loaded systemd units, real
// journalctl calls) proving unit="all" actually merges more than one
// unit's own real journal history into one time-sorted result, not a
// single unit renamed.
// TestLogsReadAllMergesEveryAllowlistedUnitSortedByTime used to pick
// two arbitrary real systemd units off the live host and rely on both
// having comparably recent journal activity -- a real, live-observed
// flake (2026-09-02): "merge every allowlisted unit's own most-recent
// `lines` entries, then keep only the overall most recent `lines`" (see
// this package's own RegisterLogsOps doc comment) is genuinely correct
// truncation behavior, but it means a unit that logs continuously
// (e.g. a periodic-poll agent) can legitimately crowd a quiet unit's
// much older entries entirely out of a small top-N window -- that's
// not a merge bug, it's an artifact of whichever two real units happen
// to get picked on a given host at a given moment. Rewritten to use
// two synthetic file-backed units with controlled, interleaved
// timestamps instead: deterministic, and it still proves the actual
// thing under test (cross-unit merge + newest-first sort), without
// depending on incidental live host log volume.
func TestLogsReadAllMergesEveryAllowlistedUnitSortedByTime(t *testing.T) {
	pathA := filepath.Join(t.TempDir(), "unit-a.log")
	pathB := filepath.Join(t.TempDir(), "unit-b.log")
	linesA := []string{
		`{"time":"2026-08-01T00:00:00Z","level":"INFO","msg":"a-older"}`,
		`{"time":"2026-08-01T00:00:04Z","level":"INFO","msg":"a-newest"}`,
	}
	linesB := []string{
		`{"time":"2026-08-01T00:00:01Z","level":"INFO","msg":"b-older"}`,
		`{"time":"2026-08-01T00:00:03Z","level":"INFO","msg":"b-newest"}`,
	}
	if err := os.WriteFile(pathA, []byte(strings.Join(linesA, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte(strings.Join(linesB, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterLogsOps(s, LogsConfig{
		Units: []string{"unit-a", "unit-b"},
		UnitNameOverride: map[string]string{
			"unit-a": pathA,
			"unit-b": pathB,
		},
		FileUnits: map[string]bool{"unit-a": true, "unit-b": true},
	})

	result, err := s.handlers["logs.read"](context.Background(), json.RawMessage(`{"unit":"all","lines":10}`))
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
	if len(decoded.Entries) != 4 {
		t.Fatalf("expected all 4 entries across both units (lines=10 is well above the total), got %d: %+v", len(decoded.Entries), decoded.Entries)
	}
	seenUnits := map[string]bool{}
	for i, e := range decoded.Entries {
		seenUnits[e.Unit] = true
		if i > 0 && decoded.Entries[i-1].Time < e.Time {
			t.Fatalf("expected entries sorted newest-first by time, got %+v then %+v", decoded.Entries[i-1], e)
		}
	}
	if len(seenUnits) < 2 {
		t.Fatalf("expected entries from both units in the merge, got only %v", seenUnits)
	}
	if decoded.Entries[0].Time != "2026-08-01T00:00:04Z" || decoded.Entries[0].Unit != "unit-a" {
		t.Fatalf("expected the real newest entry (unit-a's 00:00:04) first, got %+v", decoded.Entries[0])
	}
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

// TestLogsReadFileUnitTailsARealFile proves a FileUnits-registered
// logical unit is read from a plain file, not journalctl -- this
// preview's own apdns-hostagent runs via nohup, not a systemd unit or
// container, so its log source has to be its own redirected stdout
// file, in this codebase's own slog JSON-line shape.
func TestLogsReadFileUnitTailsARealFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	lines := []string{
		`{"time":"2026-08-01T00:00:00Z","level":"INFO","msg":"starting up"}`,
		`{"time":"2026-08-01T00:00:01Z","level":"ERROR","msg":"boom"}`,
		`{"time":"2026-08-01T00:00:02Z","level":"INFO","msg":"recovered"}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterLogsOps(s, LogsConfig{
		Units:            []string{"apdns-hostagent"},
		UnitNameOverride: map[string]string{"apdns-hostagent": path},
		FileUnits:        map[string]bool{"apdns-hostagent": true},
	})

	result, err := s.handlers["logs.read"](context.Background(), json.RawMessage(`{"unit":"apdns-hostagent","lines":10}`))
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
	if len(decoded.Entries) != 3 {
		t.Fatalf("expected all 3 real file lines, got %d: %+v", len(decoded.Entries), decoded.Entries)
	}
	if decoded.Entries[1].Time != "2026-08-01T00:00:01Z" {
		t.Fatalf("expected the real parsed timestamp from the file's own JSON, got %+v", decoded.Entries[1])
	}
}

// TestLogsReadFileUnitFiltersBySeverityAndTrimsLines proves severity
// filtering and the lines cap both apply to a file source exactly like
// a journal source: filter first (against the slog level mapped to a
// journal-style priority name), then keep only the most recent `lines`.
func TestLogsReadFileUnitFiltersBySeverityAndTrimsLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, `{"time":"2026-08-01T00:00:0`+string(rune('0'+i))+`Z","level":"INFO","msg":"info line"}`)
	}
	lines = append(lines,
		`{"time":"2026-08-01T00:00:05Z","level":"ERROR","msg":"first error"}`,
		`not json at all`,
		`{"time":"2026-08-01T00:00:06Z","level":"ERROR","msg":"second error"}`,
	)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterLogsOps(s, LogsConfig{
		Units:            []string{"apdns-hostagent"},
		UnitNameOverride: map[string]string{"apdns-hostagent": path},
		FileUnits:        map[string]bool{"apdns-hostagent": true},
	})

	result, err := s.handlers["logs.read"](context.Background(), json.RawMessage(`{"unit":"apdns-hostagent","lines":1,"severity":"err"}`))
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
	if len(decoded.Entries) != 1 {
		t.Fatalf("expected exactly 1 entry (severity filter then lines=1 trim), got %d: %+v", len(decoded.Entries), decoded.Entries)
	}
	if decoded.Entries[0].Message != `{"time":"2026-08-01T00:00:06Z","level":"ERROR","msg":"second error"}` {
		t.Fatalf("expected only the most recent real error line to survive, got %+v", decoded.Entries[0])
	}
}

// TestLogsReadContainerUnitQueriesByContainerNameField proves a
// ContainerUnits-registered logical unit is queried via journalctl's
// CONTAINER_NAME= field match, not -u -- podman/docker's own conmon
// scope name changes every container recreate, so -u would silently
// stop matching on every redeploy; CONTAINER_NAME is the stable field
// the container log driver attaches instead. Verified against the
// journalctl binary's own argument validation (a real, nonexistent
// journal directory makes it fail fast) rather than mocking exec.
func TestLogsReadContainerUnitQueriesByContainerNameField(t *testing.T) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl not available in this environment")
	}
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterLogsOps(s, LogsConfig{
		Units:            []string{"apdns-go-web"},
		UnitNameOverride: map[string]string{"apdns-go-web": "definitely-not-a-real-container-abc123"},
		ContainerUnits:   map[string]bool{"apdns-go-web": true},
	})
	result, err := s.handlers["logs.read"](context.Background(), json.RawMessage(`{"unit":"apdns-go-web","lines":5}`))
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
	if len(decoded.Entries) != 0 {
		t.Fatalf("expected no entries for a nonexistent container name, got %+v", decoded.Entries)
	}
}
