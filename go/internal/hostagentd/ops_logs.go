package hostagentd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
)

// logSeverities is journalctl's own syslog priority names (journalctl -p
// accepts either these or 0-7). Anything else is rejected before ever
// reaching exec -- same allowlist discipline as the unit name.
var logSeverities = map[string]bool{
	"emerg": true, "alert": true, "crit": true, "err": true,
	"warning": true, "notice": true, "info": true, "debug": true,
}

// AllUnitsSentinel is the unit value that means "every allowlisted unit,
// merged". Python's own log viewer (app/v2/log_viewer.py) has no such
// option -- one named unit at a time only -- so this is a real V2-only
// enhancement, not a parity requirement; it exists because operators
// reading logs during an incident want a single merged, time-sorted
// view rather than switching units one at a time.
const AllUnitsSentinel = "all"

// LogUnits is the fixed allowlist of logical unit names this agent will
// ever read logs for -- matching the spirit of app/v2/log_viewer.py's
// own ALLOWED_UNITS (a caller-supplied unit name is never passed to
// journalctl directly; only a name already in this list is accepted).
var LogUnits = []string{
	"apdns-go-web",
	"apdns-hostagent",
}

type LogsConfig struct {
	// Units is the fixed allowlist of logical unit names this agent
	// will read logs for -- defaults to LogUnits when nil, overridable
	// for tests.
	Units []string
	// JournalDir, if set, points journalctl at an explicit journal
	// directory (`journalctl --directory=...`) instead of the host's
	// own default journal -- used in this preview/testing deployment,
	// where the units being inspected run inside a container whose
	// journal isn't the host's own (mounted read-only into the agent's
	// view via /proc/<pid>/root, the same real, verified pattern this
	// package's caller documents). Empty means "read the host's own
	// default journal", the normal case once this agent runs natively
	// alongside the units it manages, post-cutover.
	JournalDir string
	// UnitNameOverride lets a deployment map the logical unit names
	// above to the real name running in this environment. What that
	// name means depends on the logical unit's entry in ContainerUnits/
	// FileUnits below: a real systemd unit name (the default, and the
	// eventual native "apdns-go-web.service" post-cutover shape), a
	// container name, or a plain log file path. nil/empty means use the
	// logical name verbatim as a systemd unit name.
	UnitNameOverride map[string]string
	// ContainerUnits marks which logical units are podman/docker
	// containers logged via journald rather than a real systemd unit --
	// journalctl -u doesn't match these: the container runtime's own
	// conmon scope name is per-instance and changes on every recreate,
	// so matching against it would break on every redeploy. journald's
	// container log driver instead attaches a stable CONTAINER_NAME=
	// field, which is what this queries against for these units. The
	// container name comes from UnitNameOverride for the logical unit.
	ContainerUnits map[string]bool
	// FileUnits marks which logical units are read from a plain log
	// file rather than the journal at all -- for a process that isn't
	// run as a systemd unit or container (this preview's own
	// apdns-hostagent, whose stdout/stderr the deploy script redirects
	// to a file since it runs via nohup, not systemd). The file path
	// comes from UnitNameOverride for the logical unit. Lines are
	// expected to be this codebase's own slog JSON format (a bare
	// "time"/"level"/"msg" object); a line that doesn't parse as JSON
	// is still shown as raw text but can't be severity-filtered.
	FileUnits map[string]bool
}

type LogEntry struct {
	Unit    string `json:"unit"`
	Time    string `json:"time"`
	Message string `json:"message"`
}

// journalJSONLine is the subset of journalctl -o json fields this
// package actually uses. MESSAGE can be either a JSON string or (for
// binary-safe transport of non-UTF8 output) a JSON array of byte
// values -- journalctl's own documented behavior -- so it's decoded via
// json.RawMessage and handled explicitly, not assumed to always be a
// plain string.
type journalJSONLine struct {
	RealtimeTimestamp string          `json:"__REALTIME_TIMESTAMP"`
	Message           json.RawMessage `json:"MESSAGE"`
}

func decodeMessage(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var bytesArr []byte
	if err := json.Unmarshal(raw, &bytesArr); err == nil {
		return string(bytesArr)
	}
	return ""
}

func RegisterLogsOps(s *Server, cfg LogsConfig) {
	units := cfg.Units
	if units == nil {
		units = LogUnits
	}
	allowed := map[string]bool{}
	for _, u := range units {
		allowed[u] = true
	}

	s.Register(hostagent.OpLogsListUnits, func(ctx context.Context, params json.RawMessage) (any, error) {
		severities := make([]string, 0, len(logSeverities))
		for sev := range logSeverities {
			severities = append(severities, sev)
		}
		sort.Strings(severities)
		return map[string]any{"units": units, "all_units_value": AllUnitsSentinel, "severities": severities}, nil
	})

	readUnit := func(ctx context.Context, logicalUnit string, lines int, severity string) ([]LogEntry, error) {
		realUnit := logicalUnit
		if cfg.UnitNameOverride != nil {
			if mapped, ok := cfg.UnitNameOverride[logicalUnit]; ok {
				realUnit = mapped
			}
		}

		if cfg.FileUnits[logicalUnit] {
			return readFileUnit(realUnit, logicalUnit, lines, severity)
		}

		var args []string
		if cfg.ContainerUnits[logicalUnit] {
			// A field match, not -u: see ContainerUnits' doc comment.
			args = []string{"CONTAINER_NAME=" + realUnit, "-n", strconv.Itoa(lines), "-o", "json", "--no-pager"}
		} else {
			args = []string{"-u", realUnit, "-n", strconv.Itoa(lines), "-o", "json", "--no-pager"}
		}
		if severity != "" {
			args = append(args, "-p", severity)
		}
		if cfg.JournalDir != "" {
			args = append([]string{"--directory=" + cfg.JournalDir}, args...)
		}
		// argv-based exec.Command only -- never a shell string built from
		// caller input (unit, lines, and severity are all validated
		// against fixed allowlists before ever reaching this call).
		out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
		if err != nil {
			return nil, fmt.Errorf("journalctl failed: %w", err)
		}
		entries := []LogEntry{}
		sc := bufio.NewScanner(bytes.NewReader(out))
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			var line journalJSONLine
			if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
				continue // one malformed journal line must never fail the whole read
			}
			ts := line.RealtimeTimestamp
			if usec, err := strconv.ParseInt(ts, 10, 64); err == nil {
				ts = time.UnixMicro(usec).UTC().Format(time.RFC3339)
			}
			entries = append(entries, LogEntry{Unit: logicalUnit, Time: ts, Message: decodeMessage(line.Message)})
		}
		return entries, nil
	}

	s.Register(hostagent.OpLogsRead, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			Unit     string `json:"unit"`
			Lines    int    `json:"lines"`
			Severity string `json:"severity"`
		}
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if in.Lines <= 0 || in.Lines > 2000 {
			in.Lines = 200
		}
		if in.Severity != "" && !logSeverities[in.Severity] {
			return nil, fmt.Errorf("severity %q is not a recognized journal priority", in.Severity)
		}

		if in.Unit == AllUnitsSentinel {
			// Merge every allowlisted unit's own most-recent `lines`
			// entries, then keep only the overall most recent `lines` --
			// each unit is queried independently (its own -n cap) so a
			// noisy unit can't starve a quiet one out of the merge before
			// the final sort/trim happens.
			all := []LogEntry{}
			for _, u := range units {
				entries, err := readUnit(ctx, u, in.Lines, in.Severity)
				if err != nil {
					return nil, fmt.Errorf("reading unit %q: %w", u, err)
				}
				all = append(all, entries...)
			}
			sort.SliceStable(all, func(i, j int) bool { return all[i].Time > all[j].Time })
			if len(all) > in.Lines {
				all = all[:in.Lines]
			}
			return map[string]any{"unit": AllUnitsSentinel, "entries": all}, nil
		}

		if !allowed[in.Unit] {
			return nil, fmt.Errorf("unit %q is not in the allowlist", in.Unit)
		}
		entries, err := readUnit(ctx, in.Unit, in.Lines, in.Severity)
		if err != nil {
			return nil, err
		}
		return map[string]any{"unit": in.Unit, "entries": entries}, nil
	})
}

// slogLevelToSeverity maps this codebase's own slog JSON level strings
// (slog.NewJSONHandler's default: "DEBUG"/"INFO"/"WARN"/"ERROR") to the
// closest journalctl-style priority name, so a file-backed log source
// can be filtered by the same severity values as a journal-backed one.
// slog has no "emerg"/"alert"/"crit"/"notice" equivalent -- a request
// for one of those never matches a file source, which is correct (this
// process never logs at those priorities), not a bug.
var slogLevelToSeverity = map[string]string{
	"DEBUG": "debug",
	"INFO":  "info",
	"WARN":  "warning",
	"ERROR": "err",
}

// maxLogFileScanBytes bounds how much of a plain log file is ever read
// into memory for a tail -- only the most recent bytes are considered,
// so an unbounded, ever-growing log file (this preview's own
// hostagent.log has no rotation yet) can never make a single logs.read
// call hold the whole file in memory.
const maxLogFileScanBytes = 8 * 1024 * 1024

// readFileUnit tails a plain log file (this codebase's own slog JSON
// lines, one object per line) rather than the journal -- for a logical
// unit registered in FileUnits, i.e. a process that isn't run as a
// systemd unit or container at all in this deployment. Severity
// filtering happens before the final `lines` trim, matching journalctl's
// own filter-then-limit order (see readUnit).
func readFileUnit(path, logicalUnit string, lines int, severity string) ([]LogEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading log file %q: %w", path, err)
	}
	if len(data) > maxLogFileScanBytes {
		data = data[len(data)-maxLogFileScanBytes:]
	}

	entries := []LogEntry{}
	for _, raw := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var parsed struct {
			Time  string `json:"time"`
			Level string `json:"level"`
		}
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			if severity != "" {
				continue // can't classify an unparsable line -- excluded rather than guessed
			}
			entries = append(entries, LogEntry{Unit: logicalUnit, Message: raw})
			continue
		}
		if severity != "" && slogLevelToSeverity[strings.ToUpper(parsed.Level)] != severity {
			continue
		}
		entries = append(entries, LogEntry{Unit: logicalUnit, Time: parsed.Time, Message: raw})
	}

	if len(entries) > lines {
		entries = entries[len(entries)-lines:]
	}
	return entries, nil
}
