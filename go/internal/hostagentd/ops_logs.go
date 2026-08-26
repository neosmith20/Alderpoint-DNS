package hostagentd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
)

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
	// above to the real unit/syslog-identifier names running in this
	// environment (e.g. the preview's Go container's own conmon-tagged
	// container log, vs. the eventual native "apdns-go-web.service"
	// unit name). nil/empty means use the logical name verbatim.
	UnitNameOverride map[string]string
}

type LogEntry struct {
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
		return map[string]any{"units": units}, nil
	})

	s.Register(hostagent.OpLogsRead, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			Unit  string `json:"unit"`
			Lines int    `json:"lines"`
		}
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if !allowed[in.Unit] {
			return nil, fmt.Errorf("unit %q is not in the allowlist", in.Unit)
		}
		if in.Lines <= 0 || in.Lines > 2000 {
			in.Lines = 200
		}
		realUnit := in.Unit
		if cfg.UnitNameOverride != nil {
			if mapped, ok := cfg.UnitNameOverride[in.Unit]; ok {
				realUnit = mapped
			}
		}

		args := []string{"-u", realUnit, "-n", strconv.Itoa(in.Lines), "-o", "json", "--no-pager"}
		if cfg.JournalDir != "" {
			args = append([]string{"--directory=" + cfg.JournalDir}, args...)
		}
		// argv-based exec.Command only -- never a shell string built
		// from caller input (both in.Unit and in.Lines are validated
		// above before ever reaching this call).
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
			entries = append(entries, LogEntry{Time: ts, Message: decodeMessage(line.Message)})
		}
		return map[string]any{"unit": in.Unit, "entries": entries}, nil
	})
}
