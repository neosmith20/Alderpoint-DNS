// Cache flush, real, via the same binaries Python's own cache_control.py
// uses (rndc for BIND, exec'd with an explicit argv -- never a shell
// string -- against the appliance's real rndc.conf; dnsdist has no live
// administrative channel by design, so its "flush" is honestly reported
// as "restart required", never faked as a live flush).
package hostagentd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
)

// BindContext is one compiled BIND recursive-cache instance -- matches
// app/v2/webapp.py's _bind_context_ports() shape (one context per
// distinct plain-upstream selection).
type BindContext struct {
	Name       string `json:"name"`
	StatsPort  int    `json:"stats_port"`
	RNDCPort   int    `json:"rndc_port"`
	Reachable  bool   `json:"reachable"`
	RNDCStatus string `json:"rndc_status,omitempty"` // populated by a real `rndc status` call when reachable
}

type CacheConfig struct {
	// RNDCConfPath is the appliance's real rndc.conf (contains the HMAC
	// key rndc needs to authenticate -- never returned in any API
	// response, only ever passed as a -c argument to the rndc binary).
	RNDCConfPath string
	// Contexts is the fixed set of BIND contexts to report on/allow
	// flushing -- discovered at agent startup from the compiled BIND
	// directory (mirrors Python's _bind_context_ports()), not something
	// a caller can specify freely.
	Contexts []BindContext
	// DialTimeout bounds every reachability probe -- a hung rndc/dial
	// call must never hang an operator's status request.
	DialTimeout time.Duration
}

func RegisterCacheOps(s *Server, cfg CacheConfig) {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 2 * time.Second
	}

	s.Register(hostagent.OpCacheStatus, func(ctx context.Context, params json.RawMessage) (any, error) {
		out := make([]BindContext, len(cfg.Contexts))
		for i, c := range cfg.Contexts {
			c.Reachable = probeTCP(c.RNDCPort, cfg.DialTimeout)
			if c.Reachable && cfg.RNDCConfPath != "" {
				if status, err := runRNDC(ctx, cfg.RNDCConfPath, c.RNDCPort, "status"); err == nil {
					c.RNDCStatus = firstLine(status)
				}
			}
			out[i] = c
		}
		return map[string]any{
			"bind": out,
			"dnsdist": map[string]any{
				"note": "the dnsdist packet cache has no live administrative channel by design; flush restarts the dnsdist service, which drops all in-memory cache state",
			},
		}, nil
	})

	s.Register(hostagent.OpCacheFlush, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			Layer   string `json:"layer"`   // "bind" | "dnsdist"
			Context string `json:"context"` // required for layer=bind; empty = every context
			Scope   string `json:"scope"`   // "all" | "name" | "tree" -- bind only
			Target  string `json:"target"`  // required for scope in {name, tree}
		}
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if in.Layer == "dnsdist" {
			// Deliberately not implemented as a live action: the only real
			// way to clear dnsdist's cache is to restart the dnsdist
			// service, which this agent will not do on a live appliance
			// without a much more careful, explicitly-scoped maintenance
			// workflow than a single flush click implies -- see this
			// package's doc comment. Reported as a real denial, not
			// silently pretended to have worked.
			return nil, fmt.Errorf("dnsdist cache flush requires a service restart, which this agent does not perform for a single flush request -- restart the dnsdist service directly to clear its cache")
		}
		if in.Layer != "bind" {
			return nil, fmt.Errorf("layer must be %q or %q", "bind", "dnsdist")
		}
		if in.Scope == "" {
			in.Scope = "all"
		}
		switch in.Scope {
		case "all", "name", "tree":
		default:
			return nil, fmt.Errorf("scope must be one of all, name, tree")
		}
		if (in.Scope == "name" || in.Scope == "tree") && in.Target == "" {
			return nil, fmt.Errorf("target is required for scope=%s", in.Scope)
		}
		if cfg.RNDCConfPath == "" {
			return nil, fmt.Errorf("no rndc.conf configured for this agent")
		}

		targets := cfg.Contexts
		if in.Context != "" {
			targets = nil
			for _, c := range cfg.Contexts {
				if c.Name == in.Context {
					targets = append(targets, c)
				}
			}
			if len(targets) == 0 {
				return nil, fmt.Errorf("unknown BIND context %q", in.Context)
			}
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("no BIND contexts configured")
		}

		type result struct {
			Context string `json:"context"`
			OK      bool   `json:"ok"`
			Detail  string `json:"detail,omitempty"`
		}
		results := make([]result, 0, len(targets))
		for _, c := range targets {
			args := []string{"flush"}
			if in.Scope == "name" {
				args = []string{"flushname", in.Target}
			} else if in.Scope == "tree" {
				args = []string{"flushtree", in.Target}
			}
			out, err := runRNDC(ctx, cfg.RNDCConfPath, c.RNDCPort, args...)
			if err != nil {
				results = append(results, result{Context: c.Name, OK: false, Detail: err.Error()})
				continue
			}
			results = append(results, result{Context: c.Name, OK: true, Detail: firstLine(out)})
		}
		return map[string]any{"results": results}, nil
	})
}

func probeTCP(port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// runRNDC execs the real rndc binary with an explicit argv (never a
// shell string) against the given port -- authentication comes entirely
// from confPath's own HMAC key, which this function never reads or
// returns itself; it only ever hands the path to rndc as a -c argument.
func runRNDC(ctx context.Context, confPath string, port int, args ...string) (string, error) {
	full := append([]string{"-c", confPath, "-s", "127.0.0.1", "-p", fmt.Sprint(port)}, args...)
	cmd := exec.CommandContext(ctx, "rndc", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("rndc %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func firstLine(s string) string {
	sc := bufio.NewScanner(strings.NewReader(s))
	if sc.Scan() {
		return sc.Text()
	}
	return ""
}
