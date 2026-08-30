// Network Configuration, real, via the `ip` binary (argv-based
// exec.Command only, never a shell string) reporting/mutating one
// explicitly-named interface at a time -- this agent never guesses "the
// default route interface" or applies anything appliance-wide.
//
// Safety: the same auto-revert-watchdog pattern Python's own
// app/v2/network_config.py already uses (a real, proven pattern for
// this exact problem, not reinvented): apply() snapshots the
// interface's current state, applies the proposed change, and starts a
// timer. If confirm() isn't called before the timer fires, rollback()
// runs automatically and restores the snapshot -- a bad change can
// never leave the interface in a broken state longer than the timeout.
// Tested exclusively against a disposable veth interface created for
// that purpose (see ops_network_test.go), never a real NIC.
package hostagentd

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
)

type NetworkConfig struct {
	// AutoRevertTimeout is how long an applied-but-unconfirmed change
	// stays live before this agent automatically reverts it. Matches
	// Python's own ~120s default; overridable for tests.
	AutoRevertTimeout time.Duration
}

type netInterfaceState struct {
	Addresses []string `json:"addresses"` // CIDR strings, e.g. "10.0.0.5/24"
	Gateway   string   `json:"gateway,omitempty"`
}

type pendingChange struct {
	iface       string
	previous    netInterfaceState
	persistSnap *persistSnapshot // nil if persistence was never attempted (unsupported backend, or not requested)
	timer       *time.Timer
}

type networkState struct {
	mu      sync.Mutex
	pending map[string]*pendingChange // keyed by interface name -- one pending change per interface at a time
}

func RegisterNetworkOps(s *Server, cfg NetworkConfig) {
	if cfg.AutoRevertTimeout <= 0 {
		cfg.AutoRevertTimeout = 120 * time.Second
	}
	ns := &networkState{pending: map[string]*pendingChange{}}

	s.Register(hostagent.OpNetworkStatus, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			Interface string `json:"interface"`
		}
		json.Unmarshal(params, &in) // empty is valid: means "every interface"
		return networkStatus(ctx, in.Interface)
	})

	s.Register(hostagent.OpNetworkApply, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			Interface string   `json:"interface"`
			Addresses []string `json:"addresses"`
			Gateway   string   `json:"gateway"`
			// Ipv4/Ipv6/Persist: when Persist is true (the default --
			// omitting it entirely still persists, matching "an owner's
			// network change should survive a reboot unless they
			// deliberately chose otherwise" as the safe default) and at
			// least one of Ipv4/Ipv6 has a real Mode, this call ALSO
			// writes the detected backend's own persistent config
			// (network_persist.go) alongside the live `ip`-based change
			// above -- one shared pending-confirmation/auto-revert/
			// rollback covers both, matching V1.1.1's own real
			// apply_change()/perform_rollback() unified design (read
			// directly from app/network_config.py, not guessed).
			Ipv4    AddrConfig `json:"ipv4"`
			Ipv6    AddrConfig `json:"ipv6"`
			Persist *bool      `json:"persist"`
		}
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if in.Interface == "" {
			return nil, fmt.Errorf("interface is required")
		}
		if len(in.Addresses) == 0 {
			return nil, fmt.Errorf("at least one address is required")
		}
		for _, a := range in.Addresses {
			if !strings.Contains(a, "/") {
				return nil, fmt.Errorf("address %q must be in CIDR form (e.g. 10.0.0.5/24)", a)
			}
		}
		persist := in.Persist == nil || *in.Persist

		ns.mu.Lock()
		if _, exists := ns.pending[in.Interface]; exists {
			ns.mu.Unlock()
			return nil, fmt.Errorf("a network change on %q is already pending confirmation", in.Interface)
		}
		ns.mu.Unlock()

		before, err := readInterfaceState(ctx, in.Interface)
		if err != nil {
			return nil, fmt.Errorf("reading current state of %q: %w", in.Interface, err)
		}

		if err := applyInterfaceState(ctx, in.Interface, netInterfaceState{Addresses: in.Addresses, Gateway: in.Gateway}); err != nil {
			return nil, fmt.Errorf("applying new configuration: %w", err)
		}

		pc := &pendingChange{iface: in.Interface, previous: before}

		var persistResult PersistResult
		if persist && (in.Ipv4.Mode != "" || in.Ipv6.Mode != "") {
			backend := DetectBackend(ctx).Backend
			snap, res, err := persistChange(ctx, backend, in.Interface, in.Ipv4, in.Ipv6)
			if err != nil {
				// The persistent-config half failed -- roll back the
				// live half immediately too (matching V1's own "apply
				// failed, rolling back immediately" behavior) rather
				// than leaving a live change with no way to survive a
				// reboot and no record of why.
				applyInterfaceState(ctx, in.Interface, before)
				if snap != nil {
					restorePersisted(ctx, snap, in.Interface)
				}
				return nil, fmt.Errorf("persisting configuration via %s failed, live change rolled back: %w", backend, err)
			}
			pc.persistSnap = snap
			persistResult = res
		}

		pc.timer = time.AfterFunc(cfg.AutoRevertTimeout, func() {
			ns.mu.Lock()
			cur, still := ns.pending[in.Interface]
			if still && cur == pc {
				delete(ns.pending, in.Interface)
			}
			ns.mu.Unlock()
			if still && cur == pc {
				applyInterfaceState(context.Background(), in.Interface, pc.previous)
				if pc.persistSnap != nil {
					restorePersisted(context.Background(), pc.persistSnap, in.Interface)
				}
				s.Log.Warn("network change auto-reverted (not confirmed in time)", "interface", in.Interface)
				s.Audit.Record(AuditEntry{Time: time.Now(), Op: "network.auto_revert", Detail: "not confirmed within " + cfg.AutoRevertTimeout.String() + ": interface=" + in.Interface, OK: true})
			}
		})
		ns.mu.Lock()
		ns.pending[in.Interface] = pc
		ns.mu.Unlock()

		return map[string]any{
			"status": "applied_pending_confirmation", "interface": in.Interface,
			"auto_revert_seconds": int(cfg.AutoRevertTimeout.Seconds()),
			"persist":             persistResult,
		}, nil
	})

	s.Register(hostagent.OpNetworkConfirm, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			Interface string `json:"interface"`
		}
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		ns.mu.Lock()
		pc, ok := ns.pending[in.Interface]
		if ok {
			pc.timer.Stop()
			delete(ns.pending, in.Interface)
		}
		ns.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("no pending network change for interface %q", in.Interface)
		}
		return map[string]any{"status": "confirmed", "interface": in.Interface}, nil
	})

	s.Register(hostagent.OpNetworkRollback, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			Interface string `json:"interface"`
		}
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		ns.mu.Lock()
		pc, ok := ns.pending[in.Interface]
		if ok {
			pc.timer.Stop()
			delete(ns.pending, in.Interface)
		}
		ns.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("no pending network change for interface %q", in.Interface)
		}
		if err := applyInterfaceState(ctx, in.Interface, pc.previous); err != nil {
			return nil, fmt.Errorf("rollback failed: %w", err)
		}
		if pc.persistSnap != nil {
			if err := restorePersisted(ctx, pc.persistSnap, in.Interface); err != nil {
				return nil, fmt.Errorf("live rollback succeeded but restoring the persistent config failed: %w", err)
			}
		}
		return map[string]any{"status": "rolled_back", "interface": in.Interface}, nil
	})
}

// networkStatus backs OpNetworkStatus. `current` is the real,
// always-safe read-only report (backend detection, active interface,
// IPv4/IPv6 mode+address+gateway) matching V1.1.1's own
// read_current_config() -- see network_backend.go. raw_addr_json is
// kept for backward compatibility with any existing caller of this
// exact field.
func networkStatus(ctx context.Context, iface string) (any, error) {
	args := []string{"-j", "addr", "show"}
	if iface != "" {
		args = append(args, "dev", iface)
	}
	out, err := exec.CommandContext(ctx, "ip", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("ip addr show: %w", err)
	}
	return map[string]any{
		"raw_addr_json": string(out),
		"current":       ReadCurrentNetworkConfig(ctx),
	}, nil
}

func readInterfaceState(ctx context.Context, iface string) (netInterfaceState, error) {
	out, err := exec.CommandContext(ctx, "ip", "-j", "addr", "show", "dev", iface).Output()
	if err != nil {
		return netInterfaceState{}, err
	}
	addrs := parseIPAddrJSON(string(out))
	gw, _ := exec.CommandContext(ctx, "ip", "-4", "route", "show", "dev", iface, "default").Output()
	return netInterfaceState{Addresses: addrs, Gateway: strings.TrimSpace(firstField(string(gw), "via"))}, nil
}

// applyInterfaceState replaces every address currently on iface with
// exactly the given set -- flush, then add each one, then (if given) a
// default route via the gateway on this device. Every step is a single
// argv-based exec.Command; nothing here is ever built as a shell string.
func applyInterfaceState(ctx context.Context, iface string, state netInterfaceState) error {
	if err := exec.CommandContext(ctx, "ip", "addr", "flush", "dev", iface).Run(); err != nil {
		return fmt.Errorf("flushing addresses: %w", err)
	}
	for _, addr := range state.Addresses {
		if err := exec.CommandContext(ctx, "ip", "addr", "add", addr, "dev", iface).Run(); err != nil {
			return fmt.Errorf("adding address %s: %w", addr, err)
		}
	}
	if state.Gateway != "" {
		if err := exec.CommandContext(ctx, "ip", "route", "replace", "default", "via", state.Gateway, "dev", iface).Run(); err != nil {
			return fmt.Errorf("setting default route: %w", err)
		}
	}
	return nil
}

// parseIPAddrJSON pulls just the address/prefixlen pairs out of `ip -j
// addr show`'s JSON -- a tiny hand-rolled extraction (not a full JSON
// struct decode) because this package only ever needs the addr_info
// list, and ip's own JSON shape has enough optional/version-dependent
// fields that a minimal, defensive extraction is more robust here than
// a strict struct.
func parseIPAddrJSON(raw string) []string {
	var docs []map[string]any
	if err := json.Unmarshal([]byte(raw), &docs); err != nil {
		return nil
	}
	var out []string
	for _, doc := range docs {
		infos, _ := doc["addr_info"].([]any)
		for _, infoAny := range infos {
			info, _ := infoAny.(map[string]any)
			local, _ := info["local"].(string)
			prefix, _ := info["prefixlen"].(float64)
			if local != "" {
				out = append(out, fmt.Sprintf("%s/%d", local, int(prefix)))
			}
		}
	}
	return out
}

func firstField(s, after string) string {
	idx := strings.Index(s, after+" ")
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(after)+1:]
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
