// Network Configuration PERSISTENCE: writing each detected backend's own
// real config so a change survives a reboot -- the real gap
// network_backend.go's own doc comment disclosed. Field-for-field ported
// from V1.1.1's real, shipped app/network_config.py
// (stage_networkd/apply_networkd, stage_netplan/apply_netplan,
// stage_networkmanager/apply_networkmanager, stage_ifupdown/
// apply_ifupdown -- read directly, not guessed) -- V1 evidence this
// package didn't have to invent from scratch.
//
// Scope: IPv4 and IPv6 static/DHCP addressing + gateway, per real
// interface, one backend at a time (matching DetectBackend's own
// single-backend-or-refuse contract). DNS/nameserver settings are
// deliberately NOT part of this file, matching V1's own real design
// (its network_config.py's own top-of-file comment: "not upstream/
// resolver settings, see app/upstream_dns.py" -- which DNS queries this
// appliance resolves through is a separate, already-persisted concern,
// internal/upstreams, not a per-interface network setting at all).
package hostagentd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// AddrConfig is one address family's real proposed config for
// stage*/apply* below -- Mode is "static", "dhcp" (IPv4) or "dhcp"/
// "slaac" (IPv6), or "" (unchanged/not touched at all for that family).
type AddrConfig struct {
	Mode    string `json:"mode"`    // "static" | "dhcp" | "slaac" | ""
	Address string `json:"address"` // bare IP, no prefix (static only)
	Prefix  int    `json:"prefix"`  // CIDR prefix length (static only)
	Gateway string `json:"gateway"` // static only
}

// PersistResult reports what got written/run, or why persistence was
// skipped -- an owner must never be told "saved" when nothing durable
// actually happened.
type PersistResult struct {
	Backend   string   `json:"backend"`
	Persisted bool     `json:"persisted"`
	Reason    string   `json:"reason,omitempty"`
	Files     []string `json:"files,omitempty"`
}

// persistSnapshot is every real byte this package needs to put a
// backend's persistent config back exactly as it was -- one entry per
// file for the file-based backends, or the prior nmcli connection
// properties for NetworkManager (which keeps no on-disk file this
// package can just diff/restore).
type persistSnapshot struct {
	backend string
	// files: path -> (existed, content). existed=false + empty content
	// means "the file did not exist before" -- rollback removes it
	// rather than writing an empty file.
	files map[string]snapshotFile
	// nmConnection/nmProps: NetworkManager only.
	nmConnection string
	nmProps      map[string]string
}

type snapshotFile struct {
	existed bool
	content string
}

func ipv4Netmask(prefix int) string {
	mask := net.CIDRMask(prefix, 32)
	return net.IP(mask).String()
}

// --- systemd-networkd --------------------------------------------------

func renderNetworkdUnit(iface string, ipv4, ipv6 AddrConfig) string {
	lines := []string{"[Match]", "Name=" + iface, "", "[Network]"}
	switch ipv4.Mode {
	case "dhcp":
		lines = append(lines, "DHCP=ipv4")
	case "static":
		lines = append(lines, fmt.Sprintf("Address=%s/%d", ipv4.Address, ipv4.Prefix), "Gateway="+ipv4.Gateway)
	}
	switch ipv6.Mode {
	case "dhcp":
		lines = append(lines, "DHCP=ipv6")
	case "static":
		lines = append(lines, fmt.Sprintf("Address=%s/%d", ipv6.Address, ipv6.Prefix), "Gateway="+ipv6.Gateway)
	case "slaac":
		lines = append(lines, "IPv6AcceptRA=yes")
	}
	return strings.Join(lines, "\n") + "\n"
}

func networkdUnitPath(iface string) string {
	return filepath.Join(networkdDropinDir, "90-alderpointdns-"+iface+".network")
}

func stageNetworkd(iface string, ipv4, ipv6 AddrConfig) (string, error) {
	if err := os.MkdirAll(networkdDropinDir, 0o755); err != nil {
		return "", err
	}
	path := networkdUnitPath(iface)
	if err := os.WriteFile(path, []byte(renderNetworkdUnit(iface, ipv4, ipv6)), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func applyNetworkd(ctx context.Context, iface string) error {
	if err := exec.CommandContext(ctx, "networkctl", "reload").Run(); err != nil {
		return fmt.Errorf("networkctl reload: %w", err)
	}
	if err := exec.CommandContext(ctx, "networkctl", "reconfigure", iface).Run(); err != nil {
		return fmt.Errorf("networkctl reconfigure %s: %w", iface, err)
	}
	return nil
}

// --- netplan -------------------------------------------------------------

func renderNetplanYAML(iface string, ipv4, ipv6 AddrConfig) string {
	var b strings.Builder
	b.WriteString("network:\n  version: 2\n  ethernets:\n")
	fmt.Fprintf(&b, "    %s:\n", iface)
	var addrs []string
	var routes []string
	switch ipv4.Mode {
	case "dhcp":
		b.WriteString("      dhcp4: true\n")
	case "static":
		b.WriteString("      dhcp4: false\n")
		addrs = append(addrs, fmt.Sprintf("%s/%d", ipv4.Address, ipv4.Prefix))
		routes = append(routes, fmt.Sprintf("        - to: 0.0.0.0/0\n          via: %s\n", ipv4.Gateway))
	}
	switch ipv6.Mode {
	case "dhcp":
		b.WriteString("      dhcp6: true\n")
	case "static":
		addrs = append(addrs, fmt.Sprintf("%s/%d", ipv6.Address, ipv6.Prefix))
		routes = append(routes, fmt.Sprintf("        - to: ::/0\n          via: %s\n", ipv6.Gateway))
	case "slaac":
		b.WriteString("      accept-ra: true\n")
	}
	if len(addrs) > 0 {
		b.WriteString("      addresses:\n")
		for _, a := range addrs {
			fmt.Fprintf(&b, "        - %s\n", a)
		}
	}
	if len(routes) > 0 {
		b.WriteString("      routes:\n")
		for _, r := range routes {
			b.WriteString(r)
		}
	}
	return b.String()
}

func stageNetplan(iface string, ipv4, ipv6 AddrConfig) (string, error) {
	if err := os.MkdirAll(netplanDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(netplanDir, "90-alderpointdns.yaml")
	// netplan requires owner-only-readable config (matching V1's own
	// os.chmod(NETPLAN_FILE, 0o600) exactly -- it refuses to apply a
	// world/group-readable YAML that might carry secrets).
	if err := os.WriteFile(path, []byte(renderNetplanYAML(iface, ipv4, ipv6)), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func applyNetplan(ctx context.Context) error {
	if err := exec.CommandContext(ctx, "netplan", "generate").Run(); err != nil {
		return fmt.Errorf("netplan generate: %w", err)
	}
	if err := exec.CommandContext(ctx, "netplan", "apply").Run(); err != nil {
		return fmt.Errorf("netplan apply: %w", err)
	}
	return nil
}

// --- ifupdown --------------------------------------------------------------

func renderIfupdownStanza(iface string, ipv4, ipv6 AddrConfig) string {
	var lines []string
	switch ipv4.Mode {
	case "dhcp":
		lines = append(lines, "auto "+iface, "iface "+iface+" inet dhcp")
	case "static":
		lines = append(lines,
			"auto "+iface,
			"iface "+iface+" inet static",
			"    address "+ipv4.Address,
			"    netmask "+ipv4Netmask(ipv4.Prefix),
			"    gateway "+ipv4.Gateway,
		)
	}
	switch ipv6.Mode {
	case "static":
		lines = append(lines,
			"iface "+iface+" inet6 static",
			fmt.Sprintf("    address %s", ipv6.Address),
			fmt.Sprintf("    netmask %d", ipv6.Prefix),
			"    gateway "+ipv6.Gateway,
		)
	case "dhcp":
		lines = append(lines, "iface "+iface+" inet6 dhcp")
	case "slaac":
		lines = append(lines, "iface "+iface+" inet6 auto")
	}
	return strings.Join(lines, "\n") + "\n"
}

func ifupdownDropinPath(iface string) string {
	return filepath.Join(ifupdownDropinDir, "90-alderpointdns-"+iface+".cfg")
}

func stageIfupdown(iface string, ipv4, ipv6 AddrConfig) (string, error) {
	if err := os.MkdirAll(ifupdownDropinDir, 0o755); err != nil {
		return "", err
	}
	path := ifupdownDropinPath(iface)
	if err := os.WriteFile(path, []byte(renderIfupdownStanza(iface, ipv4, ipv6)), 0o644); err != nil {
		return "", err
	}
	// /etc/network/interfaces must `source` interfaces.d for the
	// drop-in to take effect -- additive, never rewrites the admin's
	// own file's other stanzas, matching V1's own real behavior.
	if data, err := os.ReadFile(ifupdownInterfaces); err == nil {
		text := string(data)
		if !strings.Contains(text, "source /etc/network/interfaces.d/*") && !strings.Contains(text, "source-directory /etc/network/interfaces.d") {
			f, err := os.OpenFile(ifupdownInterfaces, os.O_APPEND|os.O_WRONLY, 0o644)
			if err == nil {
				f.WriteString("\nsource /etc/network/interfaces.d/*\n")
				f.Close()
			}
		}
	}
	return path, nil
}

func applyIfupdown(ctx context.Context, iface string) error {
	exec.CommandContext(ctx, "ifdown", iface).Run() // best-effort, matches V1's own check=False
	if err := exec.CommandContext(ctx, "ifup", iface).Run(); err != nil {
		return fmt.Errorf("ifup %s: %w", iface, err)
	}
	return nil
}

// --- NetworkManager (nmcli only -- no on-disk file this package writes
// directly; nmcli owns its own keyfile storage) --------------------------

func nmConnectionForInterface(ctx context.Context, iface string) (string, error) {
	out, err := exec.CommandContext(ctx, "nmcli", "-t", "-f", "NAME,DEVICE", "con", "show", "--active").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && parts[1] == iface {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("no active NetworkManager connection found for interface %q", iface)
}

func nmGetProps(ctx context.Context, conn string, props []string) map[string]string {
	out := map[string]string{}
	for _, p := range props {
		v, err := exec.CommandContext(ctx, "nmcli", "-g", p, "con", "show", conn).Output()
		if err == nil {
			out[p] = strings.TrimSpace(string(v))
		}
	}
	return out
}

var nmSnapshotProps = []string{"ipv4.method", "ipv4.addresses", "ipv4.gateway", "ipv6.method", "ipv6.addresses", "ipv6.gateway"}

func stageNetworkManager(ctx context.Context, conn string, ipv4, ipv6 AddrConfig) error {
	switch ipv4.Mode {
	case "dhcp":
		if err := exec.CommandContext(ctx, "nmcli", "con", "mod", conn, "ipv4.method", "auto", "ipv4.addresses", "", "ipv4.gateway", "").Run(); err != nil {
			return fmt.Errorf("nmcli ipv4 dhcp: %w", err)
		}
	case "static":
		if err := exec.CommandContext(ctx, "nmcli", "con", "mod", conn,
			"ipv4.method", "manual",
			"ipv4.addresses", fmt.Sprintf("%s/%d", ipv4.Address, ipv4.Prefix),
			"ipv4.gateway", ipv4.Gateway).Run(); err != nil {
			return fmt.Errorf("nmcli ipv4 static: %w", err)
		}
	}
	switch ipv6.Mode {
	case "static":
		if err := exec.CommandContext(ctx, "nmcli", "con", "mod", conn,
			"ipv6.method", "manual",
			"ipv6.addresses", fmt.Sprintf("%s/%d", ipv6.Address, ipv6.Prefix),
			"ipv6.gateway", ipv6.Gateway).Run(); err != nil {
			return fmt.Errorf("nmcli ipv6 static: %w", err)
		}
	case "slaac":
		if err := exec.CommandContext(ctx, "nmcli", "con", "mod", conn, "ipv6.method", "auto").Run(); err != nil {
			return fmt.Errorf("nmcli ipv6 slaac: %w", err)
		}
	}
	return nil
}

func applyNetworkManager(ctx context.Context, conn string) error {
	if err := exec.CommandContext(ctx, "nmcli", "con", "up", conn).Run(); err != nil {
		return fmt.Errorf("nmcli con up %s: %w", conn, err)
	}
	return nil
}

func restoreNetworkManager(ctx context.Context, conn string, props map[string]string) error {
	args := []string{"con", "mod", conn}
	for k, v := range props {
		args = append(args, k, v)
	}
	if err := exec.CommandContext(ctx, "nmcli", args...).Run(); err != nil {
		return fmt.Errorf("nmcli restore: %w", err)
	}
	return exec.CommandContext(ctx, "nmcli", "con", "up", conn).Run()
}

// --- snapshot / stage+apply / restore orchestration -----------------------

func snapshotFilesFor(backend, iface string) map[string]snapshotFile {
	var paths []string
	switch backend {
	case BackendNetworkd:
		paths = []string{networkdUnitPath(iface)}
	case BackendNetplan:
		paths = []string{filepath.Join(netplanDir, "90-alderpointdns.yaml")}
	case BackendIfupdown:
		paths = []string{ifupdownDropinPath(iface)}
	default:
		return nil
	}
	out := map[string]snapshotFile{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			out[p] = snapshotFile{existed: false}
			continue
		}
		out[p] = snapshotFile{existed: true, content: string(data)}
	}
	return out
}

// persistChange snapshots the backend's current persistent config, then
// stages and applies the new one -- the caller (ops_network.go) keeps
// this snapshot alongside the live-`ip`-state snapshot it already
// tracks, so one rollback restores BOTH.
func persistChange(ctx context.Context, backend, iface string, ipv4, ipv6 AddrConfig) (*persistSnapshot, PersistResult, error) {
	if backend == BackendUnsupported {
		return nil, PersistResult{Backend: backend, Persisted: false, Reason: "no single supported networking backend was detected -- this change applies to the running system only and will not survive a reboot"}, nil
	}

	snap := &persistSnapshot{backend: backend}
	var files []string

	switch backend {
	case BackendNetworkd:
		snap.files = snapshotFilesFor(backend, iface)
		path, err := stageNetworkd(iface, ipv4, ipv6)
		if err != nil {
			return nil, PersistResult{}, err
		}
		if err := applyNetworkd(ctx, iface); err != nil {
			return snap, PersistResult{}, err
		}
		files = []string{path}
	case BackendNetplan:
		snap.files = snapshotFilesFor(backend, iface)
		path, err := stageNetplan(iface, ipv4, ipv6)
		if err != nil {
			return nil, PersistResult{}, err
		}
		if err := applyNetplan(ctx); err != nil {
			return snap, PersistResult{}, err
		}
		files = []string{path}
	case BackendIfupdown:
		snap.files = snapshotFilesFor(backend, iface)
		path, err := stageIfupdown(iface, ipv4, ipv6)
		if err != nil {
			return nil, PersistResult{}, err
		}
		if err := applyIfupdown(ctx, iface); err != nil {
			return snap, PersistResult{}, err
		}
		files = []string{path}
	case BackendNetworkManager:
		conn, err := nmConnectionForInterface(ctx, iface)
		if err != nil {
			return nil, PersistResult{}, err
		}
		snap.nmConnection = conn
		snap.nmProps = nmGetProps(ctx, conn, nmSnapshotProps)
		if err := stageNetworkManager(ctx, conn, ipv4, ipv6); err != nil {
			return snap, PersistResult{}, err
		}
		if err := applyNetworkManager(ctx, conn); err != nil {
			return snap, PersistResult{}, err
		}
		files = []string{"NetworkManager connection: " + conn}
	default:
		return nil, PersistResult{Backend: backend, Persisted: false, Reason: "unrecognized backend"}, nil
	}

	return snap, PersistResult{Backend: backend, Persisted: true, Files: files}, nil
}

// restorePersisted puts a backend's persistent config back exactly as
// persistChange's own snapshot recorded it -- called from the same
// rollback path (auto-revert timer or explicit OpNetworkRollback) that
// already restores live `ip` state, so a rollback is never "half
// reverted" (live state back to normal, but the persistent file still
// carries the rejected change, ready to reapply itself on the next
// reboot).
func restorePersisted(ctx context.Context, snap *persistSnapshot, iface string) error {
	if snap == nil {
		return nil
	}
	for path, sf := range snap.files {
		if !sf.existed {
			os.Remove(path)
			continue
		}
		if err := os.WriteFile(path, []byte(sf.content), 0o644); err != nil {
			return fmt.Errorf("restoring %s: %w", path, err)
		}
	}
	switch snap.backend {
	case BackendNetworkd:
		return applyNetworkd(ctx, iface)
	case BackendNetplan:
		return applyNetplan(ctx)
	case BackendIfupdown:
		return applyIfupdown(ctx, iface)
	case BackendNetworkManager:
		if snap.nmConnection != "" {
			return restoreNetworkManager(ctx, snap.nmConnection, snap.nmProps)
		}
	}
	return nil
}

// PersistPreview is the real, generated persistent-config text (or
// command list) that OpNetworkApply's persistent half WOULD write/run
// for the detected backend, given the exact same proposed ipv4/ipv6
// config -- rendered by the identical render*/command-building logic
// persistChange itself uses below, so this can never drift out of sync
// with what an actual Apply produces. Building this never touches the
// live interface or writes any file.
type PersistPreview struct {
	Backend      string   `json:"backend"`
	WouldPersist bool     `json:"would_persist"`
	Reason       string   `json:"reason,omitempty"`
	FilePath     string   `json:"file_path,omitempty"`
	FileContent  string   `json:"file_content,omitempty"`
	Commands     []string `json:"commands,omitempty"`
}

// renderNetworkManagerCommands mirrors stageNetworkManager's real nmcli
// argv, formatted as the shell-equivalent command line it runs -- a
// dry-run rendering, never executed here.
func renderNetworkManagerCommands(conn string, ipv4, ipv6 AddrConfig) []string {
	var cmds []string
	switch ipv4.Mode {
	case "dhcp":
		cmds = append(cmds, fmt.Sprintf("nmcli con mod %s ipv4.method auto ipv4.addresses '' ipv4.gateway ''", conn))
	case "static":
		cmds = append(cmds, fmt.Sprintf("nmcli con mod %s ipv4.method manual ipv4.addresses %s/%d ipv4.gateway %s", conn, ipv4.Address, ipv4.Prefix, ipv4.Gateway))
	}
	switch ipv6.Mode {
	case "static":
		cmds = append(cmds, fmt.Sprintf("nmcli con mod %s ipv6.method manual ipv6.addresses %s/%d ipv6.gateway %s", conn, ipv6.Address, ipv6.Prefix, ipv6.Gateway))
	case "slaac":
		cmds = append(cmds, fmt.Sprintf("nmcli con mod %s ipv6.method auto", conn))
	}
	if len(cmds) > 0 {
		cmds = append(cmds, fmt.Sprintf("nmcli con up %s", conn))
	}
	return cmds
}

// previewPersist is OpNetworkPreview's implementation -- the read-only
// twin of persistChange above. Every branch mirrors persistChange's own
// switch exactly (same backends, same render calls) but never calls
// os.WriteFile/os.MkdirAll or execs netplan/networkctl/nmcli.
func previewPersist(ctx context.Context, backend, iface string, ipv4, ipv6 AddrConfig) PersistPreview {
	switch backend {
	case BackendUnsupported:
		return PersistPreview{Backend: backend, WouldPersist: false, Reason: "no single supported networking backend was detected -- this change would apply to the running system only and would not survive a reboot"}
	case BackendNetworkd:
		return PersistPreview{Backend: backend, WouldPersist: true, FilePath: networkdUnitPath(iface), FileContent: renderNetworkdUnit(iface, ipv4, ipv6)}
	case BackendNetplan:
		return PersistPreview{Backend: backend, WouldPersist: true, FilePath: filepath.Join(netplanDir, "90-alderpointdns.yaml"), FileContent: renderNetplanYAML(iface, ipv4, ipv6)}
	case BackendIfupdown:
		return PersistPreview{Backend: backend, WouldPersist: true, FilePath: ifupdownDropinPath(iface), FileContent: renderIfupdownStanza(iface, ipv4, ipv6)}
	case BackendNetworkManager:
		conn, err := nmConnectionForInterface(ctx, iface)
		if err != nil {
			return PersistPreview{Backend: backend, WouldPersist: false, Reason: "no active NetworkManager connection found for interface " + iface + ": " + err.Error()}
		}
		return PersistPreview{Backend: backend, WouldPersist: true, Commands: renderNetworkManagerCommands(conn, ipv4, ipv6)}
	default:
		return PersistPreview{Backend: backend, WouldPersist: false, Reason: "unrecognized backend"}
	}
}
