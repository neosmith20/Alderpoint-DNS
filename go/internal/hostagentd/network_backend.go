// Network Configuration read-only reporting: backend detection and
// DHCP-vs-static mode determination, field-matched against V1.1.1's own
// real app/network_config.py (detect_backend/detect_ipv4_mode/
// detect_ipv6_mode/read_current_config, read directly from the shipped
// V1.1.1 package) -- every function here is read-only (systemctl
// is-active, file/glob reads, `ip -json` reads) and never mutates
// anything, unlike ops_network.go's apply/confirm/rollback.
//
// Disclosed, real gap vs V1.1.1, not hidden: V1 could WRITE each
// backend's own persistent config (a netplan YAML drop-in, a networkd
// .network drop-in, an ifupdown stanza, or an NetworkManager connection)
// so a change survived a reboot, and could switch an interface to DHCP
// by handing it back to the owning backend. This package's own
// apply/confirm/rollback (ops_network.go) is real and safe (the same
// auto-revert-on-timeout watchdog V1 used) but is runtime-only, via
// `ip addr`/`ip route` directly -- it does not persist across a reboot,
// and cannot switch an interface to DHCP. Detecting the backend and its
// current mode (this file) is real and safe either way; writing each
// backend's own persistent config and DHCP-switching are real,
// substantial, backend-specific features not attempted in this pass --
// see NetworkView.svelte's own disclosure.
package hostagentd

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	BackendNetworkd       = "systemd-networkd"
	BackendNetworkManager = "NetworkManager"
	BackendIfupdown       = "ifupdown"
	BackendNetplan        = "netplan"
	BackendUnsupported    = "unsupported"
)

var (
	networkdDropinDir  = "/etc/systemd/network"
	netplanDir         = "/etc/netplan"
	ifupdownInterfaces = "/etc/network/interfaces"
	ifupdownDropinDir  = "/etc/network/interfaces.d"
)

type BackendInfo struct {
	Backend   string `json:"backend"`
	Ambiguous bool   `json:"ambiguous"`
	Detail    string `json:"detail"`
}

func systemctlIsActive(ctx context.Context, unit string) bool {
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

func globCount(dir, pattern string) []string {
	matches, _ := filepath.Glob(filepath.Join(dir, pattern))
	return matches
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DetectBackend mirrors V1.1.1's detect_backend() field-for-field,
// including its exact precedence (netplan checked first, since on a
// netplan system netplan's YAML is the real source of truth even though
// the live renderer underneath is networkd or NetworkManager) and its
// "more than one candidate looks active -> unsupported, ambiguous=true,
// never guess" safety rule.
func DetectBackend(ctx context.Context) BackendInfo {
	var candidates []string
	var detail []string

	netplanYAMLs := globCount(netplanDir, "*.yaml")
	if _, err := exec.LookPath("netplan"); err == nil && isDir(netplanDir) && len(netplanYAMLs) > 0 {
		candidates = append(candidates, BackendNetplan)
		detail = append(detail, "netplan binary present, "+itoa(len(netplanYAMLs))+" yaml file(s) in "+netplanDir)
	}

	if systemctlIsActive(ctx, BackendNetworkManager+".service") {
		candidates = append(candidates, BackendNetworkManager)
		detail = append(detail, "NetworkManager.service is active")
	}

	if systemctlIsActive(ctx, BackendNetworkd+".service") && !containsStr(candidates, BackendNetplan) {
		candidates = append(candidates, BackendNetworkd)
		detail = append(detail, "systemd-networkd.service is active")
	}

	if !containsStr(candidates, BackendNetplan) && !containsStr(candidates, BackendNetworkManager) && !containsStr(candidates, BackendNetworkd) && fileExists(ifupdownInterfaces) {
		candidates = append(candidates, BackendIfupdown)
		detail = append(detail, ifupdownInterfaces+" exists and no other backend is active")
	}

	switch len(candidates) {
	case 1:
		return BackendInfo{Backend: candidates[0], Ambiguous: false, Detail: strings.Join(detail, "; ")}
	case 0:
		return BackendInfo{Backend: BackendUnsupported, Ambiguous: false, Detail: "no supported networking backend detected"}
	default:
		return BackendInfo{Backend: BackendUnsupported, Ambiguous: true, Detail: "multiple networking backends appear active (" + strings.Join(candidates, ", ") + "); refusing to guess"}
	}
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

var (
	networkdNameRe  = regexp.MustCompile(`(?m)^\s*Name\s*=\s*(\S+)\s*$`)
	networkdDHCPRe  = regexp.MustCompile(`(?im)^\s*DHCP\s*=\s*(yes|ipv4|ipv6)\s*$`)
	networkdAddrRe  = regexp.MustCompile(`(?m)^\s*Address\s*=`)
	networkdAddr6Re = regexp.MustCompile(`(?m)^\s*Address\s*=.*:.*$`)
	ifupdownIfaceRe = func(iface string) *regexp.Regexp {
		return regexp.MustCompile(`(?m)^\s*iface\s+` + regexp.QuoteMeta(iface) + `\s+inet\s+(\w+)`)
	}
	netplanDHCP4Re  = regexp.MustCompile(`dhcp4:\s*true`)
	netplanDHCP6Re  = regexp.MustCompile(`dhcp6:\s*true`)
	netplanAddrsRe  = regexp.MustCompile(`addresses:`)
	netplanAcceptRA = regexp.MustCompile(`accept-ra:\s*true`)
)

// networkdBlockForInterface returns the text of the [Network]-style
// stanza block matching `Name=<interface>` inside one .network file, or
// "" if that file doesn't mention this interface. A lightweight
// block-scan (not a full ini parser), matching V1's own regex-per-file
// approach.
func networkdBlockForInterface(text, iface string) (string, bool) {
	if !networkdNameRe.MatchString(text) {
		return "", false
	}
	for _, m := range networkdNameRe.FindAllStringSubmatch(text, -1) {
		if m[1] == iface {
			return text, true
		}
	}
	return "", false
}

// DetectIPv4Mode mirrors V1.1.1's detect_ipv4_mode() -- best-effort,
// read-only, "unknown" (never guessed) if it can't be determined from
// the owning backend's own real config.
func DetectIPv4Mode(backend, iface string) string {
	switch backend {
	case BackendNetworkd:
		for _, path := range globCount(networkdDropinDir, "*.network") {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			text, ok := networkdBlockForInterface(string(data), iface)
			if !ok {
				continue
			}
			if networkdDHCPRe.MatchString(text) {
				return "dhcp"
			}
			if networkdAddrRe.MatchString(text) {
				return "static"
			}
		}
	case BackendNetworkManager:
		if _, err := exec.LookPath("nmcli"); err == nil {
			out, err := exec.Command("nmcli", "-t", "-f", "ipv4.method", "con", "show", iface).Output()
			if err == nil {
				s := string(out)
				if strings.Contains(s, "auto") {
					return "dhcp"
				}
				if strings.Contains(s, "manual") {
					return "static"
				}
			}
		}
	case BackendIfupdown:
		paths := []string{ifupdownInterfaces}
		if isDir(ifupdownDropinDir) {
			paths = append(paths, globCount(ifupdownDropinDir, "*")...)
		}
		re := ifupdownIfaceRe(iface)
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if m := re.FindStringSubmatch(string(data)); m != nil {
				switch m[1] {
				case "dhcp":
					return "dhcp"
				case "static":
					return "static"
				default:
					return "unknown"
				}
			}
		}
	case BackendNetplan:
		if isDir(netplanDir) {
			for _, path := range globCount(netplanDir, "*.yaml") {
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				text := string(data)
				if !strings.Contains(text, iface) {
					continue
				}
				if netplanDHCP4Re.MatchString(text) {
					return "dhcp"
				}
				if netplanAddrsRe.MatchString(text) {
					return "static"
				}
			}
		}
	}
	return "unknown"
}

// DetectIPv6Mode mirrors V1.1.1's detect_ipv6_mode() -- same
// best-effort/never-guess shape, plus "slaac" (router-advertised),
// which reads as neither a classic dhcp nor static stanza.
func DetectIPv6Mode(backend, iface string) string {
	switch backend {
	case BackendNetworkd:
		for _, path := range globCount(networkdDropinDir, "*.network") {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			text, ok := networkdBlockForInterface(string(data), iface)
			if !ok {
				continue
			}
			if networkdDHCPRe.MatchString(text) {
				return "dhcp"
			}
			if networkdAddr6Re.MatchString(text) {
				return "static"
			}
			return "slaac"
		}
	case BackendNetplan:
		if isDir(netplanDir) {
			for _, path := range globCount(netplanDir, "*.yaml") {
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				text := string(data)
				if !strings.Contains(text, iface) {
					continue
				}
				if netplanDHCP6Re.MatchString(text) {
					return "dhcp"
				}
				if netplanAcceptRA.MatchString(text) {
					return "slaac"
				}
			}
		}
	}
	return "unknown"
}

// virtualInterfacePrefixes names the interface-naming conventions of
// every container/VM networking backend this appliance's own deploy
// path (or a co-located one) is known to create: podman's rootful
// bridge (cni-podman0 + veth*), podman rootless (podman0), Docker
// (docker0 + veth*, plus docker-compose's br-<id> per-network
// bridges), generic Linux bridges/CNI plugins (cni0, flannel.1,
// cali*, weave*), libvirt (virbr*), and TUN/TAP devices. This is a
// disclosed, best-effort denylist by naming convention, not a
// complete taxonomy of every possible virtual interface -- but these
// are exactly the prefixes a real Podman/Docker-hosting appliance
// like this one's own web/hostagent split actually creates, which is
// the concrete defect this list exists to prevent: the DNS Transports
// page once auto-detected and displayed 10.88.0.15 (a cni-podman0
// bridge address from the WEB CONTAINER's own network namespace) as a
// client-setup address, which no phone, router, or LAN device could
// ever reach. HostLANCandidates below runs this filter from the
// host's OWN interface list (via this already-host-side agent), so it
// never repeats that exact mistake.
var virtualInterfacePrefixes = []string{
	"veth", "docker", "br-", "cni", "podman", "virbr", "tun", "tap",
	"flannel", "cali", "weave", "vxlan", "dummy", "wg",
}

func isVirtualInterface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// containerBridgeCIDRs are the well-known DEFAULT subnets Podman and
// Docker assign their own bridge networks out of, unless an operator
// has customized them. Never offered as an auto-detected client-facing
// candidate and rejected outright if an owner tries to manually save
// one -- these are Podman/Docker installation defaults, never a real
// appliance LAN, so an address here is far more likely a copy-paste of
// this exact defect than a deliberate real network.
var containerBridgeCIDRs = mustParseCIDRs(
	"10.88.0.0/16",                                                                      // Podman default rootful bridge network
	"10.89.0.0/16",                                                                      // Podman additional default bridge networks
	"172.17.0.0/16",                                                                     // Docker default bridge (docker0)
	"172.18.0.0/16", "172.19.0.0/16", "172.20.0.0/14", "172.24.0.0/14", "172.28.0.0/14", // Docker's docker-compose per-project br-* pool
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// IsContainerBridgeAddress reports whether ip falls inside one of
// Podman/Docker's own default bridge-network ranges -- see
// containerBridgeCIDRs above.
func IsContainerBridgeAddress(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range containerBridgeCIDRs {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// LANCandidate is one real, non-virtual interface's address, as seen
// from the host's own network namespace (this agent's, never the web
// container's).
type LANCandidate struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
}

// HostLANCandidates lists every IPv4 address on every non-virtual,
// non-loopback host interface -- the real candidate set for "what
// should a client actually be told to connect to", gathered from this
// already-host-side agent process rather than the unprivileged web
// container's own isolated network namespace (see the doc comment on
// virtualInterfacePrefixes above for the exact defect this exists to
// prevent). Link-local (169.254.0.0/16) addresses are skipped -- never
// a usable client-facing address. Callers decide what "ambiguous"
// means for their purpose; this just reports the real, filtered facts.
func HostLANCandidates(ctx context.Context) []LANCandidate {
	interfaces, err := ListInterfaces(ctx)
	if err != nil {
		return nil
	}
	var out []LANCandidate
	for _, iface := range interfaces {
		if isVirtualInterface(iface) {
			continue
		}
		v4s, _, err := InterfaceAddresses(ctx, iface)
		if err != nil {
			continue
		}
		for _, a := range v4s {
			ip := net.ParseIP(a.Address)
			if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			out = append(out, LANCandidate{Interface: iface, Address: a.Address})
		}
	}
	return out
}

// ListInterfaces mirrors V1.1.1's list_interfaces() -- every real
// interface name except loopback.
func ListInterfaces(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "ip", "-json", "link", "show").Output()
	if err != nil {
		return nil, err
	}
	var links []struct {
		IfName string `json:"ifname"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return nil, err
	}
	var names []string
	for _, l := range links {
		if l.IfName != "lo" {
			names = append(names, l.IfName)
		}
	}
	return names, nil
}

var defaultRouteDevRe = regexp.MustCompile(`\bdev\s+(\S+)`)
var defaultRouteViaRe = regexp.MustCompile(`\bvia\s+(\S+)`)

// DefaultRouteInterface/DefaultGateway mirror V1.1.1's
// default_route_interface()/default_gateway() -- family is "-4" or "-6".
func DefaultRouteInterface(ctx context.Context, family string) string {
	out, err := exec.CommandContext(ctx, "ip", family, "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	if m := defaultRouteDevRe.FindStringSubmatch(string(out)); m != nil {
		return m[1]
	}
	return ""
}

func DefaultGateway(ctx context.Context, family string) string {
	out, err := exec.CommandContext(ctx, "ip", family, "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	if m := defaultRouteViaRe.FindStringSubmatch(string(out)); m != nil {
		return m[1]
	}
	return ""
}

type AddrInfo struct {
	Address   string `json:"address"`
	Prefixlen int    `json:"prefixlen"`
}

// InterfaceAddresses mirrors V1.1.1's interface_addresses() -- every
// real IPv4/global-scope-IPv6 address currently on this interface, via
// `ip -json addr show dev <interface>`.
func InterfaceAddresses(ctx context.Context, iface string) (ipv4, ipv6 []AddrInfo, err error) {
	out, err := exec.CommandContext(ctx, "ip", "-json", "addr", "show", "dev", iface).Output()
	if err != nil {
		return nil, nil, err
	}
	var entries []struct {
		AddrInfo []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			Prefixlen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		for _, a := range e.AddrInfo {
			item := AddrInfo{Address: a.Local, Prefixlen: a.Prefixlen}
			switch {
			case a.Family == "inet":
				ipv4 = append(ipv4, item)
			case a.Family == "inet6" && a.Scope != "link":
				ipv6 = append(ipv6, item)
			}
		}
	}
	return ipv4, ipv6, nil
}

type FamilyConfig struct {
	Address   string `json:"address,omitempty"`
	Prefixlen int    `json:"prefixlen,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	Mode      string `json:"mode"`
}

type CurrentNetworkConfig struct {
	Backend       string        `json:"backend"`
	Ambiguous     bool          `json:"ambiguous"`
	BackendDetail string        `json:"backend_detail"`
	Interface     string        `json:"interface,omitempty"`
	Interfaces    []string      `json:"interfaces"`
	IPv4          *FamilyConfig `json:"ipv4"`
	IPv6          *FamilyConfig `json:"ipv6"`
}

// ReadCurrentNetworkConfig mirrors V1.1.1's read_current_config() --
// always-safe, read-only, shown first regardless of whether the
// detected backend supports making changes at all.
func ReadCurrentNetworkConfig(ctx context.Context) CurrentNetworkConfig {
	backendInfo := DetectBackend(ctx)
	interfaces, _ := ListInterfaces(ctx)
	iface := DefaultRouteInterface(ctx, "-4")
	if iface == "" && len(interfaces) > 0 {
		iface = interfaces[0]
	}
	result := CurrentNetworkConfig{
		Backend: backendInfo.Backend, Ambiguous: backendInfo.Ambiguous, BackendDetail: backendInfo.Detail,
		Interface: iface, Interfaces: interfaces,
	}
	if iface == "" {
		return result
	}
	v4s, v6s, err := InterfaceAddresses(ctx, iface)
	if err != nil {
		return result
	}
	v4 := FamilyConfig{Gateway: DefaultGateway(ctx, "-4"), Mode: DetectIPv4Mode(backendInfo.Backend, iface)}
	if len(v4s) > 0 {
		v4.Address, v4.Prefixlen = v4s[0].Address, v4s[0].Prefixlen
	}
	result.IPv4 = &v4
	v6 := FamilyConfig{Gateway: DefaultGateway(ctx, "-6"), Mode: DetectIPv6Mode(backendInfo.Backend, iface)}
	if len(v6s) > 0 {
		v6.Address, v6.Prefixlen = v6s[0].Address, v6s[0].Prefixlen
	}
	result.IPv6 = &v6
	return result
}
