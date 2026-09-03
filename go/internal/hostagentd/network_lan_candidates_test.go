package hostagentd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// installFakeIPBinary drops a fake `ip` executable at the front of PATH
// for the duration of one test, scripted to answer exactly the `ip -json
// link show` / `ip -json addr show dev <iface>` / `ip -4 route show
// default` invocations HostLANCandidates/ListInterfaces/
// InterfaceAddresses/DefaultRouteInterface actually make -- a real
// fixture reproducing the exact reported defect: a Podman bridge
// interface (cni-podman0, address 10.88.0.15 -- the literal address the
// DNS Transports page once displayed as a client-setup address) sitting
// alongside a real host LAN interface (eth0, address 172.16.43.100, this
// appliance's actual live DHCP address per the owner's report).
func installFakeIPBinary(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("fake `ip` binary fixture only written for a POSIX shell")
	}
	dir := t.TempDir()
	script := `#!/bin/sh
case "$*" in
  "-json link show")
    echo '[{"ifname":"lo"},{"ifname":"cni-podman0"},{"ifname":"veth1234abcd"},{"ifname":"eth0"}]'
    ;;
  "-json addr show dev cni-podman0")
    echo '[{"addr_info":[{"family":"inet","local":"10.88.0.15","prefixlen":16,"scope":"global"}]}]'
    ;;
  "-json addr show dev veth1234abcd")
    echo '[{"addr_info":[{"family":"inet","local":"10.88.0.2","prefixlen":16,"scope":"global"}]}]'
    ;;
  "-json addr show dev eth0")
    echo '[{"addr_info":[{"family":"inet","local":"172.16.43.100","prefixlen":24,"scope":"global"}]}]'
    ;;
  "-4 route show default")
    echo 'default via 172.16.43.1 dev eth0'
    ;;
  *)
    echo "fake ip: unhandled args: $*" >&2
    exit 1
    ;;
esac
`
	path := filepath.Join(dir, "ip")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestHostLANCandidatesFiltersContainerBridgeKeepsRealHostLAN is the
// core proof for the P0 fix: given a host that has BOTH a Podman bridge
// (cni-podman0/10.88.0.15, veth.../10.88.0.2) and a real LAN interface
// (eth0/172.16.43.100), HostLANCandidates -- which is what
// apdns-hostagent actually reports to the web control plane for DNS
// Transports client-setup guidance -- returns ONLY the real host LAN
// address, never the container-internal ones.
func TestHostLANCandidatesFiltersContainerBridgeKeepsRealHostLAN(t *testing.T) {
	installFakeIPBinary(t)
	candidates := HostLANCandidates(context.Background())
	if len(candidates) != 1 {
		t.Fatalf("expected exactly 1 real LAN candidate, got %d: %+v", len(candidates), candidates)
	}
	if candidates[0].Address != "172.16.43.100" || candidates[0].Interface != "eth0" {
		t.Fatalf("expected eth0/172.16.43.100, got %+v", candidates[0])
	}
	for _, c := range candidates {
		if c.Address == "10.88.0.15" || c.Address == "10.88.0.2" {
			t.Fatalf("container bridge address %q leaked into LAN candidates: %+v", c.Address, candidates)
		}
	}
}

func TestIsContainerBridgeAddress(t *testing.T) {
	for _, addr := range []string{"10.88.0.15", "10.88.255.1", "10.89.0.1", "172.17.0.1"} {
		if !IsContainerBridgeAddress(addr) {
			t.Errorf("expected %q to be recognized as a container bridge address", addr)
		}
	}
	for _, addr := range []string{"172.16.43.100", "192.168.1.10", "10.0.0.5", "not-an-ip"} {
		if IsContainerBridgeAddress(addr) {
			t.Errorf("expected %q NOT to be recognized as a container bridge address", addr)
		}
	}
}

// TestOpNetworkLANCandidatesEndToEndNeverReportsContainerBridge exercises
// the actual registered RPC handler (the exact code path the web control
// plane calls over the hostagent socket), not just the underlying
// function, against the same fixture.
func TestOpNetworkLANCandidatesEndToEndNeverReportsContainerBridge(t *testing.T) {
	installFakeIPBinary(t)
	s := &Server{}
	RegisterNetworkOps(s, NetworkConfig{})
	handler := s.handlers["network.lan_candidates"]
	if handler == nil {
		t.Fatal("network.lan_candidates was not registered")
	}
	result, err := handler(context.Background(), nil)
	if err != nil {
		t.Fatalf("network.lan_candidates: %v", err)
	}
	body := fmt.Sprintf("%v", result)
	if contains(body, "10.88.0.15") {
		t.Fatalf("container bridge address leaked through the real RPC handler: %s", body)
	}
	if !contains(body, "172.16.43.100") {
		t.Fatalf("expected the real host LAN address in the RPC response: %s", body)
	}
}
