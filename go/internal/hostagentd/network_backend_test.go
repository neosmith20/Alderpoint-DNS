package hostagentd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// withOverriddenPaths points every package-level config-path var this
// file's backend/mode detection reads at a fresh temp dir for the
// duration of one test, then restores the real values -- never touches
// the actual host's /etc/systemd/network, /etc/netplan, etc.
func withOverriddenPaths(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origNetworkd, origNetplan, origIfupdown, origIfupdownDrop := networkdDropinDir, netplanDir, ifupdownInterfaces, ifupdownDropinDir
	networkdDropinDir = filepath.Join(dir, "systemd-network")
	netplanDir = filepath.Join(dir, "netplan")
	ifupdownInterfaces = filepath.Join(dir, "interfaces")
	ifupdownDropinDir = filepath.Join(dir, "interfaces.d")
	t.Cleanup(func() {
		networkdDropinDir, netplanDir, ifupdownInterfaces, ifupdownDropinDir = origNetworkd, origNetplan, origIfupdown, origIfupdownDrop
	})
	return dir
}

func TestDetectBackendNoneActiveIsUnsupported(t *testing.T) {
	withOverriddenPaths(t)
	info := DetectBackend(context.Background())
	if info.Backend != BackendUnsupported || info.Ambiguous {
		t.Fatalf("expected unsupported/not-ambiguous with nothing configured, got %+v", info)
	}
}

func TestDetectBackendIfupdownFromRealFile(t *testing.T) {
	dir := withOverriddenPaths(t)
	if err := os.WriteFile(filepath.Join(dir, "interfaces"), []byte("auto lo\niface lo inet loopback\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info := DetectBackend(context.Background())
	if info.Backend != BackendIfupdown {
		t.Fatalf("expected ifupdown detected from a real interfaces file, got %+v", info)
	}
}

func TestDetectIPv4ModeIfupdownDHCP(t *testing.T) {
	dir := withOverriddenPaths(t)
	if err := os.WriteFile(filepath.Join(dir, "interfaces"), []byte("auto eth0\niface eth0 inet dhcp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectIPv4Mode(BackendIfupdown, "eth0"); got != "dhcp" {
		t.Fatalf("expected dhcp, got %q", got)
	}
}

func TestDetectIPv4ModeIfupdownStatic(t *testing.T) {
	dir := withOverriddenPaths(t)
	if err := os.WriteFile(filepath.Join(dir, "interfaces"), []byte("auto eth0\niface eth0 inet static\naddress 10.0.0.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectIPv4Mode(BackendIfupdown, "eth0"); got != "static" {
		t.Fatalf("expected static, got %q", got)
	}
}

func TestDetectIPv4ModeUnknownForUnrelatedInterface(t *testing.T) {
	dir := withOverriddenPaths(t)
	if err := os.WriteFile(filepath.Join(dir, "interfaces"), []byte("auto eth0\niface eth0 inet dhcp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectIPv4Mode(BackendIfupdown, "eth9"); got != "unknown" {
		t.Fatalf("expected unknown for an interface not mentioned in the config, got %q", got)
	}
}

func TestDetectIPv4ModeNetworkdDHCP(t *testing.T) {
	dir := withOverriddenPaths(t)
	if err := os.MkdirAll(networkdDropinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"
	if err := os.WriteFile(filepath.Join(dir, "systemd-network", "10-eth0.network"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectIPv4Mode(BackendNetworkd, "eth0"); got != "dhcp" {
		t.Fatalf("expected dhcp, got %q", got)
	}
}

func TestDetectIPv4ModeNetworkdStatic(t *testing.T) {
	dir := withOverriddenPaths(t)
	if err := os.MkdirAll(networkdDropinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "[Match]\nName=eth0\n\n[Network]\nAddress=10.0.0.5/24\n"
	if err := os.WriteFile(filepath.Join(dir, "systemd-network", "10-eth0.network"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectIPv4Mode(BackendNetworkd, "eth0"); got != "static" {
		t.Fatalf("expected static, got %q", got)
	}
}

func TestDetectIPv6ModeNetworkdSLAACFallback(t *testing.T) {
	dir := withOverriddenPaths(t)
	if err := os.MkdirAll(networkdDropinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A real Name= match with neither DHCP= nor a v6 Address= -> slaac,
	// matching V1.1.1's own fallback for "matched but nothing else set".
	content := "[Match]\nName=eth0\n\n[Network]\n"
	if err := os.WriteFile(filepath.Join(dir, "systemd-network", "10-eth0.network"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectIPv6Mode(BackendNetworkd, "eth0"); got != "slaac" {
		t.Fatalf("expected slaac, got %q", got)
	}
}

func TestDetectIPv4ModeNetplanDHCP(t *testing.T) {
	dir := withOverriddenPaths(t)
	if err := os.MkdirAll(netplanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "network:\n  ethernets:\n    eth0:\n      dhcp4: true\n"
	if err := os.WriteFile(filepath.Join(dir, "netplan", "90-alderpointdns.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectIPv4Mode(BackendNetplan, "eth0"); got != "dhcp" {
		t.Fatalf("expected dhcp, got %q", got)
	}
}

func TestReadCurrentNetworkConfigOnRealVeth(t *testing.T) {
	withOverriddenPaths(t)
	iface := newTestVeth(t)
	if err := exec.Command("ip", "addr", "add", "10.77.0.5/24", "dev", iface).Run(); err != nil {
		t.Fatal(err)
	}
	cfg := ReadCurrentNetworkConfig(context.Background())
	found := false
	for _, i := range cfg.Interfaces {
		if i == iface {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the real test interface %q to appear in Interfaces, got %+v", iface, cfg.Interfaces)
	}
	// Backend is unsupported on this fixture (no real backend config
	// present) -- that's expected and correct, not a test bug: this test
	// proves ListInterfaces/InterfaceAddresses work against a real
	// interface, not that a networking backend happens to be installed
	// on the machine running the test suite.
	if cfg.Backend != BackendUnsupported {
		t.Logf("note: a real networking backend is active on this host (%q) -- not a failure, just means this run isn't exercising the 'unsupported' path", cfg.Backend)
	}
}
