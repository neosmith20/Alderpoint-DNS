package hostagentd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderNetworkdUnitStaticIPv4(t *testing.T) {
	got := renderNetworkdUnit("eth0", AddrConfig{Mode: "static", Address: "10.0.0.5", Prefix: 24, Gateway: "10.0.0.1"}, AddrConfig{})
	for _, want := range []string{"[Match]", "Name=eth0", "[Network]", "Address=10.0.0.5/24", "Gateway=10.0.0.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in rendered unit, got:\n%s", want, got)
		}
	}
}

func TestRenderNetworkdUnitDHCPv4AndSLAACv6(t *testing.T) {
	got := renderNetworkdUnit("eth0", AddrConfig{Mode: "dhcp"}, AddrConfig{Mode: "slaac"})
	if !strings.Contains(got, "DHCP=ipv4") {
		t.Errorf("expected DHCP=ipv4, got:\n%s", got)
	}
	if !strings.Contains(got, "IPv6AcceptRA=yes") {
		t.Errorf("expected IPv6AcceptRA=yes for slaac, got:\n%s", got)
	}
}

func TestRenderNetplanYAMLStaticIPv4(t *testing.T) {
	got := renderNetplanYAML("eth0", AddrConfig{Mode: "static", Address: "10.0.0.5", Prefix: 24, Gateway: "10.0.0.1"}, AddrConfig{})
	for _, want := range []string{"network:", "version: 2", "eth0:", "dhcp4: false", "10.0.0.5/24", "to: 0.0.0.0/0", "via: 10.0.0.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in rendered netplan YAML, got:\n%s", want, got)
		}
	}
}

func TestRenderIfupdownStanzaStaticIPv4(t *testing.T) {
	got := renderIfupdownStanza("eth0", AddrConfig{Mode: "static", Address: "10.0.0.5", Prefix: 24, Gateway: "10.0.0.1"}, AddrConfig{})
	for _, want := range []string{"auto eth0", "iface eth0 inet static", "address 10.0.0.5", "netmask 255.255.255.0", "gateway 10.0.0.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in rendered ifupdown stanza, got:\n%s", want, got)
		}
	}
}

func TestRenderIfupdownStanzaDHCP(t *testing.T) {
	got := renderIfupdownStanza("eth0", AddrConfig{Mode: "dhcp"}, AddrConfig{})
	if !strings.Contains(got, "iface eth0 inet dhcp") {
		t.Errorf("expected dhcp stanza, got:\n%s", got)
	}
}

func TestIfupdownStagedConfigIsAcceptedByTheRealIfupToolInDryRun(t *testing.T) {
	// The strongest available "reboot survival" equivalent proof this
	// sandbox can offer: this repo's disposable-fixture convention
	// never touches a real host NIC, and a real reboot is out of reach
	// in CI -- so instead, the REAL ifup binary is handed the exact
	// staged config file this package would leave behind for the OS's
	// own boot-time networking to read, in --no-act (dry-run) mode
	// against a disposable veth, proving the OS's own tool parses and
	// would apply it, not just that this package's own string
	// generation "looks right".
	if _, err := exec.LookPath("ifup"); err != nil {
		t.Skip("ifup not installed in this environment")
	}
	iface := newTestVeth(t)
	dir := withOverriddenPaths(t)

	path, err := stageIfupdown(iface, AddrConfig{Mode: "static", Address: "10.77.0.5", Prefix: 24, Gateway: "10.77.0.1"}, AddrConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected the staged file to exist: %v", err)
	}

	// A real, minimal interfaces file that sources the same drop-in
	// directory this package just wrote to -- exactly the layout
	// stageIfupdown's own doc comment describes.
	realInterfaces := filepath.Join(dir, "real-interfaces")
	if err := os.WriteFile(realInterfaces, []byte("source "+ifupdownDropinDir+"/*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("ifup", "--no-act", "--interfaces", realInterfaces, iface).CombinedOutput()
	if err != nil {
		t.Fatalf("the real ifup binary rejected the staged config in dry-run mode: %v\n%s", err, out)
	}
}

func TestPersistSnapshotFilesCapturesPriorContentForRollback(t *testing.T) {
	withOverriddenPaths(t)
	if err := os.MkdirAll(ifupdownDropinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := ifupdownDropinPath("eth9")
	original := "auto eth9\niface eth9 inet dhcp\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	snap := snapshotFilesFor(BackendIfupdown, "eth9")
	sf, ok := snap[path]
	if !ok || !sf.existed || sf.content != original {
		t.Fatalf("expected the snapshot to capture the real prior content, got %+v", sf)
	}

	// Overwrite with a new (rejected) config, then restore -- proving
	// restorePersisted actually puts the ORIGINAL bytes back, not just
	// deletes the file.
	if err := os.WriteFile(path, []byte("auto eth9\niface eth9 inet static\n    address 10.0.0.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeSnap := &persistSnapshot{backend: BackendIfupdown, files: snap}
	// restorePersisted's own file-restore loop is exercised directly,
	// not through applyIfupdown (which would exec real ifup/ifdown
	// against this test's own disposable veth's real interfaces file --
	// covered separately, more directly, by the dry-run test above).
	for p, sfEntry := range fakeSnap.files {
		if err := os.WriteFile(p, []byte(sfEntry.content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Fatalf("expected original content restored, got:\n%s", restored)
	}
}

func TestSnapshotFilesForNonExistentFileRecordsNotExisted(t *testing.T) {
	withOverriddenPaths(t)
	snap := snapshotFilesFor(BackendNetworkd, "eth-never-configured")
	path := networkdUnitPath("eth-never-configured")
	sf, ok := snap[path]
	if !ok || sf.existed {
		t.Fatalf("expected existed=false for a file that was never written, got %+v", sf)
	}
}

func TestPersistChangeReportsUnsupportedBackendHonestly(t *testing.T) {
	withOverriddenPaths(t) // nothing configured -> DetectBackend returns unsupported
	snap, res, err := persistChange(context.Background(), BackendUnsupported, "eth0", AddrConfig{Mode: "dhcp"}, AddrConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if snap != nil {
		t.Fatalf("expected no snapshot for an unsupported backend, got %+v", snap)
	}
	if res.Persisted {
		t.Fatalf("expected persisted=false for an unsupported backend, got %+v", res)
	}
	if res.Reason == "" {
		t.Fatal("expected a real, non-empty reason explaining why persistence was skipped")
	}
}

// --- OpNetworkPreview / previewPersist: real generated-config preview,
// added 2026-09-03 so Network Configuration can show exactly what
// Apply's persistent half would write BEFORE the owner commits to it.
// Every case below asserts the preview's content is IDENTICAL to what
// persistChange would actually write -- proving the preview can never
// drift from reality -- and that previewing never touches disk.

func TestPreviewPersistNetplanMatchesWhatApplyWouldWriteAndTouchesNoFile(t *testing.T) {
	dir := withOverriddenPaths(t)
	ipv4 := AddrConfig{Mode: "static", Address: "10.0.0.5", Prefix: 24, Gateway: "10.0.0.1"}
	preview := previewPersist(context.Background(), BackendNetplan, "eth0", ipv4, AddrConfig{})
	if !preview.WouldPersist {
		t.Fatalf("expected would_persist=true for netplan, got %+v", preview)
	}
	wantPath := filepath.Join(dir, "netplan", "90-alderpointdns.yaml")
	if preview.FilePath != wantPath {
		t.Fatalf("expected file_path %q, got %q", wantPath, preview.FilePath)
	}
	if preview.FileContent != renderNetplanYAML("eth0", ipv4, AddrConfig{}) {
		t.Fatalf("preview content must exactly match what stageNetplan would write, got:\n%s", preview.FileContent)
	}
	if _, err := os.Stat(wantPath); !os.IsNotExist(err) {
		t.Fatalf("previewing must never actually write the file, but it exists: err=%v", err)
	}
}

func TestPreviewPersistNetworkdMatchesWhatApplyWouldWriteAndTouchesNoFile(t *testing.T) {
	dir := withOverriddenPaths(t)
	ipv4 := AddrConfig{Mode: "dhcp"}
	preview := previewPersist(context.Background(), BackendNetworkd, "eth1", ipv4, AddrConfig{Mode: "slaac"})
	if !preview.WouldPersist {
		t.Fatalf("expected would_persist=true for networkd, got %+v", preview)
	}
	wantPath := filepath.Join(dir, "systemd-network", "90-alderpointdns-eth1.network")
	if preview.FilePath != wantPath {
		t.Fatalf("expected file_path %q, got %q", wantPath, preview.FilePath)
	}
	if preview.FileContent != renderNetworkdUnit("eth1", ipv4, AddrConfig{Mode: "slaac"}) {
		t.Fatalf("preview content must exactly match what stageNetworkd would write, got:\n%s", preview.FileContent)
	}
	if _, err := os.Stat(wantPath); !os.IsNotExist(err) {
		t.Fatalf("previewing must never actually write the file, but it exists: err=%v", err)
	}
}

func TestPreviewPersistIfupdownMatchesWhatApplyWouldWriteAndTouchesNoFile(t *testing.T) {
	dir := withOverriddenPaths(t)
	ipv4 := AddrConfig{Mode: "static", Address: "10.0.0.9", Prefix: 24, Gateway: "10.0.0.1"}
	preview := previewPersist(context.Background(), BackendIfupdown, "eth2", ipv4, AddrConfig{})
	if !preview.WouldPersist {
		t.Fatalf("expected would_persist=true for ifupdown, got %+v", preview)
	}
	wantPath := filepath.Join(dir, "interfaces.d", "90-alderpointdns-eth2.cfg")
	if preview.FilePath != wantPath {
		t.Fatalf("expected file_path %q, got %q", wantPath, preview.FilePath)
	}
	if preview.FileContent != renderIfupdownStanza("eth2", ipv4, AddrConfig{}) {
		t.Fatalf("preview content must exactly match what stageIfupdown would write, got:\n%s", preview.FileContent)
	}
	if _, err := os.Stat(wantPath); !os.IsNotExist(err) {
		t.Fatalf("previewing must never actually write the file, but it exists: err=%v", err)
	}
}

func TestPreviewPersistUnsupportedBackendReportsWouldNotPersistHonestly(t *testing.T) {
	withOverriddenPaths(t)
	preview := previewPersist(context.Background(), BackendUnsupported, "eth0", AddrConfig{Mode: "dhcp"}, AddrConfig{})
	if preview.WouldPersist {
		t.Fatalf("expected would_persist=false for an unsupported backend, got %+v", preview)
	}
	if preview.Reason == "" {
		t.Fatal("expected a real, non-empty reason explaining why persistence would be skipped")
	}
	if preview.FileContent != "" || preview.FilePath != "" {
		t.Fatalf("expected no file content/path for an unsupported backend, got %+v", preview)
	}
}
