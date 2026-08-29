package main

// Regression test for a real live defect: the `web` subcommand's
// -dns-perf-report-path (and several sibling flags -- backups-dir,
// bootstrap-token-path, replication-cert-dir, secret-backups-dir) had a
// relative "./data/..." default. On the live podman deployment the
// process's cwd is "/" (the container root filesystem, itself
// read-only), so any of these that aren't explicitly overridden on the
// command line resolve to a path under an unwritable directory --
// exactly the live "Last benchmark run failed: mkdir data: permission
// denied" defect from System Status's Safe DNS Benchmark. This test
// reads this package's own main.go source (a static check, not an
// invocation -- main() runs the real server, not something a unit test
// should start) and fails if the `web` subcommand's flag defaults ever
// regress to a relative path again.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var flagDefaultRE = regexp.MustCompile(`fs\.String\("([a-z0-9-]+)",\s*"([^"]*)"`)

func TestWebSubcommandFlagDefaultsAreNeverRelativePaths(t *testing.T) {
	self, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(self, "main.go"))
	if err != nil {
		t.Fatal(err)
	}

	// Isolate the `web` subcommand's own flag block: from its
	// flag.NewFlagSet("web", ...) call to the end of the file (it's the
	// last subcommand defined).
	text := string(src)
	idx := strings.Index(text, `flag.NewFlagSet("web"`)
	if idx < 0 {
		t.Fatal("could not find the web subcommand's flag.NewFlagSet call -- has main.go been restructured?")
	}
	webBlock := text[idx:]

	// Scoped to the flags this defect actually affects -- appliance data/
	// state written under a directory this deployment's own launch
	// command never explicitly overrides (unlike -db/-config/-static/
	// -migrations, which the live command line always passes explicitly
	// and which legitimately default to a repo-relative path for local,
	// run-from-source-tree development). Every one of these must resolve
	// to a real absolute path with no help from the process's cwd.
	appliancePathFlags := map[string]bool{
		"backups-dir": true, "bootstrap-token-path": true, "replication-cert-dir": true,
		"secret-backups-dir": true, "dns-perf-report-path": true,
	}
	found := map[string]bool{}
	for _, m := range flagDefaultRE.FindAllStringSubmatch(webBlock, -1) {
		name, def := m[1], m[2]
		if !appliancePathFlags[name] {
			continue
		}
		found[name] = true
		if !strings.HasPrefix(def, "/") {
			t.Errorf("web subcommand flag -%s has a non-absolute default %q -- on the live deployment "+
				"the process cwd is \"/\" (the container's own read-only root filesystem), so a "+
				"relative default resolves to an unwritable path (the exact live 'mkdir data: "+
				"permission denied' defect). Use an absolute path under /var/lib/alderpointdns-go.", name, def)
		}
	}
	for name := range appliancePathFlags {
		if !found[name] {
			t.Errorf("expected to find a -%s flag definition in the web subcommand block -- has it been renamed or removed?", name)
		}
	}
}

// TestResolveDNSRuntimeTLSPath is the regression test for the live
// "DNS runtime change rejected at stage dnsdist_reload -- dnsdist
// exited immediately after start" defect: dnscompile was always given
// this process's OWN (possibly container-internal) web.tls_cert_path/
// tls_key_path to compile into dnsdist.conf, so on a split-container
// deployment (dnsdist running on the host, the cert only mounted
// inside the web container) dnsdist could never open the cert file at
// all and exited immediately the moment DoT/DoH/DoQ/DoH3 was enabled.
func TestResolveDNSRuntimeTLSPath(t *testing.T) {
	if got := resolveDNSRuntimeTLSPath("", "/etc/alderpointdns-go/certs/server.crt"); got != "/etc/alderpointdns-go/certs/server.crt" {
		t.Fatalf("expected the web config fallback when no explicit flag is set, got %q", got)
	}
	if got := resolveDNSRuntimeTLSPath("/var/lib/apdns-go-live-staging/certs/server.crt", "/etc/alderpointdns-go/certs/server.crt"); got != "/var/lib/apdns-go-live-staging/certs/server.crt" {
		t.Fatalf("expected the explicit HOST-side flag to win over the web config fallback, got %q", got)
	}
}
