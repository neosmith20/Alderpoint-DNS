// Package deployperm is a real, permanent regression test for real
// deployed-UID integration defects found live on the :10443 preview:
// once the container's web process was switched from running as root
// to its real unprivileged UID (see PARITY_MATRIX.md's host-control
// boundary section), it could no longer open some of Python's mounts at
// all.
//
// Two real scenarios covered:
//
//   - Certs: server.crt lives under a root-owned, group-restricted
//     (750/640) directory tree -- the exact shape Python's own
//     packaging already produces -- unreadable by a real unprivileged
//     UID with no matching supplementary group, readable once that one
//     GID is granted (podman `--group-add <gid>`).
//   - Analytics: as of the 2026-08-27 "database disk image is
//     malformed" incident's fix (see internal/analyticssnapshot's own
//     doc comment), the web process no longer reads Python's live
//     aggregates.db at all -- it reads a published snapshot
//     apdns-hostagent (root) produces, through its own separate
//     read-only mount. That snapshot directory is entirely
//     hostagent-owned and deliberately world-readable (no secrets in
//     aggregate query stats), so this second scenario proves the
//     OPPOSITE of the certs one: a completely unprivileged UID with NO
//     special group at all can read it, through a real kernel-enforced
//     read-only bind mount -- the group-ACL dance the old direct-read
//     design needed for analytics is gone entirely, not just patched.
package deployperm

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/analyticssnapshot"
	"alderpointdns/go-controlplane/internal/pyanalytics"
	"alderpointdns/go-controlplane/internal/tlscert"
)

const (
	reexecEnv       = "APDNS_DEPLOYPERM_REEXEC_PROBE"
	publishedDirEnv = "APDNS_DEPLOYPERM_PUBLISHED_DIR"
	certPathEnv     = "APDNS_DEPLOYPERM_CERT_PATH"
)

func TestMain(m *testing.M) {
	if os.Getenv(reexecEnv) != "" {
		os.Exit(runProbe())
	}
	os.Exit(m.Run())
}

// runProbe is what the re-exec'd subprocess actually runs, under
// whatever real UID/GID/supplementary-groups the parent test set on it
// -- the exact same pyanalytics.Open+Ping and tlscert.Reader.Status
// calls the real deployed web binary makes.
func runProbe() int {
	fail := 0
	if publishedDir := os.Getenv(publishedDirEnv); publishedDir != "" {
		r, err := pyanalytics.Open(publishedDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pyanalytics.Open:", err)
			fail = 1
		} else {
			defer r.Close()
			if err := r.Ping(context.Background()); err != nil {
				fmt.Fprintln(os.Stderr, "pyanalytics.Ping:", err)
				fail = 1
			}
		}
	}
	if certPath := os.Getenv(certPathEnv); certPath != "" {
		reader := &tlscert.Reader{CertPath: certPath}
		if _, err := reader.Status(); err != nil {
			fmt.Fprintln(os.Stderr, "tlscert.Status:", err)
			fail = 1
		}
	}
	return fail
}

// runAsRealUID re-execs this same test binary as a real different
// UID/GID (and, when given, real supplementary groups), reproducing
// exactly what a deployed container process experiences -- not
// something any single-UID in-process test could ever exercise, the
// same reasoning internal/hostagentd's own two-real-UID tests already
// established this session.
func runAsRealUID(t *testing.T, uid, gid uint32, groups []uint32, publishedDir, certPath string) error {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// go test's compiled binary (and the go-build temp directories
	// containing it) default to owner-only access in this environment --
	// world-traversable/executable is safe here (a disposable build
	// artifact under go-build's own temp dir, not anything with secrets
	// baked in) and is required for the unprivileged re-exec below to
	// even reach exec() at all.
	if err := os.Chmod(self, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(self), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(filepath.Dir(self)), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self) // TestMain intercepts before any test-flag parsing matters
	cmd.Env = append(os.Environ(), reexecEnv+"=1", publishedDirEnv+"="+publishedDir, certPathEnv+"="+certPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// TestUnprivilegedUIDNeedsTheRealSupplementaryGroupACLForCerts is the
// real regression test for the certs half: a root-owned,
// group-restricted (750/644) directory tree -- the exact shape
// Python's own packaging already produces for server.crt -- is
// unreadable by a real unprivileged UID with no matching supplementary
// group (reproducing the live :10443 defect exactly), and becomes
// readable once that one GID is granted as a supplementary group
// (reproducing the real fix: podman `--group-add <gid>`, or the
// equivalent host-side group membership for a non-containerized
// deployment). Skips if not run as root (this test needs
// CAP_SETUID/CAP_SETGID to drop into a different real UID).
func TestUnprivilegedUIDNeedsTheRealSupplementaryGroupACLForCerts(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("must run as root to exercise a real UID/GID drop")
	}

	dir := t.TempDir()
	// t.TempDir()'s own parent directory defaults to owner-only (0700)
	// in this environment -- world-traversable is safe (nothing
	// sensitive lives directly in it, only this test's own throwaway
	// subdirectory) and is required for any non-root re-exec below to
	// even traverse down to `dir` itself.
	if err := os.Chmod(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "server.crt")

	// A real, valid minimal self-signed cert -- reuse the same openssl
	// invocation pattern already used elsewhere in this session's own
	// test/deploy tooling.
	keyPath := filepath.Join(dir, "server.key")
	if out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes", "-subj", "/CN=deployperm-test").CombinedOutput(); err != nil {
		t.Skipf("openssl not usable in this environment: %v: %s", err, out)
	}

	// The real permission shape: root-owned, group-restricted, exactly
	// matching what "ls -la" on the real /root/apdns-v2-preview-state
	// certs directory showed live (750 dirs, 640/644 files, owner
	// _dnsdist, group bind -- reproduced here with a throwaway numeric
	// GID nothing else on the host uses, so this test never depends on
	// a "bind" group actually existing).
	testGID := uint32(1_700_000 + os.Getpid()%9000)
	for _, p := range []string{dir, certPath, keyPath} {
		if err := os.Chown(p, 0, int(testGID)); err != nil {
			t.Skipf("cannot chown in this environment: %v", err)
		}
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(certPath, 0o644); err != nil {
		t.Fatal(err)
	}

	const unprivilegedUID = 65534 // "nobody" -- a real, always-present, definitely-not-in-testGID unprivileged UID
	const unprivilegedGID = 65534

	err := runAsRealUID(t, unprivilegedUID, unprivilegedGID, nil, "", certPath)
	if err == nil {
		t.Fatal("expected a real permission failure without the supplementary group -- test does not reproduce the live defect")
	}
	t.Logf("confirmed: without the group ACL, the real defect reproduces: %v", err)

	err = runAsRealUID(t, unprivilegedUID, unprivilegedGID, []uint32{testGID}, "", certPath)
	if err != nil {
		t.Fatalf("expected success once the real supplementary group is granted (the actual fix -- podman --group-add / host group membership), got: %v", err)
	}
}

// TestPublishedAnalyticsSnapshotIsReadableByAnUnprivilegedUIDWithNoSpecialGroup
// is the analytics half's real regression test for the NEW design: a
// real apdns-hostagent (root) publishes a snapshot
// (internal/analyticssnapshot.Refresh) to a directory that is then
// exposed through a genuine kernel-enforced read-only bind mount (the
// exact same mechanism -- and the exact real constraint that broke the
// old direct-read design, see internal/analyticssnapshot's own
// TestPublishedSnapshotReadThroughARealReadOnlyBindMountIsSafe) -- and
// a completely unprivileged UID, with NO supplementary groups
// whatsoever (unlike the certs test above), can still open and read it
// via pyanalytics.Open. This is the concrete proof that the new
// snapshot design doesn't just fix the corruption bug, it also removes
// the whole class of group-ACL coordination the old direct-mount design
// needed for analytics specifically.
func TestPublishedAnalyticsSnapshotIsReadableByAnUnprivilegedUIDWithNoSpecialGroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("must run as root to exercise a real UID/GID drop and a real mount")
	}

	dir := t.TempDir()
	if err := os.Chmod(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "aggregates.db")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT); INSERT INTO schema_meta VALUES('version','1')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	publishedReal := filepath.Join(dir, "published-real")
	staging := filepath.Join(dir, "staging")
	if _, err := analyticssnapshot.Refresh(context.Background(), source, publishedReal, staging, 3); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	mountPoint := filepath.Join(dir, "published-ro-mount")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(publishedReal, mountPoint, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("bind mount not permitted in this environment: %v", err)
	}
	defer syscall.Unmount(mountPoint, 0)
	if err := unix.Mount("", mountPoint, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		t.Fatalf("remount read-only: %v", err)
	}

	const unprivilegedUID = 65534 // "nobody" -- no supplementary groups given at all below
	const unprivilegedGID = 65534

	err = runAsRealUID(t, unprivilegedUID, unprivilegedGID, nil, mountPoint, "")
	if err != nil {
		t.Fatalf("expected the published analytics snapshot to be readable by a completely unprivileged UID with no special group at all, got: %v", err)
	}
}
