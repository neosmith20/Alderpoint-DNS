// Package deployperm is a real, permanent regression test for a real
// deployed-UID integration defect found live on the :10443 preview:
// once the container's web process was switched from running as root
// to its real unprivileged UID (see PARITY_MATRIX.md's host-control
// boundary section), it could no longer open Python's read-only
// aggregates.db/server.crt mounts at all -- both directories are
// owned `_dnsdist:bind` mode 750 (files 640/644), a real host-side
// group ACL Python's own packaging already sets up, and the
// unprivileged web UID was not a member of that group, either on the
// host or -- more subtly, and the actual root cause -- inside the
// container process, which podman's `--user UID:GID` does not
// automatically inherit from the host's own `/etc/group` even when
// the host user IS a member. The real fix is podman's `--group-add
// <gid>`, granting exactly that one supplementary GID to the
// containerized process; this test proves the underlying mechanism
// with a real, disposable two-real-UID subprocess (never a mock),
// mirroring internal/hostagentd's own established pattern for this
// exact class of "looks fine as root, breaks for real once
// unprivileged" bug.
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

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/pyanalytics"
	"alderpointdns/go-controlplane/internal/tlscert"
)

const (
	reexecEnv   = "APDNS_DEPLOYPERM_REEXEC_PROBE"
	dbPathEnv   = "APDNS_DEPLOYPERM_DB_PATH"
	certPathEnv = "APDNS_DEPLOYPERM_CERT_PATH"
)

func TestMain(m *testing.M) {
	if os.Getenv(reexecEnv) != "" {
		os.Exit(runProbe())
	}
	os.Exit(m.Run())
}

// runProbe is what the re-exec'd subprocess actually runs, under
// whatever real UID/GID/supplementary-groups the parent test set on
// it -- the exact same pyanalytics.Open+Ping and tlscert.Reader.Status
// calls the real deployed web binary makes.
func runProbe() int {
	fail := 0
	if dbPath := os.Getenv(dbPathEnv); dbPath != "" {
		r, err := pyanalytics.Open(dbPath)
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
func runAsRealUID(t *testing.T, uid, gid uint32, groups []uint32, dbPath, certPath string) error {
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
	cmd.Env = append(os.Environ(), reexecEnv+"=1", dbPathEnv+"="+dbPath, certPathEnv+"="+certPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// TestUnprivilegedUIDNeedsTheRealSupplementaryGroupACL is the real
// regression test: a root-owned, group-restricted (750/640) directory
// tree -- the exact shape Python's own packaging already produces for
// aggregates.db/server.crt -- is unreadable by a real unprivileged UID
// with no matching supplementary group (reproducing the live :10443
// defect exactly), and becomes readable once that one GID is granted
// as a supplementary group (reproducing the real fix: podman
// `--group-add <gid>`, or the equivalent host-side group membership
// for a non-containerized deployment). Skips if not run as root (this
// test needs CAP_SETUID/CAP_SETGID to drop into a different real UID).
func TestUnprivilegedUIDNeedsTheRealSupplementaryGroupACL(t *testing.T) {
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
	dbPath := filepath.Join(dir, "aggregates.db")
	certPath := filepath.Join(dir, "server.crt")

	// A real, valid minimal aggregates.db -- in WAL journal mode, the
	// same shape as the real, live aggregates.db this defect was found
	// against (confirmed live: "PRAGMA journal_mode" reports "wal").
	// This is deliberate, not incidental: a rollback-journal-mode
	// database only needs "mode=ro" to be readable through a read-only
	// mount by an unprivileged reader with no matching group, but a
	// WAL-mode one additionally needs "immutable=1" (it otherwise tries
	// to open/create a "-shm" coordination file even for a read) -- an
	// earlier version of this test used a plain non-WAL database and
	// passed with "mode=ro" alone, silently failing to catch the real
	// live defect at all. Using the real journal mode here is what
	// makes this test an actual regression guard for the specific bug
	// found, not just a generic permission check.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT); INSERT INTO schema_meta VALUES('version','1')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// A real, valid minimal self-signed cert -- reuse the same openssl
	// invocation pattern already used elsewhere in this session's own
	// test/deploy tooling.
	keyPath := filepath.Join(dir, "server.key")
	if out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes", "-subj", "/CN=deployperm-test").CombinedOutput(); err != nil {
		t.Skipf("openssl not usable in this environment: %v: %s", err, out)
	}

	// The real permission shape: root-owned, group-restricted, exactly
	// matching what "ls -la" on the real /root/apdns-v2-preview-state
	// analytics/certs directories showed live (750 dirs, 640/644 files,
	// owner _dnsdist, group bind -- reproduced here with a throwaway
	// numeric GID nothing else on the host uses, so this test never
	// depends on a "bind" group actually existing).
	testGID := uint32(1_700_000 + os.Getpid()%9000)
	for _, p := range []string{dir, dbPath, certPath, keyPath} {
		if err := os.Chown(p, 0, int(testGID)); err != nil {
			t.Skipf("cannot chown in this environment: %v", err)
		}
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(certPath, 0o644); err != nil {
		t.Fatal(err)
	}

	const unprivilegedUID = 65534 // "nobody" -- a real, always-present, definitely-not-in-testGID unprivileged UID
	const unprivilegedGID = 65534

	err = runAsRealUID(t, unprivilegedUID, unprivilegedGID, nil, dbPath, certPath)
	if err == nil {
		t.Fatal("expected a real permission failure without the supplementary group -- test does not reproduce the live defect")
	}
	t.Logf("confirmed: without the group ACL, the real defect reproduces: %v", err)

	err = runAsRealUID(t, unprivilegedUID, unprivilegedGID, []uint32{testGID}, dbPath, certPath)
	if err != nil {
		t.Fatalf("expected success once the real supplementary group is granted (the actual fix -- podman --group-add / host group membership), got: %v", err)
	}
}
