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
	"strings"
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

	// A real, valid minimal aggregates.db -- deliberately in DELETE
	// (rollback-journal) mode, matching the real, live aggregates.db's
	// actual on-disk journal_mode confirmed during the 2026-08-27
	// "database disk image is malformed" incident (PRAGMA readback
	// against the live file reported "delete", not "wal", despite
	// Python's own aggregates_db.py requesting WAL on every connect --
	// see AGENT_PROGRESS.md and internal/pyanalytics/reader.go's Open
	// doc comment for the full story). This test previously used a
	// WAL-mode fixture and required "immutable=1" to pass -- that
	// design is exactly what caused the live corruption bug (see
	// internal/pyanalytics/repro_walcorrupt_test.go's
	// TestWALCorruptionRepro_Matrix: immutable=1 produced real
	// SQLITE_CORRUPT reads under concurrent WAL writes too, WAL mode
	// does not make immutable=1 safe). The reader no longer uses
	// immutable=1 at all; a plain rollback-journal-mode reader only
	// needs "mode=ro" to be readable through a read-only mount by an
	// unprivileged reader with a matching group (real POSIX advisory
	// read locks need no directory write access) -- see the WAL-specific
	// follow-up test below for the disclosed gap that remains for a
	// genuinely WAL-mode database under this same strict mount.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
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

// TestReadOnlyMountCannotSupportWALEvenWithGroupAccess documents a real,
// disclosed residual gap left by removing immutable=1 (see
// internal/pyanalytics/reader.go's Open doc comment and
// repro_walcorrupt_test.go): if aggregates.db ever genuinely runs in WAL
// journal mode while the analytics directory stays a strictly
// read-only-for-group (0750, no write bit) mount -- the real permission
// shape Python's own packaging sets up -- this reader cannot open it at
// all, even with the correct supplementary group, because WAL readers
// must be able to create/update a "-shm" coordination file in that same
// directory and mode=ro alone (without immutable=1) does not exempt
// that. This is intentional and safe, not a bug this package should
// paper over: failing to open cleanly (a permission error) is the
// correct behavior per "never silently mask genuine corruption, remain
// degraded/failed if a real problem persists" -- the alternative
// (immutable=1) trades this honest failure for the exact live corruption
// incident this whole test suite exists to prevent. Fixing this gap for
// real (a group-writable directory, or Python moving off WAL for this
// file, which the live diagnosis suggests may already effectively be the
// case) is future work outside this package's own authority -- it would
// touch the production analytics directory's real permissions or
// Python's own aggregates_db.py, both explicitly out of scope here.
func TestReadOnlyMountCannotSupportWALEvenWithGroupAccess(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("must run as root to exercise a real UID/GID drop")
	}

	dir := t.TempDir()
	if err := os.Chmod(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "aggregates.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Skipf("could not actually get this fixture into WAL mode (got %q) -- environment can't run this test meaningfully", mode)
	}
	if _, err := db.Exec(`CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT); INSERT INTO schema_meta VALUES('version','1')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	testGID := uint32(1_700_000 + os.Getpid()%9000)
	for _, p := range []string{dir, dbPath} {
		if err := os.Chown(p, 0, int(testGID)); err != nil {
			t.Skipf("cannot chown in this environment: %v", err)
		}
	}
	if err := os.Chmod(dir, 0o750); err != nil { // the real, strict Python-packaging shape -- no write bit for group
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0o640); err != nil {
		t.Fatal(err)
	}

	const unprivilegedUID = 65534
	const unprivilegedGID = 65534
	err = runAsRealUID(t, unprivilegedUID, unprivilegedGID, []uint32{testGID}, dbPath, "")
	if err == nil {
		t.Fatal("expected a real open failure for a WAL-mode db under a strictly read-only (no group write) mount even with correct group access -- if this now succeeds, immutable=1 or an equivalent must have been silently reintroduced, which would reopen the corruption bug this package guards against")
	}
	if !strings.Contains(err.Error(), "readonly") && !strings.Contains(err.Error(), "unable to open") {
		t.Fatalf("expected a clean permission/open failure (never a corrupt-looking error, and never a silent success), got: %v", err)
	}
	t.Logf("confirmed disclosed gap: WAL-mode db under a strict read-only mount fails cleanly even with group access: %v", err)
}
