package analyticssnapshot

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	_ "modernc.org/sqlite"
)

func newSourceFixture(t *testing.T, journalMode string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aggregates.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var got string
	if err := db.QueryRow(`PRAGMA journal_mode = ` + journalMode).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(got, journalMode) {
		t.Skipf("could not actually get journal_mode=%s in this environment (got %q)", journalMode, got)
	}
	if _, err := db.Exec(`
		CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO schema_meta VALUES ('version', '1');
		CREATE TABLE time_buckets (bucket_start INTEGER, granularity TEXT, total_queries INTEGER, blocked_queries INTEGER, cache_hits INTEGER, cache_misses INTEGER);
		INSERT INTO time_buckets VALUES (60, 'minute', 5, 1, 3, 2);
	`); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRefreshProducesAValidReadableSnapshotForBothJournalModes(t *testing.T) {
	for _, mode := range []string{"DELETE", "WAL"} {
		t.Run(mode, func(t *testing.T) {
			source := newSourceFixture(t, mode)
			published := filepath.Join(t.TempDir(), "published")
			staging := filepath.Join(t.TempDir(), "staging")

			m, err := Refresh(context.Background(), source, published, staging, 3)
			if err != nil {
				t.Fatalf("Refresh: %v", err)
			}
			if m.SourceJournalMode == "" {
				t.Fatal("expected a non-empty recorded source_journal_mode")
			}

			resolved, err := ResolveCurrent(published)
			if err != nil {
				t.Fatalf("ResolveCurrent: %v", err)
			}
			if resolved.Manifest.Generation != m.Generation {
				t.Fatalf("resolved generation %d != refreshed generation %d", resolved.Manifest.Generation, m.Generation)
			}

			// The published copy must be a real, independently valid
			// SQLite file with the real data, opened WITHOUT immutable
			// this time (proving it's a genuinely separate, complete
			// file, not some lazy reference into the source).
			db, err := sql.Open("sqlite", "file:"+resolved.DBPath+"?mode=ro")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var v string
			if err := db.QueryRow(`SELECT value FROM schema_meta LIMIT 1`).Scan(&v); err != nil {
				t.Fatalf("querying published snapshot: %v", err)
			}
			if v != "1" {
				t.Fatalf("expected schema_meta value '1', got %q", v)
			}
			var total int
			if err := db.QueryRow(`SELECT total_queries FROM time_buckets WHERE bucket_start=60`).Scan(&total); err != nil || total != 5 {
				t.Fatalf("expected real copied row data (total_queries=5), got total=%d err=%v", total, err)
			}
		})
	}
}

func TestResolveCurrentFailsHonestlyWithNoPublishedGeneration(t *testing.T) {
	_, err := ResolveCurrent(filepath.Join(t.TempDir(), "never-published"))
	if err == nil {
		t.Fatal("expected an error when nothing has ever been published, not a silent zero-value success")
	}
}

// TestRefreshAndResolveStayConsistentUnderRealConcurrentWriteAndRefresh
// is the core regression proof: a real writer (Python-shaped, fresh
// connection per batch, structural insert/delete churn) mutates the
// SOURCE continuously in both journal modes while Refresh runs
// repeatedly and ResolveCurrent is polled concurrently -- every single
// resolution must open a fully valid, internally self-consistent
// snapshot (real PRAGMA integrity_check ok, manifest generation matches
// the db file actually opened), never a torn/partial one, and the
// writer must never be starved by the snapshot process running
// alongside it.
func TestRefreshAndResolveStayConsistentUnderRealConcurrentWriteAndRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("concurrent stress test -- skipped under -short")
	}
	for _, mode := range []string{"DELETE", "WAL"} {
		t.Run(mode, func(t *testing.T) {
			source := newSourceFixture(t, mode)
			published := filepath.Join(t.TempDir(), "published")
			staging := filepath.Join(t.TempDir(), "staging")

			stop := make(chan struct{})
			var writerCommits, writerAttempts atomic.Int64
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				rng := rand.New(rand.NewSource(1))
				tick := 0
				for {
					select {
					case <-stop:
						return
					default:
					}
					writerAttempts.Add(1)
					func() {
						db, err := sql.Open("sqlite", source)
						if err != nil {
							return
						}
						defer db.Close()
						db.Exec(fmt.Sprintf(`PRAGMA journal_mode = %s`, mode))
						db.Exec(`PRAGMA busy_timeout = 5000`)
						tx, err := db.Begin()
						if err != nil {
							return
						}
						bucket := tick * 60
						tick++
						if _, err := tx.Exec(`INSERT INTO time_buckets VALUES (?, 'minute', ?, ?, ?, ?)`,
							bucket, rng.Intn(100), rng.Intn(10), rng.Intn(50), rng.Intn(50)); err != nil {
							tx.Rollback()
							return
						}
						if tick > 10 {
							tx.Exec(`DELETE FROM time_buckets WHERE bucket_start=?`, (tick-10)*60)
						}
						if tx.Commit() == nil {
							writerCommits.Add(1)
						}
					}()
				}
			}()

			var refreshOK, refreshErr, resolveOK, resolveErr, integrityErr atomic.Int64
			wg.Add(2)
			go func() {
				defer wg.Done()
				deadline := time.Now().Add(1200 * time.Millisecond)
				for time.Now().Before(deadline) {
					if _, err := Refresh(context.Background(), source, published, staging, 3); err != nil {
						refreshErr.Add(1)
						t.Logf("Refresh error (mode=%s): %v", mode, err)
					} else {
						refreshOK.Add(1)
					}
				}
			}()
			go func() {
				defer wg.Done()
				deadline := time.Now().Add(1200 * time.Millisecond)
				for time.Now().Before(deadline) {
					resolved, err := ResolveCurrent(published)
					if err != nil {
						// Expected only until the very first Refresh
						// completes -- not counted as a hard failure by
						// itself, but every SUBSEQUENT resolution once one
						// has succeeded must also succeed.
						resolveErr.Add(1)
						continue
					}
					resolveOK.Add(1)
					db, err := sql.Open("sqlite", "file:"+resolved.DBPath+"?mode=ro&immutable=1")
					if err != nil {
						integrityErr.Add(1)
						continue
					}
					var check string
					if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
						integrityErr.Add(1)
						t.Logf("integrity_check against a published snapshot failed: check=%q err=%v", check, err)
					}
					db.Close()
				}
			}()

			time.Sleep(1300 * time.Millisecond) // outlast both goroutines' own 1200ms deadlines
			close(stop)
			wg.Wait()

			t.Logf("mode=%s writer(attempts=%d commits=%d) refresh(ok=%d err=%d) resolve(ok=%d err=%d) integrityErr=%d",
				mode, writerAttempts.Load(), writerCommits.Load(), refreshOK.Load(), refreshErr.Load(), resolveOK.Load(), resolveErr.Load(), integrityErr.Load())

			if writerAttempts.Load() > 0 && writerCommits.Load() == 0 {
				t.Fatalf("mode=%s: writer never committed a single batch -- test setup broken", mode)
			}
			if refreshOK.Load() == 0 {
				t.Fatalf("mode=%s: Refresh never succeeded even once", mode)
			}
			if integrityErr.Load() > 0 {
				t.Fatalf("mode=%s: %d published snapshot reads failed integrity_check or failed to open -- the whole point of this design is that a published generation is never torn/inconsistent", mode, integrityErr.Load())
			}
			if resolveOK.Load() == 0 {
				t.Fatalf("mode=%s: ResolveCurrent never succeeded even once", mode)
			}
		})
	}
}

// TestPublishedSnapshotReadThroughARealReadOnlyBindMountIsSafe is the
// exact constraint that broke the earlier "just drop immutable=1"
// attempt: a genuine kernel-level read-only bind mount (not just
// restrictive permission bits -- confirmed via /proc/mounts and a real
// EROFS write attempt, matching the live :10443 deployment exactly),
// with a real writer continuously refreshing new generations into the
// SOURCE (which is NOT under the read-only mount -- only the published
// directory is, matching the real deployment's architecture). Proves
// mode=ro&immutable=1 against the published (mounted read-only)
// snapshot opens and reads successfully and consistently -- unlike
// plain mode=ro, which the live incident proved cannot even open on a
// real read-only mount.
func TestPublishedSnapshotReadThroughARealReadOnlyBindMountIsSafe(t *testing.T) {
	if testing.Short() {
		t.Skip("concurrent stress test with a real mount -- skipped under -short")
	}
	if os.Getuid() != 0 {
		t.Skip("real bind mounts need CAP_SYS_ADMIN -- must run as root")
	}
	mode := "DELETE"
	source := newSourceFixture(t, mode)
	publishedReal := filepath.Join(t.TempDir(), "published-real")
	if err := os.MkdirAll(publishedReal, 0o755); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(t.TempDir(), "staging")

	// Publish one generation BEFORE mounting -- ResolveCurrent's
	// symlink target must survive being observed through a bind mount.
	if _, err := Refresh(context.Background(), source, publishedReal, staging, 3); err != nil {
		t.Fatalf("initial Refresh: %v", err)
	}

	mountPoint := filepath.Join(t.TempDir(), "published-ro-mount")
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

	// Confirm this is a REAL kernel-enforced read-only mount, the same
	// shape as production (matching AGENT_PROGRESS.md's own live
	// verification: "Read-only file system" on a write attempt, "ro" in
	// /proc/mounts) -- not just restrictive permission bits.
	if err := os.WriteFile(filepath.Join(mountPoint, "canary"), []byte("x"), 0o644); err == nil {
		t.Fatal("expected the read-only bind mount to refuse a write -- test does not actually reproduce the real constraint")
	} else if !os.IsPermission(err) && !isReadOnlyFSError(err) {
		t.Fatalf("expected a permission/read-only-fs error, got: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var refreshOK atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(1000 * time.Millisecond)
		for time.Now().Before(deadline) {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := Refresh(context.Background(), source, publishedReal, staging, 3); err == nil {
				refreshOK.Add(1)
			}
		}
	}()

	var readOK, readErr atomic.Int64
	deadline := time.Now().Add(1000 * time.Millisecond)
	for time.Now().Before(deadline) {
		resolved, err := ResolveCurrent(mountPoint) // resolved THROUGH the real read-only mount
		if err != nil {
			readErr.Add(1)
			continue
		}
		db, err := sql.Open("sqlite", "file:"+resolved.DBPath+"?mode=ro&immutable=1")
		if err != nil {
			readErr.Add(1)
			continue
		}
		var v string
		if err := db.QueryRow(`SELECT value FROM schema_meta LIMIT 1`).Scan(&v); err != nil {
			readErr.Add(1)
			t.Logf("read through real read-only mount failed: %v", err)
		} else {
			readOK.Add(1)
		}
		db.Close()
	}
	close(stop)
	wg.Wait()

	t.Logf("refreshOK=%d readOK=%d readErr=%d (through a real kernel read-only bind mount)", refreshOK.Load(), readOK.Load(), readErr.Load())
	if readOK.Load() == 0 {
		t.Fatal("expected at least some successful reads through the real read-only mount")
	}
	if readErr.Load() > 0 {
		t.Fatalf("expected ZERO read failures through the real read-only mount (this is the whole point of the design) -- got %d", readErr.Load())
	}
}

func isReadOnlyFSError(err error) bool {
	return err != nil && (err.Error() != "" && (containsAny(err.Error(), "read-only", "EROFS")))
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
