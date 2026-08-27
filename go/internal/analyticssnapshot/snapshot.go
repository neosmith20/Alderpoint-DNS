// Package analyticssnapshot is the fix for the real, live P0 that
// e51b6fd/e7d3e9f's "just drop immutable=1" attempt could not actually
// resolve: the deployed Go container reads Python's aggregates.db
// through a genuinely kernel-enforced read-only bind mount (`ro` in
// /proc/mounts, not merely restrictive permission bits), and SQLite's
// own rollback-journal-mode read path needs to attempt a write-class
// open() (checking for a hot journal) even for a pure SELECT -- which a
// real read-only mount refuses with EROFS regardless of ownership/mode
// bits, confirmed live (20/20 real probes against the actual deployed
// mount). Plain "mode=ro" therefore cannot open the live file at all on
// this mount; only "immutable=1" could -- but immutable=1 against a
// live, actively-written file is exactly what produced the original
// SQLITE_CORRUPT incident (see internal/pyanalytics/
// repro_walcorrupt_test.go). Neither option alone satisfies "preserve
// normal SQLite locking against a live mutable database" AND "the
// source mount stays read-only" at once.
//
// This package breaks that tension instead of choosing between its two
// horns: apdns-hostagent (root, real unrestricted access to the actual
// host directory -- no read-only mount applies to it at all) produces
// a real, consistent, standalone copy of aggregates.db on a fixed
// interval using SQLite's own documented "VACUUM INTO" mechanism (the
// same safe point-in-time-copy-of-a-live-database primitive
// internal/backup already uses for control.db), publishes it via two
// atomic filesystem operations (a directory rename, then a symlink
// flip), and the Go web process reads ONLY that published snapshot,
// through its own separate, still-genuinely-read-only bind mount.
//
// The key property this buys: once published, a generation's files are
// never written again -- "immutable=1" is no longer a lie told to
// SQLite about a live database, it is the literal truth about a
// snapshot directory that has already been fully written and will never
// change. Combined with a real read-only mount, this is now the
// textbook case immutable=1 exists for (see the owner's own correction:
// "Immutable mode is appropriate only for a genuinely static
// snapshot").
//
// Layout under publishedDir:
//
//	gen-<unixnano>/aggregates.db      -- the VACUUM INTO'd copy
//	gen-<unixnano>/manifest.json      -- {generated_at, generation, source_journal_mode}
//	current -> gen-<unixnano>         -- atomically-flipped symlink, always valid once any
//	                                      generation has published
//
// ResolveCurrent (the read side, used by internal/pyanalytics) reads
// the symlink target ONCE and derives both the manifest path and the db
// path from that same resolved directory -- a concurrent Refresh
// flipping "current" mid-call can therefore never hand a caller one
// generation's manifest paired with a different generation's db file.
// Refresh retains the newest few generations (never fewer than 2) so a
// reader that resolved "current" a moment before a flip still has a
// valid, unpruned directory to finish reading from.
package analyticssnapshot

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	manifestFile = "manifest.json"
	dbFile       = "aggregates.db"
	currentLink  = "current"
	genPrefix    = "gen-"
)

// Manifest is one generation's own self-description, published
// alongside its db file -- never guessed or inferred by a reader.
type Manifest struct {
	GeneratedAt       float64 `json:"generated_at"`
	Generation        int64   `json:"generation"`
	SourceJournalMode string  `json:"source_journal_mode"`
}

// Refresh performs one full snapshot generation and returns its
// manifest. Never partially visible: every mutating filesystem
// operation a concurrent reader could observe (the final directory
// rename into publishedDir, the symlink flip) is atomic, and nothing is
// published until the db file and manifest are both already
// fully-written and fsynced in a staging location invisible to readers.
func Refresh(ctx context.Context, sourcePath, publishedDir, stagingDir string, retain int) (Manifest, error) {
	if retain < 2 {
		retain = 2
	}
	generation := time.Now().UnixNano()
	genName := genPrefix + strconv.FormatInt(generation, 10)
	stageDir := filepath.Join(stagingDir, genName)
	if err := os.RemoveAll(stageDir); err != nil {
		return Manifest{}, fmt.Errorf("clearing staging dir: %w", err)
	}
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return Manifest{}, fmt.Errorf("creating staging dir: %w", err)
	}
	defer os.RemoveAll(stageDir) // no-op once successfully renamed into publishedDir below

	journalMode, err := sourceJournalMode(ctx, sourcePath)
	if err != nil {
		return Manifest{}, fmt.Errorf("reading source journal mode: %w", err)
	}

	dst := filepath.Join(stageDir, dbFile)
	if err := vacuumInto(ctx, sourcePath, dst); err != nil {
		return Manifest{}, fmt.Errorf("VACUUM INTO snapshot: %w", err)
	}
	// This process (apdns-hostagent) runs as root against a real,
	// unrestricted host path -- world-readable is deliberate and safe
	// here: aggregate query statistics carry no secrets, and the actual
	// safety boundary is the read-only mount + this reader's own
	// mode=ro, not a group ACL Python's packaging happens to set up for
	// an entirely different (root-owned) directory.
	if err := os.Chmod(dst, 0o644); err != nil {
		return Manifest{}, fmt.Errorf("setting snapshot db permissions: %w", err)
	}

	m := Manifest{GeneratedAt: float64(time.Now().UnixNano()) / 1e9, Generation: generation, SourceJournalMode: journalMode}
	raw, err := json.Marshal(m)
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(stageDir, manifestFile), raw, 0o644); err != nil {
		return Manifest{}, fmt.Errorf("writing manifest: %w", err)
	}
	if err := fsyncDir(stageDir); err != nil {
		return Manifest{}, fmt.Errorf("fsyncing staged generation: %w", err)
	}

	if err := os.MkdirAll(publishedDir, 0o755); err != nil {
		return Manifest{}, fmt.Errorf("creating published dir: %w", err)
	}
	finalDir := filepath.Join(publishedDir, genName)
	if err := os.Rename(stageDir, finalDir); err != nil {
		return Manifest{}, fmt.Errorf("publishing generation: %w", err)
	}
	if err := fsyncDir(publishedDir); err != nil {
		return Manifest{}, fmt.Errorf("fsyncing published dir after rename: %w", err)
	}

	// Symlink flip: create under a unique temp name, then rename it
	// onto "current" -- rename() atomically replaces any existing
	// target, so a reader resolving "current" concurrently always sees
	// either the fully-old or fully-new target, never a half-written
	// one (unlike, say, os.Remove followed by os.Symlink, which would
	// have a real window with no "current" at all).
	tmpLink := filepath.Join(publishedDir, fmt.Sprintf(".%s.tmp-%d", currentLink, generation))
	os.Remove(tmpLink)
	if err := os.Symlink(genName, tmpLink); err != nil {
		return Manifest{}, fmt.Errorf("staging current symlink: %w", err)
	}
	if err := os.Rename(tmpLink, filepath.Join(publishedDir, currentLink)); err != nil {
		return Manifest{}, fmt.Errorf("flipping current symlink: %w", err)
	}

	pruneOldGenerations(publishedDir, retain)
	return m, nil
}

func vacuumInto(ctx context.Context, sourcePath, dstPath string) error {
	db, err := sql.Open("sqlite", "file:"+sourcePath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	// VACUUM INTO's target filename has no bind-parameter form in
	// standard SQLite syntax; dstPath is entirely host-agent-controlled
	// (built from this process's own -analytics-snapshot-staging-dir
	// flag plus a generated timestamp, never from any request or
	// user-controlled string), so a single-quote-escaped literal is
	// safe here -- no untrusted input ever reaches this SQL text.
	_, err = db.ExecContext(ctx, "VACUUM INTO "+quoteSQLString(dstPath))
	return err
}

func quoteSQLString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// sourceJournalMode is informational only (recorded in the manifest,
// surfaced by Health) -- Refresh's own safety never depends on which
// mode the source happens to be in, VACUUM INTO handles both correctly.
func sourceJournalMode(ctx context.Context, sourcePath string) (string, error) {
	db, err := sql.Open("sqlite", "file:"+sourcePath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return "", err
	}
	defer db.Close()
	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
		return "", err
	}
	return mode, nil
}

func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// pruneGrace is the minimum age a generation must reach before it's
// eligible for removal at all, regardless of retain -- protects a
// reader that has already resolved "current" to some now-superseded
// generation's directory name but hasn't finished opening its db file
// yet (a real, if normally microsecond-scale, window between
// ResolveCurrent's os.Readlink and the caller's sql.Open). Count-based
// retention alone (just "keep the newest N") isn't enough under a
// refresh cadence fast relative to a reader's own open latency -- this
// package's own concurrent tests publish far faster than any real
// deployment's interval (see internal/hostagentd's own default, 15s)
// specifically to prove that margin holds even then.
const pruneGrace = 5 * time.Second

// pruneOldGenerations keeps every generation that is EITHER among the
// `retain` most recent OR younger than pruneGrace (gen-<unixnano> sorts
// lexically the same as numerically, fixed-width decimal for any
// foreseeable timestamp, and doubles as that generation's exact
// creation instant, avoiding a filesystem mtime dependency) -- the
// generation "current" points at is always among the newest (Refresh
// just published it), and both conditions exist so neither a burst of
// rapid publishes nor a slow reader alone can cause a resolved-but-
// pruned-out-from-under-it read.
func pruneOldGenerations(publishedDir string, retain int) {
	entries, err := os.ReadDir(publishedDir)
	if err != nil {
		return
	}
	var gens []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), genPrefix) {
			gens = append(gens, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(gens)))
	cutoff := time.Now().Add(-pruneGrace).UnixNano()
	for i, g := range gens {
		if i < retain {
			continue
		}
		genNanos, err := strconv.ParseInt(strings.TrimPrefix(g, genPrefix), 10, 64)
		if err == nil && genNanos > cutoff {
			continue // too young to prune yet, even though it's beyond `retain`
		}
		os.RemoveAll(filepath.Join(publishedDir, g))
	}
}

// Resolved is ResolveCurrent's result: a self-consistent generation --
// its db path and manifest always come from the exact same resolved
// directory.
type Resolved struct {
	GenDir   string
	DBPath   string
	Manifest Manifest
}

// ResolveCurrent reads the "current" symlink and that exact generation's
// manifest -- both from the one resolved directory, so a concurrent
// Refresh flipping "current" mid-call can never mix generations. Returns
// a real, actionable error (never masked) when no generation has ever
// been published yet, or the manifest is unreadable/malformed.
func ResolveCurrent(publishedDir string) (Resolved, error) {
	target, err := os.Readlink(filepath.Join(publishedDir, currentLink))
	if err != nil {
		return Resolved{}, fmt.Errorf("no published analytics snapshot yet (reading %q symlink under %s): %w", currentLink, publishedDir, err)
	}
	// target is a relative name (e.g. "gen-172..."), written by Refresh
	// in this same package -- Join keeps resolution within publishedDir
	// regardless.
	genDir := filepath.Join(publishedDir, filepath.Base(target))
	raw, err := os.ReadFile(filepath.Join(genDir, manifestFile))
	if err != nil {
		return Resolved{}, fmt.Errorf("reading snapshot manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Resolved{}, fmt.Errorf("parsing snapshot manifest: %w", err)
	}
	return Resolved{GenDir: genDir, DBPath: filepath.Join(genDir, dbFile), Manifest: m}, nil
}
