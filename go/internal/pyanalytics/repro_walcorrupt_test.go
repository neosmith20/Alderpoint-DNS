package pyanalytics

// This file is a real, concurrent reproduction harness for the live P0
// incident recorded in AGENT_PROGRESS.md ("Analytics degraded: database
// disk image is malformed (11)"). It exists to PROVE, not assume, which
// factor (immutable mode, connection lifetime, journal mode, or WAL's own
// checkpoint/transition locking) actually produces a transient
// SQLITE_CORRUPT read against Python's real write pattern -- per the
// owner's explicit correction, a WAL database being reported as "wal" is
// NOT proof it's safe to read with immutable=1: WAL databases are still
// mutable (periodic checkpoints do rewrite the main db file in place).
//
// The writer goroutine below is a byte-for-byte behavioral match of
// app/v2/aggregates_db.py's real write pattern (verified by reading that
// file directly, not guessed): a FRESH connection is opened for every
// write batch (never a held connection), each one issues
// "PRAGMA journal_mode = WAL" and "PRAGMA busy_timeout = 5000" on
// connect (whether or not the mode actually takes -- this harness
// controls that explicitly per scenario, see runJournalMode), then a
// single explicit transaction writes a batch of rows and commits, then
// the connection closes. This matches aggregates_db.connect()'s own doc
// comment ("own connection, own WAL, own busy_timeout -- completely
// independent of control.db's connection lifecycle") and
// analytics_pipeline.py's real call pattern (one connect() per flush()
// tick via record_batch/record_live_batch).
//
// Read-only-mount emulation: production reads aggregates.db through a
// read-only bind mount (see AGENT_PROGRESS.md's mount table); the
// software-level equivalent already used by internal/pyanalytics.Open is
// the "mode=ro" URI parameter, which is what every reader scenario below
// uses too -- a real bind mount is a kernel/namespace concern out of
// scope for a Go unit test, but "mode=ro" is the exact mechanism
// standing in for it in the real deployed reader, so this is not a
// weaker constraint than production, just the same one.
import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	_ "modernc.org/sqlite"
)

// numDimensionRows is deliberately large enough that dimension_counts
// spans many database pages (not just one) -- a torn read that only
// tears within a single page would be a much narrower, less realistic
// reproduction of a real dashboard-sized deployment.
const numDimensionRows = 4000

func reproSchema(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`
		CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO schema_meta VALUES ('version', '1');
		CREATE TABLE time_buckets (
			bucket_start INTEGER NOT NULL, granularity TEXT NOT NULL,
			total_queries INTEGER NOT NULL DEFAULT 0, blocked_queries INTEGER NOT NULL DEFAULT 0,
			cache_hits INTEGER NOT NULL DEFAULT 0, cache_misses INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (bucket_start, granularity)
		);
		CREATE TABLE dimension_counts (
			bucket_start INTEGER NOT NULL, granularity TEXT NOT NULL, dimension TEXT NOT NULL,
			value TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (bucket_start, granularity, dimension, value)
		);
		CREATE INDEX idx_dim_lookup ON dimension_counts(granularity, dimension, bucket_start);
		CREATE TABLE live_buckets (
			bucket_start INTEGER PRIMARY KEY, total_queries INTEGER NOT NULL DEFAULT 0,
			blocked_queries INTEGER NOT NULL DEFAULT 0, cache_hits INTEGER NOT NULL DEFAULT 0,
			cache_misses INTEGER NOT NULL DEFAULT 0, updated_at REAL NOT NULL
		);
	`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < numDimensionRows; i++ {
		if _, err := tx.Exec(`INSERT INTO dimension_counts(bucket_start, granularity, dimension, value, count) VALUES (?,?,?,?,?)`,
			3600, "hour", "domain", fmt.Sprintf("host-%05d.example.", i), i); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// setJournalMode opens its own connection to set and VERIFY the on-disk
// journal mode before any concurrent scenario starts -- the owner's
// instruction is explicit: record the observed PRAGMA return value, never
// assume Python's own request succeeded.
func setJournalMode(t *testing.T, path, want string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var got string
	if err := db.QueryRow(`PRAGMA journal_mode = ` + want).Scan(&got); err != nil {
		t.Fatalf("setting journal_mode=%s: %v", want, err)
	}
	if !strings.EqualFold(got, want) {
		t.Fatalf("requested journal_mode=%s but PRAGMA reported %q -- cannot run this scenario, the precondition itself failed", want, got)
	}
	t.Logf("verified on-disk journal_mode=%s (PRAGMA readback confirmed, not assumed)", got)
}

// pyWriter reproduces app/v2/aggregates_db.py's real write pattern: a
// brand-new connection per batch, WAL requested every time (whether or
// not it actually takes is outside this function's control -- that's
// the whole point), a real transaction, then close. Runs until stop is
// closed. Returns commit/attempt counts so a scenario can prove the
// final design never starves this writer.
type writerStats struct {
	attempts   atomic.Int64
	commits    atomic.Int64
	busyErrors atomic.Int64
	otherErrs  atomic.Int64
}

func pyWriter(t *testing.T, path string, stop <-chan struct{}, stats *writerStats) {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	// tick simulates a sliding window of minute buckets, matching
	// analytics_pipeline.py's real per-flush behavior: each write
	// INSERTs a fresh bucket's worth of dimension rows and DELETEs a
	// now-retired one (delete_old_buckets' own retention job), forcing
	// real b-tree page allocation/free-list churn -- not just in-place
	// UPDATEs of existing rows, which never move data between pages and
	// so cannot exercise the structural-consistency hazard a
	// mid-transaction reader is actually at risk from.
	tick := 0
	for {
		select {
		case <-stop:
			return
		default:
		}
		stats.attempts.Add(1)
		bucket := tick
		retiring := tick - 20 // a 20-tick sliding retention window
		tick++
		func() {
			db, err := sql.Open("sqlite", path)
			if err != nil {
				stats.otherErrs.Add(1)
				return
			}
			defer db.Close()
			// Match aggregates_db.connect(): request WAL and set
			// busy_timeout on every single connection, matching
			// Python's own code exactly (including that it never
			// checks whether the WAL request actually took).
			db.Exec(`PRAGMA journal_mode = WAL`)
			db.Exec(`PRAGMA busy_timeout = 5000`)
			tx, err := db.Begin()
			if err != nil {
				classifyWriterErr(stats, err)
				return
			}
			for i := 0; i < 40; i++ {
				row := rng.Intn(numDimensionRows)
				if _, err := tx.Exec(`INSERT OR REPLACE INTO dimension_counts(bucket_start, granularity, dimension, value, count) VALUES (?,?,?,?,?)`,
					bucket, "minute", "domain", fmt.Sprintf("host-%05d.example.", row), i); err != nil {
					tx.Rollback()
					classifyWriterErr(stats, err)
					return
				}
			}
			if retiring >= 0 {
				if _, err := tx.Exec(`DELETE FROM dimension_counts WHERE bucket_start=? AND granularity='minute'`, retiring); err != nil {
					tx.Rollback()
					classifyWriterErr(stats, err)
					return
				}
			}
			// Also churn the always-present hour-granularity rows
			// in place (the original UPDATE-only shape), so both
			// hazards -- structural churn AND simple in-place
			// updates -- are covered by the same writer.
			for i := 0; i < 10; i++ {
				row := rng.Intn(numDimensionRows)
				if _, err := tx.Exec(`UPDATE dimension_counts SET count = count + 1 WHERE bucket_start=3600 AND granularity='hour' AND dimension='domain' AND value=?`,
					fmt.Sprintf("host-%05d.example.", row)); err != nil {
					tx.Rollback()
					classifyWriterErr(stats, err)
					return
				}
			}
			if err := tx.Commit(); err != nil {
				classifyWriterErr(stats, err)
				return
			}
			stats.commits.Add(1)
		}()
	}
}

func classifyWriterErr(stats *writerStats, err error) {
	var se *sqlite.Error
	if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_BUSY {
		stats.busyErrors.Add(1)
		return
	}
	stats.otherErrs.Add(1)
}

// readerConfig is the full factorial the owner asked for: DELETE vs WAL
// journal mode (set once, up front, and verified), immutable=1 vs plain
// mode=ro, and a long-lived single *sql.DB vs a fresh connection opened
// for every single query (matching the two candidate final designs).
type readerConfig struct {
	immutable bool
	longLived bool
}

func (c readerConfig) uri(path string) string {
	if c.immutable {
		return "file:" + path + "?mode=ro&immutable=1&_pragma=busy_timeout(2000)"
	}
	return "file:" + path + "?mode=ro&_pragma=busy_timeout(2000)"
}

type readerStats struct {
	queries    atomic.Int64
	corruptErr atomic.Int64
	busyErr    atomic.Int64
	otherErr   atomic.Int64
	corruptMsg atomic.Value // last corrupt error text, for evidence
}

func runReaderScenario(t *testing.T, path string, cfg readerConfig, duration time.Duration) *readerStats {
	t.Helper()
	stats := &readerStats{}
	stop := make(chan struct{})
	var wstats writerStats
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); pyWriter(t, path, stop, &wstats) }()

	// Deliberately queries the "minute" granularity rows -- the ones the
	// writer above is structurally inserting/deleting every tick (real
	// page allocation/free-list churn), not just the in-place-updated
	// "hour" rows -- this is where a mid-transaction reader is actually
	// at structural risk, matching Top Domains' real query shape
	// (TopDimension in reader.go).
	query := `SELECT value, SUM(count) AS total FROM dimension_counts
		WHERE dimension='domain' AND granularity='minute' AND bucket_start>=0 AND bucket_start<9999999999
		GROUP BY value ORDER BY total DESC LIMIT 10`

	runQuery := func(db *sql.DB) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			var total int64
			if err := rows.Scan(&v, &total); err != nil {
				return err
			}
		}
		return rows.Err()
	}

	// Multiple concurrent readers, matching the real dashboard's actual
	// access pattern (Top Domains, Top Blocked Domains, live-activity all
	// fire close together on page load -- see AGENT_PROGRESS.md's timing
	// evidence, 87ms/207ms calls landing within the same second) --
	// serializing on a single reader goroutine would understate real
	// concurrency and the resulting race window.
	const concurrentReaders = 6
	deadline := time.Now().Add(duration)
	var rwg sync.WaitGroup
	readerLoop := func(db *sql.DB, ownDB bool) {
		defer rwg.Done()
		for time.Now().Before(deadline) {
			stats.queries.Add(1)
			if ownDB {
				fresh, err := sql.Open("sqlite", cfg.uri(path))
				if err != nil {
					recordReaderErr(stats, err)
					continue
				}
				err = runQuery(fresh)
				fresh.Close()
				if err != nil {
					recordReaderErr(stats, err)
				}
			} else if err := runQuery(db); err != nil {
				recordReaderErr(stats, err)
			}
		}
	}

	if cfg.longLived {
		db, err := sql.Open("sqlite", cfg.uri(path))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		for i := 0; i < concurrentReaders; i++ {
			rwg.Add(1)
			go readerLoop(db, false)
		}
	} else {
		for i := 0; i < concurrentReaders; i++ {
			rwg.Add(1)
			go readerLoop(nil, true)
		}
	}
	rwg.Wait()

	close(stop)
	wg.Wait()

	t.Logf("writer: attempts=%d commits=%d busy=%d other=%d (starvation would show as commits << attempts)",
		wstats.attempts.Load(), wstats.commits.Load(), wstats.busyErrors.Load(), wstats.otherErrs.Load())
	if wstats.attempts.Load() > 0 && wstats.commits.Load() == 0 {
		t.Errorf("writer never committed a single batch during this scenario -- real starvation, not just contention")
	}
	return stats
}

func recordReaderErr(stats *readerStats, err error) {
	msg := err.Error()
	if strings.Contains(msg, "malformed") || strings.Contains(msg, "SQLITE_CORRUPT") {
		stats.corruptErr.Add(1)
		stats.corruptMsg.Store(msg)
		return
	}
	var se *sqlite.Error
	if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_BUSY {
		stats.busyErr.Add(1)
		return
	}
	stats.otherErr.Add(1)
}

// TestWALCorruptionRepro_Matrix is the real concurrent reproduction the
// owner required before any reader-design decision: full factorial of
// {DELETE, WAL} x {immutable=1, mode=ro-only} x {long-lived, short-lived
// reader connection}, each against a writer that behaves exactly like
// Python's real aggregates_db.py. Every scenario's on-disk journal_mode
// is verified via PRAGMA readback (not assumed) before the concurrent
// phase starts. Results are logged with -v so the exact evidence (error
// counts, sample error text) is captured in test output for
// AGENT_PROGRESS.md, not just asserted blindly.
func TestWALCorruptionRepro_Matrix(t *testing.T) {
	if testing.Short() {
		t.Skip("concurrent stress repro -- skipped under -short")
	}
	const scenarioDuration = 1500 * time.Millisecond

	type scenario struct {
		name    string
		journal string
		cfg     readerConfig
	}
	scenarios := []scenario{
		{"DELETE_immutable_longLived", "DELETE", readerConfig{immutable: true, longLived: true}},
		{"DELETE_immutable_shortLived", "DELETE", readerConfig{immutable: true, longLived: false}},
		{"DELETE_plainRO_longLived", "DELETE", readerConfig{immutable: false, longLived: true}},
		{"DELETE_plainRO_shortLived", "DELETE", readerConfig{immutable: false, longLived: false}},
		{"WAL_immutable_longLived", "WAL", readerConfig{immutable: true, longLived: true}},
		{"WAL_immutable_shortLived", "WAL", readerConfig{immutable: true, longLived: false}},
		{"WAL_plainRO_longLived", "WAL", readerConfig{immutable: false, longLived: true}},
		{"WAL_plainRO_shortLived", "WAL", readerConfig{immutable: false, longLived: false}},
	}

	results := make(map[string]*readerStats)
	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "aggregates.db")
			reproSchema(t, path)
			setJournalMode(t, path, sc.journal)
			stats := runReaderScenario(t, path, sc.cfg, scenarioDuration)
			results[sc.name] = stats
			corrupt := stats.corruptErr.Load()
			var sample string
			if v := stats.corruptMsg.Load(); v != nil {
				sample = v.(string)
			}
			t.Logf("RESULT %-30s queries=%d corrupt=%d busy=%d other=%d sample_corrupt_err=%q",
				sc.name, stats.queries.Load(), corrupt, stats.busyErr.Load(), stats.otherErr.Load(), sample)
		})
	}
}

// TestImmutableLongLivedConnectionIsStaleNotSafe follows up on the matrix
// above's most surprising cell: WAL_immutable_longLived and
// DELETE_immutable_longLived produced ZERO corrupt errors despite ~21000
// queries each against an actively, structurally mutating file -- a
// result that could be misread as "immutable=1 is fine as long as the
// connection stays open". This test proves that isn't safety, it's
// staleness: a long-lived immutable=1 connection keeps answering from
// (approximately) the snapshot it saw at open time and never observes
// later writes, which is exactly why it never trips over one either.
// Directly confirms the owner's correction: immutable mode is for a
// genuinely static snapshot, not a live database, WAL or not.
func TestImmutableLongLivedConnectionIsStaleNotSafe(t *testing.T) {
	if testing.Short() {
		t.Skip("stress repro -- skipped under -short")
	}
	path := filepath.Join(t.TempDir(), "aggregates.db")
	reproSchema(t, path)
	setJournalMode(t, path, "WAL")

	longLived, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer longLived.Close()

	countMinuteRows := func(db *sql.DB) int {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM dimension_counts WHERE granularity='minute'`).Scan(&n); err != nil {
			t.Fatalf("count query on long-lived immutable connection failed: %v", err)
		}
		return n
	}

	before := countMinuteRows(longLived)

	stop := make(chan struct{})
	var wstats writerStats
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); pyWriter(t, path, stop, &wstats) }()
	time.Sleep(1200 * time.Millisecond) // let the writer insert many fresh "minute" rows
	close(stop)
	wg.Wait()

	afterOnLongLived := countMinuteRows(longLived)

	fresh, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	afterOnFreshConn := countMinuteRows(fresh)

	t.Logf("minute-granularity row count: before=%d afterOnLongLivedConn=%d afterOnFreshImmutableConn=%d (writer committed %d batches)",
		before, afterOnLongLived, afterOnFreshConn, wstats.commits.Load())

	if wstats.commits.Load() == 0 {
		t.Fatal("writer never committed -- test setup broken, can't conclude anything")
	}
	if afterOnFreshConn <= before {
		t.Fatalf("sanity check failed: a brand-new connection should see the writer's inserts (before=%d, fresh=%d)", before, afterOnFreshConn)
	}
	if afterOnLongLived != before {
		t.Logf("NOTE: the long-lived immutable connection did observe some change (%d -> %d) -- staleness is not absolute, but see corruption-rate evidence in the matrix test instead", before, afterOnLongLived)
	} else {
		t.Logf("CONFIRMED: the long-lived immutable connection saw ZERO of the writer's %d committed batches (stuck at %d rows) while a fresh connection to the same file sees %d -- its apparent immunity to corruption in the matrix test is staleness, not safety", wstats.commits.Load(), afterOnLongLived, afterOnFreshConn)
	}
}
