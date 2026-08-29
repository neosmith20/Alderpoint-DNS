package dnsanalytics

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/rawquerylog"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func insertEvent(t *testing.T, db *sql.DB, ts int64, domain, outcome string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO query_events (ts, domain, qtype, rcode, protocol, client, latency_ms, outcome)
		VALUES (?, ?, 'A', 'NOERROR', 'udp', '192.0.2.1', 1.5, ?)`, ts, domain, outcome)
	if err != nil {
		t.Fatal(err)
	}
}

func insertEventClient(t *testing.T, db *sql.DB, ts int64, client, domain, outcome string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO query_events (ts, domain, qtype, rcode, protocol, client, latency_ms, outcome)
		VALUES (?, ?, 'A', 'NOERROR', 'udp', ?, 1.5, ?)`, ts, domain, client, outcome)
	if err != nil {
		t.Fatal(err)
	}
}

// TestReaderTopDimensionClient is a regression test for a real bug: this
// method used to reject any dimension other than "domain", which meant
// GET /api/clients/observed (Observed Clients) always came back
// degraded:true on the live Go-native analytics backend the moment
// Python was decommissioned, since handleListObservedClients has always
// called TopDimension(ctx, "client", ...).
func TestReaderTopDimensionClient(t *testing.T) {
	db := openTestDB(t)
	r := &Reader{DB: db}
	ctx := context.Background()
	now := time.Now().Unix()
	insertEventClient(t, db, now, "192.168.1.50", "a.example.com", OutcomeAllowed)
	insertEventClient(t, db, now, "192.168.1.50", "b.example.com", OutcomeAllowed)
	insertEventClient(t, db, now, "192.168.1.99", "a.example.com", OutcomeAllowed)

	rows, err := r.TopDimension(ctx, "client", float64(now-60), float64(now+60), "hour", 10)
	if err != nil {
		t.Fatalf("TopDimension(\"client\", ...) = err %v, want a real result", err)
	}
	if len(rows) != 2 || rows[0].Value != "192.168.1.50" || rows[0].Count != 2 {
		t.Fatalf("rows = %+v, want 192.168.1.50 first with count 2", rows)
	}
}

func TestReaderClientAnalytics(t *testing.T) {
	db := openTestDB(t)
	r := &Reader{DB: db}
	ctx := context.Background()
	now := time.Now().Unix()
	insertEventClient(t, db, now, "192.168.1.50", "a.example.com", OutcomeAllowed)
	insertEventClient(t, db, now, "192.168.1.50", "ads.example.com", OutcomeBlocked)
	insertEventClient(t, db, now-10, "192.168.1.50", "b.example.com", OutcomeAllowed)
	insertEventClient(t, db, now, "192.168.1.99", "a.example.com", OutcomeAllowed)

	rows, err := r.ClientAnalytics(ctx, 60, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want 2 clients", rows)
	}
	top := rows[0]
	if top.Client != "192.168.1.50" || top.Total != 3 || top.Blocked != 1 {
		t.Fatalf("top row = %+v, want {192.168.1.50 total:3 blocked:1}", top)
	}
	if top.LastSeen != now {
		t.Errorf("LastSeen = %d, want %d (the most recent of its three events)", top.LastSeen, now)
	}
}

func TestReaderTimeSeriesBucketsRealRows(t *testing.T) {
	db := openTestDB(t)
	r := &Reader{DB: db}
	ctx := context.Background()

	base := int64(1_700_000_000) // arbitrary fixed anchor, aligned math only needs a multiple-of-60 base
	base -= base % 3600
	insertEvent(t, db, base, "a.example.com", OutcomeAllowed)
	insertEvent(t, db, base, "b.example.com", OutcomeBlocked)
	insertEvent(t, db, base+3600, "a.example.com", OutcomeAllowed)

	buckets, err := r.TimeSeries(ctx, float64(base), float64(base+7200), "hour")
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 2 {
		t.Fatalf("buckets = %v, want 2", buckets)
	}
	if buckets[0].BucketStart != base || buckets[0].TotalQueries != 2 || buckets[0].Blocked != 1 {
		t.Errorf("bucket[0] = %+v, want {start:%d total:2 blocked:1}", buckets[0], base)
	}
	if buckets[1].TotalQueries != 1 || buckets[1].Blocked != 0 {
		t.Errorf("bucket[1] = %+v, want {total:1 blocked:0}", buckets[1])
	}
}

func TestReaderTopDimensionDomain(t *testing.T) {
	db := openTestDB(t)
	r := &Reader{DB: db}
	ctx := context.Background()
	now := time.Now().Unix()
	insertEvent(t, db, now, "popular.example.com", OutcomeAllowed)
	insertEvent(t, db, now, "popular.example.com", OutcomeBlocked)
	insertEvent(t, db, now, "rare.example.com", OutcomeAllowed)

	rows, err := r.TopDimension(ctx, "domain", float64(now-60), float64(now+60), "hour", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Value != "popular.example.com" || rows[0].Count != 2 {
		t.Fatalf("rows = %+v, want popular.example.com first with count 2", rows)
	}

	if _, err := r.TopDimension(ctx, "not-a-real-dimension", 0, 1, "hour", 10); err == nil {
		t.Error("expected an error for an unsupported dimension")
	}
}

func TestReaderTopDomainsBlockedOnly(t *testing.T) {
	db := openTestDB(t)
	r := &Reader{DB: db}
	ctx := context.Background()
	now := time.Now().Unix()
	insertEvent(t, db, now, "ads.example.com", OutcomeBlocked)
	insertEvent(t, db, now, "ads.example.com", OutcomeBlocked)
	insertEvent(t, db, now, "safe.example.com", OutcomeAllowed)

	rows, _, err := r.TopDomains(ctx, 60, true, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Domain != "ads.example.com" || rows[0].Count != 2 {
		t.Fatalf("blocked-only rows = %+v, want [{ads.example.com 2}]", rows)
	}

	all, _, err := r.TopDomains(ctx, 60, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("all rows = %+v, want 2 domains", all)
	}
}

func TestReaderRecentQueryLogFiltersAndOrdering(t *testing.T) {
	db := openTestDB(t)
	r := &Reader{DB: db}
	ctx := context.Background()
	now := time.Now().Unix()
	insertEvent(t, db, now-2, "first.example.com", OutcomeAllowed)
	insertEvent(t, db, now-1, "second.example.com", OutcomeBlocked)

	result, err := r.RecentQueryLog(ctx, 60, rawquerylog.Filters{}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 2 {
		t.Fatalf("rows = %+v, want 2", result.Rows)
	}
	// Newest first.
	if result.Rows[0].Domain != "second.example.com" || !result.Rows[0].Blocked {
		t.Errorf("rows[0] = %+v, want second.example.com blocked=true first", result.Rows[0])
	}

	blockedOnly, err := r.RecentQueryLog(ctx, 60, rawquerylog.Filters{BlockedOnly: true}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(blockedOnly.Rows) != 1 || blockedOnly.Rows[0].Domain != "second.example.com" {
		t.Fatalf("blocked-only rows = %+v", blockedOnly.Rows)
	}

	byDomain, err := r.RecentQueryLog(ctx, 60, rawquerylog.Filters{Domain: "first.example.com"}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(byDomain.Rows) != 1 || byDomain.Rows[0].Domain != "first.example.com" {
		t.Fatalf("domain-filtered rows = %+v", byDomain.Rows)
	}
}

func TestReaderHealthReachableNoWriter(t *testing.T) {
	db := openTestDB(t)
	r := &Reader{DB: db}
	h := r.Health(context.Background())
	if !h.DBReachable {
		t.Error("expected DBReachable=true")
	}
	if h.Status != "degraded" {
		t.Errorf("status = %q, want degraded (no writer configured)", h.Status)
	}
}

func TestReaderHealthOkWithFreshWriterHeartbeat(t *testing.T) {
	db := openTestDB(t)
	wtr := &Writer{DB: db}
	wtr.started = true
	wtr.lastHeartbeat.Store(time.Now().Unix())
	r := &Reader{DB: db, Writer: wtr}
	h := r.Health(context.Background())
	if h.Status != "ok" {
		t.Errorf("status = %q, want ok, reason=%q", h.Status, h.Reason)
	}
}

func TestReaderHealthDegradedOnStaleWriterHeartbeat(t *testing.T) {
	db := openTestDB(t)
	wtr := &Writer{DB: db}
	wtr.started = true
	wtr.lastHeartbeat.Store(time.Now().Add(-5 * time.Minute).Unix())
	r := &Reader{DB: db, Writer: wtr}
	h := r.Health(context.Background())
	if h.Status != "degraded" || !h.WriterStale {
		t.Errorf("h = %+v, want degraded/writer_stale for a 5-minute-old heartbeat", h)
	}
}

func TestReaderHealthFailedOnClosedDB(t *testing.T) {
	db := openTestDB(t)
	db.Close()
	r := &Reader{DB: db}
	h := r.Health(context.Background())
	if h.Status != "failed" || h.DBReachable {
		t.Errorf("h = %+v, want failed/unreachable for a closed db", h)
	}
}

func TestOpenFailsClearlyOnMissingDirectory(t *testing.T) {
	_, err := Open("/this/directory/does/not/exist/analytics.db")
	if err == nil {
		t.Fatal("expected an error for a nonexistent parent directory")
	}
}

func TestExportAllReflectsRealRows(t *testing.T) {
	db := openTestDB(t)
	r := &Reader{DB: db}
	ctx := context.Background()
	now := time.Now().Unix()
	insertEvent(t, db, now, "exported.example.com", OutcomeAllowed)

	buckets, dims, err := r.ExportAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) == 0 {
		t.Error("expected at least one time bucket")
	}
	found := false
	for _, d := range dims {
		if d["value"] == "exported.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exported.example.com among dimension rows, got %+v", dims)
	}
}
