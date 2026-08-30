package dnsanalytics

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openUpstreamTestDB(t *testing.T) *Reader {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Reader{DB: db}
}

func TestRecordUpstreamSampleFirstPollHasZeroDelta(t *testing.T) {
	r := openUpstreamTestDB(t)
	ctx := context.Background()
	// First-ever sample: no prior counter_state row exists, so every
	// delta must be 0 (there is no "since when" to measure against yet)
	// -- matches V1's own hadPrev==false contract.
	err := RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{
		{ResolverKey: "apdns_default_0", Queries: 100, Responses: 95},
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	summary, err := r.TopUpstreams(ctx, time.Now().Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary) != 1 || summary[0].QueriesAttempted != 0 {
		t.Fatalf("expected the first poll to record a zero delta, got %+v", summary)
	}
}

func TestRecordUpstreamSampleComputesRealDelta(t *testing.T) {
	r := openUpstreamTestDB(t)
	ctx := context.Background()
	now := time.Now()
	if err := RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{
		{ResolverKey: "apdns_default_0", Protocol: "UDP", Address: "9.9.9.9:53", HealthState: "up", Queries: 100, Responses: 95, Latency: 12.5},
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{
		{ResolverKey: "apdns_default_0", Protocol: "UDP", Address: "9.9.9.9:53", HealthState: "up", Queries: 150, Responses: 140, Latency: 15.0},
	}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	summary, err := r.TopUpstreams(ctx, now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary) != 1 {
		t.Fatalf("expected exactly one resolver, got %+v", summary)
	}
	s := summary[0]
	if s.QueriesAttempted != 50 || s.SuccessfulResp != 45 {
		t.Fatalf("expected the second poll's delta (50 queries, 45 responses), got %+v", s)
	}
	if s.Protocol != "UDP" || s.Address != "9.9.9.9:53" || s.HealthState != "up" {
		t.Fatalf("expected the most recent sample's own protocol/address/health, got %+v", s)
	}
}

func TestRecordUpstreamSampleClampsCounterResetToZero(t *testing.T) {
	r := openUpstreamTestDB(t)
	ctx := context.Background()
	now := time.Now()
	if err := RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{
		{ResolverKey: "apdns_default_0", Queries: 1000, Responses: 990},
	}, now); err != nil {
		t.Fatal(err)
	}
	// dnsdist restarted -- its own cumulative counters reset near zero.
	if err := RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{
		{ResolverKey: "apdns_default_0", Queries: 5, Responses: 5},
	}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	summary, err := r.TopUpstreams(ctx, now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if summary[0].QueriesAttempted != 0 {
		t.Fatalf("expected a counter reset to clamp to a zero delta for that one poll, got %+v", summary[0])
	}
	// A subsequent normal poll resumes real delta tracking from the new baseline.
	if err := RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{
		{ResolverKey: "apdns_default_0", Queries: 25, Responses: 25},
	}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	summary, err = r.TopUpstreams(ctx, now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if summary[0].QueriesAttempted != 20 {
		t.Fatalf("expected the poll after a reset to resume real delta tracking (20), got %+v", summary[0])
	}
}

func TestTopUpstreamsOrdersByRealQueryVolume(t *testing.T) {
	r := openUpstreamTestDB(t)
	ctx := context.Background()
	now := time.Now()
	RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{
		{ResolverKey: "apdns_default_0", Queries: 0}, {ResolverKey: "apdns_default_1", Queries: 0},
	}, now)
	RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{
		{ResolverKey: "apdns_default_0", Queries: 10}, {ResolverKey: "apdns_default_1", Queries: 90},
	}, now.Add(time.Minute))
	summary, err := r.TopUpstreams(ctx, now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary) != 2 || summary[0].ResolverKey != "apdns_default_1" || summary[1].ResolverKey != "apdns_default_0" {
		t.Fatalf("expected apdns_default_1 (90 queries) ranked ahead of apdns_default_0 (10 queries), got %+v", summary)
	}
}

func TestTopUpstreamsWindowExcludesOldSamples(t *testing.T) {
	r := openUpstreamTestDB(t)
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{{ResolverKey: "apdns_default_0", Queries: 0}}, old)
	RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{{ResolverKey: "apdns_default_0", Queries: 500}}, old.Add(time.Minute))
	summary, err := r.TopUpstreams(ctx, time.Now().Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary) != 0 {
		t.Fatalf("expected samples from 48h ago excluded by a 1h window, got %+v", summary)
	}
}

func TestPruneUpstreamSamplesDeletesOldRows(t *testing.T) {
	r := openUpstreamTestDB(t)
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{{ResolverKey: "apdns_default_0", Queries: 0}}, old)
	RecordUpstreamSample(ctx, r.DB, []UpstreamServerSample{{ResolverKey: "apdns_default_0", Queries: 10}}, old.Add(time.Minute))
	if err := PruneUpstreamSamples(ctx, r.DB, time.Now().Add(-24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := r.DB.QueryRowContext(ctx, `SELECT count(*) FROM upstream_resolver_samples`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected old samples pruned, %d remain", count)
	}
}
