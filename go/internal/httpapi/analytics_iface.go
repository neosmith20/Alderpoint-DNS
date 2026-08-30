package httpapi

import (
	"context"
	"time"

	"alderpointdns/go-controlplane/internal/pyanalytics"
	"alderpointdns/go-controlplane/internal/rawquerylog"
)

// AnalyticsReader and RawQueryLogReader are the exact method sets every
// analytics/statistics handler in this package uses. Both
// pyanalytics.Reader (retained for its plain data types --
// pyanalytics.Bucket/DimensionCount/AnalyticsHealth -- and its pure
// helper functions ValidGranularity/FillGaps/FillLiveGaps/StepSeconds/
// AlignedBucketStart) and internal/dnsanalytics.Reader (the real,
// Go-native implementation wired up since Python's decommission --
// see CUTOVER.md) satisfy these; the field types below being interfaces
// rather than a concrete *pyanalytics.Reader/*rawquerylog.Reader is what
// let that swap happen without touching a single handler in
// handlers_analytics.go/handlers_dashboard.go/handlers_auth.go/
// handlers_discovery.go.
type AnalyticsReader interface {
	TimeSeries(ctx context.Context, start, end float64, granularity string) ([]pyanalytics.Bucket, error)
	Live(ctx context.Context, start, end float64) ([]pyanalytics.Bucket, error)
	TopDimension(ctx context.Context, dimension string, start, end float64, granularity string, limit int) ([]pyanalytics.DimensionCount, error)
	ExportAll(ctx context.Context) (buckets []pyanalytics.ExportRow, dims []pyanalytics.ExportRow, err error)
	Health(ctx context.Context) pyanalytics.AnalyticsHealth
	// ClientAnalytics backs the Clients page's Client analytics table
	// (GET /api/analytics/top-clients) -- only *dnsanalytics.Reader
	// implements it today; pyanalytics.Reader is retained solely for its
	// plain data types now that Python is decommissioned (see CUTOVER.md),
	// so it is never asked to satisfy this interface in production.
	ClientAnalytics(ctx context.Context, minutes float64, limit int) ([]pyanalytics.ClientRow, error)
	// ClearAll backs POST /api/statistics/clear -- see
	// dnsanalytics.Reader.ClearAll's own doc comment. Only
	// *dnsanalytics.Reader implements this for real in production;
	// pyanalytics.Reader's stub exists solely so it keeps satisfying
	// this interface for pre-existing tests that construct one.
	ClearAll(ctx context.Context) (int64, error)
	// TopUpstreams backs Dashboard's real "Top Upstream Resolvers" panel
	// (GET /api/analytics/top-upstreams) -- real per-resolver dnsdist
	// backend telemetry (see internal/dnsanalytics/upstreamstats.go).
	// Only *dnsanalytics.Reader implements this for real in production;
	// pyanalytics.Reader's stub exists solely so it keeps satisfying
	// this interface, same posture as ClientAnalytics/ClearAll above.
	TopUpstreams(ctx context.Context, since time.Time, limit int) ([]pyanalytics.UpstreamResolverSummary, error)
}

type RawQueryLogReader interface {
	RecentQueryLog(ctx context.Context, minutes float64, filters rawquerylog.Filters, limit, offset int) (rawquerylog.Result, error)
	TopDomains(ctx context.Context, minutes float64, blockedOnly bool, limit int) ([]rawquerylog.DomainCount, int, error)
}
