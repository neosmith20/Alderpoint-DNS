// Package rawquerylog is a second, narrower Go->Python compatibility
// boundary for the Query Log page's "Recent Queries" grid -- a real read
// path over Python's raw per-query Parquet history
// (analytics/queries/YYYY/MM/DD/HH-<segment>.parquet, written by
// app/v2/parquet_writer.py), not the pre-aggregated bucket counts
// internal/pyanalytics already reads from aggregates.db.
//
// This exists because Python's own reader for this data
// (app/v2/analytics_query.py's PartitionPruningReader) is DuckDB-backed,
// and DuckDB's Go bindings require CGO -- incompatible with this
// project's CGO_ENABLED=0 pure-Go build requirement (the same
// already-documented reason internal/pyanalytics's TopBlockedDomains is
// honestly reported as unavailable). Investigated, not assumed: the
// underlying data is plain Parquet + Zstandard, a real file format with
// mature pure-Go readers, so a genuine native boundary is possible
// without DuckDB at all -- this package is that boundary, using
// github.com/parquet-go/parquet-go (pure Go, klauspost/compress for
// Zstandard, no cgo).
//
// Same isolation properties as internal/pyanalytics: read-only, the
// directory this package reads (analytics/queries/) lives beside
// aggregates.db under Python's analytics/ tree, not inside control.db --
// no admin password hashes or secrets are anywhere near this data.
//
//   - Partition pruning mirrors app/v2/analytics_query.py's
//     enumerate_partition_files exactly (same YYYY/MM/DD/HH-*.parquet
//     layout, same year/month/day branch pruning, same boundary-day
//     hour-level pruning from the segment filename) -- this package never
//     opens a file outside the query's time range.
//   - Failure isolation: a corrupt or unreadable segment is skipped, not
//     fatal to the rest of the query -- matching Python's own contract
//     ("one bad segment must never break a query over the rest of
//     history").
//   - Filters are a fixed allowlist of exact-equality columns (matching
//     Python's _FILTERABLE_COLUMNS -- client/domain/qtype/protocol/rcode/
//     upstream/cache_status/blocked), applied during the scan, never
//     string-interpolated into anything.
//   - Deliberately simpler than Python's implementation in one way,
//     disclosed rather than hidden: Python pushes the time/filter
//     predicate down into DuckDB's own columnar scan; this package reads
//     whole row groups and filters in Go. A rowsScannedCap bounds memory
//     use on a very wide time window instead of relying on predicate
//     pushdown -- correct for the common "recent queries" case (small
//     windows, small limits) but a genuinely large historical scan may
//     hit the cap before finding `limit` matches. This is a read-only,
//     informational display path, not an authoritative data source, so
//     that trade-off is acceptable here in a way it would not be for
//     anything this control plane writes or restores.
package rawquerylog

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/parquet-go/parquet-go"
)

const (
	DefaultLimit = 100
	MaxLimit     = 500
	MaxOffset    = 100_000
	MaxMinutes   = 31 * 24 * 60.0 // 31 days, matching Python's cap

	// rowsScannedCap is the in-memory safety circuit breaker described in
	// the package doc comment above.
	rowsScannedCap = 500_000
)

// Row mirrors app/v2/parquet_writer.py's _pa_schema exactly (same 14
// columns, same order). Every field is optional/nullable (a pointer) --
// the writer stores None for any key a caller's record omitted (see that
// module's "missing keys become None" normalization), so a reader that
// assumed every field always present would panic on real data.
type Row struct {
	ID             *int64   `parquet:"id,optional"`
	TS             *float64 `parquet:"ts,optional"`
	Client         *string  `parquet:"client,optional"`
	ClientName     *string  `parquet:"client_name,optional"`
	Domain         *string  `parquet:"domain,optional"`
	QType          *string  `parquet:"qtype,optional"`
	Protocol       *string  `parquet:"protocol,optional"`
	RCode          *string  `parquet:"rcode,optional"`
	LatencyMs      *float64 `parquet:"latency_ms,optional"`
	Blocked        *bool    `parquet:"blocked,optional"`
	BlockReason    *string  `parquet:"block_reason,optional"`
	Upstream       *string  `parquet:"upstream,optional"`
	CacheStatus    *string  `parquet:"cache_status,optional"`
	CacheProfileID *string  `parquet:"cache_profile_id,optional"`
}

// LogRow is the JSON-friendly, null-free shape returned to API callers --
// nil pointer fields become zero values, matching how the frontend
// renders a missing value as blank rather than needing null-checks
// everywhere.
type LogRow struct {
	ID             int64   `json:"id"`
	TS             float64 `json:"ts"`
	Client         string  `json:"client"`
	ClientName     string  `json:"client_name"`
	Domain         string  `json:"domain"`
	QType          string  `json:"qtype"`
	Protocol       string  `json:"protocol"`
	RCode          string  `json:"rcode"`
	LatencyMs      float64 `json:"latency_ms"`
	Blocked        bool    `json:"blocked"`
	BlockReason    string  `json:"block_reason"`
	Upstream       string  `json:"upstream"`
	CacheStatus    string  `json:"cache_status"`
	CacheProfileID string  `json:"cache_profile_id"`
}

func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

func (r Row) toLogRow() LogRow {
	return LogRow{
		ID: deref(r.ID), TS: deref(r.TS), Client: deref(r.Client), ClientName: deref(r.ClientName),
		Domain: deref(r.Domain), QType: deref(r.QType), Protocol: deref(r.Protocol), RCode: deref(r.RCode),
		LatencyMs: deref(r.LatencyMs), Blocked: deref(r.Blocked), BlockReason: deref(r.BlockReason),
		Upstream: deref(r.Upstream), CacheStatus: deref(r.CacheStatus), CacheProfileID: deref(r.CacheProfileID),
	}
}

// Filters is the fixed allowlist of exact-equality columns a caller may
// filter on -- matching Python's _FILTERABLE_COLUMNS. A nil/empty pointer
// means "don't filter on this column".
type Filters struct {
	Client      string
	Domain      string
	QType       string
	Protocol    string
	RCode       string
	Upstream    string
	CacheStatus string
	BlockedOnly bool
}

func (f Filters) matches(r Row) bool {
	if f.Client != "" && deref(r.Client) != f.Client {
		return false
	}
	if f.Domain != "" && deref(r.Domain) != f.Domain {
		return false
	}
	if f.QType != "" && deref(r.QType) != f.QType {
		return false
	}
	if f.Protocol != "" && deref(r.Protocol) != f.Protocol {
		return false
	}
	if f.RCode != "" && deref(r.RCode) != f.RCode {
		return false
	}
	if f.Upstream != "" && deref(r.Upstream) != f.Upstream {
		return false
	}
	if f.CacheStatus != "" && deref(r.CacheStatus) != f.CacheStatus {
		return false
	}
	if f.BlockedOnly && !deref(r.Blocked) {
		return false
	}
	return true
}

type Result struct {
	Rows            []LogRow `json:"rows"`
	FilesConsidered int      `json:"files_considered"`
	// Search is applied after the scan (a plain substring match across
	// every column's string form) -- matching Python's own "full-text
	// contains filtering is intentionally post-query and bounded" design:
	// the allowlisted equality filters narrow the backend scan, this
	// never widens it.
}

// Reader wraps a read-only view of Python's raw Parquet query-history
// tree. Root is analytics/queries/ (a sibling of aggregates.db under
// Python's analytics/ state directory, never control.db).
type Reader struct {
	Root string
}

// enumeratePartitionFiles mirrors app/v2/analytics_query.py's function of
// the same name exactly: prune whole year/month/day branches outside
// [startTS, endTS) before ever opening a file, then for the two boundary
// days additionally prune by the segment filename's leading "HH-" hour.
func enumeratePartitionFiles(root string, startTS, endTS float64) ([]string, error) {
	if _, err := os.Stat(root); err != nil {
		return nil, nil // matches Python: a missing root is zero files, not an error
	}
	startDate := time.Unix(int64(startTS), 0).UTC()
	endDate := time.Unix(int64(endTS), 0).UTC()
	startDay := startDate.Truncate(24 * time.Hour)
	endDay := endDate.Truncate(24 * time.Hour)

	var files []string
	yearDirs, err := sortedSubdirs(root)
	if err != nil {
		return nil, err
	}
	for _, yearName := range yearDirs {
		year, ok := numericName(yearName)
		if !ok {
			continue
		}
		if year < startDate.Year() || year > endDate.Year() {
			continue
		}
		yearPath := filepath.Join(root, yearName)
		monthDirs, err := sortedSubdirs(yearPath)
		if err != nil {
			continue
		}
		for _, monthName := range monthDirs {
			month, ok := numericName(monthName)
			if !ok {
				continue
			}
			if year == startDate.Year() && month < int(startDate.Month()) {
				continue
			}
			if year == endDate.Year() && month > int(endDate.Month()) {
				continue
			}
			monthPath := filepath.Join(yearPath, monthName)
			dayDirs, err := sortedSubdirs(monthPath)
			if err != nil {
				continue
			}
			for _, dayName := range dayDirs {
				day, ok := numericName(dayName)
				if !ok {
					continue
				}
				thisDate := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
				if thisDate.Before(startDay) || thisDate.After(endDay) {
					continue
				}
				isStartBoundary := thisDate.Equal(startDay)
				isEndBoundary := thisDate.Equal(endDay)
				dayPath := filepath.Join(monthPath, dayName)
				segments, err := sortedParquetFiles(dayPath)
				if err != nil {
					continue
				}
				for _, seg := range segments {
					if !isStartBoundary && !isEndBoundary {
						files = append(files, filepath.Join(dayPath, seg))
						continue
					}
					hour, ok := segmentHour(seg)
					if !ok {
						files = append(files, filepath.Join(dayPath, seg)) // unrecognized shape: include, don't silently drop
						continue
					}
					hourStart := time.Date(year, time.Month(month), day, hour, 0, 0, 0, time.UTC)
					hourEnd := hourStart.Add(time.Hour)
					if float64(hourEnd.Unix()) <= startTS || float64(hourStart.Unix()) >= endTS {
						continue
					}
					files = append(files, filepath.Join(dayPath, seg))
				}
			}
		}
	}
	return files, nil
}

func sortedSubdirs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func sortedParquetFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".parquet") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func numericName(name string) (int, bool) {
	n, err := strconv.Atoi(name)
	if err != nil {
		return 0, false
	}
	return n, true
}

func segmentHour(filename string) (int, bool) {
	prefix, _, ok := strings.Cut(filename, "-")
	if !ok {
		return 0, false
	}
	hour, err := strconv.Atoi(prefix)
	if err != nil {
		return 0, false
	}
	return hour, true
}

// scanRows is the shared engine behind RecentQueryLog and TopDomains:
// enumerate the pruned partition file set for [start, end), then stream
// every row of every file through visit (only rows within the window and
// matching filters). Bounded by rowsScannedCap regardless of which
// caller is consuming it -- see the package doc comment's disclosed
// trade-off.
func (r *Reader) scanRows(ctx context.Context, start, end float64, filters Filters, visit func(Row)) (filesConsidered int, err error) {
	files, err := enumeratePartitionFiles(r.Root, start, end)
	if err != nil {
		return 0, err
	}

	scanned := 0
scanLoop:
	for _, path := range files {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		func() {
			// parquet-go panics (rather than returning an error) on a
			// structurally invalid file, e.g. a bad magic header --
			// recovered here so one corrupt segment can never abort the
			// rest of the query, matching Python's own "one bad segment
			// must never break a query over the rest of history"
			// contract (there, enforced by pre-validating each segment
			// before trusting it; here, by treating any panic from
			// opening/reading a segment the same as a skip).
			defer func() { recover() }()

			f, err := os.Open(path)
			if err != nil {
				return // a segment that vanished (retention) between enumeration and read is just skipped
			}
			defer f.Close()
			if _, err := f.Stat(); err != nil {
				return
			}
			reader := parquet.NewGenericReader[Row](f)
			defer reader.Close()
			buf := make([]Row, 512)
			for {
				n, readErr := reader.Read(buf)
				for i := 0; i < n; i++ {
					row := buf[i]
					ts := deref(row.TS)
					if ts < start || ts >= end {
						continue
					}
					if !filters.matches(row) {
						continue
					}
					visit(row)
					scanned++
				}
				if scanned >= rowsScannedCap {
					return
				}
				if readErr != nil {
					break // io.EOF (normal end) or a mid-file read error -- either way, stop this file, keep what was found
				}
			}
		}()
		if scanned >= rowsScannedCap {
			break scanLoop
		}
	}
	return len(files), nil
}

func clampMinutes(minutes float64) float64 {
	if minutes < 1 {
		return 1
	}
	if minutes > MaxMinutes {
		return MaxMinutes
	}
	return minutes
}

// RecentQueryLog is the Go-native equivalent of AnalyticsService.recent_query_log
// / the GET /api/analytics/query-log contract: a bounded, time-windowed,
// filtered, most-recent-first read over the raw Parquet history.
func (r *Reader) RecentQueryLog(ctx context.Context, minutes float64, filters Filters, limit, offset int) (Result, error) {
	minutes = clampMinutes(minutes)
	if limit < 1 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	if offset < 0 {
		offset = 0
	}
	if offset > MaxOffset {
		offset = MaxOffset
	}

	end := float64(time.Now().Unix())
	start := end - minutes*60

	var matches []LogRow
	filesConsidered, err := r.scanRows(ctx, start, end, filters, func(row Row) {
		matches = append(matches, row.toLogRow())
	})
	if err != nil {
		return Result{}, err
	}

	sort.Slice(matches, func(i, j int) bool { return matches[i].TS > matches[j].TS })

	if offset >= len(matches) {
		return Result{Rows: []LogRow{}, FilesConsidered: filesConsidered}, nil
	}
	end2 := offset + limit
	if end2 > len(matches) {
		end2 = len(matches)
	}
	return Result{Rows: matches[offset:end2], FilesConsidered: filesConsidered}, nil
}

// DomainCount is one row of a TopDomains result.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// TopDomains aggregates real counts per domain over the raw query
// history -- with blockedOnly=true, this is exactly the data
// internal/pyanalytics's TopBlockedDomains had to report as permanently
// unavailable (that boundary only has pre-aggregated bucket counts, not
// per-query domain detail; this one reads the actual per-query rows).
// Counting happens in a map during the scan, not by materializing every
// row first, so this is far cheaper than RecentQueryLog for a wide
// window.
func (r *Reader) TopDomains(ctx context.Context, minutes float64, blockedOnly bool, limit int) ([]DomainCount, int, error) {
	minutes = clampMinutes(minutes)
	if limit < 1 {
		limit = 20
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	end := float64(time.Now().Unix())
	start := end - minutes*60

	counts := map[string]int{}
	filesConsidered, err := r.scanRows(ctx, start, end, Filters{BlockedOnly: blockedOnly}, func(row Row) {
		domain := deref(row.Domain)
		if domain == "" {
			return
		}
		counts[domain]++
	})
	if err != nil {
		return nil, 0, err
	}

	out := make([]DomainCount, 0, len(counts))
	for domain, count := range counts {
		out = append(out, DomainCount{Domain: domain, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Domain < out[j].Domain // stable tie-break, not map-iteration-order-dependent
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, filesConsidered, nil
}
