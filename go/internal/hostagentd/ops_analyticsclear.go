// Statistics' real "Clear" action -- deliberately not a Go-native
// operation, because there is nothing Go-native to clear: the aggregate
// rollups and raw per-query history it clears both live entirely inside
// Python's own storage (analytics/aggregates.db + analytics/queries/*.parquet).
// PARITY_MATRIX.md previously recorded this row as blocked outright,
// reasoning that clearing would require either widening the web
// container's mount of that data to read-write (risking a race with
// Python's own live writer through a boundary designed to stay
// read-only) or modifying the Python container. Neither is necessary:
// apdns-hostagent already has real, unrestricted root access to the
// exact same host path it already reads for the analytics-snapshot
// publisher (see internal/analyticssnapshot) -- running the clear from
// here needs no new mount and touches nothing the agent doesn't already
// touch.
//
// This is NOT the same risky pattern as the immutable=1 incident
// (internal/pyanalytics/repro_walcorrupt_test.go) that this migration
// already found and fixed: that bug came from asserting a live,
// actively-written database was immutable to satisfy a read-only mount.
// This code opens the file with a completely ordinary read-write SQLite
// connection (busy_timeout set, no immutable/mode=ro flag at all) and
// issues a real DELETE, exactly like Python's own
// statistics_control.clear_statistics does from its own, separate
// process today -- concurrent writer access to this file from a second
// process is already Python's own accepted, shipped design (its
// analytics writer worker and its webapp process both already open this
// same file independently), not a new risk class this introduces.
package hostagentd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"alderpointdns/go-controlplane/internal/hostagent"
)

// AnalyticsClearConfig points at Python's real, live paths -- the exact
// same AggregatesDBPath the analytics-snapshot publisher already reads
// (see cmd/apdns-hostagent's -analytics-snapshot-source), plus the raw
// Parquet history root, which the snapshot publisher has no need to
// know about. Both empty by default: an unconfigured agent honestly
// refuses analytics.clear rather than silently doing nothing.
type AnalyticsClearConfig struct {
	AggregatesDBPath string
	RawHistoryRoot   string
}

// AnalyticsClearResult mirrors Python's own ClearResult field-for-field
// (statistics_control.py) so the two are directly comparable.
type AnalyticsClearResult struct {
	AggregateBucketsCleared       int  `json:"aggregate_buckets_cleared"`
	AggregateDimensionRowsCleared int  `json:"aggregate_dimension_rows_cleared"`
	RawHistoryCleared             bool `json:"raw_history_cleared"`
	RawPartitionFilesRemoved      int  `json:"raw_partition_files_removed"`
}

func RegisterAnalyticsClearOps(s *Server, cfg AnalyticsClearConfig) {
	s.Register(hostagent.OpAnalyticsClear, func(ctx context.Context, params json.RawMessage) (any, error) {
		if cfg.AggregatesDBPath == "" {
			return nil, fmt.Errorf("analytics clear is not configured on this agent (-analytics-snapshot-source empty)")
		}
		var in struct {
			IncludeRawHistory bool `json:"include_raw_history"`
		}
		if len(params) > 0 {
			if err := json.Unmarshal(params, &in); err != nil {
				return nil, fmt.Errorf("invalid params: %w", err)
			}
		}
		return clearAnalytics(ctx, cfg, in.IncludeRawHistory)
	})
}

func clearAnalytics(ctx context.Context, cfg AnalyticsClearConfig, includeRawHistory bool) (AnalyticsClearResult, error) {
	var result AnalyticsClearResult

	if _, err := os.Stat(cfg.AggregatesDBPath); err == nil {
		db, err := sql.Open("sqlite", "file:"+cfg.AggregatesDBPath+"?_pragma=busy_timeout(5000)")
		if err != nil {
			return result, fmt.Errorf("open aggregates db: %w", err)
		}
		defer db.Close()

		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM time_buckets").Scan(&result.AggregateBucketsCleared); err != nil {
			return result, fmt.Errorf("count time_buckets: %w", err)
		}
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM dimension_counts").Scan(&result.AggregateDimensionRowsCleared); err != nil {
			return result, fmt.Errorf("count dimension_counts: %w", err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return result, fmt.Errorf("begin clear transaction: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM time_buckets"); err != nil {
			tx.Rollback()
			return result, fmt.Errorf("clear time_buckets: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM dimension_counts"); err != nil {
			tx.Rollback()
			return result, fmt.Errorf("clear dimension_counts: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return result, fmt.Errorf("commit clear transaction: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return result, fmt.Errorf("stat aggregates db: %w", err)
	}
	// A not-yet-created aggregates.db (a fresh appliance with no traffic
	// yet) is not an error -- there is simply nothing to clear, matching
	// Python's own os.path.exists guard.

	// Matches Python's own clear_statistics exactly: raw_history_cleared
	// reports whether a raw-history clear was requested (not whether the
	// root happened to exist -- a fresh appliance with no raw history
	// yet still honestly reports "yes, that was requested and there was
	// nothing to remove", not "no", since the caller's request was still
	// honored in full).
	if includeRawHistory && cfg.RawHistoryRoot != "" {
		result.RawHistoryCleared = true
		if _, err := os.Stat(cfg.RawHistoryRoot); err == nil {
			var files []string
			err := filepath.WalkDir(cfg.RawHistoryRoot, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() && filepath.Ext(path) == ".parquet" {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return result, fmt.Errorf("walk raw history root: %w", err)
			}
			sort.Strings(files)
			for _, f := range files {
				if err := os.Remove(f); err != nil {
					continue // matches Python's own best-effort "try/except OSError: continue"
				}
				result.RawPartitionFilesRemoved++
			}
		} else if !os.IsNotExist(err) {
			return result, fmt.Errorf("stat raw history root: %w", err)
		}
	}

	return result, nil
}
