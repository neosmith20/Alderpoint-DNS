// Package dnsgenerations is DNS Runtime's real deployment history +
// rollback store -- see migration 0033's own doc comment for the exact,
// disclosed scope: a dnsdist config snapshot per successfully promoted
// generation (replayable), diagnostic-only rows for failed/rolled-back
// attempts, no BIND-side file snapshot (that's continuously DB-derived,
// governed by Backup & Restore instead).
package dnsgenerations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
)

type Generation struct {
	ID                int64  `json:"id"`
	GenerationNumber  int    `json:"generation_number"`
	CreatedAt         string `json:"created_at"`
	Trigger           string `json:"trigger"`
	Promoted          bool   `json:"promoted"`
	RolledBack        bool   `json:"rolled_back"`
	Stage             string `json:"stage,omitempty"`
	Detail            string `json:"detail,omitempty"`
	Error             string `json:"error,omitempty"`
	ContentHash       string `json:"content_hash,omitempty"`
	HasSnapshot       bool   `json:"has_snapshot"` // true when dnsdist_conf was saved (promoted rows only)
	BuildMS           int64  `json:"build_ms"`
	CompileMS         int64  `json:"compile_ms"`
	RPCMS             int64  `json:"rpc_ms"`
	TotalMS           int64  `json:"total_ms"`
}

type RecordInput struct {
	Trigger     string
	Promoted    bool
	RolledBack  bool
	Stage       string
	Detail      string
	Error       string
	DnsdistConf string // saved only when Promoted
	BuildMS, CompileMS, RPCMS, TotalMS int64
}

type Store struct {
	DB *sql.DB
}

func ContentHash(dnsdistConf string) string {
	sum := sha256.Sum256([]byte(dnsdistConf))
	return hex.EncodeToString(sum[:])
}

// Record inserts one real deployment-history row and returns its
// generation number. Never returns an error to a caller that must not
// fail its own real DNS apply just because history-logging had a
// problem -- callers should treat a logging failure as best-effort
// (see internal/dnsruntime's own call site).
func (s *Store) Record(ctx context.Context, in RecordInput) (int, error) {
	var maxNum sql.NullInt64
	if err := s.DB.QueryRowContext(ctx, `SELECT MAX(generation_number) FROM dns_runtime_generations`).Scan(&maxNum); err != nil {
		return 0, err
	}
	next := int(maxNum.Int64) + 1

	var conf sql.NullString
	hash := ""
	if in.Promoted {
		conf = sql.NullString{String: in.DnsdistConf, Valid: true}
		hash = ContentHash(in.DnsdistConf)
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO dns_runtime_generations
		 (generation_number, created_at, trigger_source, promoted, rolled_back, stage, detail, error, dnsdist_conf, content_hash, build_ms, compile_ms, rpc_ms, total_ms)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		next, time.Now().UTC().Format(time.RFC3339), in.Trigger, boolInt(in.Promoted), boolInt(in.RolledBack),
		in.Stage, in.Detail, in.Error, conf, hash, in.BuildMS, in.CompileMS, in.RPCMS, in.TotalMS)
	if err != nil {
		return 0, err
	}
	return next, nil
}

func scan(row interface{ Scan(...any) error }) (Generation, error) {
	var g Generation
	var promoted, rolledBack int
	var conf sql.NullString
	err := row.Scan(&g.ID, &g.GenerationNumber, &g.CreatedAt, &g.Trigger, &promoted, &rolledBack,
		&g.Stage, &g.Detail, &g.Error, &conf, &g.ContentHash, &g.BuildMS, &g.CompileMS, &g.RPCMS, &g.TotalMS)
	g.Promoted = promoted != 0
	g.RolledBack = rolledBack != 0
	g.HasSnapshot = conf.Valid
	return g, err
}

const cols = `id, generation_number, created_at, trigger_source, promoted, rolled_back, stage, detail, error, dnsdist_conf, content_hash, build_ms, compile_ms, rpc_ms, total_ms`

// History returns the most recent generations, newest first, capped at
// limit (0 = default 50 -- plenty for a real, human-scrollable history
// list without unbounded growth on every page load).
func (s *Store) History(ctx context.Context, limit int) ([]Generation, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+cols+` FROM dns_runtime_generations ORDER BY generation_number DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Generation{}
	for rows.Next() {
		g, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// LatestPromoted is the current live generation -- what "pending
// changes" and "rollback target" both compare against.
func (s *Store) LatestPromoted(ctx context.Context) (*Generation, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT `+cols+` FROM dns_runtime_generations WHERE promoted=1 ORDER BY generation_number DESC LIMIT 1`)
	g, err := scan(row)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &g, nil
}

// PreviousPromoted is the promoted generation immediately before the
// current live one -- the real rollback target. nil when there isn't
// one (fewer than two real promotions have ever happened).
func (s *Store) PreviousPromoted(ctx context.Context) (*Generation, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT `+cols+` FROM dns_runtime_generations WHERE promoted=1 ORDER BY generation_number DESC LIMIT 1 OFFSET 1`)
	g, err := scan(row)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &g, nil
}

// SnapshotConf returns the saved dnsdist config text for a specific
// promoted generation -- "" (with an error) if that generation never
// had one saved (a failed/rolled-back attempt, or an id that doesn't
// exist).
func (s *Store) SnapshotConf(ctx context.Context, generationNumber int) (string, error) {
	var conf sql.NullString
	err := s.DB.QueryRowContext(ctx,
		`SELECT dnsdist_conf FROM dns_runtime_generations WHERE generation_number=? AND promoted=1`, generationNumber).Scan(&conf)
	if err != nil {
		return "", err
	}
	return conf.String, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
