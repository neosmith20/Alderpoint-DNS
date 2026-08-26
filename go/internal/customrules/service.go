// Package customrules is a native Go implementation of Custom Filtering
// Rules -- new functionality per docs/v2/v2-roadmap.md's locked "Custom
// Rules" decision: Python V2 has no custom-rules API at all (only V1's
// app/custom_rules.py, a free-text AdGuard-syntax parser/importer). The
// roadmap explicitly permits "a modern rule builder" as an addition, so
// this package is a structured builder (rule_type + pattern +
// rewrite_target), not a syntax parser.
//
// Required semantic classes per the roadmap ("allow, block, regex,
// rewrite, precedence, bulk lifecycle") are covered: five rule_type
// values (block/allow/regex_block/regex_allow/rewrite), a priority
// column for precedence, and bulk enable/disable/delete.
//
// Deliberately NOT included here, disclosed rather than hidden:
//
//   - Free-text AdGuard/V1-syntax parsing and import. The roadmap is
//     explicit that a modern builder is an *addition*, not permission to
//     drop V1 compatibility -- that parser (app/custom_rules.py, ~1000
//     lines of real syntax-detection logic) is a substantial separate
//     port, not a trivial add-on to this structured CRUD layer.
//   - Query Log -> rule creation (needs Query Log to exist first, which
//     needs the raw-query-history/DuckDB path this migration doesn't
//     have -- see internal/pyanalytics's doc comment on why).
//   - Rule test/evaluate (a "does this domain match?" preview endpoint)
//     and no compiled-runtime effect (same disclosed gap as Upstreams
//     and Policy).
package customrules

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrValidation = errors.New("validation failed")
)

var validRuleTypes = map[string]bool{"block": true, "allow": true, "regex_block": true, "regex_allow": true, "rewrite": true}

type Rule struct {
	ID            int64   `json:"id"`
	RuleType      string  `json:"rule_type"`
	Pattern       string  `json:"pattern"`
	RewriteTarget *string `json:"rewrite_target"`
	Enabled       bool    `json:"enabled"`
	Priority      int     `json:"priority"`
	CreatedAt     string  `json:"created_at"`
}

type Service struct {
	DB *sql.DB
}

func validate(ruleType, pattern string, rewriteTarget *string) error {
	if !validRuleTypes[ruleType] {
		return fmt.Errorf("%w: invalid rule_type: %q", ErrValidation, ruleType)
	}
	if pattern == "" {
		return fmt.Errorf("%w: pattern required", ErrValidation)
	}
	if ruleType == "rewrite" && (rewriteTarget == nil || *rewriteTarget == "") {
		return fmt.Errorf("%w: rewrite_target required for rule_type=rewrite", ErrValidation)
	}
	return nil
}

func (s *Service) List(ctx context.Context) ([]Rule, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, rule_type, pattern, rewrite_target, enabled, priority, created_at
		 FROM custom_rules ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		var enabledInt int
		if err := rows.Scan(&r.ID, &r.RuleType, &r.Pattern, &r.RewriteTarget, &enabledInt, &r.Priority, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabledInt != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Service) Create(ctx context.Context, ruleType, pattern string, rewriteTarget *string) (int64, error) {
	if err := validate(ruleType, pattern, rewriteTarget); err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO custom_rules(rule_type, pattern, rewrite_target, enabled, priority, created_at)
		 VALUES(?,?,?,1,(SELECT COALESCE(MAX(priority),0)+1 FROM custom_rules),?)`,
		ruleType, pattern, rewriteTarget, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Service) Update(ctx context.Context, id int64, ruleType, pattern string, rewriteTarget *string) error {
	if err := validate(ruleType, pattern, rewriteTarget); err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE custom_rules SET rule_type=?, pattern=?, rewrite_target=? WHERE id=?`,
		ruleType, pattern, rewriteTarget, id)
	if err != nil {
		return err
	}
	return checkAffected(res)
}

func (s *Service) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE custom_rules SET enabled=? WHERE id=?`, v, id)
	if err != nil {
		return err
	}
	return checkAffected(res)
}

func (s *Service) Delete(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM custom_rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	return checkAffected(res)
}

func checkAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// BulkSetEnabled and BulkDelete are the roadmap's required "bulk
// enable/disable/delete" lifecycle -- best-effort across the given ids
// (an unknown id is simply not matched by the UPDATE/DELETE, not an
// error for the whole batch, matching how a bulk operation across a
// possibly-stale selection should behave).
func (s *Service) BulkSetEnabled(ctx context.Context, ids []int64, enabled bool) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	v := 0
	if enabled {
		v = 1
	}
	query, args := inClauseQuery(`UPDATE custom_rules SET enabled=? WHERE id IN (`, ids, v)
	res, err := s.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Service) BulkDelete(ctx context.Context, ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	query, args := inClauseQuery(`DELETE FROM custom_rules WHERE id IN (`, ids)
	res, err := s.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func inClauseQuery(prefix string, ids []int64, leadingArgs ...any) (string, []any) {
	q := prefix
	args := append([]any{}, leadingArgs...)
	for i, id := range ids {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, id)
	}
	q += ")"
	return q, args
}

// Reorder mirrors internal/upstreams.Reorder's semantics: sets priority
// to each id's position in orderedIDs; an id omitted from the request
// keeps its current priority.
func (s *Service) Reorder(ctx context.Context, orderedIDs []int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for position, id := range orderedIDs {
		res, err := tx.ExecContext(ctx, `UPDATE custom_rules SET priority=? WHERE id=?`, position, id)
		if err != nil {
			return err
		}
		if err := checkAffected(res); err != nil {
			return fmt.Errorf("%w: unknown rule id %d", ErrNotFound, id)
		}
	}
	return tx.Commit()
}
