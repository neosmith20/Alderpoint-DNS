// Package policyentities implements the four owner-managed entities
// that policy_layers' own filtering_profile_id/parental_policy_id/
// security_policy_id/service_blocking_ruleset_id fields reference --
// previously free-text IDs pointing at nothing (no storage, no CRUD,
// no compiler support anywhere in this codebase; confirmed absent from
// V1.1.1 entirely too -- see internal/policycompile's own doc comment
// for the full V1 evidence trail). Each is a distinct, independently
// managed entity with its own table/API/UI, by explicit owner
// decision (not consolidated into one generic "profile" concept),
// even though Filtering Profile/Parental Policy/Security Policy share
// an identical (id, name, description) + category-membership shape --
// that shared shape is factored into categoryEntityService below to
// avoid three copies of the same SQL, while each still keeps its own
// table, own Go type, own exported methods, and (in httpapi) its own
// routes.
package policyentities

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrValidation = errors.New("validation failed")
	ErrNotFound   = errors.New("not found")
	ErrDuplicate  = errors.New("duplicate id or name")
	ErrInUse      = errors.New("still referenced by at least one policy scope")
)

type Service struct {
	DB *sql.DB
}

func validateID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: id is required", ErrValidation)
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return fmt.Errorf("%w: id %q must be lowercase letters, digits, hyphen, underscore only", ErrValidation, id)
		}
	}
	return nil
}

// inUseInPolicyLayers reports whether any policy_layers row currently
// resolves to id via the given column -- every delete path below
// refuses to orphan a live policy assignment, matching
// blocklists.DeleteCategory's own "never orphan a reference"
// discipline.
func inUseInPolicyLayers(ctx context.Context, db *sql.DB, column, id string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_layers WHERE `+column+` = ?`, id).Scan(&n)
	return n > 0, err
}

// --- shared (id, name, description) + category-membership entity ---

// CategoryEntity is the common shape of Filtering Profile, Parental
// Policy, and Security Policy: an owner-named set of blocklist
// categories (internal/blocklists.Category names -- validated against
// that table by the caller in httpapi, this package stays independent
// of internal/blocklists per the usual acyclic-dependency convention).
type CategoryEntity struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type categoryEntityService struct {
	db          *sql.DB
	table       string // e.g. "filtering_profiles"
	memberTable string // e.g. "filtering_profile_categories"
	fkColumn    string // e.g. "profile_id"
	policyLayerColumn string // e.g. "filtering_profile_id"
	extraCols   []string // extra column names beyond id/name/description/created_at/updated_at, in select order
}

func (s *categoryEntityService) list(ctx context.Context, extraScan func(*sql.Rows, *CategoryEntity) error) ([]CategoryEntity, error) {
	cols := "id, name, description, created_at, updated_at"
	if len(s.extraCols) > 0 {
		cols = cols + ", " + strings.Join(s.extraCols, ", ")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+cols+` FROM `+s.table+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CategoryEntity{}
	for rows.Next() {
		var e CategoryEntity
		if extraScan != nil {
			if err := extraScan(rows, &e); err != nil {
				return nil, err
			}
		} else {
			if err := rows.Scan(&e.ID, &e.Name, &e.Description, &e.CreatedAt, &e.UpdatedAt); err != nil {
				return nil, err
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		cats, err := s.categories(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Categories = cats
	}
	return out, nil
}

func (s *categoryEntityService) categories(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT category FROM `+s.memberTable+` WHERE `+s.fkColumn+` = ? ORDER BY category`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *categoryEntityService) setCategories(ctx context.Context, tx *sql.Tx, id string, categories []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM `+s.memberTable+` WHERE `+s.fkColumn+` = ?`, id); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, c := range categories {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+s.memberTable+`(`+s.fkColumn+`, category) VALUES (?, ?)`, id, c); err != nil {
			return err
		}
	}
	return nil
}

func (s *categoryEntityService) delete(ctx context.Context, id string) error {
	inUse, err := inUseInPolicyLayers(ctx, s.db, s.policyLayerColumn, id)
	if err != nil {
		return err
	}
	if inUse {
		return ErrInUse
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM `+s.table+` WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func isUniqueErr(err error) bool { return err != nil && strings.Contains(err.Error(), "UNIQUE") }
