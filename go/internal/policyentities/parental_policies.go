package policyentities

import (
	"context"
	"fmt"
	"strings"
	"time"
)

var validSafesearchModes = map[string]bool{"off": true, "moderate": true, "strict": true}

// ParentalPolicy carries its own SafeSearch mode in addition to the
// shared category-set shape -- distinct from policy_layers' own
// top-level safesearch_mode field (that field wins by direct scope
// precedence same as every other Layer field; a Parental Policy
// assigned at a scope contributes its SafeSearchMode as that scope's
// resolved value ONLY when the scope's own safesearch_mode is unset --
// see internal/policycompile's own doc comment for the exact
// precedence rule between the two).
func (s *Service) parentalPolicies() *categoryEntityService {
	return &categoryEntityService{db: s.DB, table: "parental_policies", memberTable: "parental_policy_categories", fkColumn: "policy_id", policyLayerColumn: "parental_policy_id"}
}

type ParentalPolicy struct {
	CategoryEntity
	SafesearchMode string `json:"safesearch_mode"`
}

// ListParentalPolicies uses its own dedicated query rather than the
// shared categoryEntityService.list (its extraScan hook only fills
// CategoryEntity's own fields, with no way to also hand back this
// entity's extra "safesearch_mode" column to this caller) -- simpler
// and more honest than threading an extra out-parameter through the
// shared helper for one caller.
func (s *Service) ListParentalPolicies(ctx context.Context) ([]ParentalPolicy, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, description, safesearch_mode, created_at, updated_at FROM parental_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ParentalPolicy{}
	for rows.Next() {
		var p ParentalPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.SafesearchMode, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		cats, err := s.parentalPolicies().categories(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Categories = cats
	}
	return out, nil
}

func (s *Service) CreateParentalPolicy(ctx context.Context, id, name, description, safesearchMode string, categories []string) (*ParentalPolicy, error) {
	id = strings.TrimSpace(id)
	if err := validateID(id); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrValidation)
	}
	if safesearchMode == "" {
		safesearchMode = "off"
	}
	if !validSafesearchModes[safesearchMode] {
		return nil, fmt.Errorf("%w: safesearch_mode must be off, moderate, or strict", ErrValidation)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO parental_policies(id, name, description, safesearch_mode, created_at, updated_at) VALUES (?,?,?,?,?,?)`,
		id, name, description, safesearchMode, now, now); err != nil {
		if isUniqueErr(err) {
			return nil, fmt.Errorf("%w: a parental policy with that id or name already exists", ErrDuplicate)
		}
		return nil, err
	}
	if err := s.parentalPolicies().setCategories(ctx, tx, id, categories); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ParentalPolicy{
		CategoryEntity: CategoryEntity{ID: id, Name: name, Description: description, Categories: dedupSorted(categories), CreatedAt: now, UpdatedAt: now},
		SafesearchMode: safesearchMode,
	}, nil
}

func (s *Service) UpdateParentalPolicy(ctx context.Context, id, name, description, safesearchMode string, categories []string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: name is required", ErrValidation)
	}
	if safesearchMode == "" {
		safesearchMode = "off"
	}
	if !validSafesearchModes[safesearchMode] {
		return fmt.Errorf("%w: safesearch_mode must be off, moderate, or strict", ErrValidation)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := tx.ExecContext(ctx, `UPDATE parental_policies SET name=?, description=?, safesearch_mode=?, updated_at=? WHERE id=?`, name, description, safesearchMode, now, id)
	if err != nil {
		if isUniqueErr(err) {
			return fmt.Errorf("%w: a parental policy with that name already exists", ErrDuplicate)
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := s.parentalPolicies().setCategories(ctx, tx, id, categories); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) DeleteParentalPolicy(ctx context.Context, id string) error {
	return s.parentalPolicies().delete(ctx, id)
}
