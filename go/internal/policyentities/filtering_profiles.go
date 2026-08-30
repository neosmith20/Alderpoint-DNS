package policyentities

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *Service) filteringProfiles() *categoryEntityService {
	return &categoryEntityService{db: s.DB, table: "filtering_profiles", memberTable: "filtering_profile_categories", fkColumn: "profile_id", policyLayerColumn: "filtering_profile_id"}
}

func (s *Service) ListFilteringProfiles(ctx context.Context) ([]CategoryEntity, error) {
	return s.filteringProfiles().list(ctx, nil)
}

func (s *Service) CreateFilteringProfile(ctx context.Context, id, name, description string, categories []string) (*CategoryEntity, error) {
	id = strings.TrimSpace(id)
	if err := validateID(id); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrValidation)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO filtering_profiles(id, name, description, created_at, updated_at) VALUES (?,?,?,?,?)`,
		id, name, description, now, now); err != nil {
		if isUniqueErr(err) {
			return nil, fmt.Errorf("%w: a filtering profile with that id or name already exists", ErrDuplicate)
		}
		return nil, err
	}
	if err := s.filteringProfiles().setCategories(ctx, tx, id, categories); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &CategoryEntity{ID: id, Name: name, Description: description, Categories: dedupSorted(categories), CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Service) UpdateFilteringProfile(ctx context.Context, id, name, description string, categories []string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: name is required", ErrValidation)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := tx.ExecContext(ctx, `UPDATE filtering_profiles SET name=?, description=?, updated_at=? WHERE id=?`, name, description, now, id)
	if err != nil {
		if isUniqueErr(err) {
			return fmt.Errorf("%w: a filtering profile with that name already exists", ErrDuplicate)
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := s.filteringProfiles().setCategories(ctx, tx, id, categories); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) DeleteFilteringProfile(ctx context.Context, id string) error {
	return s.filteringProfiles().delete(ctx, id)
}

// dedupSorted is used only to make a freshly-created entity's own
// returned Categories match exactly what setCategories just persisted
// (dedup, no ordering guarantee needed beyond determinism for tests).
func dedupSorted(categories []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, c := range categories {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}
