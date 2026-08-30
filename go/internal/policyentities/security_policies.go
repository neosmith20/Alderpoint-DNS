package policyentities

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *Service) securityPolicies() *categoryEntityService {
	return &categoryEntityService{db: s.DB, table: "security_policies", memberTable: "security_policy_categories", fkColumn: "policy_id", policyLayerColumn: "security_policy_id"}
}

func (s *Service) ListSecurityPolicies(ctx context.Context) ([]CategoryEntity, error) {
	return s.securityPolicies().list(ctx, nil)
}

func (s *Service) CreateSecurityPolicy(ctx context.Context, id, name, description string, categories []string) (*CategoryEntity, error) {
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
		`INSERT INTO security_policies(id, name, description, created_at, updated_at) VALUES (?,?,?,?,?)`,
		id, name, description, now, now); err != nil {
		if isUniqueErr(err) {
			return nil, fmt.Errorf("%w: a security policy with that id or name already exists", ErrDuplicate)
		}
		return nil, err
	}
	if err := s.securityPolicies().setCategories(ctx, tx, id, categories); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &CategoryEntity{ID: id, Name: name, Description: description, Categories: dedupSorted(categories), CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Service) UpdateSecurityPolicy(ctx context.Context, id, name, description string, categories []string) error {
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
	res, err := tx.ExecContext(ctx, `UPDATE security_policies SET name=?, description=?, updated_at=? WHERE id=?`, name, description, now, id)
	if err != nil {
		if isUniqueErr(err) {
			return fmt.Errorf("%w: a security policy with that name already exists", ErrDuplicate)
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := s.securityPolicies().setCategories(ctx, tx, id, categories); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) DeleteSecurityPolicy(ctx context.Context, id string) error {
	return s.securityPolicies().delete(ctx, id)
}
