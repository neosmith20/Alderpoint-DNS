package policyentities

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ServiceBlockingRuleset is domain-based, not category-based: it blocks
// specific named services (e.g. one social-media app) by their own
// known domains, orthogonal to the blocklist-subscription/category
// system CategoryEntity draws from.
type ServiceBlockingRuleset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

func (s *Service) ListServiceBlockingRulesets(ctx context.Context) ([]ServiceBlockingRuleset, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, description, created_at, updated_at FROM service_blocking_rulesets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ServiceBlockingRuleset{}
	for rows.Next() {
		var r ServiceBlockingRuleset
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		domains, err := s.serviceBlockingDomains(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Domains = domains
	}
	return out, nil
}

func (s *Service) serviceBlockingDomains(ctx context.Context, id string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT domain FROM service_blocking_ruleset_domains WHERE ruleset_id = ? ORDER BY domain`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func setServiceBlockingDomains(ctx context.Context, tx *sql.Tx, id string, domains []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM service_blocking_ruleset_domains WHERE ruleset_id = ?`, id); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimSuffix(d, ".")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO service_blocking_ruleset_domains(ruleset_id, domain) VALUES (?, ?)`, id, d); err != nil {
			return err
		}
	}
	return nil
}

// dedupNormalizedDomains mirrors setServiceBlockingDomains' own
// normalization (lowercase, trailing-dot-stripped) exactly, so a
// freshly-created ruleset's returned Domains matches what was actually
// persisted -- CategoryEntity's own dedupSorted has no such
// normalization (categories are opaque strings, not domain names) and
// would otherwise let a caller see a stale, differently-cased echo of
// what it sent rather than the real stored value.
func dedupNormalizedDomains(domains []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimSuffix(d, ".")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

func (s *Service) CreateServiceBlockingRuleset(ctx context.Context, id, name, description string, domains []string) (*ServiceBlockingRuleset, error) {
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
		`INSERT INTO service_blocking_rulesets(id, name, description, created_at, updated_at) VALUES (?,?,?,?,?)`,
		id, name, description, now, now); err != nil {
		if isUniqueErr(err) {
			return nil, fmt.Errorf("%w: a service blocking ruleset with that id or name already exists", ErrDuplicate)
		}
		return nil, err
	}
	if err := setServiceBlockingDomains(ctx, tx, id, domains); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ServiceBlockingRuleset{ID: id, Name: name, Description: description, Domains: dedupNormalizedDomains(domains), CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Service) UpdateServiceBlockingRuleset(ctx context.Context, id, name, description string, domains []string) error {
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
	res, err := tx.ExecContext(ctx, `UPDATE service_blocking_rulesets SET name=?, description=?, updated_at=? WHERE id=?`, name, description, now, id)
	if err != nil {
		if isUniqueErr(err) {
			return fmt.Errorf("%w: a service blocking ruleset with that name already exists", ErrDuplicate)
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := setServiceBlockingDomains(ctx, tx, id, domains); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) DeleteServiceBlockingRuleset(ctx context.Context, id string) error {
	inUse, err := inUseInPolicyLayers(ctx, s.DB, "service_blocking_ruleset_id", id)
	if err != nil {
		return err
	}
	if inUse {
		return ErrInUse
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM service_blocking_rulesets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
