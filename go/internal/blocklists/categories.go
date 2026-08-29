// Custom Category create/rename/delete for Blocklists -- previously
// `category` on blocklist_subscriptions was just a free-text column
// with three hardcoded UI options, no real category entity an owner
// could create, rename, or delete (0016_blocklist_categories.sql).
package blocklists

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type Category struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

var ErrCategoryInUse = fmt.Errorf("category is still used by at least one subscription")
var ErrCategoryNotFound = fmt.Errorf("category not found")

func (s *Service) ListCategories(ctx context.Context) ([]Category, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, created_at, updated_at FROM blocklist_categories ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Category{}
	for rows.Next() {
		var c Category
		if err := rows.Scan(&c.ID, &c.Name, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) CreateCategory(ctx context.Context, name string) (*Category, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("category name is required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.DB.ExecContext(ctx, `INSERT INTO blocklist_categories (name, created_at, updated_at) VALUES (?, ?, ?)`, name, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("a category named %q already exists", name)
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Category{ID: id, Name: name, CreatedAt: now, UpdatedAt: now}, nil
}

// RenameCategory renames a category and updates every subscription
// currently using its old name, in one transaction, so a rename can
// never leave a subscription pointing at a name that no longer exists
// as a real category.
func (s *Service) RenameCategory(ctx context.Context, id int64, newName string) error {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return fmt.Errorf("category name is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var oldName string
	if err := tx.QueryRowContext(ctx, `SELECT name FROM blocklist_categories WHERE id = ?`, id).Scan(&oldName); err != nil {
		if err == sql.ErrNoRows {
			return ErrCategoryNotFound
		}
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx, `UPDATE blocklist_categories SET name = ?, updated_at = ? WHERE id = ?`, newName, now, id); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("a category named %q already exists", newName)
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE blocklist_subscriptions SET category = ? WHERE category = ?`, newName, oldName); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteCategory refuses to delete a category still in use by any real
// subscription -- deleting it would silently leave those subscriptions
// pointing at a category that no longer exists, the same "never orphan
// a reference" discipline the rest of this codebase already follows.
func (s *Service) DeleteCategory(ctx context.Context, id int64) error {
	var name string
	if err := s.DB.QueryRowContext(ctx, `SELECT name FROM blocklist_categories WHERE id = ?`, id).Scan(&name); err != nil {
		if err == sql.ErrNoRows {
			return ErrCategoryNotFound
		}
		return err
	}
	var inUse int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM blocklist_subscriptions WHERE category = ?`, name).Scan(&inUse); err != nil {
		return err
	}
	if inUse > 0 {
		return ErrCategoryInUse
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM blocklist_categories WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrCategoryNotFound
	}
	return nil
}
