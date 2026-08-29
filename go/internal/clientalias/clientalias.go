// Package clientalias implements Client Aliases -- V1.1.1's
// local_dns.py upsert_alias/delete_alias/alias_for_client, read
// directly: a CIDR-to-display-name mapping so an address that isn't (or
// isn't yet) a Strong managed client still gets a real, human label
// wherever a client address is shown (Dashboard, Query Log, the
// Clients page's Client analytics table), instead of always falling
// back to the raw IP.
//
// Deliberately narrower than V1.1.1's real design: this is metadata/
// display only, matched purely client-side of the label-resolution
// chain (managed client's exact identifier > alias CIDR match > raw
// address) -- it has no DNS-answering effect and is not compiled into
// any runtime, unlike Local DNS's own A/AAAA/CNAME/PTR records.
package clientalias

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Alias struct {
	ID          int64  `json:"id"`
	CIDR        string `json:"cidr"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

var ErrNotFound = fmt.Errorf("client alias not found")

type Service struct {
	DB *sql.DB
}

func validate(cidr, displayName string) (netip.Prefix, error) {
	cidr = strings.TrimSpace(cidr)
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return netip.Prefix{}, fmt.Errorf("display_name is required")
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		// Accept a bare address too (V1.1.1's own upsert_alias contract:
		// a single IP is just a /32 or /128), matching how Client Aliases
		// are actually offered in the reference UI (one host or a range).
		addr, addrErr := netip.ParseAddr(cidr)
		if addrErr != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR or IP address: %v", err)
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		prefix = netip.PrefixFrom(addr, bits)
	}
	return prefix.Masked(), nil
}

func (s *Service) List(ctx context.Context) ([]Alias, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, cidr, display_name, description, created_at, updated_at FROM client_aliases ORDER BY cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alias{}
	for rows.Next() {
		var a Alias
		if err := rows.Scan(&a.ID, &a.CIDR, &a.DisplayName, &a.Description, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Service) Create(ctx context.Context, cidr, displayName, description string) (*Alias, error) {
	prefix, err := validate(cidr, displayName)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO client_aliases (cidr, display_name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		prefix.String(), strings.TrimSpace(displayName), strings.TrimSpace(description), now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("an alias for %s already exists", prefix.String())
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Alias{ID: id, CIDR: prefix.String(), DisplayName: strings.TrimSpace(displayName), Description: strings.TrimSpace(description), CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Service) Update(ctx context.Context, id int64, displayName, description string) error {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return fmt.Errorf("display_name is required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.DB.ExecContext(ctx, `UPDATE client_aliases SET display_name = ?, description = ?, updated_at = ? WHERE id = ?`,
		displayName, strings.TrimSpace(description), now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) Delete(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM client_aliases WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Resolver is a small, precomputed lookup structure: ResolveLabel takes
// a raw client address string and returns the alias display name for
// the most specific (longest-prefix) matching CIDR, or "" if none
// matches -- callers fall back to the raw address themselves, matching
// V1.1.1's own resolve_client_name "alias, else raw" contract.
type Resolver struct {
	prefixes []netip.Prefix
	names    []string
}

func NewResolver(aliases []Alias) *Resolver {
	r := &Resolver{}
	for _, a := range aliases {
		p, err := netip.ParsePrefix(a.CIDR)
		if err != nil {
			continue
		}
		r.prefixes = append(r.prefixes, p)
		r.names = append(r.names, a.DisplayName)
	}
	return r
}

func (r *Resolver) ResolveLabel(address string) string {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return ""
	}
	bestBits := -1
	best := ""
	for i, p := range r.prefixes {
		if p.Contains(addr) && p.Bits() > bestBits {
			bestBits = p.Bits()
			best = r.names[i]
		}
	}
	return best
}
