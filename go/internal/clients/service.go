// Package clients is a native Go implementation of Managed Clients and
// Groups -- own schema and CRUD, not a Python proxy, same reasoning as
// internal/upstreams (see that package's doc comment: the Definition of
// Done rules out a permanent Python dependency, so a policy domain gets
// its own real Go schema and service logic from the start).
//
// Field shapes and validation match app/v2/control_db.py's
// clients/client_identifiers/client_groups/client_group_members tables
// and app/v2/webapp.py's client/group routes (read directly, not
// guessed). Deliberately NOT included in this package, disclosed rather
// than hidden:
//
//   - The policy-layer system (global/network/group/client policy
//     assignment -- filtering profile, safesearch, upstream, ECS mode,
//     etc.). That's shared infrastructure spanning multiple pages
//     (Clients & Access, Filters, DNS Settings), not something to bolt
//     onto Clients alone -- it needs its own dedicated pass.
//   - Observed clients / discovery. That data comes from Python's
//     discovery worker, a live-traffic-derived store analogous to
//     analytics (see PARITY_MATRIX.md's Sequencing note on the
//     read-only pyanalytics boundary) -- a separate compatibility-
//     boundary decision, not built here. This package is Managed
//     Clients only: the operator-created identity a human explicitly
//     defined, never an auto-populated "observed" row.
//   - Client enable/disable and edit/delete are not exposed by
//     Python's own API today either (verified by reading webapp.py --
//     only create exists) -- so none are invented here. Extending this
//     package to add them is real future work, not a Python-parity gap.
package clients

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrValidation = errors.New("validation failed")
	ErrConflict   = errors.New("conflict")
)

type Identifier struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type GroupRef struct {
	GroupID  string `json:"group_id"`
	Name     string `json:"name"`
	Priority int    `json:"priority"`
}

type Client struct {
	ID          int64        `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Enabled     bool         `json:"enabled"`
	Identifiers []Identifier `json:"identifiers"`
	Groups      []GroupRef   `json:"groups"`
}

type MemberRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type Group struct {
	GroupID  string      `json:"group_id"`
	Name     string      `json:"name"`
	Priority int         `json:"priority"`
	Members  []MemberRef `json:"members"`
}

type Service struct {
	DB *sql.DB
}

var validIdentifierKinds = map[string]bool{"ipv4": true, "ipv4_cidr": true, "ipv6": true, "ipv6_cidr": true, "clientid": true}

// validateIdentifier mirrors add_client_identifier's validation: kind
// must be one of the five known kinds, and an ipv4/ipv6/*_cidr value must
// actually parse as that kind of address/prefix. "clientid" (DNS Strong
// ClientID / DoH/DoT/DoQ identity) has no further format constraint here,
// matching Python (it's opaque to this layer).
func validateIdentifier(kind, value string) error {
	if !validIdentifierKinds[kind] {
		return fmt.Errorf("%w: invalid identifier kind: %q", ErrValidation, kind)
	}
	switch kind {
	case "ipv4":
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() {
			return fmt.Errorf("%w: invalid ipv4 address: %q", ErrValidation, value)
		}
	case "ipv6":
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is6() {
			return fmt.Errorf("%w: invalid ipv6 address: %q", ErrValidation, value)
		}
	case "ipv4_cidr":
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("%w: invalid ipv4 CIDR: %q", ErrValidation, value)
		}
	case "ipv6_cidr":
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is6() {
			return fmt.Errorf("%w: invalid ipv6 CIDR: %q", ErrValidation, value)
		}
	}
	return nil
}

func (s *Service) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT group_id, name, priority FROM client_groups ORDER BY priority, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := []Group{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.GroupID, &g.Name, &g.Priority); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range groups {
		members, err := s.groupMembers(ctx, groups[i].GroupID)
		if err != nil {
			return nil, err
		}
		groups[i].Members = members
	}
	return groups, nil
}

func (s *Service) groupMembers(ctx context.Context, groupID string) ([]MemberRef, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT c.id, c.name FROM clients c
		 JOIN client_group_members m ON m.client_id = c.id
		 JOIN client_groups g ON g.id = m.group_id
		 WHERE g.group_id = ? ORDER BY c.name`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := []MemberRef{}
	for rows.Next() {
		var m MemberRef
		if err := rows.Scan(&m.ID, &m.Name); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *Service) CreateGroup(ctx context.Context, groupID, name string, priority int) error {
	if name == "" {
		return fmt.Errorf("%w: name required", ErrValidation)
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO client_groups(group_id, name, priority, created_at) VALUES(?,?,?,?)`,
		groupID, name, priority, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("%w: duplicate group_id or name: %v", ErrConflict, err)
	}
	return nil
}

func (s *Service) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, description, enabled FROM clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Client{}
	for rows.Next() {
		var c Client
		var enabledInt int
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &enabledInt); err != nil {
			return nil, err
		}
		c.Enabled = enabledInt != 0
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		ids, err := s.identifiers(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Identifiers = ids
		groups, err := s.groupsForClient(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Groups = groups
	}
	return out, nil
}

func (s *Service) identifiers(ctx context.Context, clientID int64) ([]Identifier, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT kind, value FROM client_identifiers WHERE client_id=? ORDER BY kind, value`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []Identifier{}
	for rows.Next() {
		var id Identifier
		if err := rows.Scan(&id.Kind, &id.Value); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GroupsForClient is the exported form of groupsForClient, for callers
// outside this package that need one client's group memberships without
// loading the full client list (e.g. internal/policy's effective-policy
// resolver).
func (s *Service) GroupsForClient(ctx context.Context, clientID int64) ([]GroupRef, error) {
	return s.groupsForClient(ctx, clientID)
}

func (s *Service) groupsForClient(ctx context.Context, clientID int64) ([]GroupRef, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT g.group_id, g.name, g.priority FROM client_groups g
		 JOIN client_group_members m ON m.group_id = g.id
		 WHERE m.client_id = ? ORDER BY g.priority, g.name`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := []GroupRef{}
	for rows.Next() {
		var g GroupRef
		if err := rows.Scan(&g.GroupID, &g.Name, &g.Priority); err != nil {
			return nil, err
		}
		refs = append(refs, g)
	}
	return refs, rows.Err()
}

func (s *Service) CreateClient(ctx context.Context, name, description string) (int64, error) {
	if name == "" {
		return 0, fmt.Errorf("%w: name required", ErrValidation)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO clients(name, description, enabled, created_at, updated_at) VALUES(?,?,1,?,?)`,
		name, description, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Service) AddIdentifier(ctx context.Context, clientID int64, kind, value string) error {
	if err := validateIdentifier(kind, value); err != nil {
		return err
	}
	var exists int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM clients WHERE id=?`, clientID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrNotFound
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO client_identifiers(client_id, kind, value, created_at) VALUES(?,?,?,?)`,
		clientID, kind, value, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("%w: that client identifier is already assigned: %v", ErrConflict, err)
	}
	return nil
}

func (s *Service) AddToGroup(ctx context.Context, clientID int64, groupID string) error {
	var exists int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM clients WHERE id=?`, clientID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrNotFound
	}
	var groupRowID int64
	err := s.DB.QueryRowContext(ctx, `SELECT id FROM client_groups WHERE group_id=?`, groupID).Scan(&groupRowID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: unknown group_id: %s", ErrNotFound, groupID)
	} else if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx,
		`INSERT OR IGNORE INTO client_group_members(group_id, client_id) VALUES(?,?)`, groupRowID, clientID)
	return err
}
