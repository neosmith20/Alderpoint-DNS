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
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/clientid"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrValidation = errors.New("validation failed")
	ErrConflict   = errors.New("conflict")
)

type Identifier struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Label     string `json:"label"`
	RevokedAt string `json:"revoked_at,omitempty"`

	// DoHPath/SNIHostname are populated only for kind=="clientid" --
	// the exact, real dnsdist-facing identity encodings this ClientID
	// is compiled to (internal/clientid), included here purely for
	// display (the UI/API caller shouldn't have to re-derive them) --
	// internal/dnscompile computes these itself from Value directly,
	// never from these fields.
	DoHPath     string `json:"doh_path,omitempty"`
	SNIHostname string `json:"sni_hostname,omitempty"`
}

// DomainOverride is one explicit per-client domain block/allow entry
// (see internal/dnscompile's ClientOverride for how these compile,
// and the package doc comment's disclosed scope: literal domain
// matching tied to one client's identity, not a full policy layer).
type DomainOverride struct {
	ID           int64  `json:"id"`
	ClientID     int64  `json:"client_id"`
	OverrideType string `json:"override_type"` // "block" | "allow"
	Pattern      string `json:"pattern"`
	CreatedAt    string `json:"created_at"`
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
// ClientID / DoH/DoT/DoQ identity) is validated by internal/clientid's
// exact-shape rule (48 or 64 lowercase hex, never normalized/truncated)
// -- unlike Python, this is NOT opaque to this layer: a real per-client
// DoH path/DoT-DoQ SNI binding is compiled from this exact value (see
// internal/dnscompile), so it must be a real, unambiguous identity from
// the moment it's stored, not whatever string happened to be typed in.
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
	case "clientid":
		if err := clientid.ValidateHex(value); err != nil {
			return fmt.Errorf("%w: invalid Strong ClientID: %v", ErrValidation, err)
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
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, kind, value, label, COALESCE(revoked_at,'') FROM client_identifiers WHERE client_id=? ORDER BY kind, value`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []Identifier{}
	for rows.Next() {
		var id Identifier
		if err := rows.Scan(&id.ID, &id.Kind, &id.Value, &id.Label, &id.RevokedAt); err != nil {
			return nil, err
		}
		if id.Kind == "clientid" {
			id.DoHPath = clientid.DoHPath(id.Value)
			id.SNIHostname = clientid.EncodeSNILabel(id.Value)
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

// GenerateClientID generates a new Strong ClientID with the OS-backed
// CSPRNG (internal/clientid.GenerateHex, never math/rand) at the given
// bit strength and adds it as a "clientid" identifier for clientID,
// with the given operator-supplied label. Retries once on the
// astronomically unlikely event of a real collision with an existing
// stored value (UNIQUE(kind,value) -- ErrConflict) before giving up,
// rather than either silently reusing an existing identity or handing
// the caller a transient-looking error for what is really a one-in-
// 2^192-or-2^256 coincidence.
func (s *Service) GenerateClientID(ctx context.Context, clientID int64, bits int, label string) (Identifier, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		value, err := clientid.GenerateHex(bits)
		if err != nil {
			return Identifier{}, fmt.Errorf("generating Strong ClientID: %w", err)
		}
		var exists int
		if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM clients WHERE id=?`, clientID).Scan(&exists); err != nil {
			return Identifier{}, err
		}
		if exists == 0 {
			return Identifier{}, ErrNotFound
		}
		now := time.Now().UTC().Format(time.RFC3339)
		res, err := s.DB.ExecContext(ctx,
			`INSERT INTO client_identifiers(client_id, kind, value, label, created_at) VALUES(?,'clientid',?,?,?)`,
			clientID, value, label, now)
		if err != nil {
			lastErr = fmt.Errorf("%w: generated value collided with an existing identity: %v", ErrConflict, err)
			continue
		}
		id, err := res.LastInsertId()
		if err != nil {
			return Identifier{}, err
		}
		return Identifier{
			ID: id, Kind: "clientid", Value: value, Label: label,
			DoHPath: clientid.DoHPath(value), SNIHostname: clientid.EncodeSNILabel(value),
		}, nil
	}
	return Identifier{}, lastErr
}

// RevokeIdentifier marks a "clientid" identifier revoked (sets
// revoked_at, never deletes the row -- see this migration's own doc
// comment: history/audit survives a revoke, DeleteIdentifier below is
// the separate explicit hard-delete). internal/dnsruntime's compiler
// must never bind a revoked identity -- see internal/dnsruntime's own
// orchestrator, which only ever loads active (revoked_at IS NULL)
// identifiers.
func (s *Service) RevokeIdentifier(ctx context.Context, identifierID int64) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE client_identifiers SET revoked_at=? WHERE id=? AND kind='clientid' AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), identifierID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RegenerateIdentifier revokes the given "clientid" identifier and
// generates a brand-new one (same client, same bit strength as the old
// value's own length, same label) in one transaction -- an operator
// compromise-response action: the old identity stops being honored the
// instant this commits, a fresh one takes its place, and both changes
// are atomic (never a window where the client has zero identities, and
// never a window where both the old and new are simultaneously live
// due to a partial failure).
func (s *Service) RegenerateIdentifier(ctx context.Context, identifierID int64) (Identifier, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Identifier{}, err
	}
	defer tx.Rollback()

	var clientRowID int64
	var oldValue, label string
	err = tx.QueryRowContext(ctx,
		`SELECT client_id, value, label FROM client_identifiers WHERE id=? AND kind='clientid' AND revoked_at IS NULL`,
		identifierID).Scan(&clientRowID, &oldValue, &label)
	if err == sql.ErrNoRows {
		return Identifier{}, ErrNotFound
	} else if err != nil {
		return Identifier{}, err
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE client_identifiers SET revoked_at=? WHERE id=?`,
		time.Now().UTC().Format(time.RFC3339), identifierID); err != nil {
		return Identifier{}, err
	}

	bits := clientid.Bits192
	if len(oldValue) == 64 {
		bits = clientid.Bits256
	}
	var newValue string
	var newID int64
	for attempt := 0; attempt < 2; attempt++ {
		newValue, err = clientid.GenerateHex(bits)
		if err != nil {
			return Identifier{}, fmt.Errorf("generating Strong ClientID: %w", err)
		}
		res, err2 := tx.ExecContext(ctx,
			`INSERT INTO client_identifiers(client_id, kind, value, label, created_at) VALUES(?,'clientid',?,?,?)`,
			clientRowID, newValue, label, time.Now().UTC().Format(time.RFC3339))
		if err2 != nil {
			err = fmt.Errorf("%w: generated value collided with an existing identity: %v", ErrConflict, err2)
			continue
		}
		newID, err = res.LastInsertId()
		break
	}
	if err != nil {
		return Identifier{}, err
	}
	if err := tx.Commit(); err != nil {
		return Identifier{}, err
	}
	return Identifier{
		ID: newID, Kind: "clientid", Value: newValue, Label: label,
		DoHPath: clientid.DoHPath(newValue), SNIHostname: clientid.EncodeSNILabel(newValue),
	}, nil
}

// DeleteIdentifier hard-deletes any identifier (any kind, revoked or
// not) -- the explicit, separate, operator-initiated action distinct
// from Revoke (which is specifically the "stop honoring this Strong
// ClientID, keep the history" action for kind='clientid' only).
func (s *Service) DeleteIdentifier(ctx context.Context, identifierID int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM client_identifiers WHERE id=?`, identifierID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetIdentifierLabel updates a "clientid" identifier's human label
// in place (display-only metadata, never re-validated as part of the
// identity itself).
func (s *Service) SetIdentifierLabel(ctx context.Context, identifierID int64, label string) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE client_identifiers SET label=? WHERE id=? AND kind='clientid'`, label, identifierID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

var validOverrideTypes = map[string]bool{"block": true, "allow": true}

// AddDomainOverride adds one explicit per-client domain block/allow
// entry (see internal/dnscompile's ClientOverride/this package's own
// migration doc comment for the disclosed, deliberately narrow scope).
func (s *Service) AddDomainOverride(ctx context.Context, clientID int64, overrideType, pattern string) (DomainOverride, error) {
	if !validOverrideTypes[overrideType] {
		return DomainOverride{}, fmt.Errorf("%w: invalid override_type: %q (must be block or allow)", ErrValidation, overrideType)
	}
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return DomainOverride{}, fmt.Errorf("%w: pattern required", ErrValidation)
	}
	var exists int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM clients WHERE id=?`, clientID).Scan(&exists); err != nil {
		return DomainOverride{}, err
	}
	if exists == 0 {
		return DomainOverride{}, ErrNotFound
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO client_domain_overrides(client_id, override_type, pattern, created_at) VALUES(?,?,?,?)`,
		clientID, overrideType, pattern, now)
	if err != nil {
		return DomainOverride{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return DomainOverride{}, err
	}
	return DomainOverride{ID: id, ClientID: clientID, OverrideType: overrideType, Pattern: pattern, CreatedAt: now}, nil
}

// DomainOverridesForClient lists one client's explicit domain
// overrides -- used both by the API (display) and by
// internal/dnsruntime's orchestrator (compile input).
func (s *Service) DomainOverridesForClient(ctx context.Context, clientID int64) ([]DomainOverride, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, client_id, override_type, pattern, created_at FROM client_domain_overrides WHERE client_id=? ORDER BY override_type, pattern`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DomainOverride{}
	for rows.Next() {
		var o DomainOverride
		if err := rows.Scan(&o.ID, &o.ClientID, &o.OverrideType, &o.Pattern, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// DeleteDomainOverride removes one explicit override by its own ID.
func (s *Service) DeleteDomainOverride(ctx context.Context, overrideID int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM client_domain_overrides WHERE id=?`, overrideID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AllActiveClientIdentities returns every non-revoked "clientid"
// identifier across every client, joined with each client's own
// name/enabled state and its domain overrides -- exactly the shape
// internal/dnsruntime's orchestrator needs to build
// internal/dnscompile's ClientIdentities/ClientOverrides input, without
// duplicating this query there. A disabled client's identities are
// still returned (Enabled reflects that) -- the caller decides whether
// a disabled client's bindings should still compile; today the
// orchestrator excludes them, matching how every other domain here
// treats "disabled".
type ActiveClientIdentity struct {
	ClientID      int64
	ClientName    string
	ClientEnabled bool
	IdentifierID  int64
	Value         string
	Overrides     []DomainOverride
}

func (s *Service) AllActiveClientIdentities(ctx context.Context) ([]ActiveClientIdentity, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT ci.id, ci.value, c.id, c.name, c.enabled
		FROM client_identifiers ci
		JOIN clients c ON c.id = ci.client_id
		WHERE ci.kind='clientid' AND ci.revoked_at IS NULL
		ORDER BY c.id, ci.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActiveClientIdentity
	overridesByClient := map[int64][]DomainOverride{}
	for rows.Next() {
		var a ActiveClientIdentity
		var enabledInt int
		if err := rows.Scan(&a.IdentifierID, &a.Value, &a.ClientID, &a.ClientName, &enabledInt); err != nil {
			return nil, err
		}
		a.ClientEnabled = enabledInt != 0
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if _, ok := overridesByClient[out[i].ClientID]; !ok {
			overrides, err := s.DomainOverridesForClient(ctx, out[i].ClientID)
			if err != nil {
				return nil, err
			}
			overridesByClient[out[i].ClientID] = overrides
		}
		out[i].Overrides = overridesByClient[out[i].ClientID]
	}
	return out, nil
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
