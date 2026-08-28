// Package upstreams is a native Go implementation of DNS Settings /
// Upstreams -- not a proxy or a compatibility-boundary read of Python's
// control.db, unlike internal/pyanalytics. This is deliberate: per
// PARITY_MATRIX.md's "Sequencing note", the Definition of Done rules out
// a permanent dependency on the Python web application, so a policy
// domain like this one gets its own real Go schema and CRUD from the
// start -- the same pattern already proven by internal/blocklists and
// internal/localdns -- rather than a boundary that would just have to be
// replaced later.
//
// Field shapes and validation rules are matched field-for-field against
// app/v2/policy_store.py's upstream_profiles/upstream_endpoints tables
// (read directly, not guessed) so this is real parity, not a similarly-
// named reinvention.
//
// Corrected stale disclosure (2026-08-28): this package's profiles ARE
// compiled into the real, live Go-managed dnsdist runtime -- see
// internal/dnscompile.CompileDnsdist's newServer() calls (including
// real DoH forwarding via dohPath/tls kwargs), driven by
// internal/dnsruntime.Orchestrator.build() reading this package's
// List() output. The first enabled profile really is dnsdist's live
// forwarding policy (plain/DoT forwarders also feed BIND's own
// `forwarders {}` clause) -- `runtime.promoted` reflects a real
// promotion outcome via the same apply/rollback path every other
// DNS-runtime-affecting mutation uses, not an unconditional `true`.
//
// Still not implemented, disclosed rather than hidden: `secret_ref`
// (per-endpoint auth for an authenticated upstream, e.g. a bearer token
// header on a DoH forward). A Go-native secrets store now exists
// (internal/secretstore, see the Notifications row's credential
// storage for a working consumer) -- the remaining real blocker isn't
// "no secrets store" any more, it's that dnsdist's `newServer()` Lua
// API has not yet been confirmed to support a custom per-server HTTP
// header on the installed dnsdist version. Not yet investigated; this
// is a genuine open question, not assumed infeasible or silently
// wired as inert metadata.
package upstreams

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var (
	ErrNotFound    = errors.New("unknown upstream_profile_id")
	ErrValidation  = errors.New("upstream profile validation failed")
	ErrDuplicateID = errors.New("upstream_profile_id already exists")
)

type Endpoint struct {
	Address     string  `json:"address"`
	TLSHostname *string `json:"tls_hostname"`
	Priority    int     `json:"priority"`
	Weight      int     `json:"weight"`
	DohPath     *string `json:"doh_path"`
}

type Profile struct {
	UpstreamProfileID string     `json:"upstream_profile_id"`
	Name              string     `json:"name"`
	Transport         string     `json:"transport"`
	Strategy          string     `json:"strategy"`
	Enabled           bool       `json:"enabled"`
	SortOrder         int        `json:"sort_order"`
	Order             int        `json:"order"` // 1-based, matches Python's `sort_order + 1`
	Endpoints         []Endpoint `json:"endpoints"`
}

type Service struct {
	DB *sql.DB
}

// validate mirrors policy_store.py's _validate_upstream_profile_fields
// exactly, including which error each rule produces.
func validate(transport, strategy string, endpoints []Endpoint) error {
	switch transport {
	case "plain", "dot", "doh":
	default:
		return fmt.Errorf("%w: invalid transport: %q", ErrValidation, transport)
	}
	switch strategy {
	case "ordered", "failover", "load_balanced":
	default:
		return fmt.Errorf("%w: unsupported upstream strategy: %q (supported: ordered, failover, load_balanced)", ErrValidation, strategy)
	}
	if len(endpoints) == 0 {
		return fmt.Errorf("%w: upstream profile requires at least one endpoint", ErrValidation)
	}
	for _, ep := range endpoints {
		if transport == "doh" {
			if ep.TLSHostname == nil || *ep.TLSHostname == "" {
				return fmt.Errorf("%w: DoH endpoint %q requires tls_hostname for certificate validation -- refusing to create a DoH profile with no way to verify the peer certificate", ErrValidation, ep.Address)
			}
			path := "/dns-query"
			if ep.DohPath != nil && *ep.DohPath != "" {
				path = *ep.DohPath
			}
			for _, c := range path {
				if c == '\n' || c == '\r' || c == ' ' {
					return fmt.Errorf("%w: invalid doh_path: %q", ErrValidation, path)
				}
			}
			if len(path) == 0 || path[0] != '/' {
				return fmt.Errorf("%w: invalid doh_path: %q", ErrValidation, path)
			}
		}
	}
	return nil
}

func (s *Service) List(ctx context.Context) ([]Profile, bool, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, upstream_profile_id, name, transport, strategy, enabled, sort_order
		 FROM upstream_profiles ORDER BY sort_order ASC, upstream_profile_id ASC`)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	profiles := []Profile{}
	var rowIDs []int64
	anyEnabled := false
	for rows.Next() {
		var rowID int64
		var enabledInt int
		var p Profile
		if err := rows.Scan(&rowID, &p.UpstreamProfileID, &p.Name, &p.Transport, &p.Strategy, &enabledInt, &p.SortOrder); err != nil {
			return nil, false, err
		}
		p.Enabled = enabledInt != 0
		p.Order = p.SortOrder + 1
		if p.Enabled {
			anyEnabled = true
		}
		profiles = append(profiles, p)
		rowIDs = append(rowIDs, rowID)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	for i, rowID := range rowIDs {
		eps, err := s.loadEndpoints(ctx, rowID)
		if err != nil {
			return nil, false, err
		}
		profiles[i].Endpoints = eps
	}
	return profiles, !anyEnabled, nil
}

func (s *Service) loadEndpoints(ctx context.Context, rowID int64) ([]Endpoint, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT address, tls_hostname, priority, weight, doh_path FROM upstream_endpoints
		 WHERE upstream_profile_row_id=? ORDER BY priority ASC, address ASC`, rowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	eps := []Endpoint{}
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.Address, &e.TLSHostname, &e.Priority, &e.Weight, &e.DohPath); err != nil {
			return nil, err
		}
		eps = append(eps, e)
	}
	return eps, rows.Err()
}

func (s *Service) Create(ctx context.Context, upstreamProfileID, name, transport, strategy string, endpoints []Endpoint) error {
	if err := validate(transport, strategy, endpoints); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO upstream_profiles(upstream_profile_id, name, transport, strategy, created_at, enabled, sort_order)
		 VALUES(?,?,?,?,datetime('now'),1,(SELECT COALESCE(MAX(sort_order),0)+1 FROM upstream_profiles))`,
		upstreamProfileID, name, transport, strategy)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDuplicateID, err)
	}
	rowID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	if err := insertEndpoints(ctx, tx, rowID, endpoints); err != nil {
		return err
	}
	return tx.Commit()
}

func insertEndpoints(ctx context.Context, tx *sql.Tx, rowID int64, endpoints []Endpoint) error {
	for _, e := range endpoints {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO upstream_endpoints(upstream_profile_row_id, address, tls_hostname, priority, weight, doh_path)
			 VALUES(?,?,?,?,?,?)`,
			rowID, e.Address, e.TLSHostname, e.Priority, e.Weight, e.DohPath); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) rowID(ctx context.Context, tx *sql.Tx, upstreamProfileID string) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM upstream_profiles WHERE upstream_profile_id=?`, upstreamProfileID).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, ErrNotFound
	}
	return id, err
}

func (s *Service) Update(ctx context.Context, upstreamProfileID, name, transport, strategy string, endpoints []Endpoint) error {
	if err := validate(transport, strategy, endpoints); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rowID, err := s.rowID(ctx, tx, upstreamProfileID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE upstream_profiles SET name=?, transport=?, strategy=? WHERE id=?`, name, transport, strategy, rowID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM upstream_endpoints WHERE upstream_profile_row_id=?`, rowID); err != nil {
		return err
	}
	if err := insertEndpoints(ctx, tx, rowID, endpoints); err != nil {
		return err
	}
	return tx.Commit()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Service) SetEnabled(ctx context.Context, upstreamProfileID string, enabled bool) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE upstream_profiles SET enabled=? WHERE upstream_profile_id=?`, boolToInt(enabled), upstreamProfileID)
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

func (s *Service) Delete(ctx context.Context, upstreamProfileID string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM upstream_profiles WHERE upstream_profile_id=?`, upstreamProfileID)
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

// IsLastEnabled mirrors _is_last_enabled_upstream: true only when
// upstreamProfileID is enabled AND it's the *only* enabled profile.
func (s *Service) IsLastEnabled(ctx context.Context, upstreamProfileID string) (bool, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT upstream_profile_id FROM upstream_profiles WHERE enabled=1`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var enabledIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return false, err
		}
		enabledIDs = append(enabledIDs, id)
	}
	return len(enabledIDs) == 1 && enabledIDs[0] == upstreamProfileID, rows.Err()
}

// Reorder mirrors reorder_upstream_profiles: sets sort_order to each id's
// position in orderedIDs; an id that exists but is omitted keeps its
// current position (never silently dropped from the list).
func (s *Service) Reorder(ctx context.Context, orderedIDs []string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existing := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT upstream_profile_id FROM upstream_profiles`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		existing[id] = true
	}
	rows.Close()

	for _, id := range orderedIDs {
		if !existing[id] {
			return fmt.Errorf("%w: unknown upstream_profile_id(s) in reorder request", ErrNotFound)
		}
	}
	for position, id := range orderedIDs {
		if _, err := tx.ExecContext(ctx, `UPDATE upstream_profiles SET sort_order=? WHERE upstream_profile_id=?`, position, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
