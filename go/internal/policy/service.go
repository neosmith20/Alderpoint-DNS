// Package policy is a native Go implementation of the shared policy-layer
// system (global/network/group/client/schedule), matching
// app/v2/policy_store.py's policy_layers/policy_networks tables and
// save_policy_layer/load_policy_layer field-for-field. Shared
// infrastructure: Clients & Access, Filters, and DNS Settings all read
// and write through this one package rather than each reinventing it.
//
// Deliberately not included here, disclosed rather than hidden: this
// package only stores the *desired* policy layer -- it does not compile
// it into a runtime-affecting artifact (dnsdist/BIND config), the same
// disclosed gap internal/upstreams already has. "Effective policy explain"
// (walking global -> network -> group -> client precedence to compute
// what actually applies) is also not implemented yet -- a real, separate
// piece of logic (app/v2/policy_service.py's explain_policy_for_client),
// not a trivial addition to storage.
package policy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrValidation = errors.New("validation failed")
	ErrConflict   = errors.New("conflict")
)

var validScopes = map[string]bool{"global": true, "network": true, "group": true, "client": true, "schedule": true}

// Layer mirrors PolicyLayer exactly -- every field is a pointer so "unset
// (inherit)" (Go nil / JSON null) is never confused with a real zero
// value, same reasoning as Python's use of None throughout.
type Layer struct {
	FilteringProfileID        *string `json:"filtering_profile_id"`
	SafesearchMode            *string `json:"safesearch_mode"`
	ParentalPolicyID          *string `json:"parental_policy_id"`
	SecurityPolicyID          *string `json:"security_policy_id"`
	ServiceBlockingRulesetID  *string `json:"service_blocking_ruleset_id"`
	BlockingResponseMode      *string `json:"blocking_response_mode"`
	CustomIPv4                *string `json:"custom_ipv4"`
	CustomIPv6                *string `json:"custom_ipv6"`
	UpstreamProfileID         *string `json:"upstream_profile_id"`
	FallbackStrategy          *string `json:"fallback_strategy"`
	FallbackUpstreamProfileID *string `json:"fallback_upstream_profile_id"`
	ECSMode                   *string `json:"ecs_mode"`
	DomainRoutingRulesetID    *string `json:"domain_routing_ruleset_id"`
	QueryLogEnabled           *bool   `json:"query_log_enabled"`
	StatisticsEnabled         *bool   `json:"statistics_enabled"`
}

type Network struct {
	NetworkID string `json:"network_id"`
	CIDR      string `json:"cidr"`
}

type Service struct {
	DB *sql.DB
}

func boolPtrToIntPtr(b *bool) *int {
	if b == nil {
		return nil
	}
	v := 0
	if *b {
		v = 1
	}
	return &v
}

func intPtrToBoolPtr(i *int) *bool {
	if i == nil {
		return nil
	}
	v := *i != 0
	return &v
}

// Save upserts the layer for (scope, scopeRef) -- ON CONFLICT DO UPDATE,
// matching Python's exact upsert semantics (a second save replaces the
// whole layer, it doesn't merge field-by-field).
func (s *Service) Save(ctx context.Context, scope, scopeRef string, l Layer) error {
	if !validScopes[scope] {
		return fmt.Errorf("%w: invalid scope: %q", ErrValidation, scope)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO policy_layers (
			scope, scope_ref, filtering_profile_id, safesearch_mode, parental_policy_id,
			security_policy_id, service_blocking_ruleset_id, blocking_response_mode,
			custom_ipv4, custom_ipv6, upstream_profile_id, fallback_strategy,
			fallback_upstream_profile_id, ecs_mode, domain_routing_ruleset_id,
			query_log_enabled, statistics_enabled, created_at, updated_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(scope, scope_ref) DO UPDATE SET
			filtering_profile_id=excluded.filtering_profile_id,
			safesearch_mode=excluded.safesearch_mode,
			parental_policy_id=excluded.parental_policy_id,
			security_policy_id=excluded.security_policy_id,
			service_blocking_ruleset_id=excluded.service_blocking_ruleset_id,
			blocking_response_mode=excluded.blocking_response_mode,
			custom_ipv4=excluded.custom_ipv4,
			custom_ipv6=excluded.custom_ipv6,
			upstream_profile_id=excluded.upstream_profile_id,
			fallback_strategy=excluded.fallback_strategy,
			fallback_upstream_profile_id=excluded.fallback_upstream_profile_id,
			ecs_mode=excluded.ecs_mode,
			domain_routing_ruleset_id=excluded.domain_routing_ruleset_id,
			query_log_enabled=excluded.query_log_enabled,
			statistics_enabled=excluded.statistics_enabled,
			updated_at=excluded.updated_at`,
		scope, scopeRef, l.FilteringProfileID, l.SafesearchMode, l.ParentalPolicyID,
		l.SecurityPolicyID, l.ServiceBlockingRulesetID, l.BlockingResponseMode,
		l.CustomIPv4, l.CustomIPv6, l.UpstreamProfileID, l.FallbackStrategy,
		l.FallbackUpstreamProfileID, l.ECSMode, l.DomainRoutingRulesetID,
		boolPtrToIntPtr(l.QueryLogEnabled), boolPtrToIntPtr(l.StatisticsEnabled), now, now)
	return err
}

// Load returns the zero-value (all-nil, "inherit everything") Layer if no
// row exists yet, matching Python's load_policy_layer -- a caller never
// gets an error just because a scope hasn't been configured.
func (s *Service) Load(ctx context.Context, scope, scopeRef string) (Layer, error) {
	var l Layer
	var qle, se sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `
		SELECT filtering_profile_id, safesearch_mode, parental_policy_id, security_policy_id,
		       service_blocking_ruleset_id, blocking_response_mode, custom_ipv4, custom_ipv6,
		       upstream_profile_id, fallback_strategy, fallback_upstream_profile_id, ecs_mode,
		       domain_routing_ruleset_id, query_log_enabled, statistics_enabled
		FROM policy_layers WHERE scope=? AND scope_ref=?`, scope, scopeRef).Scan(
		&l.FilteringProfileID, &l.SafesearchMode, &l.ParentalPolicyID, &l.SecurityPolicyID,
		&l.ServiceBlockingRulesetID, &l.BlockingResponseMode, &l.CustomIPv4, &l.CustomIPv6,
		&l.UpstreamProfileID, &l.FallbackStrategy, &l.FallbackUpstreamProfileID, &l.ECSMode,
		&l.DomainRoutingRulesetID, &qle, &se)
	if err == sql.ErrNoRows {
		return Layer{}, nil
	}
	if err != nil {
		return Layer{}, err
	}
	if qle.Valid {
		v := int(qle.Int64)
		l.QueryLogEnabled = intPtrToBoolPtr(&v)
	}
	if se.Valid {
		v := int(se.Int64)
		l.StatisticsEnabled = intPtrToBoolPtr(&v)
	}
	return l, nil
}

func (s *Service) ListNetworks(ctx context.Context) ([]Network, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT network_id, cidr FROM policy_networks ORDER BY network_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Network{}
	for rows.Next() {
		var n Network
		if err := rows.Scan(&n.NetworkID, &n.CIDR); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Service) CreateNetwork(ctx context.Context, networkID, cidr string) error {
	if cidr == "" {
		return fmt.Errorf("%w: cidr required", ErrValidation)
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO policy_networks(network_id, cidr, created_at) VALUES(?,?,?)`,
		networkID, cidr, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("%w: duplicate network_id or cidr: %v", ErrConflict, err)
	}
	return nil
}
