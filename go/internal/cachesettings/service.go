// Package cachesettings backs Advanced > Cache's real Configuration
// section: BIND's own options{} cache-tuning directives (max-cache-ttl,
// max-ncache-ttl, prefetch, stale-answer-enable/max-stale-ttl) -- the
// cache the page's own hit/miss counters actually measure (rndc/
// stats-channel), distinct from dnsdist's packet cache (dnscompile.
// Input.CacheMaxEntries/CacheMaxTTLSeconds, already real, unrelated to
// this settings object).
package cachesettings

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Settings struct {
	MaxCacheTTLSeconds    int    `json:"max_cache_ttl_seconds"`
	MaxNegativeTTLSeconds int    `json:"max_negative_ttl_seconds"`
	PrefetchEnabled       bool   `json:"prefetch_enabled"`
	ServeStaleEnabled     bool   `json:"serve_stale_enabled"`
	MaxStaleTTLSeconds    int    `json:"max_stale_ttl_seconds"`
	UpdatedAt             string `json:"updated_at"`
}

// Validate mirrors BIND's own real constraints (max-ncache-ttl is
// capped at 7 days by named itself; everything else just needs to be a
// sane positive duration) -- rejected here so a bad value never even
// reaches a real named.conf, rather than surfacing as an opaque
// named-checkconf failure at Apply time.
func (s Settings) Validate() error {
	if s.MaxCacheTTLSeconds < 1 || s.MaxCacheTTLSeconds > 30*86400 {
		return fmt.Errorf("max cache TTL must be between 1 second and 30 days")
	}
	if s.MaxNegativeTTLSeconds < 1 || s.MaxNegativeTTLSeconds > 7*86400 {
		return fmt.Errorf("max negative TTL must be between 1 second and 7 days (BIND's own hard limit)")
	}
	if s.ServeStaleEnabled && (s.MaxStaleTTLSeconds < 1 || s.MaxStaleTTLSeconds > 7*86400) {
		return fmt.Errorf("max stale TTL must be between 1 second and 7 days")
	}
	return nil
}

type Service struct {
	DB *sql.DB
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	var out Settings
	var prefetch, serveStale int
	err := s.DB.QueryRowContext(ctx,
		`SELECT max_cache_ttl_seconds, max_negative_ttl_seconds, prefetch_enabled, serve_stale_enabled, max_stale_ttl_seconds, updated_at
		 FROM cache_settings WHERE id=1`,
	).Scan(&out.MaxCacheTTLSeconds, &out.MaxNegativeTTLSeconds, &prefetch, &serveStale, &out.MaxStaleTTLSeconds, &out.UpdatedAt)
	out.PrefetchEnabled = prefetch != 0
	out.ServeStaleEnabled = serveStale != 0
	return out, err
}

func (s *Service) Update(ctx context.Context, in Settings) (Settings, error) {
	if err := in.Validate(); err != nil {
		return Settings{}, err
	}
	prefetch, serveStale := 0, 0
	if in.PrefetchEnabled {
		prefetch = 1
	}
	if in.ServeStaleEnabled {
		serveStale = 1
	}
	in.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.ExecContext(ctx,
		`UPDATE cache_settings SET max_cache_ttl_seconds=?, max_negative_ttl_seconds=?, prefetch_enabled=?, serve_stale_enabled=?, max_stale_ttl_seconds=?, updated_at=? WHERE id=1`,
		in.MaxCacheTTLSeconds, in.MaxNegativeTTLSeconds, prefetch, serveStale, in.MaxStaleTTLSeconds, in.UpdatedAt)
	if err != nil {
		return Settings{}, err
	}
	return in, nil
}
