// Package appliancesettings backs General Settings > Appliance Identity's
// one genuinely live-editable field: the display name. Every other real
// setting General Settings shows (timezone, protection defaults, query
// log/statistics retention, interface preferences) already has a real
// owner elsewhere (appliance.yaml at boot for timezone, AnalyticsSettings
// for query log/statistics, browser localStorage for interface
// preferences) -- this package exists only because ApplianceName was
// previously a config-file-only value with no live PUT path at all
// (see cmd/alderpointdns-go/main.go's own ApplianceName: cfg.Appliance.Name).
package appliancesettings

import (
	"context"
	"database/sql"
)

type Service struct {
	DB *sql.DB
}

// Get returns the DB-stored override, or "" if none was ever set (the
// caller falls back to the boot-time config value in that case -- see
// httpapi.Server.applianceDisplayName).
func (s *Service) Get(ctx context.Context) (string, error) {
	var name sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT display_name FROM appliance_settings WHERE id=1`).Scan(&name)
	if err != nil {
		return "", err
	}
	return name.String, nil
}

func (s *Service) Set(ctx context.Context, name string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE appliance_settings SET display_name=? WHERE id=1`, name)
	return err
}
