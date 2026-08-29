// Real-only replicable-table allowlist, Go-native translation of
// app/replication.py's REPLICABLE_TABLES/NEVER_REPLICATED_TABLES (read
// directly). Flat tables are wholesale delete-then-reinsert on apply,
// exactly like Python's own v1 "replica tables are fully primary-owned"
// design (never diffed/merged). clients/client_groups are nested and
// re-keyed by their own natural names/group_ids instead of their
// surrogate AUTOINCREMENT ids, for the identical reason Python's own
// _build_clients_section/_apply_clients_access_sections comment gives:
// a surrogate id is meaningless once copied onto a node with its own
// independent autoincrement sequence.
//
// Deliberately excluded, matching Python's own exclusion reasoning
// exactly: upstream_profiles/upstream_endpoints/domain_routing_rules
// (each appliance manages its own upstream resolvers independently --
// replicating them would let a primary silently override a replica's
// own resolver assignment, the identical incident Python's own denylist
// comment documents) and dns_transport_settings/dnscrypt_settings (real
// per-node listener ports and, for DNSCrypt, real key-material file
// paths that are meaningless -- or actively wrong -- on another node).
// admins/login_attempts/sessions/secrets/notification_*/import_jobs/
// blocklist_jobs/blocklist_settings/schema_migrations/replication_* are
// never replicated for the same reasons Python's NEVER_REPLICATED_TABLES
// lists: credentials, per-node operational state, or the replication
// bookkeeping tables themselves.
package replication

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// flatTable describes one wholesale-replicated table: which columns
// (in this exact order) are read/written, and in the order tables must
// be applied (client_groups before clients would matter if clients
// referenced groups by surrogate id, but group_id is a natural key, so
// order only matters for readability here, not correctness).
type flatTable struct {
	name    string
	columns []string
}

// created_at/updated_at are included verbatim wherever the underlying
// table requires them NOT NULL -- matching Python's own local_dns_
// records/client_aliases precedent of replicating timestamps as-is
// (this data is configuration metadata, not a secret or per-node
// operational value) rather than inventing a "stamp fresh on apply"
// rule this package would then have to keep consistent with every
// table's own NOT NULL constraints.
var flatTables = []flatTable{
	{"blocklist_categories", []string{"name", "created_at", "updated_at"}},
	{"blocklist_subscriptions", []string{"subscription_id", "name", "url", "category", "enabled", "created_at"}},
	{"custom_rules", []string{"rule_type", "pattern", "rewrite_target", "enabled", "priority", "created_at"}},
	{"local_dns_records", []string{"name", "record_type", "value", "ttl", "enabled", "created_at", "updated_at"}},
	{"client_aliases", []string{"cidr", "display_name", "description", "created_at", "updated_at"}},
	{"client_groups", []string{"group_id", "name", "priority", "created_at"}},
	{"policy_networks", []string{"network_id", "cidr", "created_at"}},
	{"policy_layers", []string{
		"scope", "scope_ref", "filtering_profile_id", "safesearch_mode", "parental_policy_id",
		"security_policy_id", "service_blocking_ruleset_id", "blocking_response_mode",
		"custom_ipv4", "custom_ipv6", "fallback_strategy", "ecs_mode", "domain_routing_ruleset_id",
		"query_log_enabled", "statistics_enabled", "created_at", "updated_at",
	}},
}

// clientIdentifier/clientOverride/clientRecord/clientsSection mirror
// Python's own nested, re-keyed clients section shape.
type clientIdentifier struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}
type clientOverride struct {
	OverrideType string `json:"override_type"`
	Pattern      string `json:"pattern"`
}
type clientRecord struct {
	Name             string             `json:"name"`
	Description      string             `json:"description"`
	Enabled          bool               `json:"enabled"`
	Identifiers      []clientIdentifier `json:"identifiers"`
	GroupIDs         []string           `json:"group_ids"`
	DomainOverrides  []clientOverride   `json:"domain_overrides"`
}

// Sections is the full canonical shape of one generation's payload --
// every flat table's rows plus the nested clients section, keyed by
// table/section name exactly like Python's own `sections` dict.
type Sections map[string]json.RawMessage

func canonicalJSON(v any) (string, error) {
	// json.Marshal on a map does NOT sort keys by default in Go the way
	// Python's json.dumps(sort_keys=True) does -- but Sections here is
	// always built by inserting keys in flatTables' own fixed order plus
	// "clients" last, and Go's encoding/json DOES sort map[string]X keys
	// alphabetically when marshaling a map value, so this is already
	// deterministic without extra work. Verified directly, not assumed.
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ContentHash matches Python's own content_hash(): SHA-256 of the
// canonical (deterministic-key-order) JSON encoding.
func ContentHash(sections Sections) (string, error) {
	canon, err := canonicalJSON(sections)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:]), nil
}

func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var one int
	err := db.QueryRowContext(ctx, `SELECT 1 FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&one)
	return err == nil
}

// BuildPayload reads the live replicable subset of this node's own
// tables -- read-only, every column named explicitly (never SELECT *),
// matching Python's own build_payload() discipline exactly.
func BuildPayload(ctx context.Context, db *sql.DB) (Sections, error) {
	out := Sections{}
	for _, t := range flatTables {
		if !tableExists(ctx, db, t.name) {
			continue
		}
		rows, err := readFlatTable(ctx, db, t)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", t.name, err)
		}
		raw, err := json.Marshal(rows)
		if err != nil {
			return nil, err
		}
		out[t.name] = raw
	}
	clients, err := buildClientsSection(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("reading clients: %w", err)
	}
	raw, err := json.Marshal(clients)
	if err != nil {
		return nil, err
	}
	out["clients"] = raw
	return out, nil
}

func readFlatTable(ctx context.Context, db *sql.DB, t flatTable) ([]map[string]any, error) {
	colSQL := ""
	for i, c := range t.columns {
		if i > 0 {
			colSQL += ", "
		}
		colSQL += c
	}
	rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM %s", colSQL, t.name))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(t.columns))
		ptrs := make([]any, len(t.columns))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := map[string]any{}
		for i, c := range t.columns {
			row[c] = vals[i]
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func buildClientsSection(ctx context.Context, db *sql.DB) ([]clientRecord, error) {
	if !tableExists(ctx, db, "clients") {
		return []clientRecord{}, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT id, name, description, enabled FROM clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type rawClient struct {
		id          int64
		name        string
		description string
		enabled     bool
	}
	var raws []rawClient
	for rows.Next() {
		var c rawClient
		var enabledInt int
		if err := rows.Scan(&c.id, &c.name, &c.description, &enabledInt); err != nil {
			return nil, err
		}
		c.enabled = enabledInt != 0
		raws = append(raws, c)
	}
	rows.Close()

	out := make([]clientRecord, 0, len(raws))
	for _, c := range raws {
		rec := clientRecord{Name: c.name, Description: c.description, Enabled: c.enabled}

		idRows, err := db.QueryContext(ctx, `SELECT kind, value FROM client_identifiers WHERE client_id=? ORDER BY id`, c.id)
		if err != nil {
			return nil, err
		}
		for idRows.Next() {
			var ci clientIdentifier
			if err := idRows.Scan(&ci.Kind, &ci.Value); err != nil {
				idRows.Close()
				return nil, err
			}
			rec.Identifiers = append(rec.Identifiers, ci)
		}
		idRows.Close()

		if tableExists(ctx, db, "client_group_members") {
			grpRows, err := db.QueryContext(ctx, `
				SELECT cg.group_id FROM client_group_members cgm
				JOIN client_groups cg ON cg.id = cgm.group_id
				WHERE cgm.client_id=? ORDER BY cg.group_id`, c.id)
			if err != nil {
				return nil, err
			}
			for grpRows.Next() {
				var groupID string
				if err := grpRows.Scan(&groupID); err != nil {
					grpRows.Close()
					return nil, err
				}
				rec.GroupIDs = append(rec.GroupIDs, groupID)
			}
			grpRows.Close()
		}

		if tableExists(ctx, db, "client_domain_overrides") {
			ovRows, err := db.QueryContext(ctx, `SELECT override_type, pattern FROM client_domain_overrides WHERE client_id=? ORDER BY id`, c.id)
			if err != nil {
				return nil, err
			}
			for ovRows.Next() {
				var ov clientOverride
				if err := ovRows.Scan(&ov.OverrideType, &ov.Pattern); err != nil {
					ovRows.Close()
					return nil, err
				}
				rec.DomainOverrides = append(rec.DomainOverrides, ov)
			}
			ovRows.Close()
		}
		out = append(out, rec)
	}
	return out, nil
}

// ApplySections overwrites this node's own replicated tables with the
// generation's content, in one transaction -- matching Python's own
// _apply_sections() "fully primary-owned on a replica" v1 design. The
// caller (SyncOnce) is responsible for snapshotting first so a failed
// apply (or downstream deploy failure) can restore exactly this state.
func ApplySections(ctx context.Context, db *sql.DB, sections Sections) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, t := range flatTables {
		raw, ok := sections[t.name]
		if !ok || !tableExists(ctx, db, t.name) {
			continue
		}
		var rows []map[string]any
		if err := json.Unmarshal(raw, &rows); err != nil {
			return fmt.Errorf("decoding %s section: %w", t.name, err)
		}
		if err := replaceFlatTable(ctx, tx, t, rows); err != nil {
			return fmt.Errorf("applying %s: %w", t.name, err)
		}
	}

	if raw, ok := sections["clients"]; ok {
		var clients []clientRecord
		if err := json.Unmarshal(raw, &clients); err != nil {
			return fmt.Errorf("decoding clients section: %w", err)
		}
		if err := applyClientsSection(ctx, tx, clients); err != nil {
			return fmt.Errorf("applying clients: %w", err)
		}
	}

	return tx.Commit()
}

func replaceFlatTable(ctx context.Context, tx *sql.Tx, t flatTable, rows []map[string]any) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+t.name); err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	colSQL, placeholders := "", ""
	for i, c := range t.columns {
		if i > 0 {
			colSQL += ", "
			placeholders += ", "
		}
		colSQL += c
		placeholders += "?"
	}
	stmt := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", t.name, colSQL, placeholders)
	for _, row := range rows {
		args := make([]any, len(t.columns))
		for i, c := range t.columns {
			args[i] = row[c]
		}
		if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
			return err
		}
	}
	return nil
}

func applyClientsSection(ctx context.Context, tx *sql.Tx, clients []clientRecord) error {
	if !tableExistsTx(ctx, tx, "clients") {
		return nil
	}
	if tableExistsTx(ctx, tx, "client_domain_overrides") {
		if _, err := tx.ExecContext(ctx, "DELETE FROM client_domain_overrides"); err != nil {
			return err
		}
	}
	if tableExistsTx(ctx, tx, "client_group_members") {
		if _, err := tx.ExecContext(ctx, "DELETE FROM client_group_members"); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM client_identifiers"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM clients"); err != nil {
		return err
	}

	groupIDToRowID := map[string]int64{}
	if tableExistsTx(ctx, tx, "client_groups") {
		rows, err := tx.QueryContext(ctx, `SELECT id, group_id FROM client_groups`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var groupID string
			if err := rows.Scan(&id, &groupID); err != nil {
				rows.Close()
				return err
			}
			groupIDToRowID[groupID] = id
		}
		rows.Close()
	}

	ts := now()
	for _, c := range clients {
		if c.Name == "" {
			continue
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO clients (name, description, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
			c.Name, c.Description, boolToInt(c.Enabled), ts, ts)
		if err != nil {
			return err
		}
		clientRowID, _ := res.LastInsertId()

		for _, id := range c.Identifiers {
			if id.Kind == "" || id.Value == "" {
				continue
			}
			// INSERT OR IGNORE: client_identifiers.(kind,value) is
			// globally UNIQUE -- a payload that (incorrectly) assigns
			// the same identifier to two clients must not abort the
			// whole apply, matching this package's "never partially
			// fail a large apply over one bad row" standard.
			tx.ExecContext(ctx, `INSERT OR IGNORE INTO client_identifiers (client_id, kind, value, created_at) VALUES (?, ?, ?, ?)`,
				clientRowID, id.Kind, id.Value, ts)
		}
		if tableExistsTx(ctx, tx, "client_group_members") {
			for _, groupID := range c.GroupIDs {
				if rowID, ok := groupIDToRowID[groupID]; ok {
					tx.ExecContext(ctx, `INSERT OR IGNORE INTO client_group_members (group_id, client_id) VALUES (?, ?)`, rowID, clientRowID)
				}
			}
		}
		if tableExistsTx(ctx, tx, "client_domain_overrides") {
			for _, ov := range c.DomainOverrides {
				if ov.OverrideType == "" || ov.Pattern == "" {
					continue
				}
				tx.ExecContext(ctx, `INSERT INTO client_domain_overrides (client_id, override_type, pattern, created_at) VALUES (?, ?, ?, ?)`,
					clientRowID, ov.OverrideType, ov.Pattern, ts)
			}
		}
	}
	return nil
}

func tableExistsTx(ctx context.Context, tx *sql.Tx, name string) bool {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&one)
	return err == nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// sectionKeys returns the sorted list of section names present, for the
// generation's own quick-preview column (no need to parse the full
// payload just to show "what's in generation #5" in the UI).
func sectionKeys(sections Sections) []string {
	keys := make([]string, 0, len(sections))
	for k := range sections {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
