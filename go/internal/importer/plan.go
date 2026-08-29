// This file adds the real staged preview -> apply workflow this
// package previously lacked (a one-shot, no-preview apply for hosts
// files only) -- matching the SHAPE of Python's own real
// app/v2/import_migration.py job model (read directly, not guessed):
// parse -> plan (every row classified, conflicts against existing data
// surfaced explicitly, never silently overwritten) -> create job ->
// apply (with per-row skip selection) -> real result counts, with a
// real pre-apply snapshot so a bad apply can be rolled back the exact
// same way Backup & Restore already does (internal/backup, real,
// tested, transactional).
//
// Three source types are implemented, disclosed rather than hidden:
// hosts-file, a simple Alderpoint-native CSV (name,record_type,value,
// ttl), and a real BIND zone-file parser (a practical subset -- see
// ImportZone's own doc comment). Python's other three source types
// (AdGuard Home YAML/live API, Pi-hole paste, XLSX) are real,
// substantial format-specific parsers each -- not attempted in this
// pass; SourceTypes lists only what's real here.
package importer

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/localdns"
)

// SourceTypes is the real, current allowlist -- an unsupported value is
// rejected before any parsing is attempted, matching Python's own
// "source_type not in SOURCE_TYPES" check.
var SourceTypes = map[string]bool{"hosts": true, "csv": true, "zone": true}

type PlanRow struct {
	Index          int    `json:"index"`
	Name           string `json:"name"`
	RecordType     string `json:"record_type"`
	Value          string `json:"value"`
	TTL            int    `json:"ttl"`
	Conflict       bool   `json:"conflict"`
	ConflictDetail string `json:"conflict_detail,omitempty"`
}

type Plan struct {
	SourceType  string    `json:"source_type"`
	SourceName  string    `json:"source_name"`
	Rows        []PlanRow `json:"rows"`
	ParseErrors []string  `json:"parse_errors"`
}

type Job struct {
	ID               int64   `json:"id"`
	SourceType       string  `json:"source_type"`
	SourceName       string  `json:"source_name"`
	Plan             Plan    `json:"plan"`
	Status           string  `json:"status"`
	Result           *Result `json:"result,omitempty"`
	SnapshotFilename *string `json:"snapshot_filename,omitempty"`
	CreatedAt        string  `json:"created_at"`
	AppliedAt        *string `json:"applied_at,omitempty"`
}

type Service struct {
	DB       *sql.DB
	LocalDNS *localdns.Service
	Backup   *backup.Service
}

// ParseToPlan runs the real format-specific parser for sourceType and
// returns an unconflicted plan (every row Index-ordered, real
// parse-time errors collected rather than aborting the whole import on
// one bad line, matching hosts.go's own already-proven policy).
func ParseToPlan(sourceType, text string, defaultDomain string) (Plan, error) {
	if !SourceTypes[sourceType] {
		return Plan{}, fmt.Errorf("unsupported source_type: %q", sourceType)
	}
	switch sourceType {
	case "hosts":
		return parseHostsPlan(text), nil
	case "csv":
		return parseCSVPlan(text), nil
	case "zone":
		if strings.TrimSpace(defaultDomain) == "" {
			return Plan{}, fmt.Errorf("default_domain is required for a zone-file import (used as $ORIGIN and to qualify relative names)")
		}
		return parseZonePlan(text, defaultDomain), nil
	default:
		return Plan{}, fmt.Errorf("unsupported source_type: %q", sourceType)
	}
}

// parseZonePlan reuses ImportZone's own line parser to build plan rows
// instead of writing directly to internal/localdns -- see ImportZone's
// doc comment for the exact supported subset ($ORIGIN honored, SOA/NS/
// MX/multi-line records skipped not fatal).
func parseZonePlan(text, defaultDomain string) Plan {
	plan := Plan{SourceType: "zone", ParseErrors: []string{}}
	origin := normalizeZoneDomain(defaultDomain)
	idx := 0
	for _, raw := range strings.Split(text, "\n") {
		line := raw
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimRight(line, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(trimmed), "$ORIGIN") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				origin = normalizeZoneDomain(strings.TrimSuffix(fields[1], "."))
			}
			continue
		}
		if strings.HasPrefix(trimmed, "$") {
			continue
		}
		m := zoneLineRE.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		name, ttlStr, recordType, data := m[1], m[2], strings.ToUpper(m[3]), strings.TrimSuffix(m[4], ".")
		var fqdn string
		if name == "@" || name == "" {
			fqdn = origin
		} else {
			fqdn = normalizeFQDN(name, origin)
		}
		ttl := zoneImportDefaultTTL
		if ttlStr != "" {
			if v, err := strconv.Atoi(ttlStr); err == nil {
				ttl = v
			}
		}
		plan.Rows = append(plan.Rows, PlanRow{Index: idx, Name: fqdn, RecordType: recordType, Value: data, TTL: ttl})
		idx++
	}
	return plan
}

func parseHostsPlan(text string) Plan {
	plan := Plan{SourceType: "hosts", ParseErrors: []string{}}
	idx := 0
	for lineNo, raw := range strings.Split(text, "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			plan.ParseErrors = append(plan.ParseErrors, fmt.Sprintf("line %d: invalid IP %q", lineNo+1, fields[0]))
			continue
		}
		rtype := "A"
		if ip.To4() == nil {
			rtype = "AAAA"
		}
		for _, host := range fields[1:] {
			plan.Rows = append(plan.Rows, PlanRow{Index: idx, Name: strings.ToLower(host), RecordType: rtype, Value: ip.String(), TTL: hostsImportTTL})
			idx++
		}
	}
	return plan
}

// parseCSVPlan reads a simple Alderpoint-native CSV:
// name,record_type,value,ttl (a header row is accepted and skipped if
// its first cell case-insensitively reads "name").
func parseCSVPlan(text string) Plan {
	plan := Plan{SourceType: "csv", ParseErrors: []string{}}
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		plan.ParseErrors = append(plan.ParseErrors, fmt.Sprintf("CSV parse error: %v", err))
		return plan
	}
	idx := 0
	for lineNo, row := range rows {
		if len(row) == 0 || strings.TrimSpace(row[0]) == "" {
			continue
		}
		if lineNo == 0 && strings.EqualFold(strings.TrimSpace(row[0]), "name") {
			continue // header row
		}
		if len(row) < 3 {
			plan.ParseErrors = append(plan.ParseErrors, fmt.Sprintf("row %d: expected at least name,record_type,value", lineNo+1))
			continue
		}
		name := strings.ToLower(strings.TrimSpace(row[0]))
		rtype := strings.ToUpper(strings.TrimSpace(row[1]))
		value := strings.TrimSpace(row[2])
		ttl := hostsImportTTL
		if len(row) >= 4 && strings.TrimSpace(row[3]) != "" {
			n, err := strconv.Atoi(strings.TrimSpace(row[3]))
			if err != nil {
				plan.ParseErrors = append(plan.ParseErrors, fmt.Sprintf("row %d: invalid ttl %q", lineNo+1, row[3]))
				continue
			}
			ttl = n
		}
		if name == "" || value == "" {
			plan.ParseErrors = append(plan.ParseErrors, fmt.Sprintf("row %d: name and value are required", lineNo+1))
			continue
		}
		plan.Rows = append(plan.Rows, PlanRow{Index: idx, Name: name, RecordType: rtype, Value: value, TTL: ttl})
		idx++
	}
	return plan
}

// annotateConflicts marks every plan row that already exists in
// local_dns_records (same name+record_type+value, matching
// internal/localdns's own uniqueness constraint) -- surfaced to the
// operator, never silently skipped or silently overwritten, matching
// Python's own "conflicts/warnings surfaced explicitly" contract.
func (s *Service) annotateConflicts(ctx context.Context, plan *Plan) error {
	existing, err := s.LocalDNS.List(ctx)
	if err != nil {
		return err
	}
	type key struct{ name, rtype, value string }
	existingSet := map[key]bool{}
	for _, r := range existing {
		existingSet[key{r.Name, r.RecordType, r.Value}] = true
	}
	for i, row := range plan.Rows {
		if existingSet[key{row.Name, row.RecordType, row.Value}] {
			plan.Rows[i].Conflict = true
			plan.Rows[i].ConflictDetail = "an identical Local DNS record already exists"
		}
	}
	return nil
}

// CreateJob parses (or accepts an already-parsed) plan, annotates
// conflicts against the CURRENT local_dns_records, and stores it --
// nothing is written to local_dns_records itself yet.
func (s *Service) CreateJob(ctx context.Context, sourceType, sourceName, text, defaultDomain string) (*Job, error) {
	plan, err := ParseToPlan(sourceType, text, defaultDomain)
	if err != nil {
		return nil, err
	}
	plan.SourceName = sourceName
	if err := s.annotateConflicts(ctx, &plan); err != nil {
		return nil, err
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.DB.ExecContext(ctx, `INSERT INTO import_jobs(source_type, source_name, plan_json, status, created_at) VALUES(?,?,?,'pending',?)`,
		sourceType, sourceName, string(planJSON), now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Job{ID: id, SourceType: sourceType, SourceName: sourceName, Plan: plan, Status: "pending", CreatedAt: now}, nil
}

func (s *Service) ListJobs(ctx context.Context) ([]Job, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, source_type, source_name, plan_json, status, result_json, snapshot_filename, created_at, applied_at FROM import_jobs ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

type ErrNotFound struct{ ID int64 }

func (e ErrNotFound) Error() string { return fmt.Sprintf("unknown import job %d", e.ID) }

func (s *Service) GetJob(ctx context.Context, id int64) (*Job, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id, source_type, source_name, plan_json, status, result_json, snapshot_filename, created_at, applied_at FROM import_jobs WHERE id=?`, id)
	j, err := scanJob(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound{ID: id}
	}
	return j, err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanJob(row scanner) (*Job, error) {
	var j Job
	var planJSON string
	var resultJSON, snapshotFilename, appliedAt sql.NullString
	if err := row.Scan(&j.ID, &j.SourceType, &j.SourceName, &planJSON, &j.Status, &resultJSON, &snapshotFilename, &j.CreatedAt, &appliedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(planJSON), &j.Plan); err != nil {
		return nil, err
	}
	if resultJSON.Valid {
		var res Result
		if err := json.Unmarshal([]byte(resultJSON.String), &res); err == nil {
			j.Result = &res
		}
	}
	if snapshotFilename.Valid {
		j.SnapshotFilename = &snapshotFilename.String
	}
	if appliedAt.Valid {
		j.AppliedAt = &appliedAt.String
	}
	return &j, nil
}

// ApplyJob is idempotent (matching Python's own contract: re-applying
// an already-applied job re-runs the same create-or-skip-existing
// logic rather than erroring) and takes a real pre-apply snapshot
// (internal/backup's own real, tested VACUUM INTO mechanism -- the
// exact same one Backup & Restore and internal/pymigrate already use)
// so a bad apply has a real, proven rollback path, not just a promise.
func (s *Service) ApplyJob(ctx context.Context, id int64, skipIndexes []int) (*Job, error) {
	job, err := s.GetJob(ctx, id)
	if err != nil {
		return nil, err
	}
	skip := map[int]bool{}
	for _, i := range skipIndexes {
		skip[i] = true
	}

	var snapshotFilename string
	if s.Backup != nil {
		snap, err := s.Backup.Create(ctx, fmt.Sprintf("pre-import-job-%d", id))
		if err != nil {
			return nil, fmt.Errorf("pre-apply snapshot failed, nothing imported: %w", err)
		}
		snapshotFilename = snap.Filename
	}

	res := Result{Errors: []string{}}
	for _, row := range job.Plan.Rows {
		if skip[row.Index] {
			res.Skipped++
			continue
		}
		_, err := s.LocalDNS.Create(ctx, localdns.CreateInput{Name: row.Name, RecordType: row.RecordType, Value: row.Value, TTL: row.TTL, Enabled: true})
		if err == localdns.ErrDuplicate {
			res.Skipped++
		} else if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("row %d (%s): %v", row.Index, row.Name, err))
		} else {
			res.Imported++
		}
	}

	resultJSON, _ := json.Marshal(res)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.DB.ExecContext(ctx, `UPDATE import_jobs SET status='applied', result_json=?, snapshot_filename=?, applied_at=? WHERE id=?`,
		string(resultJSON), snapshotFilename, now, id); err != nil {
		return nil, err
	}
	job.Status = "applied"
	job.Result = &res
	job.AppliedAt = &now
	if snapshotFilename != "" {
		job.SnapshotFilename = &snapshotFilename
	}
	return job, nil
}

// Rollback restores this control plane's state from the real
// pre-apply snapshot ApplyJob took -- the same real, tested,
// transactional restore path (mandatory safety-backup-before-restore
// included) Backup & Restore and internal/pymigrate already use.
func (s *Service) Rollback(ctx context.Context, id int64) (backup.BackupInfo, error) {
	job, err := s.GetJob(ctx, id)
	if err != nil {
		return backup.BackupInfo{}, err
	}
	if job.SnapshotFilename == nil || *job.SnapshotFilename == "" {
		return backup.BackupInfo{}, fmt.Errorf("import job %d has no snapshot to roll back to (not yet applied, or no backup service configured at apply time)", id)
	}
	if s.Backup == nil {
		return backup.BackupInfo{}, fmt.Errorf("no backup service configured")
	}
	return s.Backup.Restore(ctx, *job.SnapshotFilename, nil)
}
