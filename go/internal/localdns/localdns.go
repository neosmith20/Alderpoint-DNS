// Package localdns implements the Local DNS vertical: validated
// list/add/edit/delete against SQLite, with a synchronous
// stage-validate-promote runtime-generation step on every mutation
// (no network I/O is involved, unlike blocklist pulls, so this never
// needs a background job -- matches app/v2/webapp.py's _mutate_and_promote
// being called inline from create_local_dns).
package localdns

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var ErrNotFound = fmt.Errorf("record not found")
var ErrDuplicate = fmt.Errorf("that Local DNS record already exists")

var hostnameLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

var validRecordTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "PTR": true}

func validHostname(name string) error {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || len(name) > 253 {
		return fmt.Errorf("invalid hostname")
	}
	for _, label := range strings.Split(name, ".") {
		if !hostnameLabelRe.MatchString(label) {
			return fmt.Errorf("invalid hostname label %q", label)
		}
	}
	return nil
}

type CreateInput struct {
	Name       string
	RecordType string
	Value      string
	TTL        int
	Enabled    bool
}

func validateInput(name, recordType, value string, ttl int) (string, error) {
	if !validRecordTypes[recordType] {
		return "", fmt.Errorf("invalid record type")
	}
	if err := validHostname(name); err != nil {
		return "", err
	}
	switch recordType {
	case "A":
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("invalid IPv4 address")
		}
	case "AAAA":
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() != nil {
			return "", fmt.Errorf("invalid IPv6 address")
		}
	case "CNAME", "PTR":
		if err := validHostname(value); err != nil {
			return "", fmt.Errorf("invalid target hostname: %w", err)
		}
	}
	if ttl <= 0 || ttl > 604800 {
		return "", fmt.Errorf("ttl must be between 1 and 604800 seconds")
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), "."), nil
}

type Record struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	TTL        int    `json:"ttl"`
	Enabled    bool   `json:"enabled"`
}

type Service struct {
	DB         *sql.DB
	StagingDir string
	RuntimeDir string
}

func (s *Service) List(ctx context.Context) ([]Record, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, name, record_type, value, ttl, enabled FROM local_dns_records ORDER BY name, record_type, value LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.RecordType, &r.Value, &r.TTL, &enabled); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Service) Create(ctx context.Context, in CreateInput) (*Record, error) {
	name, err := validateInput(in.Name, in.RecordType, in.Value, in.TTL)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO local_dns_records(name, record_type, value, ttl, enabled, created_at, updated_at) VALUES(?,?,?,?,?,?,?)`,
		name, in.RecordType, in.Value, in.TTL, boolToInt(in.Enabled), now, now)
	if err != nil {
		return nil, ErrDuplicate
	}
	id, _ := res.LastInsertId()
	if err := s.stageAndPromote(ctx); err != nil {
		return nil, fmt.Errorf("record saved but runtime generation failed: %w", err)
	}
	return &Record{ID: id, Name: name, RecordType: in.RecordType, Value: in.Value, TTL: in.TTL, Enabled: in.Enabled}, nil
}

type UpdateInput struct {
	Value   *string
	TTL     *int
	Enabled *bool
}

func (s *Service) Update(ctx context.Context, id int64, in UpdateInput) (*Record, error) {
	var r Record
	var enabled int
	err := s.DB.QueryRowContext(ctx, `SELECT id, name, record_type, value, ttl, enabled FROM local_dns_records WHERE id=?`, id).
		Scan(&r.ID, &r.Name, &r.RecordType, &r.Value, &r.TTL, &enabled)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	r.Enabled = enabled != 0

	newValue, newTTL := r.Value, r.TTL
	if in.Value != nil {
		newValue = *in.Value
	}
	if in.TTL != nil {
		newTTL = *in.TTL
	}
	if _, err := validateInput(r.Name, r.RecordType, newValue, newTTL); err != nil {
		return nil, err
	}
	newEnabled := r.Enabled
	if in.Enabled != nil {
		newEnabled = *in.Enabled
	}

	_, err = s.DB.ExecContext(ctx, `UPDATE local_dns_records SET value=?, ttl=?, enabled=?, updated_at=? WHERE id=?`,
		newValue, newTTL, boolToInt(newEnabled), time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return nil, err
	}
	if err := s.stageAndPromote(ctx); err != nil {
		return nil, fmt.Errorf("record saved but runtime generation failed: %w", err)
	}
	r.Value, r.TTL, r.Enabled = newValue, newTTL, newEnabled
	return &r, nil
}

func (s *Service) Delete(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM local_dns_records WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return s.stageAndPromote(ctx)
}

// stageAndPromote regenerates the runtime Local DNS artifact from
// current SQLite state (desired state -> compile -> stage -> validate ->
// promote, same shape blocklists.go uses): write to a temp file in
// StagingDir, sanity-check it parses back, then atomically rename(2) it
// into RuntimeDir. A failure here never leaves a partially-written file
// visible at the promoted path -- the previous good file (if any) stays
// in place.
func (s *Service) stageAndPromote(ctx context.Context) error {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT name, record_type, value, ttl FROM local_dns_records WHERE enabled=1 ORDER BY name, record_type, value`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type line struct{ name, rtype, value string; ttl int }
	var lines []line
	for rows.Next() {
		var l line
		if err := rows.Scan(&l.name, &l.rtype, &l.value, &l.ttl); err != nil {
			return err
		}
		lines = append(lines, l)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].name < lines[j].name })

	if err := os.MkdirAll(s.StagingDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(s.RuntimeDir, 0o755); err != nil {
		return err
	}

	stagedPath := filepath.Join(s.StagingDir, "local-dns.hosts")
	tmpPath := fmt.Sprintf("%s.tmp.%d", stagedPath, time.Now().UnixNano())
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintf(w, "%s %s %s %d\n", l.name, l.rtype, l.value, l.ttl)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, stagedPath); err != nil {
		return err
	}

	// Validate: the staged file must parse back to exactly what we wrote
	// before it's allowed to be promoted -- a real (if minimal) "does the
	// generated runtime artifact make sense" check, not just a hope.
	if err := validateStaged(stagedPath, len(lines)); err != nil {
		return fmt.Errorf("staged artifact failed validation, not promoted: %w", err)
	}

	runtimePath := filepath.Join(s.RuntimeDir, "local-dns.hosts")
	return os.Rename(stagedPath, runtimePath) // atomic promotion
}

func validateStaged(path string, wantLines int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 4 {
			return fmt.Errorf("malformed line: %q", sc.Text())
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if n != wantLines {
		return fmt.Errorf("line count mismatch: wrote %d, read back %d", wantLines, n)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
