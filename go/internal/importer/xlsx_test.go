package importer

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildRealXLSXFixture generates a real .xlsx file using the actual
// `openpyxl` library (the same library V1.1.1's own parse_xlsx_bytes()
// reads with) via a small Python one-liner -- proving this Go reader
// against real Excel-compatible output, not a hand-built zip.
func buildRealXLSXFixture(t *testing.T, rows [][]string) []byte {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available for building a real .xlsx fixture")
	}
	path := filepath.Join(t.TempDir(), "fixture.xlsx")
	script := `
import sys, openpyxl
wb = openpyxl.Workbook()
ws = wb.active
import json
rows = json.loads(sys.argv[2])
for row in rows:
    ws.append(row)
wb.save(sys.argv[1])
`
	rowsJSON, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", script, path, string(rowsJSON))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building real xlsx fixture: %v: %s", err, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseXLSXRowsReadsARealOpenpyxlWorkbook(t *testing.T) {
	data := buildRealXLSXFixture(t, [][]string{
		{"name", "record_type", "value", "ttl"},
		{"printer.lan", "A", "10.0.0.50", "300"},
		{"nas.lan", "A", "10.0.0.60", "600"},
	})
	rows, err := ParseXLSXRows(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows (1 header + 2 data), got %d: %+v", len(rows), rows)
	}
	if rows[0][0] != "name" || rows[0][1] != "record_type" {
		t.Fatalf("expected header row to round-trip, got %+v", rows[0])
	}
	if rows[1][0] != "printer.lan" || rows[1][1] != "A" || rows[1][2] != "10.0.0.50" {
		t.Fatalf("expected row 1 to round-trip, got %+v", rows[1])
	}
	if rows[2][0] != "nas.lan" {
		t.Fatalf("expected row 2 to round-trip, got %+v", rows[2])
	}
}

func TestParseXLSXPlanEndToEndFromARealWorkbook(t *testing.T) {
	data := buildRealXLSXFixture(t, [][]string{
		{"name", "record_type", "value", "ttl"},
		{"printer.lan", "A", "10.0.0.50", "300"},
	})
	plan := parseXLSXPlan(data)
	if plan.SourceType != "xlsx" {
		t.Fatalf("expected source_type=xlsx, got %q", plan.SourceType)
	}
	if len(plan.Rows) != 1 {
		t.Fatalf("expected 1 real row, got %+v", plan.Rows)
	}
	if plan.Rows[0].Name != "printer.lan" || plan.Rows[0].RecordType != "A" || plan.Rows[0].Value != "10.0.0.50" || plan.Rows[0].TTL != 300 {
		t.Fatalf("expected the row to parse correctly, got %+v", plan.Rows[0])
	}
}

func TestParseXLSXRowsOfInvalidFileFails(t *testing.T) {
	if _, err := ParseXLSXRows([]byte("not a real xlsx file")); err == nil {
		t.Fatal("expected an error for a non-zip file")
	}
}

func TestParseToPlanXLSXDecodesBase64(t *testing.T) {
	data := buildRealXLSXFixture(t, [][]string{
		{"name", "record_type", "value", "ttl"},
		{"printer.lan", "A", "10.0.0.50", "300"},
	})
	plan, err := ParseToPlan("xlsx", base64.StdEncoding.EncodeToString(data), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rows) != 1 {
		t.Fatalf("expected 1 row, got %+v", plan.Rows)
	}
}
