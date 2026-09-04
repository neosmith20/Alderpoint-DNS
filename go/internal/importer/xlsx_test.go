package importer

import (
	"encoding/base64"
	"os"
	"testing"
)

// singleRowXLSXFixture is the same kind of checked-in real-openpyxl
// fixture as realXLSXFixture above, one data row only (see
// testdata/single_row_fixture.xlsx's own generation).
func singleRowXLSXFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/single_row_fixture.xlsx")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// realXLSXFixture returns a real .xlsx file's bytes -- generated once
// with the actual `openpyxl` library (the same library V1.1.1's own
// parse_xlsx_bytes() reads with; see testdata/fixture.xlsx's own
// generation, recorded in this repo's history) and checked in as a
// static fixture, proving this Go reader against real Excel-compatible
// output, not a hand-built zip -- without requiring python3/openpyxl to
// actually be installed to run `go test` (see the 2026-09-04 zero-Python
// audit: V2 must have no Python-based test requirements; a one-time,
// checked-in fixture keeps the real-openpyxl proof without a runtime
// Python dependency).
func realXLSXFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/fixture.xlsx")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseXLSXRowsReadsARealOpenpyxlWorkbook(t *testing.T) {
	data := realXLSXFixture(t)
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
	data := singleRowXLSXFixture(t)
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
	data := singleRowXLSXFixture(t)
	plan, err := ParseToPlan("xlsx", base64.StdEncoding.EncodeToString(data), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rows) != 1 {
		t.Fatalf("expected 1 row, got %+v", plan.Rows)
	}
}
