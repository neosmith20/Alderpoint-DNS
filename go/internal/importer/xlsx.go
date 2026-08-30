// Minimal OOXML (.xlsx) spreadsheet reader -- just enough to read the
// first worksheet's cell grid as string rows, matching V1.1.1's own
// app/importer.py:parse_xlsx_bytes() exactly in shape: read the first
// sheet, first row is headers, every other row becomes a string map.
// No external dependency: an .xlsx is a zip of XML files
// (archive/zip + encoding/xml, both stdlib) -- this reads
// xl/sharedStrings.xml (for shared-string cells) and the first sheet
// under xl/worksheets/, which is enough for the simple tabular exports
// this feature actually needs to support (a header row plus data rows,
// no formulas, no merged cells).
package importer

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type xlsxSharedStrings struct {
	XMLName xml.Name `xml:"sst"`
	SI      []struct {
		T string `xml:"t"`
		R []struct {
			T string `xml:"t"`
		} `xml:"r"`
	} `xml:"si"`
}

func (s xlsxSharedStrings) text(i int) string {
	if i < 0 || i >= len(s.SI) {
		return ""
	}
	entry := s.SI[i]
	if entry.T != "" || len(entry.R) == 0 {
		return entry.T
	}
	// Rich text (<r><t>...</t></r> runs) -- concatenate the runs.
	var b strings.Builder
	for _, r := range entry.R {
		b.WriteString(r.T)
	}
	return b.String()
}

type xlsxSheetData struct {
	XMLName xml.Name `xml:"worksheet"`
	Sheet   struct {
		Rows []struct {
			Cells []struct {
				R  string `xml:"r,attr"` // cell reference, e.g. "B3"
				T  string `xml:"t,attr"` // type: "s" (shared string), "inlineStr", or numeric (empty)
				V  string `xml:"v"`
				Is struct {
					T string `xml:"t"`
				} `xml:"is"`
			} `xml:"c"`
		} `xml:"row"`
	} `xml:"sheetData"`
}

var cellColRE = regexp.MustCompile(`^([A-Z]+)(\d+)$`)

// colIndex converts a spreadsheet column letter ("A", "B", ..., "AA") to
// a zero-based index.
func colIndex(letters string) int {
	idx := 0
	for _, c := range letters {
		idx = idx*26 + int(c-'A'+1)
	}
	return idx - 1
}

// ParseXLSXRows reads the first worksheet of a real .xlsx file into a
// row-major grid of plain strings, one string per cell, gaps between
// used columns filled with "" -- the same shape encoding/csv's
// Reader.ReadAll returns, so it can be fed into exactly the same
// downstream row-parsing logic as the native CSV source type.
func ParseXLSXRows(data []byte) ([][]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a valid .xlsx (zip) file: %w", err)
	}

	var shared xlsxSharedStrings
	if f := findZipFile(zr, "xl/sharedStrings.xml"); f != nil {
		if err := readZipXML(f, &shared); err != nil {
			return nil, fmt.Errorf("reading xl/sharedStrings.xml: %w", err)
		}
	}

	sheetFile := findFirstSheet(zr)
	if sheetFile == nil {
		return nil, fmt.Errorf("no worksheet found under xl/worksheets/")
	}
	var sheet xlsxSheetData
	if err := readZipXML(sheetFile, &sheet); err != nil {
		return nil, fmt.Errorf("reading worksheet: %w", err)
	}

	var out [][]string
	for _, row := range sheet.Sheet.Rows {
		maxCol := -1
		cellValues := map[int]string{}
		for _, c := range row.Cells {
			col := 0
			if m := cellColRE.FindStringSubmatch(c.R); m != nil {
				col = colIndex(m[1])
			}
			var val string
			switch c.T {
			case "s":
				if n, err := strconv.Atoi(strings.TrimSpace(c.V)); err == nil {
					val = shared.text(n)
				}
			case "inlineStr":
				val = c.Is.T
			default:
				val = c.V
			}
			cellValues[col] = val
			if col > maxCol {
				maxCol = col
			}
		}
		rowOut := make([]string, maxCol+1)
		for col, val := range cellValues {
			rowOut[col] = val
		}
		out = append(out, rowOut)
	}
	return out, nil
}

func findZipFile(zr *zip.Reader, name string) *zip.File {
	for _, f := range zr.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// findFirstSheet picks the lowest-numbered xl/worksheets/sheetN.xml --
// sufficient for the simple, single-sheet exports this feature targets;
// a workbook.xml.rels-based sheet-order resolution is not implemented,
// disclosed rather than silently assumed equivalent for a multi-sheet
// workbook where sheet order and file-name order diverge.
func findFirstSheet(zr *zip.Reader) *zip.File {
	var candidates []*zip.File
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "xl/worksheets/sheet") && strings.HasSuffix(f.Name, ".xml") {
			candidates = append(candidates, f)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	return candidates[0]
}

func readZipXML(f *zip.File, v any) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	return xml.Unmarshal(data, v)
}
