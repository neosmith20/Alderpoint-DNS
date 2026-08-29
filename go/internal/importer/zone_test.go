package importer

import (
	"context"
	"testing"

	"alderpointdns/go-controlplane/internal/localdns"
)

func TestImportZoneBasicFile(t *testing.T) {
	svc := newTestLocalDNS(t)
	text := "www     IN A     10.0.0.5\nmail 600 IN A 10.0.0.6\n@   IN A     10.0.0.1\nftp     CNAME www.example.com.\n"
	res, err := ImportZone(context.Background(), svc, text, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 4 || res.Skipped != 0 {
		t.Fatalf("expected 4 imported, 0 skipped, got %+v", res)
	}
	records, err := svc.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]localdns.Record{}
	for _, r := range records {
		byName[r.Name] = r
	}
	if r := byName["www.example.com"]; r.RecordType != "A" || r.Value != "10.0.0.5" || r.TTL != 300 {
		t.Fatalf("expected www.example.com -> A 10.0.0.5 ttl=300, got %+v", r)
	}
	if r := byName["mail.example.com"]; r.TTL != 600 {
		t.Fatalf("expected mail.example.com's explicit TTL 600 to be honored, got %+v", r)
	}
	if r := byName["example.com"]; r.RecordType != "A" || r.Value != "10.0.0.1" {
		t.Fatalf("expected @ to resolve to the bare origin, got %+v", r)
	}
	if r := byName["ftp.example.com"]; r.RecordType != "CNAME" || r.Value != "www.example.com" {
		t.Fatalf("expected an absolute (trailing-dot) CNAME target to be used verbatim, got %+v", r)
	}
}

func TestImportZoneHonorsOriginDirective(t *testing.T) {
	svc := newTestLocalDNS(t)
	text := "$ORIGIN other.example.\nhost IN A 10.1.1.1\n"
	res, err := ImportZone(context.Background(), svc, text, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 1 {
		t.Fatalf("expected 1 imported, got %+v", res)
	}
	records, _ := svc.List(context.Background())
	if len(records) != 1 || records[0].Name != "host.other.example" {
		t.Fatalf("expected $ORIGIN to change the qualifying domain, got %+v", records)
	}
}

func TestImportZoneSkipsUnsupportedRecordTypesWithoutAborting(t *testing.T) {
	svc := newTestLocalDNS(t)
	text := "@ IN SOA ns1.example.com. admin.example.com. ( 1 3600 900 604800 86400 )\n@ IN NS ns1.example.com.\ngood IN A 10.0.0.9\n"
	res, err := ImportZone(context.Background(), svc, text, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 1 {
		t.Fatalf("expected only the A record to import (SOA/NS lines skipped, not fatal), got %+v", res)
	}
}

func TestImportZoneCommentsAndBlankLinesIgnored(t *testing.T) {
	svc := newTestLocalDNS(t)
	text := "; a full-line comment\n\ngood IN A 10.0.0.9 ; trailing comment\n"
	res, err := ImportZone(context.Background(), svc, text, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 1 {
		t.Fatalf("expected 1 imported despite comments/blank lines, got %+v", res)
	}
}

func TestImportZoneEmptyTextImportsNothing(t *testing.T) {
	svc := newTestLocalDNS(t)
	res, err := ImportZone(context.Background(), svc, "", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 0 || res.Skipped != 0 {
		t.Fatalf("expected nothing imported for empty text, got %+v", res)
	}
	if res.Errors == nil {
		t.Fatal("expected Errors to be an empty slice, not nil")
	}
}
