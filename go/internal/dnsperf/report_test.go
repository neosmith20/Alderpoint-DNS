package dnsperf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type fakeQuerier struct {
	calls int32
	delay time.Duration
}

func (f *fakeQuerier) Query(ctx context.Context, c BenchmarkCase) []Sample {
	atomic.AddInt32(&f.calls, 1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	n := c.Queries
	if n < 1 {
		n = 1
	}
	rc := 0
	samples := make([]Sample, n)
	for i := range samples {
		samples[i] = Sample{OK: true, LatencyMs: 1.5, RCode: &rc}
	}
	return samples
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition never became true")
}

func TestServiceStartRunsAndSavesReport(t *testing.T) {
	dir := t.TempDir()
	fq := &fakeQuerier{}
	svc := &Service{
		ReportPath: filepath.Join(dir, "latest-report.json"),
		Querier:    fq,
		BuildCases: func(ctx context.Context) ([]BenchmarkCase, []string, error) {
			return []BenchmarkCase{{Name: "case-a", Server: "127.0.0.1", Port: 1, Domain: "example.com.", Queries: 3, Timeout: time.Second}}, []string{"note"}, nil
		},
	}
	if ok := svc.Start(context.Background()); !ok {
		t.Fatal("expected Start to accept the first run")
	}
	waitFor(t, 2*time.Second, func() bool { running, _ := svc.Status(); return !running })

	report, err := svc.Read()
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if report == nil || len(report.Cases) != 1 || report.Cases[0].Name != "case-a" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Cases[0].Summary.Count != 3 {
		t.Fatalf("expected 3 samples recorded, got %+v", report.Cases[0].Summary)
	}
	if atomic.LoadInt32(&fq.calls) != 1 {
		t.Fatalf("expected exactly one Query call for the one case, got %d", fq.calls)
	}
}

func TestServiceStartRejectsSecondRunWhileInFlight(t *testing.T) {
	dir := t.TempDir()
	fq := &fakeQuerier{delay: 200 * time.Millisecond}
	svc := &Service{
		ReportPath: filepath.Join(dir, "latest-report.json"),
		Querier:    fq,
		BuildCases: func(ctx context.Context) ([]BenchmarkCase, []string, error) {
			return []BenchmarkCase{{Name: "slow", Server: "127.0.0.1", Port: 1, Domain: "example.com.", Queries: 1, Timeout: time.Second}}, nil, nil
		},
	}
	if ok := svc.Start(context.Background()); !ok {
		t.Fatal("expected first Start to be accepted")
	}
	if ok := svc.Start(context.Background()); ok {
		t.Fatal("expected second concurrent Start to be rejected (matches Python's already_running)")
	}
	waitFor(t, 2*time.Second, func() bool { running, _ := svc.Status(); return !running })
}

func TestServiceStartRecordsBuildCasesFailureHonestly(t *testing.T) {
	dir := t.TempDir()
	svc := &Service{
		ReportPath: filepath.Join(dir, "latest-report.json"),
		Querier:    &fakeQuerier{},
		BuildCases: func(ctx context.Context) ([]BenchmarkCase, []string, error) {
			return nil, nil, errors.New("boom: no local DNS record configured")
		},
	}
	svc.Start(context.Background())
	waitFor(t, 2*time.Second, func() bool { running, _ := svc.Status(); return !running })
	_, lastErr := svc.Status()
	if lastErr == "" {
		t.Fatal("expected a real last_error, not silent success")
	}
	report, err := svc.Read()
	if err != nil || report != nil {
		t.Fatalf("a failed run must not fabricate a report file: report=%+v err=%v", report, err)
	}
}

func TestReadMissingReportIsNilNotError(t *testing.T) {
	svc := &Service{ReportPath: filepath.Join(t.TempDir(), "nope.json")}
	report, err := svc.Read()
	if err != nil || report != nil {
		t.Fatalf("expected nil,nil for a never-generated report, got %+v, %v", report, err)
	}
}

func TestReadCorruptReportIsHonestError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "latest-report.json")
	svc := &Service{ReportPath: path}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := svc.Read()
	if err == nil {
		t.Fatal("expected a malformed-report error, not silent success")
	}
	if report == nil || len(report.Cases) != 0 {
		t.Fatalf("expected an empty error-shape report, got %+v", report)
	}
}

func TestClearNonExistentReportIsNotAnError(t *testing.T) {
	svc := &Service{ReportPath: filepath.Join(t.TempDir(), "nope.json")}
	if err := svc.Clear(); err != nil {
		t.Fatalf("clearing a report that was never generated must not error: %v", err)
	}
}

func TestSaveThenClearRoundTrip(t *testing.T) {
	dir := t.TempDir()
	svc := &Service{ReportPath: filepath.Join(dir, "latest-report.json")}
	if err := svc.Save(Report{Schema: 1, Cases: []CaseResult{{Name: "x"}}}); err != nil {
		t.Fatal(err)
	}
	report, err := svc.Read()
	if err != nil || report == nil || len(report.Cases) != 1 {
		t.Fatalf("unexpected round trip: %+v, %v", report, err)
	}
	if err := svc.Clear(); err != nil {
		t.Fatal(err)
	}
	report, err = svc.Read()
	if err != nil || report != nil {
		t.Fatalf("expected nil report after Clear, got %+v, %v", report, err)
	}
}
