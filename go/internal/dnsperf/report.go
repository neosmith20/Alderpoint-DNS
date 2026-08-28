package dnsperf

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// BenchmarkCase mirrors app/v2/dns_performance.py's BenchmarkCase
// dataclass field-for-field.
type BenchmarkCase struct {
	Name     string
	Scope    string
	Server   string
	Port     int
	Domain   string
	QType    uint16
	Protocol string // "udp" | "tcp" | "dot" | "doh" | "dot-established" | "doh-established"
	Queries  int
	Timeout  time.Duration
	Path     string
	Pause    time.Duration

	// Target is only meaningful to HostAgentQuerier -- see its doc
	// comment and internal/hostagentd/ops_dnsperf.go's safety design.
	// LocalQuerier ignores it and dials Server/Port directly.
	Target string // "dnsdist" | "bind_plain" | "dot" | "doh"
}

// CaseResult mirrors one entry of Python's run_benchmark() results list.
type CaseResult struct {
	Name         string  `json:"name"`
	Scope        string  `json:"scope"`
	Server       string  `json:"server"`
	Port         int     `json:"port"`
	Domain       string  `json:"domain"`
	QType        uint16  `json:"qtype"`
	Protocol     string  `json:"protocol"`
	LatencyScope string  `json:"latency_scope"`
	Summary      Summary `json:"summary"`
}

// Report mirrors Python's run_benchmark() return shape (schema 1).
type Report struct {
	Schema          int          `json:"schema"`
	GeneratedAt     string       `json:"generated_at"`
	DurationSeconds float64      `json:"duration_seconds"`
	Notes           []string     `json:"notes"`
	Cases           []CaseResult `json:"cases"`
}

// Querier is the boundary this package's pure business logic calls
// through to actually exchange packets -- in production this is a
// hostagent.Client round trip (see internal/hostagentd/ops_dnsperf.go),
// because the web process's own network namespace cannot reach the
// real DNS listeners. Tests substitute a fake.
type Querier interface {
	Query(ctx context.Context, c BenchmarkCase) []Sample
}

// LocalQuerier runs cases directly with this package's own QueryOnce/
// QueryManyEstablished -- used by internal/hostagentd (which DOES run
// in the real host network namespace) and by tests.
type LocalQuerier struct{}

func (LocalQuerier) Query(ctx context.Context, c BenchmarkCase) []Sample {
	if strings.HasSuffix(c.Protocol, "-established") {
		return QueryManyEstablished(ctx, EstablishedCase{
			Server: c.Server, Port: c.Port, Domain: c.Domain, Path: c.Path,
			QType: c.QType, Protocol: c.Protocol, Queries: c.Queries, Timeout: c.Timeout,
		})
	}
	samples := make([]Sample, 0, maxInt(1, c.Queries))
	for i := 0; i < maxInt(1, c.Queries); i++ {
		samples = append(samples, QueryOnce(ctx, c.Server, c.Port, c.Domain, c.QType, c.Protocol, c.Timeout, c.Path))
		if c.Pause > 0 {
			time.Sleep(c.Pause)
		}
	}
	return samples
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// RunBenchmark matches Python's run_benchmark(): executes every case
// sequentially (never concurrently -- this is a bounded, self-directed
// latency probe, not a load-test tool) and summarizes each.
func RunBenchmark(ctx context.Context, q Querier, cases []BenchmarkCase, notes []string) Report {
	started := time.Now()
	results := make([]CaseResult, 0, len(cases))
	for _, c := range cases {
		samples := q.Query(ctx, c)
		scope := "includes connection setup for TCP/TLS protocols"
		if strings.HasSuffix(c.Protocol, "-established") {
			scope = "established connection"
		}
		results = append(results, CaseResult{
			Name: c.Name, Scope: c.Scope, Server: c.Server, Port: c.Port, Domain: c.Domain,
			QType: c.QType, Protocol: c.Protocol, LatencyScope: scope, Summary: Summarize(samples),
		})
	}
	return Report{
		Schema:          1,
		GeneratedAt:     time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		DurationSeconds: round3(time.Since(started).Seconds()),
		Notes:           notes,
		Cases:           results,
	}
}

// --- persistence + background job state (mirrors webapp.py's module-level lock/flags + save_report/read_report) ---

// Service owns the report file and the single-flight "is a benchmark
// currently running" state -- process-lifetime only for running/
// last_error (matches Python's in-memory threading.Lock globals; a
// restart clears them, exactly like Python), but the report itself
// persists to disk across restarts (matches Python's save_report).
type Service struct {
	ReportPath string
	Querier    Querier
	BuildCases func(ctx context.Context) ([]BenchmarkCase, []string, error)

	mu        sync.Mutex
	running   bool
	lastError string
}

func (s *Service) Status() (running bool, lastError string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running, s.lastError
}

// Start launches the benchmark in the background if one isn't already
// running. Returns false if one was already in flight (matches
// Python's {"status": "already_running"} response, never queuing a
// second run).
func (s *Service) Start(ctx context.Context) bool {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return false
	}
	s.running = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
		}()
		cases, notes, err := s.BuildCases(context.Background())
		if err != nil {
			s.mu.Lock()
			s.lastError = err.Error()
			s.mu.Unlock()
			return
		}
		report := RunBenchmark(context.Background(), s.Querier, cases, notes)
		if err := s.Save(report); err != nil {
			s.mu.Lock()
			s.lastError = err.Error()
			s.mu.Unlock()
			return
		}
		s.mu.Lock()
		s.lastError = ""
		s.mu.Unlock()
	}()
	return true
}

// Save matches Python's save_report(): atomic tmp-write-then-rename,
// world-readable (0644, same as Python's tmp.chmod(0o644) -- this file
// carries only latency numbers/domain names already visible elsewhere
// in the UI, never secrets).
func (s *Service) Save(report Report) error {
	if s.ReportPath == "" {
		return fmt.Errorf("no report path configured")
	}
	if err := os.MkdirAll(filepath.Dir(s.ReportPath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.ReportPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.ReportPath)
}

// Read matches Python's read_report(): nil (not an error) if no report
// has ever been generated, and an honest in-band error object (never a
// silently-empty/zeroed report) if the file exists but is unreadable or
// corrupt.
func (s *Service) Read() (*Report, error) {
	if s.ReportPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(s.ReportPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return &Report{Schema: 1}, fmt.Errorf("stored DNS performance report is not readable: %w", err)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return &Report{Schema: 1}, fmt.Errorf("stored DNS performance report is malformed: %w", err)
	}
	return &report, nil
}

// Clear matches Python's DELETE route: removing a report that was
// never generated is not an error.
func (s *Service) Clear() error {
	if s.ReportPath == "" {
		return nil
	}
	err := os.Remove(s.ReportPath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
