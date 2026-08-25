package blocklists

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// IntervalPresets mirrors app/v2/webapp.py's BLOCKLIST_INTERVAL_PRESETS
// exactly: 0 = "Manual Only" (never auto-scheduled).
var IntervalPresets = []struct {
	Seconds int    `json:"seconds"`
	Label   string `json:"label"`
}{
	{0, "Manual Only"},
	{3600, "1 hour"},
	{21600, "6 hours"},
	{43200, "12 hours"},
	{86400, "1 day"},
	{259200, "3 days"},
	{604800, "1 week"},
}

// AttentionThreshold mirrors policy_store.py's BLOCKLIST_ATTENTION_THRESHOLD:
// a subscription surfaces the page-level "needs attention" state only
// after this many consecutive failed pulls in a row -- one or two
// failures show on that row alone, never a false alarm on the first blip.
const AttentionThreshold = 3

var validIntervals = func() map[int]bool {
	m := map[int]bool{}
	for _, p := range IntervalPresets {
		m[p.Seconds] = true
	}
	return m
}()

func ValidateInterval(seconds int) error {
	if !validIntervals[seconds] {
		return fmt.Errorf("update interval must be Manual Only, 1 hour, 6 hours, 12 hours, 1 day, 3 days, or 1 week")
	}
	return nil
}

type Subscription struct {
	ID                     int64   `json:"-"`
	SubscriptionID         string  `json:"subscription_id"`
	Name                   string  `json:"name"`
	URL                    string  `json:"url"`
	Category               string  `json:"category"`
	Enabled                bool    `json:"enabled"`
	CreatedAt              string  `json:"created_at"`
	LastRefreshAt          *string `json:"last_refresh_at"`
	LastStatus             *string `json:"last_status"`
	LastError              *string `json:"last_error"`
	RuleCount              *int    `json:"rule_count"`
	LastSuccessAt          *string `json:"last_success_at"`
	NextUpdateAt           *string `json:"next_update_at"`
	UpdateDurationMs       *int    `json:"update_duration_ms"`
	UpdateIntervalSeconds  *int    `json:"update_interval_seconds"`
	FailureCount           int     `json:"failure_count"`
	FirstFailureAt         *string `json:"first_failure_at"`
	UpdateInProgress       bool    `json:"update_in_progress"`
	EffectiveIntervalSecs  int     `json:"effective_interval_seconds"`
	AttentionRequired      bool    `json:"attention_required"`
}

type Job struct {
	ID               int64           `json:"id"`
	Kind             string          `json:"kind"`
	SubscriptionIDs  []string        `json:"subscription_ids"`
	State            string          `json:"state"`
	Results          json.RawMessage `json:"results,omitempty"`
	StartedAt        string          `json:"started_at"`
	FinishedAt       *string         `json:"finished_at"`
}

type Service struct {
	DB             *sql.DB
	HTTPClient     *http.Client
	StagingDir     string
	RuntimeDir     string
	MaxConcurrent  int
	Log            *slog.Logger

	sem      chan struct{}
	initOnce sync.Once

	runningMu sync.Mutex
	running   map[string]bool
}

func (s *Service) init() {
	s.initOnce.Do(func() {
		s.sem = make(chan struct{}, s.MaxConcurrent)
		s.running = make(map[string]bool)
	})
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func (s *Service) DefaultInterval(ctx context.Context) (int, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM blocklist_settings WHERE key='default_interval_seconds'`).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil // Manual Only until explicitly configured
	} else if err != nil {
		return 0, err
	}
	var n int
	fmt.Sscanf(v, "%d", &n)
	return n, nil
}

func (s *Service) SetDefaultInterval(ctx context.Context, seconds int) error {
	if err := ValidateInterval(seconds); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO blocklist_settings(key, value) VALUES('default_interval_seconds', ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, fmt.Sprint(seconds))
	return err
}

var subscriptionColumns = []string{
	"id", "subscription_id", "name", "url", "category", "enabled", "created_at",
	"last_refresh_at", "last_status", "last_error", "rule_count", "last_success_at",
	"next_update_at", "update_duration_ms", "update_interval_seconds", "failure_count",
	"first_failure_at", "update_in_progress",
}

func scanSubscription(scanner interface{ Scan(...any) error }) (Subscription, error) {
	var sub Subscription
	var enabled, inProgress int
	err := scanner.Scan(&sub.ID, &sub.SubscriptionID, &sub.Name, &sub.URL, &sub.Category, &enabled, &sub.CreatedAt,
		&sub.LastRefreshAt, &sub.LastStatus, &sub.LastError, &sub.RuleCount, &sub.LastSuccessAt,
		&sub.NextUpdateAt, &sub.UpdateDurationMs, &sub.UpdateIntervalSeconds, &sub.FailureCount,
		&sub.FirstFailureAt, &inProgress)
	sub.Enabled = enabled != 0
	sub.UpdateInProgress = inProgress != 0
	return sub, err
}

func (s *Service) decorate(sub Subscription, defaultInterval int) Subscription {
	if sub.UpdateIntervalSeconds != nil {
		sub.EffectiveIntervalSecs = *sub.UpdateIntervalSeconds
	} else {
		sub.EffectiveIntervalSecs = defaultInterval
	}
	sub.AttentionRequired = sub.Enabled && sub.FailureCount >= AttentionThreshold
	return sub
}

func (s *Service) List(ctx context.Context) ([]Subscription, error) {
	defaultInterval, err := s.DefaultInterval(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx,
		fmt.Sprintf(`SELECT %s FROM blocklist_subscriptions ORDER BY subscription_id`, join(subscriptionColumns)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Subscription{}
	for rows.Next() {
		sub, err := scanSubscription(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s.decorate(sub, defaultInterval))
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, subscriptionID string) (*Subscription, error) {
	defaultInterval, err := s.DefaultInterval(ctx)
	if err != nil {
		return nil, err
	}
	row := s.DB.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT %s FROM blocklist_subscriptions WHERE subscription_id=?`, join(subscriptionColumns)), subscriptionID)
	sub, err := scanSubscription(row)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	decorated := s.decorate(sub, defaultInterval)
	return &decorated, nil
}

func join(cols []string) string {
	out := ""
	for i, c := range cols {
		if i > 0 {
			out += ", "
		}
		out += c
	}
	return out
}

// Create inserts a new subscription and -- regardless of its
// update_interval_seconds -- immediately triggers a real first pull job,
// exactly like app/v2/webapp.py's create_blocklist_subscription_route
// docstring explains: a newly added subscription must not sit inert
// until either a manual click or a possibly-day-away scheduled run.
func (s *Service) Create(ctx context.Context, subscriptionID, name, url, category string) (*Subscription, int64, error) {
	s.init()
	nowStr := now()
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO blocklist_subscriptions(subscription_id, name, url, category, enabled, created_at, update_in_progress)
		 VALUES(?,?,?,?,1,?,1)`, subscriptionID, name, url, category, nowStr)
	if err != nil {
		return nil, 0, fmt.Errorf("duplicate subscription_id: %w", err)
	}
	defaultInterval, _ := s.DefaultInterval(ctx)
	if defaultInterval > 0 {
		next := time.Now().UTC().Add(time.Duration(defaultInterval) * time.Second).Format(time.RFC3339)
		s.DB.ExecContext(ctx, `UPDATE blocklist_subscriptions SET next_update_at=? WHERE subscription_id=?`, next, subscriptionID)
	}

	jobID, err := s.newJob(ctx, "single", []string{subscriptionID})
	if err != nil {
		return nil, 0, err
	}
	go s.runJob(jobID, []string{subscriptionID})

	sub, err := s.Get(ctx, subscriptionID)
	return sub, jobID, err
}

func (s *Service) SetInterval(ctx context.Context, subscriptionID string, seconds int) error {
	if err := ValidateInterval(seconds); err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE blocklist_subscriptions SET update_interval_seconds=? WHERE subscription_id=?`, seconds, subscriptionID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Service) Toggle(ctx context.Context, subscriptionID string) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE blocklist_subscriptions SET enabled = 1 - enabled WHERE subscription_id=?`, subscriptionID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Delete removes the subscription row and its runtime artifact. This
// does NOT need a background job (no network I/O) -- a fast, synchronous,
// isolated operation.
func (s *Service) Delete(ctx context.Context, subscriptionID string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM blocklist_subscriptions WHERE subscription_id=?`, subscriptionID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	os.Remove(filepath.Join(s.RuntimeDir, subscriptionID+".rpz"))
	return nil
}

var ErrAlreadyRunning = fmt.Errorf("update already running for this subscription")
var ErrNothingToRefresh = fmt.Errorf("no enabled blocklists")

func (s *Service) RefreshOne(ctx context.Context, subscriptionID string) (int64, error) {
	s.init()
	sub, err := s.Get(ctx, subscriptionID)
	if err != nil {
		return 0, err
	}
	if sub == nil {
		return 0, sql.ErrNoRows
	}
	s.runningMu.Lock()
	if s.running[subscriptionID] {
		s.runningMu.Unlock()
		return 0, ErrAlreadyRunning
	}
	s.runningMu.Unlock()

	jobID, err := s.newJob(ctx, "single", []string{subscriptionID})
	if err != nil {
		return 0, err
	}
	go s.runJob(jobID, []string{subscriptionID})
	return jobID, nil
}

func (s *Service) RefreshAll(ctx context.Context) (int64, int, error) {
	s.init()
	subs, err := s.List(ctx)
	if err != nil {
		return 0, 0, err
	}
	var ids []string
	s.runningMu.Lock()
	for _, sub := range subs {
		if sub.Enabled && !s.running[sub.SubscriptionID] {
			ids = append(ids, sub.SubscriptionID)
		}
	}
	s.runningMu.Unlock()
	if len(ids) == 0 {
		return 0, 0, ErrNothingToRefresh
	}
	jobID, err := s.newJob(ctx, "all", ids)
	if err != nil {
		return 0, 0, err
	}
	go s.runJob(jobID, ids)
	return jobID, len(ids), nil
}

func (s *Service) newJob(ctx context.Context, kind string, subscriptionIDs []string) (int64, error) {
	idsJSON, _ := json.Marshal(subscriptionIDs)
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO blocklist_jobs(kind, subscription_ids, state, started_at) VALUES(?,?,'queued',?)`,
		kind, string(idsJSON), now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Service) GetJob(ctx context.Context, jobID int64) (*Job, error) {
	var j Job
	var idsJSON string
	var results sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT id, kind, subscription_ids, state, results, started_at, finished_at FROM blocklist_jobs WHERE id=?`, jobID).
		Scan(&j.ID, &j.Kind, &idsJSON, &j.State, &results, &j.StartedAt, &j.FinishedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(idsJSON), &j.SubscriptionIDs)
	if results.Valid {
		j.Results = json.RawMessage(results.String)
	}
	return &j, nil
}

type pullOutcome struct {
	SubscriptionID string `json:"subscription_id"`
	Status         string `json:"status"`
	RuleCount      int    `json:"rule_count,omitempty"`
	Error          string `json:"error,omitempty"`
	DurationMs     int    `json:"duration_ms"`
}

// runJob executes one background job: pulls every listed subscription,
// bounded to MaxConcurrent in flight at once (a semaphore, not one
// goroutine per subscription queued unboundedly), and each subscription's
// outcome is fully isolated from the others -- one failing pull never
// blocks, cancels, or corrupts any other subscription's file (partial
// failure isolation) or touches its own previously-promoted runtime file
// on failure (previous-good retention).
func (s *Service) runJob(jobID int64, subscriptionIDs []string) {
	ctx := context.Background()
	s.DB.ExecContext(ctx, `UPDATE blocklist_jobs SET state='running' WHERE id=?`, jobID)

	var wg sync.WaitGroup
	outcomes := make([]pullOutcome, len(subscriptionIDs))
	for i, subID := range subscriptionIDs {
		s.runningMu.Lock()
		s.running[subID] = true
		s.runningMu.Unlock()

		wg.Add(1)
		s.sem <- struct{}{} // bounded concurrency
		go func(i int, subID string) {
			defer wg.Done()
			defer func() { <-s.sem }()
			defer func() {
				s.runningMu.Lock()
				delete(s.running, subID)
				s.runningMu.Unlock()
			}()
			outcomes[i] = s.pullOne(ctx, subID)
		}(i, subID)
	}
	wg.Wait()

	resultsJSON, _ := json.Marshal(outcomes)
	s.DB.ExecContext(ctx, `UPDATE blocklist_jobs SET state='succeeded', results=?, finished_at=? WHERE id=?`,
		string(resultsJSON), now(), jobID)
}

func (s *Service) pullOne(ctx context.Context, subID string) pullOutcome {
	start := time.Now()
	sub, err := s.Get(ctx, subID)
	if err != nil || sub == nil {
		return pullOutcome{SubscriptionID: subID, Status: "failed", Error: "subscription no longer exists"}
	}

	s.DB.ExecContext(ctx, `UPDATE blocklist_subscriptions SET update_in_progress=1 WHERE subscription_id=?`, subID)

	result, err := s.download(ctx, sub.URL, subID)
	durationMs := int(time.Since(start).Milliseconds())
	nowStr := now()

	if err != nil {
		s.recordFailure(ctx, subID, err.Error(), durationMs, nowStr, sub.EffectiveIntervalSecs)
		if s.Log != nil {
			s.Log.Warn("blocklist pull failed", "subscription_id", subID, "err", err)
		}
		return pullOutcome{SubscriptionID: subID, Status: "failed", Error: err.Error(), DurationMs: durationMs}
	}

	s.recordSuccess(ctx, subID, len(result.Domains), durationMs, nowStr, sub.EffectiveIntervalSecs)
	return pullOutcome{SubscriptionID: subID, Status: "ok", RuleCount: len(result.Domains), DurationMs: durationMs}
}

func (s *Service) recordSuccess(ctx context.Context, subID string, ruleCount, durationMs int, nowStr string, effectiveInterval int) {
	var next any
	if effectiveInterval > 0 {
		next = time.Now().UTC().Add(time.Duration(effectiveInterval) * time.Second).Format(time.RFC3339)
	}
	s.DB.ExecContext(ctx, `UPDATE blocklist_subscriptions SET
		last_refresh_at=?, last_status='ok', last_error=NULL, rule_count=?, last_success_at=?,
		next_update_at=?, update_duration_ms=?, failure_count=0, first_failure_at=NULL, update_in_progress=0
		WHERE subscription_id=?`,
		nowStr, ruleCount, nowStr, next, durationMs, subID)
}

func (s *Service) recordFailure(ctx context.Context, subID, errMsg string, durationMs int, nowStr string, effectiveInterval int) {
	var next any
	if effectiveInterval > 0 {
		// Retry on the same schedule for Milestone 1 (no exponential
		// backoff yet -- see the migration report's known limitations).
		next = time.Now().UTC().Add(time.Duration(effectiveInterval) * time.Second).Format(time.RFC3339)
	}
	row := s.DB.QueryRowContext(ctx, `SELECT failure_count, first_failure_at FROM blocklist_subscriptions WHERE subscription_id=?`, subID)
	var failureCount int
	var firstFailureAt *string
	row.Scan(&failureCount, &firstFailureAt)
	if firstFailureAt == nil {
		firstFailureAt = &nowStr
	}
	s.DB.ExecContext(ctx, `UPDATE blocklist_subscriptions SET
		last_refresh_at=?, last_status='error', last_error=?, next_update_at=?, update_duration_ms=?,
		failure_count=failure_count+1, first_failure_at=?, update_in_progress=0
		WHERE subscription_id=?`,
		nowStr, errMsg, next, durationMs, *firstFailureAt, subID)
}
