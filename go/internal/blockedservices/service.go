package blockedservices

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/policyentities"
)

// RulesetID is the one reserved Service Blocking Ruleset this package
// owns and writes to -- an owner can still see it (read-only in spirit)
// under Advanced > Policy Profiles > Service Blocking Rulesets, same as
// any other ruleset, but this page is its one real source of truth.
const RulesetID = "standard-blocked-services"

var weekdayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

type Settings struct {
	EnabledServiceIDs []string `json:"enabled_service_ids"`
	ScheduleEnabled   bool     `json:"schedule_enabled"`
	ScheduleDays      []string `json:"schedule_days"`
	ScheduleStart     string   `json:"schedule_start"`
	ScheduleEnd       string   `json:"schedule_end"`
	ScheduleAllDay    bool     `json:"schedule_all_day"`
	UpdatedAt         string   `json:"updated_at"`
	// ScheduleActiveNow/NextActivation are computed, not stored -- real,
	// current answers, not stale data that could drift from the clock.
	ScheduleActiveNow bool    `json:"schedule_active_now"`
	NextActivation    *string `json:"next_activation"`
}

type Service struct {
	DB             *sql.DB
	Policy         *policy.Service
	PolicyEntities *policyentities.Service
	Now            func() time.Time // overridable in tests; defaults to time.Now
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) GetSettings(ctx context.Context) (Settings, error) {
	var out Settings
	var enabledJSON, daysJSON string
	var scheduleEnabled, allDay int
	err := s.DB.QueryRowContext(ctx,
		`SELECT enabled_service_ids, schedule_enabled, schedule_days, schedule_start, schedule_end, schedule_all_day, updated_at
		 FROM blocked_services_settings WHERE id=1`,
	).Scan(&enabledJSON, &scheduleEnabled, &daysJSON, &out.ScheduleStart, &out.ScheduleEnd, &allDay, &out.UpdatedAt)
	if err != nil {
		return out, err
	}
	json.Unmarshal([]byte(enabledJSON), &out.EnabledServiceIDs)
	json.Unmarshal([]byte(daysJSON), &out.ScheduleDays)
	out.ScheduleEnabled = scheduleEnabled != 0
	out.ScheduleAllDay = allDay != 0
	out.ScheduleActiveNow = s.isActiveNow(out)
	if next := s.nextActivation(out); next != nil {
		formatted := next.Format(time.RFC3339)
		out.NextActivation = &formatted
	}
	return out, nil
}

// SetEnabledServices persists which catalog services are toggled on and
// recompiles the reserved ruleset. Unknown ids are silently dropped
// (never persisted) rather than blocking the save on one bad id.
func (s *Service) SetEnabledServices(ctx context.Context, ids []string) (Settings, error) {
	valid := make([]string, 0, len(ids))
	for _, id := range ids {
		if ByID(id) != nil {
			valid = append(valid, id)
		}
	}
	sort.Strings(valid)
	enc, _ := json.Marshal(valid)
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE blocked_services_settings SET enabled_service_ids=?, updated_at=? WHERE id=1`,
		string(enc), s.now().UTC().Format(time.RFC3339)); err != nil {
		return Settings{}, err
	}
	if err := s.recompile(ctx); err != nil {
		return Settings{}, err
	}
	return s.GetSettings(ctx)
}

type ScheduleInput struct {
	Enabled bool     `json:"enabled"`
	Days    []string `json:"days"`
	Start   string   `json:"start"`
	End     string   `json:"end"`
	AllDay  bool     `json:"all_day"`
}

func (s *Service) SetSchedule(ctx context.Context, sched ScheduleInput) (Settings, error) {
	days := make([]string, 0, len(sched.Days))
	for _, d := range sched.Days {
		for _, valid := range weekdayNames {
			if d == valid {
				days = append(days, d)
				break
			}
		}
	}
	if sched.Start == "" {
		sched.Start = "00:00"
	}
	if sched.End == "" {
		sched.End = "23:59"
	}
	enc, _ := json.Marshal(days)
	enabledInt, allDayInt := 0, 0
	if sched.Enabled {
		enabledInt = 1
	}
	if sched.AllDay {
		allDayInt = 1
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE blocked_services_settings SET schedule_enabled=?, schedule_days=?, schedule_start=?, schedule_end=?, schedule_all_day=?, updated_at=? WHERE id=1`,
		enabledInt, string(enc), sched.Start, sched.End, allDayInt, s.now().UTC().Format(time.RFC3339)); err != nil {
		return Settings{}, err
	}
	if err := s.recompile(ctx); err != nil {
		return Settings{}, err
	}
	return s.GetSettings(ctx)
}

// isActiveNow: no schedule configured (ScheduleEnabled false) means
// "always active" -- a schedule is an optional restriction, not a
// requirement to configure before blocking works at all.
func (s *Service) isActiveNow(settings Settings) bool {
	if !settings.ScheduleEnabled {
		return true
	}
	if settings.ScheduleAllDay {
		return dayActive(settings, s.now())
	}
	now := s.now()
	if !dayActive(settings, now) {
		return false
	}
	return withinTimeWindow(now, settings.ScheduleStart, settings.ScheduleEnd)
}

func dayActive(settings Settings, t time.Time) bool {
	if len(settings.ScheduleDays) == 0 {
		return true // no days selected with a schedule enabled -- treat as every day rather than never
	}
	today := weekdayNames[int(t.Weekday())]
	for _, d := range settings.ScheduleDays {
		if d == today {
			return true
		}
	}
	return false
}

func withinTimeWindow(t time.Time, start, end string) bool {
	sh, sm := parseHM(start)
	eh, em := parseHM(end)
	cur := t.Hour()*60 + t.Minute()
	s := sh*60 + sm
	e := eh*60 + em
	if s <= e {
		return cur >= s && cur <= e
	}
	// an overnight window (e.g. 22:00-06:00) wraps past midnight
	return cur >= s || cur <= e
}

func parseHM(v string) (int, int) {
	var h, m int
	fmt.Sscanf(v, "%d:%d", &h, &m)
	return h, m
}

// nextActivation: the next real clock time this schedule will turn
// blocking on, scanning up to 8 days ahead (covers "no days selected"
// and every real weekly pattern) -- nil (never) only when the schedule
// is disabled (always-on, no future "activation" event exists) or
// already active right now.
func (s *Service) nextActivation(settings Settings) *time.Time {
	if !settings.ScheduleEnabled || s.isActiveNow(settings) {
		return nil
	}
	sh, sm := parseHM(settings.ScheduleStart)
	now := s.now()
	for i := 0; i < 8; i++ {
		day := now.AddDate(0, 0, i)
		candidate := time.Date(day.Year(), day.Month(), day.Day(), sh, sm, 0, 0, day.Location())
		if candidate.Before(now) {
			continue
		}
		if dayActive(settings, candidate) {
			return &candidate
		}
	}
	return nil
}

// recompile: the real bridge from "which catalog services are toggled
// on, right now" to a compiled DNS effect -- builds/updates the one
// reserved ruleset from the union of active services' own domains
// (empty when nothing is active, e.g. outside a configured schedule
// window -- an empty ruleset blocks nothing, not an error), and makes
// sure the GLOBAL policy layer actually points at it. Does not call
// DNS Runtime Apply itself -- the HTTP handler (a real request context)
// or the scheduler tick (a background context) does that, matching
// every other mutation's own "the handler applies, the service just
// persists" split.
func (s *Service) recompile(ctx context.Context) error {
	settings, err := s.GetSettings(ctx)
	if err != nil {
		return err
	}
	var domains []string
	if settings.ScheduleActiveNow {
		seen := map[string]bool{}
		for _, id := range settings.EnabledServiceIDs {
			svc := ByID(id)
			if svc == nil {
				continue
			}
			for _, d := range svc.Domains {
				if !seen[d] {
					seen[d] = true
					domains = append(domains, d)
				}
			}
		}
	}
	sort.Strings(domains)

	existing, err := s.PolicyEntities.ListServiceBlockingRulesets(ctx)
	if err != nil {
		return err
	}
	exists := false
	for _, r := range existing {
		if r.ID == RulesetID {
			exists = true
			break
		}
	}
	desc := "Managed by the Blocked Services page (Standard > Filters) -- do not edit domains here directly, they're overwritten on the next toggle."
	if exists {
		if err := s.PolicyEntities.UpdateServiceBlockingRuleset(ctx, RulesetID, "Standard Blocked Services", desc, domains); err != nil {
			return err
		}
	} else {
		if _, err := s.PolicyEntities.CreateServiceBlockingRuleset(ctx, RulesetID, "Standard Blocked Services", desc, domains); err != nil {
			return err
		}
	}

	layer, err := s.Policy.Load(ctx, "global", "global")
	if err != nil {
		return err
	}
	id := RulesetID
	layer.ServiceBlockingRulesetID = &id
	return s.Policy.Save(ctx, "global", "global", layer)
}

// RunScheduler ticks every interval, re-evaluating whether the
// configured schedule's own active window just turned on or off, and
// calls onChange (wired to a real DNS Runtime Apply in main.go) only
// when that real state actually flipped -- not on every tick, matching
// every other scheduler in this codebase's own "don't apply when
// nothing changed" discipline.
func (s *Service) RunScheduler(ctx context.Context, interval time.Duration, onChange func()) {
	lastActive := false
	if settings, err := s.GetSettings(ctx); err == nil {
		lastActive = settings.ScheduleActiveNow
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			settings, err := s.GetSettings(ctx)
			if err != nil {
				continue
			}
			if !settings.ScheduleEnabled {
				continue // nothing to flip -- SetEnabledServices/SetSchedule already recompiled synchronously
			}
			if settings.ScheduleActiveNow == lastActive {
				continue
			}
			lastActive = settings.ScheduleActiveNow
			if err := s.recompile(ctx); err != nil {
				continue
			}
			if onChange != nil {
				onChange()
			}
		}
	}
}
