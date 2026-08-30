package dnsanalytics

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sync/atomic"
)

// Settings mirrors V1.1.1's real analytics_settings row (app/analytics.py
// settings()/normalize_client()/event_from_message()/cleanup(), read
// directly from the shipped V1.1.1 package) as far as this
// single-table, event-stream architecture has an honest equivalent.
//
// Two real V1.1.1 fields have NO equivalent here and are deliberately
// NOT modeled: aggregate_retention_days and collection_interval both
// governed a separate poll-and-aggregate tier (analytics_aggregate_buckets,
// upstream_resolver_aggregate_buckets) that this package's own package
// doc comment already explains does not exist -- every aggregate here is
// computed at read time via SQL GROUP BY against query_events, so there
// is no second tier to retain separately or to poll on an interval.
// Faking a control for either would be dishonest, not parity.
//
// One real behavioral difference from V1.1.1, disclosed rather than
// hidden: V1's detailed_query_logging_enabled=false (or privacy_mode
// "aggregate_only") drops the ENTIRE per-query row, keeping only its
// separate aggregate-bucket tier. This architecture has no separate
// tier to fall back to -- disabling detailed logging here instead blanks
// just the domain field on the one row that exists, so Dashboard/
// Statistics timeseries and outcome/qtype/rcode/protocol breakdowns
// (which read this same table) keep working without per-domain
// granularity, rather than going dark entirely. Query Log / Top Domains
// / Top Blocked Domains lose real data either way, matching V1's own
// intent for this setting.
type Settings struct {
	AnalyticsEnabled            bool   `json:"analytics_enabled"`
	DetailedQueryLoggingEnabled bool   `json:"detailed_query_logging_enabled"`
	PrivacyMode                 string `json:"privacy_mode"` // "full" | "anonymized_clients" | "aggregate_only"
	ClientAnonymization         string `json:"client_anonymization"` // "truncate" | "hash"
	DetailedRetentionDays       int    `json:"detailed_retention_days"`
	DBSizeLimitBytes            int64  `json:"db_size_limit_bytes"`
	RecentQueryLimit            int    `json:"recent_query_limit"`
}

// DefaultSettings matches V1.1.1's own real defaults (analytics.py:
// DEFAULT_DETAILED_RETENTION_DAYS=7, DEFAULT_DB_LIMIT_BYTES=256MiB,
// DEFAULT_RECENT_LIMIT=100) everywhere this architecture has an
// equivalent; used whenever no settings row has been loaded yet (e.g. a
// Writer started before the control-plane DB is available), so an
// unconfigured Writer behaves exactly as this package always has.
func DefaultSettings() Settings {
	return Settings{
		AnalyticsEnabled:            true,
		DetailedQueryLoggingEnabled: true,
		PrivacyMode:                 "full",
		ClientAnonymization:         "truncate",
		DetailedRetentionDays:       7,
		DBSizeLimitBytes:            256 * 1024 * 1024,
		RecentQueryLimit:            100,
	}
}

// SettingsHolder is a hot-path-safe, concurrently-swappable reference to
// the current Settings -- the same atomic.Pointer pattern this package's
// Writer already uses for its own watchdog state (see writer.go's
// stalled/recoveryCount fields' own doc comment). A save from
// handleUpdateAnalyticsSettings swaps this in place; the Writer's
// per-frame hot path always reads the latest value with no lock, no
// database round trip, and no restart required.
type SettingsHolder struct {
	v atomic.Pointer[Settings]
}

func NewSettingsHolder(s Settings) *SettingsHolder {
	h := &SettingsHolder{}
	h.Store(s)
	return h
}

func (h *SettingsHolder) Store(s Settings) { h.v.Store(&s) }

// Load never returns nil -- an unconfigured holder (including a nil
// *SettingsHolder, checked by callers) reads as DefaultSettings.
func (h *SettingsHolder) Load() Settings {
	if h == nil {
		return DefaultSettings()
	}
	if p := h.v.Load(); p != nil {
		return *p
	}
	return DefaultSettings()
}

// anonymizeClient mirrors V1.1.1's normalize_client() field-for-field
// (analytics.py:349) including its exact truncate semantics (IPv4 -> the
// containing /24, IPv6 -> the containing /64) and its hash fallback
// (sha256 of a per-appliance secret + the raw value, first 16 hex chars,
// "anon-" prefixed) for anything that isn't truncatable (hash mode
// itself, or a value that doesn't parse as an IP at all).
//
// secret is this appliance's own anonymization key (see
// internal/dnsanalytics.Writer's AnonymizationSecret) -- unlike V1's
// analytics_secret() (a shared file V1's own web+collector processes
// both read), this process holds it directly since it is both producer
// and consumer of query_events.
func anonymizeClient(value, mode, anonymization, secret string) string {
	if mode == "full" || value == "" {
		return value
	}
	if anonymization == "truncate" {
		if ip := net.ParseIP(value); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				n := &net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
				return n.String()
			}
			n := &net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}
			return n.String()
		}
	}
	sum := sha256.Sum256([]byte(secret + value))
	return "anon-" + hex.EncodeToString(sum[:])[:16]
}

// applySettings is the Writer's single choke point for Settings
// enforcement, called once per successfully decoded frame before it
// joins the insert batch (see Run's own frame case). Returns keep=false
// when analytics is disabled outright, OR when this one response's own
// per-scope statistics_enabled resolved to false (ev.noStats -- see
// internal/dnscompile's ScopeOverride/QueryLoggingDisabled doc
// comment): since this package's own stats are computed at READ time
// from stored query_events rows (see store.go's own doc comment), the
// only real way to exclude one scope's traffic from statistics is to
// never store its rows at all. The caller must still treat the frame
// as having arrived (lastFrameAt already stamped by the caller before
// this runs) so the stall watchdog is never confused by an owner
// turning analytics (or one scope's own statistics participation) off.
//
// ev.noLog (per-scope query_log_enabled=false) is handled the same way
// the pre-existing global DetailedQueryLoggingEnabled toggle already
// is: the row is still stored (so aggregate stats/counts still reflect
// this scope's real traffic), only its own domain is blanked --
// matching that field's name (it disables the QUERY LOG, not
// statistics).
func (wtr *Writer) applySettings(ev event) (event, bool) {
	s := wtr.Settings.Load()
	if !s.AnalyticsEnabled || ev.noStats {
		return event{}, false
	}
	ev.client = anonymizeClient(ev.client, s.PrivacyMode, s.ClientAnonymization, wtr.anonymizationSecret())
	if s.PrivacyMode == "aggregate_only" || !s.DetailedQueryLoggingEnabled || ev.noLog {
		ev.domain = ""
	}
	return ev, true
}

func (wtr *Writer) anonymizationSecret() string {
	if wtr.AnonymizationSecret != "" {
		return wtr.AnonymizationSecret
	}
	// A fixed fallback (never a randomly-generated per-process value) so
	// hashed client values stay stable across restarts even when no
	// secret has been provisioned -- consistency matters more than
	// secrecy here (this is pseudonymization for reporting, not a
	// security boundary); an appliance that cares about resisting
	// dictionary correlation should set AnonymizationSecret.
	return "alderpointdns-analytics-anonymization-default"
}
