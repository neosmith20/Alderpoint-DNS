package httpapi

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/notifications"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/pyanalytics"
	"alderpointdns/go-controlplane/internal/rawquerylog"
	"alderpointdns/go-controlplane/internal/tlscert"
	"alderpointdns/go-controlplane/internal/upstreams"
)

type Server struct {
	DB            *sql.DB
	Auth          *auth.Store
	Blocklists    *blocklists.Service
	LocalDNS      *localdns.Service
	Upstreams     *upstreams.Service
	Clients       *clients.Service
	Policy        *policy.Service
	CustomRules   *customrules.Service
	Backup        *backup.Service
	DNSTransports *dnstransports.Service
	Notifications *notifications.Service
	StaticDir     string
	Log           *slog.Logger

	// TLSCert is nil unless -tls-cert-path was given a real path at
	// startup -- nil means the Encryption page's TLS status always
	// reports {"active": false}, never an error. See internal/tlscert's
	// doc comment.
	TLSCert *tlscert.Reader

	// Analytics is nil unless -analytics-db was given a real path at
	// startup -- every analytics handler must treat nil as "degraded",
	// never as a programming error. See internal/pyanalytics's doc
	// comment for exactly what this compatibility boundary is.
	Analytics *pyanalytics.Reader

	// RawQueryLog is nil unless -query-log-dir was given a real path at
	// startup -- same "nil means degraded, never a programming error"
	// contract as Analytics above. See internal/rawquerylog's doc
	// comment: a second, narrower compatibility boundary over Python's
	// raw per-query Parquet history (not the aggregates.db buckets
	// Analytics reads).
	RawQueryLog *rawquerylog.Reader

	Version    string
	StartedAt  time.Time
	SessionTTL time.Duration
	LastSeen   time.Duration

	ApplianceName     string
	ApplianceTimezone string
}

func (s *Server) Uptime() time.Duration { return time.Since(s.StartedAt) }

// Routes builds the full route table. requireAuth wraps every
// authenticated handler with session+CSRF enforcement in one place.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	requireAuth := func(h http.HandlerFunc) http.HandlerFunc {
		return RequireAuth(s.Auth, s.SessionTTL, s.LastSeen, h)
	}

	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/setup/status", s.handleSetupStatus)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", requireAuth(s.handleLogout))
	mux.HandleFunc("GET /api/session", requireAuth(s.handleSession))
	mux.HandleFunc("POST /api/session/revoke-others", requireAuth(s.handleRevokeOtherSessions))
	mux.HandleFunc("POST /api/session/password", requireAuth(s.handleChangePassword))
	mux.HandleFunc("GET /api/system/status", requireAuth(s.handleSystemStatus))
	mux.HandleFunc("GET /api/dashboard/summary", requireAuth(s.handleDashboardSummary))
	mux.HandleFunc("GET /api/analytics/timeseries", requireAuth(s.handleAnalyticsTimeseries))
	mux.HandleFunc("GET /api/analytics/live-activity", requireAuth(s.handleAnalyticsLiveActivity))
	mux.HandleFunc("GET /api/analytics/top-domains", requireAuth(s.handleAnalyticsTopDomains))
	mux.HandleFunc("GET /api/analytics/top-blocked-domains", requireAuth(s.handleAnalyticsTopBlockedDomains))
	mux.HandleFunc("GET /api/analytics/query-log", requireAuth(s.handleAnalyticsQueryLog))
	mux.HandleFunc("GET /api/statistics/export", requireAuth(s.handleStatisticsExport))

	mux.HandleFunc("GET /api/blocklists", requireAuth(s.handleListBlocklists))
	mux.HandleFunc("POST /api/blocklists", requireAuth(s.handleCreateBlocklist))
	mux.HandleFunc("POST /api/blocklists/settings", requireAuth(s.handleBlocklistSettings))
	mux.HandleFunc("POST /api/blocklists/refresh-all", requireAuth(s.handleRefreshAllBlocklists))
	mux.HandleFunc("GET /api/blocklists/jobs/{id}", requireAuth(s.handleBlocklistJob))
	mux.HandleFunc("POST /api/blocklists/{id}/interval", requireAuth(s.handleSetBlocklistInterval))
	mux.HandleFunc("POST /api/blocklists/{id}/toggle", requireAuth(s.handleToggleBlocklist))
	mux.HandleFunc("POST /api/blocklists/{id}/refresh", requireAuth(s.handleRefreshOneBlocklist))
	mux.HandleFunc("DELETE /api/blocklists/{id}", requireAuth(s.handleDeleteBlocklist))

	mux.HandleFunc("GET /api/local-dns", requireAuth(s.handleListLocalDNS))
	mux.HandleFunc("POST /api/local-dns", requireAuth(s.handleCreateLocalDNS))
	mux.HandleFunc("PATCH /api/local-dns/{id}", requireAuth(s.handleUpdateLocalDNS))
	mux.HandleFunc("DELETE /api/local-dns/{id}", requireAuth(s.handleDeleteLocalDNS))

	mux.HandleFunc("GET /api/upstreams", requireAuth(s.handleListUpstreams))
	mux.HandleFunc("POST /api/upstreams", requireAuth(s.handleCreateUpstream))
	mux.HandleFunc("PUT /api/upstreams/{id}", requireAuth(s.handleUpdateUpstream))
	mux.HandleFunc("POST /api/upstreams/{id}/enable", requireAuth(s.handleEnableUpstream))
	mux.HandleFunc("POST /api/upstreams/{id}/disable", requireAuth(s.handleDisableUpstream))
	mux.HandleFunc("DELETE /api/upstreams/{id}", requireAuth(s.handleDeleteUpstream))
	mux.HandleFunc("POST /api/upstreams/reorder", requireAuth(s.handleReorderUpstreams))

	mux.HandleFunc("GET /api/groups", requireAuth(s.handleListGroups))
	mux.HandleFunc("POST /api/groups", requireAuth(s.handleCreateGroup))
	mux.HandleFunc("GET /api/clients", requireAuth(s.handleListClients))
	mux.HandleFunc("POST /api/clients", requireAuth(s.handleCreateClient))
	mux.HandleFunc("POST /api/clients/{id}/identifiers", requireAuth(s.handleAddClientIdentifier))
	mux.HandleFunc("POST /api/clients/{id}/groups", requireAuth(s.handleAddClientGroup))

	mux.HandleFunc("GET /api/policy/global", requireAuth(s.handleGetGlobalPolicy))
	mux.HandleFunc("PUT /api/policy/global", requireAuth(s.handlePutGlobalPolicy))
	mux.HandleFunc("PUT /api/policy/network/{id}", requireAuth(s.handlePutNetworkPolicy))
	mux.HandleFunc("PUT /api/policy/group/{id}", requireAuth(s.handlePutGroupPolicy))
	mux.HandleFunc("PUT /api/policy/client/{id}", requireAuth(s.handlePutClientPolicy))
	mux.HandleFunc("GET /api/networks", requireAuth(s.handleListNetworks))
	mux.HandleFunc("POST /api/networks", requireAuth(s.handleCreateNetwork))

	mux.HandleFunc("GET /api/custom-rules", requireAuth(s.handleListCustomRules))
	mux.HandleFunc("POST /api/custom-rules", requireAuth(s.handleCreateCustomRule))
	mux.HandleFunc("PUT /api/custom-rules/{id}", requireAuth(s.handleUpdateCustomRule))
	mux.HandleFunc("POST /api/custom-rules/{id}/toggle", requireAuth(s.handleToggleCustomRule))
	mux.HandleFunc("DELETE /api/custom-rules/{id}", requireAuth(s.handleDeleteCustomRule))
	mux.HandleFunc("POST /api/custom-rules/bulk-enable", requireAuth(s.handleBulkEnableCustomRules))
	mux.HandleFunc("POST /api/custom-rules/bulk-disable", requireAuth(s.handleBulkDisableCustomRules))
	mux.HandleFunc("POST /api/custom-rules/bulk-delete", requireAuth(s.handleBulkDeleteCustomRules))
	mux.HandleFunc("POST /api/custom-rules/reorder", requireAuth(s.handleReorderCustomRules))

	mux.HandleFunc("GET /api/backup/categories", requireAuth(s.handleListBackupCategories))
	mux.HandleFunc("GET /api/backup/appliance", requireAuth(s.handleListBackups))
	mux.HandleFunc("POST /api/backup/appliance", requireAuth(s.handleCreateBackup))
	mux.HandleFunc("POST /api/backup/appliance/upload", requireAuth(s.handleUploadBackup))
	mux.HandleFunc("POST /api/backup/appliance/{name}/validate", requireAuth(s.handlePreviewBackup))
	mux.HandleFunc("POST /api/backup/appliance/{name}/restore", requireAuth(s.handleRestoreBackup))
	mux.HandleFunc("DELETE /api/backup/appliance/{name}", requireAuth(s.handleDeleteBackup))

	mux.HandleFunc("GET /api/dns-transports", requireAuth(s.handleGetDNSTransports))
	mux.HandleFunc("PUT /api/dns-transports", requireAuth(s.handleUpdateDNSTransports))
	mux.HandleFunc("GET /api/tls/status", requireAuth(s.handleTLSStatus))

	mux.HandleFunc("GET /api/notifications", requireAuth(s.handleListNotificationProviders))
	mux.HandleFunc("POST /api/notifications", requireAuth(s.handleCreateNotificationProvider))
	mux.HandleFunc("POST /api/notifications/{id}/toggle", requireAuth(s.handleToggleNotificationProvider))
	mux.HandleFunc("DELETE /api/notifications/{id}", requireAuth(s.handleDeleteNotificationProvider))

	mux.HandleFunc("/", s.handleStatic)

	return Instrument(s.Log, mux)
}
