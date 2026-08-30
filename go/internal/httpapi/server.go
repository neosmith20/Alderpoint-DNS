package httpapi

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"alderpointdns/go-controlplane/internal/auditlog"
	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/bootstrap"
	"alderpointdns/go-controlplane/internal/clientalias"
	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/dnsanalytics"
	"alderpointdns/go-controlplane/internal/dnsperf"
	"alderpointdns/go-controlplane/internal/dnsruntime"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/domainrouting"
	"alderpointdns/go-controlplane/internal/filterimport"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/importer"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/notifications"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/policyentities"
	"alderpointdns/go-controlplane/internal/replication"
	"alderpointdns/go-controlplane/internal/softwareupdates"
	"alderpointdns/go-controlplane/internal/secretbackup"
	"alderpointdns/go-controlplane/internal/secretstore"
	"alderpointdns/go-controlplane/internal/upstreams"
)

type Server struct {
	DB   *sql.DB
	Auth *auth.Store
	// AuditLog backs Administration's Recent Administrative Activity
	// table -- appliance-wide coverage via audited() (see
	// audit_middleware.go) plus a handful of hand-instrumented
	// security-relevant call sites (see internal/auditlog's own doc
	// comment). nil is a valid, supported state in tests -- Record
	// becomes a no-op.
	AuditLog *auditlog.Service
	// Bootstrap gates first-run owner setup with a real one-time
	// capability -- see internal/bootstrap's doc comment. Required
	// (never nil in practice; cmd/alderpointdns-go always wires it) --
	// a nil Bootstrap would mean setup has no gate at all, which
	// handleSetup treats as a hard failure, never a silent bypass.
	Bootstrap  *bootstrap.Manager
	Blocklists *blocklists.Service
	LocalDNS   *localdns.Service
	// ClientAliases is nil unless wired at startup (cmd/alderpointdns-go
	// always wires it in practice, matching every other native-Go
	// service). See internal/clientalias's own doc comment: display-only
	// CIDR->name mapping, never a DNS-answering record.
	ClientAliases *clientalias.Service
	// Importer is nil unless wired at startup -- nil means the real
	// preview/apply/rollback job workflow (POST /api/import/jobs etc.)
	// reports unavailable; the older one-shot POST /api/import/hosts
	// endpoint (s.LocalDNS-backed directly) is unaffected either way.
	Importer      *importer.Service
	Upstreams     *upstreams.Service
	Clients       *clients.Service
	Policy         *policy.Service
	PolicyEntities *policyentities.Service
	DomainRouting  *domainrouting.Service
	CustomRules   *customrules.Service
	Backup          *backup.Service
	SoftwareUpdates *softwareupdates.Service
	SecretBackup  *secretbackup.Service
	FilterImport  *filterimport.Service
	DNSTransports *dnstransports.Service
	Notifications *notifications.Service
	Replication   *replication.Service
	StaticDir     string
	Log           *slog.Logger

	// TLSCertPath/TLSKeyPath are this control plane's OWN real,
	// currently-served management TLS certificate/key -- the same
	// paths appliance.yaml's web.tls_cert_path/tls_key_path already
	// point at (the web server needs them just to start). Upload/
	// replace (POST /api/tls/replace) writes here; a restart is
	// required to actually serve the new pair, matching Python's own
	// real, disclosed behavior for the identical reason (a process-
	// level TLS listener does not hot-reload its certificate).
	TLSCertPath, TLSKeyPath string

	// DNSCryptBinary overrides the "dnsdist" binary name/path used to
	// generate real DNSCrypt provider/resolver key material (internal/
	// dnscryptprovision) -- empty means "dnsdist" (looked up on PATH),
	// matching every other real-binary invocation in this codebase.
	DNSCryptBinary string

	// HostAgent is nil unless -hostagent-socket was given at startup --
	// nil means Cache/Replication/Network/Logs/Software-Updates all
	// honestly report unavailable, same nil-safe contract as every
	// other optional boundary. See internal/hostagentd's doc comment:
	// this is the ONLY thing that ever gives this web process reach
	// into privileged host operations, and even then only through this
	// one narrow, allowlisted client -- never directly.
	HostAgent *hostagent.Client

	// DNSRuntime is nil unless a full DNS-runtime deployment (host-agent
	// plus BIND/dnsdist listen/proxy addresses) was configured at
	// startup -- nil means the DNS Runtime page always honestly reports
	// "unavailable" rather than a compile error. See
	// internal/dnsruntime's doc comment.
	DNSRuntime *dnsruntime.Orchestrator

	// Analytics is nil unless -analytics-db was given a real path at
	// startup -- every analytics handler must treat nil as "degraded",
	// never as a programming error. Backed by internal/dnsanalytics.Reader
	// in production (see cmd/alderpointdns-go's "web" wiring) -- an
	// interface here (see analytics_iface.go) rather than a concrete
	// type only so tests can substitute a fake.
	Analytics AnalyticsReader

	// RawQueryLog is nil unless -analytics-db was given a real path at
	// startup -- same "nil means degraded, never a programming error"
	// contract as Analytics above (the two are backed by the same
	// internal/dnsanalytics.Reader in production; this is a second,
	// narrower interface only because the raw per-query log and the
	// aggregate/time-series views used to be two entirely separate
	// Python-era compatibility boundaries -- see analytics_iface.go).
	RawQueryLog RawQueryLogReader

	// AnalyticsSettings is nil unless -analytics-db was given a real
	// path at startup (same gate as Analytics/RawQueryLog above) --
	// backs GET/PUT /api/statistics/settings (Statistics settings
	// parity, see handlers_statistics_settings.go) and is the same
	// *dnsanalytics.SettingsHolder the live analytics Writer reads on
	// its own hot path, so a save here takes effect immediately with no
	// restart.
	AnalyticsSettings *dnsanalytics.SettingsHolder

	// DNSPerf is nil unless a full DNS-runtime deployment was
	// configured at startup -- same nil-safe contract as DNSRuntime
	// above. See internal/dnsperf's doc comment: the real "Safe DNS
	// Benchmark" (System Status) exchanges real DNS/DoT/DoH packets
	// against this appliance's own Go-managed dnsdist/BIND listeners
	// via apdns-hostagent, never synthesized numbers.
	DNSPerf *dnsperf.Service

	// Secrets is nil unless a host-control agent is configured -- same
	// nil-safe contract as HostAgent above. See internal/secretstore's
	// doc comment: this is the native Go secrets subsystem's web-side
	// half (ciphertext storage + metadata only, never plaintext).
	Secrets *secretstore.Service

	// DNSPerfBindPlainAddr is BIND's own unproxied loopback listener
	// address for this deployment (matches apdns-hostagent's
	// -dns-runtime-bind-plain-port) -- purely for the "BIND direct hot
	// A response" benchmark case's display Server/Port fields (the
	// safety-relevant actual dialing happens entirely inside
	// apdns-hostagent, see internal/hostagentd/ops_dnsperf.go). Empty =
	// that one case is omitted, same "optional, never fatal" contract
	// as every other compatibility boundary.
	DNSPerfBindPlainAddr string

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
	mux.HandleFunc("POST /api/setup/bootstrap", s.handleSetupBootstrap)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", requireAuth(s.handleLogout))
	mux.HandleFunc("GET /api/session", requireAuth(s.handleSession))
	mux.HandleFunc("POST /api/session/revoke-others", requireAuth(s.handleRevokeOtherSessions))
	mux.HandleFunc("POST /api/session/password", requireAuth(s.handleChangePassword))
	mux.HandleFunc("GET /api/administration/sessions", requireAuth(s.handleListSessions))
	mux.HandleFunc("GET /api/administration/audit-log", requireAuth(s.handleListAuditLog))
	mux.HandleFunc("GET /api/system/status", requireAuth(s.handleSystemStatus))
	mux.HandleFunc("GET /api/dashboard/summary", requireAuth(s.handleDashboardSummary))
	mux.HandleFunc("GET /api/protection/status", requireAuth(s.handleProtectionStatus))
	mux.HandleFunc("POST /api/protection/toggle", requireAuth(s.handleProtectionToggle))
	mux.HandleFunc("GET /api/analytics/timeseries", requireAuth(s.handleAnalyticsTimeseries))
	mux.HandleFunc("GET /api/analytics/live-activity", requireAuth(s.handleAnalyticsLiveActivity))
	mux.HandleFunc("GET /api/analytics/top-domains", requireAuth(s.handleAnalyticsTopDomains))
	mux.HandleFunc("GET /api/analytics/top-blocked-domains", requireAuth(s.handleAnalyticsTopBlockedDomains))
	mux.HandleFunc("GET /api/analytics/top-clients", requireAuth(s.handleAnalyticsTopClients))
	mux.HandleFunc("GET /api/analytics/top-upstreams", requireAuth(s.handleAnalyticsTopUpstreams))
	mux.HandleFunc("GET /api/analytics/breakdown", requireAuth(s.handleAnalyticsBreakdown))
	mux.HandleFunc("GET /api/analytics/query-log", requireAuth(s.handleAnalyticsQueryLog))
	mux.HandleFunc("GET /api/statistics/export", requireAuth(s.handleStatisticsExport))
	mux.HandleFunc("POST /api/statistics/clear", requireAuth(s.handleStatisticsClear))
	mux.HandleFunc("GET /api/statistics/settings", requireAuth(s.handleGetAnalyticsSettings))
	mux.HandleFunc("PUT /api/statistics/settings", requireAuth(s.handleUpdateAnalyticsSettings))

	mux.HandleFunc("GET /api/blocklists", requireAuth(s.handleListBlocklists))
	mux.HandleFunc("POST /api/blocklists", requireAuth(s.audited("blocklists_create", s.handleCreateBlocklist)))
	mux.HandleFunc("POST /api/blocklists/settings", requireAuth(s.audited("blocklists_settings_update", s.handleBlocklistSettings)))
	mux.HandleFunc("GET /api/blocklists/categories", requireAuth(s.handleListBlocklistCategories))
	mux.HandleFunc("POST /api/blocklists/categories", requireAuth(s.audited("blocklists_categories_create", s.handleCreateBlocklistCategory)))
	mux.HandleFunc("POST /api/blocklists/categories/{id}/rename", requireAuth(s.audited("blocklists_categories_rename", s.handleRenameBlocklistCategory)))
	mux.HandleFunc("DELETE /api/blocklists/categories/{id}", requireAuth(s.audited("blocklists_categories_delete", s.handleDeleteBlocklistCategory)))
	mux.HandleFunc("POST /api/blocklists/refresh-all", requireAuth(s.audited("blocklists_refresh_all", s.handleRefreshAllBlocklists)))
	mux.HandleFunc("GET /api/blocklists/jobs/{id}", requireAuth(s.handleBlocklistJob))
	mux.HandleFunc("POST /api/blocklists/{id}/interval", requireAuth(s.audited("blocklists_interval_set", s.handleSetBlocklistInterval)))
	mux.HandleFunc("POST /api/blocklists/{id}/toggle", requireAuth(s.audited("blocklists_toggle", s.handleToggleBlocklist)))
	mux.HandleFunc("POST /api/blocklists/{id}/refresh", requireAuth(s.audited("blocklists_refresh", s.handleRefreshOneBlocklist)))
	mux.HandleFunc("DELETE /api/blocklists/{id}", requireAuth(s.audited("blocklists_delete", s.handleDeleteBlocklist)))

	mux.HandleFunc("GET /api/local-dns", requireAuth(s.handleListLocalDNS))
	mux.HandleFunc("POST /api/local-dns", requireAuth(s.audited("local_dns_create", s.handleCreateLocalDNS)))
	mux.HandleFunc("PATCH /api/local-dns/{id}", requireAuth(s.audited("local_dns_update", s.handleUpdateLocalDNS)))
	mux.HandleFunc("DELETE /api/local-dns/{id}", requireAuth(s.audited("local_dns_delete", s.handleDeleteLocalDNS)))
	mux.HandleFunc("GET /api/local-dns/aliases", requireAuth(s.handleListClientAliases))
	mux.HandleFunc("POST /api/local-dns/aliases", requireAuth(s.audited("local_dns_aliases_create", s.handleCreateClientAlias)))
	mux.HandleFunc("PATCH /api/local-dns/aliases/{id}", requireAuth(s.audited("local_dns_aliases_update", s.handleUpdateClientAlias)))
	mux.HandleFunc("DELETE /api/local-dns/aliases/{id}", requireAuth(s.audited("local_dns_aliases_delete", s.handleDeleteClientAlias)))

	mux.HandleFunc("GET /api/upstreams", requireAuth(s.handleListUpstreams))
	mux.HandleFunc("POST /api/upstreams", requireAuth(s.audited("upstreams_create", s.handleCreateUpstream)))
	mux.HandleFunc("PUT /api/upstreams/{id}", requireAuth(s.audited("upstreams_update", s.handleUpdateUpstream)))
	mux.HandleFunc("POST /api/upstreams/{id}/enable", requireAuth(s.audited("upstreams_enable", s.handleEnableUpstream)))
	mux.HandleFunc("POST /api/upstreams/{id}/disable", requireAuth(s.audited("upstreams_disable", s.handleDisableUpstream)))
	mux.HandleFunc("DELETE /api/upstreams/{id}", requireAuth(s.audited("upstreams_delete", s.handleDeleteUpstream)))
	mux.HandleFunc("POST /api/upstreams/reorder", requireAuth(s.audited("upstreams_reorder", s.handleReorderUpstreams)))
	mux.HandleFunc("GET /api/domain-routing", requireAuth(s.handleListDomainRoutes))
	mux.HandleFunc("POST /api/domain-routing", requireAuth(s.audited("domain_routing_create", s.handleCreateDomainRoute)))
	mux.HandleFunc("DELETE /api/domain-routing/{id}", requireAuth(s.audited("domain_routing_delete", s.handleDeleteDomainRoute)))
	mux.HandleFunc("GET /api/domain-routing/rulesets", requireAuth(s.handleListDomainRoutingRulesets))
	mux.HandleFunc("POST /api/domain-routing/rulesets", requireAuth(s.audited("domain_routing_rulesets_create", s.handleCreateDomainRoutingRuleset)))
	mux.HandleFunc("DELETE /api/domain-routing/rulesets/{id}", requireAuth(s.audited("domain_routing_rulesets_delete", s.handleDeleteDomainRoutingRuleset)))

	mux.HandleFunc("GET /api/policy-entities/filtering-profiles", requireAuth(s.handleListFilteringProfiles))
	mux.HandleFunc("POST /api/policy-entities/filtering-profiles", requireAuth(s.audited("policy_entities_filtering_profiles_create", s.handleCreateFilteringProfile)))
	mux.HandleFunc("PUT /api/policy-entities/filtering-profiles/{id}", requireAuth(s.audited("policy_entities_filtering_profiles_update", s.handleUpdateFilteringProfile)))
	mux.HandleFunc("DELETE /api/policy-entities/filtering-profiles/{id}", requireAuth(s.audited("policy_entities_filtering_profiles_delete", s.handleDeleteFilteringProfile)))
	mux.HandleFunc("GET /api/policy-entities/parental-policies", requireAuth(s.handleListParentalPolicies))
	mux.HandleFunc("POST /api/policy-entities/parental-policies", requireAuth(s.audited("policy_entities_parental_policies_create", s.handleCreateParentalPolicy)))
	mux.HandleFunc("PUT /api/policy-entities/parental-policies/{id}", requireAuth(s.audited("policy_entities_parental_policies_update", s.handleUpdateParentalPolicy)))
	mux.HandleFunc("DELETE /api/policy-entities/parental-policies/{id}", requireAuth(s.audited("policy_entities_parental_policies_delete", s.handleDeleteParentalPolicy)))
	mux.HandleFunc("GET /api/policy-entities/security-policies", requireAuth(s.handleListSecurityPolicies))
	mux.HandleFunc("POST /api/policy-entities/security-policies", requireAuth(s.audited("policy_entities_security_policies_create", s.handleCreateSecurityPolicy)))
	mux.HandleFunc("PUT /api/policy-entities/security-policies/{id}", requireAuth(s.audited("policy_entities_security_policies_update", s.handleUpdateSecurityPolicy)))
	mux.HandleFunc("DELETE /api/policy-entities/security-policies/{id}", requireAuth(s.audited("policy_entities_security_policies_delete", s.handleDeleteSecurityPolicy)))
	mux.HandleFunc("GET /api/policy-entities/service-blocking-rulesets", requireAuth(s.handleListServiceBlockingRulesets))
	mux.HandleFunc("POST /api/policy-entities/service-blocking-rulesets", requireAuth(s.audited("policy_entities_service_blocking_rulesets_create", s.handleCreateServiceBlockingRuleset)))
	mux.HandleFunc("PUT /api/policy-entities/service-blocking-rulesets/{id}", requireAuth(s.audited("policy_entities_service_blocking_rulesets_update", s.handleUpdateServiceBlockingRuleset)))
	mux.HandleFunc("DELETE /api/policy-entities/service-blocking-rulesets/{id}", requireAuth(s.audited("policy_entities_service_blocking_rulesets_delete", s.handleDeleteServiceBlockingRuleset)))

	mux.HandleFunc("GET /api/groups", requireAuth(s.handleListGroups))
	mux.HandleFunc("POST /api/groups", requireAuth(s.audited("groups_create", s.handleCreateGroup)))
	mux.HandleFunc("GET /api/clients", requireAuth(s.handleListClients))
	mux.HandleFunc("POST /api/clients", requireAuth(s.audited("clients_create", s.handleCreateClient)))
	mux.HandleFunc("PATCH /api/clients/{id}", requireAuth(s.audited("clients_update", s.handleUpdateClient)))
	mux.HandleFunc("DELETE /api/clients/{id}", requireAuth(s.audited("clients_delete", s.handleDeleteClient)))
	mux.HandleFunc("POST /api/clients/{id}/enabled", requireAuth(s.audited("clients_set_enabled", s.handleSetClientEnabled)))
	mux.HandleFunc("GET /api/clients/observed", requireAuth(s.handleListObservedClients))
	mux.HandleFunc("POST /api/clients/{id}/identifiers", requireAuth(s.audited("clients_identifiers_create", s.handleAddClientIdentifier)))
	mux.HandleFunc("POST /api/clients/{id}/identifiers/generate", requireAuth(s.audited("clients_identifiers_generate", s.handleGenerateClientID)))
	mux.HandleFunc("POST /api/clients/{id}/identifiers/{identifierId}/revoke", requireAuth(s.audited("clients_identifiers_revoke", s.handleRevokeClientIdentifier)))
	mux.HandleFunc("POST /api/clients/{id}/identifiers/{identifierId}/regenerate", requireAuth(s.audited("clients_identifiers_regenerate", s.handleRegenerateClientIdentifier)))
	mux.HandleFunc("DELETE /api/clients/{id}/identifiers/{identifierId}", requireAuth(s.audited("clients_identifiers_delete", s.handleDeleteClientIdentifier)))
	mux.HandleFunc("POST /api/clients/{id}/domain-overrides", requireAuth(s.audited("clients_domain_overrides_create", s.handleAddDomainOverride)))
	mux.HandleFunc("DELETE /api/clients/{id}/domain-overrides/{overrideId}", requireAuth(s.audited("clients_domain_overrides_delete", s.handleDeleteDomainOverride)))
	mux.HandleFunc("POST /api/clients/{id}/groups", requireAuth(s.audited("clients_group_add", s.handleAddClientGroup)))
	mux.HandleFunc("DELETE /api/clients/{id}/groups/{groupId}", requireAuth(s.audited("clients_group_remove", s.handleRemoveClientGroup)))

	mux.HandleFunc("GET /api/policy/global", requireAuth(s.handleGetGlobalPolicy))
	mux.HandleFunc("PUT /api/policy/global", requireAuth(s.audited("policy_global_update", s.handlePutGlobalPolicy)))
	mux.HandleFunc("PUT /api/policy/network/{id}", requireAuth(s.audited("policy_network_update", s.handlePutNetworkPolicy)))
	mux.HandleFunc("PUT /api/policy/group/{id}", requireAuth(s.audited("policy_group_update", s.handlePutGroupPolicy)))
	mux.HandleFunc("PUT /api/policy/client/{id}", requireAuth(s.audited("policy_client_update", s.handlePutClientPolicy)))
	mux.HandleFunc("GET /api/policy/explain", requireAuth(s.handlePolicyExplain))
	mux.HandleFunc("GET /api/networks", requireAuth(s.handleListNetworks))
	mux.HandleFunc("POST /api/networks", requireAuth(s.audited("networks_create", s.handleCreateNetwork)))

	mux.HandleFunc("GET /api/custom-rules", requireAuth(s.handleListCustomRules))
	mux.HandleFunc("POST /api/custom-rules", requireAuth(s.audited("custom_rules_create", s.handleCreateCustomRule)))
	mux.HandleFunc("PUT /api/custom-rules/{id}", requireAuth(s.audited("custom_rules_update", s.handleUpdateCustomRule)))
	mux.HandleFunc("POST /api/custom-rules/{id}/toggle", requireAuth(s.audited("custom_rules_toggle", s.handleToggleCustomRule)))
	mux.HandleFunc("DELETE /api/custom-rules/{id}", requireAuth(s.audited("custom_rules_delete", s.handleDeleteCustomRule)))
	mux.HandleFunc("POST /api/custom-rules/bulk-enable", requireAuth(s.audited("custom_rules_bulk_enable", s.handleBulkEnableCustomRules)))
	mux.HandleFunc("POST /api/custom-rules/bulk-disable", requireAuth(s.audited("custom_rules_bulk_disable", s.handleBulkDisableCustomRules)))
	mux.HandleFunc("POST /api/custom-rules/bulk-delete", requireAuth(s.audited("custom_rules_bulk_delete", s.handleBulkDeleteCustomRules)))
	mux.HandleFunc("POST /api/custom-rules/reorder", requireAuth(s.audited("custom_rules_reorder", s.handleReorderCustomRules)))
	mux.HandleFunc("GET /api/custom-rules/test-domain", requireAuth(s.handleTestDomain))

	mux.HandleFunc("GET /api/backup/categories", requireAuth(s.handleListBackupCategories))
	mux.HandleFunc("GET /api/backup/appliance", requireAuth(s.handleListBackups))
	mux.HandleFunc("POST /api/backup/appliance", requireAuth(s.audited("backup_appliance_create", s.handleCreateBackup)))
	mux.HandleFunc("POST /api/backup/appliance/upload", requireAuth(s.audited("backup_appliance_upload", s.handleUploadBackup)))
	mux.HandleFunc("POST /api/backup/appliance/{name}/validate", requireAuth(s.audited("backup_appliance_validate", s.handlePreviewBackup)))
	mux.HandleFunc("POST /api/backup/appliance/{name}/restore", requireAuth(s.audited("backup_appliance_restore", s.handleRestoreBackup)))
	mux.HandleFunc("DELETE /api/backup/appliance/{name}", requireAuth(s.audited("backup_appliance_delete", s.handleDeleteBackup)))
	mux.HandleFunc("GET /api/backup/schedule", requireAuth(s.handleGetBackupSchedule))
	mux.HandleFunc("PUT /api/backup/schedule", requireAuth(s.audited("backup_schedule_update", s.handleSetBackupSchedule)))
	mux.HandleFunc("GET /api/backup/secrets", requireAuth(s.handleListSecretBackups))
	mux.HandleFunc("POST /api/backup/secrets", requireAuth(s.audited("backup_secrets_create", s.handleCreateSecretBackup)))
	mux.HandleFunc("POST /api/backup/secrets/{name}/validate", requireAuth(s.audited("backup_secrets_validate", s.handleValidateSecretBackup)))
	mux.HandleFunc("POST /api/backup/secrets/{name}/restore", requireAuth(s.audited("backup_secrets_restore", s.handleRestoreSecretBackup)))
	mux.HandleFunc("DELETE /api/backup/secrets/{name}", requireAuth(s.audited("backup_secrets_delete", s.handleDeleteSecretBackup)))

	mux.HandleFunc("GET /api/dns-transports", requireAuth(s.handleGetDNSTransports))
	mux.HandleFunc("PUT /api/dns-transports", requireAuth(s.audited("dns_transports_update", s.handleUpdateDNSTransports)))
	mux.HandleFunc("GET /api/dns-transports/mobileconfig/{protocol}", requireAuth(s.handleDNSTransportMobileconfig))
	mux.HandleFunc("POST /api/dns-transports/dnscrypt/rotate", requireAuth(s.audited("dns_transports_dnscrypt_rotate", s.handleDNSCryptRotate)))
	mux.HandleFunc("GET /api/tls/status", requireAuth(s.handleTLSStatus))
	mux.HandleFunc("POST /api/tls/replace", requireAuth(s.audited("tls_replace", s.handleTLSReplace)))

	mux.HandleFunc("GET /api/notifications", requireAuth(s.handleListNotificationProviders))
	mux.HandleFunc("POST /api/notifications", requireAuth(s.audited("notifications_create", s.handleCreateNotificationProvider)))
	mux.HandleFunc("POST /api/notifications/{id}/toggle", requireAuth(s.audited("notifications_toggle", s.handleToggleNotificationProvider)))
	mux.HandleFunc("DELETE /api/notifications/{id}", requireAuth(s.audited("notifications_delete", s.handleDeleteNotificationProvider)))
	mux.HandleFunc("PUT /api/notifications/{id}/secret", requireAuth(s.audited("notifications_secret_set", s.handleSetNotificationSecret)))
	mux.HandleFunc("DELETE /api/notifications/{id}/secret", requireAuth(s.audited("notifications_secret_revoke", s.handleRevokeNotificationSecret)))
	mux.HandleFunc("POST /api/notifications/{id}/test", requireAuth(s.audited("notifications_test", s.handleTestNotificationProvider)))
	// Deliberately NOT nested under /api/notifications/{id}/... -- that
	// wildcard already exists for provider sub-resources (.../secret,
	// .../test), and net/http's own ServeMux refuses to register two
	// patterns where neither is more specific ("/api/notifications/
	// subscriptions/{id}" vs "/api/notifications/{id}/secret" both
	// match "/api/notifications/subscriptions/secret") -- a real
	// startup panic this exact collision produced, caught immediately
	// by trying to launch a disposable fixture, not by inspection.
	mux.HandleFunc("GET /api/notification-event-categories", requireAuth(s.handleListEventCategories))
	mux.HandleFunc("GET /api/notification-subscriptions", requireAuth(s.handleListNotificationSubscriptions))
	mux.HandleFunc("POST /api/notification-subscriptions", requireAuth(s.handleCreateNotificationSubscription))
	mux.HandleFunc("DELETE /api/notification-subscriptions/{id}", requireAuth(s.handleDeleteNotificationSubscription))
	mux.HandleFunc("GET /api/notification-history", requireAuth(s.handleListNotificationHistory))

	mux.HandleFunc("POST /api/import/hosts", requireAuth(s.audited("import_hosts_create", s.handleImportHosts)))
	mux.HandleFunc("POST /api/import/jobs", requireAuth(s.audited("import_jobs_create", s.handleCreateImportJob)))
	mux.HandleFunc("GET /api/import/jobs", requireAuth(s.handleListImportJobs))
	mux.HandleFunc("GET /api/import/jobs/{id}", requireAuth(s.handleGetImportJob))
	mux.HandleFunc("POST /api/import/jobs/{id}/apply", requireAuth(s.audited("import_job_apply", s.handleApplyImportJob)))
	mux.HandleFunc("POST /api/import/jobs/{id}/rollback", requireAuth(s.audited("import_job_rollback", s.handleRollbackImportJob)))
	mux.HandleFunc("POST /api/import/legacy-appliance", requireAuth(s.audited("import_legacy_appliance_create", s.handleImportLegacyAppliance)))
	mux.HandleFunc("POST /api/import/apdnsbak", requireAuth(s.audited("import_apdnsbak_create", s.handleImportApdnsbak)))
	mux.HandleFunc("POST /api/import/pihole", requireAuth(s.audited("import_pihole_create", s.handleImportPihole)))
	mux.HandleFunc("POST /api/import/adguard-yaml", requireAuth(s.audited("import_adguard_yaml_create", s.handleImportAdGuardYAML)))

	mux.HandleFunc("GET /api/cache/status", requireAuth(s.handleCacheStatus))
	mux.HandleFunc("POST /api/cache/flush", requireAuth(s.handleCacheFlush))
	mux.HandleFunc("POST /api/cache/dnsdist-restart", requireAuth(s.handleCacheDnsdistRestart))

	mux.HandleFunc("GET /api/dns/performance", requireAuth(s.handleDNSPerfStatus))
	mux.HandleFunc("POST /api/dns/performance/benchmark", requireAuth(s.handleDNSPerfBenchmark))
	mux.HandleFunc("DELETE /api/dns/performance", requireAuth(s.handleDNSPerfClear))

	s.registerReplicationRoutes(mux)

	mux.HandleFunc("GET /api/network/status", requireAuth(s.handleNetworkStatus))
	mux.HandleFunc("POST /api/network/apply", requireAuth(s.audited("network_apply", s.handleNetworkApply)))
	mux.HandleFunc("POST /api/network/confirm", requireAuth(s.audited("network_confirm", s.handleNetworkConfirm)))
	mux.HandleFunc("POST /api/network/rollback", requireAuth(s.audited("network_rollback", s.handleNetworkRollback)))

	mux.HandleFunc("GET /api/logs/units", requireAuth(s.handleLogsListUnits))
	mux.HandleFunc("GET /api/logs/{unit}", requireAuth(s.handleLogsRead))

	mux.HandleFunc("GET /api/updates/status", requireAuth(s.handleUpdateCheck))
	mux.HandleFunc("POST /api/updates/stage", requireAuth(s.handleUpdateStage))
	mux.HandleFunc("POST /api/updates/apply", requireAuth(s.handleUpdateApply))
	mux.HandleFunc("GET /api/updates/channel", requireAuth(s.handleGetUpdateChannel))
	mux.HandleFunc("PUT /api/updates/channel", requireAuth(s.handleSetUpdateChannel))
	mux.HandleFunc("POST /api/updates/check", requireAuth(s.handleCheckForUpdate))
	mux.HandleFunc("POST /api/updates/download-and-stage", requireAuth(s.handleUpdateDownloadAndStage))

	mux.HandleFunc("GET /api/dns-runtime/status", requireAuth(s.handleDNSRuntimeStatus))
	mux.HandleFunc("POST /api/dns-runtime/apply", requireAuth(s.handleDNSRuntimeApply))

	mux.HandleFunc("/", s.handleStatic)

	return Instrument(s.Log, mux)
}
