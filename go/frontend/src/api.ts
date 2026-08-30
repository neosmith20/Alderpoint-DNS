// Typed API client, hand-maintained against ../openapi.yaml (see that
// file's header and frontend/src/api.contract.test.ts). Every mutating
// call attaches X-CSRF-Token automatically via setCsrfToken().

export interface Subscription {
  subscription_id: string;
  name: string;
  url: string;
  category: string;
  enabled: boolean;
  created_at: string;
  last_refresh_at: string | null;
  last_status: string | null;
  last_error: string | null;
  rule_count: number | null;
  last_success_at: string | null;
  next_update_at: string | null;
  update_duration_ms: number | null;
  update_interval_seconds: number | null;
  failure_count: number;
  first_failure_at: string | null;
  update_in_progress: boolean;
  effective_interval_seconds: number;
  attention_required: boolean;
}

export interface IntervalPreset {
  seconds: number;
  label: string;
}

export interface BlocklistsResponse {
  subscriptions: Subscription[];
  settings: { default_interval_seconds: number; interval_presets: IntervalPreset[] };
}

export interface BlocklistCategory {
  id: number;
  name: string;
  created_at: string;
  updated_at: string;
}

export interface Job {
  id: number;
  kind: string;
  subscription_ids: string[];
  state: "queued" | "running" | "succeeded" | "failed";
  results?: { subscription_id: string; status: string; rule_count?: number; error?: string; duration_ms: number }[];
  started_at: string;
  finished_at: string | null;
}

export interface LocalDnsRecord {
  id: number;
  name: string;
  record_type: "A" | "AAAA" | "CNAME" | "PTR";
  value: string;
  ttl: number;
  enabled: boolean;
}

// ClientAlias: V1.1.1's Client Aliases (local_dns.py upsert_alias/
// alias_for_client) -- a CIDR-to-display-name mapping used to label a
// client address wherever one's shown (Dashboard, Query Log, Client
// analytics), when it isn't already a managed client's own identifier.
export interface ClientAlias {
  id: number;
  cidr: string;
  display_name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface BackupInfo {
  filename: string;
  size_bytes: number;
  format_version: number;
  created_at: string;
  source_version: string;
  control_db_schema_version: number;
  contents: string[];
  product: string;
  reason?: string;
  table_counts?: Record<string, number>;
  // encrypted (2026-08-29): true when this archive is passphrase-
  // protected. When true and no passphrase has been given yet, every
  // field above except filename/size_bytes/created_at is zero-valued --
  // real detail requires calling previewBackup/restoreBackup with the
  // correct passphrase.
  encrypted: boolean;
}

export interface BackupCategory {
  name: string;
  tables: string[];
}

export interface BackupScheduleSettings {
  enabled: boolean;
  interval_hours: number;
  retention_count: number;
  last_run_at?: string;
  last_status?: string;
  last_error?: string;
}

export interface SecretBackupInfo {
  name: string;
  created_at: string;
  secret_count: number;
  size_bytes: number;
}

export interface SecretBackupJob {
  id: number;
  kind: "create" | "restore";
  started_at: string;
  finished_at?: string;
  status: "succeeded" | "failed";
  filename?: string;
  secret_count: number;
  detail?: string;
}

export interface CustomRule {
  id: number;
  rule_type: "block" | "allow" | "regex_block" | "regex_allow" | "rewrite";
  pattern: string;
  rewrite_target: string | null;
  enabled: boolean;
  priority: number;
  created_at: string;
}

export interface PolicyLayer {
  filtering_profile_id: string | null;
  safesearch_mode: string | null;
  parental_policy_id: string | null;
  security_policy_id: string | null;
  service_blocking_ruleset_id: string | null;
  blocking_response_mode: string | null;
  custom_ipv4: string | null;
  custom_ipv6: string | null;
  upstream_profile_id: string | null;
  fallback_strategy: string | null;
  fallback_upstream_profile_id: string | null;
  ecs_mode: string | null;
  domain_routing_ruleset_id: string | null;
  query_log_enabled: boolean | null;
  statistics_enabled: boolean | null;
}

export const EMPTY_POLICY_LAYER: PolicyLayer = {
  filtering_profile_id: null,
  safesearch_mode: null,
  parental_policy_id: null,
  security_policy_id: null,
  service_blocking_ruleset_id: null,
  blocking_response_mode: null,
  custom_ipv4: null,
  custom_ipv6: null,
  upstream_profile_id: null,
  fallback_strategy: null,
  fallback_upstream_profile_id: null,
  ecs_mode: null,
  domain_routing_ruleset_id: null,
  query_log_enabled: null,
  statistics_enabled: null,
};

export interface ClientIdentifier {
  id: number;
  kind: "ipv4" | "ipv4_cidr" | "ipv6" | "ipv6_cidr" | "clientid";
  value: string;
  label: string;
  revoked_at?: string;
  doh_path?: string;
  sni_hostname?: string;
}

export interface ClientGroupRef {
  group_id: string;
  name: string;
  priority: number;
}

export interface ClientDomainOverride {
  id: number;
  client_id: number;
  override_type: "block" | "allow";
  pattern: string;
  created_at: string;
}

export interface ManagedClient {
  id: number;
  name: string;
  description: string;
  enabled: boolean;
  identifiers: ClientIdentifier[];
  groups: ClientGroupRef[];
  policy: PolicyLayer;
  domain_overrides: ClientDomainOverride[];
}

// ObservedClient: real recent-traffic "client" dimension from
// internal/pyanalytics's snapshot boundary (see
// GET /api/clients/observed's Go doc comment) -- an address that has
// actually queried recently, cross-referenced against every already-
// managed ipv4/ipv6 identifier. Not a persisted record: it disappears
// once its traffic window rolls off, same honesty contract as
// Dashboard's Top Domains.
export interface ObservedClient {
  address: string;
  query_count: number;
  managed: boolean;
  client_id?: number;
  // The most specific matching Client Alias's display name, when this
  // unmanaged address falls inside one -- same resolution the Clients
  // page's own Client analytics table already used. Absent when no
  // alias matches; the UI falls back to the raw address.
  alias_label?: string;
}

// ClientAnalyticsRow: one ranked row of the Clients page's "Client
// analytics" table (GET /api/analytics/top-clients), matching V1.1.1's
// clients_data() shape (app/analytics.py, read directly) field-for-field.
export interface ClientAnalyticsRow {
  raw_client: string;
  label: string;
  value: number;
  share: number;
  blocked: number;
  blocked_percent: number;
  last_seen: number;
  last_seen_iso: string;
}

export interface ClientGroupMember {
  id: number;
  name: string;
}

export interface NetworkWithPolicy {
  network_id: string;
  cidr: string;
  policy: PolicyLayer;
}

export interface ClientGroup {
  group_id: string;
  name: string;
  priority: number;
  members: ClientGroupMember[];
  policy: PolicyLayer;
}

export interface UpstreamEndpoint {
  address: string;
  tls_hostname: string | null;
  priority: number;
  weight: number;
  doh_path: string | null;
}

export interface UpstreamProfile {
  upstream_profile_id: string;
  name: string;
  transport: "plain" | "dot" | "doh";
  strategy: "ordered" | "failover" | "load_balanced";
  enabled: boolean;
  sort_order: number;
  order: number;
  endpoints: UpstreamEndpoint[];
}

export interface UpstreamEndpointInput {
  address: string;
  tls_hostname?: string | null;
  priority: number;
  weight: number;
  doh_path?: string | null;
}

export interface UpstreamProfileInput {
  name: string;
  transport: string;
  strategy: string;
  endpoints: UpstreamEndpointInput[];
}

export interface UpstreamMutationResult {
  status: string;
  dns_runtime?: DNSRuntimeApplyResult;
  was_last_enabled?: boolean;
}

export interface PolicyExplainResult {
  client_id: number;
  network_match: string | null;
  group_contributions: string[];
  fields: Record<string, { value: unknown; source: string }>;
}

export interface DomainRoute {
  id: number;
  match_kind: "exact" | "suffix";
  domain: string;
  upstream_profile_id: string;
  created_at: string;
}

export interface AnalyticsBucket {
  bucket_start: number;
  bucket_start_iso: string;
  total_queries: number;
  blocked_queries: number;
  cache_hits: number;
  cache_misses: number;
}

export interface AnalyticsTimeseriesResponse {
  degraded: boolean;
  degraded_reason?: string;
  granularity?: string;
  buckets: AnalyticsBucket[];
}

// AnalyticsSettings mirrors internal/dnsanalytics.Settings -- V1.1.1's
// real statistics_settings.html/analytics_settings row (webapp.py,
// app/analytics.py) field-for-field wherever this single-table,
// event-stream architecture has an honest equivalent. Two real V1
// fields (aggregate_retention_days, collection_interval) governed a
// separate poll-and-aggregate tier this architecture doesn't have and
// are deliberately not modeled -- see the backend's own doc comment.
export interface AnalyticsSettings {
  analytics_enabled: boolean;
  detailed_query_logging_enabled: boolean;
  privacy_mode: "full" | "anonymized_clients" | "aggregate_only";
  client_anonymization: "truncate" | "hash";
  detailed_retention_days: number;
  db_size_limit_bytes: number;
  recent_query_limit: number;
}

export interface AnalyticsTopRowsResponse {
  rows: [string, number][];
  columns: string[];
  degraded: boolean;
  degraded_reason?: string;
  aggregation_note?: string;
}

export interface QueryLogRow {
  id: number;
  ts: number;
  client: string;
  client_name: string;
  domain: string;
  qtype: string;
  protocol: string;
  rcode: string;
  latency_ms: number;
  blocked: boolean;
  block_reason: string;
  upstream: string;
  cache_status: string;
  cache_profile_id: string;
}

export interface QueryLogFilters {
  minutes: number;
  search?: string;
  domain?: string;
  client?: string;
  qtype?: string;
  protocol?: string;
  rcode?: string;
  upstream?: string;
  cache_status?: string;
  blocked_only?: boolean;
  limit?: number;
  offset?: number;
}

export interface DnsTransportSettings {
  dot_enabled: boolean;
  dot_port: number;
  doh_enabled: boolean;
  doh_port: number;
  doh_path: string;
  doq_enabled: boolean;
  doq_port: number;
  doh3_enabled: boolean;
  doh3_port: number;
  dnscrypt_enabled: boolean;
  dnscrypt_port: number;
  dnscrypt_provider_name: string;
  dnscrypt_identity_provisioned: boolean;
  dnscrypt_fingerprint?: string;
  dnscrypt_cert_serial?: number;
  dnscrypt_cert_valid_from?: number;
  dnscrypt_cert_valid_until?: number;
  dns_runtime?: DNSRuntimeApplyResult;
  server_hostname?: string;
}

export interface TlsStatus {
  active: boolean;
  subject?: string;
  not_valid_before?: string;
  not_valid_after?: string;
  san?: string[];
  is_self_signed?: boolean;
  error?: string;
}

// --- Host-agent-backed types (internal/hostagent / internal/hostagentd) ---

export interface BindCacheStats {
  available: boolean;
  error?: string;
  hits: number;
  misses: number;
  hit_ratio: number | null;
  cache_size_bytes: number | null;
}

export interface BindContextStatus {
  name: string;
  stats_port: number;
  rndc_port: number;
  reachable: boolean;
  rndc_status?: string;
  cache_stats?: BindCacheStats;
}

export interface CacheStatusResponse {
  bind: BindContextStatus[];
  dnsdist: { note: string };
}

export interface CacheFlushResult {
  results: { context: string; ok: boolean; detail?: string }[];
}

export interface DNSPerfSummary {
  count: number;
  success: number;
  timeouts: number;
  errors: number;
  p50_ms: number | null;
  p95_ms: number | null;
  p99_ms: number | null;
  max_ms: number | null;
  servfail: number;
  nxdomain: number;
}

export interface DNSPerfCaseResult {
  name: string;
  scope: string;
  server: string;
  port: number;
  domain: string;
  qtype: number;
  protocol: string;
  latency_scope: string;
  summary: DNSPerfSummary;
}

export interface DNSPerfReport {
  schema: number;
  generated_at: string;
  duration_seconds: number;
  notes: string[];
  cases: DNSPerfCaseResult[];
}

export interface DNSPerfStatusResponse {
  benchmark_running: boolean;
  last_error: string;
  report: DNSPerfReport | null;
  report_error?: string;
}

// Real Go-native Replication -- rebuilt against V1.1.1's actual
// owner-facing workflow (internal/replication, see its own doc
// comment): node identity, token-based enrollment, numbered
// content-hashed generations, mutual-TLS sync, drift detection.
export interface ReplicationSettings {
  node_id: string;
  role: "standalone" | "primary" | "replica";
  listen_host: string;
  listen_port: number;
  poll_interval_seconds: number;
  primary_address: string;
  paused: boolean;
  include_encryption_settings: boolean;
  last_applied_generation: number;
  last_applied_hash: string;
  last_sync_status: string;
  last_sync_at: string;
  drift_detected: boolean;
  drift_checked_at: string;
}

export interface ReplicationEnrollment {
  id: number;
  node_id: string;
  node_name: string;
  created_at: string;
  expires_at: string;
  status: "pending" | "consumed" | "revoked" | "expired";
  consumed_at?: string;
}

export interface ReplicationReplica {
  id: number;
  node_id: string;
  display_name: string;
  cert_fingerprint: string;
  cert_serial: string;
  enrolled_at: string;
  status: "active" | "paused" | "revoked";
  last_generation_acked: number;
  last_ack_hash: string;
  last_seen_at?: string;
  last_result: string;
}

export interface ReplicationGeneration {
  generation_number: number;
  created_at: string;
  source_node_id: string;
  schema_version: number;
  content_hash: string;
  section_keys: string[];
}

export interface ReplicationSyncResult {
  attempted_at: string;
  generation_number?: number;
  result: "success" | "up_to_date" | "no_generation" | "unreachable" | "skipped" | "failed" | "error";
  message: string;
}

export interface ReplicationIssuedToken {
  token: string;
  node_id: string;
  node_name: string;
  expires_at: string;
}

export interface ReplicationStatusResponse {
  settings: ReplicationSettings;
  enrollments?: ReplicationEnrollment[];
  replicas?: ReplicationReplica[];
  latest_generation?: ReplicationGeneration | null;
  listener_running?: boolean;
  sync_history?: ReplicationSyncResult[];
}

export interface NetworkApplyResult {
  status: string;
  interface: string;
  auto_revert_seconds: number;
}

export interface LogEntry {
  unit?: string;
  time: string;
  message: string;
}

export interface UpdateCheckResponse {
  current_version: string;
  staged: { version: string; sha256: string } | null;
}

export interface ImportHostsResult {
  imported: number;
  skipped: number;
  errors: string[];
}

export interface ImportPlanRow {
  index: number;
  name: string;
  record_type: string;
  value: string;
  ttl: number;
  conflict: boolean;
  conflict_detail?: string;
}

export interface ImportPlan {
  source_type: string;
  source_name: string;
  rows: ImportPlanRow[];
  parse_errors: string[];
}

export interface ImportJob {
  id: number;
  source_type: string;
  source_name: string;
  plan: ImportPlan;
  status: "pending" | "applied";
  result?: ImportHostsResult;
  snapshot_filename?: string;
  created_at: string;
  applied_at?: string;
}

export interface LegacyImportRowResult {
  table: string;
  key: string;
  action: "would_import" | "imported" | "skipped_duplicate" | "skipped_unsupported" | "rejected";
  detail?: string;
}

export interface LegacyImportTableSummary {
  source_count: number;
  imported: number;
  skipped: number;
  rejected: number;
}

export interface LegacyImportReport {
  dry_run: boolean;
  started_at: string;
  finished_at: string;
  snapshot_filename?: string;
  tables: Record<string, LegacyImportTableSummary>;
  results: LegacyImportRowResult[];
  not_migrated: string[];
}

export interface FilterImportItemOutcome {
  kind: "blocklist" | "rule" | "local_dns";
  text: string;
  status: "would_import" | "imported" | "skipped_duplicate" | "failed";
  detail?: string;
}

export interface FilterImportReport {
  dry_run: boolean;
  source_type: string;
  items: FilterImportItemOutcome[];
  unsupported: string[];
  counts: Record<string, number>;
}

export interface ApdnsbakManifest {
  source_version: string;
  control_db_schema_version: number;
  created_at: string;
  source_node_id: string;
  contents: string[];
}

export interface LegacyImportManifest {
  alderpointdns_app_version: string;
  database_schema_version: string;
  created_at: string;
  source_node_id: string;
  included_components: string[];
}

export interface SMTPConfig {
  host: string;
  port: number;
  from_addr: string;
  to_addr: string;
  username: string;
}

export interface NotificationProvider {
  provider_id: string;
  kind: "webhook" | "email_smtp" | "pushover" | "slack";
  display_name: string;
  config?: SMTPConfig | Record<string, never>;
  has_secret: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

// Event Subscriptions / Delivery History (2026-08-28): the real
// event-driven dispatch engine, field-matched against V1.1.1's
// app/notifications.py EVENT_CATEGORIES/subscriptions/dispatch/history.
export interface NotificationEventCategory {
  key: string;
  label: string;
  wired: boolean; // true = a real Go call site actually fires this today
  default_severity: "info" | "warning" | "critical";
}

export interface NotificationSubscription {
  id: number;
  provider_id: string;
  provider_name: string;
  event_category: string;
  min_severity: "info" | "warning" | "critical";
  enabled: boolean;
  cooldown_minutes: number | null;
  created_at: string;
  updated_at: string;
}

export interface NotificationHistoryEntry {
  id: number;
  at: string;
  event_category: string;
  severity: string;
  component: string;
  message: string;
  began_at: string;
  recovered: boolean;
  provider_id: string;
  provider_name: string;
  status: "sent" | "suppressed" | "failed";
  error: string;
}

export interface QueryLogResponse {
  rows: QueryLogRow[];
  degraded: boolean;
  degraded_reason?: string;
  files_considered?: number;
  limit: number;
  offset: number;
  filters: Record<string, unknown>;
}

export class ApiError extends Error {
  status: number;
  code: string;
  field?: string;
  constructor(status: number, code: string, detail: string, field?: string) {
    super(detail);
    this.status = status;
    this.code = code;
    this.field = field;
  }
}

let csrfToken = "";
export function setCsrfToken(token: string): void {
  csrfToken = token;
}

async function req<T>(path: string, init?: RequestInit, signal?: AbortSignal): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(init?.headers as any) };
  if (method !== "GET" && method !== "HEAD" && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  const res = await fetch(path, { ...init, method, headers, credentials: "include", signal });
  if (!res.ok) {
    let body: any = {};
    try {
      body = await res.json();
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, body.error ?? "unknown_error", body.detail ?? res.statusText, body.field);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  health: () =>
    req<{
      status: string;
      version: string;
      uptime_seconds: number;
      components: Record<
        string,
        {
          status: string;
          schema_version?: number;
          detail?: string;
          reason?: string;
          // Analytics component fields (internal/pyanalytics/health.go's
          // AnalyticsHealth) -- present only on the "analytics" component.
          db_reachable?: boolean;
          consecutive_read_failures?: number;
          writer_heartbeat_configured?: boolean;
          writer_status?: string;
          writer_stale?: boolean;
          writer_tick_count?: number;
          writer_last_success_at?: number;
          writer_last_error?: string;
          queue_depth?: number;
          queue_depth_available?: boolean;
          last_committed_bucket?: number;
        }
      >;
    }>("/api/health"),
  setupStatus: () => req<{ setup_required: boolean }>("/api/setup/status"),
  setupBootstrap: (token: string) => req<{ status: string; csrf: string }>("/api/setup/bootstrap", { method: "POST", body: JSON.stringify({ token }) }),
  setup: (body: {
    username: string;
    password: string;
    confirm_password: string;
    create_local_dns: boolean;
    server_hostname?: string;
    server_ip?: string;
  }) => req<{ status: string; local_dns: unknown }>("/api/setup", { method: "POST", body: JSON.stringify(body) }),
  login: (username: string, password: string) =>
    req<{ status: string; csrf: string }>("/api/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  logout: () => req<{ status: string }>("/api/logout", { method: "POST" }),
  session: () => req<{ authenticated: boolean; username: string; csrf: string }>("/api/session"),
  changePassword: (currentPassword: string, newPassword: string) =>
    req<{ status: string }>("/api/session/password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
  revokeOtherSessions: () => req<{ status: string; revoked_count: number }>("/api/session/revoke-others", { method: "POST" }),

  // 2026-08-28: real DELETE against this appliance's own Go-native
  // query_events table (internal/dnsanalytics.Reader.ClearAll) --
  // there is exactly one table now, so there is no longer a separate
  // "raw history" to optionally spare (the old two-tier Python
  // aggregates.db/Parquet split this used to mirror is gone).
  statisticsClear: () =>
    req<{ status: string; query_events_cleared: number }>("/api/statistics/clear", {
      method: "POST",
      body: JSON.stringify({ confirmation: "CLEAR" }),
    }),
  getAnalyticsSettings: (signal?: AbortSignal) => req<AnalyticsSettings>("/api/statistics/settings", undefined, signal),
  updateAnalyticsSettings: (settings: AnalyticsSettings) =>
    req<AnalyticsSettings>("/api/statistics/settings", { method: "PUT", body: JSON.stringify(settings) }),
  systemStatus: () =>
    req<{ version: string; uptime_seconds: number; appliance_name: string; appliance_timezone: string }>("/api/system/status"),
  dashboardSummary: (signal?: AbortSignal) =>
    req<{
      appliance_name: string;
      analytics_available: boolean;
      blocklists: { total: number; enabled: number; attention_required: number; total_rules: number };
      local_dns: { total: number; enabled: number };
    }>("/api/dashboard/summary", undefined, signal),
  protectionStatus: (signal?: AbortSignal) =>
    req<{ active: boolean; enabled_blocklists: number; enabled_rules: number }>("/api/protection/status", undefined, signal),
  protectionToggle: () =>
    req<{ active: boolean; dns_runtime?: DNSRuntimeApplyResult }>("/api/protection/toggle", { method: "POST" }),

  analyticsTimeseries: (minutes: number, granularity: "minute" | "hour" | "day", signal?: AbortSignal) =>
    req<AnalyticsTimeseriesResponse>(`/api/analytics/timeseries?minutes=${minutes}&granularity=${granularity}`, undefined, signal),
  analyticsLiveActivity: (seconds: number, signal?: AbortSignal) =>
    req<AnalyticsTimeseriesResponse & { current_qps: number; current_blocked_percent: number; rolling_10s_qps: number }>(
      `/api/analytics/live-activity?seconds=${seconds}`,
      undefined,
      signal,
    ),
  analyticsTopDomains: (minutes: number, limit: number, signal?: AbortSignal) =>
    req<AnalyticsTopRowsResponse>(`/api/analytics/top-domains?minutes=${minutes}&limit=${limit}`, undefined, signal),
  analyticsTopBlockedDomains: (minutes: number, limit: number, signal?: AbortSignal) =>
    req<AnalyticsTopRowsResponse>(`/api/analytics/top-blocked-domains?minutes=${minutes}&limit=${limit}`, undefined, signal),
  analyticsBreakdown: (dimension: "qtype" | "rcode" | "protocol", minutes: number, limit: number, signal?: AbortSignal) =>
    req<AnalyticsTopRowsResponse>(`/api/analytics/breakdown?dimension=${dimension}&minutes=${minutes}&limit=${limit}`, undefined, signal),
  analyticsQueryLog: (filters: QueryLogFilters, signal?: AbortSignal) => {
    const params = new URLSearchParams();
    params.set("minutes", String(filters.minutes));
    if (filters.search) params.set("search", filters.search);
    if (filters.domain) params.set("domain", filters.domain);
    if (filters.client) params.set("client", filters.client);
    if (filters.qtype) params.set("qtype", filters.qtype);
    if (filters.protocol) params.set("protocol", filters.protocol);
    if (filters.rcode) params.set("rcode", filters.rcode);
    if (filters.upstream) params.set("upstream", filters.upstream);
    if (filters.cache_status) params.set("cache_status", filters.cache_status);
    if (filters.blocked_only) params.set("blocked_only", "true");
    params.set("limit", String(filters.limit ?? 100));
    params.set("offset", String(filters.offset ?? 0));
    return req<QueryLogResponse>(`/api/analytics/query-log?${params.toString()}`, undefined, signal);
  },

  getDnsTransports: (signal?: AbortSignal) => req<DnsTransportSettings>("/api/dns-transports", undefined, signal),
  updateDnsTransports: (settings: DnsTransportSettings) =>
    req<DnsTransportSettings>("/api/dns-transports", { method: "PUT", body: JSON.stringify(settings) }),
  rotateDnscrypt: (rotateProvider: boolean) =>
    req<{ status: string; rotated_provider: boolean; fingerprint: string; cert_serial: number; cert_valid_until: number }>(
      "/api/dns-transports/dnscrypt/rotate",
      { method: "POST", body: JSON.stringify({ rotate_provider: rotateProvider }) },
    ),
  tlsStatus: (signal?: AbortSignal) => req<TlsStatus>("/api/tls/status", undefined, signal),
  tlsReplace: (certificatePem: string, privateKeyPem: string) =>
    req<{ status: string; restart_required: boolean; subject: string; not_valid_after: string }>("/api/tls/replace", {
      method: "POST",
      body: JSON.stringify({ certificate_pem: certificatePem, private_key_pem: privateKeyPem }),
    }),

  listNotificationProviders: (signal?: AbortSignal) => req<{ providers: NotificationProvider[] }>("/api/notifications", undefined, signal),
  createNotificationProvider: (kind: string, displayName: string, config?: Record<string, unknown>) =>
    req<NotificationProvider>("/api/notifications", {
      method: "POST",
      body: JSON.stringify({ kind, display_name: displayName, config: config ?? {} }),
    }),
  toggleNotificationProvider: (id: string, enabled: boolean) =>
    req<{ status: string }>(`/api/notifications/${encodeURIComponent(id)}/toggle`, { method: "POST", body: JSON.stringify({ enabled }) }),
  deleteNotificationProvider: (id: string) => req<{ status: string }>(`/api/notifications/${encodeURIComponent(id)}`, { method: "DELETE" }),
  setNotificationSecret: (id: string, value: string) =>
    req<{ status: string }>(`/api/notifications/${encodeURIComponent(id)}/secret`, { method: "PUT", body: JSON.stringify({ value }) }),
  revokeNotificationSecret: (id: string) => req<{ status: string }>(`/api/notifications/${encodeURIComponent(id)}/secret`, { method: "DELETE" }),
  testNotificationProvider: (id: string) =>
    req<{ ok: boolean; detail: string; status_code?: number }>(`/api/notifications/${encodeURIComponent(id)}/test`, { method: "POST" }),
  listEventCategories: (signal?: AbortSignal) =>
    req<{ categories: NotificationEventCategory[] }>("/api/notification-event-categories", undefined, signal),
  listNotificationSubscriptions: (signal?: AbortSignal) =>
    req<{ subscriptions: NotificationSubscription[] }>("/api/notification-subscriptions", undefined, signal),
  createNotificationSubscription: (providerId: string, eventCategory: string, minSeverity: string, enabled: boolean, cooldownMinutes: number | null) =>
    req<{ status: string }>("/api/notification-subscriptions", {
      method: "POST",
      body: JSON.stringify({ provider_id: providerId, event_category: eventCategory, min_severity: minSeverity, enabled, cooldown_minutes: cooldownMinutes }),
    }),
  deleteNotificationSubscription: (id: number) => req<{ status: string }>(`/api/notification-subscriptions/${id}`, { method: "DELETE" }),
  listNotificationHistory: (limit = 100, signal?: AbortSignal) =>
    req<{ history: NotificationHistoryEntry[] }>(`/api/notification-history?limit=${limit}`, undefined, signal),

  importHosts: (text: string) => req<ImportHostsResult>("/api/import/hosts", { method: "POST", body: text }),

  createImportJob: (sourceType: string, sourceName: string, text: string, defaultDomain?: string) =>
    req<{ job_id: number; plan: ImportPlan }>("/api/import/jobs", {
      method: "POST",
      body: JSON.stringify({ source_type: sourceType, source_name: sourceName, text, default_domain: defaultDomain }),
    }),
  listImportJobs: (signal?: AbortSignal) => req<{ jobs: ImportJob[] }>("/api/import/jobs", undefined, signal),
  getImportJob: (id: number) => req<ImportJob>(`/api/import/jobs/${id}`),
  applyImportJob: (id: number, skipIndexes: number[]) =>
    req<{ status: string; counts: ImportHostsResult; snapshot_filename?: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/import/jobs/${id}/apply`, {
      method: "POST",
      body: JSON.stringify({ skip_indexes: skipIndexes }),
    }),
  rollbackImportJob: (id: number) =>
    req<{ status: string; safety_backup: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/import/jobs/${id}/rollback`, { method: "POST" }),

  importApdnsbak: async (
    file: File,
    passphrase: string,
    dryRun: boolean,
  ): Promise<{ report: LegacyImportReport; manifest: ApdnsbakManifest }> => {
    const headers: Record<string, string> = { "X-CSRF-Token": csrfToken };
    if (passphrase) headers["X-Apdnsbak-Passphrase"] = passphrase;
    const res = await fetch(
      `/api/import/apdnsbak?filename=${encodeURIComponent(file.name)}&dry_run=${dryRun}`,
      { method: "POST", headers, credentials: "include", body: file },
    );
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new ApiError(res.status, body.error ?? "unknown_error", body.detail ?? res.statusText);
    }
    return res.json();
  },

  importLegacyAppliance: async (
    file: File,
    password: string,
    dryRun: boolean,
  ): Promise<{ report: LegacyImportReport; manifest: LegacyImportManifest }> => {
    const headers: Record<string, string> = { "X-CSRF-Token": csrfToken };
    if (password) headers["X-Legacy-Backup-Password"] = password;
    const res = await fetch(
      `/api/import/legacy-appliance?filename=${encodeURIComponent(file.name)}&dry_run=${dryRun}`,
      { method: "POST", headers, credentials: "include", body: file },
    );
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new ApiError(res.status, body.error ?? "unknown_error", body.detail ?? res.statusText);
    }
    return res.json();
  },

  cacheStatus: (signal?: AbortSignal) => req<CacheStatusResponse>("/api/cache/status", undefined, signal),
  cacheFlush: (layer: "bind", opts?: { context?: string; scope?: string; target?: string }) =>
    req<CacheFlushResult>("/api/cache/flush", { method: "POST", body: JSON.stringify({ layer, ...opts }) }),
  cacheDnsdistRestart: () =>
    req<{ dns_runtime: DNSRuntimeApplyResult }>("/api/cache/dnsdist-restart", { method: "POST" }),

  dnsPerformanceStatus: (signal?: AbortSignal) => req<DNSPerfStatusResponse>("/api/dns/performance", undefined, signal),
  dnsPerformanceRun: () => req<{ status: string }>("/api/dns/performance/benchmark", { method: "POST" }),
  dnsPerformanceClear: () => req<{ status: string }>("/api/dns/performance", { method: "DELETE" }),

  replicationStatus: (signal?: AbortSignal) => req<ReplicationStatusResponse>("/api/replication/status", undefined, signal),
  replicationSetRole: (role: string) => req<{ status: string }>("/api/replication/role", { method: "POST", body: JSON.stringify({ role }) }),
  replicationGenerateToken: (nodeName: string) =>
    req<ReplicationIssuedToken>("/api/replication/token", { method: "POST", body: JSON.stringify({ node_name: nodeName }) }),
  replicationRevokeEnrollment: (id: number) => req<{ status: string }>(`/api/replication/enrollments/${id}/revoke`, { method: "POST" }),
  replicationSetReplicaStatus: (id: number, status: string) =>
    req<{ status: string }>(`/api/replication/replicas/${id}/status`, { method: "POST", body: JSON.stringify({ status }) }),
  replicationConnect: (primaryHost: string, primaryPort: number, token: string) =>
    req<{ status: string; node_id: string }>("/api/replication/connect", {
      method: "POST",
      body: JSON.stringify({ primary_host: primaryHost, primary_port: primaryPort, token }),
    }),
  replicationSyncNow: () => req<ReplicationSyncResult>("/api/replication/sync-now", { method: "POST" }),
  replicationDriftCheck: () =>
    req<{ drifted: boolean; local_hash: string; expected_hash: string }>("/api/replication/drift-check", { method: "POST" }),
  replicationPause: (paused: boolean) => req<{ status: string }>("/api/replication/pause", { method: "POST", body: JSON.stringify({ paused }) }),
  replicationSettings: (settings: { listen_host: string; listen_port: number; poll_interval_seconds: number; include_encryption_settings: boolean }) =>
    req<{ status: string }>("/api/replication/settings", { method: "POST", body: JSON.stringify(settings) }),
  replicationPublishGeneration: () => req<ReplicationGeneration>("/api/replication/generations", { method: "POST" }),

  networkStatus: (iface: string, signal?: AbortSignal) =>
    req<{ raw_addr_json: string }>(`/api/network/status?interface=${encodeURIComponent(iface)}`, undefined, signal),
  networkApply: (iface: string, addresses: string[], gateway?: string) =>
    req<NetworkApplyResult>("/api/network/apply", { method: "POST", body: JSON.stringify({ interface: iface, addresses, gateway }) }),
  networkConfirm: (iface: string) => req<{ status: string }>("/api/network/confirm", { method: "POST", body: JSON.stringify({ interface: iface }) }),
  networkRollback: (iface: string) => req<{ status: string }>("/api/network/rollback", { method: "POST", body: JSON.stringify({ interface: iface }) }),

  logsListUnits: (signal?: AbortSignal) =>
    req<{ units: string[]; all_units_value: string; severities: string[] }>("/api/logs/units", undefined, signal),
  logsRead: (unit: string, lines: number, severity: string, signal?: AbortSignal) =>
    req<{ unit: string; entries: LogEntry[] }>(
      `/api/logs/${encodeURIComponent(unit)}?lines=${lines}${severity ? `&severity=${encodeURIComponent(severity)}` : ""}`,
      undefined,
      signal,
    ),

  updateCheck: (signal?: AbortSignal) => req<UpdateCheckResponse>("/api/updates/status", undefined, signal),
  updateStage: (claimedVersion: string, sha256: string, dataBase64: string) =>
    req<{ status: string; version: string; sha256: string }>("/api/updates/stage", {
      method: "POST",
      body: JSON.stringify({ claimed_version: claimedVersion, sha256, data_base64: dataBase64 }),
    }),
  updateApply: () => req<{ status: string; version: string }>("/api/updates/apply", { method: "POST" }),

  listBlocklists: (signal?: AbortSignal) => req<BlocklistsResponse>("/api/blocklists", undefined, signal),
  createBlocklist: (name: string, url: string, category: string) =>
    req<{ subscription_id: string; job_id: number; subscription: Subscription }>("/api/blocklists", {
      method: "POST",
      body: JSON.stringify({ name, url, category }),
    }),
  setDefaultInterval: (seconds: number) =>
    req<{ status: string }>("/api/blocklists/settings", { method: "POST", body: JSON.stringify({ default_interval_seconds: seconds }) }),
  setInterval: (id: string, seconds: number) =>
    req<{ status: string }>(`/api/blocklists/${encodeURIComponent(id)}/interval`, {
      method: "POST",
      body: JSON.stringify({ update_interval_seconds: seconds }),
    }),
  toggleBlocklist: (id: string) => req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/blocklists/${encodeURIComponent(id)}/toggle`, { method: "POST" }),
  deleteBlocklist: (id: string) => req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/blocklists/${encodeURIComponent(id)}`, { method: "DELETE" }),
  refreshOne: (id: string) => req<{ status: string; job_id: number }>(`/api/blocklists/${encodeURIComponent(id)}/refresh`, { method: "POST" }),
  refreshAll: () => req<{ status: string; job_id: number | null; count?: number }>("/api/blocklists/refresh-all", { method: "POST" }),
  getJob: (id: number) => req<Job>(`/api/blocklists/jobs/${id}`),
  listBlocklistCategories: (signal?: AbortSignal) =>
    req<{ categories: BlocklistCategory[] }>("/api/blocklists/categories", undefined, signal),
  createBlocklistCategory: (name: string) =>
    req<BlocklistCategory>("/api/blocklists/categories", { method: "POST", body: JSON.stringify({ name }) }),
  renameBlocklistCategory: (id: number, name: string) =>
    req<{ status: string }>(`/api/blocklists/categories/${id}/rename`, { method: "POST", body: JSON.stringify({ name }) }),
  deleteBlocklistCategory: (id: number) =>
    req<{ status: string }>(`/api/blocklists/categories/${id}`, { method: "DELETE" }),

  listLocalDNS: (signal?: AbortSignal) => req<{ records: LocalDnsRecord[] }>("/api/local-dns", undefined, signal),
  createLocalDNS: (rec: Omit<LocalDnsRecord, "id">) =>
    req<{ record: LocalDnsRecord; dns_runtime?: DNSRuntimeApplyResult }>("/api/local-dns", { method: "POST", body: JSON.stringify(rec) }),
  updateLocalDNS: (id: number, patch: Partial<Pick<LocalDnsRecord, "value" | "ttl" | "enabled">>) =>
    req<{ record: LocalDnsRecord; dns_runtime?: DNSRuntimeApplyResult }>(`/api/local-dns/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteLocalDNS: (id: number) => req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/local-dns/${id}`, { method: "DELETE" }),

  listClientAliases: (signal?: AbortSignal) => req<{ aliases: ClientAlias[] }>("/api/local-dns/aliases", undefined, signal),
  createClientAlias: (cidr: string, displayName: string, description: string) =>
    req<{ status: string; alias: ClientAlias }>("/api/local-dns/aliases", {
      method: "POST",
      body: JSON.stringify({ cidr, display_name: displayName, description }),
    }),
  updateClientAlias: (id: number, displayName: string, description: string) =>
    req<{ status: string }>(`/api/local-dns/aliases/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ display_name: displayName, description }),
    }),
  deleteClientAlias: (id: number) => req<{ status: string }>(`/api/local-dns/aliases/${id}`, { method: "DELETE" }),

  listUpstreams: (signal?: AbortSignal) =>
    req<{ upstreams: UpstreamProfile[]; native_recursion_active: boolean }>("/api/upstreams", undefined, signal),
  createUpstream: (body: UpstreamProfileInput) =>
    req<{ status: string; upstream_profile_id: string; dns_runtime?: DNSRuntimeApplyResult }>("/api/upstreams", { method: "POST", body: JSON.stringify(body) }),
  updateUpstream: (id: string, body: UpstreamProfileInput) =>
    req<UpstreamMutationResult>(`/api/upstreams/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(body) }),
  enableUpstream: (id: string) => req<UpstreamMutationResult>(`/api/upstreams/${encodeURIComponent(id)}/enable`, { method: "POST" }),
  disableUpstream: (id: string, confirmLast = false) =>
    req<UpstreamMutationResult>(`/api/upstreams/${encodeURIComponent(id)}/disable`, {
      method: "POST",
      body: JSON.stringify({ confirm_last: confirmLast }),
    }),
  deleteUpstream: (id: string, confirmLast = false) =>
    req<UpstreamMutationResult>(`/api/upstreams/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: JSON.stringify({ confirm_last: confirmLast }),
    }),
  reorderUpstreams: (orderedIds: string[]) =>
    req<{ status: string; upstreams: UpstreamProfile[]; dns_runtime?: DNSRuntimeApplyResult }>("/api/upstreams/reorder", {
      method: "POST",
      body: JSON.stringify({ ordered_upstream_profile_ids: orderedIds }),
    }),

  listDomainRoutes: (signal?: AbortSignal) => req<{ rules: DomainRoute[] }>("/api/domain-routing", undefined, signal),
  createDomainRoute: (body: { match_kind: "exact" | "suffix"; domain: string; upstream_profile_id: string }) =>
    req<{ status: string; rule: DomainRoute; dns_runtime?: DNSRuntimeApplyResult }>("/api/domain-routing", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteDomainRoute: (id: number) =>
    req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/domain-routing/${id}`, { method: "DELETE" }),

  listGroups: (signal?: AbortSignal) => req<{ groups: ClientGroup[] }>("/api/groups", undefined, signal),
  createGroup: (name: string, priority: number) =>
    req<{ status: string; group_id: string }>("/api/groups", { method: "POST", body: JSON.stringify({ name, priority }) }),
  listClients: (signal?: AbortSignal) => req<{ clients: ManagedClient[] }>("/api/clients", undefined, signal),
  createClient: (name: string, description: string) =>
    req<{ status: string; client_id: number }>("/api/clients", { method: "POST", body: JSON.stringify({ name, description }) }),
  updateClient: (clientId: number, name: string, description: string) =>
    req<{ status: string }>(`/api/clients/${clientId}`, { method: "PATCH", body: JSON.stringify({ name, description }) }),
  setClientEnabled: (clientId: number, enabled: boolean) =>
    req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/clients/${clientId}/enabled`, { method: "POST", body: JSON.stringify({ enabled }) }),
  deleteClient: (clientId: number) =>
    req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/clients/${clientId}`, { method: "DELETE" }),
  addClientIdentifier: (clientId: number, kind: string, value: string) =>
    req<{ status: string }>(`/api/clients/${clientId}/identifiers`, { method: "POST", body: JSON.stringify({ kind, value }) }),
  addClientToGroup: (clientId: number, groupId: string) =>
    req<{ status: string }>(`/api/clients/${clientId}/groups`, { method: "POST", body: JSON.stringify({ group_id: groupId }) }),
  removeClientFromGroup: (clientId: number, groupId: string) =>
    req<{ status: string }>(`/api/clients/${clientId}/groups/${encodeURIComponent(groupId)}`, { method: "DELETE" }),
  listObservedClients: (signal?: AbortSignal) =>
    req<{ observed: ObservedClient[]; degraded: boolean; degraded_reason?: string }>("/api/clients/observed", undefined, signal),
  topClients: (minutes: number, signal?: AbortSignal) =>
    req<{ clients: ClientAnalyticsRow[]; total: number; degraded: boolean; degraded_reason?: string }>(
      `/api/analytics/top-clients?minutes=${minutes}&limit=500`,
      undefined,
      signal,
    ),

  // Strong ClientID: the actual hex value is always generated
  // server-side (internal/clientid's OS-backed CSPRNG) -- the caller
  // only ever chooses the bit strength and a display label.
  generateClientID: (clientId: number, bits: 192 | 256, label: string) =>
    req<{ status: string; identifier: ClientIdentifier; dns_runtime?: DNSRuntimeApplyResult }>(
      `/api/clients/${clientId}/identifiers/generate`,
      { method: "POST", body: JSON.stringify({ bits, label }) },
    ),
  revokeClientIdentifier: (clientId: number, identifierId: number) =>
    req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(
      `/api/clients/${clientId}/identifiers/${identifierId}/revoke`,
      { method: "POST" },
    ),
  regenerateClientIdentifier: (clientId: number, identifierId: number) =>
    req<{ status: string; identifier: ClientIdentifier; dns_runtime?: DNSRuntimeApplyResult }>(
      `/api/clients/${clientId}/identifiers/${identifierId}/regenerate`,
      { method: "POST" },
    ),
  deleteClientIdentifier: (clientId: number, identifierId: number) =>
    req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(
      `/api/clients/${clientId}/identifiers/${identifierId}`,
      { method: "DELETE" },
    ),
  addClientDomainOverride: (clientId: number, overrideType: "block" | "allow", pattern: string) =>
    req<{ status: string; override: ClientDomainOverride; dns_runtime?: DNSRuntimeApplyResult }>(
      `/api/clients/${clientId}/domain-overrides`,
      { method: "POST", body: JSON.stringify({ override_type: overrideType, pattern }) },
    ),
  deleteClientDomainOverride: (clientId: number, overrideId: number) =>
    req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(
      `/api/clients/${clientId}/domain-overrides/${overrideId}`,
      { method: "DELETE" },
    ),

  getGlobalPolicy: (signal?: AbortSignal) => req<PolicyLayer>("/api/policy/global", undefined, signal),
  // Only the global scope is ever compiled into the live DNS runtime
  // today (internal/dnscompile reads the global policy layer only) --
  // a global save gets the real dns_runtime result every other
  // auto-applying mutation returns; network/group/client saves get an
  // honest "not compiled" DNSRuntimeApplyResult (attempted: false),
  // never a faked promoted: true.
  putGlobalPolicy: (layer: PolicyLayer) =>
    req<{ status: string; dns_runtime: DNSRuntimeApplyResult }>("/api/policy/global", { method: "PUT", body: JSON.stringify(layer) }),
  putNetworkPolicy: (id: string, layer: PolicyLayer) =>
    req<{ status: string; dns_runtime: DNSRuntimeApplyResult }>(`/api/policy/network/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(layer) }),
  putGroupPolicy: (id: string, layer: PolicyLayer) =>
    req<{ status: string; dns_runtime: DNSRuntimeApplyResult }>(`/api/policy/group/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(layer) }),
  putClientPolicy: (id: number, layer: PolicyLayer) =>
    req<{ status: string; dns_runtime: DNSRuntimeApplyResult }>(`/api/policy/client/${id}`, { method: "PUT", body: JSON.stringify(layer) }),
  // explainPolicy: internal/policy/effective.go's real global->network->
  // group->client precedence resolution -- clientIp is optional (omitted
  // means no network-scope layer can match, same as Python's own
  // Optional[str] contract; this page has no known client IP yet since
  // Observed Clients/discovery isn't built -- see ClientsView.svelte's
  // own doc comment).
  explainPolicy: (clientId: number, clientIp?: string) =>
    req<PolicyExplainResult>(`/api/policy/explain?client_id=${clientId}${clientIp ? `&client_ip=${encodeURIComponent(clientIp)}` : ""}`),
  listNetworks: (signal?: AbortSignal) => req<{ networks: NetworkWithPolicy[] }>("/api/networks", undefined, signal),
  createNetwork: (cidr: string) =>
    req<{ status: string; network_id: string }>("/api/networks", { method: "POST", body: JSON.stringify({ cidr }) }),

  listCustomRules: (signal?: AbortSignal) => req<{ rules: CustomRule[] }>("/api/custom-rules", undefined, signal),
  createCustomRule: (ruleType: string, pattern: string, rewriteTarget: string | null) =>
    req<{ status: string; id: number; dns_runtime?: DNSRuntimeApplyResult }>("/api/custom-rules", {
      method: "POST",
      body: JSON.stringify({ rule_type: ruleType, pattern, rewrite_target: rewriteTarget }),
    }),
  updateCustomRule: (id: number, ruleType: string, pattern: string, rewriteTarget: string | null) =>
    req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/custom-rules/${id}`, {
      method: "PUT",
      body: JSON.stringify({ rule_type: ruleType, pattern, rewrite_target: rewriteTarget }),
    }),
  toggleCustomRule: (id: number, enabled: boolean) =>
    req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/custom-rules/${id}/toggle`, { method: "POST", body: JSON.stringify({ enabled }) }),
  deleteCustomRule: (id: number) => req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/custom-rules/${id}`, { method: "DELETE" }),
  bulkEnableCustomRules: (ids: number[]) =>
    req<{ status: string; count: number; dns_runtime?: DNSRuntimeApplyResult }>("/api/custom-rules/bulk-enable", { method: "POST", body: JSON.stringify({ ids }) }),
  bulkDisableCustomRules: (ids: number[]) =>
    req<{ status: string; count: number; dns_runtime?: DNSRuntimeApplyResult }>("/api/custom-rules/bulk-disable", { method: "POST", body: JSON.stringify({ ids }) }),
  bulkDeleteCustomRules: (ids: number[]) =>
    req<{ status: string; count: number; dns_runtime?: DNSRuntimeApplyResult }>("/api/custom-rules/bulk-delete", { method: "POST", body: JSON.stringify({ ids }) }),
  reorderCustomRules: (orderedIds: number[]) =>
    req<{ status: string; rules: CustomRule[] }>("/api/custom-rules/reorder", { method: "POST", body: JSON.stringify({ ordered_ids: orderedIds }) }),
  testDomain: (domain: string, signal?: AbortSignal) =>
    req<{ domain: string; blocked: boolean; reason: string; matched?: string }>(
      `/api/custom-rules/test-domain?domain=${encodeURIComponent(domain)}`,
      undefined,
      signal,
    ),

  listBackups: (signal?: AbortSignal) => req<{ backups: BackupInfo[] }>("/api/backup/appliance", undefined, signal),
  createBackup: (passphrase?: string) =>
    req<{ status: string; backup: BackupInfo }>("/api/backup/appliance", {
      method: "POST",
      body: JSON.stringify({ passphrase: passphrase ?? "" }),
    }),
  uploadBackup: async (file: File): Promise<{ status: string; backup: BackupInfo }> => {
    const res = await fetch(`/api/backup/appliance/upload?filename=${encodeURIComponent(file.name)}`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken },
      credentials: "include",
      body: file,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new ApiError(res.status, body.error ?? "unknown_error", body.detail ?? res.statusText);
    }
    return res.json();
  },
  // previewBackup: passphrase is required (a 422 "passphrase_required"
  // ApiError) when BackupInfo.encrypted came back true from a prior
  // no-passphrase call; a 422 "wrong_passphrase" ApiError means one was
  // given but didn't decrypt.
  previewBackup: (name: string, passphrase?: string) =>
    req<BackupInfo>(`/api/backup/appliance/${encodeURIComponent(name)}/validate`, {
      method: "POST",
      body: JSON.stringify({ passphrase: passphrase ?? "" }),
    }),
  listBackupCategories: (signal?: AbortSignal) => req<{ categories: BackupCategory[] }>("/api/backup/categories", undefined, signal),
  restoreBackup: (name: string, categories?: string[], passphrase?: string) =>
    req<{ status: string; safety_backup: BackupInfo }>(`/api/backup/appliance/${encodeURIComponent(name)}/restore`, {
      method: "POST",
      body: JSON.stringify({ categories: categories ?? [], passphrase: passphrase ?? "" }),
    }),
  deleteBackup: (name: string) => req<{ status: string }>(`/api/backup/appliance/${encodeURIComponent(name)}`, { method: "DELETE" }),

  getBackupSchedule: (signal?: AbortSignal) =>
    req<BackupScheduleSettings>("/api/backup/schedule", undefined, signal),
  setBackupSchedule: (settings: { enabled: boolean; interval_hours: number; retention_count: number }) =>
    req<BackupScheduleSettings>("/api/backup/schedule", {
      method: "PUT",
      body: JSON.stringify(settings),
    }),

  listSecretBackups: (signal?: AbortSignal) =>
    req<{ backups: SecretBackupInfo[]; jobs: SecretBackupJob[] }>("/api/backup/secrets", undefined, signal),
  createSecretBackup: () =>
    req<{ status: string; backup: SecretBackupInfo }>("/api/backup/secrets", { method: "POST" }),
  validateSecretBackup: (name: string) =>
    req<{ status: string; secret_count: number }>(`/api/backup/secrets/${encodeURIComponent(name)}/validate`, { method: "POST" }),
  restoreSecretBackup: (name: string, overwrite: boolean) =>
    req<{ status: string; restored_count: number }>(`/api/backup/secrets/${encodeURIComponent(name)}/restore`, {
      method: "POST",
      body: JSON.stringify({ overwrite }),
    }),
  deleteSecretBackup: (name: string) =>
    req<{ status: string }>(`/api/backup/secrets/${encodeURIComponent(name)}`, { method: "DELETE" }),

  importPihole: (text: string, defaultDomain: string, dryRun: boolean) =>
    req<{ report: FilterImportReport }>("/api/import/pihole", {
      method: "POST",
      body: JSON.stringify({ text, default_domain: defaultDomain, dry_run: dryRun }),
    }),
  importAdGuardYAML: (text: string, dryRun: boolean) =>
    req<{ report: FilterImportReport }>("/api/import/adguard-yaml", {
      method: "POST",
      body: JSON.stringify({ text, dry_run: dryRun }),
    }),

  dnsRuntimeStatus: (signal?: AbortSignal) => req<DNSRuntimeStatus>("/api/dns-runtime/status", undefined, signal),
  applyDNSRuntime: () => req<DNSRuntimeApplyResult>("/api/dns-runtime/apply", { method: "POST" }),
};

export interface DNSRuntimeStatus {
  bind_running: boolean;
  dnsdist_running: boolean;
}

export interface DNSRuntimeApplyResult {
  attempted: boolean;
  promoted: boolean;
  rolled_back: boolean;
  stage?: string;
  detail?: string;
  error?: string;
}
