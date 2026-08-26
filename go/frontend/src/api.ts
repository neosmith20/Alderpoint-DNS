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
}

export interface BackupCategory {
  name: string;
  tables: string[];
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
  kind: "ipv4" | "ipv4_cidr" | "ipv6" | "ipv6_cidr" | "clientid";
  value: string;
}

export interface ClientGroupRef {
  group_id: string;
  name: string;
  priority: number;
}

export interface ManagedClient {
  id: number;
  name: string;
  description: string;
  enabled: boolean;
  identifiers: ClientIdentifier[];
  groups: ClientGroupRef[];
  policy: PolicyLayer;
}

export interface ClientGroupMember {
  id: number;
  name: string;
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
  dns_runtime?: DNSRuntimeApplyResult;
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

export interface BindContextStatus {
  name: string;
  stats_port: number;
  rndc_port: number;
  reachable: boolean;
  rndc_status?: string;
}

export interface CacheStatusResponse {
  bind: BindContextStatus[];
  dnsdist: { note: string };
}

export interface CacheFlushResult {
  results: { context: string; ok: boolean; detail?: string }[];
}

export interface ReplicationPeer {
  peer_node_id: string;
  display_name: string;
  url: string;
  expected_cert_sha256: string;
  expected_incoming_cert_sha256: string;
  authorized: boolean;
  direction: string;
  last_attempt_at: string;
  last_success_at: string;
  last_error: string;
  local_generation: number;
  remote_known_generation: number;
  lag: number;
}

export interface ReplicationStatusResponse {
  node_identity: { node_id: string; display_name: string; created_at: string; regenerated_at?: string } | null;
  peers: ReplicationPeer[];
}

export interface ReplicationSyncResult {
  peer_node_id: string;
  ok: boolean;
  detail: string;
  status_code?: number;
  elapsed_ms: number;
}

export interface NetworkApplyResult {
  status: string;
  interface: string;
  auto_revert_seconds: number;
}

export interface LogEntry {
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

export interface NotificationProvider {
  provider_id: string;
  kind: "webhook" | "email_smtp" | "pushover" | "slack";
  display_name: string;
  endpoint: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
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
    req<{ status: string; version: string; uptime_seconds: number; components: Record<string, { status: string; schema_version?: number; detail?: string }> }>(
      "/api/health",
    ),
  setupStatus: () => req<{ setup_required: boolean }>("/api/setup/status"),
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
  systemStatus: () =>
    req<{ version: string; uptime_seconds: number; appliance_name: string; appliance_timezone: string }>("/api/system/status"),
  dashboardSummary: (signal?: AbortSignal) =>
    req<{
      appliance_name: string;
      analytics_available: boolean;
      blocklists: { total: number; enabled: number; attention_required: number; total_rules: number };
      local_dns: { total: number; enabled: number };
    }>("/api/dashboard/summary", undefined, signal),

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
  tlsStatus: (signal?: AbortSignal) => req<TlsStatus>("/api/tls/status", undefined, signal),
  tlsReplace: (certificatePem: string, privateKeyPem: string) =>
    req<{ status: string; restart_required: boolean; subject: string; not_valid_after: string }>("/api/tls/replace", {
      method: "POST",
      body: JSON.stringify({ certificate_pem: certificatePem, private_key_pem: privateKeyPem }),
    }),

  listNotificationProviders: (signal?: AbortSignal) => req<{ providers: NotificationProvider[] }>("/api/notifications", undefined, signal),
  createNotificationProvider: (kind: string, displayName: string, endpoint: string) =>
    req<NotificationProvider>("/api/notifications", {
      method: "POST",
      body: JSON.stringify({ kind, display_name: displayName, endpoint }),
    }),
  toggleNotificationProvider: (id: string, enabled: boolean) =>
    req<{ status: string }>(`/api/notifications/${encodeURIComponent(id)}/toggle`, { method: "POST", body: JSON.stringify({ enabled }) }),
  deleteNotificationProvider: (id: string) => req<{ status: string }>(`/api/notifications/${encodeURIComponent(id)}`, { method: "DELETE" }),

  importHosts: (text: string) => req<ImportHostsResult>("/api/import/hosts", { method: "POST", body: text }),

  createImportJob: (sourceType: string, sourceName: string, text: string) =>
    req<{ job_id: number; plan: ImportPlan }>("/api/import/jobs", {
      method: "POST",
      body: JSON.stringify({ source_type: sourceType, source_name: sourceName, text }),
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

  cacheStatus: (signal?: AbortSignal) => req<CacheStatusResponse>("/api/cache/status", undefined, signal),
  cacheFlush: (layer: "bind" | "dnsdist", opts?: { context?: string; scope?: string; target?: string }) =>
    req<CacheFlushResult>("/api/cache/flush", { method: "POST", body: JSON.stringify({ layer, ...opts }) }),

  replicationStatus: (signal?: AbortSignal) => req<ReplicationStatusResponse>("/api/replication/status", undefined, signal),
  replicationSync: (peerNodeId: string) =>
    req<ReplicationSyncResult>("/api/replication/sync", { method: "POST", body: JSON.stringify({ peer_node_id: peerNodeId }) }),

  networkStatus: (iface: string, signal?: AbortSignal) =>
    req<{ raw_addr_json: string }>(`/api/network/status?interface=${encodeURIComponent(iface)}`, undefined, signal),
  networkApply: (iface: string, addresses: string[], gateway?: string) =>
    req<NetworkApplyResult>("/api/network/apply", { method: "POST", body: JSON.stringify({ interface: iface, addresses, gateway }) }),
  networkConfirm: (iface: string) => req<{ status: string }>("/api/network/confirm", { method: "POST", body: JSON.stringify({ interface: iface }) }),
  networkRollback: (iface: string) => req<{ status: string }>("/api/network/rollback", { method: "POST", body: JSON.stringify({ interface: iface }) }),

  logsListUnits: (signal?: AbortSignal) => req<{ units: string[] }>("/api/logs/units", undefined, signal),
  logsRead: (unit: string, lines: number, signal?: AbortSignal) =>
    req<{ unit: string; entries: LogEntry[] }>(`/api/logs/${encodeURIComponent(unit)}?lines=${lines}`, undefined, signal),

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

  listLocalDNS: (signal?: AbortSignal) => req<{ records: LocalDnsRecord[] }>("/api/local-dns", undefined, signal),
  createLocalDNS: (rec: Omit<LocalDnsRecord, "id">) =>
    req<{ record: LocalDnsRecord; dns_runtime?: DNSRuntimeApplyResult }>("/api/local-dns", { method: "POST", body: JSON.stringify(rec) }),
  updateLocalDNS: (id: number, patch: Partial<Pick<LocalDnsRecord, "value" | "ttl" | "enabled">>) =>
    req<{ record: LocalDnsRecord; dns_runtime?: DNSRuntimeApplyResult }>(`/api/local-dns/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteLocalDNS: (id: number) => req<{ status: string; dns_runtime?: DNSRuntimeApplyResult }>(`/api/local-dns/${id}`, { method: "DELETE" }),

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

  listGroups: (signal?: AbortSignal) => req<{ groups: ClientGroup[] }>("/api/groups", undefined, signal),
  createGroup: (name: string, priority: number) =>
    req<{ status: string; group_id: string }>("/api/groups", { method: "POST", body: JSON.stringify({ name, priority }) }),
  listClients: (signal?: AbortSignal) => req<{ clients: ManagedClient[] }>("/api/clients", undefined, signal),
  createClient: (name: string, description: string) =>
    req<{ status: string; client_id: number }>("/api/clients", { method: "POST", body: JSON.stringify({ name, description }) }),
  addClientIdentifier: (clientId: number, kind: string, value: string) =>
    req<{ status: string }>(`/api/clients/${clientId}/identifiers`, { method: "POST", body: JSON.stringify({ kind, value }) }),
  addClientToGroup: (clientId: number, groupId: string) =>
    req<{ status: string }>(`/api/clients/${clientId}/groups`, { method: "POST", body: JSON.stringify({ group_id: groupId }) }),

  getGlobalPolicy: (signal?: AbortSignal) => req<PolicyLayer>("/api/policy/global", undefined, signal),
  putGlobalPolicy: (layer: PolicyLayer) =>
    req<{ status: string; runtime: unknown }>("/api/policy/global", { method: "PUT", body: JSON.stringify(layer) }),
  putNetworkPolicy: (id: string, layer: PolicyLayer) =>
    req<{ status: string; runtime: unknown }>(`/api/policy/network/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(layer) }),
  putGroupPolicy: (id: string, layer: PolicyLayer) =>
    req<{ status: string; runtime: unknown }>(`/api/policy/group/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(layer) }),
  putClientPolicy: (id: number, layer: PolicyLayer) =>
    req<{ status: string; runtime: unknown }>(`/api/policy/client/${id}`, { method: "PUT", body: JSON.stringify(layer) }),
  listNetworks: (signal?: AbortSignal) => req<{ networks: { network_id: string; cidr: string }[] }>("/api/networks", undefined, signal),
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

  listBackups: (signal?: AbortSignal) => req<{ backups: BackupInfo[] }>("/api/backup/appliance", undefined, signal),
  createBackup: () => req<{ status: string; backup: BackupInfo }>("/api/backup/appliance", { method: "POST" }),
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
  previewBackup: (name: string) => req<BackupInfo>(`/api/backup/appliance/${encodeURIComponent(name)}/validate`, { method: "POST" }),
  listBackupCategories: (signal?: AbortSignal) => req<{ categories: BackupCategory[] }>("/api/backup/categories", undefined, signal),
  restoreBackup: (name: string, categories?: string[]) =>
    req<{ status: string; safety_backup: BackupInfo }>(`/api/backup/appliance/${encodeURIComponent(name)}/restore`, {
      method: "POST",
      body: JSON.stringify({ categories: categories ?? [] }),
    }),
  deleteBackup: (name: string) => req<{ status: string }>(`/api/backup/appliance/${encodeURIComponent(name)}`, { method: "DELETE" }),

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
