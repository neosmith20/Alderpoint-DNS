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
  runtime: { promoted: boolean; binding_count: number };
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
  health: () => req<{ status: string; version: string; uptime_seconds: number }>("/api/health"),
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
  toggleBlocklist: (id: string) => req<{ status: string }>(`/api/blocklists/${encodeURIComponent(id)}/toggle`, { method: "POST" }),
  deleteBlocklist: (id: string) => req<{ status: string }>(`/api/blocklists/${encodeURIComponent(id)}`, { method: "DELETE" }),
  refreshOne: (id: string) => req<{ status: string; job_id: number }>(`/api/blocklists/${encodeURIComponent(id)}/refresh`, { method: "POST" }),
  refreshAll: () => req<{ status: string; job_id: number | null; count?: number }>("/api/blocklists/refresh-all", { method: "POST" }),
  getJob: (id: number) => req<Job>(`/api/blocklists/jobs/${id}`),

  listLocalDNS: (signal?: AbortSignal) => req<{ records: LocalDnsRecord[] }>("/api/local-dns", undefined, signal),
  createLocalDNS: (rec: Omit<LocalDnsRecord, "id">) =>
    req<{ record: LocalDnsRecord }>("/api/local-dns", { method: "POST", body: JSON.stringify(rec) }),
  updateLocalDNS: (id: number, patch: Partial<Pick<LocalDnsRecord, "value" | "ttl" | "enabled">>) =>
    req<{ record: LocalDnsRecord }>(`/api/local-dns/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteLocalDNS: (id: number) => req<{ status: string }>(`/api/local-dns/${id}`, { method: "DELETE" }),

  listUpstreams: (signal?: AbortSignal) =>
    req<{ upstreams: UpstreamProfile[]; native_recursion_active: boolean }>("/api/upstreams", undefined, signal),
  createUpstream: (body: UpstreamProfileInput) =>
    req<{ status: string; upstream_profile_id: string }>("/api/upstreams", { method: "POST", body: JSON.stringify(body) }),
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
    req<{ status: string; upstreams: UpstreamProfile[] }>("/api/upstreams/reorder", {
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
};
