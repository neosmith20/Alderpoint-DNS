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

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(init?.headers as any) };
  if (method !== "GET" && method !== "HEAD" && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  const res = await fetch(path, { ...init, method, headers, credentials: "include" });
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

  listBlocklists: () => req<BlocklistsResponse>("/api/blocklists"),
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

  listLocalDNS: () => req<{ records: LocalDnsRecord[] }>("/api/local-dns"),
  createLocalDNS: (rec: Omit<LocalDnsRecord, "id">) =>
    req<{ record: LocalDnsRecord }>("/api/local-dns", { method: "POST", body: JSON.stringify(rec) }),
  updateLocalDNS: (id: number, patch: Partial<Pick<LocalDnsRecord, "value" | "ttl" | "enabled">>) =>
    req<{ record: LocalDnsRecord }>(`/api/local-dns/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteLocalDNS: (id: number) => req<{ status: string }>(`/api/local-dns/${id}`, { method: "DELETE" }),
};
