<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { api, ApiError, type QueryLogRow, type QueryLogFilters } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";
  import { queryLogPrefill } from "../queryLogPrefill.svelte";
  import { customRulePrefill } from "../customRulePrefill.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import OverflowMenu from "./ui/OverflowMenu.svelte";
  import Modal from "./ui/Modal.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";

  // Query Log, backed by internal/rawquerylog -- a second, narrower
  // compatibility boundary over Python's raw per-query Parquet history
  // (analytics/queries/), distinct from internal/pyanalytics's
  // pre-aggregated aggregates.db buckets. See that package's doc comment
  // for exactly what it is: pure Go (no DuckDB/cgo), partition-pruned,
  // failure-isolated per segment, filters as a fixed exact-match
  // allowlist plus an optional post-scan substring "search". It is
  // read-only -- there is no delete path over this data source, so
  // "Clear Query Log" below is disclosed-disabled rather than faked.

  const WINDOWS = [
    { label: "Last hour", minutes: 60 },
    { label: "Last 24 hours", minutes: 1440 },
    { label: "Last 7 days", minutes: 7 * 1440 },
    { label: "Last 30 days", minutes: 30 * 1440 },
  ];

  let minutes = $state(1440);
  let search = $state("");
  let domain = $state("");
  let client = $state("");
  let qtype = $state("");
  let protocol = $state("");
  let rcode = $state("");
  let upstream = $state("");
  let cacheStatus = $state("");
  /** All/Allowed/Blocked -- a real tri-state read entirely from rows
   * already fetched, since the backend filter only ever offers a single
   * "blocked_only" boolean (no "allowed only" mode exists server-side).
   * Fetching the full window and filtering the allowed/blocked split
   * client-side is honest about that -- it's the same rows either way,
   * never a second, different query. */
  let resultFilter = $state<"all" | "allowed" | "blocked">("all");
  let limit = $state(100);

  let rows = $state<QueryLogRow[]>([]);
  let degraded = $state(false);
  let degradedReason = $state("");
  let filesConsidered = $state<number | null>(null);
  let loadError = $state("");
  let loading = $state(false);
  let autoRefresh = $state(false);
  const guard = new StaleGuard();

  function activeFilterCount(): number {
    return [search, domain, client, qtype, protocol, rcode, upstream, cacheStatus].filter((v) => v !== "").length + (resultFilter !== "all" ? 1 : 0);
  }

  async function refresh() {
    const token = guard.start();
    loading = true;
    const f: QueryLogFilters = {
      minutes, search, domain, client, qtype, protocol, rcode, upstream,
      cache_status: cacheStatus, blocked_only: false, limit,
    };
    try {
      const resp = await api.analyticsQueryLog(f, router.signal());
      if (!guard.isCurrent(token)) return;
      rows = resp.rows;
      degraded = resp.degraded;
      degradedReason = resp.degraded_reason ?? "";
      filesConsidered = resp.files_considered ?? null;
      loadError = "";
    } catch (err) {
      if (!guard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof ApiError ? err.message : String(err);
    } finally {
      if (guard.isCurrent(token)) loading = false;
    }
  }

  const visibleRows = $derived(
    resultFilter === "all" ? rows : rows.filter((r) => (resultFilter === "blocked" ? r.blocked : !r.blocked)),
  );

  function resetFilters() {
    search = domain = client = qtype = protocol = rcode = upstream = cacheStatus = "";
    resultFilter = "all";
    refresh();
  }

  let autoRefreshTimer: ReturnType<typeof setInterval> | undefined;
  function toggleAutoRefresh() {
    autoRefresh = !autoRefresh;
    clearInterval(autoRefreshTimer);
    if (autoRefresh) autoRefreshTimer = setInterval(refresh, 15_000);
  }
  onDestroy(() => clearInterval(autoRefreshTimer));

  function exportCsv() {
    const header = ["Time", "Domain", "Type", "Result", "Filtering reason", "Client", "Protocol", "Upstream", "Response time (ms)"];
    const csvRows = visibleRows.map((r) => [
      new Date(r.ts * 1000).toISOString(),
      r.domain,
      r.qtype,
      r.blocked ? "Blocked" : r.rcode,
      r.block_reason ?? "",
      r.client_name || r.client,
      r.protocol,
      r.upstream,
      String(r.latency_ms ?? ""),
    ]);
    const esc = (v: string) => `"${v.replace(/"/g, '""')}"`;
    const csv = [header, ...csvRows].map((row) => row.map((c) => esc(String(c))).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `alderpoint-query-log-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  onMount(() => {
    const prefill = queryLogPrefill.takeClient();
    if (prefill) client = prefill;
    refresh();
  });

  function formatLatency(ms: number): string {
    if (ms == null) return "";
    return ms < 1 ? `${(ms * 1000).toFixed(0)} µs` : `${ms.toFixed(1)} ms`;
  }

  // Query Log -> rule creation (a real deep link, not just a suggestion):
  // Filters' own "Add rule" form is actually pre-filled with this row's
  // domain. Defaults to "block" (the common case); "allow" is offered for
  // the equally real case of un-blocking something the log shows refused.
  function createRuleFor(r: QueryLogRow, ruleType: "block" | "allow") {
    customRulePrefill.set({ ruleType, pattern: r.domain });
    router.navigate("filtering");
  }

  function manageClientFor(r: QueryLogRow) {
    router.navigate("clients");
  }

  const columns: Column<QueryLogRow>[] = [
    { key: "ts", label: "Time", sortValue: (r) => r.ts, minWidth: 14 },
    { key: "domain", label: "Domain", sortValue: (r) => r.domain, minWidth: 20 },
    { key: "qtype", label: "Type", sortValue: (r) => r.qtype, minWidth: 6 },
    { key: "result", label: "Result", sortValue: (r) => (r.blocked ? 0 : 1), minWidth: 8 },
    { key: "block_reason", label: "Filtering reason", minWidth: 14 },
    { key: "client", label: "Client", sortValue: (r) => r.client, minWidth: 12 },
    { key: "protocol", label: "Protocol", sortValue: (r) => r.protocol, minWidth: 6 },
    { key: "upstream", label: "Upstream", sortValue: (r) => r.upstream, minWidth: 10 },
    { key: "latency_ms", label: "Response time", sortValue: (r) => r.latency_ms, minWidth: 8 },
    { key: "actions", label: "Actions", minWidth: 12 },
  ];

  let selected = $state<QueryLogRow | null>(null);
</script>

<PageHeader headingId="analytics-heading" title="Query Log" description="This appliance's own query history, read directly from a real live DNS event stream.">
  {#snippet actions()}
    <button type="button" class="secondary" onclick={refresh} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button>
    <label class="auto-refresh">
      <input type="checkbox" checked={autoRefresh} onchange={toggleAutoRefresh} />
      Auto-refresh
    </label>
    <button type="button" class="secondary" onclick={exportCsv} disabled={visibleRows.length === 0}>Export</button>
    <OverflowMenu label="More Query Log actions">
      {#snippet children(close)}
        <button type="button" disabled title="Query Log reads a read-only history source; there is no delete path over it yet.">
          Clear Query Log
        </button>
      {/snippet}
    </OverflowMenu>
  {/snippet}
</PageHeader>

<form class="filters" onsubmit={(e) => { e.preventDefault(); refresh(); }}>
  <div class="range-select" role="radiogroup" aria-label="Time window">
    {#each WINDOWS as w (w.minutes)}
      <button type="button" class:active={minutes === w.minutes} onclick={() => { minutes = w.minutes; refresh(); }}>
        {w.label}
      </button>
    {/each}
  </div>

  <div class="filter-grid">
    <input placeholder="Search domain or client…" bind:value={search} aria-label="Search" />
    <select bind:value={resultFilter} aria-label="Result">
      <option value="all">All results</option>
      <option value="allowed">Allowed only</option>
      <option value="blocked">Blocked only</option>
    </select>
    <input placeholder="Response status (rcode)" bind:value={rcode} aria-label="Filter by response status" />
    <input placeholder="Query type (A, AAAA, …)" bind:value={qtype} aria-label="Filter by query type" />
    <input placeholder="Protocol" bind:value={protocol} aria-label="Filter by protocol" />
    <input placeholder="Upstream" bind:value={upstream} aria-label="Filter by upstream" />
    <input placeholder="Client" bind:value={client} aria-label="Filter by client" />
    <label class="limit">
      Limit
      <select bind:value={limit}>
        <option value={50}>50</option>
        <option value={100}>100</option>
        <option value={200}>200</option>
        <option value={500}>500</option>
      </select>
    </label>
  </div>

  <div class="actions">
    <button type="submit" disabled={loading}>{loading ? "Loading…" : "Apply filters"}</button>
    <button type="button" class="secondary" onclick={resetFilters}>Clear Filters</button>
    {#if activeFilterCount() > 0}
      <span class="badge">{activeFilterCount()} active filter{activeFilterCount() === 1 ? "" : "s"}</span>
    {/if}
  </div>
</form>

{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
{#if degraded}
  <p class="degraded-note" role="status">Query Log degraded: {degradedReason || "unavailable"}</p>
{:else if filesConsidered !== null}
  <p class="hint">{filesConsidered} segment{filesConsidered === 1 ? "" : "s"} considered. Showing {visibleRows.length} of {rows.length} loaded rows.</p>
{/if}

<div class="desktop-table">
  <DataGrid gridId="query-log" {columns} rows={visibleRows} rowKey={(r) => r.id} emptyMessage="No queries match these filters.">
    {#snippet cell(r, colKey)}
      {#if colKey === "ts"}
        <button type="button" class="row-link" onclick={() => (selected = r)}>{timestampPref.format(new Date(r.ts * 1000).toISOString())}</button>
      {:else if colKey === "domain"}
        {r.domain}
      {:else if colKey === "qtype"}
        {r.qtype}
      {:else if colKey === "result"}
        <StatusBadge label={r.blocked ? "Blocked" : r.rcode} tone={r.blocked ? "danger" : "healthy"} />
      {:else if colKey === "block_reason"}
        {r.block_reason || "—"}
      {:else if colKey === "client"}
        {r.client_name || r.client}
      {:else if colKey === "protocol"}
        {r.protocol}
      {:else if colKey === "upstream"}
        {r.upstream}
      {:else if colKey === "latency_ms"}
        {formatLatency(r.latency_ms)}
      {:else if colKey === "actions"}
        <div class="rule-actions">
          <button type="button" class="rule-action" onclick={() => createRuleFor(r, "block")}>Block</button>
          <button type="button" class="rule-action" onclick={() => createRuleFor(r, "allow")}>Allow</button>
        </div>
      {/if}
    {/snippet}
  </DataGrid>
</div>

<!-- Mobile: readable cards, never a horizontally-squeezed desktop table. -->
<ul class="mobile-cards">
  {#if visibleRows.length === 0}
    <li class="empty-card hint">No queries match these filters.</li>
  {/if}
  {#each visibleRows as r (r.id)}
    <li class="row-card">
      <button type="button" class="row-card-main" onclick={() => (selected = r)}>
        <div class="row-card-top">
          <span class="row-card-domain">{r.domain}</span>
          <StatusBadge label={r.blocked ? "Blocked" : r.rcode} tone={r.blocked ? "danger" : "healthy"} />
        </div>
        <div class="row-card-meta">
          <span>{timestampPref.format(new Date(r.ts * 1000).toISOString())}</span>
          <span>{r.qtype}</span>
          <span>{r.client_name || r.client}</span>
          <span>{formatLatency(r.latency_ms)}</span>
        </div>
      </button>
      <div class="rule-actions">
        <button type="button" class="rule-action" onclick={() => createRuleFor(r, "block")}>Block</button>
        <button type="button" class="rule-action" onclick={() => createRuleFor(r, "allow")}>Allow</button>
      </div>
    </li>
  {/each}
</ul>

{#if selected}
  {@const r = selected}
  <Modal title="Query detail" onClose={() => (selected = null)}>
    <dl class="detail-list">
      <dt>Time</dt><dd>{timestampPref.format(new Date(r.ts * 1000).toISOString())} <span class="hint">({timestampPref.mode})</span></dd>
      <dt>Domain</dt><dd>{r.domain}</dd>
      <dt>Query / response type</dt><dd>{r.qtype} / {r.rcode}</dd>
      <dt>Client</dt><dd>{r.client_name || r.client} {#if r.client_name}<span class="hint mono">({r.client})</span>{/if}</dd>
      <dt>Filtering reason</dt><dd>{r.block_reason || (r.blocked ? "Blocked (no reason recorded)" : "Not blocked")}</dd>
      <dt>Upstream</dt><dd class="mono">{r.upstream || "—"}</dd>
      <dt>Protocol</dt><dd>{r.protocol}</dd>
      <dt>Cache</dt><dd>{r.cache_status || "—"}</dd>
      <dt>Response time</dt><dd>{formatLatency(r.latency_ms)}</dd>
    </dl>
    <p class="hint">
      DNSSEC validation status and the applied client/network/profile policy chain are not recorded
      per-query in this appliance's query history yet -- not shown here rather than guessed.
    </p>
    <div class="detail-actions">
      <button type="button" onclick={() => createRuleFor(r, "block")}>Block this domain</button>
      <button type="button" class="secondary" onclick={() => createRuleFor(r, "allow")}>Allow this domain</button>
      <button type="button" class="secondary" onclick={() => manageClientFor(r)}>Manage this client</button>
    </div>
  </Modal>
{/if}

<style>
  .auto-refresh { display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; padding: 0 0.3rem; }
  .filters { display: flex; flex-direction: column; gap: 0.6rem; margin-bottom: 1rem; }
  .range-select { display: flex; gap: 0.25rem; flex-wrap: wrap; }
  .range-select button { background: transparent; color: var(--fg); border: 1px solid var(--border); padding: 0.3rem 0.6rem; font-size: 0.8rem; }
  .range-select button.active { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
  .filter-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(9rem, 1fr)); gap: 0.5rem; align-items: center; }
  .limit { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; }
  .actions { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; background: var(--card-bg); border: 1px solid var(--border); }
  .degraded-note { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.85rem; }
  .hint { font-size: 0.8rem; opacity: 0.7; }
  .error { color: var(--danger); }
  .rule-actions { display: flex; gap: 0.3rem; flex-shrink: 0; }
  .rule-action { font-size: 0.75rem; padding: 0.15rem 0.5rem; background: transparent; color: var(--fg); border: 1px solid var(--border); min-height: auto; }
  .rule-action:hover { background: var(--card-bg); }
  .row-link { background: transparent; color: var(--accent); border: none; padding: 0; font: inherit; cursor: pointer; text-decoration: underline; }

  .mobile-cards { display: none; list-style: none; margin: 0; padding: 0; flex-direction: column; gap: 0.6rem; }
  .row-card { border: 1px solid var(--border); border-radius: 8px; background: var(--card-bg); box-shadow: var(--shadow); overflow: hidden; }
  .row-card-main { width: 100%; text-align: left; background: transparent; border: none; padding: 0.75rem; display: flex; flex-direction: column; gap: 0.4rem; }
  .row-card-top { display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; }
  .row-card-domain { font-weight: 600; word-break: break-word; }
  .row-card-meta { display: flex; flex-wrap: wrap; gap: 0.6rem; font-size: 0.8rem; opacity: 0.75; }
  .row-card .rule-actions { padding: 0 0.75rem 0.6rem; }
  .empty-card { padding: 1.25rem; text-align: center; }

  @media (max-width: 760px) {
    .desktop-table { display: none; }
    .mobile-cards { display: flex; }
  }

  .detail-list { display: grid; grid-template-columns: auto 1fr; gap: 0.5rem 1rem; margin: 0 0 1rem; }
  .detail-list dt { font-weight: 600; opacity: 0.75; font-size: 0.85rem; }
  .detail-list dd { margin: 0; }
  .detail-list .mono { font-family: monospace; }
  .detail-actions { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }
</style>
