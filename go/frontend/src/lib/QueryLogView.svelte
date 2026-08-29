<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type QueryLogRow, type QueryLogFilters } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";
  import { queryLogPrefill } from "../queryLogPrefill.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";

  // Query Log, backed by internal/rawquerylog -- a second, narrower
  // compatibility boundary over Python's raw per-query Parquet history
  // (analytics/queries/), distinct from internal/pyanalytics's
  // pre-aggregated aggregates.db buckets. See that package's doc comment
  // for exactly what it is: pure Go (no DuckDB/cgo), partition-pruned,
  // failure-isolated per segment, filters as a fixed exact-match
  // allowlist plus an optional post-scan substring "search".

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
  let blockedOnly = $state(false);
  let limit = $state(100);

  let rows = $state<QueryLogRow[]>([]);
  let degraded = $state(false);
  let degradedReason = $state("");
  let filesConsidered = $state<number | null>(null);
  let loadError = $state("");
  let loading = $state(false);
  const guard = new StaleGuard();

  function activeFilterCount(): number {
    return [search, domain, client, qtype, protocol, rcode, upstream, cacheStatus].filter((v) => v !== "").length + (blockedOnly ? 1 : 0);
  }

  async function refresh() {
    const token = guard.start();
    loading = true;
    const f: QueryLogFilters = {
      minutes, search, domain, client, qtype, protocol, rcode, upstream,
      cache_status: cacheStatus, blocked_only: blockedOnly, limit,
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

  function resetFilters() {
    search = domain = client = qtype = protocol = rcode = upstream = cacheStatus = "";
    blockedOnly = false;
    refresh();
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

  const columns: Column<QueryLogRow>[] = [
    { key: "ts", label: "Time", sortValue: (r) => r.ts, minWidth: 14 },
    { key: "domain", label: "Domain", sortValue: (r) => r.domain, minWidth: 20 },
    { key: "client", label: "Client", sortValue: (r) => r.client, minWidth: 12 },
    { key: "qtype", label: "Type", sortValue: (r) => r.qtype, minWidth: 6 },
    { key: "protocol", label: "Proto", sortValue: (r) => r.protocol, minWidth: 6 },
    { key: "rcode", label: "Rcode", sortValue: (r) => r.rcode, minWidth: 8 },
    { key: "blocked", label: "Blocked", sortValue: (r) => (r.blocked ? 1 : 0), minWidth: 8 },
    { key: "latency_ms", label: "Latency", sortValue: (r) => r.latency_ms, minWidth: 8 },
    { key: "cache_status", label: "Cache", sortValue: (r) => r.cache_status, minWidth: 8 },
    { key: "upstream", label: "Upstream", sortValue: (r) => r.upstream, minWidth: 10 },
  ];
</script>

<section aria-labelledby="analytics-heading" class="query-log">
  <h2 id="analytics-heading">Query Log</h2>
  <p class="scope-note">
    Reads Python's raw per-query history directly (own pure-Go Parquet reader, no DuckDB/cgo) -- see
    the parity matrix. A wide window over a very large history is scanned with a bounded safety cap,
    disclosed via <code>files_considered</code>, rather than an unbounded read.
  </p>

  <form class="filters" onsubmit={(e) => { e.preventDefault(); refresh(); }}>
    <div class="range-select" role="radiogroup" aria-label="Time window">
      {#each WINDOWS as w (w.minutes)}
        <button type="button" class:active={minutes === w.minutes} onclick={() => { minutes = w.minutes; refresh(); }}>
          {w.label}
        </button>
      {/each}
    </div>

    <div class="filter-grid">
      <input placeholder="Search all fields…" bind:value={search} aria-label="Search" />
      <input placeholder="Domain" bind:value={domain} aria-label="Filter by domain" />
      <input placeholder="Client" bind:value={client} aria-label="Filter by client" />
      <input placeholder="Query type (A, AAAA, …)" bind:value={qtype} aria-label="Filter by query type" />
      <input placeholder="Protocol" bind:value={protocol} aria-label="Filter by protocol" />
      <input placeholder="Rcode" bind:value={rcode} aria-label="Filter by rcode" />
      <input placeholder="Upstream" bind:value={upstream} aria-label="Filter by upstream" />
      <input placeholder="Cache status" bind:value={cacheStatus} aria-label="Filter by cache status" />
      <label class="checkbox">
        <input type="checkbox" bind:checked={blockedOnly} />
        Blocked only
      </label>
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
      <button type="submit" disabled={loading}>{loading ? "Loading…" : "Refresh"}</button>
      <button type="button" class="clear-filters" onclick={resetFilters}>Clear filters</button>
      {#if activeFilterCount() > 0}
        <span class="badge">{activeFilterCount()} active filter{activeFilterCount() === 1 ? "" : "s"}</span>
      {/if}
    </div>
  </form>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
  {#if degraded}
    <p class="degraded-note" role="status">Query Log degraded: {degradedReason || "unavailable"}</p>
  {:else if filesConsidered !== null}
    <p class="hint">{filesConsidered} segment{filesConsidered === 1 ? "" : "s"} considered.</p>
  {/if}

  <DataGrid gridId="query-log" {columns} {rows} rowKey={(r) => r.id} emptyMessage="No queries match these filters.">
    {#snippet cell(r, colKey)}
      {#if colKey === "ts"}
        {timestampPref.format(new Date(r.ts * 1000).toISOString())}
      {:else if colKey === "domain"}
        {r.domain}
      {:else if colKey === "client"}
        {r.client_name || r.client}
      {:else if colKey === "qtype"}
        {r.qtype}
      {:else if colKey === "protocol"}
        {r.protocol}
      {:else if colKey === "rcode"}
        {r.rcode}
      {:else if colKey === "blocked"}
        <span class="badge {r.blocked ? 'badge-danger' : 'badge-ok'}">{r.blocked ? "Blocked" : "Allowed"}</span>
      {:else if colKey === "latency_ms"}
        {formatLatency(r.latency_ms)}
      {:else if colKey === "cache_status"}
        {r.cache_status}
      {:else if colKey === "upstream"}
        {r.upstream}
      {/if}
    {/snippet}
  </DataGrid>
</section>

<style>
  .query-log { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .filters { display: flex; flex-direction: column; gap: 0.6rem; }
  .range-select { display: flex; gap: 0.25rem; flex-wrap: wrap; }
  .range-select button { background: transparent; color: var(--fg); border: 1px solid var(--border); padding: 0.3rem 0.6rem; font-size: 0.8rem; }
  .range-select button.active { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
  .filter-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(9rem, 1fr)); gap: 0.5rem; align-items: center; }
  .filter-grid input[type="text"], .filter-grid input:not([type]) { width: 100%; }
  .checkbox { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; }
  .limit { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; }
  .actions { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; background: var(--card-bg); border: 1px solid var(--border); }
  .badge-danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); border-color: transparent; }
  .badge-ok { background: var(--badge-ok-bg, transparent); }
  .degraded-note { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.85rem; }
  .hint { font-size: 0.8rem; opacity: 0.7; }
  .error { color: var(--badge-danger-fg); }
</style>
