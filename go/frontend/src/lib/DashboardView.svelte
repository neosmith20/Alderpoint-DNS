<script lang="ts">
  import { onMount } from "svelte";
  import { api, type AnalyticsBucket, type AnalyticsTopRowsResponse, type ManagedClient, type ObservedClient, type UpstreamProfile } from "../api";
  import { router } from "../router.svelte";
  import { StaleGuard } from "../staleGuard";
  import { ALL_CARDS, loadCardOrder, saveCardOrder, type CardState } from "../dashboardCards";
  import ActivityChart from "./ActivityChart.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";

  // Real, incrementally-scoped Dashboard. Blocklists/Local DNS come from
  // the Go control plane natively; DNS Activity/Top Domains come through
  // the pyanalytics compatibility boundary (internal/pyanalytics, a
  // read-only reader of Python's own aggregates.db -- see its doc
  // comment). Top Blocked Domains reads through a second, narrower
  // boundary (internal/rawquerylog, a pure-Go Parquet reader over
  // Python's raw per-query history) that's optional at startup
  // (-query-log-dir) -- the API's own `degraded` flag is what this page
  // actually renders on, so this card is real whenever that reader is
  // configured and honestly degraded when it isn't, never hardcoded
  // either way here.

  type RangeMode = "live" | "1h" | "24h" | "7d";
  const RANGE_LABELS: Record<RangeMode, string> = { live: "Live", "1h": "Last hour", "24h": "Last 24 hours", "7d": "Last 7 days" };

  let summary = $state<Awaited<ReturnType<typeof api.dashboardSummary>> | null>(null);
  let summaryError = $state("");

  let rangeMode = $state<RangeMode>("live");
  let chartPoints = $state<{ x: number; total: number; blocked: number }[]>([]);
  let chartDegraded = $state(false);
  let chartDegradedReason = $state("");
  let chartLoading = $state(false);

  let topDomains = $state<AnalyticsTopRowsResponse | null>(null);
  let topBlockedDomains = $state<AnalyticsTopRowsResponse | null>(null);

  let cardOrder = $state<CardState[]>(loadCardOrder());
  let customizeOpen = $state(false);

  // Clients/Upstreams mini-panels -- real data from internal/clients
  // (managed clients), the observed-clients boundary (internal/pyanalytics,
  // see GET /api/clients/observed's own doc comment), and internal/upstreams.
  // These were the two Dashboard panels the parity matrix's Dashboard row
  // recorded as blocked on "the policy boundary" -- that boundary (native
  // Go internal/policy/internal/clients/internal/upstreams) now exists, so
  // this closes the gap rather than leaving the stale disclosure in place.
  let managedClients = $state<ManagedClient[] | null>(null);
  let observedClients = $state<ObservedClient[] | null>(null);
  let observedDegraded = $state(false);
  let observedDegradedReason = $state("");
  let upstreams = $state<UpstreamProfile[] | null>(null);
  let clientsError = $state("");
  let upstreamsError = $state("");

  const summaryGuard = new StaleGuard();
  const chartGuard = new StaleGuard();
  const topGuard = new StaleGuard();
  const clientsGuard = new StaleGuard();
  const upstreamsGuard = new StaleGuard();

  async function loadClientsMini() {
    const token = clientsGuard.start();
    try {
      const [clientsResp, observedResp] = await Promise.all([
        api.listClients(router.signal()),
        api.listObservedClients(router.signal()),
      ]);
      if (!clientsGuard.isCurrent(token)) return;
      managedClients = clientsResp.clients;
      observedClients = observedResp.observed;
      observedDegraded = observedResp.degraded;
      observedDegradedReason = observedResp.degraded_reason ?? "";
      clientsError = "";
    } catch (err) {
      if (!clientsGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      clientsError = err instanceof Error ? err.message : String(err);
    }
  }

  async function loadUpstreamsMini() {
    const token = upstreamsGuard.start();
    try {
      const resp = await api.listUpstreams(router.signal());
      if (!upstreamsGuard.isCurrent(token)) return;
      upstreams = resp.upstreams;
      upstreamsError = "";
    } catch (err) {
      if (!upstreamsGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      upstreamsError = err instanceof Error ? err.message : String(err);
    }
  }

  async function loadSummary() {
    const token = summaryGuard.start();
    try {
      const resp = await api.dashboardSummary(router.signal());
      if (!summaryGuard.isCurrent(token)) return;
      summary = resp;
      summaryError = "";
    } catch (err) {
      if (!summaryGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      summaryError = err instanceof Error ? err.message : String(err);
    }
  }

  function bucketsToPoints(buckets: AnalyticsBucket[]) {
    return buckets.map((b) => ({ x: b.bucket_start, total: b.total_queries, blocked: b.blocked_queries }));
  }

  async function loadTimeseries(mode: RangeMode) {
    const token = chartGuard.start();
    chartLoading = true;
    try {
      const minutes = mode === "1h" ? 60 : mode === "24h" ? 1440 : 10080;
      const granularity = mode === "1h" ? "minute" : mode === "24h" ? "hour" : "day";
      const resp = await api.analyticsTimeseries(minutes, granularity, router.signal());
      if (!chartGuard.isCurrent(token)) return;
      chartDegraded = resp.degraded;
      chartDegradedReason = resp.degraded_reason ?? "";
      chartPoints = bucketsToPoints(resp.buckets);
    } catch (err) {
      if (!chartGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      chartDegraded = true;
      chartDegradedReason = err instanceof Error ? err.message : String(err);
    } finally {
      if (chartGuard.isCurrent(token)) chartLoading = false;
    }
  }

  async function loadLiveTick() {
    const token = chartGuard.start();
    try {
      const resp = await api.analyticsLiveActivity(300, router.signal());
      if (!chartGuard.isCurrent(token)) return;
      chartDegraded = resp.degraded;
      chartDegradedReason = resp.degraded_reason ?? "";
      chartPoints = bucketsToPoints(resp.buckets);
      chartLoading = false;
    } catch (err) {
      if (!chartGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      chartDegraded = true;
      chartDegradedReason = err instanceof Error ? err.message : String(err);
      chartLoading = false;
    }
  }

  async function loadTopDomains() {
    const token = topGuard.start();
    try {
      const [top, blocked] = await Promise.all([
        api.analyticsTopDomains(1440, 15, router.signal()),
        api.analyticsTopBlockedDomains(1440, 15, router.signal()),
      ]);
      if (!topGuard.isCurrent(token)) return;
      topDomains = top;
      topBlockedDomains = blocked;
    } catch (err) {
      if (!topGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      const reason = err instanceof Error ? err.message : String(err);
      topDomains = { rows: [], columns: ["domain", "count"], degraded: true, degraded_reason: reason };
      topBlockedDomains = { rows: [], columns: ["domain", "count"], degraded: true, degraded_reason: reason };
    }
  }

  // Live polling: a real 1-second interval while (and only while) both
  // "live" mode is selected and this page is mounted -- cleared on mode
  // change and on route-away (Svelte tears down the effect when the
  // component is destroyed), so no background polling continues off this
  // route.
  $effect(() => {
    if (rangeMode !== "live") return;
    chartLoading = true;
    loadLiveTick();
    const id = setInterval(loadLiveTick, 1000);
    return () => clearInterval(id);
  });

  function selectRange(mode: RangeMode) {
    if (mode === rangeMode) return;
    rangeMode = mode;
    if (mode !== "live") {
      chartPoints = [];
      loadTimeseries(mode);
    }
  }

  onMount(() => {
    loadSummary();
    loadTopDomains();
    loadClientsMini();
    loadUpstreamsMini();
  });

  // --- card customization ---
  function toggleVisible(id: string) {
    cardOrder = cardOrder.map((c) => (c.id === id ? { ...c, visible: !c.visible } : c));
    saveCardOrder(cardOrder);
  }
  function move(id: string, dir: -1 | 1) {
    const i = cardOrder.findIndex((c) => c.id === id);
    const j = i + dir;
    if (i < 0 || j < 0 || j >= cardOrder.length) return;
    const next = [...cardOrder];
    [next[i], next[j]] = [next[j], next[i]];
    cardOrder = next;
    saveCardOrder(cardOrder);
  }
  function cardLabel(id: string): string {
    return ALL_CARDS.find((c) => c.id === id)?.label ?? id;
  }

  const domainColumns: Column<[string, number]>[] = [
    { key: "domain", label: "Domain", sortValue: (r) => r[0] },
    { key: "count", label: "Queries", sortValue: (r) => r[1] },
  ];
</script>

<section aria-labelledby="dashboard-heading" class="dashboard">
  <div class="dash-header">
    <h2 id="dashboard-heading">Dashboard</h2>
    <button class="customize-btn" onclick={() => (customizeOpen = !customizeOpen)} aria-expanded={customizeOpen}>
      Customize
    </button>
  </div>

  {#if customizeOpen}
    <div class="customize-panel" role="region" aria-label="Customize dashboard cards">
      <ul>
        {#each cardOrder as card, i (card.id)}
          <li>
            <label>
              <input type="checkbox" checked={card.visible} onchange={() => toggleVisible(card.id)} />
              {cardLabel(card.id)}
            </label>
            <span class="reorder-btns">
              <button disabled={i === 0} onclick={() => move(card.id, -1)} aria-label={`Move ${cardLabel(card.id)} up`}>&uarr;</button>
              <button disabled={i === cardOrder.length - 1} onclick={() => move(card.id, 1)} aria-label={`Move ${cardLabel(card.id)} down`}>&darr;</button>
            </span>
          </li>
        {/each}
      </ul>
    </div>
  {/if}

  {#if summaryError}
    <p class="error" role="alert">{summaryError}</p>
  {/if}

  <div class="cards">
    {#each cardOrder.filter((c) => c.visible) as card (card.id)}
      {#if card.id === "blocklists"}
        <div class="card stat-card">
          <h3>Blocklists</h3>
          {#if !summary}
            <p class="hint">Loading…</p>
          {:else}
            <p class="big">{summary.blocklists.enabled}<span class="of"> / {summary.blocklists.total} enabled</span></p>
            <p class="hint">{summary.blocklists.total_rules.toLocaleString()} rules total</p>
            {#if summary.blocklists.attention_required > 0}
              <p class="badge badge-attention">{summary.blocklists.attention_required} need attention</p>
            {/if}
          {/if}
        </div>
      {:else if card.id === "localdns"}
        <div class="card stat-card">
          <h3>Local DNS</h3>
          {#if !summary}
            <p class="hint">Loading…</p>
          {:else}
            <p class="big">{summary.local_dns.enabled}<span class="of"> / {summary.local_dns.total} enabled</span></p>
          {/if}
        </div>
      {:else if card.id === "activity"}
        <div class="card wide-card">
          <div class="card-head">
            <h3>DNS Activity</h3>
            <div class="range-select" role="radiogroup" aria-label="Activity time range">
              {#each Object.keys(RANGE_LABELS) as m}
                <button class:active={rangeMode === m} onclick={() => selectRange(m as RangeMode)}>{RANGE_LABELS[m as RangeMode]}</button>
              {/each}
            </div>
          </div>
          {#if chartDegraded}
            <p class="degraded-note" role="status">Analytics degraded: {chartDegradedReason || "unavailable"}</p>
          {:else if chartLoading && chartPoints.length === 0}
            <p class="hint">Loading…</p>
          {:else}
            <ActivityChart points={chartPoints} />
          {/if}
        </div>
      {:else if card.id === "top-domains"}
        <div class="card wide-card">
          <h3>Top Domains <span class="scope">(last 24h)</span></h3>
          {#if !topDomains}
            <p class="hint">Loading…</p>
          {:else if topDomains.degraded}
            <p class="degraded-note" role="status">Analytics degraded: {topDomains.degraded_reason || "unavailable"}</p>
          {:else}
            <DataGrid
              gridId="dashboard-top-domains"
              columns={domainColumns}
              rows={topDomains.rows}
              rowKey={(r) => r[0]}
              emptyMessage="No query activity in this window."
            >
              {#snippet cell(row, colKey)}
                {colKey === "domain" ? row[0] : row[1].toLocaleString()}
              {/snippet}
            </DataGrid>
            {#if topDomains.aggregation_note}<p class="hint">{topDomains.aggregation_note}</p>{/if}
          {/if}
        </div>
      {:else if card.id === "top-blocked-domains"}
        <div class="card wide-card">
          <h3>Top Blocked Domains <span class="scope">(last 24h)</span></h3>
          {#if !topBlockedDomains}
            <p class="hint">Loading…</p>
          {:else if topBlockedDomains.degraded}
            <p class="degraded-note" role="status">Unavailable: {topBlockedDomains.degraded_reason}</p>
          {:else}
            <DataGrid
              gridId="dashboard-top-blocked-domains"
              columns={domainColumns}
              rows={topBlockedDomains.rows}
              rowKey={(r) => r[0]}
              emptyMessage="No blocked queries in this window."
            >
              {#snippet cell(row, colKey)}
                {colKey === "domain" ? row[0] : row[1].toLocaleString()}
              {/snippet}
            </DataGrid>
          {/if}
        </div>
      {:else if card.id === "clients"}
        <div class="card wide-card">
          <div class="card-head">
            <h3>Clients</h3>
            <button class="link" onclick={() => router.navigate("clients")}>Manage</button>
          </div>
          {#if clientsError}
            <p class="degraded-note" role="status">Unable to load clients: {clientsError}</p>
          {:else if managedClients === null || observedClients === null}
            <p class="hint">Loading…</p>
          {:else}
            {@const unmanagedObserved = observedClients.filter((o) => !o.managed).slice(0, 5)}
            {@const managedSlice = managedClients.slice(0, 5)}
            {#if managedSlice.length === 0 && unmanagedObserved.length === 0}
              <p class="hint">
                No managed clients, and no DNS activity observed yet{observedDegraded ? ` (observed clients unavailable: ${observedDegradedReason || "unavailable"})` : ""}.
              </p>
            {:else}
              <table class="mini-table">
                <thead><tr><th>State</th><th>Name / address</th><th>Identifier</th></tr></thead>
                <tbody>
                  {#each managedSlice as c (c.id)}
                    <tr>
                      <td><span class="mini-badge mini-badge-ok">managed</span></td>
                      <td>{c.name}</td>
                      <td class="mono">
                        {#if c.identifiers.length}
                          {c.identifiers.map((i) => i.value).join(", ")}
                        {:else}
                          <span class="hint">none</span>
                        {/if}
                      </td>
                    </tr>
                  {/each}
                  {#each unmanagedObserved as o (o.address)}
                    <tr>
                      <td><span class="mini-badge mini-badge-observed">observed</span></td>
                      <td class="mono">{o.address}</td>
                      <td class="mono"><span class="hint">{o.query_count} queries</span></td>
                    </tr>
                  {/each}
                </tbody>
              </table>
              {#if observedDegraded}
                <p class="hint">Observed clients unavailable: {observedDegradedReason || "unavailable"} -- managed clients above are still real.</p>
              {/if}
            {/if}
          {/if}
        </div>
      {:else if card.id === "upstreams"}
        <div class="card wide-card">
          <div class="card-head">
            <h3>Upstreams</h3>
            <button class="link" onclick={() => router.navigate("upstreams")}>Manage</button>
          </div>
          {#if upstreamsError}
            <p class="degraded-note" role="status">Unable to load upstreams: {upstreamsError}</p>
          {:else if upstreams === null}
            <p class="hint">Loading…</p>
          {:else if upstreams.length === 0}
            <p class="hint">No upstream profiles configured.</p>
          {:else}
            <table class="mini-table">
              <thead><tr><th>Name</th><th>Transport</th><th>Strategy</th><th>Enabled</th></tr></thead>
              <tbody>
                {#each upstreams.slice(0, 5) as u (u.upstream_profile_id)}
                  <tr>
                    <td>{u.name}</td>
                    <td class="mono">{u.transport}</td>
                    <td class="mono">{u.strategy}</td>
                    <td>{u.enabled ? "yes" : "no"}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      {/if}
    {/each}
  </div>

</section>

<style>
  .dash-header { display: flex; justify-content: space-between; align-items: center; }
  .customize-btn { background: transparent; color: var(--fg); border: 1px solid var(--border); }
  .customize-panel { border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem 1rem; margin: 0.75rem 0; background: var(--card-bg); }
  .customize-panel ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
  .customize-panel li { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
  .customize-panel label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.88rem; }
  .reorder-btns { display: flex; gap: 0.25rem; }
  .reorder-btns button { padding: 0.15rem 0.5rem; }

  .hint { font-size: 0.85rem; opacity: 0.75; }
  .cards { display: flex; flex-wrap: wrap; gap: 1rem; margin-top: 0.75rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); }
  .stat-card { min-width: 12rem; }
  .wide-card { flex: 1 1 100%; min-width: 20rem; }
  .card h3 { margin: 0 0 0.4rem; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; opacity: 0.75; }
  .card-head { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
  .scope { text-transform: none; font-weight: 400; opacity: 0.7; }
  .big { margin: 0; font-size: 1.9rem; font-weight: 700; }
  .of { font-size: 1rem; font-weight: 400; opacity: 0.7; }
  .badge { display: inline-block; margin-top: 0.5rem; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.78rem; }
  .badge-attention { background: var(--badge-danger-bg); color: var(--badge-danger-fg); font-weight: 600; }
  .range-select { display: flex; gap: 0.25rem; flex-wrap: wrap; }
  .range-select button { background: transparent; color: var(--fg); border: 1px solid var(--border); padding: 0.3rem 0.6rem; font-size: 0.8rem; }
  .range-select button.active { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
  .degraded-note { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.85rem; }
  .scope-note { margin-top: 1.25rem; max-width: 44rem; }

  .link { background: transparent; color: var(--accent); border: none; padding: 0; font-size: 0.85rem; cursor: pointer; text-decoration: underline; }
  .mono { font-family: monospace; font-size: 0.85rem; }
  .mini-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; margin-top: 0.5rem; }
  .mini-table th { text-align: left; font-weight: 600; opacity: 0.7; padding: 0.25rem 0.5rem 0.25rem 0; border-bottom: 1px solid var(--border); }
  .mini-table td { padding: 0.3rem 0.5rem 0.3rem 0; border-bottom: 1px solid var(--border); }
  .mini-table tr:last-child td { border-bottom: none; }
  .mini-badge { display: inline-block; padding: 0.1rem 0.45rem; border-radius: 999px; font-size: 0.72rem; }
  .mini-badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .mini-badge-observed { background: var(--border); color: var(--fg); }
</style>
