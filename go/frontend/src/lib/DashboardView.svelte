<script lang="ts">
  import { onMount } from "svelte";
  import { api, type AnalyticsBucket, type AnalyticsTopRowsResponse, type ManagedClient, type ObservedClient, type UpstreamProfile, type UpstreamResolverStat } from "../api";
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

  // Protection Control: the global filtering on/off switch (see
  // handleProtectionToggle's doc comment for the exact V1.1.1 behavior
  // being matched). A fixed panel above the customizable cards, same as
  // V1's dashboard -- not itself a card an owner can hide.
  let protection = $state<Awaited<ReturnType<typeof api.protectionStatus>> | null>(null);
  let protectionError = $state("");
  let protectionBusy = $state(false);

  async function loadProtection() {
    try {
      protection = await api.protectionStatus(router.signal());
      protectionError = "";
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      protectionError = err instanceof Error ? err.message : String(err);
    }
  }

  async function toggleProtection() {
    protectionBusy = true;
    try {
      const resp = await api.protectionToggle();
      protection = { active: resp.active, enabled_blocklists: protection?.enabled_blocklists ?? 0, enabled_rules: protection?.enabled_rules ?? 0 };
      protectionError = "";
      await Promise.all([loadProtection(), loadSummary()]);
    } catch (err) {
      protectionError = err instanceof Error ? err.message : String(err);
    } finally {
      protectionBusy = false;
    }
  }

  let cacheStatus = $state<Awaited<ReturnType<typeof api.cacheStatus>> | null>(null);
  let cacheError = $state("");
  async function loadCache() {
    try {
      cacheStatus = await api.cacheStatus(router.signal());
      cacheError = "";
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      cacheError = err instanceof Error ? err.message : String(err);
    }
  }

  let topClients = $state<Awaited<ReturnType<typeof api.topClients>> | null>(null);
  async function loadTopClients() {
    try {
      topClients = await api.topClients(1440, router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      const reason = err instanceof Error ? err.message : String(err);
      topClients = { clients: [], total: 0, degraded: true, degraded_reason: reason };
    }
  }

  let qtypeBreakdown = $state<Awaited<ReturnType<typeof api.analyticsBreakdown>> | null>(null);
  let rcodeBreakdown = $state<Awaited<ReturnType<typeof api.analyticsBreakdown>> | null>(null);
  let protocolBreakdown = $state<Awaited<ReturnType<typeof api.analyticsBreakdown>> | null>(null);
  async function loadBreakdowns() {
    try {
      const [qtype, rcode, protocol] = await Promise.all([
        api.analyticsBreakdown("qtype", 1440, 10, router.signal()),
        api.analyticsBreakdown("rcode", 1440, 10, router.signal()),
        api.analyticsBreakdown("protocol", 1440, 10, router.signal()),
      ]);
      qtypeBreakdown = qtype;
      rcodeBreakdown = rcode;
      protocolBreakdown = protocol;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      const reason = err instanceof Error ? err.message : String(err);
      const degraded = { rows: [] as [string, number][], columns: [], degraded: true, degraded_reason: reason };
      qtypeBreakdown = degraded;
      rcodeBreakdown = degraded;
      protocolBreakdown = degraded;
    }
  }

  let recentActivity = $state<Awaited<ReturnType<typeof api.analyticsQueryLog>> | null>(null);
  async function loadRecentActivity() {
    try {
      recentActivity = await api.analyticsQueryLog({ minutes: 1440, limit: 15, offset: 0 }, router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      const reason = err instanceof Error ? err.message : String(err);
      recentActivity = { rows: [], degraded: true, degraded_reason: reason, limit: 15, offset: 0, filters: {} };
    }
  }

  let systemHealth = $state<Awaited<ReturnType<typeof api.health>> | null>(null);
  async function loadSystemHealth() {
    try {
      systemHealth = await api.health();
    } catch {
      systemHealth = null;
    }
  }

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

  // Top Upstream Resolvers -- real per-resolver dnsdist backend
  // telemetry (internal/dnsanalytics, polled from the live dnsdist
  // webserver API via apdns-hostagent), distinct from the "Upstreams"
  // mini-panel above (configured profiles only, no traffic data). See
  // GET /api/analytics/top-upstreams's own doc comment.
  let topUpstreams = $state<UpstreamResolverStat[] | null>(null);
  let topUpstreamsDegraded = $state(false);
  let topUpstreamsDegradedReason = $state("");

  const summaryGuard = new StaleGuard();
  const chartGuard = new StaleGuard();
  const topGuard = new StaleGuard();
  const clientsGuard = new StaleGuard();
  const upstreamsGuard = new StaleGuard();
  const topUpstreamsGuard = new StaleGuard();

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

  async function loadTopUpstreams() {
    const token = topUpstreamsGuard.start();
    try {
      const resp = await api.analyticsTopUpstreams(60, 10, router.signal());
      if (!topUpstreamsGuard.isCurrent(token)) return;
      topUpstreams = resp.resolvers;
      topUpstreamsDegraded = resp.degraded;
      topUpstreamsDegradedReason = resp.degraded_reason ?? "";
    } catch (err) {
      if (!topUpstreamsGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      topUpstreamsDegraded = true;
      topUpstreamsDegradedReason = err instanceof Error ? err.message : String(err);
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
    loadTopUpstreams();
    loadProtection();
    loadCache();
    loadTopClients();
    loadBreakdowns();
    loadRecentActivity();
    loadSystemHealth();
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

  <div class="card protection-panel">
    <div class="card-head">
      <h3>Protection Control</h3>
      {#if protection}
        <span class="mini-badge {protection.active ? 'mini-badge-ok' : 'mini-badge-observed'}">
          {protection.active ? "Active" : "Disabled"}
        </span>
      {/if}
    </div>
    {#if protectionError}
      <p class="degraded-note" role="status">Unable to load protection status: {protectionError}</p>
    {:else if !protection}
      <p class="hint">Loading…</p>
    {:else}
      <p class="hint">
        {protection.active
          ? `Filtering is active (${protection.enabled_blocklists} blocklist${protection.enabled_blocklists === 1 ? "" : "s"}, ${protection.enabled_rules} custom rule${protection.enabled_rules === 1 ? "" : "s"} enabled).`
          : "Filtering is disabled -- DNS queries are not being blocked or rewritten by policy."}
      </p>
      <button class={protection.active ? "danger" : ""} disabled={protectionBusy} onclick={toggleProtection}>
        {protectionBusy ? "Working…" : protection.active ? "Disable protection" : "Enable protection"}
      </button>
    {/if}
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
      {:else if card.id === "outcomes"}
        <div class="card wide-card">
          <h3>Query Outcomes</h3>
          {#if chartDegraded}
            <p class="degraded-note" role="status">Analytics degraded: {chartDegradedReason || "unavailable"}</p>
          {:else}
            {@const total = chartPoints.reduce((s, p) => s + p.total, 0)}
            {@const blocked = chartPoints.reduce((s, p) => s + p.blocked, 0)}
            {@const allowed = Math.max(total - blocked, 0)}
            {@const allowedPct = total ? (allowed / total) * 100 : 0}
            {@const blockedPct = total ? (blocked / total) * 100 : 0}
            <div class="outcome-row">
              <div class="outcome-head"><span>Allowed</span><span>{allowed.toLocaleString()}{total ? ` / ${allowedPct.toFixed(1)}%` : ""}</span></div>
              <span class="meter"><span style="width: {Math.min(allowedPct, 100).toFixed(1)}%"></span></span>
            </div>
            <div class="outcome-row">
              <div class="outcome-head"><span>Blocked</span><span>{blocked.toLocaleString()}{total ? ` / ${blockedPct.toFixed(1)}%` : ""}</span></div>
              <span class="meter blocked"><span style="width: {Math.min(blockedPct, 100).toFixed(1)}%"></span></span>
            </div>
            <p class="hint">Over the current Activity range ({RANGE_LABELS[rangeMode]}).</p>
          {/if}
        </div>
      {:else if card.id === "top-clients"}
        <div class="card wide-card">
          <h3>Top Clients <span class="scope">(last 24h)</span></h3>
          {#if !topClients}
            <p class="hint">Loading…</p>
          {:else if topClients.degraded}
            <p class="degraded-note" role="status">Analytics degraded: {topClients.degraded_reason || "unavailable"}</p>
          {:else if topClients.clients.length === 0}
            <p class="hint">No client activity in this window.</p>
          {:else}
            <table class="mini-table">
              <thead><tr><th>Client</th><th>Queries</th><th>Blocked</th></tr></thead>
              <tbody>
                {#each topClients.clients.slice(0, 8) as c (c.raw_client)}
                  <tr>
                    <td class="mono">{c.label}</td>
                    <td>{c.value.toLocaleString()} <span class="hint">({c.share.toFixed(1)}%)</span></td>
                    <td>{c.blocked.toLocaleString()} <span class="hint">({c.blocked_percent.toFixed(1)}%)</span></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      {:else if card.id === "qtypes" || card.id === "rcodes" || card.id === "protocols"}
        {@const data = card.id === "qtypes" ? qtypeBreakdown : card.id === "rcodes" ? rcodeBreakdown : protocolBreakdown}
        {@const label = card.id === "qtypes" ? "Query Types" : card.id === "rcodes" ? "Response Codes" : "Protocol Usage"}
        <div class="card wide-card">
          <h3>{label} <span class="scope">(last 24h)</span></h3>
          {#if !data}
            <p class="hint">Loading…</p>
          {:else if data.degraded}
            <p class="degraded-note" role="status">Analytics degraded: {data.degraded_reason || "unavailable"}</p>
          {:else if data.rows.length === 0}
            <p class="hint">No query activity in this window.</p>
          {:else}
            {@const total = data.rows.reduce((s, r) => s + r[1], 0)}
            {#each data.rows as row (row[0])}
              <div class="outcome-row">
                <div class="outcome-head"><span>{row[0]}</span><span>{row[1].toLocaleString()}{total ? ` / ${((row[1] / total) * 100).toFixed(1)}%` : ""}</span></div>
                <span class="meter"><span style="width: {Math.min(total ? (row[1] / total) * 100 : 0, 100).toFixed(1)}%"></span></span>
              </div>
            {/each}
          {/if}
        </div>
      {:else if card.id === "cache"}
        <div class="card wide-card">
          <div class="card-head">
            <h3>BIND Cache Effectiveness</h3>
            <button class="link" onclick={() => router.navigate("cache")}>Manage</button>
          </div>
          {#if cacheError}
            <p class="degraded-note" role="status">Unable to load cache status: {cacheError}</p>
          {:else if !cacheStatus}
            <p class="hint">Loading…</p>
          {:else if cacheStatus.bind.length === 0}
            <p class="hint">No BIND contexts configured.</p>
          {:else}
            {#each cacheStatus.bind as ctx (ctx.name)}
              <div class="cache-ctx">
                <div class="card-head"><strong>{ctx.name}</strong>{#if cacheStatus.bind.length > 1}<span class="hint">{ctx.reachable ? "reachable" : "unreachable"}</span>{/if}</div>
                {#if !ctx.cache_stats || !ctx.cache_stats.available}
                  <p class="hint">Unavailable: {ctx.cache_stats?.error || "BIND's statistics channel did not respond."}</p>
                {:else}
                  {@const hr = ctx.cache_stats.hit_ratio ?? 0}
                  <div class="outcome-row">
                    <div class="outcome-head"><span>Hit rate</span><span>{(hr * 100).toFixed(1)}%</span></div>
                    <span class="meter"><span style="width: {Math.min(hr * 100, 100).toFixed(1)}%"></span></span>
                  </div>
                  <p class="hint">Hits / misses: {ctx.cache_stats.hits.toLocaleString()} / {ctx.cache_stats.misses.toLocaleString()}</p>
                  {#if ctx.cache_stats.cache_size_bytes !== null}
                    <p class="hint">Cache memory: {(ctx.cache_stats.cache_size_bytes / 1048576).toFixed(1)} MB</p>
                  {/if}
                {/if}
              </div>
            {/each}
          {/if}
        </div>
      {:else if card.id === "recent-activity"}
        <div class="card wide-card">
          <div class="card-head">
            <h3>Recent Activity</h3>
            <button class="link" onclick={() => router.navigate("analytics")}>View all</button>
          </div>
          {#if !recentActivity}
            <p class="hint">Loading…</p>
          {:else if recentActivity.degraded}
            <p class="degraded-note" role="status">Analytics degraded: {recentActivity.degraded_reason || "unavailable"}</p>
          {:else if recentActivity.rows.length === 0}
            <p class="hint">No recent activity.</p>
          {:else}
            <table class="mini-table">
              <thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Status</th></tr></thead>
              <tbody>
                {#each recentActivity.rows as row (row.id)}
                  <tr>
                    <td class="mono hint">{new Date(row.ts * 1000).toLocaleTimeString()}</td>
                    <td class="mono">{row.client_name || row.client}</td>
                    <td class="mono">{row.domain}</td>
                    <td>{row.qtype}</td>
                    <td><span class="mini-badge {row.blocked ? 'mini-badge-blocked' : 'mini-badge-ok'}">{row.blocked ? "Blocked" : row.rcode}</span></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      {:else if card.id === "system-health"}
        <div class="card wide-card">
          <div class="card-head">
            <h3>System Health</h3>
            <button class="link" onclick={() => router.navigate("health")}>Details</button>
          </div>
          {#if !systemHealth}
            <p class="hint">Loading…</p>
          {:else}
            <div class="health-grid">
              {#each Object.entries(systemHealth.components) as [name, c] (name)}
                <div class="health-card">
                  <span>{name}</span>
                  <span class="mini-badge {c.status === 'ok' ? 'mini-badge-ok' : c.status === 'degraded' ? 'mini-badge-warn' : 'mini-badge-observed'}">{c.status}</span>
                </div>
              {/each}
            </div>
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
                      <td class="mono">{o.alias_label ?? o.address}</td>
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
      {:else if card.id === "top-upstreams"}
        <div class="card wide-card">
          <div class="card-head">
            <h3>Top Upstream Resolvers</h3>
            <button class="link" onclick={() => router.navigate("dns-settings")}>Manage</button>
          </div>
          {#if topUpstreamsDegraded}
            <p class="degraded-note" role="status">Resolver telemetry unavailable: {topUpstreamsDegradedReason || "unavailable"}</p>
          {/if}
          {#if topUpstreams === null}
            <p class="hint">Loading…</p>
          {:else if topUpstreams.length === 0}
            {#if !topUpstreamsDegraded}
              <p class="hint">No upstream resolver data yet. Resolver identities are configured; this panel fills once dnsdist reports real backend traffic.</p>
            {/if}
          {:else}
            <table class="mini-table">
              <thead><tr><th>Resolver</th><th>Protocol</th><th>Queries</th><th>Success</th><th>Avg latency</th><th>State</th></tr></thead>
              <tbody>
                {#each topUpstreams as u (u.resolver_key)}
                  <tr>
                    <td class="mono">{u.address || u.resolver_key}</td>
                    <td class="mono">{u.protocol || "--"}</td>
                    <td class="mono">{u.queries_attempted}</td>
                    <td class="mono">{u.queries_attempted > 0 ? Math.round((u.successful_responses / u.queries_attempted) * 100) + "%" : "--"}</td>
                    <td class="mono">{u.avg_latency_ms > 0 ? u.avg_latency_ms.toFixed(1) + " ms" : "--"}</td>
                    <td>{u.health_state || "unknown"}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
            <p class="hint">Resolver attribution is based on real dnsdist backend counters for this appliance's own managed upstream pool (last 60 minutes).</p>
          {/if}
        </div>
      {/if}
    {/each}
  </div>

</section>

<style>
  .dash-header { display: flex; justify-content: space-between; align-items: center; }
  .customize-btn { background: transparent; color: var(--fg); border: 1px solid var(--border); }
  .customize-panel { border: 1px solid var(--border); border-radius: 8px; padding: 0.4rem 0.25rem; margin: 0.75rem 0; background: var(--card-bg); box-shadow: var(--shadow); }
  .customize-panel ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; }
  /* Each row gets its own boundary (border-bottom, not just a gap) and a
     hover/focus highlight -- previously rows had only a small flex gap
     between them with nothing to mark where one ends and the next
     begins, which made reordering by eye easy to lose track of. */
  .customize-panel li {
    display: flex; justify-content: space-between; align-items: center; gap: 1rem;
    padding: 0.55rem 0.75rem; border-bottom: 1px solid var(--border); border-radius: 6px;
  }
  .customize-panel li:last-child { border-bottom: none; }
  .customize-panel li:hover { background: var(--nav-hover-bg); }
  .customize-panel li:has(:focus-visible) { background: var(--nav-hover-bg); outline: 2px solid var(--accent); outline-offset: -2px; }
  .customize-panel label { display: flex; align-items: center; gap: 0.6rem; font-size: 0.88rem; flex: 1; min-width: 0; }
  .reorder-btns { display: flex; gap: 0.3rem; flex-shrink: 0; }
  .reorder-btns button {
    padding: 0.2rem 0.55rem; background: var(--panel-elevated); border: 1px solid var(--border-strong);
    color: var(--fg); min-height: 30px;
  }
  .reorder-btns button:hover:not(:disabled) { background: var(--btn-bg); color: var(--accent-fg); border-color: var(--btn-bg); }

  .hint { font-size: 0.85rem; opacity: 0.75; }
  /* Flex, with stat-cards actually allowed to grow: previously
     stat-card had no flex-grow, so a short row (e.g. just Blocklists +
     Local DNS, with nothing else narrow enough to share it) stopped at
     two card-widths and left the rest of the row as dead space instead
     of the cards using it. flex: 1 1 14rem lets any number of
     stat-cards on one row share it evenly; wide-card still always
     takes the full row on its own. */
  .cards { display: flex; flex-wrap: wrap; gap: 1rem; margin-top: 0.75rem; align-items: stretch; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); box-shadow: var(--shadow); }
  .stat-card { flex: 1 1 14rem; min-width: 12rem; }
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

  .link { background: transparent; color: var(--accent); border: none; padding: 0; font-size: 0.85rem; cursor: pointer; text-decoration: underline; }
  .mono { font-family: monospace; font-size: 0.85rem; }
  .mini-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; margin-top: 0.5rem; }
  .mini-table th { text-align: left; font-weight: 600; opacity: 0.7; padding: 0.25rem 0.5rem 0.25rem 0; border-bottom: 1px solid var(--border); }
  .mini-table td { padding: 0.3rem 0.5rem 0.3rem 0; border-bottom: 1px solid var(--border); }
  .mini-table tr:last-child td { border-bottom: none; }
  .mini-badge { display: inline-block; padding: 0.1rem 0.45rem; border-radius: 999px; font-size: 0.72rem; }
  .mini-badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .mini-badge-observed { background: var(--border); color: var(--fg); }
  .mini-badge-blocked { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
  .mini-badge-warn { background: var(--badge-warn-bg); color: var(--badge-warn-fg); }

  .protection-panel { flex: 1 1 100%; margin-top: 0.75rem; }
  .protection-panel button { margin-top: 0.5rem; }
  .protection-panel button.danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); border-color: transparent; }

  .outcome-row { margin: 0.5rem 0; }
  .outcome-head { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 0.25rem; }
  .meter { display: block; height: 0.5rem; border-radius: 999px; background: var(--border); overflow: hidden; }
  .meter span { display: block; height: 100%; background: var(--accent); border-radius: 999px; }
  .meter.blocked span { background: var(--badge-danger-fg); }

  .cache-ctx + .cache-ctx { margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--border); }
  .health-grid { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }
  .health-card { display: flex; align-items: center; gap: 0.4rem; border: 1px solid var(--border); border-radius: 6px; padding: 0.3rem 0.6rem; font-size: 0.85rem; }
</style>
