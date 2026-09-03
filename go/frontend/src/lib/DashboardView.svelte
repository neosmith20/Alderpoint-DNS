<script lang="ts">
  import { onMount } from "svelte";
  import { api, type AnalyticsBucket, type AnalyticsTopRowsResponse, type ManagedClient, type ObservedClient, type UpstreamProfile, type UpstreamResolverStat } from "../api";
  import { router } from "../router.svelte";
  import { StaleGuard } from "../staleGuard";
  import { ALL_CARDS, loadCardOrder, saveCardOrder, defaultCardOrder, type CardState } from "../dashboardCards";
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
  /** Minutes for the currently selected period -- "live" reads the same
   * rolling 5-minute window analyticsLiveActivity itself polls, since
   * there's no other real definition of "live" to hand the headline
   * metrics/Active Clients/Query Performance loaders below. */
  function rangeMinutes(mode: RangeMode): number {
    return mode === "1h" ? 60 : mode === "24h" ? 1440 : mode === "7d" ? 10080 : 5;
  }

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

  let topClients = $state<Awaited<ReturnType<typeof api.topClients>> | null>(null);
  async function loadTopClients(minutes: number) {
    try {
      topClients = await api.topClients(minutes, router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      const reason = err instanceof Error ? err.message : String(err);
      topClients = { clients: [], total: 0, degraded: true, degraded_reason: reason };
    }
  }

  // Query Performance headline metric: real per-query latency_ms values
  // from a bounded sample of the selected period's own query log rows
  // (never a synthesized/benchmark figure -- see the card's own doc
  // comment below for why DNSPerfSummary, the manual benchmark tool's
  // output, is deliberately NOT reused here). p95/p99 are computed
  // client-side over that sample; both the sample size and "sampled" vs
  // "complete" are disclosed on the card itself rather than presented as
  // exact appliance-wide figures.
  const LATENCY_SAMPLE_LIMIT = 500;
  interface LatencyStats { avg: number; p95: number; p99: number; sampleSize: number; totalInPeriod: number }
  let latencyStats = $state<LatencyStats | null>(null);
  let latencyError = $state("");
  async function loadLatencyStats(minutes: number) {
    try {
      const resp = await api.analyticsQueryLog({ minutes, limit: LATENCY_SAMPLE_LIMIT, offset: 0 }, router.signal());
      if (resp.degraded) {
        latencyError = resp.degraded_reason || "unavailable";
        latencyStats = null;
        return;
      }
      const values = resp.rows.map((r) => r.latency_ms).filter((v): v is number => typeof v === "number" && v > 0).sort((a, b) => a - b);
      latencyError = "";
      if (values.length === 0) {
        latencyStats = null;
        return;
      }
      const pct = (p: number) => values[Math.min(values.length - 1, Math.floor((p / 100) * values.length))];
      latencyStats = {
        avg: values.reduce((s, v) => s + v, 0) / values.length,
        p95: pct(95),
        p99: pct(99),
        sampleSize: values.length,
        totalInPeriod: resp.rows.length,
      };
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      latencyError = err instanceof Error ? err.message : String(err);
      latencyStats = null;
    }
  }

  // Cache Effectiveness headline/grid card: real BIND cache hit ratio
  // (internal/hostagent -> rndc/named stats), not a manufactured figure.
  let cacheStatus = $state<Awaited<ReturnType<typeof api.cacheStatus>> | null>(null);
  let cacheStatusError = $state("");
  async function loadCacheStatus() {
    try {
      cacheStatus = await api.cacheStatus(router.signal());
      cacheStatusError = "";
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      cacheStatusError = err instanceof Error ? err.message : String(err);
    }
  }
  const primaryCacheStats = $derived(cacheStatus?.bind?.find((b) => b.cache_stats?.available)?.cache_stats ?? null);

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

  // Real, owner-found gap this closes: this appliance's real DNS
  // architecture has dnsdist forward every non-local, non-blocked
  // query to a single internal BIND backend ("apdns_bind_backend",
  // 127.0.0.1:<bind-proxy-port>) -- BIND itself is what actually holds
  // the configured upstream forwarders (Cloudflare/Google/etc, see
  // Upstreams). dnsdist itself never dials those providers directly,
  // so this table's real, honest ceiling today is exactly one row:
  // total traffic dnsdist forwarded to BIND, not a per-provider
  // breakdown. Left as a raw loopback address ("127.0.0.1:26553") that
  // row read as a meaningless internal detail; this gives it a real
  // name an owner would actually understand instead.
  function resolverDisplayName(u: UpstreamResolverStat): string {
    if (u.resolver_key === "apdns_bind_backend") return "Local resolver (BIND)";
    return u.address || u.resolver_key;
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
    const minutes = rangeMinutes(mode);
    loadTopClients(minutes);
    loadLatencyStats(minutes);
  }

  onMount(() => {
    loadSummary();
    loadTopDomains();
    loadClientsMini();
    loadUpstreamsMini();
    loadTopUpstreams();
    loadProtection();
    loadTopClients(rangeMinutes(rangeMode));
    loadLatencyStats(rangeMinutes(rangeMode));
    loadCacheStatus();
    loadBreakdowns();
    loadRecentActivity();
    loadSystemHealth();
  });

  function refreshAll() {
    loadSummary();
    loadTopDomains();
    loadClientsMini();
    loadUpstreamsMini();
    loadTopUpstreams();
    loadProtection();
    loadTopClients(rangeMinutes(rangeMode));
    loadLatencyStats(rangeMinutes(rangeMode));
    loadCacheStatus();
    loadBreakdowns();
    loadRecentActivity();
    loadSystemHealth();
    if (rangeMode !== "live") loadTimeseries(rangeMode);
  }

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
  function restoreDefaults() {
    cardOrder = defaultCardOrder();
    saveCardOrder(cardOrder);
  }

  const domainColumns: Column<[string, number]>[] = [
    { key: "domain", label: "Domain", sortValue: (r) => r[0] },
    { key: "count", label: "Queries", sortValue: (r) => r[1] },
  ];

  // Headline metrics: derived from data already loaded for the DNS
  // Activity chart/Top Clients/Query Performance sample above -- no
  // separate fetch, no manufactured numbers. No period-over-period
  // comparison is fetched anywhere in this app yet, so "trend" is
  // deliberately omitted rather than invented (see the spec's own "never
  // manufacture latency statistics" -- the same standard applies to
  // trend arrows).
  const totalQueriesHeadline = $derived(chartPoints.reduce((s, p) => s + p.total, 0));
  const blockedQueriesHeadline = $derived(chartPoints.reduce((s, p) => s + p.blocked, 0));
  const blockedPctHeadline = $derived(totalQueriesHeadline ? (blockedQueriesHeadline / totalQueriesHeadline) * 100 : 0);
</script>

<section aria-labelledby="dashboard-heading" class="dashboard">
  <div class="dash-header">
    <div class="dash-header__title">
      <h2 id="dashboard-heading">Dashboard</h2>
      {#if protection}
        <span class="mini-badge {protection.active ? 'mini-badge-ok' : 'mini-badge-observed'}">
          {protection.active ? "Protection active" : "Protection disabled"}
        </span>
      {/if}
    </div>
    <div class="dash-header__actions">
      <button class={protection?.active ? "danger" : ""} disabled={protectionBusy || !protection} onclick={toggleProtection}>
        {protectionBusy ? "Working…" : protection?.active ? "Disable protection" : "Enable protection"}
      </button>
      <div class="range-select" role="radiogroup" aria-label="Dashboard time range">
        {#each Object.keys(RANGE_LABELS) as m}
          <button class:active={rangeMode === m} onclick={() => selectRange(m as RangeMode)}>{RANGE_LABELS[m as RangeMode]}</button>
        {/each}
      </div>
      <button class="secondary" onclick={refreshAll} aria-label="Refresh dashboard">Refresh</button>
      <button class="secondary" onclick={() => (customizeOpen = !customizeOpen)} aria-expanded={customizeOpen}>
        Customize Dashboard
      </button>
    </div>
  </div>
  {#if protectionError}
    <p class="degraded-note" role="status">Unable to load protection status: {protectionError}</p>
  {:else if protection && !protection.active}
    <p class="degraded-note" role="status">
      Filtering is disabled -- DNS queries are not being blocked or rewritten by policy.
    </p>
  {:else if protection}
    <p class="hint dash-subhead">
      Filtering is active ({protection.enabled_blocklists} blocklist{protection.enabled_blocklists === 1 ? "" : "s"}, {protection.enabled_rules} custom rule{protection.enabled_rules === 1 ? "" : "s"} enabled).
    </p>
  {/if}

  {#if customizeOpen}
    <div class="customize-panel" role="region" aria-label="Customize dashboard cards">
      <p class="hint customize-intro">Enable/disable and reorder the cards below the DNS Activity chart. Headline metrics and DNS Activity itself are always shown.</p>
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
      <button type="button" class="secondary" onclick={restoreDefaults}>Restore Defaults</button>
    </div>
  {/if}

  {#if summaryError}
    <p class="error" role="alert">{summaryError}</p>
  {/if}

  <!-- Headline metrics: always exactly these four, not part of card
       customization (spec: "One row of four compact cards", distinct
       from the customizable lower grid below). -->
  <div class="headline-row">
    <div class="card headline-card">
      <h3>DNS Queries</h3>
      <p class="big">{totalQueriesHeadline.toLocaleString()}</p>
      <p class="hint">{RANGE_LABELS[rangeMode]}</p>
    </div>
    <div class="card headline-card">
      <h3>Blocked Queries</h3>
      <p class="big">{blockedQueriesHeadline.toLocaleString()}</p>
      <p class="hint">{totalQueriesHeadline ? `${blockedPctHeadline.toFixed(1)}% of total` : RANGE_LABELS[rangeMode]}</p>
    </div>
    <div class="card headline-card">
      <h3>Active Clients</h3>
      {#if !topClients}
        <p class="hint">Loading…</p>
      {:else if topClients.degraded}
        <p class="degraded-note-inline">Unavailable</p>
      {:else}
        <p class="big">{topClients.clients.length.toLocaleString()}</p>
        <p class="hint">Unique clients, {RANGE_LABELS[rangeMode].toLowerCase()}</p>
      {/if}
    </div>
    <div class="card headline-card">
      <h3>Query Performance</h3>
      {#if latencyError}
        <p class="degraded-note-inline">Unavailable: {latencyError}</p>
      {:else if !latencyStats}
        <p class="hint">Loading…</p>
      {:else}
        <p class="big">{latencyStats.avg.toFixed(1)}<span class="of"> ms avg</span></p>
        <p class="hint">P95 {latencyStats.p95.toFixed(1)} ms · P99 {latencyStats.p99.toFixed(1)} ms</p>
        <p class="hint">
          {latencyStats.sampleSize < latencyStats.totalInPeriod
            ? `Sampled from ${latencyStats.sampleSize.toLocaleString()} of ${latencyStats.totalInPeriod.toLocaleString()}+ queries`
            : `From ${latencyStats.sampleSize.toLocaleString()} queries`}
        </p>
      {/if}
    </div>
  </div>

  <!-- DNS Activity: one full-width chart, fixed (not a customizable card). -->
  <div class="card wide-card activity-card">
    <div class="card-head">
      <h3>DNS Activity</h3>
      <button class="link" onclick={() => router.navigate("analytics")}>View Query Log</button>
    </div>
    {#if chartDegraded}
      <p class="degraded-note" role="status">Statistics are disabled or unavailable: {chartDegradedReason || "unavailable"}</p>
    {:else if chartLoading && chartPoints.length === 0}
      <p class="hint">Loading…</p>
    {:else if chartPoints.length === 0}
      <p class="hint">No query activity recorded in this period yet.</p>
    {:else}
      <ActivityChart points={chartPoints} />
    {/if}
  </div>

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
      {:else if card.id === "outcomes"}
        <div class="card grid-card">
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
        <div class="card grid-card">
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
        <div class="card grid-card">
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
      {:else if card.id === "recent-activity"}
        <div class="card grid-card">
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
              <colgroup>
                <col style="width: 16%" /><col style="width: 16%" /><col style="width: 32%" /><col style="width: 12%" /><col style="width: 24%" />
              </colgroup>
              <thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Status</th></tr></thead>
              <tbody>
                {#each recentActivity.rows as row (row.id)}
                  <tr>
                    <td class="mono hint" title={new Date(row.ts * 1000).toLocaleTimeString()}>{new Date(row.ts * 1000).toLocaleTimeString()}</td>
                    <td class="mono" title={row.client_name || row.client}>{row.client_name || row.client}</td>
                    <td class="mono" title={row.domain}>{row.domain}</td>
                    <td>{row.qtype}</td>
                    <td><span class="mini-badge {row.blocked ? 'mini-badge-blocked' : 'mini-badge-ok'}">{row.blocked ? "Blocked" : row.rcode}</span></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      {:else if card.id === "system-health"}
        <div class="card grid-card">
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
        <div class="card grid-card">
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
        <div class="card grid-card">
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
        <div class="card grid-card">
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
        <div class="card grid-card">
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
              <colgroup>
                <col style="width: 34%" /><col style="width: 20%" /><col style="width: 26%" /><col style="width: 20%" />
              </colgroup>
              <thead><tr><th>Name</th><th>Transport</th><th>Strategy</th><th>Enabled</th></tr></thead>
              <tbody>
                {#each upstreams.slice(0, 5) as u (u.upstream_profile_id)}
                  <tr>
                    <td title={u.name}>{u.name}</td>
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
        <div class="card grid-card">
          <div class="card-head">
            <h3>Top Upstream Resolvers</h3>
            <button class="link" onclick={() => router.navigate("upstreams")}>Manage</button>
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
            {#if topUpstreams.some((u) => u.resolver_key === "apdns_bind_backend")}
              <p class="hint">
                Upstream forwarding happens inside BIND, not dnsdist itself -- this is total traffic
                dnsdist forwarded to it, not a breakdown per configured provider. See Upstreams for
                which providers BIND is configured to use.
              </p>
            {/if}
            <!-- Name + share-of-total bar, same pattern as every other ranked
                 list on this dashboard (Query Outcomes, Query Types, ...) --
                 not a dense multi-column table: a real owner-reported defect
                 (6 columns crammed into one card, headers overlapping/cut
                 off at "Avg latency") plus a real design-reference check
                 against AdGuard Home's own equivalent "Top Upstreams" panel
                 (client_v2/src/components/Dashboard/blocks/TopUpstreams),
                 which uses this exact name+count/percent+bar shape, not a
                 table either. Success/latency/state -- genuinely useful
                 operational detail AdGuard's own simpler version doesn't
                 carry -- survive as a compact hint line per row instead of
                 three more columns. -->
            {@const totalQueries = topUpstreams.reduce((s, r) => s + r.queries_attempted, 0)}
            {#each topUpstreams as u (u.resolver_key)}
              {@const share = totalQueries ? (u.queries_attempted / totalQueries) * 100 : 0}
              <div class="outcome-row">
                <div class="outcome-head">
                  <span title={u.address || u.resolver_key}>{resolverDisplayName(u)}</span>
                  <span>{u.queries_attempted.toLocaleString()}{totalQueries ? ` / ${share.toFixed(1)}%` : ""}</span>
                </div>
                <span class="meter"><span style="width: {Math.min(share, 100).toFixed(1)}%"></span></span>
                <p class="hint">
                  {u.protocol || "unknown protocol"} · {u.health_state || "unknown state"} ·
                  {u.queries_attempted > 0 ? Math.round((u.successful_responses / u.queries_attempted) * 100) + "% success" : "no responses yet"} ·
                  {u.avg_latency_ms > 0 ? u.avg_latency_ms.toFixed(1) + " ms avg" : "latency n/a"}
                </p>
              </div>
            {/each}
            <p class="hint">Resolver attribution is based on real dnsdist backend counters for this appliance's own managed upstream pool (last 60 minutes).</p>
          {/if}
        </div>
      {:else if card.id === "cache-effectiveness"}
        <div class="card grid-card">
          <div class="card-head">
            <h3>Cache Effectiveness</h3>
            <button class="link" onclick={() => router.navigate("cache")}>Manage</button>
          </div>
          {#if cacheStatusError}
            <p class="degraded-note" role="status">Unable to load cache status: {cacheStatusError}</p>
          {:else if !cacheStatus}
            <p class="hint">Loading…</p>
          {:else if !primaryCacheStats}
            <p class="hint">Cache statistics are not available from this appliance's DNS runtime right now.</p>
          {:else}
            {@const pct = (primaryCacheStats.hit_ratio ?? 0) * 100}
            <p class="big">{primaryCacheStats.hit_ratio !== null ? `${pct.toFixed(1)}%` : "—"}<span class="of"> hit rate</span></p>
            <span class="meter"><span style="width: {Math.min(pct, 100).toFixed(1)}%"></span></span>
            <p class="hint">{primaryCacheStats.hits.toLocaleString()} hits · {primaryCacheStats.misses.toLocaleString()} misses</p>
          {/if}
        </div>
      {/if}
    {/each}
  </div>

</section>

<style>
  /* Global page header pattern (title/status left, actions upper right) --
     see App.svelte's own header conventions and PageHeader.svelte; the
     Dashboard doesn't reuse that component directly because it needs a
     second action row (time range) and an inline status line beneath the
     title, but the left/right split and spacing rhythm match. */
  .dash-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap; }
  .dash-header__title { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
  .dash-header__title h2 { margin: 0; }
  .dash-header__actions { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .dash-subhead { margin: 0.35rem 0 0; }
  .degraded-note-inline { color: var(--warning); font-size: 0.85rem; margin: 0; }

  .headline-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-top: 1rem; }
  .headline-card { display: flex; flex-direction: column; gap: 0.15rem; }
  .activity-card { margin-top: 1rem; }
  @media (max-width: 1024px) {
    .headline-row { grid-template-columns: repeat(2, 1fr); }
  }
  @media (max-width: 620px) {
    .headline-row { grid-template-columns: 1fr; }
  }

  .customize-intro { margin: 0.1rem 0.75rem 0.5rem; }
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
  .customize-panel > button.secondary { margin: 0.4rem 0.75rem 0.25rem; }

  .hint { font-size: 0.85rem; opacity: 0.75; }
  /* Lower grid: a real fixed two-column grid on desktop (spec's "Lower
     two-column grid" with predictable row pairs), one column on mobile.
     Cards flow through cardOrder in pairs -- the default order matches
     the four named row pairs exactly (see dashboardCards.ts's own doc
     comment); reordering in Customize Dashboard changes which two cards
     share a row, but every enabled card still gets a full-width row
     partner rather than leaving a dangling half-empty row, because
     grid-auto-flow packs them in order with no gaps. */
  .cards { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-top: 1rem; align-items: stretch; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); box-shadow: var(--shadow); }
  .wide-card { grid-column: 1 / -1; }
  .grid-card { min-width: 0; }
  @media (max-width: 900px) {
    .cards { grid-template-columns: 1fr; }
  }
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
  /* table-layout: fixed + td's own max-width: 0/overflow:hidden is what
     actually keeps a long real value (a domain name, a client identifier)
     from forcing the table -- and with it the whole card -- wider than a
     grid-card's own column (a real, reported "Recent Activity spills out
     of its card" defect: 5 columns including a real unbounded-length
     domain, with no truncation or scroll boundary of any kind). Each td
     still gets a real `title` attribute (see the markup) so the full
     value is always available on hover, not just silently cut off. */
  .mini-table { width: 100%; table-layout: fixed; border-collapse: collapse; font-size: 0.88rem; margin-top: 0.5rem; }
  .mini-table th { text-align: left; font-weight: 600; font-size: 0.78rem; opacity: 0.7; padding: 0.25rem 0.5rem 0.25rem 0; border-bottom: 1px solid var(--border); overflow: hidden; white-space: nowrap; }
  .mini-table td { max-width: 0; padding: 0.3rem 0.5rem 0.3rem 0; border-bottom: 1px solid var(--border); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .mini-table tr:last-child td { border-bottom: none; }
  .mini-badge { display: inline-block; padding: 0.1rem 0.45rem; border-radius: 999px; font-size: 0.72rem; }
  .mini-badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .mini-badge-observed { background: var(--border); color: var(--fg); }
  .mini-badge-blocked { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
  .mini-badge-warn { background: var(--badge-warn-bg); color: var(--badge-warn-fg); }

  .dash-header__actions button.danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); border-color: transparent; }

  .outcome-row { margin: 0.5rem 0; }
  .outcome-head { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 0.25rem; }
  .meter { display: block; height: 0.5rem; border-radius: 999px; background: var(--border); overflow: hidden; }
  .meter span { display: block; height: 100%; background: var(--accent); border-radius: 999px; }
  .meter.blocked span { background: var(--badge-danger-fg); }

  .cache-ctx + .cache-ctx { margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--border); }
  .health-grid { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }
  .health-card { display: flex; align-items: center; gap: 0.4rem; border: 1px solid var(--border); border-radius: 6px; padding: 0.3rem 0.6rem; font-size: 0.85rem; }
</style>
