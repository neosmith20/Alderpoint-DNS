<script lang="ts">
  import { onMount } from "svelte";
  import { api, type AnalyticsSettings } from "../api";
  import { router } from "../router.svelte";

  // Statistics. Export is real: a genuine download of this appliance's
  // own Go-native query_events table, summarized the same way the
  // Dashboard/Query Log already read it (GET /api/statistics/export,
  // backed by internal/dnsanalytics.Reader.ExportAll -- Python's
  // aggregates.db is fully decommissioned, see CUTOVER.md).
  //
  // Clear is real (2026-08-28: rewritten to act directly on
  // internal/dnsanalytics -- see that package's ClearAll doc comment
  // for why this no longer routes through apdns-hostagent the way it
  // did against Python's now-permanently-inert aggregates.db/Parquet
  // bridge). There's exactly one table now, so there's no longer a
  // separate "raw history" toggle -- Clear removes all of it.
  //
  // Settings (2026-08-30): real, matching V1.1.1's own statistics_settings.html
  // field-for-field wherever this architecture has an equivalent -- see
  // GET/PUT /api/statistics/settings and internal/dnsanalytics.Settings's
  // own doc comment for the two fields deliberately NOT modeled
  // (aggregate_retention_days, collection_interval -- both governed a
  // separate poll-and-aggregate tier this single-table design doesn't
  // have) and for the one real behavioral difference from V1 (disabling
  // detailed logging blanks just the domain field here rather than
  // dropping the whole row, since there's no separate aggregate tier to
  // fall back to).

  let settings = $state<AnalyticsSettings | null>(null);
  let settingsError = $state("");
  let savingSettings = $state(false);
  let savedNote = $state(false);

  async function loadSettings() {
    try {
      settings = await api.getAnalyticsSettings();
      settingsError = "";
    } catch (err) {
      settingsError = err instanceof Error ? err.message : String(err);
    }
  }

  async function saveSettings(e: SubmitEvent) {
    e.preventDefault();
    if (!settings) return;
    savingSettings = true;
    savedNote = false;
    settingsError = "";
    try {
      settings = await api.updateAnalyticsSettings(settings);
      savedNote = true;
    } catch (err) {
      settingsError = err instanceof Error ? err.message : String(err);
    } finally {
      savingSettings = false;
    }
  }

  onMount(loadSettings);

  // Real Overview: previously this whole page was settings/export/clear
  // controls with no actual statistics on a page named "Statistics" --
  // an owner-reported "shows settings but not statistics" defect. Reuses
  // the same real analytics endpoints (and honest degraded/empty
  // handling) already proven on the Dashboard, at a fixed 24h window
  // scoped to this page rather than duplicating Dashboard's live/range
  // picker.
  type Overview = { total: number; blocked: number };
  let overview = $state<Overview | null>(null);
  let overviewDegraded = $state(false);
  let overviewDegradedReason = $state("");
  let topDomains = $state<Awaited<ReturnType<typeof api.analyticsTopDomains>> | null>(null);
  let qtypeBreakdown = $state<Awaited<ReturnType<typeof api.analyticsBreakdown>> | null>(null);

  async function loadOverview() {
    try {
      const ts = await api.analyticsTimeseries(1440, "hour");
      overviewDegraded = ts.degraded;
      overviewDegradedReason = ts.degraded_reason || "";
      overview = ts.degraded
        ? null
        : ts.buckets.reduce((acc, b) => ({ total: acc.total + b.total_queries, blocked: acc.blocked + b.blocked_queries }), { total: 0, blocked: 0 });
    } catch (err) {
      overviewDegraded = true;
      overviewDegradedReason = err instanceof Error ? err.message : String(err);
    }
    try {
      topDomains = await api.analyticsTopDomains(1440, 10);
    } catch {
      /* the card's own degraded/empty rendering covers a failed fetch */
    }
    try {
      qtypeBreakdown = await api.analyticsBreakdown("qtype", 1440, 6);
    } catch {
      /* same as above */
    }
  }

  onMount(loadOverview);

  // BIND Cache Effectiveness -- moved here from the Dashboard (2026-09-03,
  // owner-requested: it's a point-in-time cache health reading, not a
  // query-history summary, and belongs alongside the appliance's other
  // real statistics rather than crowding the Dashboard's own activity
  // cards). Same api.cacheStatus() the Cache page itself uses.
  let cacheStatus = $state<Awaited<ReturnType<typeof api.cacheStatus>> | null>(null);
  let cacheError = $state("");
  async function loadCache() {
    try {
      cacheStatus = await api.cacheStatus();
      cacheError = "";
    } catch (err) {
      cacheError = err instanceof Error ? err.message : String(err);
    }
  }
  onMount(loadCache);

  let confirmText = $state("");
  let clearing = $state(false);
  let clearError = $state("");
  let clearResult = $state<Awaited<ReturnType<typeof api.statisticsClear>> | null>(null);

  async function onClear(e: SubmitEvent) {
    e.preventDefault();
    if (confirmText !== "CLEAR") return;
    clearing = true;
    clearError = "";
    clearResult = null;
    try {
      clearResult = await api.statisticsClear();
      confirmText = "";
    } catch (err) {
      clearError = err instanceof Error ? err.message : String(err);
    } finally {
      clearing = false;
    }
  }
</script>

<section aria-labelledby="statistics-heading" class="statistics">
  <h2 id="statistics-heading">Statistics</h2>
  <p class="scope-note">
    A real overview of this appliance's own query history, and the settings that govern how much
    of it gets kept. Export downloads it; Clear permanently deletes it.
  </p>

  <h3 class="section-heading">Overview <span class="scope">(last 24h)</span></h3>
  <div class="grid-2col">
    <div class="card">
      <h3>Query volume</h3>
      {#if overviewDegraded}
        <p class="degraded-note" role="status">Analytics degraded: {overviewDegradedReason || "unavailable"}</p>
      {:else if !overview}
        <p class="hint">Loading…</p>
      {:else}
        {@const allowed = Math.max(overview.total - overview.blocked, 0)}
        {@const blockedPct = overview.total ? (overview.blocked / overview.total) * 100 : 0}
        <p class="big">{overview.total.toLocaleString()}<span class="of"> total queries</span></p>
        <p class="hint">{allowed.toLocaleString()} allowed, {overview.blocked.toLocaleString()} blocked ({blockedPct.toFixed(1)}%).</p>
      {/if}
    </div>

    <div class="card">
      <h3>Query Types</h3>
      {#if !qtypeBreakdown}
        <p class="hint">Loading…</p>
      {:else if qtypeBreakdown.degraded}
        <p class="degraded-note" role="status">Analytics degraded: {qtypeBreakdown.degraded_reason || "unavailable"}</p>
      {:else if qtypeBreakdown.rows.length === 0}
        <p class="hint">No query activity in this window.</p>
      {:else}
        {@const total = qtypeBreakdown.rows.reduce((s, r) => s + r[1], 0)}
        {#each qtypeBreakdown.rows as row (row[0])}
          <div class="outcome-row">
            <div class="outcome-head"><span>{row[0]}</span><span>{row[1].toLocaleString()}{total ? ` / ${((row[1] / total) * 100).toFixed(1)}%` : ""}</span></div>
            <span class="meter"><span style="width: {Math.min(total ? (row[1] / total) * 100 : 0, 100).toFixed(1)}%"></span></span>
          </div>
        {/each}
      {/if}
    </div>

    <div class="card wide-card">
      <h3>Top Domains</h3>
      {#if !topDomains}
        <p class="hint">Loading…</p>
      {:else if topDomains.degraded}
        <p class="degraded-note" role="status">Analytics degraded: {topDomains.degraded_reason || "unavailable"}</p>
      {:else if topDomains.rows.length === 0}
        <p class="hint">No query activity in this window.</p>
      {:else}
        <table class="mini-table">
          <thead><tr><th>Domain</th><th>Queries</th></tr></thead>
          <tbody>
            {#each topDomains.rows as row (row[0])}
              <tr><td class="mono">{row[0]}</td><td>{row[1].toLocaleString()}</td></tr>
            {/each}
          </tbody>
        </table>
        {#if topDomains.aggregation_note}<p class="hint">{topDomains.aggregation_note}</p>{/if}
      {/if}
    </div>
  </div>

  <h3 class="section-heading">BIND Cache Effectiveness</h3>
  <div class="grid-2col">
    <div class="card wide-card">
      <div class="card-head">
        <h3>Real-time cache health</h3>
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
  </div>

  <h3 class="section-heading">Statistics Settings</h3>
  <div class="grid-2col">
    <div class="card settings-card">
      <h3>Collection settings</h3>
      {#if settingsError}
        <p class="error" role="alert">{settingsError}</p>
      {/if}
      {#if !settings}
        <p class="hint">Loading…</p>
      {:else}
        <form onsubmit={saveSettings} class="settings-form">
          <label class="row"><input type="checkbox" bind:checked={settings.analytics_enabled} /> Analytics enabled</label>
          <label class="row">
            <input type="checkbox" bind:checked={settings.detailed_query_logging_enabled} /> Detailed query logging enabled
          </label>
          <label>
            Privacy mode
            <select bind:value={settings.privacy_mode}>
              <option value="full">Full</option>
              <option value="anonymized_clients">Anonymized clients</option>
              <option value="aggregate_only">Aggregate only</option>
            </select>
          </label>
          <label>
            Client anonymization
            <select bind:value={settings.client_anonymization} disabled={settings.privacy_mode === "full"}>
              <option value="truncate">Truncate</option>
              <option value="hash">Hash</option>
            </select>
          </label>
          <label>Detailed retention (days) <input type="number" min="0" bind:value={settings.detailed_retention_days} /></label>
          <label>Database size limit (bytes) <input type="number" min="1048576" bind:value={settings.db_size_limit_bytes} /></label>
          <label>Recent query limit <input type="number" min="10" bind:value={settings.recent_query_limit} /></label>
          <p class="hint">
            Aggregate-tier retention and a separate collection interval don't apply here -- this
            appliance keeps one real query history rather than a separate poll-and-aggregate tier,
            so there's nothing distinct to configure for either.
          </p>
          <div>
            <button type="submit" disabled={savingSettings}>{savingSettings ? "Saving…" : "Save settings"}</button>
            {#if savedNote}<span class="ok" role="status">Saved.</span>{/if}
          </div>
        </form>
      {/if}
    </div>

    <div class="stacked-column">
      <div class="card">
        <h3>Export</h3>
        <p class="hint">Downloads a JSON snapshot of this appliance's own real query history.</p>
        <a class="export-link" href="/api/statistics/export">Download statistics export</a>
      </div>

      <div class="card clear-card">
        <h3>Clear</h3>
        <p class="hint">
          Permanently deletes this appliance's entire real query history (the same data that
          powers the Overview above, Dashboard charts, and Query Log). This cannot be undone.
        </p>
        <form onsubmit={onClear} class="clear-form">
          <label class="confirm-row">
            Type <strong>CLEAR</strong> to confirm
            <input type="text" bind:value={confirmText} aria-label="Type CLEAR to confirm" autocomplete="off" />
          </label>
          <button type="submit" class="danger" disabled={confirmText !== "CLEAR" || clearing}>
            {clearing ? "Clearing…" : "Clear statistics"}
          </button>
        </form>
        {#if clearError}
          <p class="error" role="alert">{clearError}</p>
        {/if}
        {#if clearResult}
          <p class="ok" role="status">
            Cleared {clearResult.query_events_cleared} stored quer{clearResult.query_events_cleared === 1 ? "y" : "ies"}.
          </p>
        {/if}
      </div>
    </div>
  </div>
</section>

<style>
  .statistics { display: flex; flex-direction: column; gap: 0.75rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .section-heading { margin: 0.5rem 0 0; }
  .scope { text-transform: none; font-weight: 400; opacity: 0.7; font-size: 0.85rem; }
  /* Two responsive columns on desktop/tablet, one on mobile -- previously
     Settings/Export/Clear were three separate fixed-max-width cards
     stacked full-height regardless of viewport, and there was no actual
     statistics content on a page named "Statistics" at all. */
  .grid-2col { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1rem; align-items: start; margin-bottom: 0.5rem; }
  .stacked-column { display: flex; flex-direction: column; gap: 1rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); box-shadow: var(--shadow); display: flex; flex-direction: column; gap: 0.6rem; }
  .card.wide-card { grid-column: 1 / -1; }
  .settings-form { display: flex; flex-direction: column; gap: 0.6rem; font-size: 0.88rem; }
  .settings-form label { display: flex; flex-direction: column; gap: 0.2rem; }
  .settings-form label.row { flex-direction: row; align-items: center; gap: 0.5rem; }
  .settings-form input[type="number"] { width: 10rem; }
  .card h3 { margin: 0; }
  .card-head { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.4rem; }
  .link { background: transparent; color: var(--accent); border: none; padding: 0; font-size: 0.85rem; cursor: pointer; text-decoration: underline; }
  .cache-ctx { margin-bottom: 0.75rem; }
  .cache-ctx:last-child { margin-bottom: 0; }
  .hint { font-size: 0.85rem; opacity: 0.75; margin: 0; }
  .big { margin: 0; font-size: 1.9rem; font-weight: 700; }
  .of { font-size: 1rem; font-weight: 400; opacity: 0.7; }
  .degraded-note { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.85rem; margin: 0; }
  .outcome-row { margin: 0.3rem 0; }
  .outcome-head { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 0.25rem; }
  .meter { display: block; height: 0.5rem; border-radius: 999px; background: var(--border); overflow: hidden; }
  .meter span { display: block; height: 100%; background: var(--accent); border-radius: 999px; }
  .mono { font-family: monospace; font-size: 0.85rem; }
  .mini-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  .mini-table th { text-align: left; font-weight: 600; opacity: 0.7; padding: 0.25rem 0.5rem 0.25rem 0; border-bottom: 1px solid var(--border); }
  .mini-table td { padding: 0.3rem 0.5rem 0.3rem 0; border-bottom: 1px solid var(--border); }
  .mini-table tr:last-child td { border-bottom: none; }
  .export-link { align-self: flex-start; padding: 0.4rem 0.8rem; border: 1px solid var(--border); border-radius: 6px; background: var(--accent); color: var(--accent-fg); text-decoration: none; font-size: 0.85rem; }
  .clear-form { display: flex; flex-direction: column; gap: 0.6rem; }
  .confirm-row { display: flex; align-items: center; gap: 0.5rem; font-size: 0.88rem; }
  .confirm-row input { width: 8rem; }
  button.danger { align-self: flex-start; padding: 0.4rem 0.8rem; border: 1px solid var(--badge-danger-fg); border-radius: 6px; background: var(--badge-danger-bg); color: var(--badge-danger-fg); font-size: 0.85rem; }
  button.danger:disabled { opacity: 0.5; cursor: not-allowed; }
  .error { color: var(--badge-danger-fg); font-size: 0.85rem; }
  .ok { color: var(--badge-ok-fg); font-size: 0.85rem; }
</style>
