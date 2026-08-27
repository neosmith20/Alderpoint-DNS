<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError } from "../api";
  import { perfLog } from "../perfLog.svelte";
  import { timestampPref } from "../timestamp.svelte";

  // System Status. Metric strip + Components are real (existing
  // GET /api/health + /api/system/status, both native Go). UI
  // Performance is real, session-only client-side navigation timing
  // (perfLog.svelte.ts, fed by router.svelte.ts + RouteLoader.svelte --
  // real navigate()-to-component-ready latency, not synthetic numbers).
  //
  // Node Identity is real (2026-08-27): it already lives inside Python's
  // control.db, but internal/hostagentd's own Replication ops already
  // read it via a real, root-owned, redacted read (never the secret
  // columns) for the Replication page -- GET /api/replication/status's
  // own response already carries node_identity, this page was simply
  // never wired to fetch it. No new backend needed, matching the same
  // "the matrix said blocked, the code already isn't" correction this
  // session already made for Dashboard's Upstreams/Clients mini-panels.
  //
  // BIND Cache Counters is also real (2026-08-27): a real, read-only GET
  // of BIND's own statistics-channels JSON endpoint
  // (internal/hostagentd's fetchBindCacheStats, field-matched against
  // app/v2/cache_control.py's bind_cache_stats), reusing the exact same
  // GET /api/cache/status the Cache page already calls -- no new
  // backend op, just a new field on its existing BindContext response
  // and a card here to show it.
  //
  // Discovery status and DNS Performance benchmark are still not built,
  // disclosed rather than hidden: Discovery status is a Python-side
  // pipeline this migration hasn't built a compatibility boundary for;
  // the DNS Performance benchmark issues real load-test queries (up to
  // 10,000 per case) through BIND/dnsdist over UDP/DoT/DoH -- real work
  // genuinely out of this session's remaining scope, not re-attempted.

  let health = $state<Awaited<ReturnType<typeof api.health>> | null>(null);
  let sysStatus = $state<Awaited<ReturnType<typeof api.systemStatus>> | null>(null);
  let replication = $state<Awaited<ReturnType<typeof api.replicationStatus>> | null>(null);
  let replicationError = $state("");
  let cache = $state<Awaited<ReturnType<typeof api.cacheStatus>> | null>(null);
  let cacheError = $state("");
  let loadError = $state("");

  async function refresh() {
    loadError = "";
    try {
      const [h, s] = await Promise.all([api.health(), api.systemStatus()]);
      health = h;
      sysStatus = s;
    } catch (err) {
      loadError = err instanceof ApiError ? err.message : String(err);
    }
    replicationError = "";
    try {
      replication = await api.replicationStatus();
    } catch (err) {
      // Honest degraded, not fatal to the rest of the page -- matches
      // every other optional host-agent-backed card's contract.
      replicationError = err instanceof ApiError ? err.message : String(err);
    }
    cacheError = "";
    try {
      cache = await api.cacheStatus();
    } catch (err) {
      cacheError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
  });

  function formatUptime(seconds: number): string {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const parts = [];
    if (d) parts.push(`${d}d`);
    if (h || d) parts.push(`${h}h`);
    parts.push(`${m}m`);
    return parts.join(" ");
  }

  async function copyPerfReport() {
    const lines = perfLog.entries.map((e) => `${new Date(e.at).toISOString()}\t${e.route}\t${e.ms.toFixed(1)}ms`);
    const text = ["timestamp\troute\tlatency", ...lines].join("\n");
    try {
      await navigator.clipboard.writeText(text);
      copyStatus = "Copied.";
    } catch {
      copyStatus = "Copy failed (clipboard unavailable).";
    }
    setTimeout(() => (copyStatus = ""), 2000);
  }
  let copyStatus = $state("");
</script>

<section aria-labelledby="health-heading" class="system-status">
  <h2 id="health-heading">System Status</h2>
  <p class="scope-note">
    Metric strip, Components, UI Performance, Node Identity, and BIND Cache Counters are real.
    Discovery status and DNS Performance benchmark are not built yet -- see the parity matrix.
  </p>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <div class="metric-strip">
    <div class="metric"><span class="label">Appliance</span><span class="value">{sysStatus?.appliance_name ?? "…"}</span></div>
    <div class="metric"><span class="label">Version</span><span class="value">{health?.version ?? "…"}</span></div>
    <div class="metric"><span class="label">Uptime</span><span class="value">{health ? formatUptime(health.uptime_seconds) : "…"}</span></div>
    <div class="metric"><span class="label">Status</span><span class="value status-{health?.status}">{health?.status ?? "…"}</span></div>
    <div class="metric"><span class="label">Timezone</span><span class="value">{sysStatus?.appliance_timezone ?? "…"}</span></div>
  </div>

  <div class="card">
    <h3>Components</h3>
    {#if health}
      <table class="components">
        <thead><tr><th>Component</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>
          {#each Object.entries(health.components) as [name, c] (name)}
            <tr>
              <td>{name}</td>
              <td class="status-{c.status}">{c.status}</td>
              <td>{c.schema_version !== undefined ? `schema_version=${c.schema_version}` : (c.detail ?? c.reason ?? "")}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  <div class="card">
    <h3>Node Identity</h3>
    {#if replicationError}
      <p class="status-unavailable">Unavailable: {replicationError}</p>
    {:else if !replication}
      <p class="hint">…</p>
    {:else if !replication.node_identity}
      <p class="hint">No node identity recorded yet.</p>
    {:else}
      {@const id = replication.node_identity}
      <div class="metric-strip">
        <div class="metric"><span class="label">Node ID</span><span class="value mono">{id.node_id}</span></div>
        <div class="metric"><span class="label">Display name</span><span class="value">{id.display_name || "(unnamed)"}</span></div>
        <div class="metric"><span class="label">Created</span><span class="value">{timestampPref.format(id.created_at)}</span></div>
        {#if id.regenerated_at}
          <div class="metric"><span class="label">Regenerated</span><span class="value">{timestampPref.format(id.regenerated_at)}</span></div>
        {/if}
      </div>
    {/if}
  </div>

  <div class="card">
    <h3>BIND Cache Counters</h3>
    {#if cacheError}
      <p class="status-unavailable">Unavailable: {cacheError}</p>
    {:else if !cache}
      <p class="hint">…</p>
    {:else if cache.bind.length === 0}
      <p class="hint">No BIND contexts reported (host-control agent not configured for this deployment, or none compiled yet).</p>
    {:else}
      <table class="components">
        <thead><tr><th>Context</th><th>Hits</th><th>Misses</th><th>Hit rate</th></tr></thead>
        <tbody>
          {#each cache.bind as ctx (ctx.name)}
            <tr>
              <td>{ctx.name}</td>
              {#if !ctx.cache_stats || !ctx.cache_stats.available}
                <td colspan="3" class="status-unavailable">unavailable{ctx.cache_stats?.error ? `: ${ctx.cache_stats.error}` : ""}</td>
              {:else}
                <td>{ctx.cache_stats.hits.toLocaleString()}</td>
                <td>{ctx.cache_stats.misses.toLocaleString()}</td>
                <td>{ctx.cache_stats.hit_ratio !== null ? `${(ctx.cache_stats.hit_ratio * 100).toFixed(1)}%` : "—"}</td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  <div class="card">
    <h3>Analytics Health</h3>
    <p class="scope-note">
      Proves the analytics writer/receiver are actually alive, not just that the aggregates file
      still opens -- a stale or failed writer here must never read as zero traffic.
    </p>
    {#if health}
      {@const a = health.components.analytics}
      {#if !a}
        <p>…</p>
      {:else if a.status === "unconfigured"}
        <p class="status-unavailable">Not configured on this deployment.</p>
      {:else}
        <div class="metric-strip">
          <div class="metric"><span class="label">Overall</span><span class="value status-{a.status}">{a.status}</span></div>
          <div class="metric"><span class="label">DB reachable</span><span class="value">{a.db_reachable ? "yes" : "no"}</span></div>
          <div class="metric"><span class="label">Consecutive read failures</span><span class="value">{a.consecutive_read_failures ?? 0}</span></div>
          <div class="metric">
            <span class="label">Writer</span>
            <span class="value">
              {a.writer_heartbeat_configured ? (a.writer_status ?? "unknown") : "not configured"}
              {#if a.writer_heartbeat_configured}({a.writer_stale ? "stale" : "fresh"}){/if}
            </span>
          </div>
          {#if a.writer_heartbeat_configured}
            <div class="metric"><span class="label">Writer tick count</span><span class="value">{a.writer_tick_count ?? 0}</span></div>
            <div class="metric">
              <span class="label">Last successful write</span>
              <span class="value">{a.writer_last_success_at ? new Date(a.writer_last_success_at * 1000).toLocaleString() : "never"}</span>
            </div>
          {/if}
          <div class="metric">
            <span class="label">Queue depth</span>
            <span class="value">{a.queue_depth_available ? a.queue_depth : "unavailable"}</span>
          </div>
          <div class="metric">
            <span class="label">Last committed bucket</span>
            <span class="value">{a.last_committed_bucket ? new Date(a.last_committed_bucket * 1000).toLocaleString() : "none"}</span>
          </div>
        </div>
        {#if a.writer_last_error}<p class="degraded-note" role="status">Last writer error: {a.writer_last_error}</p>{/if}
        {#if a.reason}<p class="degraded-note" role="status">{a.reason}</p>{/if}
      {/if}
    {/if}
  </div>

  <div class="card">
    <h3>UI Performance <span class="scope">(session-only, cleared on reload)</span></h3>
    <div class="actions">
      <button class="refresh-perf" onclick={refresh}>Refresh</button>
      <button class="copy-perf" onclick={copyPerfReport} disabled={perfLog.entries.length === 0}>Copy UI Perf Report</button>
      <button class="clear-perf" onclick={() => perfLog.clear()} disabled={perfLog.entries.length === 0}>Clear Measurements</button>
      {#if copyStatus}<span class="hint">{copyStatus}</span>{/if}
    </div>
    {#if perfLog.entries.length === 0}
      <p class="hint">No navigations recorded yet this session.</p>
    {:else}
      <div class="perf-scroll">
        <table class="perf-table">
          <thead><tr><th>Time</th><th>Route</th><th>Latency</th></tr></thead>
          <tbody>
            {#each [...perfLog.entries].reverse() as entry, i (entry.at + "-" + i)}
              <tr>
                <td>{timestampPref.format(new Date(entry.at).toISOString())}</td>
                <td>{entry.route}</td>
                <td>{entry.ms.toFixed(1)} ms</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
</section>

<style>
  .system-status { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .metric-strip { display: flex; flex-wrap: wrap; gap: 1rem; }
  .metric { border: 1px solid var(--border); border-radius: 8px; padding: 0.6rem 1rem; background: var(--card-bg); min-width: 8rem; }
  .metric .label { display: block; font-size: 0.75rem; opacity: 0.65; }
  .metric .value { display: block; font-size: 1.1rem; font-weight: 600; }
  .metric .value.mono { font-family: monospace; font-size: 0.85rem; word-break: break-all; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; }
  .card h3 { margin: 0; }
  .scope { font-size: 0.75rem; font-weight: 400; opacity: 0.6; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border); }
  .status-ok { color: #16a34a; }
  .status-degraded, .status-unavailable, .status-failed { color: var(--badge-danger-fg); }
  .degraded-note { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.85rem; }
  .actions { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
  .hint { font-size: 0.8rem; opacity: 0.7; }
  .error { color: var(--badge-danger-fg); }
  .perf-scroll { max-height: 20rem; overflow-y: auto; overflow-x: auto; }
</style>
