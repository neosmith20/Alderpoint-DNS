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
  // Node Identity (2026-08-29 rebuild): real Go-native replication
  // settings (internal/replication) -- node_id, current role, and (for
  // an enrolled replica) last sync status/drift, reusing the same
  // GET /api/replication/status the Replication page itself calls.
  //
  // BIND Cache Counters is also real (2026-08-27): a real, read-only GET
  // of BIND's own statistics-channels JSON endpoint
  // (internal/hostagentd's fetchBindCacheStats, field-matched against
  // app/v2/cache_control.py's bind_cache_stats), reusing the exact same
  // GET /api/cache/status the Cache page already calls -- no new
  // backend op, just a new field on its existing BindContext response
  // and a card here to show it.
  //
  // DNS Performance benchmark is real (2026-08-28): internal/dnsperf
  // issues real DNS/DoT/DoH queries (up to 10,000 per case) against
  // this deployment's own Go-managed dnsdist/BIND runtime, executed
  // from apdns-hostagent (the web container's own network namespace
  // cannot reach those loopback ports) and summarized with the same
  // percentile math Python's dns_performance.py uses. Never touches
  // Python's separate :8443 runtime.
  //
  // Discovery status is still not built, disclosed rather than hidden:
  // a Python-side pipeline this migration hasn't built a compatibility
  // boundary for.

  let health = $state<Awaited<ReturnType<typeof api.health>> | null>(null);
  let sysStatus = $state<Awaited<ReturnType<typeof api.systemStatus>> | null>(null);
  let replication = $state<Awaited<ReturnType<typeof api.replicationStatus>> | null>(null);
  let replicationError = $state("");
  let cache = $state<Awaited<ReturnType<typeof api.cacheStatus>> | null>(null);
  let cacheError = $state("");
  let loadError = $state("");
  let dnsPerf = $state<Awaited<ReturnType<typeof api.dnsPerformanceStatus>> | null>(null);
  let dnsPerfError = $state("");
  let dnsPerfActionStatus = $state("");
  let dnsPerfPolling = false;

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
    dnsPerfError = "";
    try {
      dnsPerf = await api.dnsPerformanceStatus();
    } catch (err) {
      dnsPerfError = err instanceof ApiError ? err.message : String(err);
    }
  }

  async function runDnsBenchmark() {
    dnsPerfActionStatus = "";
    try {
      const res = await api.dnsPerformanceRun();
      dnsPerfActionStatus = res.status === "already_running" ? "A benchmark is already running." : "Benchmark started -- this can take a minute for the full case list.";
      pollDnsBenchmark();
    } catch (err) {
      dnsPerfActionStatus = err instanceof ApiError ? err.message : String(err);
    }
  }

  async function pollDnsBenchmark() {
    if (dnsPerfPolling) return;
    dnsPerfPolling = true;
    try {
      for (let i = 0; i < 120; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        try {
          dnsPerf = await api.dnsPerformanceStatus();
        } catch (err) {
          dnsPerfError = err instanceof ApiError ? err.message : String(err);
          break;
        }
        if (!dnsPerf.benchmark_running) break;
      }
    } finally {
      dnsPerfPolling = false;
    }
  }

  async function clearDnsBenchmark() {
    dnsPerfActionStatus = "";
    try {
      await api.dnsPerformanceClear();
      dnsPerf = await api.dnsPerformanceStatus();
      dnsPerfActionStatus = "Cleared.";
    } catch (err) {
      dnsPerfActionStatus = err instanceof ApiError ? err.message : String(err);
    }
  }

  function copyDnsPerfReport() {
    if (!dnsPerf?.report) return;
    const lines = dnsPerf.report.cases.map(
      (c) => `${c.name}\t${c.protocol}\t${c.summary.count}\t${c.summary.success}\t${c.summary.timeouts}\t${c.summary.errors}\t${c.summary.p50_ms ?? ""}\t${c.summary.p95_ms ?? ""}\t${c.summary.p99_ms ?? ""}\t${c.summary.max_ms ?? ""}`,
    );
    const text = ["name\tprotocol\tcount\tsuccess\ttimeouts\terrors\tp50_ms\tp95_ms\tp99_ms\tmax_ms", ...lines].join("\n");
    navigator.clipboard
      .writeText(text)
      .then(() => (dnsPerfActionStatus = "Copied."))
      .catch(() => (dnsPerfActionStatus = "Copy failed (clipboard unavailable)."));
    setTimeout(() => (dnsPerfActionStatus = ""), 2000);
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
    Metric strip, Components, UI Performance, Node Identity, BIND Cache Counters, and the DNS
    Performance benchmark are all live. Network Discovery is coming in a future release.
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
    {:else}
      {@const s = replication.settings}
      <div class="metric-strip">
        <div class="metric"><span class="label">Node ID</span><span class="value mono">{s.node_id}</span></div>
        <div class="metric"><span class="label">Replication role</span><span class="value">{s.role}</span></div>
        {#if s.role === "replica"}
          <div class="metric"><span class="label">Last sync</span><span class="value">{s.last_sync_status || "never"}</span></div>
          <div class="metric"><span class="label">Drift</span><span class="value">{s.drift_detected ? "detected" : "in sync"}</span></div>
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
    <h3>DNS Performance</h3>
    <p class="scope-note">
      A bounded, sequential set of real DNS/DoT/DoH queries against this deployment's own
      Go-managed dnsdist/BIND runtime (the only runtime this appliance has -- Python is fully
      decommissioned), never a load test (one query at a time, matching the reference
      implementation's own "safe" design).
    </p>
    <div class="actions">
      <button data-run-dns-benchmark onclick={runDnsBenchmark} disabled={dnsPerf?.benchmark_running}>
        {dnsPerf?.benchmark_running ? "Running…" : "Run Safe DNS Benchmark"}
      </button>
      <button data-copy-dns-perf onclick={copyDnsPerfReport} disabled={!dnsPerf?.report}>Copy DNS Performance Report</button>
      <button data-clear-dns-perf onclick={clearDnsBenchmark} disabled={!dnsPerf?.report}>Clear Benchmark Measurements</button>
      {#if dnsPerfActionStatus}<span class="hint">{dnsPerfActionStatus}</span>{/if}
    </div>
    {#if dnsPerfError}
      <p class="status-unavailable">Unavailable: {dnsPerfError}</p>
    {:else if !dnsPerf}
      <p class="hint">…</p>
    {:else}
      {#if dnsPerf.last_error}<p class="degraded-note" role="status">Last benchmark run failed: {dnsPerf.last_error}</p>{/if}
      {#if dnsPerf.report_error}<p class="degraded-note" role="status">{dnsPerf.report_error}</p>{/if}
      {#if !dnsPerf.report}
        <p class="hint">No DNS benchmark report yet.</p>
      {:else}
        {@const report = dnsPerf.report}
        <p class="hint">
          Generated {timestampPref.format(report.generated_at)}; duration {report.duration_seconds}s.
        </p>
        <div class="perf-scroll">
          <table class="perf-table dns-perf-table" data-dns-performance>
            <thead>
              <tr>
                <th>Case</th>
                <th>Protocol</th>
                <th>Count</th>
                <th>Success</th>
                <th>Timeouts</th>
                <th>Errors</th>
                <th>p50</th>
                <th>p95</th>
                <th>p99</th>
                <th>Max</th>
              </tr>
            </thead>
            <tbody>
              {#each report.cases as c (c.name)}
                <tr>
                  <td>{c.name}<br /><span class="scope">{c.scope}</span></td>
                  <td>{c.protocol}</td>
                  <td>{c.summary.count}</td>
                  <td>{c.summary.success}</td>
                  <td>{c.summary.timeouts}</td>
                  <td>{c.summary.errors}</td>
                  <td>{c.summary.p50_ms !== null ? `${c.summary.p50_ms} ms` : "—"}</td>
                  <td>{c.summary.p95_ms !== null ? `${c.summary.p95_ms} ms` : "—"}</td>
                  <td>{c.summary.p99_ms !== null ? `${c.summary.p99_ms} ms` : "—"}</td>
                  <td>{c.summary.max_ms !== null ? `${c.summary.max_ms} ms` : "—"}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if report.notes.length > 0}
          <ul class="notes">
            {#each report.notes as note}<li>{note}</li>{/each}
          </ul>
        {/if}
      {/if}
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
  .notes { font-size: 0.75rem; opacity: 0.7; margin: 0; padding-left: 1.2rem; }
</style>
