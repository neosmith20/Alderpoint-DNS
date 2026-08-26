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
  // Node Identity, Discovery status, DNS Performance benchmark, and BIND
  // Cache Counters are not built, disclosed rather than hidden:
  //   - Node Identity lives inside Python's control.db itself
  //     (app/v2/node_identity.py's ensure_schema calls
  //     control_db.initialize) -- the same isolation concern already
  //     refused for Observed Clients/discovery and Replication (a
  //     read-only mount would sit alongside admin password hashes).
  //   - BIND Cache Counters need the same live rndc/stats control-plane
  //     access documented as currently infeasible on the Cache row.
  //   - DNS Performance benchmark issues real queries through BIND/
  //     dnsdist and needs the same live-runtime reach as Cache/BIND
  //     Cache Counters.
  //   - Discovery status is a Python-side pipeline this migration hasn't
  //     built a compatibility boundary for.

  let health = $state<Awaited<ReturnType<typeof api.health>> | null>(null);
  let sysStatus = $state<Awaited<ReturnType<typeof api.systemStatus>> | null>(null);
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
    Metric strip, Components, and UI Performance are real. Node Identity, Discovery status, DNS
    Performance benchmark, and BIND Cache Counters are not built yet -- see the parity matrix for
    why (control.db isolation and live-runtime-control reach this control plane doesn't have).
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
              <td>{c.schema_version !== undefined ? `schema_version=${c.schema_version}` : (c.detail ?? "")}</td>
            </tr>
          {/each}
        </tbody>
      </table>
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
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; }
  .card h3 { margin: 0; }
  .scope { font-size: 0.75rem; font-weight: 400; opacity: 0.6; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border); }
  .status-ok { color: #16a34a; }
  .status-degraded, .status-unavailable { color: var(--badge-danger-fg); }
  .actions { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
  .hint { font-size: 0.8rem; opacity: 0.7; }
  .error { color: var(--badge-danger-fg); }
  .perf-scroll { max-height: 20rem; overflow-y: auto; overflow-x: auto; }
</style>
