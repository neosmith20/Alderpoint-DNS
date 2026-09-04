<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type CacheStatusResponse, type DNSRuntimeApplyResult, type CacheSettings } from "../api";
  import { router } from "../router.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";
  import PageHeader from "./ui/PageHeader.svelte";

  // Cache. Real, via internal/hostagent -> apdns-hostagent (a separate,
  // root-owned process this web service talks to over a Unix socket --
  // never direct root access from here). BIND flush uses the real rndc
  // binary against the appliance's real rndc.conf, with real flush-all/
  // flush-by-exact-name/flush-tree scopes (rndc flush/flushname/
  // flushtree) -- not just "all". dnsdist has no live administrative
  // flush channel by design (see internal/hostagentd/ops_cache.go's own
  // doc comment), so instead of a button that always fails, "Restart
  // dnsdist" re-runs the same stage->validate->promote->health-check->
  // auto-rollback pipeline every other DNS Runtime change already goes
  // through (internal/dnsruntime.Orchestrator.Apply) -- a real, safe way
  // to clear its packet cache, with the same continuity guarantees.

  let status = $state<CacheStatusResponse | null>(null);
  let loadError = $state("");
  let flushBusy = $state<string | null>(null);
  let flushResult = $state("");
  let flushError = $state("");
  let dnsdistRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);

  async function refresh() {
    loadError = "";
    try {
      status = await api.cacheStatus(router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  let cacheSettings = $state<CacheSettings | null>(null);
  let cacheSettingsError = $state("");
  let cacheSettingsBusy = $state(false);
  let cacheSettingsSaved = $state(false);
  let cacheDnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);

  async function loadCacheSettings() {
    try {
      cacheSettings = await api.getCacheSettings(router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      cacheSettingsError = err instanceof ApiError ? err.message : String(err);
    }
  }

  async function saveCacheSettings(e: Event) {
    e.preventDefault();
    if (!cacheSettings) return;
    cacheSettingsBusy = true;
    cacheSettingsError = "";
    cacheSettingsSaved = false;
    try {
      const resp = await api.updateCacheSettings(cacheSettings);
      cacheSettings = resp.settings;
      cacheDnsRuntimeResult = resp.dns_runtime ?? null;
      cacheSettingsSaved = true;
    } catch (err) {
      cacheSettingsError = err instanceof ApiError ? err.message : String(err);
    } finally {
      cacheSettingsBusy = false;
    }
  }

  onMount(() => {
    refresh();
    loadCacheSettings();
  });

  // Per-context flush target/scope (name/tree need a real domain name to
  // act on -- internal/hostagentd/ops_cache.go already supports scope
  // all/name/tree with real rndc flushname/flushtree, this UI previously
  // only ever exposed "all").
  let flushScope = $state<Record<string, "all" | "name" | "tree">>({});
  let flushTarget = $state<Record<string, string>>({});

  async function flushContext(contextName: string) {
    const scope = flushScope[contextName] ?? "all";
    const target = flushTarget[contextName]?.trim();
    if (scope !== "all" && !target) {
      flushError = `A domain name is required to flush by ${scope}`;
      return;
    }
    flushBusy = contextName;
    flushError = "";
    flushResult = "";
    try {
      const result = await api.cacheFlush("bind", { context: contextName, scope, ...(scope !== "all" ? { target } : {}) });
      const r = result.results[0];
      const scopeLabel = scope === "all" ? "" : ` (${scope}: ${target})`;
      flushResult = r?.ok ? `Flushed ${contextName}${scopeLabel}: ${r.detail ?? "ok"}` : `Failed: ${r?.detail ?? "unknown error"}`;
      await refresh();
    } catch (err) {
      flushError = err instanceof ApiError ? err.message : String(err);
    } finally {
      flushBusy = null;
    }
  }

  async function restartDnsdist() {
    flushBusy = "dnsdist";
    flushError = "";
    flushResult = "";
    dnsdistRuntimeResult = null;
    try {
      const { dns_runtime } = await api.cacheDnsdistRestart();
      dnsdistRuntimeResult = dns_runtime;
      flushResult = dns_runtime.promoted
        ? "dnsdist restarted and its cache cleared."
        : `Restart did not complete: ${dns_runtime.detail ?? dns_runtime.stage}`;
      await refresh();
    } catch (err) {
      flushError = err instanceof ApiError ? err.message : String(err);
    } finally {
      flushBusy = null;
    }
  }

  // Top metrics: aggregated from the same real per-BIND-context stats the
  // table below shows -- the only real numbers this appliance's cache
  // backend exposes today are hits/misses/hit-ratio/memory. There is no
  // entries/nodes count, no eviction counter, and no stale-answer counter
  // anywhere in internal/hostagent's own cache stats yet, so those are
  // disclosed as unavailable rather than invented.
  const aggregate = $derived.by(() => {
    const withStats = (status?.bind ?? []).filter((c) => c.cache_stats?.available);
    if (withStats.length === 0) return null;
    const hits = withStats.reduce((s, c) => s + (c.cache_stats?.hits ?? 0), 0);
    const misses = withStats.reduce((s, c) => s + (c.cache_stats?.misses ?? 0), 0);
    const memory = withStats.reduce((s, c) => s + (c.cache_stats?.cache_size_bytes ?? 0), 0);
    const total = hits + misses;
    return { hits, misses, memory, hitRate: total ? (hits / total) * 100 : null };
  });

  function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  }
</script>

<PageHeader
  headingId="cache-heading"
  title="Cache"
  description="Real status and flush for this appliance's own resolver cache, via the root-owned apdns-hostagent process (never direct root access from this web service)."
/>

<div class="cache">
{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
{#if flushResult}<p class="success" role="status">{flushResult}</p>{/if}
{#if flushError}<p class="error" role="alert">{flushError}</p>{/if}

{#if aggregate}
  <div class="metrics-row">
    <div class="metric-card"><span class="metric-label">Hit rate</span><span class="metric-value">{aggregate.hitRate !== null ? `${aggregate.hitRate.toFixed(1)}%` : "—"}</span></div>
    <div class="metric-card"><span class="metric-label">Hits / misses</span><span class="metric-value">{aggregate.hits.toLocaleString()} / {aggregate.misses.toLocaleString()}</span></div>
    <div class="metric-card"><span class="metric-label">Memory</span><span class="metric-value">{formatBytes(aggregate.memory)}</span></div>
    <div class="metric-card metric-unavailable"><span class="metric-label">Entries / evictions / stale answers</span><span class="metric-value">Not reported</span></div>
  </div>
{/if}

  <div class="card">
    <h3>BIND contexts</h3>
    {#if loadError}
      <p class="hint status-unavailable">Unavailable: {loadError}</p>
    {:else if !status}
      <p class="hint">Loading…</p>
    {:else if status.bind.length === 0}
      <p class="hint">No BIND contexts reported (hostagent not configured for this deployment, or none compiled yet).</p>
    {:else}
      <table>
        <thead><tr><th>Context</th><th>Reachable</th><th>rndc status</th><th>Cache hits/misses</th><th>Actions</th></tr></thead>
        <tbody>
          {#each status.bind as ctx (ctx.name)}
            <tr>
              <td>{ctx.name}</td>
              <td class={ctx.reachable ? "status-ok" : "status-unavailable"}>{ctx.reachable ? "Yes" : "No"}</td>
              <td>{ctx.rndc_status ?? "—"}</td>
              <td>
                {#if !ctx.cache_stats || !ctx.cache_stats.available}
                  <span class="hint">unavailable{ctx.cache_stats?.error ? `: ${ctx.cache_stats.error}` : ""}</span>
                {:else}
                  {ctx.cache_stats.hits.toLocaleString()} / {ctx.cache_stats.misses.toLocaleString()}
                  {#if ctx.cache_stats.hit_ratio !== null}
                    <span class="hint">({(ctx.cache_stats.hit_ratio * 100).toFixed(1)}% hit rate)</span>
                  {/if}
                {/if}
              </td>
              <td class="flush-cell">
                <select bind:value={flushScope[ctx.name]} aria-label={`Flush scope for ${ctx.name}`} disabled={!ctx.reachable}>
                  <option value="all">All</option>
                  <option value="name">Exact name</option>
                  <option value="tree">Tree/subtree</option>
                </select>
                {#if (flushScope[ctx.name] ?? "all") !== "all"}
                  <input
                    bind:value={flushTarget[ctx.name]}
                    placeholder="example.com"
                    aria-label={`Flush target domain for ${ctx.name}`}
                    disabled={!ctx.reachable}
                  />
                {/if}
                <button onclick={() => flushContext(ctx.name)} disabled={!ctx.reachable || flushBusy === ctx.name}>
                  {flushBusy === ctx.name ? "Flushing…" : "Flush"}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  <div class="card">
    <h3>dnsdist</h3>
    <p class="hint">
      dnsdist's packet cache has no live flush channel -- clearing it requires a real restart.
      This safely re-promotes the current, already-validated configuration (the same
      stage/validate/promote/health-check pipeline every other DNS Runtime change uses), which
      restarts dnsdist and clears its cache as a result. A failed health check rolls back
      automatically; real DNS answering is never left down.
    </p>
    <button onclick={restartDnsdist} disabled={flushBusy === "dnsdist" || !!loadError}>
      {flushBusy === "dnsdist" ? "Restarting…" : "Restart dnsdist (clears cache)"}
    </button>
    <DnsRuntimeBadge result={dnsdistRuntimeResult} />
  </div>

  <div class="card">
    <h3>Cache configuration</h3>
    <p class="hint">
      Real BIND options -- applies to the resolver cache above (dnsdist's own packet-cache size is a
      separate, fixed internal setting). Saving recompiles and applies through the same real
      validate/promote/health-check pipeline every other DNS Runtime change uses.
    </p>
    {#if cacheSettingsError}<p class="error" role="alert">{cacheSettingsError}</p>{/if}
    {#if !cacheSettings}
      <p class="hint">Loading…</p>
    {:else}
      <form onsubmit={saveCacheSettings} class="cache-config-form">
        <label>Max cache TTL (seconds) <input type="number" min="1" max="2592000" bind:value={cacheSettings.max_cache_ttl_seconds} /></label>
        <label>Max negative TTL (seconds) <input type="number" min="1" max="604800" bind:value={cacheSettings.max_negative_ttl_seconds} /></label>
        <label class="checkbox-label"><input type="checkbox" bind:checked={cacheSettings.prefetch_enabled} /> Prefetch popular records before they expire</label>
        <label class="checkbox-label"><input type="checkbox" bind:checked={cacheSettings.serve_stale_enabled} /> Serve stale answers when upstream is unreachable</label>
        {#if cacheSettings.serve_stale_enabled}
          <label>Max stale TTL (seconds) <input type="number" min="1" max="604800" bind:value={cacheSettings.max_stale_ttl_seconds} /></label>
        {/if}
        <div class="form-actions">
          <!-- Plain JS string, not markup -- Svelte does NOT HTML-decode a
               `{}` expression the way it decodes static template text, so
               "&amp;" here was a real, screenshot-caught bug: the button
               literally read "Save &amp; Apply" on screen, not "Save &
               Apply". A bare "&" is exactly what a JS string needs. -->
          <button type="submit" disabled={cacheSettingsBusy}>{cacheSettingsBusy ? "Applying…" : "Save & Apply"}</button>
          {#if cacheSettingsSaved}<span class="success">Saved.</span>{/if}
        </div>
      </form>
      <DnsRuntimeBadge result={cacheDnsRuntimeResult} />
    {/if}
  </div>
</div>

<style>
  .cache { display: flex; flex-direction: column; gap: 1rem; }
  .metrics-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }
  @media (max-width: 900px) { .metrics-row { grid-template-columns: repeat(2, 1fr); } }
  .metric-card { border: 1px solid var(--border); border-radius: 8px; padding: 0.85rem 1rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.25rem; }
  .metric-label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.03em; opacity: 0.7; }
  .metric-value { font-size: 1.3rem; font-weight: 700; }
  .metric-unavailable .metric-value { font-size: 0.95rem; opacity: 0.6; font-weight: 500; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; }
  .card h3 { margin: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border); }
  .status-ok { color: var(--success); }
  .status-unavailable { color: var(--badge-danger-fg); }
  .hint { font-size: 0.85rem; opacity: 0.75; margin: 0; }
  .success { color: var(--success); }
  .error { color: var(--badge-danger-fg); }
  .flush-cell { display: flex; gap: 0.4rem; flex-wrap: wrap; align-items: center; }
  .flush-cell input { width: 10rem; }
  .cache-config-form { display: flex; flex-direction: column; gap: 0.65rem; max-width: 28rem; }
  .cache-config-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .checkbox-label { flex-direction: row !important; align-items: center; gap: 0.5rem !important; }
  .form-actions { display: flex; align-items: center; gap: 0.6rem; }
</style>
