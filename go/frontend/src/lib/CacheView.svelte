<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type CacheStatusResponse } from "../api";
  import { router } from "../router.svelte";

  // Cache. Real, via internal/hostagent -> apdns-hostagent (a separate,
  // root-owned process this web service talks to over a Unix socket --
  // never direct root access from here). BIND flush uses the real rndc
  // binary against the appliance's real rndc.conf; dnsdist has no live
  // administrative channel by design (Python's own architecture), so
  // its "flush" honestly reports that a restart is required instead of
  // faking a live flush.

  let status = $state<CacheStatusResponse | null>(null);
  let loadError = $state("");
  let flushBusy = $state<string | null>(null);
  let flushResult = $state("");
  let flushError = $state("");

  async function refresh() {
    loadError = "";
    try {
      status = await api.cacheStatus(router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
  });

  async function flushContext(contextName: string) {
    flushBusy = contextName;
    flushError = "";
    flushResult = "";
    try {
      const result = await api.cacheFlush("bind", { context: contextName, scope: "all" });
      const r = result.results[0];
      flushResult = r?.ok ? `Flushed ${contextName}: ${r.detail ?? "ok"}` : `Failed: ${r?.detail ?? "unknown error"}`;
      await refresh();
    } catch (err) {
      flushError = err instanceof ApiError ? err.message : String(err);
    } finally {
      flushBusy = null;
    }
  }

  async function flushDnsdist() {
    flushBusy = "dnsdist";
    flushError = "";
    flushResult = "";
    try {
      await api.cacheFlush("dnsdist");
    } catch (err) {
      // Expected: dnsdist flush is honestly denied, not faked -- see
      // internal/hostagentd/ops_cache.go's own doc comment.
      flushError = err instanceof ApiError ? err.message : String(err);
    } finally {
      flushBusy = null;
    }
  }
</script>

<section aria-labelledby="cache-heading" class="cache">
  <h2 id="cache-heading">Cache</h2>
  <p class="scope-note">
    Real status and flush, via the root-owned apdns-hostagent process (never direct root access from
    this web service). dnsdist has no live flush channel by design -- see the note below.
  </p>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
  {#if flushResult}<p class="success" role="status">{flushResult}</p>{/if}
  {#if flushError}<p class="error" role="alert">{flushError}</p>{/if}

  <div class="card">
    <h3>BIND contexts</h3>
    {#if !status}
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
              <td>
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
    <p class="hint">{status?.dnsdist.note ?? "…"}</p>
    <button onclick={flushDnsdist} disabled={flushBusy === "dnsdist"}>{flushBusy === "dnsdist" ? "…" : "Attempt flush"}</button>
  </div>
</section>

<style>
  .cache { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; }
  .card h3 { margin: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border); }
  .status-ok { color: #16a34a; }
  .status-unavailable { color: var(--badge-danger-fg); }
  .hint { font-size: 0.85rem; opacity: 0.75; margin: 0; }
  .success { color: #16a34a; }
  .error { color: var(--badge-danger-fg); }
</style>
