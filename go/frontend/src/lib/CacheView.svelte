<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type CacheStatusResponse, type DNSRuntimeApplyResult } from "../api";
  import { router } from "../router.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";

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

  onMount(() => {
    refresh();
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
</script>

<section aria-labelledby="cache-heading" class="cache">
  <h2 id="cache-heading">Cache</h2>
  <p class="scope-note">
    Real status and flush, via the root-owned apdns-hostagent process (never direct root access from
    this web service). Each BIND context can be flushed entirely, by an exact domain name, or by a
    whole subtree. dnsdist has no live flush channel by design -- see the note below.
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
    <button onclick={restartDnsdist} disabled={flushBusy === "dnsdist"}>
      {flushBusy === "dnsdist" ? "Restarting…" : "Restart dnsdist (clears cache)"}
    </button>
    <DnsRuntimeBadge result={dnsdistRuntimeResult} />
  </div>
</section>

<style>
  .cache { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
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
</style>
