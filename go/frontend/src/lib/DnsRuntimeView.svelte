<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type DNSRuntimeStatus, type DNSRuntimeApplyResult } from "../api";
  import { router } from "../router.svelte";

  // DNS Runtime: the real Go-native BIND + dnsdist compiler/promotion
  // pipeline (internal/dnscompile, internal/dnsruntime,
  // internal/hostagentd/ops_dnsruntime.go). Local DNS changes apply
  // automatically on save; Custom Rules, Blocklists, DNS Settings, and
  // DNS Transports changes are compiled the next time this page's
  // "Apply Runtime Changes" is used (or the next time a Local DNS
  // change triggers it) -- not yet auto-triggered from those pages
  // individually. Scope: global policy only (not yet per-network), one
  // default upstream profile, no domain routing yet -- see
  // internal/dnscompile's own doc comment for the complete list.

  let status = $state<DNSRuntimeStatus | null>(null);
  let statusError = $state("");
  let applyBusy = $state(false);
  let applyResult = $state<DNSRuntimeApplyResult | null>(null);
  let applyError = $state("");

  async function refresh() {
    statusError = "";
    try {
      status = await api.dnsRuntimeStatus(router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      statusError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
  });

  async function apply() {
    applyBusy = true;
    applyError = "";
    applyResult = null;
    try {
      applyResult = await api.applyDNSRuntime();
      await refresh();
    } catch (err) {
      applyError = err instanceof ApiError ? err.message : String(err);
    } finally {
      applyBusy = false;
    }
  }
</script>

<section aria-labelledby="dnsruntime-heading" class="dnsruntime">
  <h2 id="dnsruntime-heading">DNS Runtime</h2>
  <p class="scope-note">
    Real BIND + dnsdist compilation, validation (against the actual installed binaries), atomic
    promotion, and automatic rollback on any failure -- see internal/dnscompile and
    internal/hostagentd/ops_dnsruntime.go. Global policy scope only (not per-network yet); one
    default upstream profile; no domain routing yet. Local DNS changes apply automatically;
    Custom Rules, Blocklists, DNS Settings, and DNS Transports changes need "Apply Runtime
    Changes" below until each is individually wired to auto-trigger.
  </p>

  {#if statusError}<p class="error" role="alert">{statusError}</p>{/if}

  <div class="card">
    <h3>Runtime status</h3>
    {#if status}
      <div class="row">
        <span class={status.bind_running ? "status-ok" : "status-unavailable"}>BIND {status.bind_running ? "running" : "not running"}</span>
        <span class={status.dnsdist_running ? "status-ok" : "status-unavailable"}>dnsdist {status.dnsdist_running ? "running" : "not running"}</span>
      </div>
    {:else}
      <p class="hint">Loading…</p>
    {/if}
  </div>

  <div class="card">
    <h3>Apply Runtime Changes</h3>
    <p class="hint">Recompiles current Local DNS / Custom Rules / Blocklists / DNS Settings / DNS Transport state and promotes it through the host-control agent.</p>
    <button onclick={apply} disabled={applyBusy}>{applyBusy ? "Applying…" : "Apply Runtime Changes"}</button>
    {#if applyError}<p class="error" role="alert">{applyError}</p>{/if}
    {#if applyResult}
      {#if applyResult.promoted}
        <p class="success" role="status">Promoted successfully.</p>
      {:else if applyResult.rolled_back}
        <p class="error" role="alert">Rejected at stage "{applyResult.stage}": {applyResult.detail}. Previous runtime restored.</p>
      {:else}
        <p class="error" role="alert">{applyResult.error}</p>
      {/if}
    {/if}
  </div>
</section>

<style>
  .dnsruntime { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; max-width: 32rem; }
  .card h3 { margin: 0; }
  .row { display: flex; gap: 1rem; }
  .status-ok { color: #16a34a; }
  .status-unavailable { opacity: 0.6; }
  .success { color: #16a34a; }
  .error { color: var(--badge-danger-fg); }
  .hint { font-size: 0.85rem; opacity: 0.7; }
</style>
