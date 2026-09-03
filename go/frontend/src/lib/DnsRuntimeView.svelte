<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type DNSRuntimeStatus, type DNSRuntimeApplyResult } from "../api";
  import { router } from "../router.svelte";

  // DNS Runtime: the real Go-native BIND + dnsdist compiler/promotion
  // pipeline (internal/dnscompile, internal/dnsruntime,
  // internal/hostagentd/ops_dnsruntime.go). Every resolver-affecting
  // save already auto-applies through the same real compiler (Local
  // DNS, Upstreams/Domain Routing, Custom Rules, Blocklists, DNS
  // Transports, Clients & Access global/network policy, Strong
  // ClientID -- see every applyDNSRuntimeBestEffort call site). "Apply
  // Runtime Changes" below is a manual re-compile-and-promote-now
  // action (useful after fixing an underlying config issue, or to
  // force a fresh promotion), not the only way a change takes effect.
  // Scope: one default upstream profile, a flat global domain-routing
  // list, global + per-network response-mode policy (2026-08-28) -- no
  // per-group/per-client general-policy compilation yet -- see
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
    promotion, and automatic rollback on any failure. Every resolver-affecting save already
    auto-applies through this same pipeline (Local DNS, Upstreams/Domain Routing, Custom Rules,
    Blocklists, DNS Transports, Clients &amp; Access global/network policy, Strong ClientID).
    "Apply Runtime Changes" below is a manual re-compile-and-promote action, not the only path to
    a live effect. One default upstream profile and a flat global domain-routing list; global and
    per-network response-mode policy (blocked-answer type) enforce live today. Per-group and
    per-client general policy fields do not enforce yet -- see Clients &amp; Access below for
    exactly which fields.
  </p>

  {#if statusError}<p class="error" role="alert">{statusError}</p>{/if}

  <div class="grid-2col">
    <div class="card">
      <h3>Runtime status</h3>
      {#if statusError}
        <p class="hint status-unavailable">Unavailable: {statusError}</p>
      {:else if status}
        <div class="row">
          <span class={status.bind_running ? "status-ok" : "status-unavailable"}>BIND {status.bind_running ? "running" : "not running"}</span>
          <span class={status.dnsdist_running ? "status-ok" : "status-unavailable"}>dnsdist {status.dnsdist_running ? "running" : "not running"}</span>
        </div>
        <p class="hint">
          Last successful promotion:
          {status.last_promoted_at ? new Date(status.last_promoted_at).toLocaleString() : "none yet this hostagent generation"}
        </p>
      {:else}
        <p class="hint">Loading…</p>
      {/if}
    </div>

    <div class="card">
      <h3>Apply Runtime Changes</h3>
      <p class="hint">Recompiles current Local DNS / Custom Rules / Blocklists / DNS Settings / DNS Transport state and promotes it through the host-control agent.</p>
      <button onclick={apply} disabled={applyBusy || !!statusError}>{applyBusy ? "Applying…" : "Apply Runtime Changes"}</button>
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

    <div class="card">
      <h3>What auto-applies already</h3>
      <p class="hint">
        Every resolver-affecting save already runs this same compile/validate/promote/rollback
        pipeline on its own: Local DNS, Upstreams &amp; Domain Routing, Custom Rules, Blocklists,
        DNS Transports, Clients &amp; Access global/network policy, and Strong ClientID. The
        button on this page is a manual re-run, not the only path to a live effect.
      </p>
    </div>

    <div class="card">
      <h3>Current compile scope</h3>
      <p class="hint">
        One default upstream profile and a flat global domain-routing list; global and
        per-network response-mode policy (blocked-answer type) enforce live today. Per-group and
        per-client general policy fields do not enforce yet -- see Clients &amp; Access for
        exactly which fields.
      </p>
    </div>
  </div>
</section>

<style>
  .dnsruntime { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  /* Two columns on desktop/tablet, one on mobile -- previously two
     narrow fixed-max-width cards stacked full-height down a wide page,
     leaving most of the viewport as dead space either side of them. */
  .grid-2col { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1rem; align-items: start; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); box-shadow: var(--shadow); display: flex; flex-direction: column; gap: 0.6rem; }
  .card h3 { margin: 0; }
  .row { display: flex; gap: 1rem; }
  .status-ok { color: var(--success); }
  .status-unavailable { opacity: 0.6; }
  .success { color: var(--success); }
  .error { color: var(--badge-danger-fg); }
  .hint { font-size: 0.85rem; opacity: 0.7; }
</style>
