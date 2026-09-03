<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type DNSRuntimeStatus, type DNSRuntimeApplyResult } from "../api";
  import { router } from "../router.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";

  // DNS Runtime: the real Go-native BIND + dnsdist compiler/promotion
  // pipeline (internal/dnscompile, internal/dnsruntime,
  // internal/hostagentd/ops_dnsruntime.go). Every resolver-affecting
  // save already auto-applies through the same real compiler (Local
  // DNS, Upstreams/Domain Routing, Custom Rules, Blocklists, DNS
  // Transports, Scope Policies global/network policy, Strong
  // ClientID -- see every applyDNSRuntimeBestEffort call site). "Apply
  // Runtime Changes" below is a manual re-compile-and-promote-now
  // action (useful after fixing an underlying config issue, or to
  // force a fresh promotion), not the only way a change takes effect.
  // Scope: one default upstream profile, a flat global domain-routing
  // list, global + per-network response-mode policy -- no per-group/
  // per-client general-policy compilation yet -- see
  // internal/dnscompile's own doc comment for the complete list.
  //
  // Disclosed ceiling of DNSRuntimeStatus itself: bind_running /
  // dnsdist_running / last_promoted_at is the complete real status this
  // appliance tracks today. There is no generation id, no pending-
  // changes count, no persisted deployment history, no rollback-state
  // record, and no generated-configuration inventory anywhere in the Go
  // backend yet -- every one of those spec sections below says so
  // explicitly rather than being silently dropped or faked.

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

  const overallHealthy = $derived(!!status && status.bind_running && status.dnsdist_running);

  // Apply-stage timeline: real, measured per-stage timings from the most
  // recent apply (see DNSRuntimeApplyResult.timings' own doc comment) --
  // not synthesized. Absent on a response where attempted was false.
  const timelineStages = $derived.by(() => {
    const t = applyResult?.timings;
    if (!t) return [];
    return [
      { label: "Build (this process)", ms: t.build_ms },
      { label: "Web compile", ms: t.web_compile_ms },
      { label: "Agent compile", ms: t.compile_ms },
      { label: "Validate", ms: t.validate_ms },
      { label: "Promote", ms: t.promote_ms },
      { label: "Reload", ms: t.reload_ms },
      { label: "Health check", ms: t.health_check_ms },
    ];
  });
  const timelineTotal = $derived(applyResult?.timings?.total_ms ?? 0);
</script>

<PageHeader
  headingId="dnsruntime-heading"
  title="DNS Runtime"
  description="Real BIND + dnsdist compilation, validation against the actual installed binaries, atomic promotion, and automatic rollback on any failure."
>
  {#snippet actions()}
    <button type="button" onclick={apply} disabled={applyBusy || !!statusError}>{applyBusy ? "Applying…" : "Apply Pending Changes"}</button>
  {/snippet}
</PageHeader>

{#if statusError}<p class="error" role="alert">{statusError}</p>{/if}

<div class="status-summary">
  <StatusBadge label={statusError ? "Unavailable" : overallHealthy ? "Healthy" : "Degraded"} tone={statusError ? "danger" : overallHealthy ? "healthy" : "danger"} />
  <span>Last successful deployment: <strong>{status?.last_promoted_at ? new Date(status.last_promoted_at).toLocaleString() : "none yet this hostagent generation"}</strong></span>
  <span class="hint">Active generation / pending-changes count are not tracked by this appliance yet.</span>
</div>

<div class="grid-2col">
  <div class="card">
    <h3>BIND</h3>
    <StatusBadge label={status?.bind_running ? "Running" : "Not running"} tone={status?.bind_running ? "healthy" : "danger"} />
    <p class="hint">Recursive/authoritative resolver -- validated via rndc against the real installed binary before every promotion.</p>
  </div>
  <div class="card">
    <h3>dnsdist</h3>
    <StatusBadge label={status?.dnsdist_running ? "Running" : "Not running"} tone={status?.dnsdist_running ? "healthy" : "danger"} />
    <p class="hint">Front-line DNS listener/load balancer -- forwards non-local, non-blocked queries to BIND.</p>
  </div>
</div>

<div class="card wide">
  <h3>Apply-stage timeline</h3>
  {#if applyError}
    <p class="error" role="alert">{applyError}</p>
  {:else if applyResult}
    {#if applyResult.promoted}
      <p class="success" role="status">Promoted successfully{timelineTotal ? ` in ${timelineTotal} ms` : ""}.</p>
    {:else if applyResult.rolled_back}
      <p class="error" role="alert">Rejected at stage "{applyResult.stage}": {applyResult.detail}. Previous runtime restored automatically -- real DNS answering was never left down.</p>
    {:else}
      <p class="error" role="alert">{applyResult.error}</p>
    {/if}
    {#if timelineStages.length > 0}
      <div class="timeline">
        {#each timelineStages as s (s.label)}
          <div class="timeline-row">
            <span class="timeline-label">{s.label}</span>
            <span class="timeline-bar"><span style="width: {timelineTotal ? Math.min((s.ms / timelineTotal) * 100, 100) : 0}%"></span></span>
            <span class="timeline-ms">{s.ms} ms</span>
          </div>
        {/each}
      </div>
    {/if}
  {:else}
    <p class="hint">Run "Apply Pending Changes" above to see real, measured per-stage timing for this specific apply.</p>
  {/if}
</div>

<div class="grid-2col">
  <div class="card">
    <h3>Generated configuration inventory</h3>
    <p class="hint">
      Not exposed by this appliance's DNS runtime yet -- there is no owner-facing listing of the
      generated BIND/dnsdist configuration files themselves. This is a disclosed gap.
    </p>
  </div>
  <div class="card">
    <h3>Recent deployment history &amp; rollback state</h3>
    <p class="hint">
      Not persisted anywhere yet -- only the most recent apply's own result (above) and the
      last-successful-promotion timestamp are tracked. A failed apply already rolls back
      automatically in real time; there is no separate manual "Roll Back to Previous Generation"
      action because no prior generations are retained to roll back to.
    </p>
  </div>
</div>

<div class="card wide">
  <h3>What auto-applies already</h3>
  <p class="hint">
    Every resolver-affecting save already runs this same compile/validate/promote/rollback
    pipeline on its own: Local DNS, Upstreams &amp; Domain Routing, Custom Rules, Blocklists,
    DNS Transports, Scope Policies global/network policy, and Strong ClientID. The button above
    is a manual re-run, not the only path to a live effect. One default upstream profile and a
    flat global domain-routing list; global and per-network response-mode policy (blocked-answer
    type) enforce live today. Per-group and per-client general policy fields do not enforce yet --
    see Scope Policies for exactly which fields.
  </p>
</div>

<style>
  .status-summary {
    display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem; font-size: 0.85rem; margin-bottom: 1rem;
    padding: 0.75rem 1rem; border: 1px solid var(--border); border-radius: 8px; background: var(--panel-elevated);
  }
  .grid-2col { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1rem; align-items: start; margin-bottom: 1rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); box-shadow: var(--shadow); display: flex; flex-direction: column; gap: 0.6rem; }
  .card.wide { margin-bottom: 1rem; }
  .card h3 { margin: 0; }
  .success { color: var(--success); }
  .error { color: var(--danger); }
  .hint { font-size: 0.85rem; opacity: 0.7; }

  .timeline { display: flex; flex-direction: column; gap: 0.4rem; margin-top: 0.5rem; }
  .timeline-row { display: grid; grid-template-columns: 9rem 1fr 4.5rem; align-items: center; gap: 0.6rem; font-size: 0.82rem; }
  .timeline-bar { display: block; height: 0.5rem; border-radius: 999px; background: var(--border); overflow: hidden; }
  .timeline-bar span { display: block; height: 100%; background: var(--accent); border-radius: 999px; }
  .timeline-ms { text-align: right; font-family: monospace; opacity: 0.8; }
</style>
