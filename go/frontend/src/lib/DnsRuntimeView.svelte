<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type DNSRuntimeStatus, type DNSRuntimeApplyResult, type DNSRuntimeGeneration, type DNSRuntimeInventoryFile } from "../api";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";

  // DNS Runtime: the real Go-native BIND + dnsdist compiler/promotion
  // pipeline (internal/dnscompile, internal/dnsruntime,
  // internal/hostagentd/ops_dnsruntime.go). Every resolver-affecting
  // save already auto-applies through the same real compiler (Local
  // DNS, Upstreams/Domain Routing, Custom Rules, Blocklists, DNS
  // Transports, Scope Policies global/network policy, Strong
  // ClientID -- see every applyDNSRuntimeBestEffort call site). "Apply
  // Pending Changes" below is a manual re-compile-and-promote-now
  // action, not the only way a change takes effect.
  //
  // Generation tracking (internal/dnsgenerations): a real, replayable
  // snapshot of the dnsdist config is saved on every successful
  // promotion; deployment history and Roll Back to Previous Generation
  // are both real. Disclosed, not faked: there is no BIND-side file
  // snapshot per generation (that state is continuously derived from
  // the live DB -- blocklists/local DNS/policy -- governed by Backup &
  // Restore instead), so rollback restores dnsdist's own compiled
  // config, not BIND zone/RPZ file history.

  let status = $state<DNSRuntimeStatus | null>(null);
  let statusError = $state("");
  let applyBusy = $state(false);
  let applyResult = $state<DNSRuntimeApplyResult | null>(null);
  let applyError = $state("");

  let generations = $state<DNSRuntimeGeneration[]>([]);
  let generationsAvailable = $state(false);
  let inventory = $state<DNSRuntimeInventoryFile[]>([]);
  let pending = $state<{ known: boolean; pending: boolean } | null>(null);

  let rollbackBusy = $state(false);
  let rollbackResult = $state<DNSRuntimeApplyResult | null>(null);
  let confirmRollbackOpen = $state(false);

  async function refresh() {
    statusError = "";
    try {
      status = await api.dnsRuntimeStatus(router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      statusError = err instanceof ApiError ? err.message : String(err);
    }
    try {
      const g = await api.dnsRuntimeGenerations(router.signal());
      generations = g.generations;
      generationsAvailable = g.available;
    } catch {
      /* the history card's own "unavailable" state covers a failed fetch */
    }
    try {
      const inv = await api.dnsRuntimeInventory(router.signal());
      inventory = inv.files;
    } catch {
      /* the inventory card's own empty state covers a failed fetch */
    }
    try {
      pending = await api.dnsRuntimePendingChanges(router.signal());
    } catch {
      pending = null;
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

  async function runRollback() {
    confirmRollbackOpen = false;
    rollbackBusy = true;
    rollbackResult = null;
    try {
      rollbackResult = await api.dnsRuntimeRollback();
      await refresh();
    } catch (err) {
      rollbackResult = { attempted: true, promoted: false, rolled_back: false, error: err instanceof ApiError ? err.message : String(err) };
    } finally {
      rollbackBusy = false;
    }
  }

  const overallHealthy = $derived(!!status && status.bind_running && status.dnsdist_running);
  const activeGeneration = $derived(generations.find((g) => g.promoted && !g.rolled_back) ?? null);
  const promotedGenerations = $derived(generations.filter((g) => g.promoted));
  const canRollback = $derived(promotedGenerations.length >= 2);

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

  function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    return `${(n / 1024).toFixed(1)} KB`;
  }
</script>

<PageHeader
  headingId="dnsruntime-heading"
  title="DNS Runtime"
  description="Real BIND + dnsdist compilation, validation against the actual installed binaries, atomic promotion, and automatic rollback on any failure."
>
  {#snippet actions()}
    <button type="button" class="secondary" onclick={() => (confirmRollbackOpen = true)} disabled={!canRollback || rollbackBusy}>
      {rollbackBusy ? "Rolling back…" : "Roll Back to Previous Generation"}
    </button>
    <button type="button" onclick={apply} disabled={applyBusy || !!statusError}>{applyBusy ? "Applying…" : "Apply Pending Changes"}</button>
  {/snippet}
</PageHeader>

{#if statusError}<p class="error" role="alert">{statusError}</p>{/if}

<div class="status-summary">
  <StatusBadge label={statusError ? "Unavailable" : overallHealthy ? "Healthy" : "Degraded"} tone={statusError ? "danger" : overallHealthy ? "healthy" : "danger"} />
  <span>Active generation: <strong>{activeGeneration ? `#${activeGeneration.generation_number}` : "none yet"}</strong></span>
  <span>Last successful deployment: <strong>{status?.last_promoted_at ? new Date(status.last_promoted_at).toLocaleString() : "none yet"}</strong></span>
  {#if pending?.known}
    <StatusBadge label={pending.pending ? "Pending changes" : "Up to date"} tone={pending.pending ? "warning" : "healthy"} />
  {/if}
</div>

{#if rollbackResult}
  {#if rollbackResult.promoted}
    <p class="success" role="status">Rolled back successfully.</p>
  {:else}
    <p class="error" role="alert">Rollback failed: {rollbackResult.error || rollbackResult.detail}</p>
  {/if}
{/if}

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

<div class="card wide" data-apply-result>
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
    {#if inventory.length === 0}
      <p class="hint">No generated files found yet.</p>
    {:else}
      <table class="inv-table">
        <thead><tr><th>File</th><th>Size</th><th>Modified</th></tr></thead>
        <tbody>
          {#each inventory as f (f.path)}
            <tr><td class="mono" title={f.path}>{f.path}</td><td>{formatBytes(f.size_bytes)}</td><td>{timestampPref.format(f.mod_time)}</td></tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
  <div class="card">
    <h3>Validation &amp; rollback state</h3>
    <p class="hint">
      {#if !generationsAvailable}
        Deployment history is not available on this deployment.
      {:else if canRollback}
        {promotedGenerations.length} promoted generations on record. Rolling back restores dnsdist's own compiled configuration to the previous one -- through the same validate/promote/health-check pipeline every apply uses.
      {:else}
        Only one promoted generation exists so far -- nothing to roll back to yet.
      {/if}
    </p>
  </div>
</div>

<div class="card wide">
  <h3>Recent deployment history</h3>
  {#if generations.length === 0}
    <p class="hint">No deployment attempts recorded yet.</p>
  {:else}
    <table class="history-table">
      <thead><tr><th>Gen</th><th>When</th><th>Trigger</th><th>Result</th><th>Detail</th></tr></thead>
      <tbody>
        {#each generations as g (g.id)}
          <tr>
            <td>#{g.generation_number}</td>
            <td class="mono">{timestampPref.format(g.created_at)}</td>
            <td>{g.trigger}</td>
            <td>
              {#if g.promoted}<StatusBadge label="Promoted" tone="healthy" />
              {:else if g.rolled_back}<StatusBadge label="Rejected, rolled back" tone="warning" />
              {:else}<StatusBadge label="Failed" tone="danger" />{/if}
            </td>
            <td>{g.error || g.detail || "—"}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
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

{#if confirmRollbackOpen}
  <ConfirmDialog
    title="Roll Back to Previous Generation"
    message="Re-promote the previous generation's own saved dnsdist configuration? This goes through the same validate/promote/health-check pipeline as a normal apply, with automatic rollback if it fails health checks."
    confirmLabel="Roll Back"
    onConfirm={runRollback}
    onCancel={() => (confirmRollbackOpen = false)}
  />
{/if}

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
  .mono { font-family: monospace; font-size: 0.8rem; }

  .timeline { display: flex; flex-direction: column; gap: 0.4rem; margin-top: 0.5rem; }
  .timeline-row { display: grid; grid-template-columns: 9rem 1fr 4.5rem; align-items: center; gap: 0.6rem; font-size: 0.82rem; }
  .timeline-bar { display: block; height: 0.5rem; border-radius: 999px; background: var(--border); overflow: hidden; }
  .timeline-bar span { display: block; height: 100%; background: var(--accent); border-radius: 999px; }
  .timeline-ms { text-align: right; font-family: monospace; opacity: 0.8; }

  .inv-table, .history-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  .inv-table th, .history-table th { text-align: left; font-weight: 600; opacity: 0.7; padding: 0.3rem 0.5rem 0.3rem 0; border-bottom: 1px solid var(--border); }
  .inv-table td, .history-table td { padding: 0.3rem 0.5rem 0.3rem 0; border-bottom: 1px solid var(--border); max-width: 20rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .inv-table tr:last-child td, .history-table tr:last-child td { border-bottom: none; }
</style>
