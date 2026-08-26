<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "../api";
  import { router } from "../router.svelte";
  import { StaleGuard } from "../staleGuard";

  // Real, honestly-scoped Dashboard: only what the Go control plane
  // genuinely owns today (Blocklists, Local DNS). Analytics, live DNS
  // Activity, upstreams, and observed clients are NOT here -- they live in
  // Python's separate analytics/policy stores with no Go compatibility
  // boundary built yet (see PARITY_MATRIX.md's Dashboard row). Showing
  // fewer real cards is the honest choice over showing more fake ones;
  // customizable card add/remove/reorder is future work once there's more
  // than one real card type to arrange.
  let summary = $state<Awaited<ReturnType<typeof api.dashboardSummary>> | null>(null);
  let loadError = $state("");
  const guard = new StaleGuard();

  async function refresh() {
    const token = guard.start();
    try {
      const resp = await api.dashboardSummary(router.signal());
      if (!guard.isCurrent(token)) return;
      summary = resp;
      loadError = "";
    } catch (err) {
      if (!guard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof Error ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
  });
</script>

<section aria-labelledby="dashboard-heading">
  <h2 id="dashboard-heading">Dashboard</h2>
  {#if loadError}
    <p class="error" role="alert">{loadError}</p>
  {:else if !summary}
    <p class="hint">Loading…</p>
  {:else}
    <div class="cards">
      <div class="card">
        <h3>Blocklists</h3>
        <p class="big">{summary.blocklists.enabled}<span class="of"> / {summary.blocklists.total} enabled</span></p>
        <p class="hint">{summary.blocklists.total_rules.toLocaleString()} rules total</p>
        {#if summary.blocklists.attention_required > 0}
          <p class="badge badge-attention">{summary.blocklists.attention_required} need attention</p>
        {/if}
      </div>
      <div class="card">
        <h3>Local DNS</h3>
        <p class="big">{summary.local_dns.enabled}<span class="of"> / {summary.local_dns.total} enabled</span></p>
      </div>
    </div>
    <p class="hint scope-note">
      This Dashboard shows what the Go control plane currently owns (Blocklists, Local DNS). Query
      activity, live DNS Activity, upstreams, and clients are not migrated yet -- see the parity
      matrix.
    </p>
  {/if}
</section>

<style>
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .cards { display: flex; flex-wrap: wrap; gap: 1rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); min-width: 12rem; }
  .card h3 { margin: 0 0 0.4rem; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; opacity: 0.75; }
  .big { margin: 0; font-size: 1.9rem; font-weight: 700; }
  .of { font-size: 1rem; font-weight: 400; opacity: 0.7; }
  .badge { display: inline-block; margin-top: 0.5rem; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.78rem; }
  .badge-attention { background: var(--badge-danger-bg); color: var(--badge-danger-fg); font-weight: 600; }
  .scope-note { margin-top: 1.25rem; max-width: 34rem; }
</style>
