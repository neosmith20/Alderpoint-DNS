<script lang="ts">
  import { onMount } from "svelte";
  import { api, type Subscription, type IntervalPreset } from "../api";
  import { StaleGuard } from "../staleGuard";

  let subs = $state<Subscription[]>([]);
  let presets = $state<IntervalPreset[]>([]);
  let defaultInterval = $state(0);
  let loadError = $state("");
  let pendingDelete = $state<Set<string>>(new Set());
  let pendingRefresh = $state<Set<string>>(new Set());
  let jobPollers = $state<Record<string, string>>({}); // subscription_id -> job state

  let newName = $state("");
  let newUrl = $state("");
  let newCategory = $state("standard");
  let addBusy = $state(false);
  let addError = $state("");

  const guard = new StaleGuard();

  export async function refresh(): Promise<void> {
    const token = guard.start();
    try {
      const resp = await api.listBlocklists();
      if (!guard.isCurrent(token)) return; // a newer refresh already landed; discard this stale one
      subs = resp.subscriptions;
      presets = resp.settings.interval_presets;
      defaultInterval = resp.settings.default_interval_seconds;
      loadError = "";
    } catch (err) {
      if (!guard.isCurrent(token)) return;
      loadError = err instanceof Error ? err.message : String(err);
    }
  }

  // Loaded on demand by RouteLoader when this page is routed to -- own our
  // own initial data fetch rather than relying on the shell to know we
  // need one (RouteLoader is generic across every future page).
  onMount(() => {
    refresh();
  });

  async function pollJob(subscriptionId: string, jobId: number) {
    for (let i = 0; i < 120; i++) {
      try {
        const j = await api.getJob(jobId);
        jobPollers = { ...jobPollers, [subscriptionId]: j.state };
        if (j.state === "succeeded" || j.state === "failed") {
          await refresh();
          break;
        }
      } catch {
        break;
      }
      await new Promise((r) => setTimeout(r, 400));
    }
  }

  async function addSubscription(e: Event) {
    e.preventDefault();
    addError = "";
    addBusy = true;
    try {
      const created = await api.createBlocklist(newName, newUrl, newCategory);
      newName = "";
      newUrl = "";
      await refresh();
      jobPollers = { ...jobPollers, [created.subscription_id]: "queued" };
      pollJob(created.subscription_id, created.job_id);
    } catch (err) {
      addError = err instanceof Error ? err.message : String(err);
    } finally {
      addBusy = false;
    }
  }

  async function onSetInterval(sub: Subscription, seconds: number) {
    await api.setInterval(sub.subscription_id, seconds);
    await refresh();
  }

  async function onToggle(sub: Subscription) {
    await api.toggleBlocklist(sub.subscription_id);
    await refresh();
  }

  async function onRefreshOne(sub: Subscription) {
    pendingRefresh = new Set(pendingRefresh).add(sub.subscription_id);
    try {
      const { job_id } = await api.refreshOne(sub.subscription_id);
      jobPollers = { ...jobPollers, [sub.subscription_id]: "queued" };
      await pollJob(sub.subscription_id, job_id);
    } catch (err) {
      loadError = err instanceof Error ? err.message : String(err);
    } finally {
      const next = new Set(pendingRefresh);
      next.delete(sub.subscription_id);
      pendingRefresh = next;
    }
  }

  async function onRefreshAll() {
    const { job_id } = await api.refreshAll();
    if (job_id) await refresh();
  }

  async function onDelete(sub: Subscription) {
    pendingDelete = new Set(pendingDelete).add(sub.subscription_id);
    try {
      await api.deleteBlocklist(sub.subscription_id);
      await refresh();
    } catch (err) {
      loadError = err instanceof Error ? err.message : String(err);
    } finally {
      const next = new Set(pendingDelete);
      next.delete(sub.subscription_id);
      pendingDelete = next;
    }
  }

  function fmtInterval(sub: Subscription): string {
    const preset = presets.find((p) => p.seconds === sub.effective_interval_seconds);
    return preset?.label ?? `${sub.effective_interval_seconds}s`;
  }
</script>

<section aria-labelledby="blocklists-heading">
  <div class="section-header">
    <h2 id="blocklists-heading">Blocklists</h2>
    <button onclick={onRefreshAll} disabled={subs.every((s) => !s.enabled)}>Update All</button>
  </div>

  <form onsubmit={addSubscription} class="add-form">
    <label>Name <input required bind:value={newName} /></label>
    <label>URL <input required bind:value={newUrl} type="url" /></label>
    <label>
      Category
      <select bind:value={newCategory}>
        <option>standard</option>
        <option>privacy</option>
        <option>aggressive</option>
      </select>
    </label>
    <button type="submit" disabled={addBusy}>{addBusy ? "Adding…" : "Add subscription"}</button>
    {#if addError}<p class="error" role="alert">{addError}</p>{/if}
  </form>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <div class="table-scroll">
    <table aria-label="Blocklist subscriptions">
      <thead>
        <tr>
          <th>Name</th><th>Status</th><th>Entries</th><th>Interval</th><th>Job</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each subs as sub (sub.subscription_id)}
          <tr class:pending={pendingDelete.has(sub.subscription_id)} class:attention={sub.attention_required}>
            <td>{sub.name}</td>
            <td>
              {#if sub.attention_required}
                <span class="badge badge-attention" role="status">Needs attention ({sub.failure_count} failures)</span>
              {:else if sub.last_status === "ok"}
                <span class="badge badge-ok">OK</span>
              {:else if sub.last_status === "error"}
                <span class="badge badge-warn">1 failure</span>
              {:else}
                <span>never run</span>
              {/if}
            </td>
            <td>{sub.rule_count ?? "-"}</td>
            <td>
              <select value={sub.update_interval_seconds ?? -1} onchange={(e) => onSetInterval(sub, Number((e.target as HTMLSelectElement).value))}>
                <option value={-1}>Default ({fmtInterval(sub)})</option>
                {#each presets as p}
                  <option value={p.seconds}>{p.label}</option>
                {/each}
              </select>
            </td>
            <td>{jobPollers[sub.subscription_id] ?? "-"}</td>
            <td class="actions">
              <button onclick={() => onToggle(sub)}>{sub.enabled ? "Disable" : "Enable"}</button>
              <button onclick={() => onRefreshOne(sub)} disabled={pendingRefresh.has(sub.subscription_id) || sub.update_in_progress} aria-busy={pendingRefresh.has(sub.subscription_id)}>
                {pendingRefresh.has(sub.subscription_id) || sub.update_in_progress ? "Updating…" : "Update Now"}
              </button>
              <button onclick={() => onDelete(sub)} disabled={pendingDelete.has(sub.subscription_id)} aria-busy={pendingDelete.has(sub.subscription_id)}>
                {pendingDelete.has(sub.subscription_id) ? "Deleting…" : "Delete"}
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<style>
  .section-header { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
  .table-scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border); white-space: nowrap; }
  tr.pending { opacity: 0.5; }
  tr.attention { background: var(--attention-bg); }
  .actions { display: flex; gap: 0.4rem; }
  .badge { padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.78rem; }
  .badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .badge-warn { background: var(--badge-warn-bg); color: var(--badge-warn-fg); }
  .badge-attention { background: var(--badge-danger-bg); color: var(--badge-danger-fg); font-weight: 600; }
</style>
