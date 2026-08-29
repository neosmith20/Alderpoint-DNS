<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type Subscription, type IntervalPreset, type DNSRuntimeApplyResult, type BlocklistCategory } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import DataGrid from "./DataGrid.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";
  import type { Column } from "./datagrid";

  let subs = $state<Subscription[]>([]);
  let presets = $state<IntervalPreset[]>([]);
  let defaultInterval = $state(0);
  let loadError = $state("");
  let pendingDelete = $state<Set<string>>(new Set());
  let pendingRefresh = $state<Set<string>>(new Set());
  let jobPollers = $state<Record<string, string>>({}); // subscription_id -> job state

  let newName = $state("");
  let newUrl = $state("");
  let newCategory = $state("");
  let addBusy = $state(false);
  let addError = $state("");

  // Custom Category create/rename/delete -- previously `category` on
  // blocklist_subscriptions was just a free-text column with three
  // hardcoded UI options, no real category entity an owner could
  // create, rename, or delete. See internal/blocklists/categories.go.
  let categories = $state<BlocklistCategory[]>([]);
  let categoriesOpen = $state(false);
  let newCategoryName = $state("");
  let categoryBusy = $state(false);
  let categoryError = $state("");
  let renamingCategoryId = $state<number | null>(null);
  let renameCategoryName = $state("");

  async function refreshCategories() {
    try {
      const resp = await api.listBlocklistCategories(router.signal());
      categories = resp.categories;
      if (!newCategory && categories.length > 0) newCategory = categories[0].name;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      categoryError = err instanceof ApiError ? err.message : String(err);
    }
  }

  async function addCategory(e: Event) {
    e.preventDefault();
    categoryError = "";
    categoryBusy = true;
    try {
      await api.createBlocklistCategory(newCategoryName);
      newCategoryName = "";
      await refreshCategories();
    } catch (err) {
      categoryError = err instanceof ApiError ? err.message : String(err);
    } finally {
      categoryBusy = false;
    }
  }

  function startRenameCategory(cat: BlocklistCategory) {
    renamingCategoryId = cat.id;
    renameCategoryName = cat.name;
  }

  async function commitRenameCategory() {
    if (renamingCategoryId === null) return;
    categoryError = "";
    categoryBusy = true;
    try {
      await api.renameBlocklistCategory(renamingCategoryId, renameCategoryName);
      renamingCategoryId = null;
      await refreshCategories();
      await refresh();
    } catch (err) {
      categoryError = err instanceof ApiError ? err.message : String(err);
    } finally {
      categoryBusy = false;
    }
  }

  async function deleteCategory(cat: BlocklistCategory) {
    categoryError = "";
    categoryBusy = true;
    try {
      await api.deleteBlocklistCategory(cat.id);
      await refreshCategories();
    } catch (err) {
      categoryError = err instanceof ApiError ? err.message : String(err);
    } finally {
      categoryBusy = false;
    }
  }

  const guard = new StaleGuard();
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);

  export async function refresh(): Promise<void> {
    const token = guard.start();
    try {
      // router.signal() ties this request to the current navigation: if the
      // operator routes away before it resolves, the fetch itself is
      // aborted (not just discarded client-side) -- no background network
      // work continues off-route.
      const resp = await api.listBlocklists(router.signal());
      if (!guard.isCurrent(token)) return; // a newer refresh already landed; discard this stale one
      subs = resp.subscriptions;
      presets = resp.settings.interval_presets;
      defaultInterval = resp.settings.default_interval_seconds;
      loadError = "";
    } catch (err) {
      if (!guard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return; // navigated away; not a real error
      loadError = err instanceof Error ? err.message : String(err);
    }
  }

  // Loaded on demand by RouteLoader when this page is routed to -- own our
  // own initial data fetch rather than relying on the shell to know we
  // need one (RouteLoader is generic across every future page).
  onMount(() => {
    refresh();
    refreshCategories();
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
    const resp = await api.toggleBlocklist(sub.subscription_id);
    dnsRuntimeResult = resp.dns_runtime ?? null;
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
      const resp = await api.deleteBlocklist(sub.subscription_id);
      dnsRuntimeResult = resp.dns_runtime ?? null;
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

  const columns: Column<Subscription>[] = [
    { key: "name", label: "Name", sortValue: (s) => s.name.toLowerCase(), minWidth: 14 },
    { key: "status", label: "Status", sortValue: (s) => (s.attention_required ? 0 : s.last_status === "ok" ? 2 : 1) },
    { key: "entries", label: "Entries", sortValue: (s) => s.rule_count ?? -1 },
    { key: "interval", label: "Interval", minWidth: 12 },
    { key: "job", label: "Job", minWidth: 8 },
    { key: "actions", label: "Actions", minWidth: 20 },
  ];

  function rowClass(sub: Subscription): string {
    const classes: string[] = [];
    if (pendingDelete.has(sub.subscription_id)) classes.push("row-pending");
    if (sub.attention_required) classes.push("row-attention");
    return classes.join(" ");
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
      <select bind:value={newCategory} required>
        {#each categories as cat (cat.id)}
          <option value={cat.name}>{cat.name}</option>
        {/each}
      </select>
    </label>
    <button type="submit" disabled={addBusy || categories.length === 0}>{addBusy ? "Adding…" : "Add subscription"}</button>
    <button type="button" class="link-button" onclick={() => (categoriesOpen = !categoriesOpen)}>
      {categoriesOpen ? "Hide categories" : "Manage categories"}
    </button>
    {#if addError}<p class="error" role="alert">{addError}</p>{/if}
  </form>

  {#if categoriesOpen}
    <div class="card categories-card">
      <h3>Categories</h3>
      {#if categoryError}<p class="error" role="alert">{categoryError}</p>{/if}
      <ul class="category-list">
        {#each categories as cat (cat.id)}
          <li>
            {#if renamingCategoryId === cat.id}
              <input bind:value={renameCategoryName} aria-label={`Rename category ${cat.name}`} />
              <button onclick={commitRenameCategory} disabled={categoryBusy}>Save</button>
              <button onclick={() => (renamingCategoryId = null)} disabled={categoryBusy}>Cancel</button>
            {:else}
              <span>{cat.name}</span>
              <button onclick={() => startRenameCategory(cat)} disabled={categoryBusy}>Rename</button>
              <button onclick={() => deleteCategory(cat)} disabled={categoryBusy}>Delete</button>
            {/if}
          </li>
        {/each}
      </ul>
      <form onsubmit={addCategory} class="add-category-form">
        <input required bind:value={newCategoryName} placeholder="New category name" aria-label="New category name" />
        <button type="submit" disabled={categoryBusy}>{categoryBusy ? "Adding…" : "Add category"}</button>
      </form>
    </div>
  {/if}

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
  <DnsRuntimeBadge result={dnsRuntimeResult} />

  <DataGrid gridId="blocklist-subscriptions" {columns} rows={subs} rowKey={(s) => s.subscription_id} {rowClass} emptyMessage="No blocklist subscriptions yet.">
    {#snippet cell(sub, colKey)}
      {#if colKey === "name"}
        {sub.name}
      {:else if colKey === "status"}
        {#if sub.attention_required}
          <span class="badge badge-attention" role="status">Needs attention ({sub.failure_count} failures)</span>
        {:else if sub.last_status === "ok"}
          <span class="badge badge-ok">OK</span>
        {:else if sub.last_status === "error"}
          <span class="badge badge-warn">1 failure</span>
        {:else}
          <span>never run</span>
        {/if}
      {:else if colKey === "entries"}
        {sub.rule_count ?? "-"}
      {:else if colKey === "interval"}
        <select value={sub.update_interval_seconds ?? -1} onchange={(e) => onSetInterval(sub, Number((e.target as HTMLSelectElement).value))}>
          <option value={-1}>Default ({fmtInterval(sub)})</option>
          {#each presets as p}
            <option value={p.seconds}>{p.label}</option>
          {/each}
        </select>
      {:else if colKey === "job"}
        {jobPollers[sub.subscription_id] ?? "-"}
      {:else if colKey === "actions"}
        <div class="actions">
          <button onclick={() => onToggle(sub)}>{sub.enabled ? "Disable" : "Enable"}</button>
          <button onclick={() => onRefreshOne(sub)} disabled={pendingRefresh.has(sub.subscription_id) || sub.update_in_progress} aria-busy={pendingRefresh.has(sub.subscription_id)}>
            {pendingRefresh.has(sub.subscription_id) || sub.update_in_progress ? "Updating…" : "Update Now"}
          </button>
          <button onclick={() => onDelete(sub)} disabled={pendingDelete.has(sub.subscription_id)} aria-busy={pendingDelete.has(sub.subscription_id)}>
            {pendingDelete.has(sub.subscription_id) ? "Deleting…" : "Delete"}
          </button>
        </div>
      {/if}
    {/snippet}
  </DataGrid>
</section>

<style>
  .section-header { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
  .badge { padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.78rem; }
  .badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .badge-warn { background: var(--badge-warn-bg); color: var(--badge-warn-fg); }
  .badge-attention { background: var(--badge-danger-bg); color: var(--badge-danger-fg); font-weight: 600; }
  .link-button { background: none; border: none; color: var(--link, #2563eb); cursor: pointer; padding: 0; text-decoration: underline; align-self: flex-end; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; }
  .categories-card h3 { margin: 0; }
  .category-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
  .category-list li { display: flex; align-items: center; gap: 0.5rem; }
  .add-category-form { display: flex; gap: 0.5rem; }
</style>
