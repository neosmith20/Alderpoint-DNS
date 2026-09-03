<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type Subscription, type IntervalPreset, type DNSRuntimeApplyResult, type BlocklistCategory } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";
  import DataGrid from "./DataGrid.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";
  import type { Column } from "./datagrid";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";
  import Modal from "./ui/Modal.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";

  let subs = $state<Subscription[]>([]);
  let presets = $state<IntervalPreset[]>([]);
  let defaultInterval = $state(0);
  let loadError = $state("");
  let pendingDelete = $state<Set<string>>(new Set());
  let pendingRefresh = $state<Set<string>>(new Set());
  let jobPollers = $state<Record<string, string>>({}); // subscription_id -> job state

  let search = $state("");
  const filteredSubs = $derived(
    search.trim() ? subs.filter((s) => s.name.toLowerCase().includes(search.trim().toLowerCase()) || s.url.toLowerCase().includes(search.trim().toLowerCase())) : subs,
  );

  // No real backend capability exists yet to fetch/preview a candidate
  // blocklist URL before saving it (no "Validate/Test Source" endpoint) --
  // Add Blocklist below discloses that rather than faking a check.
  let addModalOpen = $state(false);
  let newName = $state("");
  let newUrl = $state("");
  let newCategory = $state("");
  let newEnableImmediately = $state(true);
  let addBusy = $state(false);
  let addError = $state("");

  // Custom Category create/rename/delete -- previously `category` on
  // blocklist_subscriptions was just a free-text column with three
  // hardcoded UI options, no real category entity an owner could
  // create, rename, or delete. See internal/blocklists/categories.go.
  let categories = $state<BlocklistCategory[]>([]);
  let categoriesModalOpen = $state(false);
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

  let confirmDeleteCategory = $state<BlocklistCategory | null>(null);

  function deleteCategory(cat: BlocklistCategory) {
    confirmDeleteCategory = cat;
  }

  async function runDeleteCategory() {
    const cat = confirmDeleteCategory;
    confirmDeleteCategory = null;
    if (!cat) return;
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
      const resp = await api.listBlocklists(router.signal());
      if (!guard.isCurrent(token)) return;
      subs = resp.subscriptions;
      presets = resp.settings.interval_presets;
      defaultInterval = resp.settings.default_interval_seconds;
      loadError = "";
    } catch (err) {
      if (!guard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof Error ? err.message : String(err);
    }
  }

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
      if (!newEnableImmediately) await api.toggleBlocklist(created.subscription_id);
      newName = "";
      newUrl = "";
      addModalOpen = false;
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

  let confirmDeleteSub = $state<Subscription | null>(null);
  function onDelete(sub: Subscription) {
    confirmDeleteSub = sub;
  }
  async function runDeleteSub() {
    const sub = confirmDeleteSub;
    confirmDeleteSub = null;
    if (!sub) return;
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

  // Header summary: the most recent attempt across every subscription,
  // and whether anything currently needs attention -- real, from the
  // same rows the table itself renders.
  const lastGlobalUpdate = $derived.by(() => {
    const attempts = subs.map((s) => s.last_refresh_at).filter((v): v is string => !!v);
    if (attempts.length === 0) return null;
    return attempts.reduce((a, b) => (new Date(a) > new Date(b) ? a : b));
  });
  const attentionCount = $derived(subs.filter((s) => s.attention_required).length);

  const columns: Column<Subscription>[] = [
    { key: "enabled", label: "Enabled", sortValue: (s) => (s.enabled ? 1 : 0), minWidth: 8 },
    { key: "name", label: "Name", sortValue: (s) => s.name.toLowerCase(), minWidth: 14 },
    { key: "url", label: "Source", minWidth: 18 },
    { key: "entries", label: "Rule count", sortValue: (s) => s.rule_count ?? -1, minWidth: 8 },
    { key: "last_success", label: "Last successful update", sortValue: (s) => (s.last_success_at ? new Date(s.last_success_at).getTime() : 0), minWidth: 14 },
    { key: "last_attempt", label: "Last attempted update", sortValue: (s) => (s.last_refresh_at ? new Date(s.last_refresh_at).getTime() : 0), minWidth: 14 },
    { key: "interval", label: "Update schedule", minWidth: 12 },
    { key: "status", label: "Health", sortValue: (s) => (s.attention_required ? 0 : s.last_status === "ok" ? 2 : 1), minWidth: 10 },
    { key: "actions", label: "Actions", minWidth: 18 },
  ];

  function rowClass(sub: Subscription): string {
    const classes: string[] = [];
    if (pendingDelete.has(sub.subscription_id)) classes.push("row-pending");
    if (sub.attention_required) classes.push("row-attention");
    return classes.join(" ");
  }
</script>

<PageHeader headingId="blocklists-heading" title="Blocklists" description="Domain lists this appliance blocks against, updated on their own schedule.">
  {#snippet actions()}
    <button type="button" onclick={() => { addError = ""; addModalOpen = true; }} disabled={categories.length === 0}>Add Blocklist</button>
    <button type="button" class="secondary" onclick={onRefreshAll} disabled={subs.every((s) => !s.enabled)}>Update All</button>
    <button type="button" class="secondary" onclick={() => (categoriesModalOpen = true)}>Manage Categories</button>
  {/snippet}
</PageHeader>

<p class="hint status-line">
  {#if lastGlobalUpdate}Last global update attempt: {timestampPref.format(lastGlobalUpdate)}.{:else}No blocklist has been updated yet.{/if}
  {#if attentionCount > 0}<span class="attention-inline">{attentionCount} list{attentionCount === 1 ? "" : "s"} need attention.</span>{/if}
</p>

<div class="toolbar">
  <input class="search-input" placeholder="Search name or source URL…" bind:value={search} aria-label="Search blocklists" />
</div>

{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
<DnsRuntimeBadge result={dnsRuntimeResult} />

<DataGrid gridId="blocklist-subscriptions" {columns} rows={filteredSubs} rowKey={(s) => s.subscription_id} {rowClass} emptyMessage={subs.length === 0 ? "No blocklist subscriptions yet." : "No blocklists match this search."}>
  {#snippet cell(sub, colKey)}
    {#if colKey === "enabled"}
      <button type="button" class="toggle-btn" onclick={() => onToggle(sub)} aria-pressed={sub.enabled}>
        <StatusBadge label={sub.enabled ? "Enabled" : "Disabled"} tone={sub.enabled ? "healthy" : "neutral"} />
      </button>
    {:else if colKey === "name"}
      {sub.name}
      <p class="hint category-line">{sub.category}</p>
    {:else if colKey === "url"}
      <span class="mono url-cell" title={sub.url}>{sub.url}</span>
    {:else if colKey === "entries"}
      {sub.rule_count ?? "—"}
    {:else if colKey === "last_success"}
      {sub.last_success_at ? timestampPref.format(sub.last_success_at) : "Never"}
    {:else if colKey === "last_attempt"}
      {sub.last_refresh_at ? timestampPref.format(sub.last_refresh_at) : "Never"}
    {:else if colKey === "interval"}
      <select value={sub.update_interval_seconds ?? -1} onchange={(e) => onSetInterval(sub, Number((e.target as HTMLSelectElement).value))} aria-label={`Update schedule for ${sub.name}`}>
        <option value={-1}>Default ({fmtInterval(sub)})</option>
        {#each presets as p}<option value={p.seconds}>{p.label}</option>{/each}
      </select>
    {:else if colKey === "status"}
      {#if sub.attention_required}
        <StatusBadge label={`Needs attention (${sub.failure_count})`} tone="danger" />
      {:else if sub.last_status === "ok"}
        <StatusBadge label="Healthy" tone="healthy" />
      {:else if sub.last_status === "error"}
        <StatusBadge label="1 failure" tone="warning" />
      {:else}
        <StatusBadge label="Never run" tone="neutral" />
      {/if}
    {:else if colKey === "actions"}
      <div class="actions">
        <button type="button" class="secondary small" onclick={() => onRefreshOne(sub)} disabled={pendingRefresh.has(sub.subscription_id) || sub.update_in_progress} aria-busy={pendingRefresh.has(sub.subscription_id)}>
          {pendingRefresh.has(sub.subscription_id) || sub.update_in_progress ? "Updating…" : "Update Now"}
        </button>
        <button type="button" class="secondary small danger" onclick={() => onDelete(sub)} disabled={pendingDelete.has(sub.subscription_id)} aria-busy={pendingDelete.has(sub.subscription_id)}>
          {pendingDelete.has(sub.subscription_id) ? "Deleting…" : "Delete"}
        </button>
      </div>
      {#if jobPollers[sub.subscription_id]}<p class="hint job-line">Job: {jobPollers[sub.subscription_id]}</p>{/if}
    {/if}
  {/snippet}
</DataGrid>

{#if addModalOpen}
  <Modal title="Add Blocklist" onClose={() => (addModalOpen = false)}>
    <form onsubmit={addSubscription} class="modal-form">
      <label>Name <input required bind:value={newName} /></label>
      <label>URL / path <input required bind:value={newUrl} type="url" placeholder="https://…" /></label>
      <label>
        Category
        <select bind:value={newCategory} required>
          {#each categories as cat (cat.id)}<option value={cat.name}>{cat.name}</option>{/each}
        </select>
      </label>
      <label class="checkbox-label"><input type="checkbox" bind:checked={newEnableImmediately} /> Enable immediately</label>
      <p class="hint">
        There is no automated "Validate/Test Source" check for a candidate URL yet -- this appliance
        will fetch and parse it for real the first time it updates, right after you save.
      </p>
      <div class="form-actions">
        <button type="submit" disabled={addBusy}>{addBusy ? "Adding…" : "Add Blocklist"}</button>
        <button type="button" class="secondary" onclick={() => (addModalOpen = false)}>Cancel</button>
      </div>
      {#if addError}<p class="error" role="alert">{addError}</p>{/if}
    </form>
  </Modal>
{/if}

{#if categoriesModalOpen}
  <Modal title="Manage Categories" onClose={() => (categoriesModalOpen = false)}>
    {#if categoryError}<p class="error" role="alert">{categoryError}</p>{/if}
    <ul class="category-list">
      {#each categories as cat (cat.id)}
        <li>
          {#if renamingCategoryId === cat.id}
            <input bind:value={renameCategoryName} aria-label={`Rename category ${cat.name}`} />
            <button type="button" class="secondary small" onclick={commitRenameCategory} disabled={categoryBusy}>Save</button>
            <button type="button" class="secondary small" onclick={() => (renamingCategoryId = null)} disabled={categoryBusy}>Cancel</button>
          {:else}
            <span>{cat.name}</span>
            <button type="button" class="secondary small" onclick={() => startRenameCategory(cat)} disabled={categoryBusy}>Rename</button>
            <button type="button" class="secondary small danger" onclick={() => deleteCategory(cat)} disabled={categoryBusy}>Delete</button>
          {/if}
        </li>
      {/each}
    </ul>
    <form onsubmit={addCategory} class="add-category-form">
      <input required bind:value={newCategoryName} placeholder="New category name" aria-label="New category name" />
      <button type="submit" disabled={categoryBusy}>{categoryBusy ? "Adding…" : "Add category"}</button>
    </form>
  </Modal>
{/if}

{#if confirmDeleteCategory}
  <ConfirmDialog
    title="Delete category"
    message={`Delete the category "${confirmDeleteCategory.name}"? Subscriptions in it are not deleted, but lose this grouping.`}
    confirmLabel="Delete"
    onConfirm={runDeleteCategory}
    onCancel={() => (confirmDeleteCategory = null)}
  />
{/if}

{#if confirmDeleteSub}
  <ConfirmDialog
    title="Delete blocklist"
    message={`Delete the blocklist subscription "${confirmDeleteSub.name}"? Its rules stop being enforced as soon as this takes effect on the live DNS runtime.`}
    confirmLabel="Delete"
    onConfirm={runDeleteSub}
    onCancel={() => (confirmDeleteSub = null)}
  />
{/if}

<style>
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .status-line { margin: -0.25rem 0 0.75rem; }
  .attention-inline { color: var(--warning); font-weight: 600; margin-left: 0.5rem; }
  .toolbar { display: flex; flex-wrap: wrap; gap: 0.6rem; margin-bottom: 0.75rem; }
  .search-input { min-width: 16rem; flex: 1 1 16rem; }
  .toggle-btn { background: transparent; border: none; padding: 0; min-height: auto; cursor: pointer; }
  .category-line { margin: 0.1rem 0 0; }
  .url-cell { display: inline-block; max-width: 22rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
  .mono { font-family: monospace; font-size: 0.82rem; }
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
  .job-line { margin: 0.3rem 0 0; }
  .error { color: var(--danger); }
  .danger { color: var(--danger); }
  button.secondary.small { min-height: auto; padding: 0.3rem 0.6rem; font-size: 0.8rem; }

  .modal-form { display: flex; flex-direction: column; gap: 0.75rem; }
  .modal-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .checkbox-label { flex-direction: row !important; align-items: center; gap: 0.5rem !important; }
  .form-actions { display: flex; gap: 0.5rem; }

  .category-list { list-style: none; margin: 0 0 1rem; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
  .category-list li { display: flex; align-items: center; gap: 0.5rem; }
  .add-category-form { display: flex; gap: 0.5rem; }
</style>
