<script lang="ts">
  import { onMount } from "svelte";
  import { api, type Subscription, type IntervalPreset, type DNSRuntimeApplyResult, type BlocklistCategory } from "../api";
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

  // Allowlists: the exact same fetch/parse/schedule/category pipeline
  // Blocklists uses (internal/blocklists), on the exact same table --
  // distinguished only by list_type=="allow" (migration 0029). A domain
  // on an enabled allowlist always wins over the same domain appearing
  // on a blocklist or in a blocked category, full stop -- there is no
  // scenario where a blocklist can override it.

  let subs = $state<Subscription[]>([]);
  let presets = $state<IntervalPreset[]>([]);
  let loadError = $state("");
  let pendingDelete = $state<Set<string>>(new Set());
  let pendingRefresh = $state<Set<string>>(new Set());
  let jobPollers = $state<Record<string, string>>({});

  let search = $state("");
  const filteredSubs = $derived(
    search.trim() ? subs.filter((s) => s.name.toLowerCase().includes(search.trim().toLowerCase()) || s.url.toLowerCase().includes(search.trim().toLowerCase())) : subs,
  );

  let addModalOpen = $state(false);
  let newName = $state("");
  let newUrl = $state("");
  let newCategory = $state("");
  let newEnableImmediately = $state(true);
  let addBusy = $state(false);
  let addError = $state("");

  let categories = $state<BlocklistCategory[]>([]);
  async function refreshCategories() {
    try {
      const resp = await api.listBlocklistCategories(router.signal());
      categories = resp.categories;
      if (!newCategory && categories.length > 0) newCategory = categories[0].name;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
    }
  }

  const guard = new StaleGuard();
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);

  export async function refresh(): Promise<void> {
    const token = guard.start();
    try {
      const resp = await api.listBlocklists(router.signal());
      if (!guard.isCurrent(token)) return;
      subs = resp.subscriptions.filter((s) => s.list_type === "allow");
      presets = resp.settings.interval_presets;
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
      const created = await api.createBlocklist(newName, newUrl, newCategory, "allow");
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
    // Real, but not scoped to just allowlists -- there is no
    // allow-only "refresh all" endpoint, only a global one. Refreshing
    // a couple of extra (blocklist) subscriptions along with these is
    // harmless, never incorrect.
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

<PageHeader headingId="allowlists-heading" title="Allowlists" description="Domain lists this appliance always permits, updated on their own schedule.">
  {#snippet actions()}
    <button type="button" onclick={() => { addError = ""; addModalOpen = true; }} disabled={categories.length === 0}>Add Allowlist</button>
    <button type="button" class="secondary" onclick={onRefreshAll} disabled={subs.every((s) => !s.enabled)}>Update All</button>
  {/snippet}
</PageHeader>

<p class="hint precedence-note">
  A domain here is never blocked, no matter what else is configured -- an allowlist entry always
  beats the same domain appearing on a blocklist or in a blocked category. Use this for a
  legitimate domain a blocklist blocks by mistake, not as a general filtering off-switch.
</p>

<p class="hint status-line">
  {#if lastGlobalUpdate}Last global update attempt: {timestampPref.format(lastGlobalUpdate)}.{:else}No allowlist has been updated yet.{/if}
  {#if attentionCount > 0}<span class="attention-inline">{attentionCount} list{attentionCount === 1 ? "" : "s"} need attention.</span>{/if}
</p>

<div class="toolbar">
  <input class="search-input" placeholder="Search name or source URL…" bind:value={search} aria-label="Search allowlists" />
</div>

{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
<DnsRuntimeBadge result={dnsRuntimeResult} />

<DataGrid gridId="allowlist-subscriptions" {columns} rows={filteredSubs} rowKey={(s) => s.subscription_id} {rowClass} emptyMessage={subs.length === 0 ? "No allowlist subscriptions yet." : "No allowlists match this search."}>
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
  <Modal title="Add Allowlist" onClose={() => (addModalOpen = false)}>
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
        <button type="submit" disabled={addBusy}>{addBusy ? "Adding…" : "Add Allowlist"}</button>
        <button type="button" class="secondary" onclick={() => (addModalOpen = false)}>Cancel</button>
      </div>
      {#if addError}<p class="error" role="alert">{addError}</p>{/if}
    </form>
  </Modal>
{/if}

{#if confirmDeleteSub}
  <ConfirmDialog
    title="Delete allowlist"
    message={`Delete the allowlist subscription "${confirmDeleteSub.name}"? Domains only permitted by it may become blocked again as soon as this takes effect on the live DNS runtime, if a blocklist also covers them.`}
    confirmLabel="Delete"
    onConfirm={runDeleteSub}
    onCancel={() => (confirmDeleteSub = null)}
  />
{/if}

<style>
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .precedence-note { margin: -0.25rem 0 0.5rem; max-width: 52rem; }
  .status-line { margin: 0 0 0.75rem; }
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
</style>
