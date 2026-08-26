<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, EMPTY_POLICY_LAYER, type CustomRule } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";
  import PolicyEditor from "./PolicyEditor.svelte";

  // Filters page: Custom Filtering Rules (native Go, new functionality --
  // see internal/customrules's doc comment for why: Python V2 has no
  // custom-rules API at all, only V1's free-text AdGuard-syntax parser,
  // which this structured "modern rule builder" deliberately does not
  // replicate) plus the Global Answer Policy editor (shared PolicyEditor,
  // same component ClientsView uses for per-client/group policy).

  let rules = $state<CustomRule[]>([]);
  let loadError = $state("");
  const guard = new StaleGuard();

  let globalPolicy = $state(EMPTY_POLICY_LAYER);

  let ruleType = $state<CustomRule["rule_type"]>("block");
  let pattern = $state("");
  let rewriteTarget = $state("");
  let addBusy = $state(false);
  let addError = $state("");

  let editingId = $state<number | null>(null);
  let editPattern = $state("");
  let editRewriteTarget = $state("");

  let selected = $state<Set<number>>(new Set());

  async function refresh() {
    const token = guard.start();
    try {
      const [r, p] = await Promise.all([api.listCustomRules(router.signal()), api.getGlobalPolicy(router.signal())]);
      if (!guard.isCurrent(token)) return;
      rules = r.rules;
      globalPolicy = p;
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

  async function addRule(e: Event) {
    e.preventDefault();
    addError = "";
    addBusy = true;
    try {
      await api.createCustomRule(ruleType, pattern, ruleType === "rewrite" ? rewriteTarget : null);
      pattern = "";
      rewriteTarget = "";
      await refresh();
    } catch (err) {
      addError = err instanceof ApiError ? err.message : String(err);
    } finally {
      addBusy = false;
    }
  }

  function startEdit(r: CustomRule) {
    editingId = r.id;
    editPattern = r.pattern;
    editRewriteTarget = r.rewrite_target ?? "";
  }

  async function saveEdit(r: CustomRule) {
    await api.updateCustomRule(r.id, r.rule_type, editPattern, r.rule_type === "rewrite" ? editRewriteTarget : null);
    editingId = null;
    await refresh();
  }

  async function toggleRule(r: CustomRule) {
    await api.toggleCustomRule(r.id, !r.enabled);
    await refresh();
  }

  async function deleteRule(r: CustomRule) {
    await api.deleteCustomRule(r.id);
    await refresh();
  }

  function toggleSelected(id: number) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    selected = next;
  }

  async function bulkEnable() {
    await api.bulkEnableCustomRules([...selected]);
    selected = new Set();
    await refresh();
  }
  async function bulkDisable() {
    await api.bulkDisableCustomRules([...selected]);
    selected = new Set();
    await refresh();
  }
  async function bulkDelete() {
    await api.bulkDeleteCustomRules([...selected]);
    selected = new Set();
    await refresh();
  }

  async function move(r: CustomRule, dir: -1 | 1) {
    const ids = rules.map((x) => x.id);
    const i = ids.indexOf(r.id);
    const j = i + dir;
    if (j < 0 || j >= ids.length) return;
    [ids[i], ids[j]] = [ids[j], ids[i]];
    await api.reorderCustomRules(ids);
    await refresh();
  }

  const columns: Column<CustomRule>[] = [
    { key: "select", label: "", minWidth: 3 },
    { key: "priority", label: "#", sortValue: (r) => r.priority, minWidth: 4 },
    { key: "rule_type", label: "Type", sortValue: (r) => r.rule_type, minWidth: 10 },
    { key: "pattern", label: "Pattern", sortValue: (r) => r.pattern.toLowerCase(), minWidth: 16 },
    { key: "status", label: "Status", sortValue: (r) => (r.enabled ? 1 : 0), minWidth: 8 },
    { key: "actions", label: "Actions", minWidth: 20 },
  ];

  function rowClass(r: CustomRule): string {
    return r.enabled ? "" : "row-pending";
  }
</script>

<section aria-labelledby="filtering-heading" class="filtering">
  <h2 id="filtering-heading">Filters</h2>

  <div class="card">
    <h3>Global Answer Policy</h3>
    <PolicyEditor layer={globalPolicy} onSave={(l) => api.putGlobalPolicy(l).then(refresh)} />
  </div>

  <div class="card">
    <h3>Custom Filtering Rules</h3>
    <p class="hint">
      A structured rule builder (block / allow / regex block / regex allow / rewrite). Does not yet
      import V1's free-text AdGuard-syntax rules -- see the parity matrix.
    </p>
    {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

    <form onsubmit={addRule} class="add-form">
      <label>
        Type
        <select bind:value={ruleType}>
          <option value="block">Block</option>
          <option value="allow">Allow</option>
          <option value="regex_block">Regex block</option>
          <option value="regex_allow">Regex allow</option>
          <option value="rewrite">Rewrite</option>
        </select>
      </label>
      <label>Pattern <input required bind:value={pattern} placeholder="example.com or a regex" /></label>
      {#if ruleType === "rewrite"}
        <label>Rewrite target <input required bind:value={rewriteTarget} placeholder="10.0.0.5" /></label>
      {/if}
      <button type="submit" disabled={addBusy}>{addBusy ? "Adding…" : "Add rule"}</button>
      {#if addError}<p class="error" role="alert">{addError}</p>{/if}
    </form>

    {#if selected.size > 0}
      <div class="bulk-bar" role="toolbar" aria-label="Bulk actions">
        <span>{selected.size} selected</span>
        <button onclick={bulkEnable}>Enable</button>
        <button onclick={bulkDisable}>Disable</button>
        <button class="danger" onclick={bulkDelete}>Delete</button>
      </div>
    {/if}

    <DataGrid gridId="custom-rules" {columns} rows={rules} rowKey={(r) => r.id} {rowClass} emptyMessage="No custom rules yet.">
      {#snippet cell(r, colKey)}
        {#if colKey === "select"}
          <input type="checkbox" checked={selected.has(r.id)} onchange={() => toggleSelected(r.id)} aria-label={`Select rule ${r.pattern}`} />
        {:else if colKey === "priority"}
          {r.priority + 1}
        {:else if colKey === "rule_type"}
          {r.rule_type}
        {:else if colKey === "pattern"}
          {#if editingId === r.id}
            <input bind:value={editPattern} aria-label="Edit pattern" />
            {#if r.rule_type === "rewrite"}
              <input bind:value={editRewriteTarget} aria-label="Edit rewrite target" />
            {/if}
          {:else}
            {r.pattern}{r.rewrite_target ? ` -> ${r.rewrite_target}` : ""}
          {/if}
        {:else if colKey === "status"}
          <span class="badge" class:badge-ok={r.enabled} class:badge-warn={!r.enabled}>{r.enabled ? "Enabled" : "Disabled"}</span>
        {:else if colKey === "actions"}
          <div class="actions">
            {#if editingId === r.id}
              <button onclick={() => saveEdit(r)}>Save</button>
              <button onclick={() => (editingId = null)}>Cancel</button>
            {:else}
              <button onclick={() => startEdit(r)}>Edit</button>
              <button onclick={() => toggleRule(r)}>{r.enabled ? "Disable" : "Enable"}</button>
              <button onclick={() => deleteRule(r)}>Delete</button>
              <button onclick={() => move(r, -1)} aria-label="Move up">&uarr;</button>
              <button onclick={() => move(r, 1)} aria-label="Move down">&darr;</button>
            {/if}
          </div>
        {/if}
      {/snippet}
    </DataGrid>
  </div>
</section>

<style>
  .filtering { display: flex; flex-direction: column; gap: 1rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); }
  .card h3 { margin-top: 0; }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .add-form { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; margin: 0.75rem 0; }
  .add-form label { display: flex; flex-direction: column; font-size: 0.85rem; gap: 0.25rem; }
  .bulk-bar { display: flex; align-items: center; gap: 0.6rem; padding: 0.5rem 0.75rem; background: var(--nav-hover-bg); border-radius: 6px; margin-bottom: 0.75rem; font-size: 0.85rem; }
  .actions { display: flex; gap: 0.3rem; flex-wrap: wrap; }
  .badge { padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.78rem; }
  .badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .badge-warn { background: var(--badge-warn-bg); color: var(--badge-warn-fg); }
  .danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
</style>
