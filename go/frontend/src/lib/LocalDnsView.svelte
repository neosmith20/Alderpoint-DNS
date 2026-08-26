<script lang="ts">
  import { onMount } from "svelte";
  import { api, type LocalDnsRecord } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";

  let records = $state<LocalDnsRecord[]>([]);
  let loadError = $state("");
  let pendingDelete = $state<Set<number>>(new Set());
  let editingId = $state<number | null>(null);
  let editValue = $state("");
  let editTTL = $state(300);

  let newName = $state("");
  let newType = $state<LocalDnsRecord["record_type"]>("A");
  let newValue = $state("");
  let newTTL = $state(300);
  let addBusy = $state(false);
  let addError = $state("");

  const guard = new StaleGuard();

  export async function refresh(): Promise<void> {
    const token = guard.start();
    try {
      const resp = await api.listLocalDNS(router.signal());
      if (!guard.isCurrent(token)) return;
      records = resp.records;
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
  });

  async function addRecord(e: Event) {
    e.preventDefault();
    addError = "";
    addBusy = true;
    try {
      await api.createLocalDNS({ name: newName, record_type: newType, value: newValue, ttl: newTTL, enabled: true });
      newName = "";
      newValue = "";
      await refresh();
    } catch (err) {
      addError = err instanceof Error ? err.message : String(err);
    } finally {
      addBusy = false;
    }
  }

  function startEdit(r: LocalDnsRecord) {
    editingId = r.id;
    editValue = r.value;
    editTTL = r.ttl;
  }

  async function saveEdit(r: LocalDnsRecord) {
    await api.updateLocalDNS(r.id, { value: editValue, ttl: editTTL });
    editingId = null;
    await refresh();
  }

  async function toggleEnabled(r: LocalDnsRecord) {
    await api.updateLocalDNS(r.id, { enabled: !r.enabled });
    await refresh();
  }

  async function deleteRecord(r: LocalDnsRecord) {
    pendingDelete = new Set(pendingDelete).add(r.id);
    try {
      await api.deleteLocalDNS(r.id);
      await refresh();
    } catch (err) {
      loadError = err instanceof Error ? err.message : String(err);
    } finally {
      const next = new Set(pendingDelete);
      next.delete(r.id);
      pendingDelete = next;
    }
  }

  const columns: Column<LocalDnsRecord>[] = [
    { key: "name", label: "Name", sortValue: (r) => r.name.toLowerCase(), minWidth: 14 },
    { key: "type", label: "Type", sortValue: (r) => r.record_type, minWidth: 8 },
    { key: "value", label: "Value", minWidth: 14 },
    { key: "ttl", label: "TTL", sortValue: (r) => r.ttl, minWidth: 6 },
    { key: "enabled", label: "Enabled", sortValue: (r) => (r.enabled ? 1 : 0), minWidth: 8 },
    { key: "actions", label: "Actions", minWidth: 16 },
  ];

  function rowClass(r: LocalDnsRecord): string {
    return pendingDelete.has(r.id) ? "row-pending" : "";
  }
</script>

<section aria-labelledby="localdns-heading">
  <h2 id="localdns-heading">Local DNS</h2>

  <form onsubmit={addRecord} class="add-form">
    <label>Name <input required bind:value={newName} placeholder="host.lan" /></label>
    <label>
      Type
      <select bind:value={newType}>
        <option>A</option><option>AAAA</option><option>CNAME</option><option>PTR</option>
      </select>
    </label>
    <label>Value <input required bind:value={newValue} placeholder="10.0.0.5" /></label>
    <label>TTL <input type="number" min="1" bind:value={newTTL} /></label>
    <button type="submit" disabled={addBusy}>{addBusy ? "Adding…" : "Add record"}</button>
    {#if addError}<p class="error" role="alert">{addError}</p>{/if}
  </form>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <DataGrid gridId="local-dns-records" {columns} rows={records} rowKey={(r) => r.id} {rowClass} emptyMessage="No Local DNS records yet.">
    {#snippet cell(r, colKey)}
      {#if colKey === "name"}
        {r.name}
      {:else if colKey === "type"}
        {r.record_type}
      {:else if colKey === "value"}
        {#if editingId === r.id}
          <input bind:value={editValue} aria-label={`Edit value for ${r.name}`} />
        {:else}
          {r.value}
        {/if}
      {:else if colKey === "ttl"}
        {#if editingId === r.id}
          <input type="number" min="1" bind:value={editTTL} style="width:5rem" aria-label={`Edit TTL for ${r.name}`} />
        {:else}
          {r.ttl}
        {/if}
      {:else if colKey === "enabled"}
        {r.enabled ? "yes" : "no"}
      {:else if colKey === "actions"}
        <div class="actions">
          {#if editingId === r.id}
            <button onclick={() => saveEdit(r)}>Save</button>
            <button onclick={() => (editingId = null)}>Cancel</button>
          {:else}
            <button onclick={() => startEdit(r)}>Edit</button>
            <button onclick={() => toggleEnabled(r)}>{r.enabled ? "Disable" : "Enable"}</button>
            <button onclick={() => deleteRecord(r)} disabled={pendingDelete.has(r.id)} aria-busy={pendingDelete.has(r.id)}>
              {pendingDelete.has(r.id) ? "Deleting…" : "Delete"}
            </button>
          {/if}
        </div>
      {/if}
    {/snippet}
  </DataGrid>
</section>

<style>
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
</style>
