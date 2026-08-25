<script lang="ts">
  import { api, type LocalDnsRecord } from "../api";
  import { StaleGuard } from "../staleGuard";

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
      const resp = await api.listLocalDNS();
      if (!guard.isCurrent(token)) return;
      records = resp.records;
      loadError = "";
    } catch (err) {
      if (!guard.isCurrent(token)) return;
      loadError = err instanceof Error ? err.message : String(err);
    }
  }

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

  <div class="table-scroll">
    <table aria-label="Local DNS records">
      <thead><tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th>Enabled</th><th>Actions</th></tr></thead>
      <tbody>
        {#each records as r (r.id)}
          <tr class:pending={pendingDelete.has(r.id)}>
            <td>{r.name}</td>
            <td>{r.record_type}</td>
            <td>
              {#if editingId === r.id}
                <input bind:value={editValue} aria-label={`Edit value for ${r.name}`} />
              {:else}
                {r.value}
              {/if}
            </td>
            <td>
              {#if editingId === r.id}
                <input type="number" min="1" bind:value={editTTL} style="width:5rem" aria-label={`Edit TTL for ${r.name}`} />
              {:else}
                {r.ttl}
              {/if}
            </td>
            <td>{r.enabled ? "yes" : "no"}</td>
            <td class="actions">
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
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<style>
  .table-scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border); white-space: nowrap; }
  tr.pending { opacity: 0.5; }
  .actions { display: flex; gap: 0.4rem; }
</style>
