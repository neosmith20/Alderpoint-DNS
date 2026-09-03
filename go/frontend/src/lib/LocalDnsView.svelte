<script lang="ts">
  import { onMount } from "svelte";
  import { api, type LocalDnsRecord, type DNSRuntimeApplyResult, type ClientAlias, ApiError } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import { toast } from "../toast.svelte";
  import DataGrid from "./DataGrid.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";
  import type { Column } from "./datagrid";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import Panel from "./ui/Panel.svelte";
  import Modal from "./ui/Modal.svelte";

  let records = $state<LocalDnsRecord[]>([]);
  let loadError = $state("");
  let pendingDelete = $state<Set<number>>(new Set());
  let editingId = $state<number | null>(null);
  let editValue = $state("");
  let editTTL = $state(300);
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);
  let search = $state("");

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

  let filteredRecords = $derived(
    search.trim() === ""
      ? records
      : records.filter((r) => {
          const q = search.trim().toLowerCase();
          return r.name.toLowerCase().includes(q) || r.value.toLowerCase().includes(q) || r.record_type.toLowerCase().includes(q);
        }),
  );

  // Client Aliases (V1.1.1's local_dns.py upsert_alias/alias_for_client,
  // read directly): a CIDR->display-name mapping used to label a client
  // address (Dashboard, Query Log, Client analytics) that isn't already
  // a managed client's own identifier. Display-only, no DNS-answering
  // effect -- see internal/clientalias's own doc comment.
  let aliases = $state<ClientAlias[]>([]);
  let aliasLoadError = $state("");
  let aliasUnavailable = $state(false);
  const aliasGuard = new StaleGuard();

  let newAliasCidr = $state("");
  let newAliasName = $state("");
  let newAliasDescription = $state("");
  let addAliasBusy = $state(false);
  let addAliasError = $state("");

  async function refreshAliases() {
    const token = aliasGuard.start();
    try {
      const resp = await api.listClientAliases(router.signal());
      if (!aliasGuard.isCurrent(token)) return;
      aliases = resp.aliases;
      aliasLoadError = "";
      aliasUnavailable = false;
    } catch (err) {
      if (!aliasGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      if (err instanceof ApiError && err.status === 503) {
        aliasUnavailable = true;
        return;
      }
      aliasLoadError = err instanceof Error ? err.message : String(err);
    }
  }

  async function addAlias(e: Event) {
    e.preventDefault();
    addAliasError = "";
    addAliasBusy = true;
    try {
      await api.createClientAlias(newAliasCidr, newAliasName, newAliasDescription);
      newAliasCidr = "";
      newAliasName = "";
      newAliasDescription = "";
      await refreshAliases();
    } catch (err) {
      addAliasError = err instanceof ApiError ? err.message : String(err);
    } finally {
      addAliasBusy = false;
    }
  }

  let confirmDeleteAlias = $state<ClientAlias | null>(null);

  function deleteAlias(a: ClientAlias) {
    confirmDeleteAlias = a;
  }

  async function runDeleteAlias() {
    const a = confirmDeleteAlias;
    confirmDeleteAlias = null;
    if (!a) return;
    try {
      await api.deleteClientAlias(a.id);
      await refreshAliases();
      toast.success(`Removed alias "${a.display_name}".`);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : String(err));
    }
  }

  // Loaded on demand by RouteLoader when this page is routed to -- own our
  // own initial data fetch rather than relying on the shell to know we
  // need one (RouteLoader is generic across every future page).
  onMount(() => {
    refresh();
    refreshAliases();
  });

  let addModalOpen = $state(false);

  async function addRecord(e: Event) {
    e.preventDefault();
    addError = "";
    addBusy = true;
    try {
      const resp = await api.createLocalDNS({ name: newName, record_type: newType, value: newValue, ttl: newTTL, enabled: true });
      dnsRuntimeResult = resp.dns_runtime ?? null;
      newName = "";
      newValue = "";
      addModalOpen = false;
      await refresh();
    } catch (err) {
      addError = err instanceof Error ? err.message : String(err);
    } finally {
      addBusy = false;
    }
  }

  function exportCsv() {
    const header = ["Name", "Type", "Value", "TTL", "Enabled"];
    const csvRows = records.map((r) => [r.name, r.record_type, r.value, String(r.ttl), r.enabled ? "yes" : "no"]);
    const esc = (v: string) => `"${v.replace(/"/g, '""')}"`;
    const csv = [header, ...csvRows].map((row) => row.map((c) => esc(String(c))).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "alderpoint-local-dns.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  function startEdit(r: LocalDnsRecord) {
    editingId = r.id;
    editValue = r.value;
    editTTL = r.ttl;
  }

  async function saveEdit(r: LocalDnsRecord) {
    const resp = await api.updateLocalDNS(r.id, { value: editValue, ttl: editTTL });
    dnsRuntimeResult = resp.dns_runtime ?? null;
    editingId = null;
    await refresh();
  }

  async function toggleEnabled(r: LocalDnsRecord) {
    const resp = await api.updateLocalDNS(r.id, { enabled: !r.enabled });
    dnsRuntimeResult = resp.dns_runtime ?? null;
    await refresh();
  }

  let confirmDeleteRecord = $state<LocalDnsRecord | null>(null);

  function deleteRecord(r: LocalDnsRecord) {
    confirmDeleteRecord = r;
  }

  async function runDeleteRecord() {
    const r = confirmDeleteRecord;
    confirmDeleteRecord = null;
    if (!r) return;
    pendingDelete = new Set(pendingDelete).add(r.id);
    try {
      const resp = await api.deleteLocalDNS(r.id);
      dnsRuntimeResult = resp.dns_runtime ?? null;
      await refresh();
      toast.success(`Deleted "${r.name}".`);
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

<section aria-labelledby="localdns-heading" class="localdns">
  <PageHeader
    title="Local DNS"
    headingId="localdns-heading"
    description="Appliance-wide A/AAAA/CNAME/PTR records, answered directly by the compiled dnsdist runtime, plus Client Aliases for labeling addresses elsewhere in the UI."
  >
    {#snippet actions()}
      <button type="button" onclick={() => { addError = ""; addModalOpen = true; }}>Add Record</button>
      <button type="button" class="secondary" onclick={() => router.navigate("importexport")}>Import</button>
      <button type="button" class="secondary" onclick={exportCsv} disabled={records.length === 0}>Export</button>
    {/snippet}
  </PageHeader>

  <Panel heading="Records">
    {#snippet actions()}
      <input class="search-input" placeholder="Search name, value, type…" bind:value={search} aria-label="Search Local DNS records" />
    {/snippet}
    <DnsRuntimeBadge result={dnsRuntimeResult} />

    {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

    <DataGrid
      gridId="local-dns-records"
      {columns}
      rows={filteredRecords}
      rowKey={(r) => r.id}
      {rowClass}
      emptyMessage={records.length === 0 ? "No Local DNS records yet." : "No records match this search."}
    >
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
  </Panel>

  <Panel heading="Client Aliases">
    <p class="hint">
      Labels an address range wherever a client is shown (Dashboard, Query Log, Client analytics) --
      display only, no DNS-answering effect. A managed client's own identifier always wins over an
      alias for the same address.
    </p>
    {#if aliasUnavailable}
      <p class="hint">Client Aliases are not configured on this deployment.</p>
    {:else}
      {#if aliasLoadError}<p class="error" role="alert">{aliasLoadError}</p>{/if}
      {#if aliases.length === 0 && !aliasLoadError}
        <p class="hint">No client aliases yet.</p>
      {:else}
        <ul class="alias-list">
          {#each aliases as a (a.id)}
            <li class="alias-row">
              <code>{a.cidr}</code>
              <strong>{a.display_name}</strong>
              {#if a.description}<span class="hint">{a.description}</span>{/if}
              <button type="button" class="secondary small" onclick={() => deleteAlias(a)}>Remove</button>
            </li>
          {/each}
        </ul>
      {/if}
      <form onsubmit={addAlias} class="add-form">
        <label>CIDR or IP <input required bind:value={newAliasCidr} placeholder="192.168.1.0/24" /></label>
        <label>Display name <input required bind:value={newAliasName} placeholder="Kids devices" /></label>
        <label>Description <input bind:value={newAliasDescription} placeholder="optional" /></label>
        <button type="submit" disabled={addAliasBusy}>{addAliasBusy ? "Adding…" : "Add alias"}</button>
        {#if addAliasError}<p class="error" role="alert">{addAliasError}</p>{/if}
      </form>
    {/if}
  </Panel>
</section>

{#if addModalOpen}
  <Modal title="Add Record" onClose={() => (addModalOpen = false)}>
    <form onsubmit={addRecord} class="modal-form">
      <label>Name <input required bind:value={newName} placeholder="host.lan" /></label>
      <label>
        Type
        <select bind:value={newType}>
          <option>A</option><option>AAAA</option><option>CNAME</option><option>PTR</option>
        </select>
      </label>
      <label>Value <input required bind:value={newValue} placeholder="10.0.0.5" /></label>
      <label>TTL <input type="number" min="1" bind:value={newTTL} /></label>
      <div class="form-actions">
        <button type="submit" disabled={addBusy}>{addBusy ? "Adding…" : "Add Record"}</button>
        <button type="button" class="secondary" onclick={() => (addModalOpen = false)}>Cancel</button>
      </div>
      {#if addError}<p class="error" role="alert">{addError}</p>{/if}
    </form>
  </Modal>
{/if}

{#if confirmDeleteAlias}
  <ConfirmDialog
    title="Remove alias"
    message={`Remove the alias "${confirmDeleteAlias.display_name}" for ${confirmDeleteAlias.cidr}?`}
    confirmLabel="Remove"
    onConfirm={runDeleteAlias}
    onCancel={() => (confirmDeleteAlias = null)}
  />
{/if}

{#if confirmDeleteRecord}
  <ConfirmDialog
    title="Delete record"
    message={`Delete the ${confirmDeleteRecord.record_type} record "${confirmDeleteRecord.name}" (${confirmDeleteRecord.value})? This takes effect on the live DNS runtime immediately.`}
    confirmLabel="Delete"
    onConfirm={runDeleteRecord}
    onCancel={() => (confirmDeleteRecord = null)}
  />
{/if}

<style>
  .localdns { display: flex; flex-direction: column; gap: 1rem; }
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
  .add-form { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; margin: 0.75rem 0; }
  .add-form label { display: flex; flex-direction: column; font-size: 0.85rem; gap: 0.25rem; }
  .search-input { min-width: 14rem; }
  .modal-form { display: flex; flex-direction: column; gap: 0.75rem; }
  .modal-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .form-actions { display: flex; gap: 0.5rem; }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .alias-list { list-style: none; margin: 0 0 0.75rem; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
  .alias-row { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
  button.secondary.small { min-height: auto; padding: 0.3rem 0.6rem; font-size: 0.8rem; }
</style>
