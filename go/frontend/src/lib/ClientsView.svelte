<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type ManagedClient, type ClientGroup } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";
  import PolicyEditor from "./PolicyEditor.svelte";

  // Native Go implementation (own schema/CRUD) -- see internal/clients's
  // and internal/policy's doc comments for exactly what's covered
  // (managed clients, identifiers, groups, per-client/per-group policy
  // assignment via the shared PolicyEditor) and what's deliberately not
  // here yet: Observed Clients/discovery (Python-owned live data, same
  // shape of problem as Dashboard's analytics -- needs its own
  // compatibility-boundary decision, not built here) and "effective
  // policy explain" (global->network->group->client precedence
  // resolution -- real separate logic, not built here). This page is
  // Managed Clients only, disclosed in-page below.

  let managedClients = $state<ManagedClient[]>([]);
  let groups = $state<ClientGroup[]>([]);
  let loadError = $state("");
  const guard = new StaleGuard();

  let newClientName = $state("");
  let newClientDescription = $state("");
  let addClientBusy = $state(false);
  let addClientError = $state("");

  let newGroupName = $state("");
  let newGroupPriority = $state(0);
  let addGroupBusy = $state(false);
  let addGroupError = $state("");

  let identifierClientId = $state<number | null>(null);
  let identifierKind = $state<"ipv4" | "ipv4_cidr" | "ipv6" | "ipv6_cidr" | "clientid">("ipv4");
  let identifierValue = $state("");
  let identifierError = $state("");

  let groupAssignClientId = $state<number | null>(null);
  let groupAssignGroupId = $state("");

  let policyEditorClientId = $state<number | null>(null);
  let policyEditorGroupId = $state<string | null>(null);

  async function refresh() {
    const token = guard.start();
    try {
      const [c, g] = await Promise.all([api.listClients(router.signal()), api.listGroups(router.signal())]);
      if (!guard.isCurrent(token)) return;
      managedClients = c.clients;
      groups = g.groups;
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

  async function addClient(e: Event) {
    e.preventDefault();
    addClientError = "";
    addClientBusy = true;
    try {
      await api.createClient(newClientName, newClientDescription);
      newClientName = "";
      newClientDescription = "";
      await refresh();
    } catch (err) {
      addClientError = err instanceof ApiError ? err.message : String(err);
    } finally {
      addClientBusy = false;
    }
  }

  async function addGroup(e: Event) {
    e.preventDefault();
    addGroupError = "";
    addGroupBusy = true;
    try {
      await api.createGroup(newGroupName, newGroupPriority);
      newGroupName = "";
      await refresh();
    } catch (err) {
      addGroupError = err instanceof ApiError ? err.message : String(err);
    } finally {
      addGroupBusy = false;
    }
  }

  function startAddIdentifier(c: ManagedClient) {
    identifierClientId = c.id;
    identifierValue = "";
    identifierError = "";
  }

  async function submitIdentifier(e: Event) {
    e.preventDefault();
    if (identifierClientId === null) return;
    identifierError = "";
    try {
      await api.addClientIdentifier(identifierClientId, identifierKind, identifierValue);
      identifierClientId = null;
      await refresh();
    } catch (err) {
      identifierError = err instanceof ApiError ? err.message : String(err);
    }
  }

  function startAssignGroup(c: ManagedClient) {
    groupAssignClientId = c.id;
    groupAssignGroupId = groups[0]?.group_id ?? "";
  }

  async function submitAssignGroup(e: Event) {
    e.preventDefault();
    if (groupAssignClientId === null || !groupAssignGroupId) return;
    await api.addClientToGroup(groupAssignClientId, groupAssignGroupId);
    groupAssignClientId = null;
    await refresh();
  }

  const columns: Column<ManagedClient>[] = [
    { key: "name", label: "Name", sortValue: (c) => c.name.toLowerCase(), minWidth: 12 },
    { key: "identifiers", label: "Identifiers", minWidth: 16 },
    { key: "groups", label: "Groups", minWidth: 12 },
    { key: "actions", label: "Actions", minWidth: 16 },
  ];
</script>

<section aria-labelledby="clients-heading" class="clients">
  <h2 id="clients-heading">Clients</h2>
  <p class="scope-note">
    Managed Clients only (native Go). Observed/discovered clients and per-client policy assignment
    are not migrated yet -- see the parity matrix.
  </p>
  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <div class="two-col">
    <form onsubmit={addClient} class="add-form">
      <h3>Add managed client</h3>
      <label>Name <input required bind:value={newClientName} /></label>
      <label>Description <input bind:value={newClientDescription} /></label>
      <button type="submit" disabled={addClientBusy}>{addClientBusy ? "Adding…" : "Add client"}</button>
      {#if addClientError}<p class="error" role="alert">{addClientError}</p>{/if}
    </form>

    <form onsubmit={addGroup} class="add-form">
      <h3>Add group</h3>
      <label>Name <input required bind:value={newGroupName} /></label>
      <label>Priority <input type="number" bind:value={newGroupPriority} /></label>
      <button type="submit" disabled={addGroupBusy}>{addGroupBusy ? "Adding…" : "Add group"}</button>
      {#if addGroupError}<p class="error" role="alert">{addGroupError}</p>{/if}
    </form>
  </div>

  <h3>Managed Clients</h3>
  <DataGrid gridId="managed-clients" {columns} rows={managedClients} rowKey={(c) => c.id} emptyMessage="No managed clients yet.">
    {#snippet cell(c, colKey)}
      {#if colKey === "name"}
        {c.name}
      {:else if colKey === "identifiers"}
        <span class="chips">
          {#each c.identifiers as id}
            <span class="chip">{id.kind}: {id.value}</span>
          {/each}
        </span>
      {:else if colKey === "groups"}
        <span class="chips">
          {#each c.groups as g}
            <span class="chip">{g.name}</span>
          {/each}
        </span>
      {:else if colKey === "actions"}
        <div class="actions">
          <button onclick={() => startAddIdentifier(c)}>Add identifier</button>
          <button onclick={() => startAssignGroup(c)} disabled={groups.length === 0}>Assign group</button>
          <button onclick={() => (policyEditorClientId = policyEditorClientId === c.id ? null : c.id)}>Policy</button>
        </div>
        {#if identifierClientId === c.id}
          <form onsubmit={submitIdentifier} class="inline-form">
            <select bind:value={identifierKind}>
              <option value="ipv4">IPv4</option>
              <option value="ipv4_cidr">IPv4 CIDR</option>
              <option value="ipv6">IPv6</option>
              <option value="ipv6_cidr">IPv6 CIDR</option>
              <option value="clientid">Strong ClientID</option>
            </select>
            <input required bind:value={identifierValue} placeholder="Value" aria-label="Identifier value" />
            <button type="submit">Save</button>
            <button type="button" onclick={() => (identifierClientId = null)}>Cancel</button>
            {#if identifierError}<p class="error" role="alert">{identifierError}</p>{/if}
          </form>
        {/if}
        {#if groupAssignClientId === c.id}
          <form onsubmit={submitAssignGroup} class="inline-form">
            <select bind:value={groupAssignGroupId}>
              {#each groups as g}
                <option value={g.group_id}>{g.name}</option>
              {/each}
            </select>
            <button type="submit">Save</button>
            <button type="button" onclick={() => (groupAssignClientId = null)}>Cancel</button>
          </form>
        {/if}
        {#if policyEditorClientId === c.id}
          <div class="inline-policy">
            <PolicyEditor layer={c.policy} onSave={(l) => api.putClientPolicy(c.id, l).then(refresh)} />
          </div>
        {/if}
      {/if}
    {/snippet}
  </DataGrid>

  <h3>Groups</h3>
  {#if groups.length === 0}
    <p class="hint">No groups yet.</p>
  {:else}
    <ul class="group-list">
      {#each groups as g}
        <li>
          <div class="group-row">
            <span><strong>{g.name}</strong> (priority {g.priority}) -- {g.members.length} member{g.members.length === 1 ? "" : "s"}</span>
            <button onclick={() => (policyEditorGroupId = policyEditorGroupId === g.group_id ? null : g.group_id)}>Policy</button>
          </div>
          {#if policyEditorGroupId === g.group_id}
            <div class="inline-policy">
              <PolicyEditor layer={g.policy} onSave={(l) => api.putGroupPolicy(g.group_id, l).then(refresh)} />
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .clients { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 40rem; }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .two-col { display: flex; flex-wrap: wrap; gap: 1rem; }
  .add-form { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.5rem; min-width: 16rem; flex: 1; }
  .add-form h3 { margin: 0; }
  .add-form label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.85rem; }
  .chips { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  .chip { background: var(--nav-hover-bg); padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.78rem; }
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
  .inline-form { display: flex; gap: 0.4rem; margin-top: 0.4rem; flex-wrap: wrap; align-items: center; }
  .group-list { margin: 0; padding-left: 1.2rem; font-size: 0.9rem; display: flex; flex-direction: column; gap: 0.5rem; }
  .group-row { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
  .inline-policy { margin: 0.5rem 0 0.5rem -1.2rem; padding: 0.75rem; border: 1px solid var(--border); border-radius: 6px; background: var(--card-bg); }
</style>
