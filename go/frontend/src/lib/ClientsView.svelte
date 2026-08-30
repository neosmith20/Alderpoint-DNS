<script lang="ts">
  import { onMount } from "svelte";
  import {
    api,
    ApiError,
    type ManagedClient,
    type ClientGroup,
    type ClientIdentifier,
    type PolicyExplainResult,
    type ObservedClient,
    type ClientAnalyticsRow,
  } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import { queryLogPrefill } from "../queryLogPrefill.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";
  import PolicyEditor from "./PolicyEditor.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import Panel from "./ui/Panel.svelte";
  import SegmentedControl from "./ui/SegmentedControl.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";
  import Modal from "./ui/Modal.svelte";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";
  import { toast } from "../toast.svelte";

  // Native Go implementation (own schema/CRUD) -- see internal/clients's
  // and internal/policy's doc comments for exactly what's covered:
  // full managed-client lifecycle (create/edit/enable-disable/delete),
  // identifiers (IP/CIDR and Strong ClientID) with real generation/
  // validation/revoke/regenerate/delete, group membership (assign and
  // remove), per-client/per-group policy assignment via the shared
  // PolicyEditor, "effective policy explain" (global->network->group->
  // client precedence resolution, GET /api/policy/explain, see
  // internal/policy/effective.go), and per-client explicit domain
  // overrides compiled into real dnsdist DoH-path/DoT+DoQ-SNI
  // enforcement (see internal/clientid, internal/dnscompile). Observed
  // Clients below is a real but disclosed-narrower substitute for a
  // dedicated discovery worker: it reads recent real traffic straight
  // from internal/pyanalytics's snapshot boundary (see
  // GET /api/clients/observed's Go doc comment) -- no first-seen/
  // last-seen history, no hostname/vendor fingerprinting, no
  // loopback/unspecified addresses ever presented as a host.

  let managedClients = $state<ManagedClient[]>([]);
  let groups = $state<ClientGroup[]>([]);
  let loadError = $state("");
  const guard = new StaleGuard();

  // Client analytics (V1.1.1's clients_data(), see
  // internal/dnsanalytics.Reader.ClientAnalytics / GET
  // /api/analytics/top-clients): every client seen in the selected
  // window, ranked by query volume, with its own blocked count/percent
  // and last-seen timestamp.
  type RangeKey = "1h" | "24h" | "7d" | "30d";
  const RANGE_MINUTES: Record<RangeKey, number> = { "1h": 60, "24h": 1440, "7d": 7 * 1440, "30d": 30 * 1440 };
  const RANGE_OPTIONS: { key: RangeKey; label: string }[] = [
    { key: "1h", label: "Last hour" },
    { key: "24h", label: "Last 24 hours" },
    { key: "7d", label: "Last 7 days" },
    { key: "30d", label: "Last 30 days" },
  ];
  let analyticsRange = $state<RangeKey>("24h");
  let analyticsRows = $state<ClientAnalyticsRow[]>([]);
  let analyticsDegraded = $state(false);
  let analyticsDegradedReason = $state("");
  let analyticsError = $state("");
  let analyticsLoading = $state(false);
  const analyticsGuard = new StaleGuard();

  async function loadAnalytics() {
    const token = analyticsGuard.start();
    analyticsLoading = true;
    try {
      const resp = await api.topClients(RANGE_MINUTES[analyticsRange], router.signal());
      if (!analyticsGuard.isCurrent(token)) return;
      analyticsRows = resp.clients;
      analyticsDegraded = resp.degraded;
      analyticsDegradedReason = resp.degraded_reason ?? "";
      analyticsError = "";
    } catch (err) {
      if (!analyticsGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      analyticsError = err instanceof ApiError ? err.message : String(err);
    } finally {
      if (analyticsGuard.isCurrent(token)) analyticsLoading = false;
    }
  }

  function setAnalyticsRange(r: RangeKey) {
    analyticsRange = r;
    loadAnalytics();
  }

  function goToQueryLog(rawClient: string) {
    queryLogPrefill.setClient(rawClient);
    router.navigate("analytics");
  }

  function formatLastSeen(unixSeconds: number): string {
    if (!unixSeconds) return "never";
    return new Date(unixSeconds * 1000).toLocaleString();
  }

  const analyticsColumns: Column<ClientAnalyticsRow>[] = [
    { key: "label", label: "Client", sortValue: (r) => r.label.toLowerCase(), minWidth: 16 },
    { key: "value", label: "Queries", sortValue: (r) => r.value, minWidth: 10 },
    { key: "share", label: "Share", sortValue: (r) => r.share, minWidth: 8 },
    { key: "blocked", label: "Blocked", sortValue: (r) => r.blocked, minWidth: 10 },
    { key: "last_seen", label: "Last Seen", sortValue: (r) => r.last_seen, minWidth: 14 },
    { key: "query_log", label: "", minWidth: 10 },
  ];

  // Managed-client directory search/filter.
  let clientSearch = $state("");
  let statusFilter = $state<"all" | "enabled" | "disabled">("all");
  let filteredManagedClients = $derived(
    managedClients.filter((c) => {
      if (statusFilter === "enabled" && !c.enabled) return false;
      if (statusFilter === "disabled" && c.enabled) return false;
      if (!clientSearch.trim()) return true;
      const q = clientSearch.trim().toLowerCase();
      return (
        c.name.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.identifiers.some((id) => id.value.toLowerCase().includes(q)) ||
        c.groups.some((g) => g.name.toLowerCase().includes(q))
      );
    }),
  );

  let addClientModalOpen = $state(false);
  let addGroupModalOpen = $state(false);

  let observed = $state<ObservedClient[]>([]);
  let observedDegraded = $state(false);
  let observedDegradedReason = $state("");
  let observedLoadError = $state("");
  const observedGuard = new StaleGuard();

  // Shared destructive-action confirm dialog (design-system unification):
  // replaces every native window.confirm() on this page (delete client,
  // delete/revoke/regenerate an identifier) with the one real,
  // app-styled ConfirmDialog every future destructive action should use
  // instead of inventing its own native-dialog or inline-banner pattern.
  let pendingConfirm = $state<{ title: string; message: string; confirmLabel: string; run: () => Promise<void> } | null>(null);

  function askConfirm(title: string, message: string, confirmLabel: string, run: () => Promise<void>) {
    pendingConfirm = { title, message, confirmLabel, run };
  }

  async function runPendingConfirm() {
    if (!pendingConfirm) return;
    const { run } = pendingConfirm;
    pendingConfirm = null;
    try {
      await run();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : String(err));
    }
  }

  let manageAddress = $state<string | null>(null);
  let manageMode = $state<"new" | "existing">("new");
  let manageNewName = $state("");
  let manageExistingClientId = $state<number | null>(null);
  let manageError = $state("");
  let manageBusy = $state(false);

  let editClientId = $state<number | null>(null);
  let editName = $state("");
  let editDescription = $state("");
  let editError = $state("");
  let editBusy = $state(false);

  let newClientName = $state("");
  let newClientDescription = $state("");
  let addClientBusy = $state(false);
  let addClientError = $state("");

  let newGroupName = $state("");
  let newGroupPriority = $state(0);
  let addGroupBusy = $state(false);
  let addGroupError = $state("");

  let identifierClientId = $state<number | null>(null);
  let identifierKind = $state<"ipv4" | "ipv4_cidr" | "ipv6" | "ipv6_cidr">("ipv4");
  let identifierValue = $state("");
  let identifierError = $state("");

  let groupAssignClientId = $state<number | null>(null);
  let groupAssignGroupId = $state("");

  let policyEditorClientId = $state<number | null>(null);
  let policyEditorGroupId = $state<string | null>(null);

  let explainClientId = $state<number | null>(null);
  let explainResult = $state<PolicyExplainResult | null>(null);
  let explainError = $state("");

  // Strong ClientID: generate form.
  let generateClientId = $state<number | null>(null);
  let generateBits = $state<192 | 256>(256);
  let generateLabel = $state("");
  let generateBusy = $state(false);
  let generateError = $state("");
  let lastGenerated = $state<{ clientId: number; identifier: ClientIdentifier } | null>(null);

  // Strong ClientID: per-client domain override form.
  let overrideClientId = $state<number | null>(null);
  let overrideType = $state<"block" | "allow">("block");
  let overridePattern = $state("");
  let overrideError = $state("");

  async function toggleExplain(c: ManagedClient) {
    if (explainClientId === c.id) {
      explainClientId = null;
      return;
    }
    explainClientId = c.id;
    explainResult = null;
    explainError = "";
    try {
      explainResult = await api.explainPolicy(c.id);
    } catch (err) {
      explainError = err instanceof ApiError ? err.message : String(err);
    }
  }

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

  async function refreshObserved() {
    const token = observedGuard.start();
    try {
      const res = await api.listObservedClients(router.signal());
      if (!observedGuard.isCurrent(token)) return;
      observed = res.observed;
      observedDegraded = res.degraded;
      observedDegradedReason = res.degraded_reason ?? "";
      observedLoadError = "";
    } catch (err) {
      if (!observedGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      observedLoadError = err instanceof Error ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
    refreshObserved();
    loadAnalytics();
  });

  function startEditClient(c: ManagedClient) {
    editClientId = c.id;
    editName = c.name;
    editDescription = c.description;
    editError = "";
  }

  async function submitEditClient(e: Event) {
    e.preventDefault();
    if (editClientId === null) return;
    editError = "";
    editBusy = true;
    try {
      await api.updateClient(editClientId, editName, editDescription);
      editClientId = null;
      await refresh();
    } catch (err) {
      editError = err instanceof ApiError ? err.message : String(err);
    } finally {
      editBusy = false;
    }
  }

  async function toggleEnabled(c: ManagedClient) {
    await api.setClientEnabled(c.id, !c.enabled);
    await refresh();
  }

  function deleteClient(c: ManagedClient) {
    askConfirm(
      "Delete client",
      `Permanently delete client "${c.name}"? This removes all its identifiers, group memberships, and domain overrides. This cannot be undone.`,
      "Delete",
      async () => {
        await api.deleteClient(c.id);
        await Promise.all([refresh(), refreshObserved()]);
        toast.success(`Deleted client "${c.name}".`);
      },
    );
  }

  async function removeFromGroup(c: ManagedClient, groupId: string) {
    await api.removeClientFromGroup(c.id, groupId);
    await refresh();
  }

  function deleteIpIdentifier(c: ManagedClient, id: ClientIdentifier) {
    askConfirm("Remove identifier", `Remove identifier ${id.value} from "${c.name}"?`, "Remove", async () => {
      await api.deleteClientIdentifier(c.id, id.id);
      await Promise.all([refresh(), refreshObserved()]);
      toast.success(`Removed identifier ${id.value}.`);
    });
  }

  function startManage(address: string) {
    manageAddress = address;
    manageMode = "new";
    manageNewName = address;
    manageExistingClientId = managedClients[0]?.id ?? null;
    manageError = "";
  }

  async function submitManage(e: Event) {
    e.preventDefault();
    if (manageAddress === null) return;
    manageError = "";
    manageBusy = true;
    const kind = manageAddress.includes(":") ? "ipv6" : "ipv4";
    try {
      let clientId: number;
      if (manageMode === "new") {
        const created = await api.createClient(manageNewName || manageAddress, "");
        clientId = created.client_id;
      } else {
        if (manageExistingClientId === null) throw new Error("choose a client");
        clientId = manageExistingClientId;
      }
      await api.addClientIdentifier(clientId, kind, manageAddress);
      manageAddress = null;
      await Promise.all([refresh(), refreshObserved()]);
    } catch (err) {
      manageError = err instanceof ApiError ? err.message : String(err);
    } finally {
      manageBusy = false;
    }
  }

  async function addClient(e: Event) {
    e.preventDefault();
    addClientError = "";
    addClientBusy = true;
    try {
      await api.createClient(newClientName, newClientDescription);
      newClientName = "";
      newClientDescription = "";
      addClientModalOpen = false;
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
      addGroupModalOpen = false;
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

  function startGenerateClientID(c: ManagedClient) {
    generateClientId = c.id;
    generateLabel = "";
    generateError = "";
    lastGenerated = null;
  }

  async function submitGenerateClientID(e: Event) {
    e.preventDefault();
    if (generateClientId === null) return;
    generateError = "";
    generateBusy = true;
    try {
      const result = await api.generateClientID(generateClientId, generateBits, generateLabel);
      lastGenerated = { clientId: generateClientId, identifier: result.identifier };
      generateClientId = null;
      await refresh();
    } catch (err) {
      generateError = err instanceof ApiError ? err.message : String(err);
    } finally {
      generateBusy = false;
    }
  }

  function revokeIdentifier(c: ManagedClient, id: ClientIdentifier) {
    const label = id.label || id.value.slice(0, 12) + "…";
    askConfirm(
      "Revoke Strong ClientID",
      `Revoke this Strong ClientID (${label})? DoH/DoT/DoQ traffic using it will stop being recognized once applied.`,
      "Revoke",
      async () => {
        await api.revokeClientIdentifier(c.id, id.id);
        await refresh();
        toast.success(`Revoked identifier ${label}.`);
      },
    );
  }

  function regenerateIdentifier(c: ManagedClient, id: ClientIdentifier) {
    const label = id.label || id.value.slice(0, 12) + "…";
    askConfirm(
      "Regenerate Strong ClientID",
      `Regenerate this Strong ClientID (${label})? The old value stops working immediately once applied; a new one replaces it.`,
      "Regenerate",
      async () => {
        const result = await api.regenerateClientIdentifier(c.id, id.id);
        lastGenerated = { clientId: c.id, identifier: result.identifier };
        await refresh();
        toast.success(`Regenerated identifier ${label}.`);
      },
    );
  }

  function deleteIdentifier(c: ManagedClient, id: ClientIdentifier) {
    const label = id.label || id.value.slice(0, 12) + "…";
    askConfirm("Delete identifier", `Permanently delete this identifier (${label})? This cannot be undone.`, "Delete", async () => {
      await api.deleteClientIdentifier(c.id, id.id);
      if (lastGenerated?.identifier.id === id.id) lastGenerated = null;
      await refresh();
      toast.success(`Deleted identifier ${label}.`);
    });
  }

  function startAddOverride(c: ManagedClient) {
    overrideClientId = c.id;
    overridePattern = "";
    overrideType = "block";
    overrideError = "";
  }

  async function submitAddOverride(e: Event) {
    e.preventDefault();
    if (overrideClientId === null) return;
    overrideError = "";
    try {
      await api.addClientDomainOverride(overrideClientId, overrideType, overridePattern);
      overrideClientId = null;
      await refresh();
    } catch (err) {
      overrideError = err instanceof ApiError ? err.message : String(err);
    }
  }

  async function deleteOverride(c: ManagedClient, overrideId: number) {
    await api.deleteClientDomainOverride(c.id, overrideId);
    await refresh();
  }

  function copyToClipboard(text: string) {
    navigator.clipboard?.writeText(text).catch(() => {});
  }

  const columns: Column<ManagedClient>[] = [
    { key: "name", label: "Name", sortValue: (c) => c.name.toLowerCase(), minWidth: 14 },
    { key: "identifiers", label: "Identifiers", minWidth: 20 },
    { key: "overrides", label: "Strong ClientID Overrides", minWidth: 16 },
    { key: "groups", label: "Groups", minWidth: 12 },
    { key: "actions", label: "Actions", minWidth: 18 },
  ];
</script>

<section aria-labelledby="clients-heading" class="clients">
  <PageHeader
    title="Clients"
    headingId="clients-heading"
    description="Every managed and observed client on this appliance -- query analytics, identity, group/network association, and per-client policy in one place."
  />
  <p class="scope-note">
    Full managed-client lifecycle (native Go): create, edit, enable/disable, delete, group and
    network association, identifier removal. Strong ClientID (DoH path / DoT+DoQ SNI identity) is
    real: generated values are compiled into live dnsdist enforcement, with per-client explicit
    domain overrides (deny beats allow beats default policy). See "Clients &amp; Access" for global
    and network-level policy, and the parity matrix for exactly what's covered.
  </p>
  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <Panel heading="Client analytics">
    {#snippet actions()}
      <SegmentedControl label="Client analytics time range" options={RANGE_OPTIONS} value={analyticsRange} onChange={setAnalyticsRange} />
    {/snippet}
    {#if analyticsError}
      <p class="error" role="alert">{analyticsError}</p>
    {:else if analyticsDegraded}
      <p class="hint">Client analytics degraded{analyticsDegradedReason ? `: ${analyticsDegradedReason}` : ""}.</p>
    {/if}
    {#if !analyticsLoading && !analyticsError && analyticsRows.length === 0}
      <p class="hint">No client activity yet. Detailed rows will appear here once telemetry is collected for this range.</p>
    {:else}
      <DataGrid gridId="client-analytics" columns={analyticsColumns} rows={analyticsRows} rowKey={(r) => r.raw_client} emptyMessage="No client activity yet.">
        {#snippet cell(r, colKey)}
          {#if colKey === "label"}
            <span class="mono" title={r.raw_client}>{r.label}</span>
          {:else if colKey === "value"}
            {r.value}
          {:else if colKey === "share"}
            {r.share.toFixed(1)}%
          {:else if colKey === "blocked"}
            {r.blocked} ({r.blocked_percent.toFixed(1)}%)
          {:else if colKey === "last_seen"}
            <span class="mono">{formatLastSeen(r.last_seen)}</span>
          {:else if colKey === "query_log"}
            <button type="button" class="secondary small" onclick={() => goToQueryLog(r.raw_client)}>Query Log</button>
          {/if}
        {/snippet}
      </DataGrid>
    {/if}
  </Panel>

  <Panel heading="Managed clients">
    {#snippet actions()}
      <input class="search-input" placeholder="Search name, description, address, group…" bind:value={clientSearch} aria-label="Search managed clients" />
      <select bind:value={statusFilter} aria-label="Filter by status">
        <option value="all">All statuses</option>
        <option value="enabled">Enabled</option>
        <option value="disabled">Disabled</option>
      </select>
      <button type="button" onclick={() => { addClientError = ""; addClientModalOpen = true; }}>Add client</button>
      <button type="button" class="secondary" onclick={() => { addGroupError = ""; addGroupModalOpen = true; }} disabled={managedClients.length === 0 && groups.length === 0}>Add group</button>
    {/snippet}
  <DataGrid gridId="managed-clients" {columns} rows={filteredManagedClients} rowKey={(c) => c.id} emptyMessage={managedClients.length === 0 ? "No managed clients yet." : "No clients match this search/filter."}>
    {#snippet cell(c, colKey)}
      {#if colKey === "name"}
        {#if editClientId === c.id}
          <form onsubmit={submitEditClient} class="inline-form edit-name-form">
            <input required bind:value={editName} aria-label="Client name" />
            <input bind:value={editDescription} placeholder="Description" aria-label="Client description" />
            <button type="submit" disabled={editBusy}>{editBusy ? "Saving…" : "Save"}</button>
            <button type="button" onclick={() => (editClientId = null)}>Cancel</button>
            {#if editError}<p class="error" role="alert">{editError}</p>{/if}
          </form>
        {:else}
          <div class="name-cell">
            <span class:disabled-name={!c.enabled}>{c.name}</span>
            {#if !c.enabled}<span class="badge disabled-badge">disabled</span>{/if}
          </div>
          {#if c.description}<p class="hint client-desc">{c.description}</p>{/if}
        {/if}
      {:else if colKey === "identifiers"}
        <div class="id-list">
          {#each c.identifiers as id (id.id)}
            {#if id.kind === "clientid"}
              <div class="clientid-row" class:revoked={!!id.revoked_at}>
                <div class="clientid-main">
                  <span class="chip clientid-chip">Strong ClientID{id.label ? `: ${id.label}` : ""}</span>
                  {#if id.revoked_at}<span class="badge revoked-badge">revoked</span>{/if}
                  <code class="hexval" title={id.value}>{id.value.slice(0, 10)}…{id.value.slice(-6)} ({id.value.length * 4}-bit)</code>
                  <button type="button" class="mini" onclick={() => copyToClipboard(id.value)}>Copy hex</button>
                </div>
                {#if !id.revoked_at}
                  <div class="clientid-paths">
                    <div><span class="path-label">DoH path:</span> <code>{id.doh_path}</code> <button type="button" class="mini" onclick={() => copyToClipboard(id.doh_path ?? "")}>Copy</button></div>
                    <div><span class="path-label">DoT/DoQ SNI:</span> <code>{id.sni_hostname}</code> <button type="button" class="mini" onclick={() => copyToClipboard(id.sni_hostname ?? "")}>Copy</button></div>
                  </div>
                  <div class="clientid-actions">
                    <button type="button" onclick={() => regenerateIdentifier(c, id)}>Regenerate</button>
                    <button type="button" onclick={() => revokeIdentifier(c, id)}>Revoke</button>
                    <button type="button" onclick={() => deleteIdentifier(c, id)}>Delete</button>
                  </div>
                {:else}
                  <div class="clientid-actions">
                    <button type="button" onclick={() => deleteIdentifier(c, id)}>Delete</button>
                  </div>
                {/if}
              </div>
            {:else}
              <span class="chip">
                {id.kind}: {id.value}
                <button type="button" class="chip-x" onclick={() => deleteIpIdentifier(c, id)} aria-label="Remove identifier">×</button>
              </span>
            {/if}
          {/each}
          {#if lastGenerated && lastGenerated.clientId === c.id}
            <p class="hint reveal-once">
              New Strong ClientID generated -- shown once above; the full hex value is always retrievable via
              "Copy hex" on its own row afterward.
            </p>
          {/if}
        </div>
      {:else if colKey === "overrides"}
        <span class="chips">
          {#each c.domain_overrides as o (o.id)}
            <span class="chip" class:override-block={o.override_type === "block"} class:override-allow={o.override_type === "allow"}>
              {o.override_type}: {o.pattern}
              <button type="button" class="chip-x" onclick={() => deleteOverride(c, o.id)} aria-label="Remove override">×</button>
            </span>
          {/each}
        </span>
      {:else if colKey === "groups"}
        <span class="chips">
          {#each c.groups as g}
            <span class="chip">
              {g.name}
              <button type="button" class="chip-x" onclick={() => removeFromGroup(c, g.group_id)} aria-label="Remove from group">×</button>
            </span>
          {/each}
        </span>
      {:else if colKey === "actions"}
        <div class="actions">
          <button onclick={() => startGenerateClientID(c)}>Generate Strong ClientID</button>
          <button onclick={() => startAddOverride(c)}>Add domain override</button>
          <button onclick={() => startAddIdentifier(c)}>Add IP identifier</button>
          <button onclick={() => startAssignGroup(c)} disabled={groups.length === 0}>Assign group</button>
          <button onclick={() => (policyEditorClientId = policyEditorClientId === c.id ? null : c.id)}>Policy</button>
          <button onclick={() => toggleExplain(c)}>Explain</button>
          <button onclick={() => startEditClient(c)}>Edit</button>
          <button onclick={() => toggleEnabled(c)}>{c.enabled ? "Disable" : "Enable"}</button>
          <button class="danger" onclick={() => deleteClient(c)}>Delete</button>
        </div>
        {#if generateClientId === c.id}
          <form onsubmit={submitGenerateClientID} class="inline-form">
            <select bind:value={generateBits}>
              <option value={256}>256-bit (64 hex)</option>
              <option value={192}>192-bit (48 hex)</option>
            </select>
            <input bind:value={generateLabel} placeholder="Label (optional)" aria-label="ClientID label" />
            <button type="submit" disabled={generateBusy}>{generateBusy ? "Generating…" : "Generate"}</button>
            <button type="button" onclick={() => (generateClientId = null)}>Cancel</button>
            {#if generateError}<p class="error" role="alert">{generateError}</p>{/if}
          </form>
        {/if}
        {#if overrideClientId === c.id}
          <form onsubmit={submitAddOverride} class="inline-form">
            <select bind:value={overrideType}>
              <option value="block">Block</option>
              <option value="allow">Allow</option>
            </select>
            <input required bind:value={overridePattern} placeholder="Domain (e.g. ads.example.com)" aria-label="Override domain" />
            <button type="submit">Save</button>
            <button type="button" onclick={() => (overrideClientId = null)}>Cancel</button>
            {#if overrideError}<p class="error" role="alert">{overrideError}</p>{/if}
          </form>
        {/if}
        {#if identifierClientId === c.id}
          <form onsubmit={submitIdentifier} class="inline-form">
            <select bind:value={identifierKind}>
              <option value="ipv4">IPv4</option>
              <option value="ipv4_cidr">IPv4 CIDR</option>
              <option value="ipv6">IPv6</option>
              <option value="ipv6_cidr">IPv6 CIDR</option>
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
            <PolicyEditor layer={c.policy} onSave={(l) => api.putClientPolicy(c.id, l).then((res) => { refresh(); return res; })} />
          </div>
        {/if}
        {#if explainClientId === c.id}
          <div class="inline-policy explain-panel">
            {#if explainError}<p class="error" role="alert">{explainError}</p>{/if}
            {#if explainResult}
              <p class="explain-summary">
                Network match: <strong>{explainResult.network_match ?? "none"}</strong>
                {#if explainResult.group_contributions.length}
                  &middot; Groups: <strong>{explainResult.group_contributions.join(", ")}</strong>
                {/if}
              </p>
              <table class="explain-table">
                <thead><tr><th>Field</th><th>Value</th><th>Source</th></tr></thead>
                <tbody>
                  {#each Object.entries(explainResult.fields) as [field, entry] (field)}
                    <tr>
                      <td>{field}</td>
                      <td>{String(entry.value)}</td>
                      <td>{entry.source}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}
          </div>
        {/if}
      {/if}
    {/snippet}
  </DataGrid>
  </Panel>

  <Panel heading="Groups">
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
                <PolicyEditor layer={g.policy} onSave={(l) => api.putGroupPolicy(g.group_id, l).then((res) => { refresh(); return res; })} />
              </div>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </Panel>

  <Panel heading="Observed Clients">
    <p class="scope-note">
      Addresses that have actually sent DNS queries recently (from real traffic data, not a discovery
      worker -- no history, no hostname/vendor detection). Loopback and unspecified addresses are never
      shown as a host. Use "Manage Client" to turn an observed address into a managed client.
    </p>
    {#if observedLoadError}<p class="error" role="alert">{observedLoadError}</p>{/if}
    {#if observedDegraded}<p class="hint">Observed traffic data degraded{observedDegradedReason ? `: ${observedDegradedReason}` : ""}.</p>{/if}
    {#if observed.length === 0 && !observedLoadError}
      <p class="hint">No recent traffic observed.</p>
    {:else}
      <ul class="observed-list">
        {#each observed as o (o.address)}
          <li class="observed-row">
            <code>{o.address}</code>
            <span class="hint">{o.query_count} quer{o.query_count === 1 ? "y" : "ies"}</span>
            {#if o.managed}
              <StatusBadge label="Managed" tone="healthy" />
            {:else}
              <StatusBadge label="Unmanaged" tone="neutral" />
              <button type="button" onclick={() => startManage(o.address)}>Manage Client</button>
            {/if}
          </li>
          {#if manageAddress === o.address}
            <li>
              <form onsubmit={submitManage} class="inline-form">
                <label><input type="radio" bind:group={manageMode} value="new" /> New client named <input bind:value={manageNewName} aria-label="New client name" /></label>
                <label>
                  <input type="radio" bind:group={manageMode} value="existing" disabled={managedClients.length === 0} />
                  Attach to existing
                  <select bind:value={manageExistingClientId} disabled={managedClients.length === 0}>
                    {#each managedClients as mc}
                      <option value={mc.id}>{mc.name}</option>
                    {/each}
                  </select>
                </label>
                <button type="submit" disabled={manageBusy}>{manageBusy ? "Saving…" : "Save"}</button>
                <button type="button" onclick={() => (manageAddress = null)}>Cancel</button>
                {#if manageError}<p class="error" role="alert">{manageError}</p>{/if}
              </form>
            </li>
          {/if}
        {/each}
      </ul>
    {/if}
  </Panel>
</section>

{#if addClientModalOpen}
  <Modal title="Add managed client" onClose={() => (addClientModalOpen = false)}>
    <form onsubmit={addClient} class="modal-form">
      <label>Name <input required bind:value={newClientName} /></label>
      <label>Description <input bind:value={newClientDescription} /></label>
      <div class="form-actions">
        <button type="submit" disabled={addClientBusy}>{addClientBusy ? "Adding…" : "Add client"}</button>
        <button type="button" class="secondary" onclick={() => (addClientModalOpen = false)}>Cancel</button>
      </div>
      {#if addClientError}<p class="error" role="alert">{addClientError}</p>{/if}
    </form>
  </Modal>
{/if}

{#if addGroupModalOpen}
  <Modal title="Add group" onClose={() => (addGroupModalOpen = false)}>
    <form onsubmit={addGroup} class="modal-form">
      <label>Name <input required bind:value={newGroupName} /></label>
      <label>Priority <input type="number" bind:value={newGroupPriority} /></label>
      <div class="form-actions">
        <button type="submit" disabled={addGroupBusy}>{addGroupBusy ? "Adding…" : "Add group"}</button>
        <button type="button" class="secondary" onclick={() => (addGroupModalOpen = false)}>Cancel</button>
      </div>
      {#if addGroupError}<p class="error" role="alert">{addGroupError}</p>{/if}
    </form>
  </Modal>
{/if}

{#if pendingConfirm}
  <ConfirmDialog
    title={pendingConfirm.title}
    message={pendingConfirm.message}
    confirmLabel={pendingConfirm.confirmLabel}
    onConfirm={runPendingConfirm}
    onCancel={() => (pendingConfirm = null)}
  />
{/if}

<style>
  .clients { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 44rem; }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .chips { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  .chip { background: var(--nav-hover-bg); padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.78rem; display: inline-flex; align-items: center; gap: 0.3rem; }
  .chip-x { background: none; border: none; cursor: pointer; padding: 0; font-size: 0.9rem; line-height: 1; opacity: 0.7; }
  .chip-x:hover { opacity: 1; }
  .override-block { background: color-mix(in srgb, red 12%, var(--nav-hover-bg)); }
  .override-allow { background: color-mix(in srgb, green 12%, var(--nav-hover-bg)); }
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
  .inline-form { display: flex; gap: 0.4rem; margin-top: 0.4rem; flex-wrap: wrap; align-items: center; }
  .group-list { margin: 0; padding-left: 1.2rem; font-size: 0.9rem; display: flex; flex-direction: column; gap: 0.5rem; }
  .group-row { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
  .inline-policy { margin: 0.5rem 0 0.5rem -1.2rem; padding: 0.75rem; border: 1px solid var(--border); border-radius: 6px; background: var(--card-bg); }
  .explain-summary { font-size: 0.85rem; margin: 0 0 0.5rem; }
  .explain-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  .explain-table th, .explain-table td { text-align: left; padding: 0.25rem 0.5rem; border-bottom: 1px solid var(--border); }

  .id-list { display: flex; flex-direction: column; gap: 0.5rem; }
  .clientid-row { border: 1px solid var(--border); border-radius: 6px; padding: 0.4rem 0.6rem; display: flex; flex-direction: column; gap: 0.3rem; font-size: 0.78rem; background: var(--card-bg); }
  .clientid-row.revoked { opacity: 0.6; }
  .clientid-main { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; }
  .clientid-chip { background: var(--accent, #4a7); color: var(--accent-fg, #fff); }
  .badge.revoked-badge { background: #a33; color: #fff; padding: 0.05rem 0.4rem; border-radius: 999px; font-size: 0.7rem; }
  .hexval { font-family: monospace; }
  .clientid-paths { display: flex; flex-direction: column; gap: 0.15rem; }
  .path-label { opacity: 0.7; margin-right: 0.3rem; }
  .clientid-paths code { font-family: monospace; word-break: break-all; }
  .clientid-actions { display: flex; gap: 0.3rem; flex-wrap: wrap; }
  .mini { font-size: 0.72rem; padding: 0.05rem 0.4rem; }
  .reveal-once { font-style: italic; }
  .danger { color: #c33; }
  .name-cell { display: flex; align-items: center; gap: 0.4rem; }
  .disabled-name { opacity: 0.55; text-decoration: line-through; }
  .badge.disabled-badge { background: #888; color: #fff; padding: 0.05rem 0.4rem; border-radius: 999px; font-size: 0.7rem; }
  .client-desc { margin: 0.15rem 0 0; }
  .edit-name-form { flex-direction: column; align-items: stretch; }
  .observed-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
  .observed-row { display: flex; align-items: center; gap: 0.6rem; }

  .search-input { min-width: 16rem; flex: 1 1 16rem; }
  button.secondary.small,
  button.small { min-height: auto; padding: 0.3rem 0.6rem; font-size: 0.8rem; }
  .modal-form { display: flex; flex-direction: column; gap: 0.75rem; }
  .modal-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .form-actions { display: flex; gap: 0.5rem; }
</style>
