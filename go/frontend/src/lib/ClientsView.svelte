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
    type ObservedRetentionSettings,
    type ObservedRetentionSchedule,
    type ClientAnalyticsRow,
  } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import { queryLogPrefill } from "../queryLogPrefill.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";
  import PolicyEditor from "./PolicyEditor.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
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
  // GET /api/clients/observed's Go doc comment) -- no first-seen
  // history, no hostname/vendor fingerprinting, no loopback/unspecified
  // addresses ever presented as a host.
  //
  // 2026-09 redesign: every per-row inline edit form (edit name, add
  // identifier, assign group, generate/revoke Strong ClientID, add
  // override, policy, explain) is consolidated into one "Add/Edit
  // Managed Client" modal with grouped sections, replacing eight
  // separate per-row toggle states with one -- see clientModal below.

  let activeTab = $state<"managed" | "observed">("managed");

  let managedClients = $state<ManagedClient[]>([]);
  let groups = $state<ClientGroup[]>([]);
  let loadError = $state("");
  const guard = new StaleGuard();

  // Client analytics: every client seen in the last 24h, used both for
  // the Managed Clients table's own "Recent queries"/"Last seen" columns
  // (best-effort join against a client's own identifier values -- there
  // is no direct managed-client-id -> raw-client foreign key, so a
  // client with no matching raw identifier honestly shows "--", not a
  // guess) and available as its own reference list.
  let analyticsRows = $state<ClientAnalyticsRow[]>([]);
  let analyticsDegraded = $state(false);
  let analyticsDegradedReason = $state("");

  async function loadAnalytics() {
    try {
      const resp = await api.topClients(1440, router.signal());
      analyticsRows = resp.clients;
      analyticsDegraded = resp.degraded;
      analyticsDegradedReason = resp.degraded_reason ?? "";
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
    }
  }

  function analyticsFor(c: ManagedClient): ClientAnalyticsRow | undefined {
    const values = new Set(c.identifiers.filter((i) => i.kind !== "clientid").map((i) => i.value));
    return analyticsRows.find((r) => values.has(r.raw_client) || r.raw_client === c.name);
  }

  function goToQueryLog(rawClient: string) {
    queryLogPrefill.setClient(rawClient);
    router.navigate("analytics");
  }

  function formatLastSeen(unixSeconds: number | undefined): string {
    if (!unixSeconds) return "—";
    return new Date(unixSeconds * 1000).toLocaleString();
  }

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

  let addGroupModalOpen = $state(false);

  let observed = $state<ObservedClient[]>([]);
  let observedDegraded = $state(false);
  let observedDegradedReason = $state("");
  let observedLoadError = $state("");
  let observedSearch = $state("");
  const observedGuard = new StaleGuard();
  const filteredObserved = $derived(
    observed.filter((o) => {
      if (!observedSearch.trim()) return true;
      const q = observedSearch.trim().toLowerCase();
      return o.address.toLowerCase().includes(q) || (o.alias_label ?? "").toLowerCase().includes(q);
    }),
  );

  // Observed Clients retention.
  let retentionSettings = $state<ObservedRetentionSettings | null>(null);
  let retentionLoadError = $state("");
  let retentionSaving = $state(false);
  let retentionSaveError = $state("");
  let retentionSaveResult = $state("");
  let retentionPreviewCount = $state<number | null>(null);
  let retentionPreviewError = $state("");
  let retentionCleaning = $state(false);
  let retentionCleanError = $state("");
  let retentionCleanResult = $state("");
  let retentionDialogOpen = $state(false);
  let retentionDaysDraft = $state(90);
  let retentionScheduleDraft = $state<ObservedRetentionSchedule>("manual");

  async function loadRetentionSettings() {
    try {
      retentionSettings = await api.getObservedRetentionSettings();
      retentionDaysDraft = retentionSettings.retention_days;
      retentionScheduleDraft = retentionSettings.schedule;
      retentionLoadError = "";
      await refreshRetentionPreview();
    } catch (err) {
      retentionLoadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  async function refreshRetentionPreview() {
    retentionPreviewError = "";
    try {
      const resp = await api.previewObservedRetention(retentionDaysDraft);
      retentionPreviewCount = resp.degraded ? null : resp.would_remove_clients;
      if (resp.degraded) retentionPreviewError = resp.degraded_reason || "unavailable";
    } catch (err) {
      retentionPreviewCount = null;
      retentionPreviewError = err instanceof ApiError ? err.message : String(err);
    }
  }

  /** Best-effort estimate only -- the backend records the last run, not a
   * computed next-run time. Disclosed as an estimate, never presented as
   * a scheduled fact the server itself will honor to the minute. */
  const nextCleanupEstimate = $derived.by(() => {
    if (!retentionSettings || retentionScheduleDraft === "manual") return null;
    const days = retentionScheduleDraft === "daily" ? 1 : retentionScheduleDraft === "weekly" ? 7 : 30;
    const base = retentionSettings.last_run_at ? new Date(retentionSettings.last_run_at).getTime() : Date.now();
    return new Date(base + days * 86_400_000);
  });

  async function saveRetentionSettings(e: Event) {
    e.preventDefault();
    retentionSaving = true;
    retentionSaveError = "";
    retentionSaveResult = "";
    try {
      retentionSettings = await api.updateObservedRetentionSettings(retentionDaysDraft, retentionScheduleDraft);
      retentionSaveResult = "Saved.";
      await refreshRetentionPreview();
    } catch (err) {
      retentionSaveError = err instanceof ApiError ? err.message : String(err);
    } finally {
      retentionSaving = false;
    }
  }

  function confirmCleanNow() {
    const count = retentionPreviewCount;
    askConfirm(
      "Clean old observed clients",
      count === null
        ? `This will permanently remove every observed client not seen in the last ${retentionDaysDraft} days (and their query history). Recently-seen clients are never touched. This cannot be undone.`
        : `This will permanently remove ${count} observed client${count === 1 ? "" : "s"} not seen in the last ${retentionDaysDraft} days (and their query history). Recently-seen clients are never touched. This cannot be undone.`,
      "Clean now",
      cleanRetentionNow,
    );
  }

  async function cleanRetentionNow() {
    retentionCleaning = true;
    retentionCleanError = "";
    retentionCleanResult = "";
    try {
      const resp = await api.cleanObservedRetention();
      retentionCleanResult = resp.removed_clients === 0
        ? "No stale observed clients to remove."
        : `Removed ${resp.removed_clients} observed client${resp.removed_clients === 1 ? "" : "s"}.`;
      await Promise.all([refreshObserved(), loadRetentionSettings()]);
    } catch (err) {
      retentionCleanError = err instanceof ApiError ? err.message : String(err);
    } finally {
      retentionCleaning = false;
    }
  }

  // Shared destructive-action confirm dialog.
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

  // --- "Save as Managed Client" (an observed address -> a real managed
  // client), a compact modal distinct from the full editor below. ---
  let manageAddress = $state<string | null>(null);
  let manageMode = $state<"new" | "existing">("new");
  let manageNewName = $state("");
  let manageExistingClientId = $state<number | null>(null);
  let manageError = $state("");
  let manageBusy = $state(false);

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

  // --- Add/Edit Managed Client: one dedicated modal, grouped sections
  // (Identity / Addresses & identifiers / Group assignment / Filtering,
  // security & policy / Domain overrides / Effective-policy preview).
  // `clientModal` holds the id of the client being edited, or the
  // sentinel "new" while the compact create step is showing (which,
  // on success, becomes the same editor for the freshly created client
  // -- Add flows straight into Edit rather than being a separate form). ---
  let clientModal = $state<number | "new" | null>(null);
  const editingClient = $derived(typeof clientModal === "number" ? managedClients.find((c) => c.id === clientModal) ?? null : null);

  let newClientName = $state("");
  let newClientDescription = $state("");
  let addClientBusy = $state(false);
  let addClientError = $state("");

  function openAddClient() {
    newClientName = "";
    newClientDescription = "";
    addClientError = "";
    clientModal = "new";
  }

  async function submitAddClient(e: Event) {
    e.preventDefault();
    addClientError = "";
    addClientBusy = true;
    try {
      const created = await api.createClient(newClientName, newClientDescription);
      await refresh();
      clientModal = created.client_id;
      toast.success(`Created client "${newClientName}". Continue configuring it below.`);
    } catch (err) {
      addClientError = err instanceof ApiError ? err.message : String(err);
    } finally {
      addClientBusy = false;
    }
  }

  let editName = $state("");
  let editDescription = $state("");
  let editIdentityError = $state("");
  let editIdentityBusy = $state(false);

  $effect(() => {
    if (editingClient) {
      editName = editingClient.name;
      editDescription = editingClient.description;
    }
  });

  async function saveIdentity(e: Event) {
    e.preventDefault();
    if (!editingClient) return;
    editIdentityError = "";
    editIdentityBusy = true;
    try {
      await api.updateClient(editingClient.id, editName, editDescription);
      await refresh();
      toast.success("Saved.");
    } catch (err) {
      editIdentityError = err instanceof ApiError ? err.message : String(err);
    } finally {
      editIdentityBusy = false;
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
        clientModal = null;
        await Promise.all([refresh(), refreshObserved()]);
        toast.success(`Deleted client "${c.name}".`);
      },
    );
  }

  function deleteIpIdentifier(c: ManagedClient, id: ClientIdentifier) {
    askConfirm("Remove identifier", `Remove identifier ${id.value} from "${c.name}"?`, "Remove", async () => {
      await api.deleteClientIdentifier(c.id, id.id);
      await Promise.all([refresh(), refreshObserved()]);
      toast.success(`Removed identifier ${id.value}.`);
    });
  }

  let identifierKind = $state<"ipv4" | "ipv4_cidr" | "ipv6" | "ipv6_cidr">("ipv4");
  let identifierValue = $state("");
  let identifierError = $state("");

  async function submitIdentifier(e: Event) {
    e.preventDefault();
    if (!editingClient) return;
    identifierError = "";
    try {
      await api.addClientIdentifier(editingClient.id, identifierKind, identifierValue);
      identifierValue = "";
      await refresh();
    } catch (err) {
      identifierError = err instanceof ApiError ? err.message : String(err);
    }
  }

  let groupAssignGroupId = $state("");
  async function submitAssignGroup(e: Event) {
    e.preventDefault();
    if (!editingClient || !groupAssignGroupId) return;
    await api.addClientToGroup(editingClient.id, groupAssignGroupId);
    await refresh();
  }
  async function removeFromGroup(c: ManagedClient, groupId: string) {
    await api.removeClientFromGroup(c.id, groupId);
    await refresh();
  }

  let generateBits = $state<192 | 256>(256);
  let generateLabel = $state("");
  let generateBusy = $state(false);
  let generateError = $state("");
  let lastGenerated = $state<{ clientId: number; identifier: ClientIdentifier } | null>(null);

  async function submitGenerateClientID(e: Event) {
    e.preventDefault();
    if (!editingClient) return;
    generateError = "";
    generateBusy = true;
    try {
      const result = await api.generateClientID(editingClient.id, generateBits, generateLabel);
      lastGenerated = { clientId: editingClient.id, identifier: result.identifier };
      generateLabel = "";
      await refresh();
    } catch (err) {
      generateError = err instanceof ApiError ? err.message : String(err);
    } finally {
      generateBusy = false;
    }
  }

  function revokeIdentifier(c: ManagedClient, id: ClientIdentifier) {
    const label = id.label || id.value.slice(0, 12) + "…";
    askConfirm("Revoke Strong ClientID", `Revoke this Strong ClientID (${label})? DoH/DoT/DoQ traffic using it will stop being recognized once applied.`, "Revoke", async () => {
      await api.revokeClientIdentifier(c.id, id.id);
      await refresh();
      toast.success(`Revoked identifier ${label}.`);
    });
  }
  function regenerateIdentifier(c: ManagedClient, id: ClientIdentifier) {
    const label = id.label || id.value.slice(0, 12) + "…";
    askConfirm("Regenerate Strong ClientID", `Regenerate this Strong ClientID (${label})? The old value stops working immediately once applied; a new one replaces it.`, "Regenerate", async () => {
      const result = await api.regenerateClientIdentifier(c.id, id.id);
      lastGenerated = { clientId: c.id, identifier: result.identifier };
      await refresh();
      toast.success(`Regenerated identifier ${label}.`);
    });
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

  let overrideType = $state<"block" | "allow">("block");
  let overridePattern = $state("");
  let overrideError = $state("");
  async function submitAddOverride(e: Event) {
    e.preventDefault();
    if (!editingClient) return;
    overrideError = "";
    try {
      await api.addClientDomainOverride(editingClient.id, overrideType, overridePattern);
      overridePattern = "";
      await refresh();
    } catch (err) {
      overrideError = err instanceof ApiError ? err.message : String(err);
    }
  }
  async function deleteOverride(c: ManagedClient, overrideId: number) {
    await api.deleteClientDomainOverride(c.id, overrideId);
    await refresh();
  }

  let explainResult = $state<PolicyExplainResult | null>(null);
  let explainError = $state("");
  let explainLoading = $state(false);
  async function loadExplain(c: ManagedClient) {
    explainLoading = true;
    explainResult = null;
    explainError = "";
    try {
      explainResult = await api.explainPolicy(c.id);
    } catch (err) {
      explainError = err instanceof ApiError ? err.message : String(err);
    } finally {
      explainLoading = false;
    }
  }
  $effect(() => {
    if (editingClient) loadExplain(editingClient);
  });

  function copyToClipboard(text: string) {
    navigator.clipboard?.writeText(text).catch(() => {});
  }

  // --- Groups (kept as its own small modal, reachable from the header). ---
  let newGroupName = $state("");
  let newGroupPriority = $state(0);
  let addGroupBusy = $state(false);
  let addGroupError = $state("");
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
    loadRetentionSettings();
  });

  function policySummary(p: ManagedClient["policy"]): string {
    const set = [
      p.filtering_profile_id && "filtering", p.parental_policy_id && "parental", p.security_policy_id && "security",
      p.service_blocking_ruleset_id && "blocked services", p.upstream_profile_id && "upstream",
      p.domain_routing_ruleset_id && "routing",
    ].filter(Boolean);
    return set.length ? `Custom (${set.join(", ")})` : "Inherited";
  }

  const managedColumns: Column<ManagedClient>[] = [
    { key: "name", label: "Name", sortValue: (c) => c.name.toLowerCase(), minWidth: 14 },
    { key: "identifiers", label: "Identifiers", minWidth: 16 },
    { key: "group", label: "Group / network", minWidth: 12 },
    { key: "policy", label: "Effective policy", minWidth: 16 },
    { key: "blocked_services", label: "Blocked services", minWidth: 12 },
    { key: "upstream", label: "Upstream / routing", minWidth: 12 },
    { key: "logging", label: "Logging / stats", minWidth: 10 },
    { key: "recent", label: "Recent queries", sortValue: (c) => analyticsFor(c)?.value ?? -1, minWidth: 10 },
    { key: "last_seen", label: "Last seen", sortValue: (c) => analyticsFor(c)?.last_seen ?? 0, minWidth: 14 },
    { key: "actions", label: "Actions", minWidth: 10 },
  ];

  const observedColumns: Column<ObservedClient>[] = [
    { key: "address", label: "Address", sortValue: (o) => o.address, minWidth: 14 },
    { key: "alias", label: "Resolved name / alias", sortValue: (o) => o.alias_label ?? "", minWidth: 16 },
    { key: "source", label: "Detection source", minWidth: 12 },
    { key: "last_seen", label: "Last seen", minWidth: 10 },
    { key: "count", label: "Query count", sortValue: (o) => o.query_count, minWidth: 10 },
    { key: "status", label: "Status", minWidth: 10 },
    { key: "actions", label: "Actions", minWidth: 12 },
  ];
</script>

<PageHeader
  title="Clients"
  headingId="clients-heading"
  description="Managed clients (with real identity, policy, and Strong ClientID enforcement) and observed clients (real recent traffic, no history)."
>
  {#snippet actions()}
    {#if activeTab === "managed"}
      <button type="button" onclick={openAddClient}>Add Managed Client</button>
      <button type="button" class="secondary" onclick={() => { addGroupError = ""; addGroupModalOpen = true; }}>Manage Groups</button>
    {/if}
  {/snippet}
</PageHeader>
{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

<div class="tabs" role="tablist" aria-label="Client views">
  <button type="button" role="tab" aria-selected={activeTab === "managed"} class:active={activeTab === "managed"} onclick={() => (activeTab = "managed")}>
    Managed Clients <span class="tab-count">{managedClients.length}</span>
  </button>
  <button type="button" role="tab" aria-selected={activeTab === "observed"} class:active={activeTab === "observed"} onclick={() => (activeTab = "observed")}>
    Observed Clients <span class="tab-count">{observed.length}</span>
  </button>
</div>

{#if activeTab === "managed"}
  <div class="toolbar">
    <input class="search-input" placeholder="Search name, description, address, group…" bind:value={clientSearch} aria-label="Search managed clients" />
    <select bind:value={statusFilter} aria-label="Filter by status">
      <option value="all">All statuses</option>
      <option value="enabled">Enabled</option>
      <option value="disabled">Disabled</option>
    </select>
  </div>
  {#if analyticsDegraded}<p class="hint">Recent-queries/Last-seen data degraded{analyticsDegradedReason ? `: ${analyticsDegradedReason}` : ""} -- other columns are still real.</p>{/if}

  <DataGrid gridId="managed-clients" columns={managedColumns} rows={filteredManagedClients} rowKey={(c) => c.id} emptyMessage={managedClients.length === 0 ? "No managed clients yet." : "No clients match this search/filter."}>
    {#snippet cell(c, colKey)}
      {@const a = analyticsFor(c)}
      {#if colKey === "name"}
        <button type="button" class="row-link" onclick={() => (clientModal = c.id)}>{c.name}</button>
        {#if !c.enabled}<span class="badge disabled-badge">disabled</span>{/if}
      {:else if colKey === "identifiers"}
        <span class="chips">
          {#each c.identifiers as id (id.id)}
            <span class="chip">{id.kind === "clientid" ? `Strong ClientID${id.revoked_at ? " (revoked)" : ""}` : id.value}</span>
          {/each}
          {#if c.identifiers.length === 0}<span class="hint">none</span>{/if}
        </span>
      {:else if colKey === "group"}
        {c.groups.map((g) => g.name).join(", ") || "—"}
      {:else if colKey === "policy"}
        {policySummary(c.policy)}
      {:else if colKey === "blocked_services"}
        {c.policy.service_blocking_ruleset_id ?? "Inherited"}
      {:else if colKey === "upstream"}
        {c.policy.upstream_profile_id ?? "Inherited"}
      {:else if colKey === "logging"}
        {c.policy.query_log_enabled === null ? "Inherit" : c.policy.query_log_enabled ? "On" : "Off"}
      {:else if colKey === "recent"}
        {#if a}
          {a.value.toLocaleString()}
          {#if a.blocked > 0}<span class="hint"> ({a.blocked} blocked, {a.blocked_percent.toFixed(1)}%)</span>{/if}
        {:else}
          —
        {/if}
      {:else if colKey === "last_seen"}
        {formatLastSeen(a?.last_seen)}
      {:else if colKey === "actions"}
        <div class="actions">
          <button type="button" class="secondary small" onclick={() => (clientModal = c.id)}>Edit</button>
          {#if a}<button type="button" class="secondary small" onclick={() => goToQueryLog(a.raw_client)}>Query Log</button>{/if}
          <button type="button" class="secondary small" onclick={() => toggleEnabled(c)}>{c.enabled ? "Disable" : "Enable"}</button>
          <button type="button" class="secondary small danger" onclick={() => deleteClient(c)}>Delete</button>
        </div>
      {/if}
    {/snippet}
  </DataGrid>
{:else}
  <div class="toolbar">
    <input class="search-input" placeholder="Search address or alias…" bind:value={observedSearch} aria-label="Search observed clients" />
    <button type="button" class="secondary" onclick={() => (retentionDialogOpen = true)}>Retention…</button>
  </div>
  <p class="hint retention-summary">
    {#if retentionSettings}
      Retention: remove after {retentionSettings.retention_days} days unseen, schedule {retentionScheduleDraft}.
      {#if retentionSettings.last_run_at}Last cleanup {new Date(retentionSettings.last_run_at).toLocaleString()}.{:else}Never run yet.{/if}
      {#if nextCleanupEstimate}Next estimated {nextCleanupEstimate.toLocaleString()}.{/if}
    {/if}
  </p>

  {#if observedLoadError}<p class="error" role="alert">{observedLoadError}</p>{/if}
  {#if observedDegraded}<p class="hint">Observed traffic data degraded{observedDegradedReason ? `: ${observedDegradedReason}` : ""}.</p>{/if}

  <DataGrid gridId="observed-clients" columns={observedColumns} rows={filteredObserved} rowKey={(o) => o.address} emptyMessage="No recent traffic observed.">
    {#snippet cell(o, colKey)}
      {#if colKey === "address"}
        <code>{o.address}</code>
      {:else if colKey === "alias"}
        {o.alias_label ?? "—"}
      {:else if colKey === "source"}
        Real DNS traffic (last 24h)
      {:else if colKey === "last_seen"}
        Within window
      {:else if colKey === "count"}
        {o.query_count}
      {:else if colKey === "status"}
        {#if o.managed}<StatusBadge label="Managed" tone="healthy" />{:else}<StatusBadge label="Unmanaged" tone="neutral" />{/if}
      {:else if colKey === "actions"}
        {#if !o.managed}
          <button type="button" class="secondary small" onclick={() => startManage(o.address)}>Save as Managed Client</button>
        {/if}
      {/if}
    {/snippet}
  </DataGrid>
{/if}

{#if manageAddress !== null}
  <Modal title="Save as Managed Client" onClose={() => (manageAddress = null)}>
    <form onsubmit={submitManage} class="modal-form">
      <label class="radio-label"><input type="radio" bind:group={manageMode} value="new" /> New client named <input bind:value={manageNewName} aria-label="New client name" /></label>
      <label class="radio-label">
        <input type="radio" bind:group={manageMode} value="existing" disabled={managedClients.length === 0} />
        Attach to existing
        <select bind:value={manageExistingClientId} disabled={managedClients.length === 0}>
          {#each managedClients as mc}<option value={mc.id}>{mc.name}</option>{/each}
        </select>
      </label>
      <div class="form-actions">
        <button type="submit" disabled={manageBusy}>{manageBusy ? "Saving…" : "Save"}</button>
        <button type="button" class="secondary" onclick={() => (manageAddress = null)}>Cancel</button>
      </div>
      {#if manageError}<p class="error" role="alert">{manageError}</p>{/if}
    </form>
  </Modal>
{/if}

{#if retentionDialogOpen && retentionSettings}
  <Modal title="Observed Clients retention" onClose={() => (retentionDialogOpen = false)}>
    <p class="hint">
      Observed Clients otherwise accumulates forever. An address that has queried at all within the
      window below is never touched, no matter how old its earliest activity is.
    </p>
    <form onsubmit={saveRetentionSettings} class="retention-form">
      <label>
        Remove clients not seen in
        <input type="number" min="1" max="3650" bind:value={retentionDaysDraft} oninput={refreshRetentionPreview} aria-label="Retention days" /> days
      </label>
      <label>
        Automatic schedule
        <select bind:value={retentionScheduleDraft} aria-label="Auto-clean schedule">
          <option value="manual">Manual only (never auto-runs)</option>
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="monthly">Monthly</option>
        </select>
      </label>
      <button type="submit" disabled={retentionSaving}>{retentionSaving ? "Saving…" : "Save settings"}</button>
      {#if retentionSaveResult}<span class="success" role="status">{retentionSaveResult}</span>{/if}
      {#if retentionSaveError}<p class="error" role="alert">{retentionSaveError}</p>{/if}
    </form>

    <p class="hint preview-line">
      {#if retentionPreviewError}
        Preview unavailable: {retentionPreviewError}
      {:else if retentionPreviewCount === null}
        Calculating how many clients this would remove…
      {:else if retentionPreviewCount === 0}
        No observed clients currently qualify for removal at {retentionDaysDraft} days.
      {:else}
        This would currently remove <strong>{retentionPreviewCount}</strong> observed client{retentionPreviewCount === 1 ? "" : "s"} not seen in {retentionDaysDraft} days.
      {/if}
    </p>
    {#if nextCleanupEstimate}<p class="hint">Next estimated automatic cleanup: {nextCleanupEstimate.toLocaleString()} (estimated from schedule -- not a server-tracked exact time).</p>{/if}

    <div class="form-actions">
      <button type="button" class="danger-btn" onclick={confirmCleanNow} disabled={retentionCleaning || retentionPreviewCount === 0}>
        {retentionCleaning ? "Cleaning…" : "Run Cleanup Now"}
      </button>
    </div>
    {#if retentionCleanResult}<p class="success" role="status">{retentionCleanResult}</p>{/if}
    {#if retentionCleanError}<p class="error" role="alert">{retentionCleanError}</p>{/if}
    {#if retentionSettings.last_run_at}
      <p class="hint">
        Last cleanup: {new Date(retentionSettings.last_run_at).toLocaleString()} --
        {retentionSettings.last_status === "succeeded"
          ? `removed ${retentionSettings.last_removed_clients} client${retentionSettings.last_removed_clients === 1 ? "" : "s"}.`
          : `failed${retentionSettings.last_error ? `: ${retentionSettings.last_error}` : ""}.`}
      </p>
    {/if}
  </Modal>
{/if}

{#if clientModal === "new"}
  <Modal title="Add Managed Client" onClose={() => (clientModal = null)}>
    <form onsubmit={submitAddClient} class="modal-form">
      <label>Name <input required bind:value={newClientName} /></label>
      <label>Description <input bind:value={newClientDescription} /></label>
      <p class="hint">Identifiers, group assignment, policy, and domain overrides can be added on the next screen once the client exists.</p>
      <div class="form-actions">
        <button type="submit" disabled={addClientBusy}>{addClientBusy ? "Creating…" : "Create and continue"}</button>
        <button type="button" class="secondary" onclick={() => (clientModal = null)}>Cancel</button>
      </div>
      {#if addClientError}<p class="error" role="alert">{addClientError}</p>{/if}
    </form>
  </Modal>
{:else if editingClient}
  {@const c = editingClient}
  <Modal title={`Edit ${c.name}`} onClose={() => (clientModal = null)}>
    <div class="editor-sections">
      <section class="editor-section">
        <h3>Identity</h3>
        <form onsubmit={saveIdentity} class="inline-form">
          <input required bind:value={editName} aria-label="Client name" placeholder="Name" />
          <input bind:value={editDescription} placeholder="Description" aria-label="Client description" />
          <button type="submit" disabled={editIdentityBusy}>{editIdentityBusy ? "Saving…" : "Save"}</button>
          <button type="button" class="secondary small" onclick={() => toggleEnabled(c)}>{c.enabled ? "Disable" : "Enable"}</button>
        </form>
        {#if editIdentityError}<p class="error" role="alert">{editIdentityError}</p>{/if}
      </section>

      <section class="editor-section">
        <h3>Addresses &amp; identifiers</h3>
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
                    <button type="button" class="mini" onclick={() => regenerateIdentifier(c, id)}>Regenerate</button>
                    <button type="button" class="mini" onclick={() => revokeIdentifier(c, id)}>Revoke</button>
                    <button type="button" class="mini" onclick={() => deleteIdentifier(c, id)}>Delete</button>
                  </div>
                {:else}
                  <div class="clientid-actions"><button type="button" class="mini" onclick={() => deleteIdentifier(c, id)}>Delete</button></div>
                {/if}
              </div>
            {:else}
              <span class="chip">{id.kind}: {id.value}<button type="button" class="chip-x" onclick={() => deleteIpIdentifier(c, id)} aria-label="Remove identifier">×</button></span>
            {/if}
          {/each}
          {#if lastGenerated && lastGenerated.clientId === c.id}
            <p class="hint reveal-once">New Strong ClientID generated -- shown once above; the full hex value is always retrievable via "Copy hex" afterward.</p>
          {/if}
        </div>
        <form onsubmit={submitIdentifier} class="inline-form">
          <select bind:value={identifierKind} aria-label="Identifier kind">
            <option value="ipv4">IPv4</option><option value="ipv4_cidr">IPv4 CIDR</option>
            <option value="ipv6">IPv6</option><option value="ipv6_cidr">IPv6 CIDR</option>
          </select>
          <input required bind:value={identifierValue} placeholder="Address" aria-label="Identifier value" />
          <button type="submit">Add address</button>
        </form>
        {#if identifierError}<p class="error" role="alert">{identifierError}</p>{/if}
        <form onsubmit={submitGenerateClientID} class="inline-form">
          <select bind:value={generateBits} aria-label="Strong ClientID bits">
            <option value={256}>256-bit Strong ClientID</option>
            <option value={192}>192-bit Strong ClientID</option>
          </select>
          <input bind:value={generateLabel} placeholder="Label (optional)" aria-label="ClientID label" />
          <button type="submit" disabled={generateBusy}>{generateBusy ? "Generating…" : "Generate"}</button>
        </form>
        {#if generateError}<p class="error" role="alert">{generateError}</p>{/if}
      </section>

      <section class="editor-section">
        <h3>Group / network assignment</h3>
        <span class="chips">
          {#each c.groups as g}<span class="chip">{g.name}<button type="button" class="chip-x" onclick={() => removeFromGroup(c, g.group_id)} aria-label="Remove from group">×</button></span>{/each}
          {#if c.groups.length === 0}<span class="hint">No groups assigned.</span>{/if}
        </span>
        <form onsubmit={submitAssignGroup} class="inline-form">
          <select bind:value={groupAssignGroupId} aria-label="Assign to group">
            <option value="">Choose a group…</option>
            {#each groups as g}<option value={g.group_id}>{g.name}</option>{/each}
          </select>
          <button type="submit" disabled={!groupAssignGroupId}>Assign</button>
        </form>
      </section>

      <section class="editor-section">
        <h3>Filtering, security &amp; policy</h3>
        <p class="hint">Covers filtering profile, parental/SafeSearch policy, security policy, blocked services, upstream and domain-routing policy, ECS, and query-log/statistics controls. Anything left "(Inherit)" falls back to this client's group, then network, then the global default.</p>
        <PolicyEditor layer={c.policy} onSave={(l) => api.putClientPolicy(c.id, l).then((res) => { refresh(); loadExplain(c); return res; })} />
      </section>

      <section class="editor-section">
        <h3>Domain overrides</h3>
        <p class="hint">Explicit per-client block/allow, enforced only when this client is identified via a Strong ClientID (DoH path or DoT/DoQ SNI) -- a real override beats any policy above.</p>
        <span class="chips">
          {#each c.domain_overrides as o (o.id)}
            <span class="chip" class:override-block={o.override_type === "block"} class:override-allow={o.override_type === "allow"}>
              {o.override_type}: {o.pattern}<button type="button" class="chip-x" onclick={() => deleteOverride(c, o.id)} aria-label="Remove override">×</button>
            </span>
          {/each}
        </span>
        <form onsubmit={submitAddOverride} class="inline-form">
          <select bind:value={overrideType} aria-label="Override type"><option value="block">Block</option><option value="allow">Allow</option></select>
          <input required bind:value={overridePattern} placeholder="Domain (e.g. ads.example.com)" aria-label="Override domain" />
          <button type="submit">Add override</button>
        </form>
        {#if overrideError}<p class="error" role="alert">{overrideError}</p>{/if}
      </section>

      <section class="editor-section">
        <h3>Effective-policy preview</h3>
        {#if explainLoading}<p class="hint">Loading…</p>{/if}
        {#if explainError}<p class="error" role="alert">{explainError}</p>{/if}
        {#if explainResult}
          <p class="explain-summary">
            Network match: <strong>{explainResult.network_match ?? "none"}</strong>
            {#if explainResult.group_contributions.length}&middot; Groups: <strong>{explainResult.group_contributions.join(", ")}</strong>{/if}
          </p>
          <table class="explain-table">
            <thead><tr><th>Field</th><th>Value</th><th>Source</th></tr></thead>
            <tbody>
              {#each Object.entries(explainResult.fields) as [field, entry] (field)}
                <tr><td>{field}</td><td>{String(entry.value)}</td><td>{entry.source}</td></tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </section>

      <div class="editor-danger">
        <button type="button" class="danger-btn" onclick={() => deleteClient(c)}>Delete this client</button>
      </div>
    </div>
  </Modal>
{/if}

{#if addGroupModalOpen}
  <Modal title="Manage Groups" onClose={() => (addGroupModalOpen = false)}>
    {#if groups.length === 0}
      <p class="hint">No groups yet.</p>
    {:else}
      <ul class="group-list">
        {#each groups as g}
          <li>
            <div class="group-row">
              <span><strong>{g.name}</strong> (priority {g.priority}) -- {g.members.length} member{g.members.length === 1 ? "" : "s"}</span>
              <button type="button" class="secondary small" onclick={() => (policyEditorGroupId = policyEditorGroupId === g.group_id ? null : g.group_id)}>Policy</button>
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
    <form onsubmit={addGroup} class="modal-form add-group-form">
      <h3>Add group</h3>
      <label>Name <input required bind:value={newGroupName} /></label>
      <label>Priority <input type="number" bind:value={newGroupPriority} /></label>
      <div class="form-actions">
        <button type="submit" disabled={addGroupBusy}>{addGroupBusy ? "Adding…" : "Add group"}</button>
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
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .error { color: var(--danger); }
  .success { color: var(--success); }

  .tabs { display: flex; gap: 0.3rem; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }
  .tabs button { background: transparent; color: var(--muted); border: none; border-bottom: 2px solid transparent; border-radius: 0; padding: 0.6rem 0.2rem; margin-right: 1.25rem; font-weight: 600; min-height: auto; }
  .tabs button.active { color: var(--fg); border-bottom-color: var(--accent); }
  .tab-count { font-weight: 400; opacity: 0.6; font-size: 0.85rem; }

  .toolbar { display: flex; flex-wrap: wrap; gap: 0.6rem; margin-bottom: 0.75rem; align-items: center; }
  .search-input { min-width: 16rem; flex: 1 1 16rem; }
  .retention-summary { margin: -0.25rem 0 0.75rem; }

  .row-link { background: transparent; color: var(--accent); border: none; padding: 0; font: inherit; font-weight: 600; cursor: pointer; text-decoration: underline; }
  .chips { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  .chip { background: var(--nav-hover-bg); padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.78rem; display: inline-flex; align-items: center; gap: 0.3rem; }
  .chip-x { background: none; border: none; cursor: pointer; padding: 0; font-size: 0.9rem; line-height: 1; opacity: 0.7; }
  .chip-x:hover { opacity: 1; }
  .override-block { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
  .override-allow { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .actions { display: flex; gap: 0.35rem; flex-wrap: wrap; }
  .badge.disabled-badge, .badge.revoked-badge { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.05rem 0.4rem; border-radius: 999px; font-size: 0.7rem; margin-left: 0.4rem; }

  button.secondary.small, button.small, .mini { min-height: auto; padding: 0.3rem 0.6rem; font-size: 0.78rem; }
  .danger { color: var(--danger); }
  .danger-btn { background: var(--badge-danger-bg); color: var(--badge-danger-fg); border-color: transparent; }

  .modal-form { display: flex; flex-direction: column; gap: 0.75rem; }
  .modal-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .radio-label { flex-direction: row !important; align-items: center; gap: 0.5rem !important; flex-wrap: wrap; }
  .form-actions { display: flex; gap: 0.5rem; }

  .editor-sections { display: flex; flex-direction: column; gap: 1.25rem; }
  .editor-section h3 { margin: 0 0 0.5rem; font-size: 0.9rem; }
  .editor-section > .hint { margin-bottom: 0.5rem; }
  .inline-form { display: flex; gap: 0.4rem; margin-top: 0.5rem; flex-wrap: wrap; align-items: center; }
  .id-list { display: flex; flex-direction: column; gap: 0.5rem; }
  .clientid-row { border: 1px solid var(--border); border-radius: 6px; padding: 0.4rem 0.6rem; display: flex; flex-direction: column; gap: 0.3rem; font-size: 0.78rem; background: var(--panel-elevated); }
  .clientid-row.revoked { opacity: 0.6; }
  .clientid-main { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; }
  .clientid-chip { background: var(--accent); color: var(--accent-fg); }
  .hexval { font-family: monospace; }
  .clientid-paths { display: flex; flex-direction: column; gap: 0.15rem; }
  .path-label { opacity: 0.7; margin-right: 0.3rem; }
  .clientid-paths code { font-family: monospace; word-break: break-all; }
  .clientid-actions { display: flex; gap: 0.3rem; flex-wrap: wrap; }
  .reveal-once { font-style: italic; }
  .explain-summary { font-size: 0.85rem; margin: 0 0 0.5rem; }
  .explain-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  .explain-table th, .explain-table td { text-align: left; padding: 0.25rem 0.5rem; border-bottom: 1px solid var(--border); }
  .editor-danger { border-top: 1px solid var(--border); padding-top: 1rem; }

  .group-list { margin: 0 0 1rem; padding-left: 1.2rem; font-size: 0.9rem; display: flex; flex-direction: column; gap: 0.5rem; }
  .group-row { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
  .inline-policy { margin: 0.5rem 0 0.5rem -1.2rem; padding: 0.75rem; border: 1px solid var(--border); border-radius: 6px; background: var(--card-bg); }
  .add-group-form { border-top: 1px solid var(--border); padding-top: 1rem; }
  .add-group-form h3 { margin: 0 0 0.5rem; font-size: 0.9rem; }

  .retention-form { display: flex; flex-wrap: wrap; align-items: end; gap: 1rem; }
  .retention-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .retention-form input[type="number"] { width: 6rem; }
  .preview-line { margin: 0.5rem 0; }
</style>
