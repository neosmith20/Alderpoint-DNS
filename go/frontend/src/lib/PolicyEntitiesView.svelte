<script lang="ts">
  // Owner-facing CRUD for the four real entities policy scopes (Scope
  // Policies / DNS Settings) reference: Filtering Profiles, Parental
  // Policies (own SafeSearch mode), Security Policies, and Service
  // Blocking Rulesets -- see internal/policyentities' own doc comment.
  // Every one of these, once assigned to a network/group/client's
  // policy, is a real compiled DNS-runtime effect
  // (internal/dnsruntime's computeScopeOverrides), not a stored-only
  // label.
  //
  // 2026-09 redesign: tabs (one entity type at a time, full-width table,
  // Add opens a dedicated modal) replace the previous four side-by-side
  // cards each with its own tiny inline Add form -- exactly the pattern
  // the redesign spec calls out to avoid.
  import { onMount } from "svelte";
  import { api, ApiError, type CategoryEntity, type ParentalPolicy, type ServiceBlockingRuleset, type DNSRuntimeApplyResult } from "../api";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";
  import Modal from "./ui/Modal.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";

  type EntityKind = "filtering" | "parental" | "security" | "service";
  const TABS: { key: EntityKind; label: string; description: string }[] = [
    { key: "filtering", label: "Filtering Profiles", description: "A named set of blocklist categories to enforce for whichever scope selects it." },
    { key: "parental", label: "Parental Policies", description: "A named SafeSearch mode + category set (e.g. adult content) for a network, group, or client." },
    { key: "security", label: "Security Policies", description: "A named security-oriented category set (malware, telemetry, etc.)." },
    { key: "service", label: "Service Blocking Rulesets", description: "A named list of specific domains (e.g. one app/service) to block -- independent of the blocklist-category system above." },
  ];
  let activeTab = $state<EntityKind>("filtering");

  let filteringProfiles = $state<CategoryEntity[]>([]);
  let securityPolicies = $state<CategoryEntity[]>([]);
  let parentalPolicies = $state<ParentalPolicy[]>([]);
  let serviceRulesets = $state<ServiceBlockingRuleset[]>([]);
  let loadError = $state("");
  let lastRuntime = $state<DNSRuntimeApplyResult | null>(null);
  let search = $state("");

  async function refresh() {
    try {
      const [fp, sp, pp, sr] = await Promise.all([
        api.listFilteringProfiles(router.signal()),
        api.listSecurityPolicies(router.signal()),
        api.listParentalPolicies(router.signal()),
        api.listServiceBlockingRulesets(router.signal()),
      ]);
      filteringProfiles = fp.profiles;
      securityPolicies = sp.policies;
      parentalPolicies = pp.policies;
      serviceRulesets = sr.rulesets;
      loadError = "";
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof Error ? err.message : String(err);
    }
  }
  onMount(refresh);

  function parseList(raw: string): string[] {
    return raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  }

  function rowsFor(kind: EntityKind): (CategoryEntity | ParentalPolicy | ServiceBlockingRuleset)[] {
    const all = kind === "filtering" ? filteringProfiles : kind === "security" ? securityPolicies : kind === "parental" ? parentalPolicies : serviceRulesets;
    if (!search.trim()) return all;
    const q = search.trim().toLowerCase();
    return all.filter((e) => e.name.toLowerCase().includes(q) || e.id.toLowerCase().includes(q));
  }

  function summaryFor(kind: EntityKind, e: CategoryEntity | ParentalPolicy | ServiceBlockingRuleset): string {
    if (kind === "service") return (e as ServiceBlockingRuleset).domains.join(", ") || "no domains";
    const cats = (e as CategoryEntity).categories.join(", ") || "no categories";
    if (kind === "parental") return `SafeSearch: ${(e as ParentalPolicy).safesearch_mode}, ${cats}`;
    return cats;
  }

  let confirmDelete = $state<{ kind: string; name: string; run: () => Promise<void> } | null>(null);
  async function runConfirmDelete() {
    const pending = confirmDelete;
    confirmDelete = null;
    if (pending) await pending.run();
  }

  function deleteEntity(kind: EntityKind, id: string, name: string) {
    const label = TABS.find((t) => t.key === kind)!.label.replace(/s$/, "");
    confirmDelete = {
      kind: label,
      name,
      run: async () => {
        const res =
          kind === "filtering" ? await api.deleteFilteringProfile(id) :
          kind === "security" ? await api.deleteSecurityPolicy(id) :
          kind === "parental" ? await api.deleteParentalPolicy(id) :
          await api.deleteServiceBlockingRuleset(id);
        lastRuntime = res.dns_runtime ?? null;
        await refresh();
      },
    };
  }

  // --- Add modal: one shared form, fields shown per active tab. ---
  let addModalOpen = $state(false);
  let draftId = $state("");
  let draftName = $state("");
  let draftDescription = $state("");
  let draftCategories = $state("");
  let draftDomains = $state("");
  let draftSafesearch = $state<"off" | "moderate" | "strict">("off");
  let addBusy = $state(false);
  let addError = $state("");

  function openAdd() {
    draftId = draftName = draftDescription = draftCategories = draftDomains = "";
    draftSafesearch = "off";
    addError = "";
    addModalOpen = true;
  }

  async function submitAdd(e: Event) {
    e.preventDefault();
    addError = "";
    addBusy = true;
    try {
      const res =
        activeTab === "filtering" ? await api.createFilteringProfile({ id: draftId, name: draftName, description: draftDescription, categories: parseList(draftCategories) }) :
        activeTab === "security" ? await api.createSecurityPolicy({ id: draftId, name: draftName, description: draftDescription, categories: parseList(draftCategories) }) :
        activeTab === "parental" ? await api.createParentalPolicy({ id: draftId, name: draftName, description: draftDescription, safesearch_mode: draftSafesearch, categories: parseList(draftCategories) }) :
        await api.createServiceBlockingRuleset({ id: draftId, name: draftName, description: draftDescription, domains: parseList(draftDomains) });
      lastRuntime = res.dns_runtime ?? null;
      addModalOpen = false;
      await refresh();
    } catch (err) {
      addError = err instanceof ApiError ? err.message : String(err);
    } finally {
      addBusy = false;
    }
  }

  const columns: Column<CategoryEntity | ParentalPolicy | ServiceBlockingRuleset>[] = [
    { key: "name", label: "Name", sortValue: (e) => e.name.toLowerCase(), minWidth: 14 },
    { key: "summary", label: "Main settings", minWidth: 22 },
    { key: "updated_at", label: "Last modified", sortValue: (e) => (e.updated_at ? new Date(e.updated_at).getTime() : 0), minWidth: 14 },
    { key: "actions", label: "Actions", minWidth: 8 },
  ];
</script>

<PageHeader
  title="Policy Profiles"
  headingId="policy-entities-heading"
  description="Named, reusable sets a network, group, or client's own policy can select -- each is a real, compiled DNS-runtime effect once assigned (see Scope Policies)."
>
  {#snippet actions()}
    <button type="button" onclick={openAdd}>Add {TABS.find((t) => t.key === activeTab)?.label.replace(/s$/, "")}</button>
  {/snippet}
</PageHeader>

{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
<DnsRuntimeBadge result={lastRuntime} />

<div class="tabs" role="tablist" aria-label="Policy entity type">
  {#each TABS as t (t.key)}
    <button type="button" role="tab" aria-selected={activeTab === t.key} class:active={activeTab === t.key} onclick={() => (activeTab = t.key)}>{t.label}</button>
  {/each}
</div>

<p class="hint tab-description">{TABS.find((t) => t.key === activeTab)?.description}</p>

<div class="toolbar">
  <input class="search-input" placeholder="Search name or id…" bind:value={search} aria-label="Search" />
</div>

<DataGrid gridId={`policy-entities-${activeTab}`} {columns} rows={rowsFor(activeTab)} rowKey={(e) => e.id} emptyMessage="None yet.">
  {#snippet cell(e, colKey)}
    {#if colKey === "name"}
      {e.name} <span class="mono">({e.id})</span>
      {#if e.description}<p class="hint desc-line">{e.description}</p>{/if}
    {:else if colKey === "summary"}
      {summaryFor(activeTab, e)}
    {:else if colKey === "updated_at"}
      {e.updated_at ? timestampPref.format(e.updated_at) : "—"}
    {:else if colKey === "actions"}
      <button type="button" class="secondary small danger" onclick={() => deleteEntity(activeTab, e.id, e.name)}>Delete</button>
    {/if}
  {/snippet}
</DataGrid>

{#if addModalOpen}
  <Modal title={`Add ${TABS.find((t) => t.key === activeTab)?.label.replace(/s$/, "")}`} onClose={() => (addModalOpen = false)}>
    <form onsubmit={submitAdd} class="modal-form">
      <label>ID <input required bind:value={draftId} placeholder="e.g. kids-standard" /></label>
      <label>Display name <input required bind:value={draftName} /></label>
      <label>Description <input bind:value={draftDescription} placeholder="optional" /></label>
      {#if activeTab === "parental"}
        <label>
          SafeSearch
          <select bind:value={draftSafesearch}>
            <option value="off">Off</option>
            <option value="moderate">Moderate</option>
            <option value="strict">Strict</option>
          </select>
        </label>
      {/if}
      {#if activeTab === "service"}
        <label>Domains (comma-separated) <input bind:value={draftDomains} placeholder="app1.example.com, app2.example.com" /></label>
      {:else}
        <label>Categories (comma-separated) <input bind:value={draftCategories} placeholder="ads, malware" /></label>
      {/if}
      <div class="form-actions">
        <button type="submit" disabled={addBusy}>{addBusy ? "Adding…" : "Add"}</button>
        <button type="button" class="secondary" onclick={() => (addModalOpen = false)}>Cancel</button>
      </div>
      {#if addError}<p class="error" role="alert">{addError}</p>{/if}
    </form>
  </Modal>
{/if}

{#if confirmDelete}
  <ConfirmDialog
    title={`Delete ${confirmDelete.kind.toLowerCase()}`}
    message={`Delete the ${confirmDelete.kind.toLowerCase()} "${confirmDelete.name}"? Any network, group, or client policy still selecting it keeps that selection but stops getting its effect -- update those policies afterward.`}
    confirmLabel="Delete"
    onConfirm={runConfirmDelete}
    onCancel={() => (confirmDelete = null)}
  />
{/if}

<style>
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .desc-line { margin: 0.1rem 0 0; }
  .mono { font-family: monospace; opacity: 0.7; font-size: 0.78rem; }
  .error { color: var(--danger); }

  .tabs { display: flex; gap: 0.3rem; border-bottom: 1px solid var(--border); margin: 0.75rem 0 0; flex-wrap: wrap; }
  .tabs button { background: transparent; color: var(--muted); border: none; border-bottom: 2px solid transparent; border-radius: 0; padding: 0.55rem 0.2rem; margin-right: 1.25rem; font-weight: 600; min-height: auto; }
  .tabs button.active { color: var(--fg); border-bottom-color: var(--accent); }
  .tab-description { margin: 0.5rem 0 0.75rem; }

  .toolbar { display: flex; flex-wrap: wrap; gap: 0.6rem; margin-bottom: 0.75rem; }
  .search-input { min-width: 16rem; flex: 1 1 16rem; }

  button.secondary.small { min-height: auto; padding: 0.3rem 0.6rem; font-size: 0.8rem; }
  .danger { color: var(--danger); }

  .modal-form { display: flex; flex-direction: column; gap: 0.75rem; }
  .modal-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .form-actions { display: flex; gap: 0.5rem; }
</style>
