<script lang="ts">
  // Owner-facing CRUD for the four real entities blocker-1 policy
  // scopes (Clients & Access / DNS Settings) reference: Filtering
  // Profiles, Parental Policies (own SafeSearch mode), Security
  // Policies, and Service Blocking Rulesets -- see
  // internal/policyentities' own doc comment. Every one of these,
  // once assigned to a network/group/client's policy, is a real
  // compiled DNS-runtime effect (internal/dnsruntime's
  // computeScopeOverrides), not a stored-only label.
  import { onMount } from "svelte";
  import { api, ApiError, type CategoryEntity, type ParentalPolicy, type ServiceBlockingRuleset, type DNSRuntimeApplyResult } from "../api";
  import { router } from "../router.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import Panel from "./ui/Panel.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";

  let filteringProfiles = $state<CategoryEntity[]>([]);
  let securityPolicies = $state<CategoryEntity[]>([]);
  let parentalPolicies = $state<ParentalPolicy[]>([]);
  let serviceRulesets = $state<ServiceBlockingRuleset[]>([]);
  let loadError = $state("");
  let lastRuntime = $state<DNSRuntimeApplyResult | null>(null);

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
    return raw
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  // --- Filtering Profiles ---
  let fpId = $state(""), fpName = $state(""), fpCategories = $state(""), fpBusy = $state(false), fpError = $state("");
  async function createFilteringProfile(e: Event) {
    e.preventDefault();
    fpBusy = true;
    fpError = "";
    try {
      const res = await api.createFilteringProfile({ id: fpId, name: fpName, categories: parseList(fpCategories) });
      lastRuntime = res.dns_runtime ?? null;
      fpId = fpName = fpCategories = "";
      await refresh();
    } catch (err) {
      fpError = err instanceof ApiError ? err.message : String(err);
    } finally {
      fpBusy = false;
    }
  }
  async function deleteFilteringProfile(id: string) {
    const res = await api.deleteFilteringProfile(id);
    lastRuntime = res.dns_runtime ?? null;
    await refresh();
  }

  // --- Security Policies ---
  let spId = $state(""), spName = $state(""), spCategories = $state(""), spBusy = $state(false), spError = $state("");
  async function createSecurityPolicy(e: Event) {
    e.preventDefault();
    spBusy = true;
    spError = "";
    try {
      const res = await api.createSecurityPolicy({ id: spId, name: spName, categories: parseList(spCategories) });
      lastRuntime = res.dns_runtime ?? null;
      spId = spName = spCategories = "";
      await refresh();
    } catch (err) {
      spError = err instanceof ApiError ? err.message : String(err);
    } finally {
      spBusy = false;
    }
  }
  async function deleteSecurityPolicy(id: string) {
    const res = await api.deleteSecurityPolicy(id);
    lastRuntime = res.dns_runtime ?? null;
    await refresh();
  }

  // --- Parental Policies ---
  let ppId = $state(""), ppName = $state(""), ppCategories = $state(""), ppSafesearch = $state("off"), ppBusy = $state(false), ppError = $state("");
  async function createParentalPolicy(e: Event) {
    e.preventDefault();
    ppBusy = true;
    ppError = "";
    try {
      const res = await api.createParentalPolicy({ id: ppId, name: ppName, safesearch_mode: ppSafesearch, categories: parseList(ppCategories) });
      lastRuntime = res.dns_runtime ?? null;
      ppId = ppName = ppCategories = "";
      ppSafesearch = "off";
      await refresh();
    } catch (err) {
      ppError = err instanceof ApiError ? err.message : String(err);
    } finally {
      ppBusy = false;
    }
  }
  async function deleteParentalPolicy(id: string) {
    const res = await api.deleteParentalPolicy(id);
    lastRuntime = res.dns_runtime ?? null;
    await refresh();
  }

  // --- Service Blocking Rulesets ---
  let srId = $state(""), srName = $state(""), srDomains = $state(""), srBusy = $state(false), srError = $state("");
  async function createServiceRuleset(e: Event) {
    e.preventDefault();
    srBusy = true;
    srError = "";
    try {
      const res = await api.createServiceBlockingRuleset({ id: srId, name: srName, domains: parseList(srDomains) });
      lastRuntime = res.dns_runtime ?? null;
      srId = srName = srDomains = "";
      await refresh();
    } catch (err) {
      srError = err instanceof ApiError ? err.message : String(err);
    } finally {
      srBusy = false;
    }
  }
  async function deleteServiceRuleset(id: string) {
    const res = await api.deleteServiceBlockingRuleset(id);
    lastRuntime = res.dns_runtime ?? null;
    await refresh();
  }
</script>

<PageHeader
  title="Policy Profiles"
  headingId="policy-entities-heading"
  description="Named, reusable sets a network, group, or client's own policy can select -- each is a real, compiled DNS-runtime effect once assigned (see Clients & Access)."
/>

{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
<DnsRuntimeBadge result={lastRuntime} />

<div class="grid">
  <Panel heading="Filtering Profiles">
    <p class="hint">A named set of blocklist categories to enforce for whichever scope selects it.</p>
    <ul class="entity-list">
      {#each filteringProfiles as p (p.id)}
        <li><strong>{p.name}</strong> <span class="mono">({p.id})</span> — {p.categories.join(", ") || "no categories"} <button onclick={() => deleteFilteringProfile(p.id)}>Delete</button></li>
      {:else}
        <li class="hint">None yet.</li>
      {/each}
    </ul>
    <form onsubmit={createFilteringProfile} class="add-form">
      <input placeholder="id (e.g. kids-standard)" value={fpId} oninput={(e) => (fpId = (e.target as HTMLInputElement).value)} required />
      <input placeholder="Display name" value={fpName} oninput={(e) => (fpName = (e.target as HTMLInputElement).value)} required />
      <input placeholder="categories, comma-separated" value={fpCategories} oninput={(e) => (fpCategories = (e.target as HTMLInputElement).value)} />
      <button type="submit" disabled={fpBusy}>{fpBusy ? "Adding…" : "Add"}</button>
    </form>
    {#if fpError}<p class="error" role="alert">{fpError}</p>{/if}
  </Panel>

  <Panel heading="Parental Policies">
    <p class="hint">A named SafeSearch mode + category set (e.g. adult content) for a network, group, or client.</p>
    <ul class="entity-list">
      {#each parentalPolicies as p (p.id)}
        <li><strong>{p.name}</strong> <span class="mono">({p.id})</span> — SafeSearch: {p.safesearch_mode}, {p.categories.join(", ") || "no categories"} <button onclick={() => deleteParentalPolicy(p.id)}>Delete</button></li>
      {:else}
        <li class="hint">None yet.</li>
      {/each}
    </ul>
    <form onsubmit={createParentalPolicy} class="add-form">
      <input placeholder="id" value={ppId} oninput={(e) => (ppId = (e.target as HTMLInputElement).value)} required />
      <input placeholder="Display name" value={ppName} oninput={(e) => (ppName = (e.target as HTMLInputElement).value)} required />
      <select value={ppSafesearch} onchange={(e) => (ppSafesearch = (e.target as HTMLSelectElement).value)}>
        <option value="off">SafeSearch: off</option>
        <option value="moderate">SafeSearch: moderate</option>
        <option value="strict">SafeSearch: strict</option>
      </select>
      <input placeholder="categories, comma-separated" value={ppCategories} oninput={(e) => (ppCategories = (e.target as HTMLInputElement).value)} />
      <button type="submit" disabled={ppBusy}>{ppBusy ? "Adding…" : "Add"}</button>
    </form>
    {#if ppError}<p class="error" role="alert">{ppError}</p>{/if}
  </Panel>

  <Panel heading="Security Policies">
    <p class="hint">A named security-oriented category set (malware, telemetry, etc.).</p>
    <ul class="entity-list">
      {#each securityPolicies as p (p.id)}
        <li><strong>{p.name}</strong> <span class="mono">({p.id})</span> — {p.categories.join(", ") || "no categories"} <button onclick={() => deleteSecurityPolicy(p.id)}>Delete</button></li>
      {:else}
        <li class="hint">None yet.</li>
      {/each}
    </ul>
    <form onsubmit={createSecurityPolicy} class="add-form">
      <input placeholder="id" value={spId} oninput={(e) => (spId = (e.target as HTMLInputElement).value)} required />
      <input placeholder="Display name" value={spName} oninput={(e) => (spName = (e.target as HTMLInputElement).value)} required />
      <input placeholder="categories, comma-separated" value={spCategories} oninput={(e) => (spCategories = (e.target as HTMLInputElement).value)} />
      <button type="submit" disabled={spBusy}>{spBusy ? "Adding…" : "Add"}</button>
    </form>
    {#if spError}<p class="error" role="alert">{spError}</p>{/if}
  </Panel>

  <Panel heading="Service Blocking Rulesets">
    <p class="hint">A named list of specific domains (e.g. one app/service) to block -- independent of the blocklist-category system above.</p>
    <ul class="entity-list">
      {#each serviceRulesets as r (r.id)}
        <li><strong>{r.name}</strong> <span class="mono">({r.id})</span> — {r.domains.join(", ") || "no domains"} <button onclick={() => deleteServiceRuleset(r.id)}>Delete</button></li>
      {:else}
        <li class="hint">None yet.</li>
      {/each}
    </ul>
    <form onsubmit={createServiceRuleset} class="add-form">
      <input placeholder="id" value={srId} oninput={(e) => (srId = (e.target as HTMLInputElement).value)} required />
      <input placeholder="Display name" value={srName} oninput={(e) => (srName = (e.target as HTMLInputElement).value)} required />
      <input placeholder="domains, comma-separated" value={srDomains} oninput={(e) => (srDomains = (e.target as HTMLInputElement).value)} />
      <button type="submit" disabled={srBusy}>{srBusy ? "Adding…" : "Add"}</button>
    </form>
    {#if srError}<p class="error" role="alert">{srError}</p>{/if}
  </Panel>
</div>

<style>
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1rem; }
  .entity-list { list-style: none; margin: 0 0 0.75rem; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
  .entity-list li { font-size: 0.85rem; display: flex; align-items: baseline; gap: 0.4rem; flex-wrap: wrap; }
  .mono { font-family: monospace; opacity: 0.7; font-size: 0.75rem; }
  .add-form { display: flex; flex-direction: column; gap: 0.4rem; }
  .hint { font-size: 0.8rem; opacity: 0.7; margin: 0 0 0.5rem; }
  .error { color: #dc2626; font-size: 0.85rem; }
</style>
