<script lang="ts">
  // Shared policy-layer editor -- one component, used at every scope
  // (global/network/group/client). Every field is tri-state:
  // "(Inherit)" (null) vs an explicit value, matching the backend's own
  // "unset means inherit from the next layer up" semantics -- never
  // silently defaults a field to some value the operator didn't choose.
  //
  // filtering_profile_id/parental_policy_id/security_policy_id/
  // service_blocking_ruleset_id/upstream_profile_id/
  // domain_routing_ruleset_id are real dropdowns backed by this
  // appliance's own live entities (internal/policyentities,
  // internal/upstreams, internal/domainrouting) -- not free-text
  // fields an operator could point at something that doesn't exist.
  // Every option here is a real, compiled DNS-runtime effect at every
  // scope (internal/dnsruntime's computeScopeOverrides).
  import { onMount } from "svelte";
  import {
    api,
    ApiError,
    EMPTY_POLICY_LAYER,
    type PolicyLayer,
    type DNSRuntimeApplyResult,
    type CategoryEntity,
    type ParentalPolicy,
    type ServiceBlockingRuleset,
    type UpstreamProfile,
    type DomainRoutingRuleset,
  } from "../api";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";

  let {
    layer,
    onSave,
  }: {
    layer: PolicyLayer;
    onSave: (l: PolicyLayer) => Promise<{ dns_runtime?: DNSRuntimeApplyResult | null } | unknown>;
  } = $props();

  // Starts empty and is synced from the `layer` prop by the $effect below
  // (which also re-syncs on every prop change) -- avoids reading a prop
  // directly inside a $state initializer.
  let draft = $state<PolicyLayer>({ ...EMPTY_POLICY_LAYER });
  let busy = $state(false);
  let error = $state("");
  let success = $state(false);
  // Every scope's PUT now returns a real dns_runtime result -- surfaced
  // through the same shared DnsRuntimeBadge every other resolver-
  // affecting save on this appliance already uses, so "Saved." never
  // implies a live effect this scope didn't actually have.
  let runtimeResult = $state<DNSRuntimeApplyResult | null>(null);

  let filteringProfiles = $state<CategoryEntity[]>([]);
  let securityPolicies = $state<CategoryEntity[]>([]);
  let parentalPolicies = $state<ParentalPolicy[]>([]);
  let serviceRulesets = $state<ServiceBlockingRuleset[]>([]);
  let upstreamProfiles = $state<UpstreamProfile[]>([]);
  let routingRulesets = $state<DomainRoutingRuleset[]>([]);

  onMount(async () => {
    const [fp, sp, pp, sr, up, rr] = await Promise.allSettled([
      api.listFilteringProfiles(),
      api.listSecurityPolicies(),
      api.listParentalPolicies(),
      api.listServiceBlockingRulesets(),
      api.listUpstreams(),
      api.listDomainRoutingRulesets(),
    ]);
    if (fp.status === "fulfilled") filteringProfiles = fp.value.profiles;
    if (sp.status === "fulfilled") securityPolicies = sp.value.policies;
    if (pp.status === "fulfilled") parentalPolicies = pp.value.policies;
    if (sr.status === "fulfilled") serviceRulesets = sr.value.rulesets;
    if (up.status === "fulfilled") upstreamProfiles = up.value.upstreams;
    if (rr.status === "fulfilled") routingRulesets = rr.value.rulesets;
  });

  $effect(() => {
    draft = { ...layer };
  });

  function textOrNull(v: string): string | null {
    return v.trim() === "" ? null : v.trim();
  }

  async function save(e: Event) {
    e.preventDefault();
    error = "";
    success = false;
    runtimeResult = null;
    busy = true;
    try {
      const res = (await onSave(draft)) as { dns_runtime?: DNSRuntimeApplyResult | null } | undefined;
      runtimeResult = res?.dns_runtime ?? null;
      success = true;
    } catch (err) {
      error = err instanceof ApiError ? err.message : String(err);
    } finally {
      busy = false;
    }
  }

  function triState(v: boolean | null): string {
    return v === null ? "inherit" : v ? "on" : "off";
  }
  function fromTriState(s: string): boolean | null {
    return s === "inherit" ? null : s === "on";
  }
</script>

<form onsubmit={save} class="policy-editor">
  <div class="grid">
    <label>
      Safesearch
      <select value={draft.safesearch_mode ?? ""} onchange={(e) => (draft.safesearch_mode = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        <option value="off">Off</option>
        <option value="moderate">Moderate</option>
        <option value="strict">Strict</option>
      </select>
    </label>
    <label>
      Blocking response
      <select value={draft.blocking_response_mode ?? ""} onchange={(e) => (draft.blocking_response_mode = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        <option value="nxdomain">NXDOMAIN</option>
        <option value="refused">REFUSED</option>
        <option value="null_ip">Null IP</option>
        <option value="custom_ip">Custom IP</option>
      </select>
    </label>
    {#if draft.blocking_response_mode === "custom_ip"}
      <label>Custom IPv4 <input value={draft.custom_ipv4 ?? ""} oninput={(e) => (draft.custom_ipv4 = textOrNull((e.target as HTMLInputElement).value))} /></label>
      <label>Custom IPv6 <input value={draft.custom_ipv6 ?? ""} oninput={(e) => (draft.custom_ipv6 = textOrNull((e.target as HTMLInputElement).value))} /></label>
    {/if}
    <label>
      ECS mode
      <select value={draft.ecs_mode ?? ""} onchange={(e) => (draft.ecs_mode = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        <option value="disabled">Disabled (default -- no client subnet ever sent upstream)</option>
        <option value="enabled">Enabled (attach this scope's real client subnet to upstream queries)</option>
      </select>
    </label>
    <label>
      Fallback strategy <span class="hint-inline">(stored, not yet compiled into DNS behavior at any scope)</span>
      <select value={draft.fallback_strategy ?? ""} onchange={(e) => (draft.fallback_strategy = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        <option value="none">None</option>
        <option value="on_failure">On failure</option>
        <option value="always_parallel">Always parallel</option>
      </select>
    </label>
    <label>
      Upstream profile
      <select value={draft.upstream_profile_id ?? ""} onchange={(e) => (draft.upstream_profile_id = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        {#each upstreamProfiles as p (p.upstream_profile_id)}
          <option value={p.upstream_profile_id}>{p.name}</option>
        {/each}
      </select>
    </label>
    <label>
      Filtering profile
      <select value={draft.filtering_profile_id ?? ""} onchange={(e) => (draft.filtering_profile_id = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        {#each filteringProfiles as p (p.id)}
          <option value={p.id}>{p.name}</option>
        {/each}
      </select>
    </label>
    <label>
      Parental policy
      <select value={draft.parental_policy_id ?? ""} onchange={(e) => (draft.parental_policy_id = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        {#each parentalPolicies as p (p.id)}
          <option value={p.id}>{p.name}</option>
        {/each}
      </select>
    </label>
    <label>
      Security policy
      <select value={draft.security_policy_id ?? ""} onchange={(e) => (draft.security_policy_id = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        {#each securityPolicies as p (p.id)}
          <option value={p.id}>{p.name}</option>
        {/each}
      </select>
    </label>
    <label>
      Service blocking
      <select value={draft.service_blocking_ruleset_id ?? ""} onchange={(e) => (draft.service_blocking_ruleset_id = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        {#each serviceRulesets as r (r.id)}
          <option value={r.id}>{r.name}</option>
        {/each}
      </select>
    </label>
    <label>
      Domain routing ruleset
      <select value={draft.domain_routing_ruleset_id ?? ""} onchange={(e) => (draft.domain_routing_ruleset_id = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        {#each routingRulesets as r (r.id)}
          <option value={r.id}>{r.name}</option>
        {/each}
      </select>
    </label>
    <label>
      Query log
      <select value={triState(draft.query_log_enabled)} onchange={(e) => (draft.query_log_enabled = fromTriState((e.target as HTMLSelectElement).value))}>
        <option value="inherit">(Inherit)</option>
        <option value="on">Enabled</option>
        <option value="off">Disabled</option>
      </select>
    </label>
    <label>
      Statistics
      <select value={triState(draft.statistics_enabled)} onchange={(e) => (draft.statistics_enabled = fromTriState((e.target as HTMLSelectElement).value))}>
        <option value="inherit">(Inherit)</option>
        <option value="on">Enabled</option>
        <option value="off">Disabled</option>
      </select>
    </label>
  </div>
  <div class="editor-actions">
    <button type="submit" disabled={busy}>{busy ? "Saving…" : "Save policy"}</button>
    {#if success}<span class="ok" role="status">Saved.</span>{/if}
  </div>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if success && runtimeResult?.attempted === false}
    <p class="hint">Saved, but not compiled into the live DNS runtime at this scope. {runtimeResult.detail ?? ""}</p>
  {:else}
    <DnsRuntimeBadge result={runtimeResult} />
  {/if}
</form>

<style>
  .policy-editor { display: flex; flex-direction: column; gap: 0.6rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); gap: 0.6rem; }
  .grid label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.8rem; }
  .editor-actions { display: flex; align-items: center; gap: 0.6rem; }
  .ok { color: #16a34a; font-size: 0.85rem; }
  .hint { font-size: 0.8rem; opacity: 0.75; margin: 0; }
  .hint-inline { font-weight: normal; opacity: 0.65; font-size: 0.75rem; }
</style>
