<script lang="ts">
  // Shared policy-layer editor -- one component, used at every scope
  // (global/network/group/client) per PARITY_MATRIX.md's Clients & Access
  // and Filters rows ("shared field set"). Every field is tri-state:
  // "(Inherit)" (null) vs an explicit value, matching the backend's own
  // "unset means inherit from the next layer up" semantics -- never
  // silently defaults a field to some value the operator didn't choose.
  import { ApiError, EMPTY_POLICY_LAYER, type PolicyLayer } from "../api";

  let {
    layer,
    onSave,
  }: {
    layer: PolicyLayer;
    onSave: (l: PolicyLayer) => Promise<unknown>;
  } = $props();

  // Starts empty and is synced from the `layer` prop by the $effect below
  // (which also re-syncs on every prop change) -- avoids reading a prop
  // directly inside a $state initializer.
  let draft = $state<PolicyLayer>({ ...EMPTY_POLICY_LAYER });
  let busy = $state(false);
  let error = $state("");
  let success = $state(false);

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
    busy = true;
    try {
      await onSave(draft);
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
        <option value="disabled">Disabled</option>
        <option value="preserve">Preserve</option>
        <option value="custom">Custom</option>
      </select>
    </label>
    <label>
      Fallback strategy
      <select value={draft.fallback_strategy ?? ""} onchange={(e) => (draft.fallback_strategy = textOrNull((e.target as HTMLSelectElement).value))}>
        <option value="">(Inherit)</option>
        <option value="none">None</option>
        <option value="on_failure">On failure</option>
        <option value="always_parallel">Always parallel</option>
      </select>
    </label>
    <label>Upstream profile ID <input value={draft.upstream_profile_id ?? ""} oninput={(e) => (draft.upstream_profile_id = textOrNull((e.target as HTMLInputElement).value))} placeholder="(Inherit)" /></label>
    <label>Filtering profile ID <input value={draft.filtering_profile_id ?? ""} oninput={(e) => (draft.filtering_profile_id = textOrNull((e.target as HTMLInputElement).value))} placeholder="(Inherit)" /></label>
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
</form>

<style>
  .policy-editor { display: flex; flex-direction: column; gap: 0.6rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); gap: 0.6rem; }
  .grid label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.8rem; }
  .editor-actions { display: flex; align-items: center; gap: 0.6rem; }
  .ok { color: #16a34a; font-size: 0.85rem; }
</style>
