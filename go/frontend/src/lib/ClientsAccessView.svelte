<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type NetworkWithPolicy, type PolicyLayer } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import PolicyEditor from "./PolicyEditor.svelte";

  // Clients & Access: the real functional page behind the nav item that
  // used to have no `load` function at all (RouteLoader.svelte's
  // "Not yet available" fallback). This is the global/network layer of
  // internal/policy's global->network->group->client precedence system
  // (see internal/policy/effective.go and GET /api/policy/explain);
  // group- and client-scoped policy assignment already live on the
  // Clients page (each managed client/group's own "Policy" button),
  // right next to the identity they apply to -- kept there rather than
  // duplicated here.
  //
  // Deliberately NOT built here, disclosed rather than hidden: V1's
  // separate whole-client access_rules subsystem (app/clients.py's
  // add_access_rule/evaluate_access -- a second, independent allow/deny
  // engine keyed only by client IP). This Go migration's actual access
  // decision is a single, real mechanism already live in dnsdist today:
  // explicit per-client domain overrides (deny beats allow beats
  // default policy -- see the Clients page's "Add domain override" and
  // internal/dnscompile's ClientOverride compilation) layered under the
  // same global->network->group->client policy precedence every other
  // setting uses. Building a second, separate whole-client-IP allow/deny
  // engine on top of that would be a real, disclosed duplication of
  // access control, not a missing feature -- see PARITY_MATRIX.md.

  let globalPolicy = $state<PolicyLayer | null>(null);
  let globalLoadError = $state("");
  const globalGuard = new StaleGuard();

  let networks = $state<NetworkWithPolicy[]>([]);
  let networksLoadError = $state("");
  const networksGuard = new StaleGuard();

  let newNetworkCidr = $state("");
  let addNetworkBusy = $state(false);
  let addNetworkError = $state("");

  let expandedNetworkId = $state<string | null>(null);

  async function refreshGlobal() {
    const token = globalGuard.start();
    try {
      const l = await api.getGlobalPolicy(router.signal());
      if (!globalGuard.isCurrent(token)) return;
      globalPolicy = l;
      globalLoadError = "";
    } catch (err) {
      if (!globalGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      globalLoadError = err instanceof Error ? err.message : String(err);
    }
  }

  async function refreshNetworks() {
    const token = networksGuard.start();
    try {
      const res = await api.listNetworks(router.signal());
      if (!networksGuard.isCurrent(token)) return;
      networks = res.networks;
      networksLoadError = "";
    } catch (err) {
      if (!networksGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      networksLoadError = err instanceof Error ? err.message : String(err);
    }
  }

  onMount(() => {
    refreshGlobal();
    refreshNetworks();
  });

  async function addNetwork(e: Event) {
    e.preventDefault();
    addNetworkError = "";
    addNetworkBusy = true;
    try {
      await api.createNetwork(newNetworkCidr);
      newNetworkCidr = "";
      await refreshNetworks();
    } catch (err) {
      addNetworkError = err instanceof ApiError ? err.message : String(err);
    } finally {
      addNetworkBusy = false;
    }
  }
</script>

<section aria-labelledby="clients-access-heading" class="clients-access">
  <h2 id="clients-access-heading">Clients &amp; Access</h2>
  <p class="scope-note">
    Global default policy, network-scoped policy, and the explicit-deny &gt; explicit-allow &gt;
    default precedence that governs every client. Strong ClientID lifecycle (generate, add, display,
    copy, regenerate, revoke, DoH path, DoT/DoQ SNI) and per-client domain overrides live on the
    <button type="button" class="link-btn" onclick={() => router.navigate("clients")}>Clients</button> page,
    next to each identity they apply to.
  </p>

  <h3>Global Policy</h3>
  <p class="hint">
    The default policy every client falls back to unless a network, group, or client layer overrides
    a field. This is the only scope compiled into the live DNS runtime today (see
    internal/dnscompile's doc comment) -- network/group/client layers are stored and used by
    "Explain" resolution, but not compiled yet.
  </p>
  {#if globalLoadError}<p class="error" role="alert">{globalLoadError}</p>{/if}
  {#if globalPolicy}
    <div class="policy-card">
      <PolicyEditor layer={globalPolicy} onSave={(l) => api.putGlobalPolicy(l).then(refreshGlobal)} />
    </div>
  {/if}

  <h3>Networks</h3>
  <p class="hint">
    A network is a CIDR range (e.g. a VLAN or subnet). Its policy layer applies to any client whose
    IP falls inside it, above global but below group/client layers -- see the "Explain" panel on the
    Clients page for exactly how a given client resolves.
  </p>
  {#if networksLoadError}<p class="error" role="alert">{networksLoadError}</p>{/if}

  <form onsubmit={addNetwork} class="add-form">
    <label>CIDR <input required bind:value={newNetworkCidr} placeholder="192.168.1.0/24" /></label>
    <button type="submit" disabled={addNetworkBusy}>{addNetworkBusy ? "Adding…" : "Add network"}</button>
    {#if addNetworkError}<p class="error" role="alert">{addNetworkError}</p>{/if}
  </form>

  {#if networks.length === 0 && !networksLoadError}
    <p class="hint">No networks defined yet.</p>
  {:else}
    <ul class="network-list">
      {#each networks as n (n.network_id)}
        <li>
          <div class="network-row">
            <span><code>{n.cidr}</code></span>
            <button onclick={() => (expandedNetworkId = expandedNetworkId === n.network_id ? null : n.network_id)}>
              {expandedNetworkId === n.network_id ? "Hide policy" : "Policy"}
            </button>
          </div>
          {#if expandedNetworkId === n.network_id}
            <div class="policy-card">
              <PolicyEditor layer={n.policy} onSave={(l) => api.putNetworkPolicy(n.network_id, l).then(refreshNetworks)} />
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .clients-access { display: flex; flex-direction: column; gap: 0.75rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 48rem; }
  .hint { font-size: 0.85rem; opacity: 0.75; max-width: 44rem; }
  .policy-card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); max-width: 40rem; }
  .add-form { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.5rem; max-width: 20rem; }
  .add-form label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.85rem; }
  .network-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }
  .network-row { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; max-width: 30rem; }
  .link-btn { background: none; border: none; padding: 0; color: var(--accent, #4a7); text-decoration: underline; cursor: pointer; font: inherit; }
</style>
