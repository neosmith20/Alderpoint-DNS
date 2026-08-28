<script lang="ts">
  import { onMount } from "svelte";
  import {
    api,
    ApiError,
    type ClientGroup,
    type ManagedClient,
    type NetworkWithPolicy,
    type PolicyExplainResult,
    type PolicyLayer,
  } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import PolicyEditor from "./PolicyEditor.svelte";

  // Clients & Access: the global/network/group layers of internal/
  // policy's global->network->group->client precedence system (see
  // internal/policy/effective.go and GET /api/policy/explain), plus a
  // standalone Explain workbench so any client's real effective policy
  // can be inspected without hunting through the Clients table first --
  // matching the old Python "Policies / Explain" page's own single-page
  // layout (Global Policy / Networks / Groups side by side, an Explain
  // drawer alongside), which this page previously did not (see this
  // file's git history for the sparser predecessor).
  //
  // Client- and group-MEMBERSHIP actions (assigning a client to a group,
  // adding/removing group members) deliberately stay on the Clients page
  // instead of being duplicated here -- they're identity-scoped actions
  // that belong right next to the client/group row they act on. This
  // page owns the policy CONTENT of each scope (global/network/group)
  // and the read-only Explain view across all of them.
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

  let groups = $state<ClientGroup[]>([]);
  let groupsLoadError = $state("");
  const groupsGuard = new StaleGuard();

  let clients = $state<ManagedClient[]>([]);
  const clientsGuard = new StaleGuard();

  let newNetworkCidr = $state("");
  let addNetworkBusy = $state(false);
  let addNetworkError = $state("");

  let expandedNetworkId = $state<string | null>(null);
  let expandedGroupId = $state<string | null>(null);

  let explainClientId = $state<number | null>(null);
  let explainClientIp = $state("");
  let explainBusy = $state(false);
  let explainError = $state("");
  let explainResult = $state<PolicyExplainResult | null>(null);

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

  async function refreshGroups() {
    const token = groupsGuard.start();
    try {
      const res = await api.listGroups(router.signal());
      if (!groupsGuard.isCurrent(token)) return;
      groups = res.groups;
      groupsLoadError = "";
    } catch (err) {
      if (!groupsGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      groupsLoadError = err instanceof Error ? err.message : String(err);
    }
  }

  async function refreshClients() {
    const token = clientsGuard.start();
    try {
      const res = await api.listClients(router.signal());
      if (!clientsGuard.isCurrent(token)) return;
      clients = res.clients;
      if (explainClientId === null && clients.length > 0) explainClientId = clients[0].id;
    } catch (err) {
      if (!clientsGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      // Non-fatal for this page: Explain simply has no clients to offer yet.
    }
  }

  onMount(() => {
    refreshGlobal();
    refreshNetworks();
    refreshGroups();
    refreshClients();
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

  async function runExplain(e: Event) {
    e.preventDefault();
    if (explainClientId === null) return;
    explainError = "";
    explainBusy = true;
    explainResult = null;
    try {
      explainResult = await api.explainPolicy(explainClientId, explainClientIp.trim() || undefined);
    } catch (err) {
      explainError = err instanceof ApiError ? err.message : String(err);
    } finally {
      explainBusy = false;
    }
  }

  // ExplainEntry.Source is "global", "network:<id>", "group:<id>", or
  // "client" (see internal/policy/effective.go) -- strip the ":<id>"
  // suffix for the badge's color-coding class, keep the full string as
  // the visible label.
  function sourceClass(source: string): string {
    return `source-${source.split(":")[0]}`;
  }

  function policySummary(p: PolicyLayer | null | undefined): string {
    if (!p) return "inherit";
    const active = Object.entries(p).filter(([, v]) => v !== null && v !== undefined && v !== "");
    if (active.length === 0) return "inherit";
    return active.slice(0, 3).map(([k, v]) => `${k}=${v}`).join(", ");
  }
</script>

<section aria-labelledby="clients-access-heading" class="clients-access">
  <h2 id="clients-access-heading">Clients &amp; Access</h2>
  <p class="scope-note">
    Global default policy, network-scoped policy, group-scoped policy, and the explicit-deny &gt;
    explicit-allow &gt; default precedence that governs every client. Strong ClientID lifecycle
    (generate, add, display, copy, regenerate, revoke, DoH path, DoT/DoQ SNI), group membership, and
    per-client domain overrides live on the
    <button type="button" class="link-btn" onclick={() => router.navigate("clients")}>Clients</button> page,
    next to each identity they apply to.
  </p>

  <div class="layout">
    <div class="scopes">
      <section class="panel">
        <div class="panel-head">
          <h3>Global Policy</h3>
          <span class="badge">applies to every client by default</span>
        </div>
        <p class="hint">
          The default policy every client falls back to unless a network, group, or client layer
          overrides a field. This is the only scope compiled into the live DNS runtime today (see
          internal/dnscompile's doc comment) -- network/group/client layers are stored and used by
          Explain resolution below, but not compiled yet.
        </p>
        {#if globalLoadError}<p class="error" role="alert">{globalLoadError}</p>{/if}
        {#if globalPolicy}
          <div class="policy-card">
            <PolicyEditor layer={globalPolicy} onSave={(l) => api.putGlobalPolicy(l).then(refreshGlobal)} />
          </div>
        {:else if !globalLoadError}
          <p class="hint">Loading…</p>
        {/if}
      </section>

      <section class="panel">
        <div class="panel-head">
          <h3>Networks</h3>
          <span class="badge">{networks.length} configured</span>
        </div>
        <p class="hint">
          A network is a CIDR range (e.g. a VLAN or subnet). Its policy layer applies to any client
          whose IP falls inside it, above global but below group/client layers.
        </p>
        {#if networksLoadError}<p class="error" role="alert">{networksLoadError}</p>{/if}

        <form onsubmit={addNetwork} class="add-form">
          <label>CIDR <input required bind:value={newNetworkCidr} placeholder="192.168.1.0/24" /></label>
          <button type="submit" disabled={addNetworkBusy}>{addNetworkBusy ? "Adding…" : "Add network"}</button>
          {#if addNetworkError}<p class="error" role="alert">{addNetworkError}</p>{/if}
        </form>

        {#if networks.length === 0 && !networksLoadError}
          <p class="empty">No networks defined yet.</p>
        {:else}
          <ul class="scope-list networks-list">
            {#each networks as n (n.network_id)}
              <li>
                <div class="scope-row">
                  <span><code>{n.cidr}</code></span>
                  <span class="summary">{policySummary(n.policy)}</span>
                  <button
                    onclick={() => (expandedNetworkId = expandedNetworkId === n.network_id ? null : n.network_id)}
                  >
                    {expandedNetworkId === n.network_id ? "Hide policy" : "Policy"}
                  </button>
                </div>
                {#if expandedNetworkId === n.network_id}
                  <div class="policy-card">
                    <PolicyEditor
                      layer={n.policy}
                      onSave={(l) => api.putNetworkPolicy(n.network_id, l).then(refreshNetworks)}
                    />
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </section>

      <section class="panel">
        <div class="panel-head">
          <h3>Groups</h3>
          <span class="badge">{groups.length} configured</span>
        </div>
        <p class="hint">
          A group's policy layer applies to every client assigned to it, above network but below a
          client's own overrides. Create groups and assign clients to them on the
          <button type="button" class="link-btn" onclick={() => router.navigate("clients")}>Clients</button> page;
          this section edits the policy each group carries.
        </p>
        {#if groupsLoadError}<p class="error" role="alert">{groupsLoadError}</p>{/if}
        {#if groups.length === 0 && !groupsLoadError}
          <p class="empty">No groups defined yet.</p>
        {:else}
          <ul class="scope-list groups-list">
            {#each groups as g (g.group_id)}
              <li>
                <div class="scope-row">
                  <span><strong>{g.name}</strong> <span class="hint">(priority {g.priority})</span></span>
                  <span class="hint">{g.members.length} member{g.members.length === 1 ? "" : "s"}</span>
                  <span class="summary">{policySummary(g.policy)}</span>
                  <button onclick={() => (expandedGroupId = expandedGroupId === g.group_id ? null : g.group_id)}>
                    {expandedGroupId === g.group_id ? "Hide policy" : "Policy"}
                  </button>
                </div>
                {#if expandedGroupId === g.group_id}
                  <div class="policy-card">
                    <PolicyEditor layer={g.policy} onSave={(l) => api.putGroupPolicy(g.group_id, l).then(refreshGroups)} />
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </section>
    </div>

    <aside class="panel drawer">
      <div class="panel-head">
        <h3>Explain Effective Policy</h3>
      </div>
      <p class="hint">
        Resolves the real global -&gt; network -&gt; group -&gt; client precedence
        (internal/policy/effective.go) for one client, field by field, showing exactly which scope
        won each field. An optional client IP lets you check which network layer (if any) would
        match, independent of the client's own stored identifiers.
      </p>
      <form onsubmit={runExplain} class="explain-form">
        <label>
          Client
          <select bind:value={explainClientId} disabled={clients.length === 0}>
            {#each clients as c (c.id)}
              <option value={c.id}>{c.name}</option>
            {/each}
          </select>
        </label>
        <label>Client IP <input bind:value={explainClientIp} placeholder="optional, e.g. 10.0.0.42" /></label>
        <button type="submit" disabled={explainBusy || clients.length === 0}>
          {explainBusy ? "Explaining…" : "Explain effective policy"}
        </button>
      </form>
      {#if clients.length === 0}
        <p class="empty">No managed clients yet -- create one on the Clients page to use Explain.</p>
      {/if}
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
                <td>{entry.value === null || entry.value === undefined || entry.value === "" ? "—" : String(entry.value)}</td>
                <td><span class="badge {sourceClass(entry.source)}">{entry.source}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else if !explainError}
        <p class="hint">Select a client and run Explain to see how its effective policy resolves.</p>
      {/if}
    </aside>
  </div>
</section>

<style>
  .clients-access { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 52rem; }
  .hint { font-size: 0.85rem; opacity: 0.75; max-width: 44rem; }
  .empty { font-size: 0.85rem; opacity: 0.6; font-style: italic; }

  .layout { display: flex; gap: 1.25rem; align-items: flex-start; flex-wrap: wrap; }
  .scopes { display: flex; flex-direction: column; gap: 1rem; flex: 2 1 34rem; min-width: 26rem; }

  .panel { border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; }
  .panel-head { display: flex; align-items: baseline; justify-content: space-between; gap: 0.75rem; }
  .panel-head h3 { margin: 0; }
  .badge { background: var(--nav-hover-bg); padding: 0.1rem 0.55rem; border-radius: 999px; font-size: 0.72rem; opacity: 0.85; white-space: nowrap; }

  .policy-card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--bg, transparent); }
  .add-form { border: 1px dashed var(--border); border-radius: 8px; padding: 0.75rem 1rem; display: flex; flex-direction: column; gap: 0.5rem; max-width: 22rem; }
  .add-form label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.85rem; }

  .scope-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }
  .scope-row { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
  .scope-row .summary { font-size: 0.78rem; opacity: 0.7; flex: 1; }

  .drawer { flex: 1 1 20rem; min-width: 18rem; position: sticky; top: 1rem; }
  .explain-form { display: flex; flex-direction: column; gap: 0.5rem; }
  .explain-form label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.85rem; }
  .explain-summary { font-size: 0.85rem; margin: 0.25rem 0; }
  .explain-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  .explain-table th, .explain-table td { text-align: left; padding: 0.25rem 0.5rem; border-bottom: 1px solid var(--border); }
  .badge.source-global { background: color-mix(in srgb, gray 20%, var(--nav-hover-bg)); }
  .badge.source-network { background: color-mix(in srgb, dodgerblue 20%, var(--nav-hover-bg)); }
  .badge.source-group { background: color-mix(in srgb, orange 20%, var(--nav-hover-bg)); }
  .badge.source-client { background: color-mix(in srgb, green 20%, var(--nav-hover-bg)); }

  .link-btn { background: none; border: none; padding: 0; color: var(--accent, #4a7); text-decoration: underline; cursor: pointer; font: inherit; }

  @media (max-width: 60rem) {
    .layout { flex-direction: column; }
    .drawer { position: static; width: 100%; }
  }
</style>
