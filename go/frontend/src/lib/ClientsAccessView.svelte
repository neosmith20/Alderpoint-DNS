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
  import PageHeader from "./ui/PageHeader.svelte";
  import Panel from "./ui/Panel.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";

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

  // Inherited / Overrides / Effective (2026-09-03): every field a scope
  // can set, in the same order PolicyEditor presents them, so the
  // read-only summary table below lines up with the edit form under it.
  // Computed entirely client-side from data this page already loaded --
  // no new endpoint. This mirrors internal/policy/effective.go's own
  // "unset means inherit" rule for exactly two layers (a scope and
  // Global) -- Group vs. Network's real relative precedence, and
  // multi-group priority, is a per-CLIENT question that genuinely needs
  // a real client to resolve (which network it's in, which groups it
  // belongs to) -- that's exactly what Explain (right) answers for one
  // real client. This table intentionally does NOT pretend to guess
  // that without a client; it shows what THIS scope alone contributes
  // on top of Global, which is the honest, well-defined half of the
  // question.
  type PolicyFieldKey = keyof PolicyLayer;
  const FIELD_LABELS: [PolicyFieldKey, string][] = [
    ["filtering_profile_id", "Filtering profile"],
    ["parental_policy_id", "Parental policy"],
    ["security_policy_id", "Security policy"],
    ["service_blocking_ruleset_id", "Service blocking"],
    ["safesearch_mode", "Safesearch"],
    ["blocking_response_mode", "Blocking response"],
    ["custom_ipv4", "Custom IPv4"],
    ["custom_ipv6", "Custom IPv6"],
    ["ecs_mode", "ECS mode"],
    ["upstream_profile_id", "Upstream profile"],
    ["fallback_strategy", "Fallback strategy"],
    ["fallback_upstream_profile_id", "Fallback upstream profile"],
    ["domain_routing_ruleset_id", "Domain routing ruleset"],
    ["query_log_enabled", "Query log"],
    ["statistics_enabled", "Statistics"],
  ];

  function formatFieldValue(v: string | boolean | null | undefined): string {
    if (v === null || v === undefined || v === "") return "—";
    if (typeof v === "boolean") return v ? "Enabled" : "Disabled";
    return String(v);
  }

  function isSet(v: string | boolean | null | undefined): boolean {
    return v !== null && v !== undefined && v !== "";
  }

  interface EffectiveRow {
    key: PolicyFieldKey;
    label: string;
    inherited: string;
    override: string;
    effective: string;
    source: "this scope" | "inherited" | "built-in default";
  }

  function effectiveRows(base: PolicyLayer | null, override: PolicyLayer | null): EffectiveRow[] {
    return FIELD_LABELS.map(([key, label]) => {
      const overrideVal = override ? override[key] : null;
      const baseVal = base ? base[key] : null;
      const overridden = isSet(overrideVal);
      const effectiveVal = overridden ? overrideVal : baseVal;
      const source: EffectiveRow["source"] = overridden ? "this scope" : isSet(baseVal) ? "inherited" : "built-in default";
      return {
        key,
        label,
        inherited: formatFieldValue(baseVal),
        override: overridden ? formatFieldValue(overrideVal) : "(inherit)",
        effective: formatFieldValue(effectiveVal),
        source,
      };
    });
  }
</script>

{#snippet scopeTable(base: PolicyLayer | null, override: PolicyLayer | null, showInherited: boolean)}
  <div class="table-wrap">
    <table class="effective-table">
      <thead>
        <tr>
          <th>Field</th>
          {#if showInherited}<th>Inherited (Global)</th>{/if}
          <th>Override (this scope)</th>
          <th>Effective DNS behavior</th>
        </tr>
      </thead>
      <tbody>
        {#each effectiveRows(base, override) as row (row.key)}
          <tr class={row.source === "this scope" ? "row-overridden" : ""}>
            <td>{row.label}</td>
            {#if showInherited}<td>{row.inherited}</td>{/if}
            <td>{row.override}</td>
            <td><strong>{row.effective}</strong> <span class="badge {row.source === 'this scope' ? 'source-group' : row.source === 'inherited' ? 'source-global' : 'source-default'}">{row.source}</span></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/snippet}

<section aria-labelledby="clients-access-heading" class="clients-access">
  <PageHeader
    title="Scope Policies"
    headingId="clients-access-heading"
    description="Global default policy, network-scoped policy, group-scoped policy, and the explicit-deny > explicit-allow > default precedence that governs every client."
  />
  <Panel heading="Client Scope">
    {#snippet actions()}
      <StatusBadge label="Most specific -- above Group, Network, and Global" tone="accent" />
    {/snippet}
    <p class="hint">
      The most specific scope in the precedence chain (Client &gt; Group &gt; Network &gt; Global): a
      field set on a client's own identity wins over every scope shown below. Strong ClientID
      lifecycle (generate, add, display, copy, regenerate, revoke, DoH path, DoT/DoQ SNI), group
      membership, per-client policy fields, and per-domain overrides are all managed on the
      <button type="button" class="link-btn" onclick={() => router.navigate("clients")}>Clients</button> page,
      next to each identity they apply to -- not duplicated here. Use <strong>Explain Effective
      Policy</strong> (right) to see one real client's fully resolved, field-by-field effective DNS
      behavior across every scope, including its own client-level overrides.
    </p>
  </Panel>

  <div class="layout">
    <div class="scopes">
      <Panel heading="Global Policy">
        {#snippet actions()}
          <StatusBadge label="Applies to every client by default" tone="accent" />
        {/snippet}
        <p class="hint">
          The default policy every client falls back to unless a network, group, or client layer
          overrides a field. Enforced live by this appliance's own DNS runtime. This is the root
          scope -- it has nothing to inherit from; an unset field here falls back to this
          appliance's built-in default behavior.
        </p>
        {#if globalLoadError}<p class="error" role="alert">{globalLoadError}</p>{/if}
        {#if globalPolicy}
          <div class="policy-card">
            <h4>Selected scope: Global -- effective DNS behavior</h4>
            {@render scopeTable(null, globalPolicy, false)}
            <h4>Overrides at this scope</h4>
            <PolicyEditor layer={globalPolicy} onSave={(l) => api.putGlobalPolicy(l).then((res) => { refreshGlobal(); return res; })} />
          </div>
        {:else if !globalLoadError}
          <p class="hint">Loading…</p>
        {/if}
      </Panel>

      <Panel heading="Networks">
        {#snippet actions()}
          <StatusBadge label="{networks.length} configured" tone="neutral" />
        {/snippet}
        <p class="hint">
          A network is a CIDR range (e.g. a VLAN or subnet). Its policy layer applies to any client
          whose IP falls inside it, above global but below group/client layers.
          <strong>Enforced live:</strong> a network's own blocking-response fields
          (NXDOMAIN/REFUSED/null IP/custom IP), its own Filtering/Parental/Security profile
          category assignments, SafeSearch, ECS opt-in, per-network upstream/domain routing, and
          query-log/statistics participation all compile into the live DNS runtime whenever they
          differ from global (see the Filtering profile / Parental policy / Security policy /
          SafeSearch / ECS mode fields on the policy form below).
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
                    <h4>Selected scope: Network {n.cidr}</h4>
                    <p class="hint">
                      Inherited from Global unless overridden here. Effective DNS behavior below
                      assumes no Group layer also applies to a given client -- Group outranks
                      Network, so a client belonging to a group with its own value for a field
                      gets the group's value instead; see Explain (right) for one real client's
                      true fully-resolved result.
                    </p>
                    {@render scopeTable(globalPolicy, n.policy, true)}
                    <h4>Overrides at this scope</h4>
                    <PolicyEditor
                      layer={n.policy}
                      onSave={(l) => api.putNetworkPolicy(n.network_id, l).then((res) => { refreshNetworks(); return res; })}
                    />
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </Panel>

      <Panel heading="Groups">
        {#snippet actions()}
          <StatusBadge label="{groups.length} configured" tone="neutral" />
        {/snippet}
        <p class="hint">
          A group's policy layer applies to every client assigned to it, above network but below a
          client's own overrides. Create groups and assign clients to them on the
          <button type="button" class="link-btn" onclick={() => router.navigate("clients")}>Clients</button> page;
          this section edits the policy each group carries. <strong>Enforced live:</strong> a
          group's own fields are resolved into each real member client's own compiled DNS
          behavior (highest-priority group wins a field when a client belongs to more than one),
          the same precedence Explain shows. (Strong ClientID's own per-client domain overrides
          are a separate mechanism that also enforces live -- see the Clients page.)
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
                    <h4>Selected scope: Group {g.name}</h4>
                    <p class="hint">
                      Inherited from Global unless overridden here. Effective DNS behavior below
                      is what a member client gets for a field this group sets -- if that client
                      belongs to more than one group, the highest-priority group's value for that
                      field wins instead; see Explain (right) for one real client's true
                      fully-resolved result.
                    </p>
                    {@render scopeTable(globalPolicy, g.policy, true)}
                    <h4>Overrides at this scope</h4>
                    <PolicyEditor layer={g.policy} onSave={(l) => api.putGroupPolicy(g.group_id, l).then((res) => { refreshGroups(); return res; })} />
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </Panel>
    </div>

    <aside class="drawer">
    <Panel heading="Explain Effective Policy">
      <p class="hint">
        Resolves the real global -&gt; network -&gt; group -&gt; client precedence for one client, field by
        field, showing exactly which scope won each field. An optional client IP lets you check which network layer (if any) would
        match, independent of the client's own stored identifiers. Every scope shown here compiles
        into the live DNS runtime -- see each scope's own Save result above for real-time
        confirmation of the applied change.
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
    </Panel>
    </aside>
  </div>
</section>

<style>
  .clients-access { display: flex; flex-direction: column; gap: 1rem; }
  .hint { font-size: 0.85rem; opacity: 0.75; max-width: 44rem; }
  .empty { font-size: 0.85rem; opacity: 0.6; font-style: italic; }

  .layout { display: flex; gap: 1.25rem; align-items: flex-start; flex-wrap: wrap; }
  .scopes { display: flex; flex-direction: column; gap: 1rem; flex: 2 1 34rem; min-width: 26rem; }

  .badge { background: var(--nav-hover-bg); padding: 0.1rem 0.55rem; border-radius: 999px; font-size: 0.72rem; opacity: 0.85; white-space: nowrap; }

  .policy-card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--bg, transparent); display: flex; flex-direction: column; gap: 0.6rem; }
  .policy-card h4 { margin: 0.4rem 0 0; font-size: 0.85rem; }
  .policy-card h4:first-child { margin-top: 0; }
  .table-wrap { overflow-x: auto; }
  .effective-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  .effective-table th, .effective-table td { text-align: left; padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .effective-table td:last-child { white-space: normal; }
  .effective-table tr.row-overridden { background: var(--attention-bg, transparent); }
  .badge.source-default { opacity: 0.6; }
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
