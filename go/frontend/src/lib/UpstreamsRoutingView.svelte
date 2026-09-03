<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type UpstreamProfile, type UpstreamEndpointInput, type DNSRuntimeApplyResult, type DomainRoute, type DomainRoutingRuleset, type DNSPerfStatusResponse } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";
  import DataGrid from "./DataGrid.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";
  import type { Column } from "./datagrid";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";

  // Upstreams & Routing (Advanced). Native Go implementation (own
  // schema/CRUD, not a Python proxy) -- see internal/upstreams's doc
  // comment for what's preserved (transport/strategy/endpoint
  // validation, the last-enabled-managed-upstream confirm dance,
  // reorder). Every mutation compiles and auto-applies through the real
  // DNS runtime. The simplified Standard > DNS page manages the same
  // real upstream profiles through a lighter form -- see that page's
  // own doc comment for exactly what it omits.

  let profiles = $state<UpstreamProfile[]>([]);
  let nativeRecursionActive = $state(false);
  let loadError = $state("");
  const guard = new StaleGuard();

  let activeTab = $state<"groups" | "routes" | "bootstrap">("groups");

  let pendingAction = $state<Set<string>>(new Set());
  let confirmLastFor = $state<string | null>(null);
  let confirmLastVerb = $state<"disable" | "delete">("disable");

  let editingId = $state<string | null>(null);
  let formName = $state("");
  let formTransport = $state<"plain" | "dot" | "doh">("plain");
  let formStrategy = $state<"ordered" | "failover" | "load_balanced">("ordered");
  let formEndpoints = $state<UpstreamEndpointInput[]>([{ address: "", priority: 0, weight: 1, tls_hostname: "", doh_path: "" }]);
  let formBusy = $state(false);
  let formError = $state("");
  let formOpen = $state(false);
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);

  let applyElapsedMs = $state(0);
  let applyTimer: ReturnType<typeof setInterval> | undefined;
  function startApplyTimer() {
    applyElapsedMs = 0;
    const startedAt = Date.now();
    applyTimer = setInterval(() => (applyElapsedMs = Date.now() - startedAt), 200);
  }
  function stopApplyTimer() {
    if (applyTimer) clearInterval(applyTimer);
    applyTimer = undefined;
  }

  async function refresh(): Promise<void> {
    const token = guard.start();
    try {
      const resp = await api.listUpstreams(router.signal());
      if (!guard.isCurrent(token)) return;
      profiles = resp.upstreams;
      nativeRecursionActive = resp.native_recursion_active;
      loadError = "";
    } catch (err) {
      if (!guard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof Error ? err.message : String(err);
    }
  }

  let domainRoutes = $state<DomainRoute[]>([]);
  let routeMatchKind = $state<"exact" | "suffix">("suffix");
  let routeDomain = $state("");
  let routeProfileID = $state("");
  let routeRulesetID = $state("");
  let routeBusy = $state(false);
  let routeError = $state("");
  const routeGuard = new StaleGuard();

  let rulesets = $state<DomainRoutingRuleset[]>([]);
  let newRulesetId = $state("");
  let newRulesetName = $state("");
  let rulesetBusy = $state(false);
  let rulesetError = $state("");

  async function refreshRoutes(): Promise<void> {
    const token = routeGuard.start();
    try {
      const [routesResp, rulesetsResp] = await Promise.all([api.listDomainRoutes(router.signal()), api.listDomainRoutingRulesets(router.signal())]);
      if (!routeGuard.isCurrent(token)) return;
      domainRoutes = routesResp.rules;
      rulesets = rulesetsResp.rulesets;
    } catch (err) {
      if (!routeGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      routeError = err instanceof Error ? err.message : String(err);
    }
  }

  async function submitRoute(e: Event) {
    e.preventDefault();
    routeError = "";
    routeBusy = true;
    try {
      const resp = await api.createDomainRoute({
        match_kind: routeMatchKind, domain: routeDomain.trim(),
        upstream_profile_id: routeProfileID, ruleset_id: routeRulesetID || undefined,
      });
      dnsRuntimeResult = resp.dns_runtime ?? null;
      routeDomain = "";
      await refreshRoutes();
    } catch (err) {
      routeError = err instanceof ApiError ? err.message : String(err);
    } finally {
      routeBusy = false;
    }
  }

  async function createRuleset(e: Event) {
    e.preventDefault();
    rulesetError = "";
    rulesetBusy = true;
    try {
      await api.createDomainRoutingRuleset({ id: newRulesetId.trim(), name: newRulesetName.trim() });
      newRulesetId = "";
      newRulesetName = "";
      await refreshRoutes();
    } catch (err) {
      rulesetError = err instanceof ApiError ? err.message : String(err);
    } finally {
      rulesetBusy = false;
    }
  }

  let confirmDeleteRuleset = $state<DomainRoutingRuleset | null>(null);
  function deleteRuleset(rs: DomainRoutingRuleset) { confirmDeleteRuleset = rs; }
  async function runDeleteRuleset() {
    const rs = confirmDeleteRuleset;
    confirmDeleteRuleset = null;
    if (!rs) return;
    rulesetError = "";
    try {
      await api.deleteDomainRoutingRuleset(rs.id);
      await refreshRoutes();
    } catch (err) {
      rulesetError = err instanceof ApiError ? err.message : String(err);
    }
  }

  let confirmDeleteRoute = $state<DomainRoute | null>(null);
  function deleteRoute(r: DomainRoute) { confirmDeleteRoute = r; }
  async function runDeleteRoute() {
    const r = confirmDeleteRoute;
    confirmDeleteRoute = null;
    if (!r) return;
    routeBusy = true;
    try {
      const resp = await api.deleteDomainRoute(r.id);
      dnsRuntimeResult = resp.dns_runtime ?? null;
      await refreshRoutes();
    } catch (err) {
      routeError = err instanceof ApiError ? err.message : String(err);
    } finally {
      routeBusy = false;
    }
  }

  let confirmDeleteProfile = $state<UpstreamProfile | null>(null);
  function requestDeleteProfile(p: UpstreamProfile) { confirmDeleteProfile = p; }
  async function runDeleteProfile() {
    const p = confirmDeleteProfile;
    confirmDeleteProfile = null;
    if (p) await onDelete(p);
  }

  // --- Health & performance: reuses the same real DNS Performance
  // benchmark System Status runs (internal/dnsperf) -- "Test Upstreams"
  // here is the same real, bounded, sequential probe, not a second
  // implementation. ---
  let perfStatus = $state<DNSPerfStatusResponse | null>(null);
  let perfError = $state("");
  async function loadPerf() {
    try {
      perfStatus = await api.dnsPerformanceStatus(router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      perfError = err instanceof ApiError ? err.message : String(err);
    }
  }
  async function runPerfTest() {
    perfError = "";
    try {
      await api.dnsPerformanceRun();
      const poll = setInterval(async () => {
        await loadPerf();
        if (!perfStatus?.benchmark_running) clearInterval(poll);
      }, 1000);
    } catch (err) {
      perfError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
    refreshRoutes();
    loadPerf();
  });

  function resetForm() {
    editingId = null;
    formName = "";
    formTransport = "plain";
    formStrategy = "ordered";
    formEndpoints = [{ address: "", priority: 0, weight: 1, tls_hostname: "", doh_path: "" }];
    formError = "";
    formOpen = false;
  }

  function startEdit(p: UpstreamProfile) {
    editingId = p.upstream_profile_id;
    formName = p.name;
    formTransport = p.transport;
    formStrategy = p.strategy;
    formEndpoints = p.endpoints.map((e) => ({ address: e.address, priority: e.priority, weight: e.weight, tls_hostname: e.tls_hostname ?? "", doh_path: e.doh_path ?? "" }));
    formError = "";
    formOpen = true;
  }

  function addEndpointRow() {
    formEndpoints = [...formEndpoints, { address: "", priority: formEndpoints.length, weight: 1, tls_hostname: "", doh_path: "" }];
  }
  function removeEndpointRow(i: number) {
    formEndpoints = formEndpoints.filter((_, idx) => idx !== i);
  }

  async function submitForm(e: Event) {
    e.preventDefault();
    formError = "";
    formBusy = true;
    startApplyTimer();
    const body = {
      name: formName, transport: formTransport, strategy: formStrategy,
      endpoints: formEndpoints.filter((ep) => ep.address.trim() !== "").map((ep) => ({
        address: ep.address.trim(), priority: ep.priority, weight: ep.weight || 1,
        tls_hostname: ep.tls_hostname?.trim() || null, doh_path: ep.doh_path?.trim() || null,
      })),
    };
    try {
      const resp = editingId ? await api.updateUpstream(editingId, body) : await api.createUpstream(body);
      dnsRuntimeResult = resp.dns_runtime ?? null;
      resetForm();
      await refresh();
    } catch (err) {
      formError = err instanceof ApiError ? err.message : String(err);
    } finally {
      formBusy = false;
      stopApplyTimer();
    }
  }

  function withPending<T>(id: string, fn: () => Promise<T>): Promise<T> {
    pendingAction = new Set(pendingAction).add(id);
    return fn().finally(() => {
      const next = new Set(pendingAction);
      next.delete(id);
      pendingAction = next;
    });
  }

  async function onEnable(p: UpstreamProfile) {
    const resp = await withPending(p.upstream_profile_id, () => api.enableUpstream(p.upstream_profile_id));
    dnsRuntimeResult = resp.dns_runtime ?? null;
    await refresh();
  }
  async function onDisable(p: UpstreamProfile, confirmed = false) {
    try {
      const resp = await withPending(p.upstream_profile_id, () => api.disableUpstream(p.upstream_profile_id, confirmed));
      dnsRuntimeResult = resp.dns_runtime ?? null;
      confirmLastFor = null;
      await refresh();
    } catch (err) {
      if (err instanceof ApiError && err.code === "last_enabled_upstream") {
        confirmLastFor = p.upstream_profile_id;
        confirmLastVerb = "disable";
        return;
      }
      loadError = err instanceof Error ? err.message : String(err);
    }
  }
  async function onDelete(p: UpstreamProfile, confirmed = false) {
    try {
      const resp = await withPending(p.upstream_profile_id, () => api.deleteUpstream(p.upstream_profile_id, confirmed));
      dnsRuntimeResult = resp.dns_runtime ?? null;
      confirmLastFor = null;
      await refresh();
    } catch (err) {
      if (err instanceof ApiError && err.code === "last_enabled_upstream") {
        confirmLastFor = p.upstream_profile_id;
        confirmLastVerb = "delete";
        return;
      }
      loadError = err instanceof Error ? err.message : String(err);
    }
  }
  async function move(p: UpstreamProfile, dir: -1 | 1) {
    const ids = profiles.map((x) => x.upstream_profile_id);
    const i = ids.indexOf(p.upstream_profile_id);
    const j = i + dir;
    if (j < 0 || j >= ids.length) return;
    [ids[i], ids[j]] = [ids[j], ids[i]];
    const resp = await api.reorderUpstreams(ids);
    dnsRuntimeResult = resp.dns_runtime ?? null;
    await refresh();
  }

  const columns: Column<UpstreamProfile>[] = [
    { key: "order", label: "Order", sortValue: (p) => p.order, minWidth: 6 },
    { key: "name", label: "Name", sortValue: (p) => p.name.toLowerCase(), minWidth: 12 },
    { key: "transport", label: "Transport", sortValue: (p) => p.transport, minWidth: 8 },
    { key: "addresses", label: "Addresses", minWidth: 16 },
    { key: "strategy", label: "Strategy", sortValue: (p) => p.strategy, minWidth: 10 },
    { key: "status", label: "Health", sortValue: (p) => (p.enabled ? 1 : 0), minWidth: 8 },
    { key: "actions", label: "Actions", minWidth: 24 },
  ];
</script>

<PageHeader
  headingId="upstreams-heading"
  title="Upstreams &amp; Routing"
  description="The complete upstream groups, domain routing, and resolver health/performance workflow. Standard > DNS manages the same profiles through a simplified form."
>
  {#snippet actions()}
    <button type="button" onclick={() => { resetForm(); formOpen = true; }}>Add Upstream Group</button>
  {/snippet}
</PageHeader>

{#if nativeRecursionActive}
  <p class="info-banner" role="status">
    No managed upstream is currently enabled. BIND is performing normal native recursive
    resolution using the root/authoritative DNS hierarchy.
  </p>
{/if}
{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
<DnsRuntimeBadge result={dnsRuntimeResult} />

<div class="tabs" role="tablist" aria-label="Upstreams and routing">
  <button type="button" role="tab" aria-selected={activeTab === "groups"} class:active={activeTab === "groups"} onclick={() => (activeTab = "groups")}>Upstream Groups</button>
  <button type="button" role="tab" aria-selected={activeTab === "routes"} class:active={activeTab === "routes"} onclick={() => (activeTab = "routes")}>Domain Routes</button>
  <button type="button" role="tab" aria-selected={activeTab === "bootstrap"} class:active={activeTab === "bootstrap"} onclick={() => (activeTab = "bootstrap")}>Bootstrap / Fallback / Health</button>
</div>

{#if activeTab === "groups"}
  {#if formOpen}
    <form onsubmit={submitForm} class="profile-form">
      <h3>{editingId ? `Edit "${editingId}"` : "Add upstream group"}</h3>
      <div class="form-row">
        <label>Name <input required bind:value={formName} /></label>
        <label>
          Transport
          <select bind:value={formTransport}>
            <option value="plain">Plain (UDP/TCP 53)</option>
            <option value="dot">DNS-over-TLS</option>
            <option value="doh">DNS-over-HTTPS</option>
          </select>
        </label>
        <label>
          Strategy
          <select bind:value={formStrategy}>
            <option value="ordered">Ordered (first available)</option>
            <option value="failover">Failover</option>
            <option value="load_balanced">Load balanced</option>
          </select>
        </label>
      </div>
      <div class="endpoints-editor">
        <p class="endpoints-label">Endpoints</p>
        {#each formEndpoints as ep, i}
          <div class="endpoint-row">
            <input placeholder="Address (e.g. 1.1.1.1)" required bind:value={ep.address} aria-label={`Endpoint ${i + 1} address`} />
            {#if formTransport !== "plain"}
              <input placeholder="TLS hostname" bind:value={ep.tls_hostname} aria-label={`Endpoint ${i + 1} TLS hostname`} />
            {/if}
            {#if formTransport === "doh"}
              <input placeholder="/dns-query" bind:value={ep.doh_path} aria-label={`Endpoint ${i + 1} DoH path`} />
            {/if}
            <input type="number" min="0" bind:value={ep.priority} class="narrow" aria-label={`Endpoint ${i + 1} priority`} title="Priority" />
            <input type="number" min="1" bind:value={ep.weight} class="narrow" aria-label={`Endpoint ${i + 1} weight`} title="Weight" />
            {#if formEndpoints.length > 1}
              <button type="button" onclick={() => removeEndpointRow(i)} aria-label={`Remove endpoint ${i + 1}`}>&times;</button>
            {/if}
          </div>
        {/each}
        <button type="button" onclick={addEndpointRow} class="add-endpoint-btn">+ Add endpoint</button>
      </div>
      <div class="form-actions">
        <button type="submit" disabled={formBusy}>{formBusy ? "Saving…" : editingId ? "Save changes" : "Add group"}</button>
        <button type="button" class="secondary" onclick={resetForm}>Cancel</button>
      </div>
      {#if formBusy}
        <p class="applying-note" role="status">
          Applying to the DNS runtime ({(applyElapsedMs / 1000).toFixed(1)}s elapsed) -- this can take up to 30
          seconds while it recompiles, restarts the resolver, and verifies DNS is answering correctly.
        </p>
      {/if}
      {#if formError}<p class="error" role="alert">{formError}</p>{/if}
    </form>
  {/if}

  <DataGrid gridId="upstream-profiles" {columns} rows={profiles} rowKey={(p) => p.upstream_profile_id} emptyMessage="No upstream groups configured yet.">
    {#snippet cell(p, colKey)}
      {#if colKey === "order"}
        {p.order}
      {:else if colKey === "name"}
        {p.name}
      {:else if colKey === "transport"}
        {p.transport}
      {:else if colKey === "addresses"}
        <span class="chips">{#each p.endpoints as ep}<span class="chip">{ep.address}</span>{/each}</span>
      {:else if colKey === "strategy"}
        {p.strategy}
      {:else if colKey === "status"}
        <StatusBadge label={p.enabled ? "Enabled" : "Disabled"} tone={p.enabled ? "healthy" : "neutral"} />
      {:else if colKey === "actions"}
        <div class="actions">
          <button type="button" class="secondary small" onclick={() => startEdit(p)}>Edit</button>
          {#if p.enabled}
            <button type="button" class="secondary small" onclick={() => onDisable(p)} disabled={pendingAction.has(p.upstream_profile_id)}>Disable</button>
          {:else}
            <button type="button" class="secondary small" onclick={() => onEnable(p)} disabled={pendingAction.has(p.upstream_profile_id)}>Enable</button>
          {/if}
          <button type="button" class="secondary small danger" onclick={() => requestDeleteProfile(p)} disabled={pendingAction.has(p.upstream_profile_id)}>Delete</button>
          <button type="button" class="secondary small" onclick={() => move(p, -1)} aria-label={`Move ${p.name} up`}>&uarr;</button>
          <button type="button" class="secondary small" onclick={() => move(p, 1)} aria-label={`Move ${p.name} down`}>&darr;</button>
        </div>
        {#if confirmLastFor === p.upstream_profile_id}
          <div class="confirm-last" role="alertdialog">
            <p>
              This is the final enabled managed upstream. {confirmLastVerb === "disable" ? "Disabling" : "Deleting"} it leaves
              zero managed forwarders -- BIND will perform normal native recursion. Confirm?
            </p>
            <button type="button" class="danger" onclick={() => (confirmLastVerb === "disable" ? onDisable(p, true) : onDelete(p, true))}>Confirm {confirmLastVerb}</button>
            <button type="button" class="secondary" onclick={() => (confirmLastFor = null)}>Cancel</button>
          </div>
        {/if}
      {/if}
    {/snippet}
  </DataGrid>
{:else if activeTab === "routes"}
  <div class="card">
    <p class="scope-note">
      Exact/suffix domain rules that send matching queries to a different upstream group instead
      of the default one. A route with no ruleset applies globally, in every scope; a route
      assigned to a named ruleset only applies to a network/group/client whose own policy selects
      that ruleset (see Scope Policies). The most specific match always wins.
    </p>

    <div class="ruleset-row">
      <h4>Rulesets</h4>
      <div class="ruleset-list">
        {#each rulesets as rs (rs.id)}
          <span class="ruleset-chip">{rs.name} <button type="button" onclick={() => deleteRuleset(rs)} title="Delete">×</button></span>
        {:else}
          <span class="hint">No named rulesets yet -- every route below applies globally.</span>
        {/each}
      </div>
      <form onsubmit={createRuleset} class="ruleset-form">
        <input placeholder="id (e.g. kids-routes)" bind:value={newRulesetId} required aria-label="Ruleset id" />
        <input placeholder="Display name" bind:value={newRulesetName} required aria-label="Ruleset name" />
        <button type="submit" disabled={rulesetBusy}>{rulesetBusy ? "Adding…" : "New Ruleset"}</button>
      </form>
      {#if rulesetError}<p class="error" role="alert">{rulesetError}</p>{/if}
    </div>

    <form class="route-form" onsubmit={submitRoute}>
      <select bind:value={routeMatchKind} aria-label="Match kind">
        <option value="suffix">Suffix (matches subdomains too)</option>
        <option value="exact">Exact (this name only)</option>
      </select>
      <input type="text" placeholder="corp.example.com" bind:value={routeDomain} required aria-label="Domain" />
      <select bind:value={routeProfileID} required aria-label="Upstream group">
        <option value="" disabled selected>Upstream group…</option>
        {#each profiles as p (p.upstream_profile_id)}<option value={p.upstream_profile_id}>{p.name}</option>{/each}
      </select>
      <select bind:value={routeRulesetID} aria-label="Ruleset">
        <option value="">Global (every scope)</option>
        {#each rulesets as rs (rs.id)}<option value={rs.id}>{rs.name}</option>{/each}
      </select>
      <button type="submit" disabled={routeBusy || !routeProfileID}>{routeBusy ? "Adding…" : "Add Route"}</button>
    </form>
    {#if routeError}<p class="error" role="alert">{routeError}</p>{/if}

    <table class="routes-table">
      <thead><tr><th>Match</th><th>Domain</th><th>Upstream</th><th>Ruleset</th><th>Priority</th><th>Actions</th></tr></thead>
      <tbody>
        {#each domainRoutes as r (r.id)}
          <tr>
            <td>{r.match_kind}</td>
            <td>{r.domain}</td>
            <td>{profiles.find((p) => p.upstream_profile_id === r.upstream_profile_id)?.name ?? r.upstream_profile_id}</td>
            <td>{r.ruleset_id ? (rulesets.find((rs) => rs.id === r.ruleset_id)?.name ?? r.ruleset_id) : "Global"}</td>
            <td>{r.match_kind === "exact" ? "Highest" : r.domain.split(".").length}</td>
            <td><button type="button" class="secondary small danger" onclick={() => deleteRoute(r)} disabled={routeBusy}>Delete</button></td>
          </tr>
        {:else}
          <tr class="empty-row"><td colspan="6">No domain routes configured.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
{:else}
  <div class="grid-2col">
    <div class="card">
      <h3>Bootstrap resolvers</h3>
      <p class="hint">
        Not applicable to this appliance's architecture -- every upstream endpoint is configured as
        a literal IP address (see Upstream Groups), never a hostname that would itself need a
        separate bootstrap resolver to look up first.
      </p>
    </div>
    <div class="card">
      <h3>Fallback</h3>
      <p class="hint">
        Handled by each upstream group's own Strategy (Failover moves to the next endpoint when
        one is unreachable) and by group Order above (a disabled or failing group's traffic falls
        to the next enabled group) -- not a separate fallback list.
      </p>
    </div>
  </div>

  <div class="card wide">
    <h3>Health &amp; Performance</h3>
    <p class="hint">
      A bounded, sequential set of real DNS/DoT/DoH queries against this appliance's own live
      resolvers -- the same real benchmark System Status runs, not a second implementation.
    </p>
    <button type="button" onclick={runPerfTest} disabled={perfStatus?.benchmark_running}>
      {perfStatus?.benchmark_running ? "Running…" : "Test Upstreams"}
    </button>
    {#if perfError}<p class="error" role="alert">{perfError}</p>{/if}
    {#if perfStatus?.report}
      <table class="perf-table">
        <thead><tr><th>Case</th><th>Protocol</th><th>Success</th><th>p50</th><th>p95</th><th>p99</th></tr></thead>
        <tbody>
          {#each perfStatus.report.cases as c (c.name)}
            <tr>
              <td>{c.name}</td><td>{c.protocol}</td>
              <td>{c.summary.count ? Math.round((c.summary.success / c.summary.count) * 100) : 0}%</td>
              <td>{c.summary.p50_ms !== null ? `${c.summary.p50_ms} ms` : "—"}</td>
              <td>{c.summary.p95_ms !== null ? `${c.summary.p95_ms} ms` : "—"}</td>
              <td>{c.summary.p99_ms !== null ? `${c.summary.p99_ms} ms` : "—"}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="hint">No test run yet this session.</p>
    {/if}
  </div>
{/if}

{#if confirmDeleteProfile}
  <ConfirmDialog title="Delete upstream group" message={`Delete "${confirmDeleteProfile.name}"? This takes effect on the live DNS runtime immediately.`} confirmLabel="Delete" onConfirm={runDeleteProfile} onCancel={() => (confirmDeleteProfile = null)} />
{/if}
{#if confirmDeleteRuleset}
  <ConfirmDialog title="Delete ruleset" message={`Delete the domain routing ruleset "${confirmDeleteRuleset.name}"? Any domain route assigned to it stops being scoped to it.`} confirmLabel="Delete" onConfirm={runDeleteRuleset} onCancel={() => (confirmDeleteRuleset = null)} />
{/if}
{#if confirmDeleteRoute}
  <ConfirmDialog title="Delete domain route" message={`Delete the route for "${confirmDeleteRoute.domain}"? This takes effect on the live DNS runtime immediately.`} confirmLabel="Delete" onConfirm={runDeleteRoute} onCancel={() => (confirmDeleteRoute = null)} />
{/if}

<style>
  .info-banner { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.6rem 0.9rem; border-radius: 6px; font-size: 0.88rem; margin-bottom: 0.75rem; }
  .error { color: var(--danger); }
  .hint { font-size: 0.85rem; opacity: 0.75; }

  .tabs { display: flex; gap: 0.3rem; border-bottom: 1px solid var(--border); margin: 0.75rem 0 1rem; flex-wrap: wrap; }
  .tabs button { background: transparent; color: var(--muted); border: none; border-bottom: 2px solid transparent; border-radius: 0; padding: 0.55rem 0.2rem; margin-right: 1.25rem; font-weight: 600; min-height: auto; }
  .tabs button.active { color: var(--fg); border-bottom-color: var(--accent); }

  .profile-form { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 1rem; }
  .profile-form h3 { margin: 0; }
  .form-row { display: flex; flex-wrap: wrap; gap: 0.75rem; }
  .form-row label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .endpoints-editor { display: flex; flex-direction: column; gap: 0.4rem; }
  .endpoints-label { font-size: 0.8rem; opacity: 0.75; margin: 0; }
  .endpoint-row { display: flex; gap: 0.4rem; flex-wrap: wrap; align-items: center; }
  .endpoint-row input { flex: 1 1 8rem; }
  .endpoint-row input.narrow { flex: 0 0 4rem; }
  .add-endpoint-btn { align-self: flex-start; background: transparent; color: var(--fg); border: 1px dashed var(--border); }
  .form-actions { display: flex; gap: 0.5rem; }
  .applying-note { font-size: 0.82rem; opacity: 0.85; background: var(--panel-elevated); border-radius: 6px; padding: 0.5rem 0.75rem; margin: 0; }
  .chips { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  .chip { background: var(--nav-hover-bg); padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.78rem; }
  .actions { display: flex; gap: 0.3rem; flex-wrap: wrap; }
  button.secondary.small { min-height: auto; padding: 0.3rem 0.6rem; font-size: 0.8rem; }
  .danger { color: var(--danger); }
  .confirm-last { margin-top: 0.5rem; padding: 0.6rem 0.8rem; border-radius: 6px; background: var(--attention-bg); display: flex; flex-direction: column; gap: 0.4rem; max-width: 26rem; }
  .confirm-last p { margin: 0; font-size: 0.85rem; }
  button.danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.75rem; }
  .card.wide { margin-top: 1rem; }
  .card h3 { margin: 0; }
  .grid-2col { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .route-form { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
  .route-form input { flex: 1 1 12rem; }
  .ruleset-row { border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 0.8rem; display: flex; flex-direction: column; gap: 0.4rem; }
  .ruleset-row h4 { margin: 0; font-size: 0.85rem; }
  .ruleset-list { display: flex; flex-wrap: wrap; gap: 0.4rem; }
  .ruleset-chip { background: var(--card-bg); border: 1px solid var(--border); border-radius: 999px; padding: 0.15rem 0.6rem; font-size: 0.8rem; display: inline-flex; align-items: center; gap: 0.3rem; }
  .ruleset-chip button { border: none; background: none; cursor: pointer; opacity: 0.6; }
  .ruleset-form { display: flex; gap: 0.4rem; flex-wrap: wrap; }
  .ruleset-form input { flex: 1 1 8rem; }
  .routes-table, .perf-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .routes-table th, .routes-table td, .perf-table th, .perf-table td { text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border); }
  .empty-row td { opacity: 0.6; font-style: italic; }
</style>
