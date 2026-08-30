<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type UpstreamProfile, type UpstreamEndpointInput, type DNSRuntimeApplyResult, type DomainRoute } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import DataGrid from "./DataGrid.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";
  import type { Column } from "./datagrid";

  // Native Go implementation (own schema/CRUD, not a Python proxy) --
  // see internal/upstreams's doc comment for what's preserved
  // (transport/strategy/endpoint validation, the last-enabled-managed-
  // upstream confirm dance, reorder). Every mutation now compiles and
  // auto-applies through the real DNS runtime (internal/dnscompile,
  // internal/dnsruntime) -- see the dns_runtime feedback below each
  // action, matching every other resolver-affecting page's own
  // auto-apply contract.

  let profiles = $state<UpstreamProfile[]>([]);
  let nativeRecursionActive = $state(false);
  let loadError = $state("");
  const guard = new StaleGuard();

  let pendingAction = $state<Set<string>>(new Set());
  let confirmLastFor = $state<string | null>(null); // upstream_profile_id awaiting last-enabled confirmation
  let confirmLastVerb = $state<"disable" | "delete">("disable");

  // --- create/edit form ---
  let editingId = $state<string | null>(null); // null = create mode
  let formName = $state("");
  let formTransport = $state<"plain" | "dot" | "doh">("plain");
  let formStrategy = $state<"ordered" | "failover" | "load_balanced">("ordered");
  let formEndpoints = $state<UpstreamEndpointInput[]>([{ address: "", priority: 0, weight: 1, tls_hostname: "", doh_path: "" }]);
  let formBusy = $state(false);
  let formError = $state("");
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);

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

  // --- domain routing (see internal/domainrouting's own doc comment:
  // one flat global list of exact/suffix rules, not Python's real
  // per-network rulesets -- a route is real and auto-applies through
  // the same DNS runtime every other mutation on this page does) ---
  let domainRoutes = $state<DomainRoute[]>([]);
  let routeMatchKind = $state<"exact" | "suffix">("suffix");
  let routeDomain = $state("");
  let routeProfileID = $state("");
  let routeBusy = $state(false);
  let routeError = $state("");
  const routeGuard = new StaleGuard();

  async function refreshRoutes(): Promise<void> {
    const token = routeGuard.start();
    try {
      const resp = await api.listDomainRoutes(router.signal());
      if (!routeGuard.isCurrent(token)) return;
      domainRoutes = resp.rules;
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
      const resp = await api.createDomainRoute({ match_kind: routeMatchKind, domain: routeDomain.trim(), upstream_profile_id: routeProfileID });
      dnsRuntimeResult = resp.dns_runtime ?? null;
      routeDomain = "";
      await refreshRoutes();
    } catch (err) {
      routeError = err instanceof ApiError ? err.message : String(err);
    } finally {
      routeBusy = false;
    }
  }

  async function deleteRoute(r: DomainRoute) {
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

  onMount(() => {
    refresh();
    refreshRoutes();
  });

  function resetForm() {
    editingId = null;
    formName = "";
    formTransport = "plain";
    formStrategy = "ordered";
    formEndpoints = [{ address: "", priority: 0, weight: 1, tls_hostname: "", doh_path: "" }];
    formError = "";
  }

  function startEdit(p: UpstreamProfile) {
    editingId = p.upstream_profile_id;
    formName = p.name;
    formTransport = p.transport;
    formStrategy = p.strategy;
    formEndpoints = p.endpoints.map((e) => ({ address: e.address, priority: e.priority, weight: e.weight, tls_hostname: e.tls_hostname ?? "", doh_path: e.doh_path ?? "" }));
    formError = "";
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
    const body = {
      name: formName,
      transport: formTransport,
      strategy: formStrategy,
      endpoints: formEndpoints
        .filter((ep) => ep.address.trim() !== "")
        .map((ep) => ({
          address: ep.address.trim(),
          priority: ep.priority,
          weight: ep.weight || 1,
          tls_hostname: ep.tls_hostname?.trim() || null,
          doh_path: ep.doh_path?.trim() || null,
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
    { key: "status", label: "Status", sortValue: (p) => (p.enabled ? 1 : 0), minWidth: 8 },
    { key: "actions", label: "Actions", minWidth: 24 },
  ];
</script>

<section aria-labelledby="upstreams-heading" class="upstreams">
  <h2 id="upstreams-heading">DNS Settings</h2>

  {#if nativeRecursionActive}
    <p class="info-banner" role="status">
      No managed upstream is currently enabled. BIND is performing normal native recursive
      resolution using the root/authoritative DNS hierarchy.
    </p>
  {/if}
  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
  <DnsRuntimeBadge result={dnsRuntimeResult} />

  <form onsubmit={submitForm} class="profile-form">
    <h3>{editingId ? `Edit "${editingId}"` : "Add upstream profile"}</h3>
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
      <button type="submit" disabled={formBusy}>{formBusy ? "Saving…" : editingId ? "Save changes" : "Add profile"}</button>
      {#if editingId}<button type="button" onclick={resetForm}>Cancel</button>{/if}
    </div>
    {#if formError}<p class="error" role="alert">{formError}</p>{/if}
  </form>

  <DataGrid gridId="upstream-profiles" {columns} rows={profiles} rowKey={(p) => p.upstream_profile_id} emptyMessage="No upstream profiles configured yet.">
    {#snippet cell(p, colKey)}
      {#if colKey === "order"}
        {p.order}
      {:else if colKey === "name"}
        {p.name}
      {:else if colKey === "transport"}
        {p.transport}
      {:else if colKey === "addresses"}
        <span class="chips">
          {#each p.endpoints as ep}
            <span class="chip">{ep.address}</span>
          {/each}
        </span>
      {:else if colKey === "strategy"}
        {p.strategy}
      {:else if colKey === "status"}
        <span class="badge" class:badge-ok={p.enabled} class:badge-warn={!p.enabled}>{p.enabled ? "Enabled" : "Disabled"}</span>
      {:else if colKey === "actions"}
        <div class="actions">
          <button onclick={() => startEdit(p)}>Edit</button>
          {#if p.enabled}
            <button onclick={() => onDisable(p)} disabled={pendingAction.has(p.upstream_profile_id)}>Disable</button>
          {:else}
            <button onclick={() => onEnable(p)} disabled={pendingAction.has(p.upstream_profile_id)}>Enable</button>
          {/if}
          <button onclick={() => onDelete(p)} disabled={pendingAction.has(p.upstream_profile_id)}>Delete</button>
          <button onclick={() => move(p, -1)} aria-label={`Move ${p.name} up`}>&uarr;</button>
          <button onclick={() => move(p, 1)} aria-label={`Move ${p.name} down`}>&darr;</button>
        </div>
        {#if confirmLastFor === p.upstream_profile_id}
          <div class="confirm-last" role="alertdialog">
            <p>
              This is the final enabled managed upstream. {confirmLastVerb === "disable" ? "Disabling" : "Deleting"} it leaves
              zero managed forwarders -- BIND will perform normal native recursion. Confirm?
            </p>
            <button
              class="danger"
              onclick={() => (confirmLastVerb === "disable" ? onDisable(p, true) : onDelete(p, true))}
            >
              Confirm {confirmLastVerb}
            </button>
            <button onclick={() => (confirmLastFor = null)}>Cancel</button>
          </div>
        {/if}
      {/if}
    {/snippet}
  </DataGrid>

  <div class="card">
    <h3>Domain Routing</h3>
    <p class="scope-note">
      A flat, global list of exact/suffix domain rules that send matching queries to a different
      upstream profile instead of the default one. Per-network domain routing is planned for a
      future release. The most specific match always wins.
    </p>

    <form class="route-form" onsubmit={submitRoute}>
      <select bind:value={routeMatchKind} aria-label="Match kind">
        <option value="suffix">Suffix (matches subdomains too)</option>
        <option value="exact">Exact (this name only)</option>
      </select>
      <input type="text" placeholder="corp.example.com" bind:value={routeDomain} required aria-label="Domain" />
      <select bind:value={routeProfileID} required aria-label="Upstream profile">
        <option value="" disabled selected>Upstream profile…</option>
        {#each profiles as p (p.upstream_profile_id)}
          <option value={p.upstream_profile_id}>{p.name}</option>
        {/each}
      </select>
      <button type="submit" disabled={routeBusy || !routeProfileID}>{routeBusy ? "Adding…" : "Add Route"}</button>
    </form>
    {#if routeError}<p class="error" role="alert">{routeError}</p>{/if}

    <table class="routes-table">
      <thead><tr><th>Match</th><th>Domain</th><th>Upstream</th><th>Actions</th></tr></thead>
      <tbody>
        {#each domainRoutes as r (r.id)}
          <tr>
            <td>{r.match_kind}</td>
            <td>{r.domain}</td>
            <td>{profiles.find((p) => p.upstream_profile_id === r.upstream_profile_id)?.name ?? r.upstream_profile_id}</td>
            <td><button onclick={() => deleteRoute(r)} disabled={routeBusy}>Delete</button></td>
          </tr>
        {:else}
          <tr class="empty-row"><td colspan="4">No domain routes configured.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<style>
  .upstreams { display: flex; flex-direction: column; gap: 1rem; }
  .info-banner { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.6rem 0.9rem; border-radius: 6px; font-size: 0.88rem; }
  .profile-form { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.75rem; }
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
  .chips { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  .chip { background: var(--nav-hover-bg); padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.78rem; }
  .badge { padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.78rem; }
  .badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .badge-warn { background: var(--badge-warn-bg); color: var(--badge-warn-fg); }
  .actions { display: flex; gap: 0.3rem; flex-wrap: wrap; }
  .confirm-last { margin-top: 0.5rem; padding: 0.6rem 0.8rem; border-radius: 6px; background: var(--attention-bg); display: flex; flex-direction: column; gap: 0.4rem; max-width: 26rem; }
  .confirm-last p { margin: 0; font-size: 0.85rem; }
  .danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.75rem; }
  .card h3 { margin: 0; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .route-form { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
  .route-form input { flex: 1 1 12rem; }
  .routes-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .routes-table th, .routes-table td { text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border); }
  .empty-row td { opacity: 0.6; font-style: italic; }
</style>
