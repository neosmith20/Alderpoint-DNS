<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type UpstreamProfile, type DNSRuntimeApplyResult } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";
  import Modal from "./ui/Modal.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";

  // DNS (Standard): normal resolver configuration -- which upstream DNS
  // servers this appliance uses, nothing more. Manages the exact same
  // real upstream profiles Advanced > Upstreams & Routing does (same
  // internal/upstreams backend, same DNS runtime auto-apply), just
  // through a simplified add form (plain DNS only, one address per
  // line, no transport/strategy/priority/weight/domain-routing
  // controls) -- see that page for the complete workflow.

  let profiles = $state<UpstreamProfile[]>([]);
  let nativeRecursionActive = $state(false);
  let loadError = $state("");
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);
  const guard = new StaleGuard();

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
  onMount(refresh);

  let addOpen = $state(false);
  let addName = $state("");
  let addAddresses = $state("");
  let addBusy = $state(false);
  let addError = $state("");

  async function submitAdd(e: Event) {
    e.preventDefault();
    addError = "";
    const addresses = addAddresses.split(/[\n,]/).map((a) => a.trim()).filter(Boolean);
    if (addresses.length === 0) {
      addError = "At least one resolver address is required.";
      return;
    }
    addBusy = true;
    try {
      const resp = await api.createUpstream({
        name: addName,
        transport: "plain",
        strategy: "ordered",
        endpoints: addresses.map((address, i) => ({ address, priority: i, weight: 1, tls_hostname: null, doh_path: null })),
      });
      dnsRuntimeResult = resp.dns_runtime ?? null;
      addName = "";
      addAddresses = "";
      addOpen = false;
      await refresh();
    } catch (err) {
      addError = err instanceof ApiError ? err.message : String(err);
    } finally {
      addBusy = false;
    }
  }

  let pendingAction = $state<Set<string>>(new Set());
  async function toggle(p: UpstreamProfile) {
    pendingAction = new Set(pendingAction).add(p.upstream_profile_id);
    try {
      const resp = p.enabled ? await api.disableUpstream(p.upstream_profile_id, false) : await api.enableUpstream(p.upstream_profile_id);
      dnsRuntimeResult = resp.dns_runtime ?? null;
      await refresh();
    } catch (err) {
      if (err instanceof ApiError && err.code === "last_enabled_upstream") {
        loadError = "This is the final enabled resolver -- disabling it leaves no managed upstream. Use Advanced > Upstreams & Routing to confirm that deliberately.";
      } else {
        loadError = err instanceof Error ? err.message : String(err);
      }
    } finally {
      const next = new Set(pendingAction);
      next.delete(p.upstream_profile_id);
      pendingAction = next;
    }
  }
</script>

<PageHeader
  headingId="dns-settings-heading"
  title="DNS"
  description="Which upstream DNS resolvers this appliance uses. For upstream groups, domain routing, and resolver health/performance, use Advanced > Upstreams & Routing."
>
  {#snippet actions()}
    <button type="button" onclick={() => (addOpen = true)}>Add Resolver</button>
    <button type="button" class="secondary" onclick={() => router.navigate("upstreams-routing")}>Advanced…</button>
  {/snippet}
</PageHeader>

{#if nativeRecursionActive}
  <p class="info-banner" role="status">
    No resolver is currently enabled. This appliance is performing normal native recursive
    resolution using the root/authoritative DNS hierarchy instead of a configured upstream.
  </p>
{/if}
{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
<DnsRuntimeBadge result={dnsRuntimeResult} />

<div class="list">
  {#each profiles as p (p.upstream_profile_id)}
    <div class="resolver-card">
      <div class="resolver-main">
        <span class="resolver-name">{p.name}</span>
        <span class="resolver-addresses">{p.endpoints.map((e) => e.address).join(", ")}</span>
      </div>
      <StatusBadge label={p.enabled ? "Active" : "Disabled"} tone={p.enabled ? "healthy" : "neutral"} />
      <button type="button" class="secondary small" onclick={() => toggle(p)} disabled={pendingAction.has(p.upstream_profile_id)}>
        {p.enabled ? "Disable" : "Enable"}
      </button>
    </div>
  {:else}
    <p class="hint">No resolvers configured yet -- this appliance is using native recursion.</p>
  {/each}
</div>

<p class="hint footer-note">
  Multiple resolvers, load balancing, DNS-over-TLS/HTTPS, and domain-specific routing are all
  available in Advanced &gt; Upstreams &amp; Routing -- this page manages the same real resolvers
  through a simpler form.
</p>

{#if addOpen}
  <Modal title="Add Resolver" onClose={() => (addOpen = false)}>
    <form onsubmit={submitAdd} class="modal-form">
      <label>Name <input required bind:value={addName} placeholder="e.g. Cloudflare" /></label>
      <label>
        Address(es), one per line
        <textarea required bind:value={addAddresses} rows="3" placeholder="1.1.1.1&#10;1.0.0.1"></textarea>
      </label>
      <p class="hint">Plain DNS (port 53). For DNS-over-TLS/HTTPS or advanced strategies, use Advanced &gt; Upstreams &amp; Routing.</p>
      <div class="form-actions">
        <button type="submit" disabled={addBusy}>{addBusy ? "Saving…" : "Add Resolver"}</button>
        <button type="button" class="secondary" onclick={() => (addOpen = false)}>Cancel</button>
      </div>
      {#if addError}<p class="error" role="alert">{addError}</p>{/if}
    </form>
  </Modal>
{/if}

<style>
  .info-banner { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.6rem 0.9rem; border-radius: 6px; font-size: 0.88rem; margin-bottom: 0.75rem; }
  .error { color: var(--danger); }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .footer-note { margin-top: 1rem; max-width: 40rem; }

  .list { display: flex; flex-direction: column; gap: 0.6rem; max-width: 40rem; }
  .resolver-card { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1rem; border: 1px solid var(--border); border-radius: 8px; background: var(--card-bg); }
  .resolver-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .resolver-name { font-weight: 600; }
  .resolver-addresses { font-size: 0.82rem; font-family: monospace; opacity: 0.75; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  button.secondary.small { min-height: auto; padding: 0.3rem 0.6rem; font-size: 0.8rem; }

  .modal-form { display: flex; flex-direction: column; gap: 0.75rem; }
  .modal-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .modal-form textarea { font-family: monospace; }
  .form-actions { display: flex; gap: 0.5rem; }
</style>
