<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type DnsTransportSettings, type TlsStatus, type DNSRuntimeApplyResult } from "../api";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";

  // Encryption. Two independently-scoped native pieces, each with its
  // own disclosed gap -- see internal/dnstransports and internal/tlscert:
  //
  //  - DNS Transport settings (DoT/DoH/DoQ/DoH3/DNSCrypt enable+port) are
  //    real native-Go storage. DoT and DoH now compile into and
  //    auto-apply to the real DNS runtime (internal/dnscompile,
  //    internal/dnsruntime) -- see the dns_runtime feedback below Save.
  //    DoQ/DoH3/DNSCrypt are not compiled yet (each needs its own
  //    listener wiring; DNSCrypt additionally needs a Go-native secrets
  //    store for its identity material, which doesn't exist yet).
  //  - TLS status is real and read-only (a genuine read of Python's own
  //    DNS-transport certificate, when -tls-cert-status-path is
  //    configured) -- there is no "replace" here, since promoting a new
  //    certificate needs that same unreachable live restart.

  let settings = $state<DnsTransportSettings | null>(null);
  let loadError = $state("");
  let saveError = $state("");
  let saveResult = $state("");
  let saving = $state(false);
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);

  let tls = $state<TlsStatus | null>(null);

  async function loadAll() {
    loadError = "";
    try {
      const [t, s] = await Promise.all([api.getDnsTransports(router.signal()), api.tlsStatus(router.signal())]);
      settings = t;
      tls = s;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(() => {
    loadAll();
  });

  async function save() {
    if (!settings) return;
    saving = true;
    saveError = "";
    saveResult = "";
    try {
      settings = await api.updateDnsTransports(settings);
      dnsRuntimeResult = settings.dns_runtime ?? null;
      saveResult = "Saved.";
    } catch (err) {
      saveError = err instanceof ApiError ? err.message : String(err);
    } finally {
      saving = false;
    }
  }
</script>

<section aria-labelledby="encryption-heading" class="encryption">
  <h2 id="encryption-heading">Encryption</h2>
  <p class="scope-note">
    DNS Transport settings are stored natively; DoT and DoH now compile into and auto-apply to the
    real DNS runtime (DoQ/DoH3/DNSCrypt not yet). TLS status is a real, read-only view of Python's
    own DNS-transport certificate -- see the parity matrix for the full scope.
  </p>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <div class="card">
    <h3>TLS Certificate</h3>
    {#if !tls}
      <p class="hint">Loading…</p>
    {:else if !tls.active}
      <p class="degraded-note" role="status">
        {tls.error ? `Unavailable: ${tls.error}` : "No certificate available (not configured, or none provisioned yet)."}
      </p>
    {:else}
      <dl class="cert-info">
        <dt>Subject</dt>
        <dd>{tls.subject}</dd>
        <dt>Valid</dt>
        <dd>
          {tls.not_valid_before ? timestampPref.format(tls.not_valid_before) : "?"} &ndash;
          {tls.not_valid_after ? timestampPref.format(tls.not_valid_after) : "?"}
        </dd>
        <dt>Subject Alternative Names</dt>
        <dd>{(tls.san ?? []).join(", ") || "none"}</dd>
        <dt>Self-signed</dt>
        <dd>{tls.is_self_signed ? "Yes" : "No"}</dd>
      </dl>
    {/if}
  </div>

  {#if settings}
    <form class="card transports" onsubmit={(e) => { e.preventDefault(); save(); }}>
      <h3>DNS Transports</h3>

      <fieldset>
        <legend><label><input type="checkbox" bind:checked={settings.dot_enabled} /> DNS-over-TLS (DoT)</label></legend>
        <label class="port">Port <input type="number" min="1" max="65535" bind:value={settings.dot_port} /></label>
      </fieldset>

      <fieldset>
        <legend><label><input type="checkbox" bind:checked={settings.doh_enabled} /> DNS-over-HTTPS (DoH)</label></legend>
        <label class="port">Port <input type="number" min="1" max="65535" bind:value={settings.doh_port} /></label>
        <label class="path">Path <input bind:value={settings.doh_path} placeholder="/dns-query" /></label>
      </fieldset>

      <fieldset>
        <legend><label><input type="checkbox" bind:checked={settings.doq_enabled} /> DNS-over-QUIC (DoQ)</label></legend>
        <label class="port">Port <input type="number" min="1" max="65535" bind:value={settings.doq_port} /></label>
      </fieldset>

      <fieldset>
        <legend><label><input type="checkbox" bind:checked={settings.doh3_enabled} /> DNS-over-HTTP/3 (DoH3)</label></legend>
        <label class="port">Port <input type="number" min="1" max="65535" bind:value={settings.doh3_port} /></label>
      </fieldset>

      <fieldset>
        <legend><label><input type="checkbox" bind:checked={settings.dnscrypt_enabled} /> DNSCrypt</label></legend>
        <label class="port">Port <input type="number" min="1" max="65535" bind:value={settings.dnscrypt_port} /></label>
        <label class="path">Provider name <input bind:value={settings.dnscrypt_provider_name} /></label>
        {#if !settings.dnscrypt_identity_provisioned}
          <p class="hint">Identity not provisioned yet -- key generation needs a native secrets store, not yet built.</p>
        {/if}
      </fieldset>

      <div class="actions">
        <button type="submit" disabled={saving}>{saving ? "Saving…" : "Save"}</button>
      </div>
      {#if saveResult}<p class="success" role="status">{saveResult}</p>{/if}
      {#if saveError}<p class="error" role="alert">{saveError}</p>{/if}
      <DnsRuntimeBadge result={dnsRuntimeResult} />
    </form>
  {/if}
</section>

<style>
  .encryption { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.75rem; }
  .card h3 { margin: 0; }
  .cert-info { display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1rem; font-size: 0.9rem; }
  .cert-info dt { opacity: 0.7; }
  .cert-info dd { margin: 0; }
  .transports fieldset { border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 0.9rem; display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem; }
  .transports legend { padding: 0 0.3rem; font-weight: 600; }
  .transports label { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; }
  .transports input[type="number"] { width: 6rem; }
  .actions { display: flex; align-items: center; gap: 0.6rem; }
  .success { color: #16a34a; }
  .error { color: var(--badge-danger-fg); }
  .degraded-note { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.85rem; }
  .hint { font-size: 0.8rem; opacity: 0.7; }
</style>
