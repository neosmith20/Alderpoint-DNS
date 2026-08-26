<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type DnsTransportSettings, type TlsStatus, type DNSRuntimeApplyResult } from "../api";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";

  // Encryption. Two independently-scoped native pieces:
  //
  //  - TLS Certificate: this control plane's OWN real management
  //    certificate (the same one its HTTPS listener serves, and DoT/DoH
  //    reuse -- matching Python's own "single appliance-wide cert"
  //    design). Real upload/replace (internal/tlscert's write side,
  //    field-matched against Python's own app/v2/tls_cert.py): a bad
  //    replacement is validated BEFORE anything on disk changes and
  //    never touches the currently-working certificate. Matches
  //    Python's own real, disclosed behavior: promoting a new
  //    certificate needs a restart to actually take effect (a
  //    process-level TLS listener does not hot-reload), not a defect.
  //  - DNS Transport settings (DoT/DoH/DoQ/DoH3/DNSCrypt enable+port).
  //    DoT and DoH compile into and auto-apply to the real DNS runtime.
  //    DoQ/DoH3/DNSCrypt are not compiled yet (each needs its own
  //    listener wiring; DNSCrypt additionally needs identity/
  //    certificate generation this pass didn't build).

  let settings = $state<DnsTransportSettings | null>(null);
  let loadError = $state("");
  let saveError = $state("");
  let saveResult = $state("");
  let saving = $state(false);
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);

  let tls = $state<TlsStatus | null>(null);
  let certFile: FileList | undefined = $state();
  let keyFile: FileList | undefined = $state();
  let replaceBusy = $state(false);
  let replaceError = $state("");
  let replaceResult = $state("");

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

  async function replaceCert(e: Event) {
    e.preventDefault();
    const cf = certFile?.[0];
    const kf = keyFile?.[0];
    if (!cf || !kf) return;
    replaceBusy = true;
    replaceError = "";
    replaceResult = "";
    try {
      const [certificatePem, privateKeyPem] = await Promise.all([cf.text(), kf.text()]);
      const result = await api.tlsReplace(certificatePem, privateKeyPem);
      replaceResult = `Promoted: ${result.subject}. A restart is required for this control plane to actually serve it.`;
      await loadAll();
    } catch (err) {
      replaceError = err instanceof ApiError ? err.message : String(err);
    } finally {
      replaceBusy = false;
    }
  }

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
    TLS Certificate is this control plane's own real, replaceable management certificate (also
    reused by DoT/DoH). DNS Transport settings are stored natively; DoT and DoH compile into and
    auto-apply to the real DNS runtime (DoQ/DoH3/DNSCrypt not yet) -- see the parity matrix.
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

    <form onsubmit={replaceCert} class="replace-form">
      <h4>Replace certificate</h4>
      <label>Certificate (PEM) <input type="file" bind:files={certFile} accept=".crt,.pem" aria-label="Certificate file" required /></label>
      <label>Private key (PEM) <input type="file" bind:files={keyFile} accept=".key,.pem" aria-label="Private key file" required /></label>
      <button type="submit" disabled={replaceBusy || !certFile?.[0] || !keyFile?.[0]}>{replaceBusy ? "Uploading…" : "Upload & Replace"}</button>
      {#if replaceResult}<p class="success" role="status">{replaceResult}</p>{/if}
      {#if replaceError}<p class="error" role="alert">{replaceError}</p>{/if}
    </form>
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
  .replace-form { display: flex; flex-direction: column; gap: 0.5rem; border-top: 1px solid var(--border); padding-top: 0.75rem; margin-top: 0.25rem; }
  .replace-form h4 { margin: 0; font-size: 0.85rem; }
  .replace-form label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.85rem; }
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
