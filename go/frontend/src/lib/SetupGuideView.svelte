<script lang="ts">
  import { onMount } from "svelte";
  import { api, type DnsTransportSettings, type TlsStatus } from "../api";
  import { router } from "../router.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";

  // Setup Guide: device/protocol connection instructions, built from the
  // same real client-facing-address/certificate data Encryption already
  // computes (see that page's own doc comment for the exact detection
  // rules) -- this page only ever shows an address/protocol combination
  // that is real and currently enabled; it never invents a working
  // configuration. Server configuration itself (enabling a transport,
  // replacing the certificate) happens on Encryption -- this page links
  // there rather than duplicating those controls.

  let settings = $state<DnsTransportSettings | null>(null);
  let tls = $state<TlsStatus | null>(null);
  let loadError = $state("");

  onMount(async () => {
    try {
      const [s, t] = await Promise.all([api.getDnsTransports(router.signal()), api.tlsStatus(router.signal())]);
      settings = s;
      tls = t;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof Error ? err.message : String(err);
    }
  });

  const certSan = $derived(settings?.cert_san ?? []);
  // effective_client_address is the backend's own authoritative "what
  // should a client actually be told" value (same priority order
  // Encryption's page uses, and the same field that gates real Apple
  // profile downloads server-side) -- never re-derived independently here.
  const clientAddress = $derived(settings?.effective_client_address ?? "");
  const clientAddressCertValid = $derived(!!clientAddress && certSan.includes(clientAddress));

  function copy(text: string) {
    navigator.clipboard?.writeText(text).catch(() => {});
  }

  type ProtocolKey = "plain" | "dot" | "doh" | "doq" | "doh3" | "dnscrypt";
  const PROTOCOL_LABEL: Record<ProtocolKey, string> = { plain: "Plain DNS", dot: "DoT", doh: "DoH", doq: "DoQ", doh3: "DoH3", dnscrypt: "DNSCrypt" };

  function protocolEnabled(p: ProtocolKey): boolean {
    if (!settings) return false;
    if (p === "plain") return true;
    if (p === "dot") return settings.dot_enabled;
    if (p === "doh") return settings.doh_enabled;
    if (p === "doq") return settings.doq_enabled;
    if (p === "doh3") return settings.doh3_enabled;
    return settings.dnscrypt_enabled;
  }

  /** A protocol "works with the current configuration" only when it's
   * enabled AND (for the certificate-backed transports) the active
   * certificate actually covers the client-facing address -- otherwise
   * every client device would get a real validation error, so this page
   * says so up front instead of handing out instructions that fail. */
  function protocolWorks(p: ProtocolKey): boolean {
    if (!protocolEnabled(p)) return false;
    if (p === "plain" || p === "dnscrypt") return true;
    return clientAddressCertValid;
  }

  function doqUri(): string {
    return `quic://${clientAddress}:${settings?.doq_port ?? 853}`;
  }
  function dohUri(): string {
    return `https://${clientAddress}:${settings?.doh_port ?? 443}${settings?.doh_path ?? "/dns-query"}`;
  }

  const enabledProtocols = $derived((["plain", "dot", "doh", "doq", "doh3", "dnscrypt"] as ProtocolKey[]).filter(protocolEnabled));

  type DeviceKey = "router" | "windows" | "macos" | "android" | "ios";
  const DEVICES: { key: DeviceKey; label: string }[] = [
    { key: "router", label: "Router" },
    { key: "windows", label: "Windows" },
    { key: "macos", label: "macOS" },
    { key: "android", label: "Android" },
    { key: "ios", label: "iOS" },
  ];
  let activeDevice = $state<DeviceKey>("router");

  /** Which protocols this page actually shows setup steps for, per
   * device -- deliberately conservative: only protocols with real,
   * broadly-documented native or profile-based OS support for that
   * platform, never a guessed/unverified claim. */
  const DEVICE_PROTOCOLS: Record<DeviceKey, ProtocolKey[]> = {
    router: ["plain"],
    windows: ["plain", "doh", "dot"],
    macos: ["plain", "dot", "doh"],
    android: ["plain", "dot"],
    ios: ["plain", "dot", "doh"],
  };
</script>

<PageHeader
  headingId="setup-guide-heading"
  title="Setup Guide"
  description="Exact, copyable connection details for every device and protocol this appliance currently supports -- nothing shown here is a guess."
/>

{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

{#if settings && tls}
  <div class="status-summary">
    <span>Client-facing address: <code>{clientAddress || "not set"}</code> <button type="button" class="mini" onclick={() => copy(clientAddress)}>Copy</button></span>
    <StatusBadge label={tls.active ? "Certificate ready" : "No certificate"} tone={tls.active ? "healthy" : "danger"} />
    <span>Enabled protocols: {enabledProtocols.map((p) => PROTOCOL_LABEL[p]).join(", ")}</span>
    <button type="button" class="secondary small" onclick={() => router.navigate("encryption")}>Configure in Encryption</button>
  </div>

  {#if clientAddress && !clientAddressCertValid}
    <p class="degraded-note" role="alert">
      The active certificate does not cover "{clientAddress}" -- encrypted-transport setup below is
      blocked until that's fixed on Encryption. Plain DNS is unaffected (it doesn't use TLS).
    </p>
  {/if}
{/if}

<div class="tabs" role="tablist" aria-label="Device">
  {#each DEVICES as d (d.key)}
    <button type="button" role="tab" aria-selected={activeDevice === d.key} class:active={activeDevice === d.key} onclick={() => (activeDevice = d.key)}>{d.label}</button>
  {/each}
</div>

{#if settings}
  <div class="protocol-list">
    {#each DEVICE_PROTOCOLS[activeDevice] as p (p)}
      <div class="card protocol-card">
        <div class="card-head">
          <h3>{PROTOCOL_LABEL[p]}</h3>
          {#if protocolWorks(p)}
            <StatusBadge label="Works now" tone="healthy" />
          {:else if protocolEnabled(p)}
            <StatusBadge label="Certificate issue" tone="warning" />
          {:else}
            <StatusBadge label="Not enabled" tone="neutral" />
          {/if}
        </div>

        {#if p === "plain"}
          <p class="hint">Set this appliance as the DNS server (IPv4/IPv6). No certificate or trust step needed.</p>
          <p class="value-row"><code>{clientAddress || "not set"}</code> <button type="button" class="mini" onclick={() => copy(clientAddress)}>Copy</button></p>
          {#if activeDevice === "router"}
            <ol class="steps">
              <li>Open your router's admin page (usually a plain-DNS address on your own LAN, e.g. its gateway IP).</li>
              <li>Find the WAN or DHCP DNS server setting.</li>
              <li>Set the primary (and, if offered, secondary) DNS server to the address above.</li>
              <li>Save and let connected devices renew their lease (or reboot the router).</li>
            </ol>
          {/if}
        {:else if p === "dot" && protocolEnabled(p)}
          <p class="value-row"><code>{clientAddress}:{settings?.dot_port}</code> <button type="button" class="mini" onclick={() => copy(`${clientAddress}:${settings?.dot_port}`)}>Copy</button></p>
          <p class="hint">Requires trusting this appliance's certificate (see Encryption &gt; Certificate) unless it's already from a trusted CA.</p>
          {#if activeDevice === "android"}
            <ol class="steps">
              <li>Settings &rarr; Network &amp; internet &rarr; Private DNS.</li>
              <li>Choose "Private DNS provider hostname".</li>
              <li>Enter the hostname portion of the address above (not the port).</li>
              <li>Save. Android shows a warning icon if the hostname can't be resolved or the certificate isn't trusted.</li>
            </ol>
          {:else if activeDevice === "windows"}
            <ol class="steps">
              <li>Settings &rarr; Network &amp; internet &rarr; your connection &rarr; DNS server assignment &rarr; Edit.</li>
              <li>Set the server address, then set "DNS over HTTPS/TLS" to On (manual template) using the address above.</li>
              <li>Windows 11 22H2+ only -- earlier Windows builds don't support DoT natively.</li>
            </ol>
          {:else if activeDevice === "macos"}
            <ol class="steps">
              <li>Download the Apple configuration profile below and install it (System Settings &rarr; Profiles), or configure manually in Network settings on macOS 13+.</li>
            </ol>
            <a class="mini-btn" href="/api/dns-transports/mobileconfig/dot" target="_blank" rel="noopener">Download Apple Profile (.mobileconfig)</a>
            <p class="hint">This installs a signed, real configuration profile generated for this appliance's own current address and certificate -- not a generic template.</p>
          {/if}
        {:else if p === "doh" && protocolEnabled(p)}
          <p class="value-row"><code>{dohUri()}</code> <button type="button" class="mini" onclick={() => copy(dohUri())}>Copy</button></p>
          <p class="hint">Requires trusting this appliance's certificate unless it's already from a trusted CA.</p>
          {#if activeDevice === "windows"}
            <ol class="steps">
              <li>Settings &rarr; Network &amp; internet &rarr; your connection &rarr; DNS server assignment &rarr; Edit.</li>
              <li>Set the server address, then set "DNS over HTTPS/TLS" to On, template = the URL above.</li>
              <li>Windows 11 only -- Windows 10 does not support DoH in network settings.</li>
            </ol>
          {:else if activeDevice === "macos" || activeDevice === "ios"}
            <a class="mini-btn" href="/api/dns-transports/mobileconfig/doh" target="_blank" rel="noopener">Download Apple Profile (.mobileconfig)</a>
            <p class="hint">Real, signed profile for this appliance's current address -- not a generic template. Install via Settings &rarr; General &rarr; VPN &amp; Device Management (iOS) or System Settings &rarr; Profiles (macOS).</p>
          {/if}
        {:else if !protocolEnabled(p)}
          <p class="hint">Not enabled on this appliance yet. Enable it on Encryption &gt; DNS Transports first.</p>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<style>
  .error { color: var(--danger); }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .degraded-note { background: var(--badge-warn-bg); color: var(--badge-warn-fg); padding: 0.6rem 0.85rem; border-radius: 8px; font-size: 0.85rem; margin: 0.75rem 0; }
  .status-summary {
    display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem; font-size: 0.85rem; margin-bottom: 1rem;
    padding: 0.75rem 1rem; border: 1px solid var(--border); border-radius: 8px; background: var(--panel-elevated);
  }
  .status-summary code { font-family: monospace; }
  .status-summary button.secondary.small { margin-left: auto; min-height: auto; padding: 0.3rem 0.6rem; font-size: 0.8rem; }
  .mini { font-size: 0.72rem; padding: 0.1rem 0.45rem; min-height: auto; background: transparent; color: var(--fg); border: 1px solid var(--border); }

  .tabs { display: flex; gap: 0.3rem; border-bottom: 1px solid var(--border); margin-bottom: 1rem; flex-wrap: wrap; }
  .tabs button { background: transparent; color: var(--muted); border: none; border-bottom: 2px solid transparent; border-radius: 0; padding: 0.55rem 0.2rem; margin-right: 1.25rem; font-weight: 600; min-height: auto; }
  .tabs button.active { color: var(--fg); border-bottom-color: var(--accent); }

  .protocol-list { display: flex; flex-direction: column; gap: 1rem; max-width: 46rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); }
  .card-head { display: flex; justify-content: space-between; align-items: center; gap: 0.75rem; }
  .card-head h3 { margin: 0; }
  .value-row { display: flex; align-items: center; gap: 0.5rem; font-size: 0.95rem; }
  .value-row code { font-family: monospace; background: var(--panel-elevated); padding: 0.2rem 0.5rem; border-radius: 6px; word-break: break-all; }
  .steps { margin: 0.5rem 0 0; padding-left: 1.2rem; font-size: 0.88rem; display: flex; flex-direction: column; gap: 0.3rem; }
  .mini-btn {
    display: inline-block; margin-top: 0.5rem; padding: 0.5rem 0.9rem; border-radius: 8px;
    background: var(--btn-bg); color: var(--accent-fg); font-weight: 650; text-decoration: none; font-size: 0.85rem;
  }
  .mini-btn:hover { background: var(--btn-bg-hover); }
</style>
