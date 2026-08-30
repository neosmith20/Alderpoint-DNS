<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type CurrentNetworkConfig } from "../api";
  import StatusBadge from "./ui/StatusBadge.svelte";

  // Network Configuration. Compared directly against V1.1.1's real
  // system_network.html/app/network_config.py (read directly from the
  // shipped V1.1.1 package): Detected Backend, Active Interface, a
  // readable Current Network Settings table, and a structured
  // apply/confirm/rollback flow, gated read-only when the backend is
  // unsupported/ambiguous -- matching V1's own layout and safety
  // language field-for-field.
  //
  // Real, disclosed gap vs V1.1.1 (see
  // internal/hostagentd/network_backend.go's own doc comment): apply
  // below is real and safe -- the same auto-revert-on-timeout watchdog
  // V1 used, proven against a real disposable test interface in
  // internal/hostagentd's own test suite -- but is runtime-only via `ip
  // addr`/`ip route`, so it does not persist across a reboot, and this
  // page cannot yet switch an interface to DHCP (V1 could do both, per
  // backend). Backend detection and current-mode reporting ARE real.

  let current = $state<CurrentNetworkConfig | null>(null);
  let statusError = $state("");

  let selectedIface = $state("");
  let ipv4Address = $state("");
  // A number input's bind:value is a real JS number (or "" when empty),
  // never a string -- the CIDR builder below must never call .trim() on
  // this (a real bug found live via Chromium during this page's own
  // rebuild: it did, and threw on every real Apply click).
  let ipv4Prefix = $state<number | "">(24);
  let ipv4Gateway = $state("");
  let applyError = $state("");
  let applyResult = $state<{ auto_revert_seconds: number } | null>(null);
  let busy = $state(false);
  let confirmBusy = $state(false);
  let rollbackBusy = $state(false);
  let actionResult = $state("");

  async function refresh() {
    statusError = "";
    try {
      const resp = await api.networkStatus("");
      current = resp.current;
      if (!selectedIface) selectedIface = current.interface ?? current.interfaces[0] ?? "";
    } catch (err) {
      statusError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(refresh);

  async function apply(e: Event) {
    e.preventDefault();
    if (!selectedIface.trim() || !ipv4Address.trim()) return;
    applyError = "";
    applyResult = null;
    busy = true;
    try {
      const cidr = `${ipv4Address.trim()}/${ipv4Prefix || 24}`;
      applyResult = await api.networkApply(selectedIface.trim(), [cidr], ipv4Gateway.trim() || undefined);
    } catch (err) {
      applyError = err instanceof ApiError ? err.message : String(err);
    } finally {
      busy = false;
    }
  }

  async function confirm() {
    confirmBusy = true;
    actionResult = "";
    try {
      await api.networkConfirm(selectedIface.trim());
      actionResult = "Confirmed -- the change is now permanent for this boot.";
      applyResult = null;
      await refresh();
    } catch (err) {
      actionResult = err instanceof ApiError ? err.message : String(err);
    } finally {
      confirmBusy = false;
    }
  }

  async function rollback() {
    rollbackBusy = true;
    actionResult = "";
    try {
      await api.networkRollback(selectedIface.trim());
      actionResult = "Rolled back to the previous configuration.";
      applyResult = null;
      await refresh();
    } catch (err) {
      actionResult = err instanceof ApiError ? err.message : String(err);
    } finally {
      rollbackBusy = false;
    }
  }
</script>

<section aria-labelledby="network-heading" class="network">
  <h2 id="network-heading">Network Configuration</h2>
  <p class="scope-note">
    This server's own network interface (DHCP/static IP, gateway) -- separate from DNS
    upstream/resolver settings. Applying a change here does not persist across a reboot yet, and
    switching an interface to DHCP isn't wired up yet -- static changes apply live immediately, with
    the same automatic-rollback safety window as every other change on this page.
  </p>

  {#if statusError}<p class="error" role="alert">{statusError}</p>{/if}

  {#if current}
    <section class="status-grid">
      <div class="card">
        <h3>Detected Backend</h3>
        <StatusBadge label={current.backend} tone={current.backend === "unsupported" ? "danger" : "healthy"} />
        <p class="hint">{current.backend_detail}</p>
        {#if current.ambiguous}
          <p class="error" role="alert">
            Multiple networking backends appear active on this host. Settings are shown read-only
            below -- Alderpoint DNS refuses to guess which one owns configuration here.
          </p>
        {/if}
      </div>
      <div class="card">
        <h3>Active Interface</h3>
        <p class="mono">{current.interface ?? "none detected"}</p>
      </div>
    </section>

    <div class="card wide">
      <h3>Current Network Settings</h3>
      <table class="settings-table">
        <thead><tr><th>Field</th><th>Value</th></tr></thead>
        <tbody>
          <tr><td>IPv4 mode</td><td class="mono">{current.ipv4?.mode ?? "unknown"}</td></tr>
          <tr><td>Current IPv4 address</td><td class="mono">{current.ipv4?.address ? `${current.ipv4.address}/${current.ipv4.prefixlen}` : "none"}</td></tr>
          <tr><td>Default gateway (IPv4)</td><td class="mono">{current.ipv4?.gateway || "none"}</td></tr>
          <tr><td>IPv6 mode</td><td class="mono">{current.ipv6?.mode ?? "unknown"}</td></tr>
          <tr><td>Current IPv6 address</td><td class="mono">{current.ipv6?.address ? `${current.ipv6.address}/${current.ipv6.prefixlen}` : "none"}</td></tr>
          <tr><td>Default gateway (IPv6)</td><td class="mono">{current.ipv6?.gateway || "none"}</td></tr>
        </tbody>
      </table>
    </div>

    {#if current.backend === "unsupported"}
      <div class="card wide empty-state">
        <h3>Network configuration is read-only on this host</h3>
        <p class="hint">{current.backend_detail}</p>
      </div>
    {:else}
      <form class="card wide" onsubmit={apply}>
        <h3>Change Network Configuration</h3>
        <p class="error" role="alert">
          Changing this server's IP address may disconnect your browser. Unless confirmed within
          the safety window below, the previous configuration is restored automatically -- no
          reboot required.
        </p>
        <label>
          Interface
          <select bind:value={selectedIface}>
            {#each current.interfaces as iface}
              <option value={iface}>{iface}</option>
            {/each}
          </select>
        </label>
        <div class="grid-compact">
          <label>Static IPv4 address <input bind:value={ipv4Address} placeholder="192.168.1.10" /></label>
          <label>Prefix length (CIDR) <input type="number" min="0" max="32" bind:value={ipv4Prefix} placeholder="24" /></label>
          <label>Gateway <input bind:value={ipv4Gateway} placeholder="192.168.1.1" /></label>
        </div>
        <button type="submit" disabled={busy || !selectedIface.trim() || !ipv4Address.trim()}>{busy ? "Applying…" : "Apply"}</button>
        {#if applyError}<p class="error" role="alert">{applyError}</p>{/if}
      </form>
    {/if}
  {/if}

  {#if applyResult}
    <div class="card pending">
      <h3>Network configuration changed</h3>
      <StatusBadge label="Awaiting confirmation" tone="neutral" />
      <p>
        Reverts automatically in <strong>{applyResult.auto_revert_seconds}s</strong> unless confirmed.
        If you are reading this from the <strong>new</strong> address, everything is working; confirm
        below to make it permanent for this boot.
      </p>
      <div class="row">
        <button onclick={confirm} disabled={confirmBusy}>{confirmBusy ? "…" : "Keep Configuration"}</button>
        <button onclick={rollback} disabled={rollbackBusy}>{rollbackBusy ? "…" : "Roll back now"}</button>
      </div>
    </div>
  {/if}
  {#if actionResult}<p class="hint" role="status">{actionResult}</p>{/if}
</section>

<style>
  .network { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .status-grid { display: flex; flex-wrap: wrap; gap: 1rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; max-width: 32rem; }
  .card.wide { max-width: 44rem; }
  .card h3 { margin: 0; }
  .row { display: flex; gap: 0.5rem; align-items: center; }
  label { display: flex; flex-direction: column; gap: 0.3rem; font-size: 0.85rem; }
  .grid-compact { display: grid; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); gap: 0.6rem; }
  .settings-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  .settings-table th { text-align: left; font-weight: 600; opacity: 0.7; padding: 0.3rem 0.5rem 0.3rem 0; border-bottom: 1px solid var(--border); }
  .settings-table td { padding: 0.35rem 0.5rem 0.35rem 0; border-bottom: 1px solid var(--border); }
  .settings-table tr:last-child td { border-bottom: none; }
  .mono { font-family: monospace; font-size: 0.85rem; }
  .pending { background: var(--attention-bg); }
  .empty-state { opacity: 0.85; }
  .hint { font-size: 0.85rem; opacity: 0.8; margin: 0; }
  .error { color: var(--badge-danger-fg); font-size: 0.85rem; margin: 0; }
</style>
