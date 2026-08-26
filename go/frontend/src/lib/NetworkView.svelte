<script lang="ts">
  import { api, ApiError } from "../api";

  // Network Configuration. Real, via apdns-hostagent's `ip` binary
  // calls (argv-based, never a shell string) against one
  // explicitly-named interface at a time. Safety: the same auto-revert
  // watchdog pattern Python's own app/v2/network_config.py already
  // uses -- apply() stages the change and starts a timer; unless
  // confirm() is called before it fires, the interface automatically
  // reverts to its previous state. Proven against a real, disposable
  // test interface in internal/hostagentd's own test suite -- never
  // exercised here against a real NIC without an explicit interface
  // name the operator chose.

  let iface = $state("");
  let addressesText = $state("");
  let gateway = $state("");
  let statusRaw = $state("");
  let statusError = $state("");
  let applyError = $state("");
  let applyResult = $state<{ auto_revert_seconds: number } | null>(null);
  let busy = $state(false);
  let confirmBusy = $state(false);
  let rollbackBusy = $state(false);
  let actionResult = $state("");

  async function loadStatus(e?: Event) {
    e?.preventDefault();
    if (!iface.trim()) return;
    statusError = "";
    try {
      const resp = await api.networkStatus(iface.trim());
      statusRaw = resp.raw_addr_json;
    } catch (err) {
      statusError = err instanceof ApiError ? err.message : String(err);
    }
  }

  async function apply(e: Event) {
    e.preventDefault();
    applyError = "";
    applyResult = null;
    busy = true;
    try {
      const addresses = addressesText.split(/[\n,]/).map((a) => a.trim()).filter(Boolean);
      applyResult = await api.networkApply(iface.trim(), addresses, gateway.trim() || undefined);
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
      await api.networkConfirm(iface.trim());
      actionResult = "Confirmed -- the change is now permanent.";
      applyResult = null;
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
      await api.networkRollback(iface.trim());
      actionResult = "Rolled back to the previous configuration.";
      applyResult = null;
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
    Real host interface reporting and apply/rollback, via apdns-hostagent. A safety window (auto-revert
    timer) applies to every change until explicitly confirmed -- an unconfirmed change reverts itself
    automatically.
  </p>

  <form class="card" onsubmit={loadStatus}>
    <h3>Current Settings</h3>
    <div class="row">
      <input placeholder="Interface (e.g. eth0)" bind:value={iface} aria-label="Interface name" />
      <button type="submit">Refresh</button>
    </div>
    {#if statusError}<p class="error" role="alert">{statusError}</p>{/if}
    {#if statusRaw}<pre class="raw">{statusRaw}</pre>{/if}
  </form>

  <form class="card" onsubmit={apply}>
    <h3>Change configuration</h3>
    <label>
      Addresses (CIDR, one per line)
      <textarea bind:value={addressesText} rows="3" placeholder="10.0.0.5/24" aria-label="Addresses"></textarea>
    </label>
    <label>
      Gateway (optional)
      <input bind:value={gateway} placeholder="10.0.0.1" aria-label="Gateway" />
    </label>
    <button type="submit" disabled={busy || !iface.trim()}>{busy ? "Applying…" : "Apply"}</button>
    {#if applyError}<p class="error" role="alert">{applyError}</p>{/if}
  </form>

  {#if applyResult}
    <div class="card pending">
      <p>
        Applied. Reverts automatically in <strong>{applyResult.auto_revert_seconds}s</strong> unless confirmed.
      </p>
      <div class="row">
        <button onclick={confirm} disabled={confirmBusy}>{confirmBusy ? "…" : "Confirm"}</button>
        <button onclick={rollback} disabled={rollbackBusy}>{rollbackBusy ? "…" : "Roll back now"}</button>
      </div>
    </div>
  {/if}
  {#if actionResult}<p class="hint" role="status">{actionResult}</p>{/if}
</section>

<style>
  .network { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; max-width: 32rem; }
  .card h3 { margin: 0; }
  .row { display: flex; gap: 0.5rem; align-items: center; }
  label { display: flex; flex-direction: column; gap: 0.3rem; font-size: 0.85rem; }
  .raw { font-size: 0.75rem; max-height: 12rem; overflow: auto; background: var(--bg); padding: 0.5rem; border-radius: 6px; }
  .pending { background: var(--attention-bg); }
  .hint { font-size: 0.85rem; opacity: 0.8; }
  .error { color: var(--badge-danger-fg); }
</style>
