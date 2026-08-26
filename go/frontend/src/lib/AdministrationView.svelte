<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError } from "../api";
  import { timestampPref, type TimestampMode } from "../timestamp.svelte";

  let applianceName = $state("");
  let statusError = $state("");

  let currentPassword = $state("");
  let newPassword = $state("");
  let confirmNewPassword = $state("");
  let passwordBusy = $state(false);
  let passwordError = $state("");
  let passwordSuccess = $state(false);

  let revokeBusy = $state(false);
  let revokeResult = $state<string>("");

  onMount(async () => {
    try {
      const status = await api.systemStatus();
      applianceName = status.appliance_name;
      timestampPref.applianceTimezone = status.appliance_timezone || "UTC";
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      statusError = err instanceof Error ? err.message : String(err);
    }
  });

  async function changePassword(e: Event) {
    e.preventDefault();
    passwordError = "";
    passwordSuccess = false;
    if (newPassword !== confirmNewPassword) {
      passwordError = "New password and confirmation do not match.";
      return;
    }
    passwordBusy = true;
    try {
      await api.changePassword(currentPassword, newPassword);
      currentPassword = "";
      newPassword = "";
      confirmNewPassword = "";
      passwordSuccess = true;
    } catch (err) {
      passwordError = err instanceof ApiError ? err.message : String(err);
    } finally {
      passwordBusy = false;
    }
  }

  async function revokeOtherSessions() {
    revokeBusy = true;
    revokeResult = "";
    try {
      const resp = await api.revokeOtherSessions();
      revokeResult = resp.revoked_count === 0 ? "No other sessions were active." : `Revoked ${resp.revoked_count} other session${resp.revoked_count === 1 ? "" : "s"}.`;
    } catch (err) {
      revokeResult = err instanceof Error ? err.message : String(err);
    } finally {
      revokeBusy = false;
    }
  }

  function onTimestampModeChange(mode: TimestampMode) {
    timestampPref.setMode(mode);
  }

  const now = Date.now();
</script>

<section aria-labelledby="admin-heading" class="admin">
  <h2 id="admin-heading">Administration</h2>
  {#if statusError}<p class="error" role="alert">{statusError}</p>{/if}

  <div class="card">
    <h3>Timestamp Display</h3>
    <p class="hint">Controls how every timestamp in this application is shown. Changes apply instantly, everywhere, with no reload.</p>
    <div class="radio-row" role="radiogroup" aria-label="Timestamp display mode">
      <label>
        <input type="radio" name="ts-mode" checked={timestampPref.mode === "browser"} onchange={() => onTimestampModeChange("browser")} />
        Browser Local
      </label>
      <label>
        <input type="radio" name="ts-mode" checked={timestampPref.mode === "appliance"} onchange={() => onTimestampModeChange("appliance")} />
        Appliance Time {applianceName ? `(${applianceName})` : ""}
      </label>
      <label>
        <input type="radio" name="ts-mode" checked={timestampPref.mode === "utc"} onchange={() => onTimestampModeChange("utc")} />
        UTC
      </label>
    </div>
    <p class="preview">Preview: <strong>{timestampPref.format(now)}</strong></p>
  </div>

  <div class="card">
    <h3>Change Password</h3>
    <form onsubmit={changePassword} class="stack-form">
      <label>Current password <input required type="password" bind:value={currentPassword} autocomplete="current-password" /></label>
      <label>New password (12+ characters) <input required minlength="12" type="password" bind:value={newPassword} autocomplete="new-password" /></label>
      <label>Confirm new password <input required type="password" bind:value={confirmNewPassword} autocomplete="new-password" /></label>
      <button type="submit" disabled={passwordBusy}>{passwordBusy ? "Changing…" : "Change password"}</button>
      {#if passwordError}<p class="error" role="alert">{passwordError}</p>{/if}
      {#if passwordSuccess}<p class="success" role="status">Password changed.</p>{/if}
    </form>
  </div>

  <div class="card">
    <h3>Sessions</h3>
    <p class="hint">Sign every other browser/device out of this admin account. This session stays signed in.</p>
    <button class="danger" onclick={revokeOtherSessions} disabled={revokeBusy}>{revokeBusy ? "Revoking…" : "Revoke other sessions"}</button>
    {#if revokeResult}<p class="hint" role="status">{revokeResult}</p>{/if}
  </div>
</section>

<style>
  .admin { max-width: 40rem; display: flex; flex-direction: column; gap: 1rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); }
  .card h3 { margin-top: 0; }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .radio-row { display: flex; flex-wrap: wrap; gap: 1rem; }
  .radio-row label, .checkbox-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.9rem; }
  .preview { margin-top: 0.75rem; font-size: 0.85rem; }
  .stack-form { display: flex; flex-direction: column; gap: 0.65rem; max-width: 22rem; }
  .stack-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .success { color: #16a34a; }
  .danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
</style>
