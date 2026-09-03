<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type AdminSessionRow, type AuditLogEntry } from "../api";
  import { timestampPref, type TimestampMode } from "../timestamp.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";

  let applianceName = $state("");
  let statusError = $state("");

  // Sessions / Recent Administrative Activity, matching V1.1.1's real
  // administration.html field-for-field (see GET
  // /api/administration/{sessions,audit-log}'s own doc comments for
  // the one real, disclosed scope gap: audit entries only cover the
  // security-relevant actions wired so far, not every mutating
  // endpoint in the appliance).
  let sessions = $state<AdminSessionRow[] | null>(null);
  let sessionsError = $state("");
  let auditEntries = $state<AuditLogEntry[] | null>(null);
  let auditError = $state("");

  async function loadSessions() {
    try {
      const resp = await api.listAdminSessions();
      sessions = resp.sessions;
    } catch (err) {
      sessionsError = err instanceof Error ? err.message : String(err);
    }
  }

  async function loadAuditLog() {
    try {
      const resp = await api.listAuditLog();
      auditEntries = resp.entries;
    } catch (err) {
      auditError = err instanceof Error ? err.message : String(err);
    }
  }

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
    loadSessions();
    loadAuditLog();
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
      await Promise.all([loadSessions(), loadAuditLog()]);
    } catch (err) {
      passwordError = err instanceof ApiError ? err.message : String(err);
    } finally {
      passwordBusy = false;
    }
  }

  let confirmRevokeSessions = $state(false);

  function revokeOtherSessions() {
    confirmRevokeSessions = true;
  }

  async function runRevokeOtherSessions() {
    confirmRevokeSessions = false;
    revokeBusy = true;
    revokeResult = "";
    try {
      const resp = await api.revokeOtherSessions();
      revokeResult = resp.revoked_count === 0 ? "No other sessions were active." : `Revoked ${resp.revoked_count} other session${resp.revoked_count === 1 ? "" : "s"}.`;
      await Promise.all([loadSessions(), loadAuditLog()]);
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

  <div class="grid-2col">
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
    <p class="hint">Changing the password signs out every other active session automatically.</p>
    <form onsubmit={changePassword} class="stack-form">
      <label>Current password <input required type="password" bind:value={currentPassword} autocomplete="current-password" /></label>
      <label>New password (12+ characters) <input required minlength="12" type="password" bind:value={newPassword} autocomplete="new-password" /></label>
      <label>Confirm new password <input required type="password" bind:value={confirmNewPassword} autocomplete="new-password" /></label>
      <button type="submit" disabled={passwordBusy}>{passwordBusy ? "Changing…" : "Change password"}</button>
      {#if passwordError}<p class="error" role="alert">{passwordError}</p>{/if}
      {#if passwordSuccess}<p class="success" role="status">Password changed. Other sessions were signed out.</p>{/if}
    </form>
  </div>
  </div>

  <div class="card wide">
    <h3>Sessions</h3>
    <p class="hint">Sessions other than this one can be revoked without changing the password.</p>
    <button class="danger" onclick={revokeOtherSessions} disabled={revokeBusy}>{revokeBusy ? "Revoking…" : "Revoke all other sessions"}</button>
    {#if revokeResult}<p class="hint" role="status">{revokeResult}</p>{/if}
    {#if sessionsError}
      <p class="error" role="alert">{sessionsError}</p>
    {:else if !sessions}
      <p class="hint">Loading…</p>
    {:else}
      <div class="table-scroll"><table class="admin-table">
        <thead><tr><th>Session</th><th>Started</th><th>Last seen</th><th>IP</th><th>Client</th></tr></thead>
        <tbody>
          {#each sessions as row, i (row.created_at + i)}
            <tr>
              <td>{#if row.is_current}<StatusBadge label="This session" tone="healthy" />{:else}&mdash;{/if}</td>
              <td class="mono">{row.created_at}</td>
              <td class="mono">{row.last_seen_at}</td>
              <td class="mono">{row.ip}</td>
              <td>{row.user_agent}</td>
            </tr>
          {/each}
        </tbody>
      </table></div>
    {/if}
  </div>

  <div class="card wide">
    <h3>Recent Administrative Activity</h3>
    {#if auditError}
      <p class="error" role="alert">{auditError}</p>
    {:else if !auditEntries}
      <p class="hint">Loading…</p>
    {:else if auditEntries.length === 0}
      <p class="hint">No administrative activity recorded yet.</p>
    {:else}
      <div class="table-scroll"><table class="admin-table">
        <thead><tr><th>When</th><th>Action</th><th>Result</th><th>IP</th><th>Detail</th></tr></thead>
        <tbody>
          {#each auditEntries as entry, i (entry.at + i)}
            <tr>
              <td class="mono">{entry.at}</td>
              <td>{entry.action}</td>
              <td><StatusBadge label={entry.success ? "Success" : "Failed"} tone={entry.success ? "healthy" : "danger"} /></td>
              <td class="mono">{entry.ip}</td>
              <td>{entry.detail}</td>
            </tr>
          {/each}
        </tbody>
      </table></div>
    {/if}
  </div>
</section>

{#if confirmRevokeSessions}
  <ConfirmDialog
    title="Revoke other sessions"
    message="Sign out every other active session for this account? This device's own session is not affected."
    confirmLabel="Revoke"
    onConfirm={runRevokeOtherSessions}
    onCancel={() => (confirmRevokeSessions = false)}
  />
{/if}

<style>
  .admin { display: flex; flex-direction: column; gap: 1rem; }
  /* Two responsive columns on desktop/tablet, one on mobile -- Timestamp
     Display and Change Password previously had no shared container, so
     they simply stacked full-width one above the other regardless of
     how much horizontal room the page had. */
  .grid-2col { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1rem; align-items: start; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); box-shadow: var(--shadow); }
  .card.wide { max-width: 72rem; }
  .card h3 { margin-top: 0; }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .radio-row { display: flex; flex-wrap: wrap; gap: 1rem; }
  .radio-row label, .checkbox-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.9rem; }
  .preview { margin-top: 0.75rem; font-size: 0.85rem; }
  .stack-form { display: flex; flex-direction: column; gap: 0.65rem; max-width: 22rem; }
  .stack-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .success { color: var(--success); }
  .danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); margin-top: 0.5rem; }
  .table-scroll { overflow-x: auto; margin-top: 0.75rem; }
  .admin-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .admin-table th { text-align: left; font-weight: 600; opacity: 0.7; padding: 0.3rem 0.5rem 0.3rem 0; border-bottom: 1px solid var(--border); }
  .admin-table td { padding: 0.35rem 0.5rem 0.35rem 0; border-bottom: 1px solid var(--border); word-break: break-word; }
  .admin-table tr:last-child td { border-bottom: none; }
  .mono { font-family: monospace; }
</style>
