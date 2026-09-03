<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type AdminSessionRow } from "../api";
  import { timestampPref, type TimestampMode } from "../timestamp.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";
  import { COLOR_PALETTE, loadColors, saveColors, applyColors, type ColorRole, type ColorChoices } from "../colors";
  import { router } from "../router.svelte";

  let applianceName = $state("");
  let sessionTimeoutSeconds = $state(0);
  let loginRateLimitMax = $state(0);
  let loginRateLimitWindowSeconds = $state(0);
  let statusError = $state("");

  // Appearance: which palette swatch (colorPalette.ts) drives each of
  // three real UI roles. Applied instantly on click (no Save button --
  // matching the existing light/dark theme toggle's own "changes apply
  // instantly, everywhere" convention this page's Timestamp Display
  // card already documents), persisted per-viewer in localStorage.
  let colorChoices = $state<ColorChoices>(loadColors());
  function pickColor(role: ColorRole, id: string) {
    colorChoices = { ...colorChoices, [role]: id };
    saveColors(colorChoices);
    applyColors(colorChoices);
  }
  function resetColors() {
    colorChoices = { accent: "", success: "", danger: "" };
    saveColors(colorChoices);
    applyColors(colorChoices);
  }

  // Sessions / Recent Administrative Activity, matching V1.1.1's real
  // administration.html field-for-field (see GET
  // /api/administration/{sessions,audit-log}'s own doc comments for
  // the one real, disclosed scope gap: audit entries only cover the
  // security-relevant actions wired so far, not every mutating
  // endpoint in the appliance).
  let sessions = $state<AdminSessionRow[] | null>(null);
  let sessionsError = $state("");

  async function loadSessions() {
    try {
      const resp = await api.listAdminSessions();
      sessions = resp.sessions;
    } catch (err) {
      sessionsError = err instanceof Error ? err.message : String(err);
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
      sessionTimeoutSeconds = status.session_timeout_seconds;
      loginRateLimitMax = status.login_rate_limit_max_attempts;
      loginRateLimitWindowSeconds = status.login_rate_limit_window_seconds;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      statusError = err instanceof Error ? err.message : String(err);
    }
    loadSessions();
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
      await loadSessions();
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
      await loadSessions();
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
    <h3>Administrator Account</h3>
    <p class="hint">This appliance supports a single administrator account -- there is no multi-account list to manage. Changing the password signs out every other active session automatically.</p>
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
    <div class="appearance-head">
      <h3>Appearance</h3>
      <button type="button" class="secondary" onclick={resetColors}>Reset to defaults</button>
    </div>
    <p class="hint">
      Pick a color for each real role in the interface -- Primary drives buttons, links, and the
      active nav item; Success and Danger drive allowed/blocked status text and badges. Changes
      apply instantly, everywhere, with no reload. This is a per-browser preference, like light/dark
      mode above -- it doesn't sync across devices or other people viewing this appliance.
    </p>
    {#each [{ role: "accent" as ColorRole, label: "Primary (buttons, links, active nav)" }, { role: "success" as ColorRole, label: "Success (allowed / healthy)" }, { role: "danger" as ColorRole, label: "Danger (blocked / failed)" }] as group (group.role)}
      <div class="swatch-group">
        <span class="swatch-label">{group.label}</span>
        <div class="swatch-row" role="radiogroup" aria-label={`${group.label} color`}>
          <button
            type="button"
            class="swatch swatch-default"
            class:selected={!colorChoices[group.role]}
            aria-pressed={!colorChoices[group.role]}
            title="Theme default"
            onclick={() => pickColor(group.role, "")}
          >?</button>
          {#each COLOR_PALETTE as s (s.id)}
            <button
              type="button"
              class="swatch"
              class:selected={colorChoices[group.role] === s.id}
              aria-pressed={colorChoices[group.role] === s.id}
              style="background: {s.base};"
              title={s.name}
              onclick={() => pickColor(group.role, s.id)}
            ></button>
          {/each}
        </div>
      </div>
    {/each}
  </div>

  <div class="card wide">
    <h3>Active Sessions</h3>
    <p class="hint">Every other session can be revoked at once, below (there is no per-session revoke endpoint yet -- only all-others).</p>
    <button class="danger" onclick={revokeOtherSessions} disabled={revokeBusy}>{revokeBusy ? "Revoking…" : "Revoke Other Sessions"}</button>
    {#if revokeResult}<p class="hint" role="status">{revokeResult}</p>{/if}
    {#if sessionsError}
      <p class="error" role="alert">{sessionsError}</p>
    {:else if !sessions}
      <p class="hint">Loading…</p>
    {:else}
      <div class="table-scroll"><table class="admin-table">
        <thead><tr><th>Administrator</th><th>Started</th><th>Last seen</th><th>Source IP</th><th>Client</th></tr></thead>
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
    <h3>Authentication Security</h3>
    <dl class="security-facts">
      <dt>Session timeout</dt>
      <dd>{sessionTimeoutSeconds ? `${Math.round(sessionTimeoutSeconds / 3600)} hours of inactivity` : "…"}</dd>
      <dt>Login rate limit</dt>
      <dd>{loginRateLimitMax ? `${loginRateLimitMax} failed attempts per ${Math.round(loginRateLimitWindowSeconds / 60)} minutes, per source IP` : "…"}</dd>
      <dt>Password policy</dt>
      <dd>12+ characters, enforced server-side on every change</dd>
    </dl>
    <p class="hint">
      These values are real and already enforced -- not yet owner-configurable from this page.
    </p>
  </div>

  <div class="card wide audit-link-card">
    <div>
      <h3>Recent Administrative Activity</h3>
      <p class="hint">Sign-ins, password changes, session revocations and other administrative actions now have their own page, with real filtering and search.</p>
    </div>
    <button type="button" onclick={() => router.navigate("audit")}>Open Audit Log</button>
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
  .security-facts { display: grid; grid-template-columns: auto 1fr; gap: 0.4rem 1rem; margin: 0 0 0.75rem; font-size: 0.88rem; }
  .security-facts dt { font-weight: 600; opacity: 0.75; }
  .security-facts dd { margin: 0; }
  .radio-row { display: flex; flex-wrap: wrap; gap: 1rem; }
  .radio-row label, .checkbox-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.9rem; }
  .preview { margin-top: 0.75rem; font-size: 0.85rem; }
  .stack-form { display: flex; flex-direction: column; gap: 0.65rem; max-width: 22rem; }
  .stack-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .success { color: var(--success); }
  .danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); margin-top: 0.5rem; }
  .appearance-head { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
  .appearance-head h3 { margin: 0; }
  .swatch-group { margin-top: 0.9rem; }
  .swatch-label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.4rem; }
  .swatch-row { display: flex; flex-wrap: wrap; gap: 0.5rem; }
  .swatch {
    width: 1.7rem; height: 1.7rem; border-radius: 999px; padding: 0;
    border: 2px solid transparent; cursor: pointer; box-shadow: inset 0 0 0 1px rgba(0, 0, 0, 0.15);
  }
  .swatch.selected { border-color: var(--fg); }
  .swatch-default {
    background: var(--panel-elevated); color: var(--fg); font-size: 0.85rem; font-weight: 700;
    display: flex; align-items: center; justify-content: center; border-color: var(--border-strong);
  }
  .swatch-default.selected { border-color: var(--fg); border-width: 2px; }
  .audit-link-card { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
  .audit-link-card h3 { margin: 0 0 0.35rem; }
  .audit-link-card p { margin: 0; }
  .table-scroll { overflow-x: auto; margin-top: 0.75rem; }
  .admin-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .admin-table th { text-align: left; font-weight: 600; opacity: 0.7; padding: 0.3rem 0.5rem 0.3rem 0; border-bottom: 1px solid var(--border); }
  .admin-table td { padding: 0.35rem 0.5rem 0.35rem 0; border-bottom: 1px solid var(--border); word-break: break-word; }
  .admin-table tr:last-child td { border-bottom: none; }
  .mono { font-family: monospace; }
</style>
