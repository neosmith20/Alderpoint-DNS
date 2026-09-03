<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type AnalyticsSettings } from "../api";
  import { router } from "../router.svelte";
  import { loadTheme, applyTheme, hasExplicitTheme, useSystemTheme, type Theme } from "../theme";
  import { loadProfile, saveProfile, type NavProfile } from "../profile";
  import { timestampPref, type TimestampMode } from "../timestamp.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";

  // General Settings: a real settings hub, not a page that owns its own
  // duplicate copy of anything. Every control here reads/writes the
  // exact same real state as its other home elsewhere in the app
  // (Dashboard's Protection Control, Advanced Analytics' collection
  // settings, Scope Policies' Global Answer Policy, the sidebar's own
  // theme toggle) -- nothing is a second, parallel source of truth.

  // --- Appliance Identity ---
  let applianceName = $state("");
  let applianceTimezone = $state("");
  let nameDraft = $state("");
  let nameBusy = $state(false);
  let nameError = $state("");
  let nameSaved = $state(false);
  let statusError = $state("");

  async function loadIdentity() {
    try {
      const status = await api.systemStatus();
      applianceName = status.appliance_name;
      applianceTimezone = status.appliance_timezone || "UTC";
      nameDraft = applianceName;
      timestampPref.applianceTimezone = applianceTimezone;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      statusError = err instanceof Error ? err.message : String(err);
    }
  }

  async function saveName(e: Event) {
    e.preventDefault();
    nameBusy = true;
    nameError = "";
    nameSaved = false;
    try {
      const resp = await api.setApplianceDisplayName(nameDraft.trim());
      applianceName = resp.appliance_name;
      nameSaved = true;
    } catch (err) {
      nameError = err instanceof ApiError ? err.message : String(err);
    } finally {
      nameBusy = false;
    }
  }

  function onTimestampModeChange(mode: TimestampMode) {
    timestampPref.setMode(mode);
  }
  const now = Date.now();

  // --- Protection Defaults ---
  let protection = $state<Awaited<ReturnType<typeof api.protectionStatus>> | null>(null);
  let protectionBusy = $state(false);
  let protectionError = $state("");

  async function loadProtection() {
    try {
      protection = await api.protectionStatus(router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      protectionError = err instanceof Error ? err.message : String(err);
    }
  }
  async function toggleProtection() {
    protectionBusy = true;
    try {
      await api.protectionToggle();
      await loadProtection();
    } catch (err) {
      protectionError = err instanceof ApiError ? err.message : String(err);
    } finally {
      protectionBusy = false;
    }
  }

  // --- Query Log / Statistics (one real settings object -- see
  // internal/dnsanalytics.Settings' own doc comment for why this
  // architecture has no separate query-log-vs-statistics split). ---
  let analytics = $state<AnalyticsSettings | null>(null);
  let analyticsError = $state("");
  let analyticsBusy = $state(false);
  let analyticsSaved = $state(false);

  async function loadAnalytics() {
    try {
      analytics = await api.getAnalyticsSettings(router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      analyticsError = err instanceof Error ? err.message : String(err);
    }
  }
  async function saveAnalytics(e: Event) {
    e.preventDefault();
    if (!analytics) return;
    analyticsBusy = true;
    analyticsError = "";
    analyticsSaved = false;
    try {
      analytics = await api.updateAnalyticsSettings(analytics);
      analyticsSaved = true;
    } catch (err) {
      analyticsError = err instanceof ApiError ? err.message : String(err);
    } finally {
      analyticsBusy = false;
    }
  }

  let confirmClearOpen = $state(false);
  let clearBusy = $state(false);
  let clearResult = $state("");
  async function runClear() {
    confirmClearOpen = false;
    clearBusy = true;
    try {
      const resp = await api.statisticsClear();
      clearResult = `Cleared ${resp.query_events_cleared.toLocaleString()} recorded queries.`;
    } catch (err) {
      clearResult = err instanceof ApiError ? err.message : String(err);
    } finally {
      clearBusy = false;
    }
  }

  // --- Interface Preferences ---
  let profile = $state<NavProfile>(loadProfile());
  function setProfile(p: NavProfile) {
    profile = p;
    saveProfile(p);
  }

  type ThemeChoice = "light" | "dark" | "system";
  let themeChoice = $state<ThemeChoice>(hasExplicitTheme() ? loadTheme() : "system");
  function setThemeChoice(choice: ThemeChoice) {
    themeChoice = choice;
    if (choice === "system") useSystemTheme();
    else applyTheme(choice as Theme);
  }

  const DASHBOARD_PERIOD_KEY = "apdns-go-dashboard-default-period";
  let dashboardPeriod = $state<"live" | "1h" | "24h" | "7d">((localStorage.getItem(DASHBOARD_PERIOD_KEY) as "live" | "1h" | "24h" | "7d") || "live");
  function setDashboardPeriod(p: "live" | "1h" | "24h" | "7d") {
    dashboardPeriod = p;
    try {
      localStorage.setItem(DASHBOARD_PERIOD_KEY, p);
    } catch {
      /* best-effort */
    }
  }

  onMount(() => {
    loadIdentity();
    loadProtection();
    loadAnalytics();
  });
</script>

<PageHeader
  headingId="general-settings-heading"
  title="General"
  description="Appliance identity, protection defaults, query log &amp; statistics, and interface preferences -- every control here is the same real setting shown elsewhere, not a separate copy."
/>

{#if statusError}<p class="error" role="alert">{statusError}</p>{/if}

<div class="settings">
  <section class="settings-section">
    <h2>Appliance Identity</h2>
    <div class="row">
      <div class="row-label">
        <span>Display name</span>
        <p class="hint">Shown in the browser tab, this appliance's own Local DNS suggestion, and anywhere else it identifies itself.</p>
      </div>
      <form onsubmit={saveName} class="row-control">
        <input required bind:value={nameDraft} aria-label="Appliance display name" />
        <button type="submit" disabled={nameBusy || nameDraft.trim() === applianceName}>{nameBusy ? "Saving…" : "Save"}</button>
        {#if nameSaved}<span class="success">Saved.</span>{/if}
        {#if nameError}<p class="error" role="alert">{nameError}</p>{/if}
      </form>
    </div>
    <div class="row">
      <div class="row-label">
        <span>Timezone</span>
        <p class="hint">Detected at startup from this appliance's own configuration file -- not editable here without a restart.</p>
      </div>
      <div class="row-control"><span class="value">{applianceTimezone || "…"}</span></div>
    </div>
    <div class="row">
      <div class="row-label">
        <span>Language</span>
        <p class="hint">Not supported yet -- this interface is English-only.</p>
      </div>
      <div class="row-control"><span class="value muted">English (only)</span></div>
    </div>
    <div class="row">
      <div class="row-label">
        <span>Timestamp format</span>
        <p class="hint">Controls how every timestamp in this application is shown. Applies instantly, everywhere.</p>
      </div>
      <div class="row-control">
        <div class="radio-row">
          <label><input type="radio" name="ts-mode" checked={timestampPref.mode === "browser"} onchange={() => onTimestampModeChange("browser")} /> Browser Local</label>
          <label><input type="radio" name="ts-mode" checked={timestampPref.mode === "appliance"} onchange={() => onTimestampModeChange("appliance")} /> Appliance Time</label>
          <label><input type="radio" name="ts-mode" checked={timestampPref.mode === "utc"} onchange={() => onTimestampModeChange("utc")} /> UTC</label>
        </div>
        <p class="hint">Preview: <strong>{timestampPref.format(now)}</strong></p>
      </div>
    </div>
  </section>

  <section class="settings-section">
    <h2>Protection Defaults</h2>
    <div class="row">
      <div class="row-label">
        <span>Global filtering</span>
        <p class="hint">The appliance-wide on/off switch for blocklists and custom rules.</p>
      </div>
      <div class="row-control">
        {#if protectionError}
          <p class="error" role="alert">{protectionError}</p>
        {:else if protection}
          <button type="button" class={protection.active ? "danger" : ""} disabled={protectionBusy} onclick={toggleProtection}>
            {protectionBusy ? "Working…" : protection.active ? "Disable protection" : "Enable protection"}
          </button>
        {/if}
      </div>
    </div>
    <div class="row">
      <div class="row-label">
        <span>Browsing security, parental protection &amp; SafeSearch</span>
        <p class="hint">The default security/parental policy and SafeSearch mode every client falls back to, unless a network, group, or client overrides it.</p>
      </div>
      <div class="row-control"><button type="button" class="secondary" onclick={() => router.navigate("policies")}>Configure in Scope Policies</button></div>
    </div>
    <div class="row">
      <div class="row-label">
        <span>Default blocked-services behavior</span>
        <p class="hint">Which well-known services (social media, gaming, etc.) are blocked appliance-wide, and on what schedule.</p>
      </div>
      <div class="row-control"><button type="button" class="secondary" onclick={() => router.navigate("blocked-services")}>Configure in Blocked Services</button></div>
    </div>
  </section>

  <section class="settings-section">
    <h2>Query Log &amp; Statistics</h2>
    <p class="hint section-note">
      This appliance keeps query history in one real table -- there is no separate "query log" vs
      "statistics" store, so the settings below govern both at once.
    </p>
    {#if analyticsError}<p class="error" role="alert">{analyticsError}</p>{/if}
    {#if !analytics}
      <p class="hint">Loading…</p>
    {:else}
      <form onsubmit={saveAnalytics}>
        <div class="row">
          <div class="row-label"><span>Collection enabled</span></div>
          <div class="row-control"><label class="switch-label"><input type="checkbox" bind:checked={analytics.analytics_enabled} /> Enabled</label></div>
        </div>
        <div class="row">
          <div class="row-label"><span>Detailed query logging</span><p class="hint">When off, the domain field is blanked on new rows instead of recorded.</p></div>
          <div class="row-control"><label class="switch-label"><input type="checkbox" bind:checked={analytics.detailed_query_logging_enabled} /> Enabled</label></div>
        </div>
        <div class="row">
          <div class="row-label"><span>Privacy / anonymization</span></div>
          <div class="row-control">
            <select bind:value={analytics.privacy_mode}>
              <option value="full">Full detail</option>
              <option value="anonymized_clients">Anonymize clients</option>
              <option value="aggregate_only">Aggregate only</option>
            </select>
            {#if analytics.privacy_mode === "anonymized_clients"}
              <select bind:value={analytics.client_anonymization}>
                <option value="truncate">Truncate address</option>
                <option value="hash">Hash address</option>
              </select>
            {/if}
          </div>
        </div>
        <div class="row">
          <div class="row-label"><span>Ignored domains</span><p class="hint">Not supported yet -- every domain is recorded (subject to the privacy mode above).</p></div>
          <div class="row-control"><span class="value muted">Not available</span></div>
        </div>
        <div class="row">
          <div class="row-label"><span>Retention</span></div>
          <div class="row-control"><input type="number" min="1" max="3650" bind:value={analytics.detailed_retention_days} style="width:6rem" /> days</div>
        </div>
        <div class="row">
          <div class="row-label"><span>Database size limit</span></div>
          <div class="row-control"><input type="number" min="1048576" bind:value={analytics.db_size_limit_bytes} /> bytes</div>
        </div>
        <div class="row-actions">
          <button type="submit" disabled={analyticsBusy}>{analyticsBusy ? "Saving…" : "Save"}</button>
          {#if analyticsSaved}<span class="success">Saved.</span>{/if}
        </div>
      </form>
    {/if}

    <div class="row danger-row">
      <div class="row-label">
        <span>Clear Query Log &amp; Statistics</span>
        <p class="hint">Permanently deletes every recorded query. Cannot be undone.</p>
      </div>
      <div class="row-control">
        <a class="secondary export-btn" href="/api/statistics/export">Export</a>
        <button type="button" class="danger" disabled={clearBusy} onclick={() => (confirmClearOpen = true)}>{clearBusy ? "Clearing…" : "Clear"}</button>
      </div>
    </div>
    {#if clearResult}<p class="hint" role="status">{clearResult}</p>{/if}
  </section>

  <section class="settings-section">
    <h2>Interface Preferences</h2>
    <div class="row">
      <div class="row-label"><span>Navigation profile</span><p class="hint">Standard shows everyday pages; Advanced adds operational/administrative pages. Direct links to Advanced pages still work either way.</p></div>
      <div class="row-control">
        <div class="radio-row">
          <label><input type="radio" name="nav-profile" checked={profile === "standard"} onchange={() => setProfile("standard")} /> Standard</label>
          <label><input type="radio" name="nav-profile" checked={profile === "advanced"} onchange={() => setProfile("advanced")} /> Advanced</label>
        </div>
      </div>
    </div>
    <div class="row">
      <div class="row-label"><span>Theme</span></div>
      <div class="row-control">
        <div class="radio-row">
          <label><input type="radio" name="theme-choice" checked={themeChoice === "light"} onchange={() => setThemeChoice("light")} /> Light</label>
          <label><input type="radio" name="theme-choice" checked={themeChoice === "dark"} onchange={() => setThemeChoice("dark")} /> Dark</label>
          <label><input type="radio" name="theme-choice" checked={themeChoice === "system"} onchange={() => setThemeChoice("system")} /> System</label>
        </div>
      </div>
    </div>
    <div class="row">
      <div class="row-label"><span>Default Dashboard period</span><p class="hint">The time range Dashboard opens with.</p></div>
      <div class="row-control">
        <select value={dashboardPeriod} onchange={(e) => setDashboardPeriod((e.target as HTMLSelectElement).value as typeof dashboardPeriod)}>
          <option value="live">Live</option>
          <option value="1h">Last hour</option>
          <option value="24h">Last 24 hours</option>
          <option value="7d">Last 7 days</option>
        </select>
      </div>
    </div>
    <div class="row">
      <div class="row-label"><span>Table page size</span><p class="hint">Not applicable -- this app's own tables show every row with a resizable/scrollable grid instead of pagination.</p></div>
      <div class="row-control"><span class="value muted">Not applicable</span></div>
    </div>
  </section>
</div>

{#if confirmClearOpen}
  <ConfirmDialog
    title="Clear Query Log &amp; Statistics"
    message="Permanently delete every recorded query? This cannot be undone."
    confirmLabel="Clear"
    onConfirm={runClear}
    onCancel={() => (confirmClearOpen = false)}
  />
{/if}

<style>
  .settings { max-width: 44rem; display: flex; flex-direction: column; gap: 2rem; }
  .settings-section h2 { font-size: 1.05rem; margin: 0 0 0.25rem; }
  .section-note { margin: 0 0 0.75rem; }
  .row { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-start; gap: 0.75rem; padding: 0.85rem 0; border-bottom: 1px solid var(--border); }
  .row:last-child { border-bottom: none; }
  .row-label { flex: 1 1 16rem; display: flex; flex-direction: column; gap: 0.2rem; }
  .row-label > span { font-weight: 600; font-size: 0.92rem; }
  .row-control { flex: 1 1 16rem; display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
  .row-actions { display: flex; align-items: center; gap: 0.6rem; padding-top: 0.5rem; }
  .danger-row { border-top: 2px solid var(--border); margin-top: 0.5rem; padding-top: 1rem; }
  .hint { font-size: 0.82rem; opacity: 0.7; margin: 0; }
  .value { font-size: 0.9rem; }
  .value.muted { opacity: 0.6; font-style: italic; }
  .error { color: var(--danger); font-size: 0.85rem; }
  .success { color: var(--success); font-size: 0.85rem; }
  .radio-row { display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.88rem; }
  .radio-row label { display: flex; align-items: center; gap: 0.35rem; }
  .switch-label { display: flex; align-items: center; gap: 0.4rem; font-size: 0.88rem; }
  button.danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); border-color: transparent; }
  .export-btn { display: inline-flex; align-items: center; text-decoration: none; }
</style>
