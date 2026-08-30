<script lang="ts">
  import { onMount } from "svelte";
  import { api, type AnalyticsSettings } from "../api";

  // Statistics. Export is real: a genuine download of this appliance's
  // own Go-native query_events table, summarized the same way the
  // Dashboard/Query Log already read it (GET /api/statistics/export,
  // backed by internal/dnsanalytics.Reader.ExportAll -- Python's
  // aggregates.db is fully decommissioned, see CUTOVER.md).
  //
  // Clear is real (2026-08-28: rewritten to act directly on
  // internal/dnsanalytics -- see that package's ClearAll doc comment
  // for why this no longer routes through apdns-hostagent the way it
  // did against Python's now-permanently-inert aggregates.db/Parquet
  // bridge). There's exactly one table now, so there's no longer a
  // separate "raw history" toggle -- Clear removes all of it.
  //
  // Settings (2026-08-30): real, matching V1.1.1's own statistics_settings.html
  // field-for-field wherever this architecture has an equivalent -- see
  // GET/PUT /api/statistics/settings and internal/dnsanalytics.Settings's
  // own doc comment for the two fields deliberately NOT modeled
  // (aggregate_retention_days, collection_interval -- both governed a
  // separate poll-and-aggregate tier this single-table design doesn't
  // have) and for the one real behavioral difference from V1 (disabling
  // detailed logging blanks just the domain field here rather than
  // dropping the whole row, since there's no separate aggregate tier to
  // fall back to).

  let settings = $state<AnalyticsSettings | null>(null);
  let settingsError = $state("");
  let savingSettings = $state(false);
  let savedNote = $state(false);

  async function loadSettings() {
    try {
      settings = await api.getAnalyticsSettings();
      settingsError = "";
    } catch (err) {
      settingsError = err instanceof Error ? err.message : String(err);
    }
  }

  async function saveSettings(e: SubmitEvent) {
    e.preventDefault();
    if (!settings) return;
    savingSettings = true;
    savedNote = false;
    settingsError = "";
    try {
      settings = await api.updateAnalyticsSettings(settings);
      savedNote = true;
    } catch (err) {
      settingsError = err instanceof Error ? err.message : String(err);
    } finally {
      savingSettings = false;
    }
  }

  onMount(loadSettings);

  let confirmText = $state("");
  let clearing = $state(false);
  let clearError = $state("");
  let clearResult = $state<Awaited<ReturnType<typeof api.statisticsClear>> | null>(null);

  async function onClear(e: SubmitEvent) {
    e.preventDefault();
    if (confirmText !== "CLEAR") return;
    clearing = true;
    clearError = "";
    clearResult = null;
    try {
      clearResult = await api.statisticsClear();
      confirmText = "";
    } catch (err) {
      clearError = err instanceof Error ? err.message : String(err);
    } finally {
      clearing = false;
    }
  }
</script>

<section aria-labelledby="statistics-heading" class="statistics">
  <h2 id="statistics-heading">Statistics</h2>
  <p class="scope-note">
    Export downloads this appliance's own query history. Clear permanently deletes it.
  </p>

  <div class="card settings-card">
    <h3>Settings</h3>
    {#if settingsError}
      <p class="error" role="alert">{settingsError}</p>
    {/if}
    {#if !settings}
      <p class="hint">Loading…</p>
    {:else}
      <form onsubmit={saveSettings} class="settings-form">
        <label class="row"><input type="checkbox" bind:checked={settings.analytics_enabled} /> Analytics enabled</label>
        <label class="row">
          <input type="checkbox" bind:checked={settings.detailed_query_logging_enabled} /> Detailed query logging enabled
        </label>
        <label>
          Privacy mode
          <select bind:value={settings.privacy_mode}>
            <option value="full">Full</option>
            <option value="anonymized_clients">Anonymized clients</option>
            <option value="aggregate_only">Aggregate only</option>
          </select>
        </label>
        <label>
          Client anonymization
          <select bind:value={settings.client_anonymization} disabled={settings.privacy_mode === "full"}>
            <option value="truncate">Truncate</option>
            <option value="hash">Hash</option>
          </select>
        </label>
        <label>Detailed retention (days) <input type="number" min="0" bind:value={settings.detailed_retention_days} /></label>
        <label>Database size limit (bytes) <input type="number" min="1048576" bind:value={settings.db_size_limit_bytes} /></label>
        <label>Recent query limit <input type="number" min="10" bind:value={settings.recent_query_limit} /></label>
        <p class="hint">
          Aggregate-tier retention and a separate collection interval don't apply here -- this
          appliance keeps one real query history rather than a separate poll-and-aggregate tier, so
          there's nothing distinct to configure for either.
        </p>
        <div>
          <button type="submit" disabled={savingSettings}>{savingSettings ? "Saving…" : "Save settings"}</button>
          {#if savedNote}<span class="ok" role="status">Saved.</span>{/if}
        </div>
      </form>
    {/if}
  </div>

  <div class="card">
    <h3>Export</h3>
    <p class="hint">Downloads a JSON snapshot of this appliance's own real query history.</p>
    <a class="export-link" href="/api/statistics/export">Download statistics export</a>
  </div>

  <div class="card clear-card">
    <h3>Clear</h3>
    <p class="hint">
      Permanently deletes this appliance's entire real query history (the same data that powers
      Dashboard charts, Top Domains, and Query Log). This cannot be undone.
    </p>
    <form onsubmit={onClear} class="clear-form">
      <label class="confirm-row">
        Type <strong>CLEAR</strong> to confirm
        <input type="text" bind:value={confirmText} aria-label="Type CLEAR to confirm" autocomplete="off" />
      </label>
      <button type="submit" class="danger" disabled={confirmText !== "CLEAR" || clearing}>
        {clearing ? "Clearing…" : "Clear statistics"}
      </button>
    </form>
    {#if clearError}
      <p class="error" role="alert">{clearError}</p>
    {/if}
    {#if clearResult}
      <p class="ok" role="status">
        Cleared {clearResult.query_events_cleared} stored quer{clearResult.query_events_cleared === 1 ? "y" : "ies"}.
      </p>
    {/if}
  </div>
</section>

<style>
  .statistics { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; max-width: 28rem; }
  .settings-card { max-width: 34rem; }
  .settings-form { display: flex; flex-direction: column; gap: 0.6rem; font-size: 0.88rem; }
  .settings-form label { display: flex; flex-direction: column; gap: 0.2rem; }
  .settings-form label.row { flex-direction: row; align-items: center; gap: 0.5rem; }
  .settings-form input[type="number"] { width: 10rem; }
  .card h3 { margin: 0; }
  .hint { font-size: 0.85rem; opacity: 0.75; margin: 0; }
  .export-link { align-self: flex-start; padding: 0.4rem 0.8rem; border: 1px solid var(--border); border-radius: 6px; background: var(--accent); color: var(--accent-fg); text-decoration: none; font-size: 0.85rem; }
  .clear-card { max-width: 32rem; }
  .clear-form { display: flex; flex-direction: column; gap: 0.6rem; }
  .confirm-row { display: flex; align-items: center; gap: 0.5rem; font-size: 0.88rem; }
  .confirm-row input { width: 8rem; }
  button.danger { align-self: flex-start; padding: 0.4rem 0.8rem; border: 1px solid var(--badge-danger-fg); border-radius: 6px; background: var(--badge-danger-bg); color: var(--badge-danger-fg); font-size: 0.85rem; }
  button.danger:disabled { opacity: 0.5; cursor: not-allowed; }
  .error { color: var(--badge-danger-fg); font-size: 0.85rem; }
  .ok { color: var(--badge-ok-fg); font-size: 0.85rem; }
</style>
