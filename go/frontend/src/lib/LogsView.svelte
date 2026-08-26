<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type LogEntry } from "../api";
  import { router } from "../router.svelte";

  // Logs. Real, bounded, read-only journalctl access via apdns-hostagent
  // (see internal/hostagentd/ops_logs.go) -- a fixed allowlist of
  // logical unit names, never a caller-supplied unit string passed
  // straight to journalctl.

  let units = $state<string[]>([]);
  let selectedUnit = $state("");
  let lines = $state(200);
  let entries = $state<LogEntry[]>([]);
  let loadError = $state("");
  let loading = $state(false);

  async function loadUnits() {
    try {
      const resp = await api.logsListUnits(router.signal());
      units = resp.units;
      if (units.length > 0 && !selectedUnit) selectedUnit = units[0];
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  async function loadEntries() {
    if (!selectedUnit) return;
    loading = true;
    loadError = "";
    try {
      const resp = await api.logsRead(selectedUnit, lines, router.signal());
      entries = resp.entries;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof ApiError ? err.message : String(err);
    } finally {
      loading = false;
    }
  }

  onMount(async () => {
    await loadUnits();
    await loadEntries();
  });
</script>

<section aria-labelledby="logs-heading" class="logs">
  <h2 id="logs-heading">Logs</h2>
  <p class="scope-note">
    Real, bounded journalctl access via apdns-hostagent, restricted to a fixed allowlist of units.
  </p>

  <form class="filters" onsubmit={(e) => { e.preventDefault(); loadEntries(); }}>
    <select bind:value={selectedUnit} aria-label="Unit">
      {#each units as u (u)}
        <option value={u}>{u}</option>
      {/each}
    </select>
    <select bind:value={lines} aria-label="Line count">
      <option value={50}>50 lines</option>
      <option value={200}>200 lines</option>
      <option value={500}>500 lines</option>
    </select>
    <button type="submit" disabled={loading}>{loading ? "Loading…" : "Refresh"}</button>
  </form>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <div class="log-scroll">
    <table>
      <thead><tr><th>Time</th><th>Message</th></tr></thead>
      <tbody>
        {#each entries as e, i (i)}
          <tr><td>{e.time}</td><td class="msg">{e.message}</td></tr>
        {:else}
          <tr class="empty-row"><td colspan="2">No log entries.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<style>
  .logs { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .filters { display: flex; gap: 0.5rem; align-items: center; }
  .log-scroll { max-height: 32rem; overflow: auto; border: 1px solid var(--border); border-radius: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; font-family: monospace; }
  th, td { text-align: left; padding: 0.25rem 0.6rem; border-bottom: 1px solid var(--border); }
  th { position: sticky; top: 0; background: var(--card-bg); }
  .msg { white-space: pre-wrap; word-break: break-word; }
  .error { color: var(--badge-danger-fg); }
</style>
