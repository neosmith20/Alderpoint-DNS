<script lang="ts">
  import { api } from "../api";

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
    Export is a real download of this appliance's own Go-native query history. Clear is a real,
    destructive DELETE against that same store -- see the parity matrix.
  </p>

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
