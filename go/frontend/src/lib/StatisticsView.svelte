<script lang="ts">
  import { api } from "../api";

  // Statistics. Export is real: a genuine download of the aggregates
  // store's own two tables (GET /api/statistics/export, backed by
  // internal/pyanalytics.ExportAll -- proven against the actually-live
  // preview's real aggregates.db). Deliberately does not include raw
  // per-query history (already exportable via Query Log's filters),
  // matching Python's own export shape.
  //
  // Clear is real (2026-08-27): POST /api/statistics/clear, run via
  // apdns-hostagent -- the same already-root process that already has
  // real, unrestricted host-path access to Python's live aggregates.db
  // for the analytics-snapshot publisher, so this needed no new mount
  // into the unprivileged web container. Same server-side "type CLEAR
  // to confirm" + optional raw-history wipe as V1's own route (see
  // internal/hostagentd/ops_analyticsclear.go).

  let confirmText = $state("");
  let includeRawHistory = $state(true);
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
      clearResult = await api.statisticsClear(includeRawHistory);
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
    Export is a real download of the analytics aggregate store. Clear is a real, destructive action
    against the same live analytics store, performed via the host-control agent (never a direct
    write from this web process) -- see the parity matrix.
  </p>

  <div class="card">
    <h3>Export</h3>
    <p class="hint">Downloads a JSON snapshot of aggregate time buckets and dimension counts.</p>
    <a class="export-link" href="/api/statistics/export">Download statistics export</a>
  </div>

  <div class="card clear-card">
    <h3>Clear</h3>
    <p class="hint">
      Permanently deletes the aggregate rollups (dashboard/top-domain data) that power charts and
      panels. Optionally also deletes the raw per-query history files. This cannot be undone.
    </p>
    <form onsubmit={onClear} class="clear-form">
      <label class="checkbox-row">
        <input type="checkbox" bind:checked={includeRawHistory} />
        Also delete raw per-query history (Parquet files)
      </label>
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
        Cleared {clearResult.aggregate_buckets_cleared} time bucket(s) and
        {clearResult.aggregate_dimension_rows_cleared} dimension row(s).
        {#if clearResult.raw_history_cleared}
          Also removed {clearResult.raw_partition_files_removed} raw history file(s).
        {:else}
          Raw per-query history was left untouched.
        {/if}
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
  .checkbox-row, .confirm-row { display: flex; align-items: center; gap: 0.5rem; font-size: 0.88rem; }
  .confirm-row input { width: 8rem; }
  button.danger { align-self: flex-start; padding: 0.4rem 0.8rem; border: 1px solid var(--badge-danger-fg); border-radius: 6px; background: var(--badge-danger-bg); color: var(--badge-danger-fg); font-size: 0.85rem; }
  button.danger:disabled { opacity: 0.5; cursor: not-allowed; }
  .error { color: var(--badge-danger-fg); font-size: 0.85rem; }
  .ok { color: var(--badge-ok-fg); font-size: 0.85rem; }
</style>
