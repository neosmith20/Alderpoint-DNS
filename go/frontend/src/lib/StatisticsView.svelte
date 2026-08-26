<script lang="ts">
  // Statistics. Export is real: a genuine download of the aggregates
  // store's own two tables (GET /api/statistics/export, backed by
  // internal/pyanalytics.ExportAll -- proven against the actually-live
  // preview's real aggregates.db). Deliberately does not include raw
  // per-query history (already exportable via Query Log's filters),
  // matching Python's own export shape.
  //
  // Clear is deliberately not built: it would mean writing to Python's
  // live, actively-written aggregates.db/Parquet tree through a mount
  // this control plane only ever holds read-only -- the same isolation
  // boundary every other compatibility boundary this migration built
  // (pyanalytics/rawquerylog/tlscert) respects. Disclosed here, not
  // silently omitted.
</script>

<section aria-labelledby="statistics-heading" class="statistics">
  <h2 id="statistics-heading">Statistics</h2>
  <p class="scope-note">
    Export is a real download of the analytics aggregate store. Clear is not built here -- it would
    require write access to Python's live analytics store, which this control plane deliberately only
    ever reads. See the parity matrix.
  </p>

  <div class="card">
    <h3>Export</h3>
    <p class="hint">Downloads a JSON snapshot of aggregate time buckets and dimension counts.</p>
    <a class="export-link" href="/api/statistics/export">Download statistics export</a>
  </div>
</section>

<style>
  .statistics { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; max-width: 28rem; }
  .card h3 { margin: 0; }
  .hint { font-size: 0.85rem; opacity: 0.75; margin: 0; }
  .export-link { align-self: flex-start; padding: 0.4rem 0.8rem; border: 1px solid var(--border); border-radius: 6px; background: var(--accent); color: var(--accent-fg); text-decoration: none; font-size: 0.85rem; }
</style>
