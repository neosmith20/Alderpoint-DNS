<script lang="ts">
  import { api, ApiError, type ImportJob, type DNSRuntimeApplyResult } from "../api";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";

  // Import. Real staged preview -> selection -> apply -> rollback/report
  // workflow (internal/importer's job model), field-matched against
  // Python's own real POST /api/import/jobs -> GET .../jobs/{id} ->
  // POST .../jobs/{id}/apply shape -- not a one-shot blind apply.
  // Two source types are real: hosts-file and a simple Alderpoint-
  // native CSV (name,record_type,value,ttl). AdGuard YAML/live API,
  // Pi-hole paste, BIND zone, and XLSX are not built -- disclosed, not
  // silently assumed equivalent.

  let sourceType = $state<"hosts" | "csv">("hosts");
  let sourceText = $state("");
  let previewBusy = $state(false);
  let previewError = $state("");

  let job = $state<ImportJob | null>(null);
  let skipped = $state<Set<number>>(new Set());
  let applyBusy = $state(false);
  let applyError = $state("");
  let rollbackBusy = $state(false);
  let rollbackError = $state("");
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);

  async function preview(e: Event) {
    e.preventDefault();
    previewError = "";
    previewBusy = true;
    job = null;
    skipped = new Set();
    try {
      const created = await api.createImportJob(sourceType, sourceType === "hosts" ? "hosts import" : "csv import", sourceText);
      job = await api.getImportJob(created.job_id);
    } catch (err) {
      previewError = err instanceof ApiError ? err.message : String(err);
    } finally {
      previewBusy = false;
    }
  }

  function toggleSkip(index: number) {
    const next = new Set(skipped);
    if (next.has(index)) next.delete(index);
    else next.add(index);
    skipped = next;
  }

  async function apply() {
    if (!job) return;
    applyBusy = true;
    applyError = "";
    try {
      const result = await api.applyImportJob(job.id, [...skipped]);
      dnsRuntimeResult = result.dns_runtime ?? null;
      job = await api.getImportJob(job.id);
    } catch (err) {
      applyError = err instanceof ApiError ? err.message : String(err);
    } finally {
      applyBusy = false;
    }
  }

  async function rollback() {
    if (!job) return;
    rollbackBusy = true;
    rollbackError = "";
    try {
      const result = await api.rollbackImportJob(job.id);
      dnsRuntimeResult = result.dns_runtime ?? null;
      job = await api.getImportJob(job.id);
    } catch (err) {
      rollbackError = err instanceof ApiError ? err.message : String(err);
    } finally {
      rollbackBusy = false;
    }
  }

  function startOver() {
    job = null;
    sourceText = "";
    skipped = new Set();
  }
</script>

<section aria-labelledby="importexport-heading" class="import-view">
  <h2 id="importexport-heading">Import</h2>
  <p class="scope-note">
    Real staged preview -> selection -> apply -> rollback (internal/importer). hosts-file and a
    simple Alderpoint CSV (name,record_type,value,ttl) are built; AdGuard YAML/live API, Pi-hole
    paste, BIND zone, and XLSX are not -- see the parity matrix.
  </p>

  {#if !job}
    <form class="card" onsubmit={preview}>
      <h3>1. Preview a source</h3>
      <label>
        Source type
        <select bind:value={sourceType}>
          <option value="hosts">Hosts file</option>
          <option value="csv">CSV (name,record_type,value,ttl)</option>
        </select>
      </label>
      <textarea
        bind:value={sourceText}
        placeholder={sourceType === "hosts" ? "127.0.0.1 localhost\n10.0.0.5 nas nas.lan" : "name,record_type,value,ttl\nprinter.lan,A,10.0.0.50,300"}
        aria-label={sourceType === "hosts" ? "Hosts file contents" : "CSV contents"}
        rows="8"
      ></textarea>
      <div class="actions">
        <button type="submit" disabled={previewBusy || !sourceText.trim()}>{previewBusy ? "Parsing…" : "Preview"}</button>
      </div>
      {#if previewError}<p class="error" role="alert">{previewError}</p>{/if}
    </form>
  {:else}
    <div class="card">
      <div class="job-header">
        <h3>2. Review &amp; select ({job.plan.rows.length} row{job.plan.rows.length === 1 ? "" : "s"})</h3>
        <button type="button" onclick={startOver}>Start over</button>
      </div>

      {#if job.plan.parse_errors.length > 0}
        <ul class="parse-errors">
          {#each job.plan.parse_errors as e (e)}<li>{e}</li>{/each}
        </ul>
      {/if}

      {#if job.status === "pending"}
        <table class="plan-table">
          <thead><tr><th></th><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th>Status</th></tr></thead>
          <tbody>
            {#each job.plan.rows as row (row.index)}
              <tr class={row.conflict ? "row-conflict" : ""}>
                <td><input type="checkbox" checked={!skipped.has(row.index)} onchange={() => toggleSkip(row.index)} aria-label={`Include ${row.name}`} /></td>
                <td>{row.name}</td>
                <td>{row.record_type}</td>
                <td>{row.value}</td>
                <td>{row.ttl}</td>
                <td>{#if row.conflict}<span class="badge badge-warn" title={row.conflict_detail}>conflict</span>{:else}<span class="badge badge-ok">new</span>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        <div class="actions">
          <button onclick={apply} disabled={applyBusy}>{applyBusy ? "Applying…" : `Apply (${job.plan.rows.length - skipped.size} row${job.plan.rows.length - skipped.size === 1 ? "" : "s"})`}</button>
        </div>
        {#if applyError}<p class="error" role="alert">{applyError}</p>{/if}
      {:else}
        <p class="success" role="status">
          Applied: <strong>{job.result?.imported ?? 0}</strong> imported, <strong>{job.result?.skipped ?? 0}</strong> skipped.
        </p>
        {#if job.result?.errors && job.result.errors.length > 0}
          <ul class="parse-errors">
            {#each job.result.errors as e (e)}<li>{e}</li>{/each}
          </ul>
        {/if}
        <DnsRuntimeBadge result={dnsRuntimeResult} />
        {#if job.snapshot_filename}
          <div class="actions">
            <button class="danger" onclick={rollback} disabled={rollbackBusy}>{rollbackBusy ? "Rolling back…" : "Roll back this import"}</button>
          </div>
          {#if rollbackError}<p class="error" role="alert">{rollbackError}</p>{/if}
        {/if}
      {/if}
    </div>
  {/if}
</section>

<style>
  .import-view { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; max-width: 44rem; }
  .card h3 { margin: 0; }
  .job-header { display: flex; justify-content: space-between; align-items: center; }
  textarea { font-family: monospace; font-size: 0.85rem; resize: vertical; }
  .actions { display: flex; gap: 0.6rem; }
  .error { color: var(--badge-danger-fg); }
  .success { color: #16a34a; }
  .parse-errors { font-size: 0.8rem; opacity: 0.85; max-height: 8rem; overflow-y: auto; margin: 0; padding-left: 1.2rem; }
  .plan-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .plan-table th, .plan-table td { padding: 0.3rem 0.5rem; text-align: left; border-bottom: 1px solid var(--border); }
  .row-conflict { background: var(--attention-bg); }
  .badge { padding: 0.1rem 0.4rem; border-radius: 999px; font-size: 0.72rem; }
  .badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .badge-warn { background: var(--badge-warn-bg); color: var(--badge-warn-fg); }
  .danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
</style>
