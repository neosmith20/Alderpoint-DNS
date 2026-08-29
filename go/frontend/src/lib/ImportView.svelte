<script lang="ts">
  import { api, ApiError, type ImportJob, type DNSRuntimeApplyResult, type LegacyImportReport, type LegacyImportManifest } from "../api";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";

  // Import. Real staged preview -> selection -> apply -> rollback/report
  // workflow (internal/importer's job model), field-matched against
  // Python's own real POST /api/import/jobs -> GET .../jobs/{id} ->
  // POST .../jobs/{id}/apply shape -- not a one-shot blind apply.
  // Three source types are real: hosts-file, a simple Alderpoint-native
  // CSV (name,record_type,value,ttl), and a real BIND zone-file parser
  // (a practical subset -- A/AAAA/CNAME/PTR, $ORIGIN honored; no $TTL,
  // SOA/NS/MX, or multi-line records). AdGuard YAML/live API, Pi-hole
  // paste, and XLSX are not built -- disclosed, not silently assumed
  // equivalent.

  let sourceType = $state<"hosts" | "csv" | "zone">("hosts");
  let sourceText = $state("");
  let defaultDomain = $state("");
  let previewBusy = $state(false);
  let previewError = $state("");

  let job = $state<ImportJob | null>(null);
  let skipped = $state<Set<number>>(new Set());
  let applyBusy = $state(false);
  let applyError = $state("");
  let rollbackBusy = $state(false);
  let rollbackError = $state("");
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);
  let dismissedJobIds = new Set<number>();

  async function preview(e: Event) {
    e.preventDefault();
    previewError = "";
    previewBusy = true;
    job = null;
    skipped = new Set();
    try {
      const sourceName = sourceType === "hosts" ? "hosts import" : sourceType === "csv" ? "csv import" : "zone import";
      const created = await api.createImportJob(sourceType, sourceName, sourceText, sourceType === "zone" ? defaultDomain : undefined);
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
    if (job) dismissedJobIds.add(job.id);
    job = null;
    sourceText = "";
    skipped = new Set();
  }

  // Legacy V1.1.1 appliance backup import -- a real .tar.gz/.tar.gz.enc
  // archive (app/backup.py's create_backup output), reusing the same
  // audited, bounded internal/pymigrate table set already used for the
  // one-time cutover import. A different shape from the job-based
  // workflow above (Report, not a plan/apply job row), so it gets its
  // own card rather than a fourth sourceType.
  let legacyFile: File | null = $state(null);
  let legacyFileInput: HTMLInputElement | undefined = $state();
  let legacyPassword = $state("");
  let legacyBusy = $state(false);
  let legacyError = $state("");
  let legacyReport = $state<LegacyImportReport | null>(null);
  let legacyManifest = $state<LegacyImportManifest | null>(null);

  function onLegacyFileChange() {
    legacyFile = legacyFileInput?.files?.[0] ?? null;
    legacyReport = null;
    legacyError = "";
  }

  async function runLegacyImport(dryRun: boolean) {
    if (!legacyFile) return;
    legacyBusy = true;
    legacyError = "";
    try {
      const resp = await api.importLegacyAppliance(legacyFile, legacyPassword, dryRun);
      legacyReport = resp.report;
      legacyManifest = resp.manifest;
    } catch (err) {
      legacyError = err instanceof ApiError ? err.message : String(err);
    } finally {
      legacyBusy = false;
    }
  }

  function legacyTotals(): { imported: number; skipped: number; rejected: number } {
    if (!legacyReport) return { imported: 0, skipped: 0, rejected: 0 };
    return Object.values(legacyReport.tables).reduce(
      (acc, t) => ({ imported: acc.imported + t.imported, skipped: acc.skipped + t.skipped, rejected: acc.rejected + t.rejected }),
      { imported: 0, skipped: 0, rejected: 0 },
    );
  }

  // A previewed-but-not-yet-applied job is a real, server-persisted row
  // (import_jobs) -- not component-local state. Without this, navigating
  // away (e.g. to Local DNS to sanity-check the preview) and back would
  // silently drop the staged plan even though it still exists in the
  // database, forcing a re-preview for no reason. Resume it on mount.
  $effect(() => {
    if (job) return;
    let cancelled = false;
    (async () => {
      try {
        const { jobs } = await api.listImportJobs();
        // Resume the most recent still-relevant job -- "pending" (previewed,
        // not yet applied) or "applied" (its rollback control must stay
        // reachable after navigating away and back, not just immediately
        // after the apply click).
        const resumable = jobs.find((j) => (j.status === "pending" || j.status === "applied") && !dismissedJobIds.has(j.id));
        if (resumable && !cancelled) job = resumable;
      } catch {
        // best-effort resume only -- an empty form is still a safe fallback
      }
    })();
    return () => {
      cancelled = true;
    };
  });
</script>

<section aria-labelledby="importexport-heading" class="import-view">
  <h2 id="importexport-heading">Import</h2>
  <p class="scope-note">
    Real staged preview -> selection -> apply -> rollback (internal/importer). hosts-file, a
    simple Alderpoint CSV (name,record_type,value,ttl), and a BIND zone-file parser (a practical
    subset -- A/AAAA/CNAME/PTR, $ORIGIN honored) are built; AdGuard YAML/live API, Pi-hole paste,
    and XLSX are not -- see the parity matrix.
  </p>

  {#if !job}
    <form class="card" onsubmit={preview}>
      <h3>1. Preview a source</h3>
      <label>
        Source type
        <select bind:value={sourceType}>
          <option value="hosts">Hosts file</option>
          <option value="csv">CSV (name,record_type,value,ttl)</option>
          <option value="zone">BIND zone file</option>
        </select>
      </label>
      {#if sourceType === "zone"}
        <label>
          Default domain (used as $ORIGIN, and to qualify relative names)
          <input bind:value={defaultDomain} placeholder="example.com" required />
        </label>
      {/if}
      <textarea
        bind:value={sourceText}
        placeholder={sourceType === "hosts"
          ? "127.0.0.1 localhost\n10.0.0.5 nas nas.lan"
          : sourceType === "csv"
            ? "name,record_type,value,ttl\nprinter.lan,A,10.0.0.50,300"
            : "www\tIN\tA\t10.0.0.50\nmail\t600\tIN\tA\t10.0.0.51"}
        aria-label={sourceType === "hosts" ? "Hosts file contents" : sourceType === "csv" ? "CSV contents" : "Zone file contents"}
        rows="8"
      ></textarea>
      <div class="actions">
        <button type="submit" disabled={previewBusy || !sourceText.trim() || (sourceType === "zone" && !defaultDomain.trim())}>
          {previewBusy ? "Parsing…" : "Preview"}
        </button>
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

  <h3 id="legacy-import-heading">Import a V1.1.1 appliance backup</h3>
  <p class="scope-note">
    Upload a real V1.1.1 backup archive (<code>alderpointdns-backup-*.tar.gz</code> or
    <code>.tar.gz.enc</code>) to import its Local DNS records, upstream profiles, DNS transport
    settings, the global policy layer, and blocklist subscriptions -- the same bounded, audited
    table set used for a live cutover, applied here to an uploaded file instead. A password is
    required only for an encrypted (<code>.enc</code>) archive.
  </p>
  <div class="card">
    <label>
      Backup file
      <input type="file" bind:this={legacyFileInput} onchange={onLegacyFileChange} aria-label="Legacy V1.1.1 backup file" accept=".tar.gz,.enc" />
    </label>
    <label>
      Password (only for a <code>.tar.gz.enc</code> archive)
      <input type="password" bind:value={legacyPassword} autocomplete="off" />
    </label>
    <div class="actions">
      <button onclick={() => runLegacyImport(true)} disabled={!legacyFile || legacyBusy}>
        {legacyBusy ? "Working…" : "Preview (dry run)"}
      </button>
      <button onclick={() => runLegacyImport(false)} disabled={!legacyFile || legacyBusy}>
        {legacyBusy ? "Working…" : "Import for real"}
      </button>
    </div>
    {#if legacyError}<p class="error" role="alert">{legacyError}</p>{/if}
    {#if legacyReport}
      {@const totals = legacyTotals()}
      <p class={legacyReport.dry_run ? "" : "success"} role="status">
        {legacyReport.dry_run ? "Dry run -- nothing written." : "Imported for real."}
        <strong>{totals.imported}</strong> {legacyReport.dry_run ? "would import" : "imported"},
        <strong>{totals.skipped}</strong> skipped, <strong>{totals.rejected}</strong> rejected.
        {#if legacyReport.snapshot_filename}
          A pre-migration safety backup was saved as "{legacyReport.snapshot_filename}".
        {/if}
      </p>
      {#if legacyManifest}
        <p class="scope-note">
          Source: appliance {legacyManifest.source_node_id || "(unknown)"}, app version
          {legacyManifest.alderpointdns_app_version || "unknown"}, created {legacyManifest.created_at || "unknown"}.
        </p>
      {/if}
      <table class="plan-table">
        <thead><tr><th>Table</th><th>Source rows</th><th>Imported</th><th>Skipped</th><th>Rejected</th></tr></thead>
        <tbody>
          {#each Object.entries(legacyReport.tables) as [table, summary] (table)}
            <tr>
              <td>{table}</td>
              <td>{summary.source_count}</td>
              <td>{summary.imported}</td>
              <td>{summary.skipped}</td>
              <td>{summary.rejected}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      <details>
        <summary>Not migrated (disclosed, not silently skipped)</summary>
        <p class="scope-note">{legacyReport.not_migrated.join(", ")}</p>
      </details>
    {/if}
  </div>
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
