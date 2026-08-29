<script lang="ts">
  import {
    api,
    ApiError,
    type ImportJob,
    type DNSRuntimeApplyResult,
    type LegacyImportReport,
    type LegacyImportManifest,
    type ApdnsbakManifest,
    type FilterImportReport,
  } from "../api";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";

  // Import. Real staged preview -> selection -> apply -> rollback/report
  // workflow (internal/importer's job model), field-matched against
  // Python's own real POST /api/import/jobs -> GET .../jobs/{id} ->
  // POST .../jobs/{id}/apply shape -- not a one-shot blind apply.
  // Four source types are real: hosts-file, a simple Alderpoint-native
  // CSV (name,record_type,value,ttl), a real BIND zone-file parser (a
  // practical subset -- A/AAAA/CNAME/PTR, $ORIGIN honored; no $TTL,
  // SOA/NS/MX, or multi-line records), and a real .xlsx spreadsheet
  // reader (same name,record_type,value,ttl tabular shape as the CSV
  // source). AdGuard Home YAML/live API and Pi-hole are their own
  // separate feature further down this page (a different translation
  // target -- blocklists + local DNS + custom rules together, not just
  // local DNS records).

  let sourceType = $state<"hosts" | "csv" | "zone" | "xlsx">("hosts");
  let sourceText = $state("");
  let xlsxFile: File | null = $state(null);
  let xlsxFileInput: HTMLInputElement | undefined = $state();
  let defaultDomain = $state("");
  let previewBusy = $state(false);
  let previewError = $state("");

  function fileToBase64(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result as string;
        resolve(result.slice(result.indexOf(",") + 1));
      };
      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(file);
    });
  }

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
      const sourceName =
        sourceType === "hosts" ? "hosts import" : sourceType === "csv" ? "csv import" : sourceType === "zone" ? "zone import" : "xlsx import";
      const text = sourceType === "xlsx" ? (xlsxFile ? await fileToBase64(xlsxFile) : "") : sourceText;
      const created = await api.createImportJob(sourceType, sourceName, text, sourceType === "zone" ? defaultDomain : undefined);
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

  // V2 Python .apdnsbak import -- same pymigrate.Report shape and same
  // "legacy" card pattern as the V1.1.1 archive above, just a different
  // source format (Fernet-encrypted, passphrase-protected) and a
  // different backend package (internal/apdnsbak).
  let apdnsbakFile: File | null = $state(null);
  let apdnsbakFileInput: HTMLInputElement | undefined = $state();
  let apdnsbakPassphrase = $state("");
  let apdnsbakBusy = $state(false);
  let apdnsbakError = $state("");
  let apdnsbakReport = $state<LegacyImportReport | null>(null);
  let apdnsbakManifest = $state<ApdnsbakManifest | null>(null);

  function onApdnsbakFileChange() {
    apdnsbakFile = apdnsbakFileInput?.files?.[0] ?? null;
    apdnsbakReport = null;
    apdnsbakError = "";
  }

  async function runApdnsbakImport(dryRun: boolean) {
    if (!apdnsbakFile) return;
    apdnsbakBusy = true;
    apdnsbakError = "";
    try {
      const resp = await api.importApdnsbak(apdnsbakFile, apdnsbakPassphrase, dryRun);
      apdnsbakReport = resp.report;
      apdnsbakManifest = resp.manifest;
    } catch (err) {
      apdnsbakError = err instanceof ApiError ? err.message : String(err);
    } finally {
      apdnsbakBusy = false;
    }
  }

  function apdnsbakTotals(): { imported: number; skipped: number; rejected: number } {
    if (!apdnsbakReport) return { imported: 0, skipped: 0, rejected: 0 };
    return Object.values(apdnsbakReport.tables).reduce(
      (acc, t) => ({ imported: acc.imported + t.imported, skipped: acc.skipped + t.skipped, rejected: acc.rejected + t.rejected }),
      { imported: 0, skipped: 0, rejected: 0 },
    );
  }

  // Pi-hole / AdGuard Home import -- a different translation target from
  // everything above (blocklists + Local DNS + custom rules together,
  // not just local_dns_records), so it gets its own dry-run/apply
  // Report card (internal/filterimport) rather than the Plan/Job
  // selection workflow.
  let filterSourceType = $state<"pihole" | "adguard_yaml">("pihole");
  let filterText = $state("");
  let filterDefaultDomain = $state("");
  let filterBusy = $state(false);
  let filterError = $state("");
  let filterReport = $state<FilterImportReport | null>(null);

  async function runFilterImport(dryRun: boolean) {
    if (!filterText.trim()) return;
    filterBusy = true;
    filterError = "";
    try {
      const resp =
        filterSourceType === "pihole"
          ? await api.importPihole(filterText, filterDefaultDomain, dryRun)
          : await api.importAdGuardYAML(filterText, dryRun);
      filterReport = resp.report;
    } catch (err) {
      filterError = err instanceof ApiError ? err.message : String(err);
    } finally {
      filterBusy = false;
    }
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
          <option value="xlsx">Spreadsheet (.xlsx)</option>
        </select>
      </label>
      {#if sourceType === "zone"}
        <label>
          Default domain (used as $ORIGIN, and to qualify relative names)
          <input bind:value={defaultDomain} placeholder="example.com" required />
        </label>
      {/if}
      {#if sourceType === "xlsx"}
        <label>
          Spreadsheet file (first sheet: name, record_type, value, ttl columns)
          <input type="file" accept=".xlsx" bind:this={xlsxFileInput} onchange={() => (xlsxFile = xlsxFileInput?.files?.[0] ?? null)} aria-label="Spreadsheet file" />
        </label>
      {:else}
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
      {/if}
      <div class="actions">
        <button
          type="submit"
          disabled={previewBusy ||
            (sourceType === "xlsx" ? !xlsxFile : !sourceText.trim()) ||
            (sourceType === "zone" && !defaultDomain.trim())}
        >
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

  <h3 id="apdnsbak-import-heading">Import a V2 (.apdnsbak) appliance backup</h3>
  <p class="scope-note">
    Upload a real, portable V2 Python backup (<code>*.apdnsbak</code>, passphrase-protected) to
    import its configuration database through the same audited table set as the V1.1.1 import
    above. Only a <strong>portable (passphrase)</strong> backup can be imported here -- a "local
    mode" backup is keyed from a secret that only exists on the original appliance and cannot be
    decrypted anywhere else. <code>secrets.json</code> and TLS/DNSCrypt certificate files inside the
    archive are not imported (Go's own secrets store and certificate management are not compatible
    containers for that material).
  </p>
  <div class="card">
    <label>
      Backup file
      <input type="file" bind:this={apdnsbakFileInput} onchange={onApdnsbakFileChange} aria-label="V2 appliance backup file" accept=".apdnsbak" />
    </label>
    <label>
      Restore passphrase
      <input type="password" bind:value={apdnsbakPassphrase} autocomplete="off" />
    </label>
    <div class="actions">
      <button onclick={() => runApdnsbakImport(true)} disabled={!apdnsbakFile || apdnsbakBusy}>
        {apdnsbakBusy ? "Working…" : "Preview (dry run)"}
      </button>
      <button onclick={() => runApdnsbakImport(false)} disabled={!apdnsbakFile || apdnsbakBusy}>
        {apdnsbakBusy ? "Working…" : "Import for real"}
      </button>
    </div>
    {#if apdnsbakError}<p class="error" role="alert">{apdnsbakError}</p>{/if}
    {#if apdnsbakReport}
      {@const totals = apdnsbakTotals()}
      <p class={apdnsbakReport.dry_run ? "" : "success"} role="status">
        {apdnsbakReport.dry_run ? "Dry run -- nothing written." : "Imported for real."}
        <strong>{totals.imported}</strong> {apdnsbakReport.dry_run ? "would import" : "imported"},
        <strong>{totals.skipped}</strong> skipped, <strong>{totals.rejected}</strong> rejected.
        {#if apdnsbakReport.snapshot_filename}
          A pre-migration safety backup was saved as "{apdnsbakReport.snapshot_filename}".
        {/if}
      </p>
      {#if apdnsbakManifest}
        <p class="scope-note">
          Source: appliance {apdnsbakManifest.source_node_id || "(unknown)"}, app version
          {apdnsbakManifest.source_version || "unknown"}, created {apdnsbakManifest.created_at || "unknown"}.
        </p>
      {/if}
      <table class="plan-table">
        <thead><tr><th>Table</th><th>Source rows</th><th>Imported</th><th>Skipped</th><th>Rejected</th></tr></thead>
        <tbody>
          {#each Object.entries(apdnsbakReport.tables) as [table, summary] (table)}
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
        <p class="scope-note">{apdnsbakReport.not_migrated.join(", ")}</p>
      </details>
    {/if}
  </div>

  <h3 id="filter-import-heading">Import from Pi-hole or AdGuard Home</h3>
  <p class="scope-note">
    Pastes a real Pi-hole export (adlists.list URLs, whitelist/blacklist domains, regex lists,
    dnsmasq <code>cname=</code> lines, custom.list hosts entries) or uploads a real AdGuard Home
    <code>AdGuardHome.yaml</code> (filters, <code>user_rules</code> in common AdBlock syntax, DNS
    rewrites) and translates it across Blocklists, Local DNS, and Custom Rules together. Not built:
    allowlist-subscription filters (no Alderpoint DNS equivalent), client/group settings, and the
    live AdGuard Home API source (a real third-party device this environment cannot reach) --
    reported as explicit findings, never silently dropped.
  </p>
  <div class="card">
    <label>
      Source
      <select bind:value={filterSourceType}>
        <option value="pihole">Pi-hole export (paste)</option>
        <option value="adguard_yaml">AdGuard Home YAML</option>
      </select>
    </label>
    {#if filterSourceType === "pihole"}
      <label>
        Default domain (for bare hostnames in custom.list / cname= entries)
        <input bind:value={filterDefaultDomain} placeholder="lan" />
      </label>
    {/if}
    <textarea
      bind:value={filterText}
      placeholder={filterSourceType === "pihole"
        ? "https://example.com/hosts.txt\nblacklist ads.example.com\ncname=alias,target.lan,600"
        : "filters:\n  - name: AdGuard filter\n    url: https://example.com/filter.txt\nuser_rules:\n  - ||ads.example.com^"}
      aria-label={filterSourceType === "pihole" ? "Pi-hole export contents" : "AdGuard Home YAML contents"}
      rows="8"
    ></textarea>
    <div class="actions">
      <button onclick={() => runFilterImport(true)} disabled={!filterText.trim() || filterBusy}>
        {filterBusy ? "Working…" : "Preview (dry run)"}
      </button>
      <button onclick={() => runFilterImport(false)} disabled={!filterText.trim() || filterBusy}>
        {filterBusy ? "Working…" : "Import for real"}
      </button>
    </div>
    {#if filterError}<p class="error" role="alert">{filterError}</p>{/if}
    {#if filterReport}
      <p class={filterReport.dry_run ? "" : "success"} role="status">
        {filterReport.dry_run ? "Dry run -- nothing written." : "Imported for real."}
        <strong>{filterReport.counts.imported ?? filterReport.counts.would_import ?? 0}</strong>
        {filterReport.dry_run ? "would import" : "imported"},
        <strong>{filterReport.counts.skipped_duplicate ?? 0}</strong> skipped as duplicates,
        <strong>{filterReport.counts.failed ?? 0}</strong> failed.
      </p>
      <table class="plan-table">
        <thead><tr><th>Kind</th><th>Item</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>
          {#each filterReport.items as item, i (i)}
            <tr>
              <td>{item.kind}</td>
              <td>{item.text}</td>
              <td>{item.status}</td>
              <td>{item.detail ?? ""}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if filterReport.unsupported.length > 0}
        <details>
          <summary>Unsupported findings ({filterReport.unsupported.length})</summary>
          <ul class="parse-errors">
            {#each filterReport.unsupported as u (u)}<li>{u}</li>{/each}
          </ul>
        </details>
      {/if}
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
