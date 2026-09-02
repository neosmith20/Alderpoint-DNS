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
  // one-time cutover import.
  let legacyFile: File | null = $state(null);
  let legacyPassword = $state("");
  let legacyBusy = $state(false);
  let legacyError = $state("");
  let legacyReport = $state<LegacyImportReport | null>(null);
  let legacyManifest = $state<LegacyImportManifest | null>(null);

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
  // report pattern as the V1.1.1 archive above, just a different source
  // format (Fernet-encrypted, passphrase-protected) and a different
  // backend package (internal/apdnsbak).
  let apdnsbakFile: File | null = $state(null);
  let apdnsbakPassphrase = $state("");
  let apdnsbakBusy = $state(false);
  let apdnsbakError = $state("");
  let apdnsbakReport = $state<LegacyImportReport | null>(null);
  let apdnsbakManifest = $state<ApdnsbakManifest | null>(null);

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

  // Alderpoint DNS Backup: previously the V1.1.1 (.tar.gz[.enc]) and V2
  // (.apdnsbak) archives were two separate cards with near-identical
  // controls and no explanation of which to pick or why "Import" even
  // exists alongside Backup & Restore. Combined into one card with one
  // file input; the backup type is detected from the uploaded filename
  // -- the same signal each backend endpoint already validates against
  // (legacyimport.IsLegacyArchiveName / the apdnsbak handler's own
  // filename check), so a wrong guess here is caught server-side too,
  // never silently misrouted. legacyFile/apdnsbakFile and their run/
  // totals functions above are unchanged and still do the real work;
  // this layer only decides which one a given upload maps to.
  type BackupKind = "legacy" | "apdnsbak" | null;
  function detectBackupKind(filename: string): BackupKind {
    const lower = filename.toLowerCase();
    if (lower.endsWith(".apdnsbak")) return "apdnsbak";
    if (lower.endsWith(".tar.gz") || lower.endsWith(".tar.gz.enc")) return "legacy";
    return null;
  }
  let combinedFile = $state<File | null>(null);
  let combinedFileInput: HTMLInputElement | undefined = $state();
  let combinedKind = $state<BackupKind>(null);
  let combinedSecret = $state("");
  function onCombinedFileChange() {
    const f = combinedFileInput?.files?.[0] ?? null;
    combinedFile = f;
    combinedKind = f ? detectBackupKind(f.name) : null;
    legacyFile = combinedKind === "legacy" ? f : null;
    apdnsbakFile = combinedKind === "apdnsbak" ? f : null;
    legacyReport = null;
    apdnsbakReport = null;
    legacyError = "";
    apdnsbakError = "";
  }
  function runCombinedImport(dryRun: boolean) {
    if (combinedKind === "legacy") {
      legacyPassword = combinedSecret;
      runLegacyImport(dryRun);
    } else if (combinedKind === "apdnsbak") {
      apdnsbakPassphrase = combinedSecret;
      runApdnsbakImport(dryRun);
    }
  }
  const combinedBusy = $derived(legacyBusy || apdnsbakBusy);
  const combinedError = $derived(combinedKind === "apdnsbak" ? apdnsbakError : legacyError);
  const combinedReport = $derived(combinedKind === "apdnsbak" ? apdnsbakReport : legacyReport);

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
    Bring data in <em>from another source</em> -- another Alderpoint DNS or V1.1.1 appliance, or a
    different product entirely (AdGuard Home, Pi-hole). This is different from
    <strong>Backup &amp; Restore</strong>, which is this appliance's own native backup lifecycle
    (back it up, restore it, on itself). Preview a source, choose what to bring in, then apply --
    with rollback available afterward where the source supports it.
  </p>

  <div class="grid-2col">
    {#if !job}
      <form class="card" onsubmit={preview}>
        <h3>Import DNS records (hosts / CSV / zone file / spreadsheet)</h3>
        <p class="hint">
          A hosts file, a simple Alderpoint CSV (name, record type, value, TTL), a BIND zone file
          (A/AAAA/CNAME/PTR, with <code>$ORIGIN</code> honored), or a spreadsheet (.xlsx).
        </p>
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
          <h3>Review &amp; select ({job.plan.rows.length} row{job.plan.rows.length === 1 ? "" : "s"})</h3>
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

    <div class="card">
      <h3 id="alderpoint-backup-import-heading">Alderpoint DNS Backup</h3>
      <p class="hint">
        Upload a real Alderpoint DNS appliance backup -- a V1.1.1
        <code>alderpointdns-backup-*.tar.gz</code> (optionally <code>.tar.gz.enc</code>) or a V2
        <code>*.apdnsbak</code> portable archive. The type is detected automatically from the
        filename. Only a <strong>portable (passphrase)</strong> V2 backup can be imported here, not
        a "local mode" one keyed from a secret that only exists on its original appliance. Always
        preview with a dry run first -- a real import has no one-click undo; a real safety backup
        of this appliance's own data is taken automatically right before it writes anything, and
        can be restored from Backup &amp; Restore if needed.
      </p>
      <label>
        Backup file
        <input
          type="file"
          bind:this={combinedFileInput}
          onchange={onCombinedFileChange}
          aria-label="Alderpoint DNS backup file"
          accept=".tar.gz,.enc,.apdnsbak"
        />
      </label>
      {#if combinedFile && !combinedKind}
        <p class="error" role="alert">
          "{combinedFile.name}" doesn't look like a recognized Alderpoint DNS backup filename --
          expected <code>alderpointdns-backup-*.tar.gz</code>, <code>.tar.gz.enc</code>, or
          <code>*.apdnsbak</code>.
        </p>
      {:else if combinedKind}
        <p class="hint">Detected: {combinedKind === "apdnsbak" ? "V2 (.apdnsbak) portable backup" : "V1.1.1 appliance backup"}</p>
      {/if}
      <label>
        Password / passphrase (only if this backup is encrypted or portable)
        <input type="password" bind:value={combinedSecret} autocomplete="off" />
      </label>
      <div class="actions">
        <button onclick={() => runCombinedImport(true)} disabled={!combinedKind || combinedBusy}>
          {combinedBusy ? "Working…" : "Preview (dry run)"}
        </button>
        <button onclick={() => runCombinedImport(false)} disabled={!combinedKind || combinedBusy}>
          {combinedBusy ? "Working…" : "Import for real"}
        </button>
      </div>
      {#if combinedError}<p class="error" role="alert">{combinedError}</p>{/if}
      {#if combinedReport}
        {@const totals = combinedKind === "apdnsbak" ? apdnsbakTotals() : legacyTotals()}
        {@const manifest = combinedKind === "apdnsbak" ? apdnsbakManifest : legacyManifest}
        <p class={combinedReport.dry_run ? "" : "success"} role="status">
          {combinedReport.dry_run ? "Dry run -- nothing written." : "Imported for real."}
          <strong>{totals.imported}</strong> {combinedReport.dry_run ? "would import" : "imported"},
          <strong>{totals.skipped}</strong> skipped, <strong>{totals.rejected}</strong> rejected.
          {#if combinedReport.snapshot_filename}
            A pre-migration safety backup was saved as "{combinedReport.snapshot_filename}".
          {/if}
        </p>
        {#if manifest}
          <p class="scope-note">
            Source: appliance {manifest.source_node_id || "(unknown)"}, app version
            {("alderpointdns_app_version" in manifest ? manifest.alderpointdns_app_version : manifest.source_version) || "unknown"},
            created {manifest.created_at || "unknown"}.
          </p>
        {/if}
        <table class="plan-table">
          <thead><tr><th>Table</th><th>Source rows</th><th>Imported</th><th>Skipped</th><th>Rejected</th></tr></thead>
          <tbody>
            {#each Object.entries(combinedReport.tables) as [table, summary] (table)}
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
          <p class="scope-note">{combinedReport.not_migrated.join(", ")}</p>
        </details>
      {/if}
    </div>

    <div class="card wide-card">
      <h3 id="filter-import-heading">Import from Pi-hole or AdGuard Home</h3>
      <p class="hint">
        Pastes a real Pi-hole export (adlists.list URLs, whitelist/blacklist domains, regex lists,
        dnsmasq <code>cname=</code> lines, custom.list hosts entries) or uploads a real AdGuard Home
        <code>AdGuardHome.yaml</code> (filters, <code>user_rules</code> in common AdBlock syntax, DNS
        rewrites) and translates it across Blocklists, Local DNS, and Custom Rules together. Not
        built: allowlist-subscription filters (no Alderpoint DNS equivalent), client/group
        settings, and the live AdGuard Home API source (a real third-party device this environment
        cannot reach) -- reported as explicit findings, never silently dropped.
      </p>
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
  </div>
</section>

<style>
  .import-view { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 60rem; }
  /* Two responsive columns on desktop/tablet, one on mobile -- previously
     every card here was pinned to max-width: 44rem and stacked full-
     height regardless of viewport width, wasting most of a wide screen. */
  .grid-2col { display: grid; grid-template-columns: repeat(auto-fit, minmax(22rem, 1fr)); gap: 1rem; align-items: start; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); box-shadow: var(--shadow); display: flex; flex-direction: column; gap: 0.6rem; }
  .card.wide-card { grid-column: 1 / -1; }
  .card h3 { margin: 0; }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .job-header { display: flex; justify-content: space-between; align-items: center; }
  textarea { font-family: monospace; font-size: 0.85rem; resize: vertical; }
  .actions { display: flex; gap: 0.6rem; }
  .error { color: var(--badge-danger-fg); }
  .success { color: var(--success); }
  .parse-errors { font-size: 0.8rem; opacity: 0.85; max-height: 8rem; overflow-y: auto; margin: 0; padding-left: 1.2rem; }
  .plan-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .plan-table th, .plan-table td { padding: 0.3rem 0.5rem; text-align: left; border-bottom: 1px solid var(--border); }
  .row-conflict { background: var(--attention-bg); }
  .badge { padding: 0.1rem 0.4rem; border-radius: 999px; font-size: 0.72rem; }
  .badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .badge-warn { background: var(--badge-warn-bg); color: var(--badge-warn-fg); }
  .danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
</style>
