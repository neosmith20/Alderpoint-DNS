<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type BackupInfo } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";

  // Backup & Restore, native Go (own format -- see internal/backup's doc
  // comment for exactly why this isn't byte-compatible with Python's
  // encrypted `.apdnsbak` or V1.1.1's `.tar.gz` yet, and what a real
  // bridge to either would need). What IS real: consistent VACUUM INTO
  // snapshots, archive-bomb size limits, upload+structural preview,
  // typed-confirmation-gated restore with a mandatory pre-restore safety
  // backup and a transactional (all-or-nothing) apply, and deletion.

  let backups = $state<BackupInfo[]>([]);
  let loadError = $state("");
  const guard = new StaleGuard();

  let createBusy = $state(false);
  let createError = $state("");

  let uploadBusy = $state(false);
  let uploadError = $state("");
  let fileInput: HTMLInputElement | undefined = $state();

  let restoreTarget = $state<string | null>(null);
  let restoreConfirmText = $state("");
  let restoreBusy = $state(false);
  let restoreError = $state("");
  let restoreResult = $state("");

  async function refresh() {
    const token = guard.start();
    try {
      const resp = await api.listBackups(router.signal());
      if (!guard.isCurrent(token)) return;
      backups = resp.backups;
      loadError = "";
    } catch (err) {
      if (!guard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof Error ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
  });

  async function createBackup() {
    createError = "";
    createBusy = true;
    try {
      await api.createBackup();
      await refresh();
    } catch (err) {
      createError = err instanceof ApiError ? err.message : String(err);
    } finally {
      createBusy = false;
    }
  }

  async function uploadFile() {
    const file = fileInput?.files?.[0];
    if (!file) return;
    uploadError = "";
    uploadBusy = true;
    try {
      await api.uploadBackup(file);
      if (fileInput) fileInput.value = "";
      await refresh();
    } catch (err) {
      uploadError = err instanceof ApiError ? err.message : String(err);
    } finally {
      uploadBusy = false;
    }
  }

  function startRestore(b: BackupInfo) {
    restoreTarget = b.filename;
    restoreConfirmText = "";
    restoreError = "";
    restoreResult = "";
  }

  async function confirmRestore(b: BackupInfo) {
    if (restoreConfirmText !== b.filename) return;
    restoreBusy = true;
    restoreError = "";
    try {
      const resp = await api.restoreBackup(b.filename);
      restoreResult = `Restored. A safety backup of the previous state was saved as "${resp.safety_backup.filename}".`;
      restoreTarget = null;
      await refresh();
    } catch (err) {
      restoreError = err instanceof ApiError ? err.message : String(err);
    } finally {
      restoreBusy = false;
    }
  }

  async function deleteBackup(b: BackupInfo) {
    await api.deleteBackup(b.filename);
    await refresh();
  }

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }

  const columns: Column<BackupInfo>[] = [
    { key: "filename", label: "Filename", sortValue: (b) => b.filename, minWidth: 20 },
    { key: "created_at", label: "Created", sortValue: (b) => b.created_at, minWidth: 14 },
    { key: "reason", label: "Reason", sortValue: (b) => b.reason ?? "", minWidth: 10 },
    { key: "size", label: "Size", sortValue: (b) => b.size_bytes, minWidth: 8 },
    { key: "actions", label: "Actions", minWidth: 18 },
  ];
</script>

<section aria-labelledby="backup-heading" class="backup">
  <h2 id="backup-heading">Backup &amp; Restore</h2>
  <p class="scope-note">
    Native Go backup format (not yet byte-compatible with Python's encrypted <code>.apdnsbak</code>
    or V1.1.1's <code>.tar.gz</code>) -- see the parity matrix. Covers this control plane's own data
    (blocklists, Local DNS, DNS Settings, Clients &amp; Access, Filters).
  </p>
  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <div class="two-col">
    <div class="card">
      <h3>Create a backup</h3>
      <button onclick={createBackup} disabled={createBusy}>{createBusy ? "Creating…" : "Create backup now"}</button>
      {#if createError}<p class="error" role="alert">{createError}</p>{/if}
    </div>

    <div class="card">
      <h3>Upload a backup</h3>
      <input type="file" bind:this={fileInput} aria-label="Backup file to upload" />
      <button onclick={uploadFile} disabled={uploadBusy}>{uploadBusy ? "Uploading…" : "Upload"}</button>
      {#if uploadError}<p class="error" role="alert">{uploadError}</p>{/if}
    </div>
  </div>

  {#if restoreResult}<p class="success" role="status">{restoreResult}</p>{/if}

  <DataGrid gridId="appliance-backups" {columns} rows={backups} rowKey={(b) => b.filename} emptyMessage="No backups yet.">
    {#snippet cell(b, colKey)}
      {#if colKey === "filename"}
        {b.filename}
      {:else if colKey === "created_at"}
        {timestampPref.format(b.created_at)}
      {:else if colKey === "reason"}
        {b.reason === "pre-restore-safety" ? "Safety (auto)" : "Manual"}
      {:else if colKey === "size"}
        {formatSize(b.size_bytes)}
      {:else if colKey === "actions"}
        <div class="actions">
          <button onclick={() => startRestore(b)}>Restore…</button>
          <button onclick={() => deleteBackup(b)}>Delete</button>
        </div>
        {#if restoreTarget === b.filename}
          <div class="restore-confirm">
            <p>
              This replaces current data (except your active session) with this backup's contents.
              A safety backup of the current state is taken automatically first. Type the filename to
              confirm:
            </p>
            <code>{b.filename}</code>
            <input bind:value={restoreConfirmText} aria-label="Type the filename to confirm restore" />
            <div class="actions">
              <button
                class="danger"
                disabled={restoreConfirmText !== b.filename || restoreBusy}
                onclick={() => confirmRestore(b)}
              >
                {restoreBusy ? "Restoring…" : "Confirm restore"}
              </button>
              <button onclick={() => (restoreTarget = null)}>Cancel</button>
            </div>
            {#if restoreError}<p class="error" role="alert">{restoreError}</p>{/if}
          </div>
        {/if}
      {/if}
    {/snippet}
  </DataGrid>
</section>

<style>
  .backup { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 44rem; }
  .two-col { display: flex; flex-wrap: wrap; gap: 1rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; flex: 1; min-width: 14rem; }
  .card h3 { margin: 0; }
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
  .success { color: #16a34a; }
  .restore-confirm { margin-top: 0.6rem; padding: 0.75rem; border-radius: 6px; background: var(--attention-bg); display: flex; flex-direction: column; gap: 0.5rem; max-width: 28rem; }
  .restore-confirm p { margin: 0; font-size: 0.85rem; }
  .danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
</style>
