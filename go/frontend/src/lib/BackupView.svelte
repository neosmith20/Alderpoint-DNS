<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type BackupInfo, type BackupCategory, type SecretBackupInfo } from "../api";
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
  let categories = $state<BackupCategory[]>([]);
  let loadError = $state("");
  const guard = new StaleGuard();

  let createBusy = $state(false);
  let createError = $state("");

  let uploadBusy = $state(false);
  let uploadError = $state("");
  let fileInput: HTMLInputElement | undefined = $state();

  let restoreTarget = $state<string | null>(null);
  let restoreConfirmText = $state("");
  // null = "full restore, every category" (the default -- and critically,
  // this must NOT depend on `categories` having finished loading yet: the
  // picker fetch is async and opening the dialog immediately after
  // creating a backup can win the race). Only becomes a concrete Set once
  // the operator actually toggles a checkbox.
  let restoreCategoryOverrides = $state<Set<string> | null>(null);
  let restoreBusy = $state(false);
  let restoreError = $state("");
  let restoreResult = $state("");

  // Secret Backups: a separate, smaller archive of just the sealed
  // provider/notification secrets (see internal/secretbackup) -- kept
  // entirely apart from the appliance-config backups above because they
  // have a different unit (individual secrets, not config tables),
  // different security handling (re-encrypted with a dedicated key
  // entirely inside apdns-hostagent, never seen as plaintext here), and
  // no selective-category restore.
  let secretBackups = $state<SecretBackupInfo[]>([]);
  let secretBackupsLoadError = $state("");
  let secretBackupsUnavailable = $state(false);
  const secretGuard = new StaleGuard();

  let secretCreateBusy = $state(false);
  let secretCreateError = $state("");

  let secretRestoreTarget = $state<string | null>(null);
  let secretRestoreOverwrite = $state(false);
  let secretRestoreBusy = $state(false);
  let secretRestoreError = $state("");
  let secretRestoreResult = $state("");

  async function refreshSecretBackups() {
    const token = secretGuard.start();
    try {
      const resp = await api.listSecretBackups(router.signal());
      if (!secretGuard.isCurrent(token)) return;
      secretBackups = resp.backups;
      secretBackupsLoadError = "";
      secretBackupsUnavailable = false;
    } catch (err) {
      if (!secretGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      if (err instanceof ApiError && err.status === 503) {
        secretBackupsUnavailable = true;
        return;
      }
      secretBackupsLoadError = err instanceof Error ? err.message : String(err);
    }
  }

  async function createSecretBackup() {
    secretCreateError = "";
    secretCreateBusy = true;
    try {
      await api.createSecretBackup();
      await refreshSecretBackups();
    } catch (err) {
      secretCreateError = err instanceof ApiError ? err.message : String(err);
    } finally {
      secretCreateBusy = false;
    }
  }

  function startSecretRestore(b: SecretBackupInfo) {
    secretRestoreTarget = b.name;
    secretRestoreOverwrite = false;
    secretRestoreError = "";
    secretRestoreResult = "";
  }

  async function confirmSecretRestore(b: SecretBackupInfo) {
    secretRestoreBusy = true;
    secretRestoreError = "";
    try {
      const resp = await api.restoreSecretBackup(b.name, secretRestoreOverwrite);
      secretRestoreResult = `Restored ${resp.restored_count} secret(s) from "${b.name}".`;
      secretRestoreTarget = null;
    } catch (err) {
      secretRestoreError = err instanceof ApiError ? err.message : String(err);
    } finally {
      secretRestoreBusy = false;
    }
  }

  async function deleteSecretBackup(b: SecretBackupInfo) {
    await api.deleteSecretBackup(b.name);
    await refreshSecretBackups();
  }

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
    refreshSecretBackups();
    api
      .listBackupCategories(router.signal())
      .then((resp) => (categories = resp.categories))
      .catch(() => {
        /* selective-restore picker degrades to "no per-category breakdown", not fatal */
      });
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
    restoreCategoryOverrides = null; // reset to "full restore" every time the dialog opens
  }

  function categoryChecked(name: string): boolean {
    return restoreCategoryOverrides === null || restoreCategoryOverrides.has(name);
  }

  function toggleRestoreCategory(name: string) {
    // First toggle from the implicit "everything checked" state: build an
    // explicit set of every *other* category, i.e. deselect just this one.
    const base = restoreCategoryOverrides ?? new Set(categories.map((c) => c.name));
    const next = new Set(base);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    restoreCategoryOverrides = next;
  }

  function categoryCount(b: BackupInfo, cat: BackupCategory): number {
    if (!b.table_counts) return 0;
    return cat.tables.reduce((sum, t) => sum + (b.table_counts?.[t] ?? 0), 0);
  }

  // Only a real, explicit "everything unchecked" (an empty non-null
  // override set) should disable the button -- not the mere absence of a
  // loaded category list, which would otherwise make the button
  // incorrectly unavailable for the entire time the async fetch is in
  // flight.
  function restoreBlockedByCategories(): boolean {
    return restoreCategoryOverrides !== null && restoreCategoryOverrides.size === 0;
  }

  async function confirmRestore(b: BackupInfo) {
    if (restoreConfirmText !== b.filename || restoreBlockedByCategories()) return;
    restoreBusy = true;
    restoreError = "";
    try {
      // null override (or one that covers every known category) means a
      // full restore -- send an empty list, which the server treats the
      // same way. Otherwise send exactly the categories still checked.
      const isFullRestore = restoreCategoryOverrides === null || restoreCategoryOverrides.size === categories.length;
      const chosen = isFullRestore ? [] : [...restoreCategoryOverrides!];
      const resp = await api.restoreBackup(b.filename, chosen);
      const scope = isFullRestore ? "Restored." : `Restored (${chosen.join(", ")} only).`;
      restoreResult = `${scope} A safety backup of the previous state was saved as "${resp.safety_backup.filename}".`;
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

  const secretColumns: Column<SecretBackupInfo>[] = [
    { key: "name", label: "Filename", sortValue: (b) => b.name, minWidth: 20 },
    { key: "created_at", label: "Created", sortValue: (b) => b.created_at, minWidth: 14 },
    { key: "secret_count", label: "Secrets", sortValue: (b) => b.secret_count, minWidth: 8 },
    { key: "size", label: "Size", sortValue: (b) => b.size_bytes, minWidth: 8 },
    { key: "actions", label: "Actions", minWidth: 18 },
  ];
</script>

<section aria-labelledby="backup-heading" class="backup">
  <h2 id="backup-heading">Backup &amp; Restore</h2>
  <p class="scope-note">
    Native Go backup format (not yet byte-compatible with Python's encrypted <code>.apdnsbak</code>
    or V1.1.1's <code>.tar.gz</code>) -- see the parity matrix. Covers this control plane's own data
    (blocklists, Local DNS, DNS Settings, Clients &amp; Access, Filters), and supports restoring just
    the categories you choose instead of everything at once.
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
              This replaces current data (except your active session) with this backup's contents,
              for the categories selected below. A safety backup of the current state is taken
              automatically first.
            </p>
            {#if categories.length > 0}
              <fieldset class="category-picker">
                <legend>Restore these categories:</legend>
                {#each categories as cat (cat.name)}
                  <label>
                    <input
                      type="checkbox"
                      checked={categoryChecked(cat.name)}
                      onchange={() => toggleRestoreCategory(cat.name)}
                    />
                    {cat.name.replaceAll("_", " ")}
                    {#if b.table_counts}<span class="count">({categoryCount(b, cat)} rows)</span>{/if}
                  </label>
                {/each}
              </fieldset>
            {/if}
            <p>Type the filename to confirm:</p>
            <code>{b.filename}</code>
            <input class="filename-confirm" bind:value={restoreConfirmText} aria-label="Type the filename to confirm restore" />
            <div class="actions">
              <button
                class="danger"
                disabled={restoreConfirmText !== b.filename || restoreBlockedByCategories() || restoreBusy}
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

  <h2 id="secret-backups-heading">Secret Backups</h2>
  <p class="scope-note">
    A separate archive of just the sealed provider/notification secrets (API tokens, webhook URLs,
    etc.) -- not appliance config. Re-encrypted with a dedicated backup key held entirely inside the
    hostagent; this web process never sees the plaintext.
  </p>

  {#if secretBackupsUnavailable}
    <p class="error" role="alert">
      Secret backups are not configured for this deployment (the hostagent socket is not set up).
    </p>
  {:else}
    {#if secretBackupsLoadError}<p class="error" role="alert">{secretBackupsLoadError}</p>{/if}
    {#if secretRestoreResult}<p class="success" role="status">{secretRestoreResult}</p>{/if}

    <div class="card" style="max-width: 20rem;">
      <h3>Create a secret backup</h3>
      <button onclick={createSecretBackup} disabled={secretCreateBusy}>
        {secretCreateBusy ? "Creating…" : "Create secret backup now"}
      </button>
      {#if secretCreateError}<p class="error" role="alert">{secretCreateError}</p>{/if}
    </div>

    <DataGrid
      gridId="secret-backups"
      columns={secretColumns}
      rows={secretBackups}
      rowKey={(b) => b.name}
      emptyMessage="No secret backups yet."
    >
      {#snippet cell(b, colKey)}
        {#if colKey === "name"}
          {b.name}
        {:else if colKey === "created_at"}
          {timestampPref.format(b.created_at)}
        {:else if colKey === "secret_count"}
          {b.secret_count}
        {:else if colKey === "size"}
          {formatSize(b.size_bytes)}
        {:else if colKey === "actions"}
          <div class="actions">
            <button onclick={() => startSecretRestore(b)}>Restore…</button>
            <button onclick={() => deleteSecretBackup(b)}>Delete</button>
          </div>
          {#if secretRestoreTarget === b.name}
            <div class="restore-confirm">
              <label>
                <input type="checkbox" bind:checked={secretRestoreOverwrite} />
                Overwrite secrets that already exist (otherwise existing secrets are left untouched)
              </label>
              <div class="actions">
                <button class="danger" disabled={secretRestoreBusy} onclick={() => confirmSecretRestore(b)}>
                  {secretRestoreBusy ? "Restoring…" : "Confirm restore"}
                </button>
                <button onclick={() => (secretRestoreTarget = null)}>Cancel</button>
              </div>
              {#if secretRestoreError}<p class="error" role="alert">{secretRestoreError}</p>{/if}
            </div>
          {/if}
        {/if}
      {/snippet}
    </DataGrid>
  {/if}
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
  .category-picker { border: 1px solid var(--border); border-radius: 6px; padding: 0.5rem 0.75rem; display: flex; flex-direction: column; gap: 0.3rem; }
  .category-picker legend { font-size: 0.8rem; opacity: 0.75; padding: 0 0.3rem; }
  .category-picker label { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; }
  .category-picker .count { opacity: 0.6; font-size: 0.8rem; }
  .danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
</style>
