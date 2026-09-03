<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type BackupInfo, type BackupCategory, type SecretBackupInfo, type BackupScheduleSettings } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";
  import { toast } from "../toast.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";

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
  // Passphrase protection (2026-08-29): opt-in, defaulting to unchecked
  // -- matching V1.1.1's own optional password protection default and
  // this format's historical unencrypted-only behavior, so an owner who
  // never notices the checkbox gets the same result as before. Left
  // unchecked, a real warning renders (see the markup below) rather than
  // silently exporting admin password hashes in the clear with no
  // indication anything is unprotected.
  let createEncrypt = $state(false);
  let createPassphrase = $state("");
  let createPassphraseConfirm = $state("");

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
  // Passphrase-gated preview (2026-08-29): for an encrypted backup, the
  // real manifest (table counts, real category contents) is unreadable
  // until the correct passphrase is given -- restoreUnlocked holds the
  // real BackupInfo once that's happened (or immediately, for an
  // already-unencrypted row); restorePassphrase/restorePassphraseError
  // drive the "enter passphrase to preview" sub-step gating it.
  let restorePassphrase = $state("");
  let restorePassphraseError = $state("");
  let restorePassphraseBusy = $state(false);
  let restoreUnlocked = $state<BackupInfo | null>(null);

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

  let confirmDeleteSecretBackup = $state<SecretBackupInfo | null>(null);

  function deleteSecretBackup(b: SecretBackupInfo) {
    confirmDeleteSecretBackup = b;
  }

  async function runDeleteSecretBackup() {
    const b = confirmDeleteSecretBackup;
    confirmDeleteSecretBackup = null;
    if (!b) return;
    await api.deleteSecretBackup(b.name);
    await refreshSecretBackups();
    toast.success(`Deleted secret backup "${b.name}".`);
  }

  // Scheduled Backups -- owner-configurable periodic backups, field-matched
  // against V1.1.1's own real settings (schedule_enabled/schedule_interval_hours/
  // retention_count) but run by this control plane's own in-process scheduler
  // (see internal/backup/schedule.go's doc comment for why) rather than a
  // systemd timer. This is also what makes the backup_failure notification
  // category real: there's now a periodic background action for it to observe.
  let schedule = $state<BackupScheduleSettings | null>(null);
  let scheduleLoadError = $state("");
  let scheduleEnabled = $state(false);
  let scheduleIntervalHours = $state(24);
  let scheduleRetentionCount = $state(7);
  let scheduleSaveBusy = $state(false);
  let scheduleSaveError = $state("");

  async function refreshSchedule() {
    try {
      const s = await api.getBackupSchedule(router.signal());
      schedule = s;
      scheduleEnabled = s.enabled;
      scheduleIntervalHours = s.interval_hours;
      scheduleRetentionCount = s.retention_count;
      scheduleLoadError = "";
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      scheduleLoadError = err instanceof Error ? err.message : String(err);
    }
  }

  async function saveSchedule() {
    scheduleSaveError = "";
    scheduleSaveBusy = true;
    try {
      schedule = await api.setBackupSchedule({
        enabled: scheduleEnabled,
        interval_hours: scheduleIntervalHours,
        retention_count: scheduleRetentionCount,
      });
      toast.success("Backup schedule saved.");
    } catch (err) {
      scheduleSaveError = err instanceof ApiError ? err.message : String(err);
    } finally {
      scheduleSaveBusy = false;
    }
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
    refreshSchedule();
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
    if (createEncrypt) {
      if (createPassphrase.length < 8) {
        createError = "Passphrase must be at least 8 characters.";
        return;
      }
      if (createPassphrase !== createPassphraseConfirm) {
        createError = "Passphrases do not match.";
        return;
      }
    }
    createBusy = true;
    try {
      await api.createBackup(createEncrypt ? createPassphrase : undefined);
      createPassphrase = "";
      createPassphraseConfirm = "";
      toast.success(createEncrypt ? "Encrypted backup created." : "Backup created.");
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
    restorePassphrase = "";
    restorePassphraseError = "";
    // An already-unencrypted row already carries its own real manifest
    // (List returns full detail for those) -- only an encrypted row
    // needs the separate "unlock" sub-step below before the real
    // category picker has anything real to show.
    restoreUnlocked = b.encrypted ? null : b;
  }

  async function unlockRestore(b: BackupInfo) {
    restorePassphraseError = "";
    restorePassphraseBusy = true;
    try {
      restoreUnlocked = await api.previewBackup(b.filename, restorePassphrase);
    } catch (err) {
      restorePassphraseError =
        err instanceof ApiError && err.code === "wrong_passphrase" ? "Wrong passphrase." : err instanceof ApiError ? err.message : String(err);
    } finally {
      restorePassphraseBusy = false;
    }
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
      const resp = await api.restoreBackup(b.filename, chosen, b.encrypted ? restorePassphrase : undefined);
      const scope = isFullRestore ? "Restored." : `Restored (${chosen.join(", ")} only).`;
      restoreResult = `${scope} A safety backup of the previous state was saved as "${resp.safety_backup.filename}".`;
      restoreTarget = null;
      toast.success("Restore complete.");
      await refresh();
    } catch (err) {
      restoreError = err instanceof ApiError ? err.message : String(err);
    } finally {
      restoreBusy = false;
    }
  }

  let confirmDeleteBackup = $state<BackupInfo | null>(null);

  function deleteBackup(b: BackupInfo) {
    confirmDeleteBackup = b;
  }

  async function runDeleteBackup() {
    const b = confirmDeleteBackup;
    confirmDeleteBackup = null;
    if (!b) return;
    await api.deleteBackup(b.filename);
    await refresh();
    toast.success(`Deleted "${b.filename}".`);
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
    Covers this appliance's own data (blocklists, Local DNS, DNS Settings, Clients &amp; Access,
    Filters), and supports restoring just the categories you choose instead of everything at once.
    Backups can optionally be protected with a passphrase (see the checkbox below).
    <strong>An unprotected backup is not encrypted</strong> -- anyone with the downloaded file can
    read its contents, including admin account password hashes -- so store downloaded backups
    somewhere you trust, or protect them with a passphrase.
  </p>
  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <div class="two-col">
    <div class="card">
      <h3>Create a backup</h3>
      <label class="schedule-row">
        <input type="checkbox" class="encrypt-toggle" bind:checked={createEncrypt} />
        Protect this backup with a passphrase
      </label>
      {#if createEncrypt}
        <input
          type="password"
          bind:value={createPassphrase}
          placeholder="Passphrase (min. 8 characters)"
          aria-label="Backup passphrase"
          autocomplete="new-password"
        />
        <input
          type="password"
          bind:value={createPassphraseConfirm}
          placeholder="Confirm passphrase"
          aria-label="Confirm backup passphrase"
          autocomplete="new-password"
        />
        <p class="hint">
          Keep this passphrase somewhere safe -- it is never stored anywhere, and a backup cannot be
          previewed or restored without it, not even by an administrator.
        </p>
      {:else}
        <p class="warning" role="alert">
          ⚠ This backup will NOT be encrypted. It will include admin account password hashes and every
          managed client/network's identifying data in the clear.
        </p>
      {/if}
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

  <div class="card schedule-card">
    <h3>Scheduled backups</h3>
    {#if scheduleLoadError}<p class="error" role="alert">{scheduleLoadError}</p>{/if}
    <label class="schedule-row">
      <input type="checkbox" bind:checked={scheduleEnabled} />
      Automatically create a backup on a schedule
    </label>
    <label class="schedule-row">
      Every
      <input
        type="number"
        min="1"
        max="720"
        bind:value={scheduleIntervalHours}
        disabled={!scheduleEnabled}
        aria-label="Backup interval in hours"
      />
      hours
    </label>
    <label class="schedule-row">
      Keep the most recent
      <input
        type="number"
        min="0"
        max="100"
        bind:value={scheduleRetentionCount}
        disabled={!scheduleEnabled}
        aria-label="Number of scheduled backups to retain"
      />
      scheduled backups
    </label>
    <button onclick={saveSchedule} disabled={scheduleSaveBusy}>{scheduleSaveBusy ? "Saving…" : "Save schedule"}</button>
    {#if scheduleSaveError}<p class="error" role="alert">{scheduleSaveError}</p>{/if}
    {#if schedule?.last_run_at}
      <p class="schedule-status">
        Last scheduled run: {timestampPref.format(schedule.last_run_at)} --
        <span class={schedule.last_status === "failed" ? "error" : "success"}>{schedule.last_status}</span>
        {#if schedule.last_status === "failed" && schedule.last_error}({schedule.last_error}){/if}
      </p>
    {:else if schedule?.enabled}
      <p class="schedule-status">Enabled -- no scheduled run yet.</p>
    {/if}
  </div>

  {#if restoreResult}<p class="success" role="status">{restoreResult}</p>{/if}

  <DataGrid gridId="appliance-backups" {columns} rows={backups} rowKey={(b) => b.filename} emptyMessage="No backups yet.">
    {#snippet cell(b, colKey)}
      {#if colKey === "filename"}
        {b.filename}
        {#if b.encrypted}<span class="lock-badge" title="Passphrase-protected">🔒 Encrypted</span>{/if}
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
            {#if b.encrypted && !restoreUnlocked}
              <p>This backup is passphrase-protected. Enter the passphrase to preview its real contents before restoring.</p>
              <input
                type="password"
                bind:value={restorePassphrase}
                placeholder="Backup passphrase"
                aria-label="Enter the backup's passphrase"
                autocomplete="current-password"
              />
              <div class="actions">
                <button disabled={!restorePassphrase || restorePassphraseBusy} onclick={() => unlockRestore(b)}>
                  {restorePassphraseBusy ? "Checking…" : "Unlock"}
                </button>
                <button onclick={() => (restoreTarget = null)}>Cancel</button>
              </div>
              {#if restorePassphraseError}<p class="error" role="alert">{restorePassphraseError}</p>{/if}
            {:else}
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
                      {#if restoreUnlocked?.table_counts}<span class="count">({categoryCount(restoreUnlocked, cat)} rows)</span>{/if}
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
            {/if}
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

{#if confirmDeleteBackup}
  <ConfirmDialog
    title="Delete backup"
    message={`Delete "${confirmDeleteBackup.filename}"? This cannot be undone.`}
    confirmLabel="Delete"
    onConfirm={runDeleteBackup}
    onCancel={() => (confirmDeleteBackup = null)}
  />
{/if}

{#if confirmDeleteSecretBackup}
  <ConfirmDialog
    title="Delete secret backup"
    message={`Delete "${confirmDeleteSecretBackup.name}"? This cannot be undone.`}
    confirmLabel="Delete"
    onConfirm={runDeleteSecretBackup}
    onCancel={() => (confirmDeleteSecretBackup = null)}
  />
{/if}

<style>
  .backup { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 44rem; }
  .two-col { display: flex; flex-wrap: wrap; gap: 1rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; flex: 1; min-width: 14rem; }
  .card h3 { margin: 0; }
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
  .error { color: var(--badge-danger-fg); }
  .success { color: var(--success); }
  .warning { color: var(--badge-danger-fg); font-size: 0.85rem; margin: 0; }
  .hint { font-size: 0.8rem; opacity: 0.75; margin: 0; }
  .lock-badge { margin-left: 0.5rem; font-size: 0.78rem; opacity: 0.8; }
  .restore-confirm { margin-top: 0.6rem; padding: 0.75rem; border-radius: 6px; background: var(--attention-bg); display: flex; flex-direction: column; gap: 0.5rem; max-width: 28rem; }
  .restore-confirm p { margin: 0; font-size: 0.85rem; }
  .category-picker { border: 1px solid var(--border); border-radius: 6px; padding: 0.5rem 0.75rem; display: flex; flex-direction: column; gap: 0.3rem; }
  .category-picker legend { font-size: 0.8rem; opacity: 0.75; padding: 0 0.3rem; }
  .category-picker label { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; }
  .category-picker .count { opacity: 0.6; font-size: 0.8rem; }
  .danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
  .schedule-card { max-width: 28rem; }
  .schedule-row { display: flex; align-items: center; gap: 0.4rem; font-size: 0.9rem; }
  .schedule-row input[type="number"] { width: 5rem; }
  .schedule-status { font-size: 0.85rem; opacity: 0.85; margin: 0; }
</style>
