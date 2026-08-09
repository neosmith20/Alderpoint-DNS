# Backup and Recovery Guide

The backup/restore paths described here are acceptance-tested, but keep
independent copies of anything important — see `docs/known-limitations.md`.

Routine backups:

- Use **Operations > Backup & Restore** (`/backup`) for
  previewable, checksummed backups. This is a dedicated workflow, separate
  from **Spreadsheet/Text Import** (`/import`) -- native `.tar.gz`/
  `.tar.gz.enc` Alderpoint DNS backups are never restored through the
  import page, and CSV/hosts/zone/Pi-hole/AdGuard data is never restored
  through the backup page.
- Keep private keys/credentials excluded unless the recovery scenario requires
  them.
- Use password encryption for backups that leave the VM.
- Scheduled backups use `alderpointdns-backup.timer`.
- Timestamps shown on this page (Backup & Restore listing, restore preview,
  Last Backup/Last Restore) display in the server's own configured local
  timezone, with a clear abbreviation/offset (e.g. "Aug 8, 2026 at 6:47 PM
  MDT") -- not UTC. This is display-only: the canonical timestamp in each
  backup's `manifest.json` and in `backup_history` stays UTC/ISO-8601, and
  restore never depends on the displayed or filename timestamp.
- A successful interactive **Create Backup** also automatically starts a
  browser download of that backup (via the same authenticated download
  route the manual **Download** button uses), in addition to -- not
  instead of -- keeping it stored and listed on the server for later
  re-download.

## Large backups and Analytics History

A long-running Alderpoint DNS install's Analytics History makes routine
backups grow over time; this is expected and supported. Migrating such a
server (e.g. onto new production DNS hardware) must never fail because of
an upload size limit tuned for spreadsheet/text data.

- Native backup uploads are **streamed to disk in ~4 MiB chunks**
  (`backup.begin_streamed_upload`), never held whole in the web process's
  memory -- a 20 MiB backup and a several-GiB backup both use the same
  bounded amount of memory to upload.
- The native backup upload limit is governed by `max_upload_mib` (default
  **4096 MiB / 4 GiB**), and the extracted/uncompressed-size ceiling by
  `max_extracted_mib` (default **16384 MiB / 16 GiB**) -- both configurable
  from the **Restore Upload Limits** panel on `/backup`, within a hard
  ceiling of 50 GiB / 200 GiB. This is a *separate* policy from the 10 MiB
  cap on the Spreadsheet/Text Import page (`app/importer.py`'s
  `MAX_UPLOAD_BYTES`), which is unaffected and unrelated.
- Free disk space is checked before an upload is accepted (and again,
  periodically, during a large streamed upload) and again before
  extraction, using the archive's actual scanned size.
- Before anything live is touched, the archive is verified to be a
  recognizable Alderpoint DNS native backup (manifest.json with the
  expected fields), checked for path traversal, symlinks, hardlinks, and
  device/fifo members, and its total extracted size is checked against the
  configured ceiling -- all before a single content byte is written to the
  extraction directory, so a compressed archive bomb cannot bypass the
  upload size limit.
- If you hit an upload limit while migrating a large, long-running server:
  raise `max_upload_mib`/`max_extracted_mib` on the *destination* server's
  Backup & Restore page first, then retry the upload.

Restore workflow:

1. Upload or select a backup from **Backup & Restore**.
2. Preview the restore -- shows when the backup was created, the source
   Alderpoint DNS version, archive size, and an Included/Not Included
   status for every component (configuration, blocklists/custom rules, DNS
   cache settings, analytics history, certificates, admin/auth data).
3. Confirm selected components.
4. Alderpoint DNS takes a safety backup before applying.
5. BIND/dnsdist configuration is validated; restored SQLite tables come
   from a consistent, checksum-verified copy.
6. Services touched by the restore are restarted.
7. DNS health checks run.
8. Failure triggers rollback to the safety backup.

### Restore lifecycle: phases, heartbeat, and abandoned-restore recovery

A restore records its progress durably in `restore_history` as it moves
through phases (`validating` -> `extracting` -> `pre_restore_backup` ->
`restoring_configuration` -> `preparing_working_db` ->
`restoring_analytics`/`restoring_database` -> `validating_database` ->
`promoting` -> `promoted` -> `restarting_services` -> `postcheck` ->
`cleanup` -> `completed`/`failed`/`promoted_recovery_required`), each with
a `heartbeat_at` timestamp and, for the large analytics-history table,
`progress_current`/`progress_total` row counts updated between committed
chunks (not per-row).

The row also records the exact worker that's doing the work: PID, that
PID's process-start time (guards against PID reuse), and the host's boot
ID (guards against a reboot). On application startup, and every time
Backup & Restore status is fetched, `reap_abandoned_restores()` checks
every `status='running'` row against this identity. A restore is only ever
reaped -- marked `interrupted`, `finished_at` set, a diagnostic message
recorded, its staging directory cleaned up -- once its recorded worker can
no longer be found alive. Elapsed time alone never triggers this: a
genuinely long-running restore whose worker is still alive is left
running no matter how long it's been, by design (`heartbeat_at` age is
surfaced to the UI as "may be stuck" only, never used to fail a restore
outright). Cleanup only ever removes the specific staging subdirectory
recorded for that restore, and refuses to act on anything that isn't
strictly inside `STAGING_DIR` -- the uploaded archive and the pre-restore
safety backup (both in `BACKUP_DIR`) are never touched by it.
`pre_restore_backup_path` is itself written to the row as soon as that
backup exists (not only in the restore's final update), so it's always
discoverable even from a row that was reaped mid-restore.

`promoted_at` is the authoritative "point of no return" marker (see the
staged/atomic-promotion architecture immediately below): NULL means the
live database was never touched by this restore attempt, no matter what
else it did; once set, the live database's data changes have already
committed. `reap_abandoned_restores()` treats these very differently --
see below.

### Staged/atomic-promotion database restore

The database side of a restore never writes to the live database file
directly. All of the expensive work -- extracting, merging potentially
millions of archived rows, validating -- happens against a private
**working copy**; the live database is only ever touched by one brief,
already-fully-validated **promotion** step at the very end. A restore
interrupted at any point before that step leaves the live database
completely untouched, because nothing was ever written to it -- there is
nothing to roll back. A restore interrupted during or after that step has
already committed its (already-validated) database changes.

1. The usual pre-restore safety backup is taken first, as always.
2. A private working copy of the live database is created with SQLite's
   own online backup API (`Connection.backup()`, the same mechanism
   `sqlite_backup_copy()` uses for regular backup creation) -- safe
   against a live, concurrently-written WAL-mode database, unlike a raw
   file copy.
3. Every selected table is merged from the backup archive into that
   working copy -- never the live db -- in independently committed chunks
   (200,000 rows per chunk, by primary-key range) for real progress on
   large tables. This is now unconditionally safe regardless of any other
   process writing to the *live* database, because nothing else can see
   or write to a private working copy in the first place -- the earlier
   "confirmed collector stop" gate this replaced existed only because an
   earlier version of this code chunked directly against the live
   database.
4. `PRAGMA quick_check` runs against the working copy. A failure here
   raises before anything live is ever touched.
5. Only once the working copy is fully valid: every other database writer
   is quiesced, the *current* live state of every table not touched by
   the merge (excluded/unselected components, and this restore's own
   bookkeeping tables, which are always excluded from the archive merge
   itself) is copied into the working copy -- closing the gap between
   when the working copy was snapshotted and now -- both databases are
   checkpointed to a single file with no outstanding WAL, and the working
   copy atomically replaces the live file via a plain filesystem rename
   (`os.replace`, atomic on the same filesystem: any process opening the
   path mid-rename gets either the fully-old or fully-new file, never a
   torn mix).
6. Services are restarted and DNS is health-checked as before.

**Writer quiescing, and why it isn't `systemctl stop alderpointdns`:**
Every real writer of this database -- the web app, the analytics
collector, and every scheduled backup/filter-update/notify/
software-update-check timer job -- opens a fresh SQLite connection per
operation rather than holding one open (see `app/webapp.py`'s `db()`), so
`PRAGMA locking_mode=EXCLUSIVE` on a dedicated connection (retried with
backoff) is sufficient to guarantee exclusivity for the brief promotion
window, uniformly, without having to enumerate every writer individually.
This includes closing the restore's own bookkeeping connection first: WAL
mode's exclusive locking requires being the *only* open connection to the
file, even the restore's own idle one. `alderpointdns-analytics.service`
is still explicitly stopped as a courtesy beforehand (cutting down on
wasted retries -- it's a separate systemd unit, safe to stop from here),
but correctness never depends on that succeeding. `alderpointdns.service`
itself is deliberately *never* stopped via `systemctl` for this: restores
run as (or as a descendant of) that very service's sudo-escalated
privileged helper, and systemd's default `KillMode=control-group` would
send a stop's `SIGTERM` to the restore's own process too.

**Post-promotion failure never fakes a rollback.** If service restart or
the final DNS postcheck fails *after* promotion has already committed,
`restore_backup()` does not attempt to revert the database: it was only
ever promoted after passing `PRAGMA quick_check`, so a later, unrelated
failure is a service/health-recovery situation, not a data-integrity one,
and automatically reverting an already-valid database would itself be the
riskier action. The restore is marked `promoted_recovery_required` (never
left `running`), service restarts are attempted automatically, and the
message names the pre-restore safety backup's path for manual recovery if
that's genuinely what's needed. `reap_abandoned_restores()` applies the
same distinction to a promoted-but-then-killed worker: `promoted_at` set
means the reap message says so explicitly and also attempts the same
best-effort service restart, rather than the generic "safe to retry"
message it gives an abandoned restore that never reached promotion.

### Large analytics restore: what was actually slow, and the fix

An earlier disposable-VM validation pass hit a ~296 MiB / 2.8M-row
Analytics History restore that ran for **over 10 hours** without ever
finishing, on a severely memory-constrained (2 GiB RAM) sandbox VM, and
was eventually terminated externally with the restore's own state stuck
at `status='running'` forever -- the exact scenario the lifecycle tracking
above now detects and recovers from automatically.

Forensic recovery of that VM's disk (see the incident notes) plus direct
profiling of the real `_merge_database()` merge code against synthetic
2.8M-row data on comparable hardware established, with evidence rather
than assumption:

- The merge itself (`ATTACH` + `INSERT INTO ... SELECT` from the archived
  copy) is **not** algorithmically slow: `EXPLAIN QUERY PLAN` shows a
  plain table scan (no missing-index lookups), and profiling measured
  roughly 18,000-40,000+ rows/sec depending on commit strategy -- a
  2.8M-row table merges in well under three minutes on unconstrained
  hardware.
- Deliberately constraining the same operation to a 200 MiB memory
  cgroup (with swap available) reproduced a dramatic, multi-hundred-times
  slowdown -- still incomplete and eventually OOM-killed after nearly six
  minutes, versus ~67 seconds unconstrained for the exact same merge. This
  is strong, directly-reproduced evidence that **severe memory/swap
  pressure in that specific sandbox, not a defect in the merge algorithm,
  was the dominant real-world cause** of the multi-hour hang.
- Separately, and confirmed by the forensic VM's own logs (a live
  `sqlite3.OperationalError: database is locked` from the analytics
  collector's poll thread), the restore's SQLite write transaction and the
  live analytics collector's own writer were racing for the same file's
  single write lock.

That evidence originally motivated two narrower fixes (pausing the
analytics collector around a live-database merge, and gating chunked
commits behind a *confirmed* collector stop before they were safe). Both
are superseded by the staged/atomic-promotion architecture described
above: the merge no longer touches the live database at all, so chunked
commits are unconditionally safe regardless of what else is writing to
the live db, and `PRAGMA quick_check` now runs against the working copy
*before* anything live is touched, rather than against the live database
after the fact. The analytics collector is still stopped as a courtesy
during promotion (see "Writer quiescing" above), but that's an
optimization now, not a correctness requirement.

Validated locally against the real, staged `restore_backup()` code path
end to end (this engineering host has 3.8 GiB total RAM -- not enough to
spin up the 4-8 GiB disposable VM this would ideally be validated in, so
this is a same-host, no-mocked-merge-logic run instead; see the incident
notes for that caveat spelled out explicitly):

- A real ~2.8M-row analytics restore (32 MiB compressed archive; smaller
  than the original 296 MiB real-world archive since synthetic
  domains/clients compress better than organic traffic, but the same row
  count) completed in **7.0 seconds total**, with the actual live-database
  **promotion window measured at ~0.09 seconds** -- extraction, the
  pre-restore safety backup, and file components together took ~1.9s;
  creating the working copy plus merging all 2.8M rows into it together
  took ~4.2s (roughly 666,000 rows/sec for that combined phase, working
  entirely against the private copy); `PRAGMA quick_check` took ~0.8s.
  Destination `query_events` count matched the archive's source count
  **exactly** (2,800,000 = 2,800,000); `PRAGMA quick_check` returned `ok`;
  `promoted_at` was recorded; peak RSS for the whole restore was ~36 MiB;
  the staging directory (including the working copy) was fully cleaned up.
- Three separate real `SIGKILL` interruption tests, each proving the live
  database is byte-for-byte/row-for-row unaffected by a kill before
  promotion, and correctly reflects the promoted content after one:
  - **Mid-chunked-merge into the working copy** (a 250,001-row table,
    killed mid-chunk): live database proven **byte-identical** before and
    after the kill; the next status read reaped it as `interrupted`,
    `promoted_at` NULL, staging cleaned, source archive retained.
  - **Immediately before promotion** (working copy fully merged and
    validated, killed right before the exclusive lock is acquired): same
    result -- live database untouched, `promoted_at` NULL.
  - **Immediately after promotion, before postcheck** (killed right after
    the atomic swap committed): reaped as `interrupted` with `promoted_at`
    **set**, the message explicitly stating the swap had already
    committed, and a best-effort restart of `alderpointdns`/
    `alderpointdns-analytics` attempted automatically since a
    promoted-but-interrupted restore may have left them stopped; the
    pre-restore safety backup remained present and discoverable from the
    row (a real bug found and fixed by this exact test: that path wasn't
    recorded until a restore's *final* update, so a worker killed before
    reaching it left the row unable to point at its own safety backup even
    though the backup file existed all along).
- named/dnsdist/DNS-resolution/web-UI health were **not** exercised by
  this local run (this host has neither daemon installed) -- those need
  the real disposable-VM environment; this only proves the SQLite
  merge/lifecycle/promotion logic itself, not full-system health after a
  restore.

Emergency recovery:

- DNS should continue through BIND/dnsdist even if the web app is down.
- Use `systemctl status named dnsdist alderpointdns alderpointdns-analytics`.
- Use `alderpointdns-diagnostics --output-dir /tmp` for a sanitized support
  bundle.
- Use `scripts/restore.sh` only for legacy whole-archive emergencies; prefer
  the native `/backup` restore path.
