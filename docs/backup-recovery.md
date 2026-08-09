# Backup and Recovery Guide

Alderpoint DNS is currently beta software (v0.4.0-beta.5). The backup/restore
paths described here are acceptance-tested, but keep independent copies of
anything important — see `docs/known-limitations.md`.

Routine backups:

- Use **System > Administration > Backup & Restore** (`/backup`) for
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
`restoring_configuration` -> `restoring_analytics`/`restoring_database` ->
`validating_database` -> `restarting_services` -> `postcheck` -> `cleanup`
-> `completed`/`failed`), each with a `heartbeat_at` timestamp and, for the
large analytics-history table, `progress_current`/`progress_total` row
counts updated between committed chunks (not per-row).

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

Two changes follow directly from that evidence:

1. **The analytics collector is now explicitly paused** (`systemctl stop
   alderpointdns-analytics`) before an analytics-history merge begins, and
   restarted afterward unconditionally (success, failure, or an exception
   during rollback) -- eliminating the write-lock race at its source
   instead of leaving it to `busy_timeout` retries.
2. **Large tables are copied in committed chunks** (200,000 rows per
   chunk, by primary-key range) instead of one multi-hour uncommitted
   transaction, so heartbeat/progress is durably visible to another
   connection (the web UI, or a startup abandoned-restore check) while a
   huge restore is still running. This is gated behind confirmation --
   not merely a request -- that the analytics collector actually stopped
   (`_wait_inactive()`): a competing-writer stress test reproduced a real
   `UNIQUE constraint` / `database is locked` failure when chunked commits
   were allowed to interleave with an active concurrent writer, which is
   exactly why that confirmation is mandatory rather than assumed. If the
   collector can't be confirmed stopped, the merge falls back to the
   original one-shot atomic path for that table -- slower to observe,
   never wrong.
3. A `PRAGMA quick_check` now runs against the live database immediately
   after a database-touching merge, before services are restarted --
   failing (and rolling back) a restore whose merge somehow left the
   database inconsistent, rather than only ever being checked
   after the fact by an administrator.

Validated locally against the real `restore_backup()` code path end to end
(this engineering host has 3.8 GiB total RAM -- not enough to spin up the
4-8 GiB disposable VM this would ideally be validated in, so this is a
same-host, no-mocked-merge-logic run instead; see the incident notes for
that caveat spelled out explicitly):

- A ~2.8M-row / 75 MiB-compressed synthetic analytics restore (smaller
  compression ratio than the original real-world 296 MiB, since synthetic
  domains/clients compress better than organic traffic, but the same row
  count) completed in seconds, not hours; destination `query_events` count
  matched the archived source count exactly (2,800,001 = 2,800,001);
  `PRAGMA quick_check` returned `ok`; `user_auth_data` (admins table) and
  other requested components restored correctly; the staging directory was
  fully cleaned up; `restore_history` recorded the real worker PID and
  reached `phase='completed'`.
- A second run intentionally `SIGKILL`ed the restore process while it was
  actively mid-`restoring_analytics` (progress `0/1500001` at kill time, a
  1.5M-row archive): the very next status read (no manual intervention)
  found it already reaped -- `status='interrupted'`, `finished_at` set, a
  message naming the dead PID, its last phase/component, and last
  heartbeat -- staging cleaned up, and the source archive left untouched.
- named/dnsdist/DNS-resolution/web-UI health were **not** exercised by
  this local run (this host has neither daemon installed) -- those need
  the real disposable-VM environment; this only proves the SQLite
  merge/lifecycle logic itself, not full-system health after a restore.

Emergency recovery:

- DNS should continue through BIND/dnsdist even if the web app is down.
- Use `systemctl status named dnsdist alderpointdns alderpointdns-analytics`.
- Use `alderpointdns-diagnostics --output-dir /tmp` for a sanitized support
  bundle.
- Use `scripts/restore.sh` only for legacy whole-archive emergencies; prefer
  the native `/backup` restore path.
