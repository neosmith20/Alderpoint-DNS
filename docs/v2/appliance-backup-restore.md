# Full appliance backup/restore (beta-rescue priority 3)

## What this replaces

RC43's `/api/backup/secrets` was real (encrypted, integrity-checked) but
covered secrets only, and the UI presented it as "the backup feature."
This adds `/api/backup/appliance`: a real whole-appliance backup, with
the secrets-only backup preserved as one still-useful component, not the
whole feature.

## Contents

One encrypted archive (`app/v2/backup_restore.py`):

- **control.db**, via SQLite's own online backup API (`Connection.
  backup()`) for a real consistent snapshot, not a raw file copy that
  could tear against a concurrent writer. This alone covers: desired
  configuration, clients/groups/networks, policy assignments, filtering
  (service definitions/rulesets), Local DNS, upstream profiles, domain
  routing/fallback, schedules, DNS-transport/encryption settings,
  notification configuration, and replication peer/identity metadata --
  everything currently modeled in control.db.
- **protected secrets** (notification provider tokens, the replication
  client key, etc.), via the existing audited `secret_store`/
  `secret_backup` primitives.
- **HTTPS and DNSCrypt certificate/key material**, when present.

## Explicit policy: raw query history

Excluded, architecturally rather than by a flag: `app/v2/control_db.py`'s
own schema guard (`_assert_no_forbidden_tables`) refuses to let raw
query-history tables exist in control.db at all, and this module never
reads anything outside control.db + the secrets store + cert files. There
is no code path by which raw query history could end up in a backup.
Analytics *configuration* (e.g. DNS-transport settings that affect what
gets logged) is included because it lives in control.db; the raw query
data itself (vendor-runtime-v2-analytics' separate parquet/duckdb store)
is not.

## Restore safety

Staged: decrypt -> untar -> validate (archive member allowlist only, no
path-traversal extraction; the staged control.db is opened read-only and
checked for its core tables) all happen in an isolated scratch directory
before anything about the live appliance changes.

Promotion snapshots the *current* live control.db/secrets/certs into a
rollback directory before any atomic swap, and rolls every already-
swapped piece back if a later piece fails -- "a failed restore must leave
the prior valid appliance operational" is enforced structurally: proven
in `tests/v2/test_backup_restore.py::TestApplianceBackupApiRoutes::
test_a_failed_restore_leaves_the_prior_appliance_operational` with a
real corrupted archive that decrypts fine but fails staging.

After a successful promotion, the webapp recompiles/promotes the runtime
against the restored control.db (`_mutate_and_promote`) so the restored
state is actually live, not just present on disk.

Restore-job bookkeeping is itself stored in control.db, which a
successful restore replaces -- so the "succeeded" record is written
*after* promotion, into the now-current (just-restored) database, not
UPDATEd against a row id that no longer exists there. (A real defect
found and fixed while proving this end-to-end: an earlier version
recorded "running" before staging and tried to UPDATE it by id
afterward, which silently vanished on a successful restore.)

## Proof

- `tests/v2/test_backup_restore.py`: create/validate, wrong-key and
  tampered-archive detection, path-traversal-resistant staging, a
  corrupted-archive failed restore that leaves the prior control.db
  completely untouched, real HTTP-route coverage, and
  `TestRealRuntimeProof`: backup -> mutate the live control.db -> restore
  -> the exact `runtime_compile.build_bindings` +
  `compile_multi_policy_dnsdist_config` the live webapp uses -> a real
  `dnsdist` process -> a real DNS query proving the restored (pre-
  mutation) Local DNS record resolves and the post-backup mutation does
  not.
- `tests/v2/browser/chromium_ui_harness.js`: a full backup -> mutate ->
  restore workflow driven entirely through the UI, asserting the
  post-backup mutation does not survive the restore.
