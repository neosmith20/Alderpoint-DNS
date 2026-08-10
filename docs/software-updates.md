# Software Updates

**System > Software Updates** (`/system/administration/software-updates`)
discovers, validates, and installs newer Alderpoint DNS Debian packages, either
from GitHub Releases or a manually uploaded `.deb`. This document describes
the architecture; see `docs/versioning.md` for the version model it depends on.

## Scope

Software Updates manages **dpkg-installed** Alderpoint DNS installations
only. A source checkout with no dpkg-owned `alderpointdns` package shows
"Software Updates: unmanaged source installation" and every install action
is refused -- it never attempts to silently convert a source install into a
package install.

## Privilege model

Matches `app/network_config.py` and `app/backup.py`: the unprivileged web
process (`alderpointdns` user) never runs `apt`/`dpkg` itself. It only
validates a request and writes a row to `software_update_jobs`.

- **Checking** is safe to run directly via `sudo alderpointdns_compiler.py
  update-check` from an HTTP request -- it only reads from GitHub and
  writes to `software_update_settings`, and never restarts anything.
- **Installing** restarts `alderpointdns.service` -- the web process's own
  service -- partway through (via the package's `postinst`). A `sudo`
  child of the HTTP request handling that install would be killed along
  with the rest of that service's process tree when it restarts. Instead,
  the web process asks `sudo systemctl start --no-block
  alderpointdns-software-update.service` to hand the work to a wholly
  independent systemd unit (its own cgroup, owned by PID 1), which execs
  `alderpointdns_compiler.py update-run` as root and survives
  `alderpointdns.service` being restarted or killed out from under it. The
  web request returns immediately; the browser polls durable job state.

Both entry points are fixed, argument-free sudoers lines -- no arbitrary
command, path, or URL from the web process is ever passed to `sudo`.

## Durable job state

`software_update_jobs` (one row per check-for-updates-triggered or manual
install) and `software_update_events` (an append-only phase/message log)
live in the same SQLite database as everything else. Phases:

```
pending -> checking -> downloading -> validating -> backing_up ->
simulating -> installing -> restarting -> postcheck -> completed | failed
```

Because `alderpointdns-software-update.service` is an independent unit,
`alderpointdns.service` restarting mid-install does not interrupt it. The
browser reconnects (or the administrator reloads the page later) and reads
job state from the database -- never from the process that started it. The
Software Updates page auto-refreshes its job panel every 3 seconds while a
job is in a non-terminal phase (via the same `data-refresh-url` fragment
mechanism `/system/logs` already uses).

### Abandoned-job recovery

If the runner itself dies (host reboot, OOM, `systemctl stop`) while a job
is in a non-terminal phase, `software_updates.reap_abandoned_jobs()` --
mirroring `app/backup.py`'s `reap_abandoned_restores()` worker-identity
design exactly (a recorded `(pid, process-start-ticks, boot-id)` triple, not
a wall-clock timeout) -- fails that job with a diagnostic message instead of
leaving it stuck forever. This matters beyond the UI: the install/upload
routes refuse to start a new job while an existing one is in a non-terminal
phase (`"an update is already in progress"`), so an unreaped abandoned job
would otherwise permanently block every future update attempt. Reaping runs
on application startup and on every `update_status()` call (i.e. every time
the Software Updates page or its job-status fragment is loaded), so an
abandoned job is caught promptly either way.

A job reaped before it reached the `installing` phase made no package
changes and is reported as safe to retry. One reaped from `installing`
onward is reported as package-state-uncertain (apt-get may have partially
run) -- an administrator should confirm actual installed state
(`dpkg -l alderpointdns`, `systemctl status`) before assuming either
outcome; no automatic package rollback is attempted here either.

## GitHub release discovery

No release tag, `.deb` filename, beta number, or asset URL is ever
hardcoded -- every one of those is read from the GitHub Releases API
response for the configured repository (`software_update_settings.github_repo`,
defaulting to the project's own repo).

- **Stable channel**: non-draft, non-prerelease releases only.
- **Prerelease channel**: non-draft releases (prerelease or not).
- Malformed tags (anything that doesn't parse as SemVer) are skipped, not
  guessed at.
- Candidates are SemVer-sorted (`software_updates.compare_semver()`); the
  winner must be strictly newer than the resolved installed version
  (`backup.version_source_status()["resolved"]`) -- never a downgrade,
  never "the same version".
- Exactly one compatible `.deb` asset (`alderpointdns_<ver>_<all|amd64>.deb`)
  and exactly one `SHA256SUMS` asset are required; zero or more than one of
  either is rejected as missing/ambiguous.

## Private repository credential

The GitHub repository is currently private. An optional credential lives at
`/etc/alderpointdns/software-updates.env` (root-owned, mode 0600,
`GITHUB_TOKEN=...`), created directly on the server by an administrator --
never through the web UI. It is:

- read only by the privileged (root) update-check/update-run paths,
- refused entirely (treated as "not configured", not read) if the file's
  ownership/permissions are ever looser than root-only,
- never rendered in any template, sent to browser JS, or written to
  diagnostics/logs -- `software_updates.redact()` strips both
  `Authorization:` headers and the literal configured token value from any
  text before it is stored or logged, and `_diagnostics_merge()` applies
  it unconditionally to every diagnostics write, not only at each call
  site.

When the repository is later made public, no credential is required and
`software_update_settings.github_repo` needs no change.

## Validation pipeline (both GitHub and manual updates)

1. Download (or accept the uploaded) `.deb` and its checksum.
2. Verify SHA-256 (against the release's `SHA256SUMS` for a GitHub update;
   against an administrator-supplied checksum, or an automatically
   fetched official `SHA256SUMS` if the uploaded package's version
   matches a real release and GitHub is reachable, for a manual upload).
3. `dpkg-deb -f` inspection: `Package` must be exactly `alderpointdns`;
   `Architecture` must be `all` or `amd64`; for a GitHub update, `Version`
   must correspond to the release tag (`source_version_to_deb_form()`).
4. `dpkg --compare-versions candidate gt installed` -- reject same-version
   and downgrade attempts. (Release/channel ranking above uses SemVer
   comparison; this step uses `dpkg --compare-versions`, the exact
   comparison `apt`/`dpkg` will perform -- see `docs/versioning.md` for
   why these stay separate.)
5. **Mandatory pre-upgrade backup** via the existing native backup
   infrastructure (`backup.create_backup(purpose="pre_upgrade", ...)`).
   If it fails, the update **aborts** -- no `apt` operation is attempted,
   and there is no "install anyway" override. The backup is retained
   regardless of what happens afterward (a failed update never deletes
   it), and normal backup retention pruning never runs against it (only
   the scheduled-backup CLI path calls `prune_backups()`).
6. `apt-get install -s -y <path>` (simulation). Any simulated removal of a
   critical package (`alderpointdns`, `bind9`, `dnsdist`, ...) aborts.
7. `apt-get install -y <path>` (the real install). `postinst` runs
   normally -- schema migrations, the unconditional service restarts,
   etc. -- exactly as a manual `apt install` would.
8. Post-upgrade health check: all four services active, `PRAGMA
   quick_check`, ordinary DNS resolution, the web app's own `/healthz`
   responding locally, and the installed dpkg version matching what was
   expected. A failed health check fails the job (the pre-upgrade backup
   is retained) -- Software Updates does not claim automatic package
   rollback.

## Manual `.deb` upload

A fallback, not a separate updater: the uploaded file is streamed to a
bounded-memory, restrictive-permission staging file (`UPLOAD_CHUNK_BYTES`
= 4 MiB chunks, confined to a fixed staging directory regardless of the
uploaded filename) and then fed into the exact same job/validation/install
pipeline above via `software_update_jobs.operation = 'manual'`.

## Update checking vs. installing

- **Automatic checking** is on by default
  (`software_update_settings.auto_check_enabled`), driven by
  `alderpointdns-software-update-check.timer` (root, reads the optional
  credential). The timer only ever execs `update-check` -- never
  `update-run` -- so a scheduled firing can physically never install
  anything, only record whether an update is available.
- **The cadence is operator-controlled**
  (`software_update_settings.check_interval_hours`, 1-168, default 6) and
  actually drives the timer: saving Software Updates' settings calls
  `software_updates.deploy_check_schedule()` (root, via the fixed,
  argument-free `update-check-schedule-deploy` sudoers entry), which
  renders a systemd drop-in
  (`/etc/systemd/system/alderpointdns-software-update-check.timer.d/alderpointdns.conf`)
  from the stored interval and reloads/re-enables the timer -- exactly
  `app/filter_schedule.py`'s drop-in mechanism, reused rather than
  reinvented. The stored value is always range-clamped
  (`MIN_CHECK_INTERVAL_HOURS`..`MAX_CHECK_INTERVAL_HOURS`) before it ever
  reaches the drop-in or a systemctl argument, so no operator-supplied
  text can reach a unit file or shell.
- **Turning "Automatically check for updates" off actually stops the
  timer**, not just makes `update-check` a no-op at runtime:
  `deploy_check_schedule()` removes the drop-in and
  `systemctl disable --now`s the timer. (`update-check` itself *also*
  still no-ops when checking is disabled and invoked without `--force` --
  belt and suspenders against a stale enabled timer surviving a failed
  deploy, not the primary enforcement mechanism.)
- **Concurrent checks are deduplicated, not queued or interleaved**:
  `run_check()` takes a non-blocking `flock` (`CHECK_LOCK`) before doing
  any work; a check that lands while another is already in flight (a
  scheduled firing overlapping a manual "Check for Updates" click, or
  vice versa) immediately returns `{"skipped": True, "reason": "a check
  is already in progress"}` rather than making a second, redundant
  GitHub request and racing the first to write
  `software_update_settings`.
- **A failed check (GitHub unreachable, malformed response, etc.)
  records `last_check_error` and otherwise changes nothing** -- the next
  scheduled or manual check runs completely normally; there is no
  backoff, lockout, or persistent failure state to clear.
- **Unattended automatic installation is off by default** and has no
  execution path in this release (`unattended_install_enabled` exists as
  a setting for a future opt-in mechanism but nothing consumes it yet;
  `alderpointdns-software-update.service` is never enabled or started
  automatically -- only ever via an explicit administrator action).

## Failure handling

GitHub-unavailable, malformed-response, checksum-mismatch, wrong-package,
wrong-architecture, same-version/downgrade, APT-simulation-failure,
backup-failure, install-failure, and post-upgrade-health-check-failure are
all distinct, tested failure modes (`tests/test_software_updates.py`) that
land the job in `phase='failed'` with a redacted `error` message and
(from the backup step onward) a retained pre-upgrade backup. Automatic
package rollback is not implemented and not advertised; a failed update
past the install step requires administrator recovery (restore the
retained pre-upgrade backup, or reinstall the previous `.deb`).

## Known limitations

- No unattended-install execution path yet (see above) -- only checking
  is ever automatic.
- Automatic package rollback on a failed install is not implemented.
