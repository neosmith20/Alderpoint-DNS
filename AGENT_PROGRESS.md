# BindGuard Agent Progress

Updated: 2026-07-29

## Initial audit

Files/areas inspected:

- `git status --short`: uncommitted replication changes in `app/bindguard_compiler.py`, `app/replication.py`, `app/webapp.py`, `packaging/bindguard.service`, `packaging/sudoers-bindguard`, `web/templates/base.html`; untracked `bindguard-handoff.md` and `web/templates/replication.html`.
- `git diff` and `git diff --stat`: reviewed the current uncommitted replication UI/autostart/enrollment changes.
- `git log --oneline -15`: latest commit is `323c7f9 Merge branch 'worktree-agent-a9ab38f57674f71cc'`; recent replication commit is `dd88276 Add primary-to-replica replication core (uncommitted work-in-progress recovered)`.
- Untracked files: `bindguard-handoff.md`, `web/templates/replication.html`.
- `/opt/bindguard/bindguard-handoff.md`: present; contains older interrupted-work handoff context.
- `/tmp/replica-test/`: present with `setup.py`, `enroll.py`, `sync.py`, `drift.py`, enrollment material, `bindguard.db`, and related temp files; no `sync_fail.py`.
- Service status: `bindguard`, `named`, `dnsdist`, and `bindguard-analytics` are active/running. Logs show an SSL EOF in `bindguard` and a `sqlite3.OperationalError: database is locked` in analytics while the analytics service remains active.

Tests run:

- `python3 -B tests/test_replication.py`: passed, 5 tests.
- `python3 -B tests/test_backup.py`: passed, 33 tests. The suite still prints ResourceWarnings from older backup-test SQLite contexts, but all assertions pass.
- `python3 -B /tmp/replica-test/sync_fail.py`: passed with escalation for localhost listener access. Result was `failed`, generation 1, message `deploy failed, rolled back: intentional live rollback test deploy failure`, and `state_restored: true`.
- `python3 -B /tmp/replica-test/revoked_peer.py`: passed with escalation. Primary denied the revoked replica with `replica is revoked`, then restored prior status.
- `python3 -B /tmp/replica-test/sync.py`: passed with escalation to restore the temp replica and primary health row to `success: applied`.
- `python3 -B tests/test_replication.py`: rerun passed, 5 tests.
- `python3 -B tests/test_backup.py`: rerun passed, 33 tests, with the same pre-existing ResourceWarnings from older backup-test SQLite contexts.
- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
- `/opt/bindguard/tests/test_acceptance.sh`: passed. Intentional invalid-RPZ/forced-rollback tracebacks appeared during failure-path tests as expected. Backup unit portion still emits pre-existing SQLite ResourceWarnings, but the suite completed with `BindGuard acceptance suite passed`.
- Final service status after acceptance: `bindguard`, `named`, `dnsdist`, and `bindguard-analytics` active/running. Live `/etc/systemd/system/bindguard.service` and `/etc/sudoers.d/bindguard` already match the packaging changes needed for replication.

Files changed:

- Added `AGENT_PROGRESS.md`.
- Added `tests/test_replication.py`.
- Updated `tests/test_acceptance.sh` to include replication unit tests.
- Updated `app/replication.py` so replica apply/rollback replaces replicated key/value settings as a complete subset and includes optional replicated encryption settings.
- Updated `app/backup.py` so backup archive permission hardening remains `0640` but does not fail unit-test/temp filesystems when `chown root:bindguard` is unsupported.
- Added `/tmp/replica-test/sync_fail.py` and `/tmp/replica-test/revoked_peer.py` as resumable live-test scripts.
- Updated `tests/test_web_smoke.sh` to check Replication routes and navigation.
- Updated `README.md`, `CHANGELOG.md`, `docs/web.md`, `docs/database.md`, `docs/testing.md`, `docs/adguard-parity.md`, and added `docs/replication-promotion.md`.
- Marked `bindguard-handoff.md` as superseded by `AGENT_PROGRESS.md`.

Commits now present on `main`:

- `c12a09c Complete primary-to-replica replication`
- `3c80bc8 Record BindGuard backlog handoff progress`

Current state:

- The repository is clean at the close-out commit.
- The controlled reboot has completed and core services are active.
- `/opt/bindguard/tests/test_acceptance.sh` passed again on 2026-07-29 after
  the current-state check.

## Navigation and IA cleanup

Started from clean `main` at `2afc948`.

Inventory of authenticated primary navigation links and preserved URLs:

- Dashboard: `/`
- DNS: `/query-log`, `/local-dns`, `/dns-settings`, `/dns-cache`
- Security: `/custom-rules`, `/blocklists`, `/encryption`
- Operations: `/import`, `/backup`, `/replication`
- System: `/statistics-settings`, `/system`

Implemented a grouped responsive primary navigation in `web/templates/base.html`
using native `<details>` sections so the groups work by click, touch, and
keyboard rather than hover-only behavior. Dashboard remains the first direct
link. Active child pages use `aria-current="page"` and active parent sections
use `aria-current="true"` plus an open group.

Updated `web/static/app.css` for desktop dropdowns and mobile stacked groups,
and updated `web/static/app.js` so Escape/outside-click closes open desktop
groups without affecting route behavior.

Updated `tests/test_web_smoke.sh` to inventory every primary navigation href,
assert grouped section hooks, verify active parent/child rendering, and confirm
unauthenticated primary pages redirect instead of exposing the admin navigation.

Validation:

- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
