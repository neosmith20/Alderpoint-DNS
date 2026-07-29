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

## Upstream Resolvers and Global Status

Inspected current forwarding architecture:

- dnsdist is the client-facing DNS proxy.
- BIND is the recursive resolver, DNSSEC validator, RPZ policy point, and Local
  DNS authoritative backend.
- Before this work, BIND used a static `forwarders` block in
  `/etc/bind/named.conf.options`.

Implemented managed upstream resolvers:

- Added `app/upstream_dns.py`.
- Added `upstream_resolvers` and `upstream_deployments` tables.
- DNS Settings now has an Upstream Resolvers section with add/edit,
  enable/disable, reorder, delete, health, latency, and deployment result.
- Supports plain UDP/TCP DNS, DNS-over-TLS, and DNS-over-HTTPS.
- Existing BIND forwarders are imported on first use.
- Generated config:
  - `/var/lib/bindguard/compiled/bind/upstream-forwarders.conf`
  - `/var/lib/bindguard/compiled/dnsdist/upstream-forwarder.conf`
- BIND forwards to a managed dnsdist loopback upstream pool at
  `127.0.0.1:5355`.
- Deployment validates dnsdist and BIND config, restarts dnsdist, reloads BIND,
  performs a functional lookup, records health/latency, and rolls back
  generated files on failure.
- DoH URLs with query strings/fragments are rejected to avoid storing or
  logging credentials/tokens.

Implemented global service status:

- Added `global_service_status()` and `/status/summary`.
- The top-right badge is now rendered by the shared shell on every
  authenticated page.
- Shared JS refreshes the badge through `/status/summary` without a full page
  reload.
- Smoke tests cover healthy, degraded, inactive, and unknown status logic.

Backlog audit:

- BIND cache-management settings UI: complete (`0ed4bf5`, `/dns-cache`).
- Configurable Encryption Settings page: complete (`4acb870`, `/encryption`).
- Import and migration beyond Local DNS CSV: complete (`5d172fc`, `/import`).
- Native Backup and Restore: complete (`cfea522`, `40721ec`, `/backup`).
- Replication: complete (`c12a09c`, `/replication`).
- AdGuard parity documentation: complete and updated (`docs/adguard-parity.md`).
- Local DNS fixes, Query Log refresh behavior, latency correction, acceptance
  testing, and reboot validation: represented in current commits and
  `docs/progress.md`.

Validation during this checkpoint:

- `python3 -B /opt/bindguard/tests/test_upstream_dns.py`: passed.
- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
- `/opt/bindguard/app/bindguard_compiler.py deploy --no-download`: passed with
  deployment id `198`.
- Live DNS after deploy:
  - `dig @127.0.0.1 -p 5353 cloudflare.com A +short`: returned A records.
  - `dig @127.0.0.1 -p 53 cloudflare.com A +short`: returned A records.
- Live upstream DB state: four imported plain resolvers are enabled and healthy.

## Post-reboot navigation correction

Started from clean `main` at `fced3f2` (`Redesign admin navigation shell`).

Post-reboot verification completed on 2026-07-29:

- `bindguard`, `named`, `dnsdist`, and `bindguard-analytics` were active.
- Required listeners were present:
  - dnsdist: `0.0.0.0:53`, `[::]:53`, `0.0.0.0:443`, `[::]:443`,
    `0.0.0.0:853`, `[::]:853`, and managed upstream listener
    `127.0.0.1:5355`.
  - BIND backend: `127.0.0.1:5353`, `127.0.0.1:5354`, and `::1:5353`.
  - Web/admin: `0.0.0.0:3000`, `0.0.0.0:8843`.
  - Analytics sink: `127.0.0.1:5301`.
- DNS resolution succeeded through both BIND backend
  (`dig @127.0.0.1 -p 5353 cloudflare.com A +short`) and dnsdist frontend
  (`dig @127.0.0.1 -p 53 cloudflare.com A +short`).
- Upstream resolver settings persisted after reboot: four imported plain
  resolvers remained enabled and healthy, with recent deployed records.
- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
- `/opt/bindguard/tests/test_acceptance.sh`: passed.

Navigation correction:

- Replaced the `<details>` navigation groups with explicit app-style sidebar
  sections using button-controlled panels.
- Desktop now reserves a fixed left navigation column and pins the sidebar while
  the main content resizes in the adjacent column.
- Mobile now uses a slide-out drawer with backdrop dismissal, Escape handling,
  full-row section toggles, and automatic close after route selection.
- Active sections remain expanded; active pages use `aria-current="page"`,
  stronger background/border styling, and an inset accent marker.
- Added a mobile top-bar service-status badge so global service state remains
  visible when the drawer is closed, and updated status refresh logic to update
  all visible badges.
- Updated web smoke coverage for the new nav structure, active-state rendering,
  mobile hooks, and shared status refresh hooks.

Rendered inspection:

- Used live Chromium inspection against the authenticated web app at desktop
  (`1440x1000`), tablet (`900x900`), and mobile (`390x844`, `430x932`)
  viewport widths.
- Verified no visible menu item escaped the nav/drawer container, visible rows
  remained clickable, active section/page state was obvious, drawer open/close
  worked, Escape closed the drawer, and content did not render beneath the
  sidebar or mobile top bar.
- Screenshots were captured under `/tmp/bindguard-nav-*.png` for local review.

Final validation before commit:

- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
- `/opt/bindguard/tests/test_acceptance.sh`: passed. Expected rollback-test
  tracebacks and pre-existing backup ResourceWarnings appeared, but the suite
  completed with `BindGuard acceptance suite passed`.
