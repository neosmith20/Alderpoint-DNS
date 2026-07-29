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

## Package 1: Per-Upstream Resolver Analytics

Started from clean `main` at `6720b6f` (`Modernize admin sidebar navigation`).

Initial inspection:

- `git status --short`: clean.
- `git log --oneline -20`: latest commit was `6720b6f`; prior checkpoint
  `fced3f2` and upstream resolver commit `20d6bc4` were present.
- `git diff`: empty.
- Reviewed `AGENT_PROGRESS.md`, existing route/template/tests/docs inventory,
  live service state, generated dnsdist upstream config, live upstream resolver
  DB records, analytics collector code, dnsdist web/API status, and the
  existing encryption/import/backup/restore/replication/cache implementations.
- `bindguard`, `named`, `dnsdist`, and `bindguard-analytics` were active before
  changes.
- Live upstream resolver configuration contained four enabled healthy imported
  plain resolvers: `1.1.1.2`, `1.0.0.2`, `4.2.2.1`, and `4.2.2.2`.

Implementation:

- Added `upstream_resolver_aggregate_buckets` and
  `upstream_resolver_counter_state` schema creation in `app/analytics.py`.
- Added authenticated polling of dnsdist's local
  `/api/v1/servers/localhost` endpoint and mapped managed upstream backends
  back to `upstream_resolvers.id` through generated names such as
  `upstream-1-Imported-upstream-1`.
- Stored resolver name, protocol, endpoint, enabled state, health state,
  attempted queries, successful responses, failures, timeouts, average/recent
  latency, last success, and last failure as aggregate snapshots.
- First poll seeds counter state without backfilling old dnsdist counters as
  new traffic. Counter resets are treated as zero deltas.
- Historical rows snapshot resolver metadata so deleting a resolver does not
  corrupt dashboard history.
- The collector records resolver aggregates only. It does not label individual
  client query rows with an upstream because the current dnsdist+BIND
  architecture does not expose that per-query relationship.
- Dashboard Top Upstream Resolvers now renders real ranked resolver data, links
  to DNS Settings, and provides a clear empty state when no resolver counters
  are available yet.
- Updated `CHANGELOG.md`, `docs/configuration.md`, `docs/database.md`,
  `docs/progress.md`, and `docs/testing.md`.

Live verification:

- Ran `/opt/bindguard/app/analytics.py init-db` against the live DB.
- Ran `/opt/bindguard/app/analytics.py collect-once`; first resolver poll
  correctly seeded counters with zero attempted-query deltas.
- Restarted `bindguard-analytics` and `bindguard`.
- Generated controlled DNS traffic through both BIND backend and dnsdist
  frontend, then ran another `collect-once`.
- Live resolver analytics rows showed nonzero activity for resolver 1 with
  successes capped to attempted queries and no failures/timeouts.
- All core services remained active after restarts.

Tests:

- `python3 -B /opt/bindguard/tests/test_analytics.py`: passed, 24 tests.
- `python3 -B /opt/bindguard/tests/test_upstream_dns.py`: passed, 7 tests.
- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
- `/opt/bindguard/tests/test_acceptance.sh`: passed. Expected invalid-RPZ and
  forced-rollback tracebacks appeared, as did pre-existing backup ResourceWarnings;
  final result was `BindGuard acceptance suite passed`.

Files changed:

- `app/analytics.py`
- `web/templates/dashboard.html`
- `tests/test_analytics.py`
- `tests/test_web_smoke.sh`
- `CHANGELOG.md`
- `docs/configuration.md`
- `docs/database.md`
- `docs/progress.md`
- `docs/testing.md`
- `AGENT_PROGRESS.md`

Remaining work:

- Package 2: Encryption Settings gap audit and any required corrections.
- Package 3: Import and Migration gap audit and any required corrections.
- Package 4: Installation, upgrades, packaging, and diagnostics complete
  (`Add installer upgrade diagnostics packaging`).
- Package 5: BIND Cache Management gap audit and any required corrections.
- Package 6: external beta and v1.0 hardening.

## Package 2: Encryption Settings listener controls

Started from clean `main` at `1c8d669` (`Add per-upstream resolver analytics`).

Gap audit:

- Existing Encryption Settings already separated upstream resolver encryption
  from client-facing encrypted DNS, and already supported DoH, DoT, DoQ,
  DoH3, certificate metadata, self-signed/local-CA/uploaded/existing-path
  certificate modes, certificate/key matching, dnsdist validation, service
  restart, protocol tests, rollback, Apple DoH/DoT profiles, and private-key
  redaction.
- The main missing requested control was configurable listening interfaces:
  live dnsdist config still bound client DNS listeners to hardcoded wildcard
  IPv4/IPv6 addresses.

Implementation:

- Added `listen_ipv4` and `listen_ipv6` Encryption Settings with defaults
  `0.0.0.0` and `::` to preserve existing lab behavior.
- Validation accepts blanking one address family, rejects invalid/mismatched IP
  families, and rejects blanking both families so DNS listeners remain present.
- Updated the dnsdist packaging template so plain DNS, DoH, DoH3, DoT, DoQ,
  and DNSCrypt listeners bind through `BINDGUARD_DNS_LISTEN_IPV4` and
  `BINDGUARD_DNS_LISTEN_IPV6`.
- Updated the dnsdist config migration to refresh older parameterized configs
  that do not yet contain listener-address variables while preserving existing
  console/web API secrets.
- Added Encryption page controls and a wildcard-listener warning.
- Hardened `detect_server_ip()` to return only valid IPv4 addresses and
  hardened certificate ownership writes to tolerate unsupported temp-filesystem
  `chown` behavior.
- Updated `CHANGELOG.md`, `docs/configuration.md`, `docs/dnsdist.md`, and
  `docs/security.md`.

Live deployment and verification:

- `/opt/bindguard/app/bindguard_compiler.py encryption-deploy`: succeeded with
  deployment id `10`.
- Live `/etc/dnsdist/dnsdist.conf` and packaging template now contain
  `BINDGUARD_DNS_LISTEN_IPV4` / `BINDGUARD_DNS_LISTEN_IPV6` handling.
- Live `/etc/systemd/system/dnsdist.service.d/bindguard.conf` contains
  `Environment=BINDGUARD_DNS_LISTEN_IPV4=0.0.0.0` and
  `Environment=BINDGUARD_DNS_LISTEN_IPV6=::`.
- `dnsdist`, `bindguard`, `named`, and `bindguard-analytics` remained active.
- Listener audit confirmed expected DNS, encrypted-DNS, BIND backend, web, and
  analytics listeners.
- DNS resolution succeeded through both BIND backend
  (`dig @127.0.0.1 -p 5353 cloudflare.com A +short`) and dnsdist frontend
  (`dig @127.0.0.1 -p 53 cloudflare.com A +short`).

Tests:

- `python3 -B /opt/bindguard/tests/test_encryption.py`: passed, 31 tests.
- `dnsdist --check-config -C /opt/bindguard/packaging/dnsdist.conf`: passed.
- `/opt/bindguard/tests/test_dnsdist_frontend.sh`: passed.
- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
- `/opt/bindguard/tests/test_acceptance.sh`: passed. Expected invalid-RPZ and
  forced-rollback tracebacks appeared, as did pre-existing backup ResourceWarnings;
  final result was `BindGuard acceptance suite passed`.

Files changed:

- `app/encryption.py`
- `app/webapp.py`
- `packaging/dnsdist.conf`
- `web/templates/encryption.html`
- `tests/test_encryption.py`
- `tests/test_web_smoke.sh`
- `CHANGELOG.md`
- `docs/configuration.md`
- `docs/dnsdist.md`
- `docs/security.md`
- `AGENT_PROGRESS.md`

Remaining work:

- Package 3: Import and Migration gap audit and corrections complete
  (`Expand import migration sources`).
- Package 4: Installation, upgrades, packaging, and diagnostics.
- Package 5: BIND Cache Management gap audit and any required corrections.
- Package 6: external beta and v1.0 hardening.

## Package 3 - Import and Migration Expansion

Started from clean `main` at `1d9c55a` (`Add encrypted DNS listener controls`)
and preserved existing import, backup, restore, replication, encryption,
upstream resolver, cache, route, service, certificate, and credential behavior.

Implemented:

- Added staged source retention for imports under
  `/var/lib/bindguard/imports`, with sanitized filenames, empty-upload
  rejection, and a 10 MiB upload size limit.
- Added `import_jobs.source_path` as an idempotent schema migration for
  row-oriented imports.
- Added Pi-hole text/list parsing for adlist URLs, allow/block domain lines,
  plain domain block entries, and hosts-style local DNS rewrites. Unsupported
  syntax is reported for preview instead of executed.
- Added BindGuard-native JSON export/import for local DNS records, client
  aliases, custom allow/block rules, blocklist sources, and managed upstream
  resolvers.
- Expanded AdGuard Home migration to translate safe `dns.upstream_dns`
  entries into managed upstream resolver candidates where BindGuard can model
  them. Domain-specific upstream routing and unsupported resolver schemes are
  listed as untranslatable.
- Added a structured migration summary for add/update/conflict/skipped/
  unsupported states before apply.
- Added upstream resolver application for migration imports, including
  validation and duplicate protocol/address/port/path suppression.
- Updated the Import page to expose Pi-hole, BindGuard-native JSON import,
  native JSON export, staged source metadata, upstream resolver group
  selection, and generalized migration preview text while preserving the
  existing AdGuard routes.

Files changed:

- `app/importer.py`
- `app/webapp.py`
- `web/templates/import_migration.html`
- `tests/test_importer.py`
- `tests/test_web_smoke.sh`
- `CHANGELOG.md`
- `docs/adguard-parity.md`
- `docs/database.md`
- `docs/known-limitations.md`
- `docs/progress.md`
- `docs/testing.md`
- `docs/web.md`
- `AGENT_PROGRESS.md`

Tests and verification:

- `python3 -m py_compile /opt/bindguard/app/importer.py /opt/bindguard/app/webapp.py`: passed.
- `python3 -B /opt/bindguard/tests/test_importer.py`: passed, 23 tests.
- `python3 -B /opt/bindguard/tests/test_upstream_dns.py`: passed, 7 tests.
- `git diff --check`: passed.
- Restarted `bindguard`; service returned active.
- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
- `/opt/bindguard/tests/test_acceptance.sh`: passed. Expected invalid-RPZ and
  forced-rollback tracebacks appeared, as did pre-existing backup ResourceWarnings;
  final result was `BindGuard acceptance suite passed`.

Known limitations:

- Pi-hole import intentionally targets practical text/list exports rather than
  reading Pi-hole's live gravity database internals.
- AdGuard domain-specific upstream routing is not imported because BindGuard
  currently has one shared managed upstream set for non-local queries.
- Migration-style applies still use the existing deployment path after
  database writes; source data is backed up before apply and unsupported items
  are previewed, but a future hardening pass can make the structured migration
  report persist as its own import job type.

## Package 4 - Installation, Upgrade, Packaging, and Diagnostics

Implemented:

- Added `VERSION` (`0.4.0-beta.1`), `requirements.txt`, and
  `requirements-debian.txt`.
- Added `scripts/install.sh` for reviewed fresh Debian-based installs. It
  checks OS/version, architecture, memory, and disk; installs packages;
  creates the `bindguard` user/group; creates application/config/data/log/
  backup/import-staging directories; creates a Python virtual environment;
  installs systemd units and sudoers policy; generates local secrets;
  initializes databases and generated DNS; enables services; and runs service
  health checks. It supports `--dry-run`, `--skip-apt`, `--source`, and
  `BINDGUARD_INSTALL_ROOT`.
- Added `scripts/upgrade.sh` for safe local upgrades. It detects current and
  target versions, creates a pre-upgrade backup, creates a rollback snapshot,
  replaces application files without deleting persistent data, validates
  Python/BIND/dnsdist/sudoers state, runs migrations/deploy, restarts services
  in controlled order, and restores the snapshot on failure. It supports
  dry-run/test-root mode.
- Added `scripts/bindguard-diagnostics`, which generates a sanitized support
  bundle with version, OS/kernel/Python, service status, listeners, BIND and
  dnsdist validation, schema object names, recent warnings, network/resource
  summaries, DNS health checks, and configuration metadata. It redacts
  passwords, API keys, session secrets, tokens, Authorization headers, private
  keys, and sensitive resolver URL query strings. Private DNS records and
  query contents are excluded by default.
- Added Debian packaging scaffold under `packaging/debian`, including
  `control`, `rules`, `install`, `changelog`, `postinst`, `prerm`, and
  `postrm`. Normal remove preserves `/etc/bindguard`, `/var/lib/bindguard`,
  and `/var/log/bindguard`; purge removes them only when explicitly requested.
- Added `scripts/build-deb.sh` to build a local test `.deb` with `dpkg-deb`
  without requiring `debhelper` on the active VM.
- Added `tests/test_install_upgrade_diagnostics.sh` and included it in
  `tests/test_acceptance.sh`.
- Added documentation: `docs/install.md`, `docs/upgrade.md`,
  `docs/diagnostics.md`, and `docs/packaging.md`; updated changelog, testing,
  and progress docs.

Tests:

- `python3 -m py_compile /opt/bindguard/scripts/bindguard-diagnostics`: passed.
- `sh -n /opt/bindguard/scripts/install.sh`: passed.
- `sh -n /opt/bindguard/scripts/upgrade.sh`: passed.
- `sh -n /opt/bindguard/scripts/build-deb.sh`: passed.
- `/opt/bindguard/tests/test_install_upgrade_diagnostics.sh`: passed; it ran
  installer and upgrader dry-runs in an isolated test root, verified
  diagnostics redaction and bundle structure, and built/inspected a test
  `.deb`.
- `git diff --check`: passed.
- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
- `/opt/bindguard/tests/test_acceptance.sh`: passed. Expected invalid-RPZ and
  forced-rollback tracebacks appeared, as did pre-existing backup ResourceWarnings;
  final result was `BindGuard acceptance suite passed`.

Live service state after acceptance:

- `bindguard`, `named`, `dnsdist`, and `bindguard-analytics` remained active
  during package 4 verification.

Known limitations:

- The full `dpkg-buildpackage`/debhelper release pipeline is scaffolded but
  not exercised on this VM because `debhelper` is not installed. The local
  `dpkg-deb` test package path is present and tested.
- The diagnostics `--include-private-dns` flag is an explicit opt-in
  placeholder; diagnostics still does not export private DNS records. Use an
  encrypted backup for support cases that truly need private data.
