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
- Package 5: BIND Cache Management gap audit and corrections complete
  (`Tighten BIND cache management controls`).
- Package 6: external beta and v1.0 hardening complete
  (`Prepare external beta hardening docs`).

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

## Package 5 - BIND Cache Management Corrections

Audit result:

- BIND cache management was already substantially implemented in
  `app/dns_cache.py`, `/dns-cache`, the privileged `cache-flush` compiler
  command, tests, and docs.
- Existing coverage already included max cache size, positive/negative TTLs,
  serve-stale, prefetch, flush-all/name/tree, BIND cache stats, staged
  deployment, validation, rollback, persistence through deploy/restart/
  backup/restore paths, and acceptance/benchmark tests.

Corrections implemented:

- Added `recursive_clients` to `dns_cache_settings`, validation, generated
  BIND config (`recursive-clients 1000;` by default), the Cache page, web
  route handling, smoke fixtures, unit tests, and docs.
- Added an explicit "Refresh statistics" action on `/dns-cache`.
- Changed `/dns-cache/settings` to use `deploy_no_download_or_raise()` so
  failed privileged deploys surface as page errors instead of redirecting as
  if successful.
- Added `cache_flush_apply_or_raise()` and switched all cache flush routes to
  report privileged helper failure rather than silently redirecting.
- Updated docs/changelog/progress to describe recursive-client support,
  refresh behavior, and failure surfacing.

Live deployment:

- Ran `/opt/bindguard/app/bindguard_compiler.py deploy --no-download`;
  deployment id `239`.
- Verified `/var/lib/bindguard/compiled/bind/cache-options.conf` contains
  `recursive-clients 1000;`.
- Ran `named-checkconf -p /etc/bind/named.conf`; validation passed
  (BIND's existing experimental `allow-proxy` warnings appeared).
- Restarted `bindguard`; service returned active.

Tests:

- `python3 -B /opt/bindguard/tests/test_dns_cache.py`: passed, 21 tests.
- `python3 -m py_compile /opt/bindguard/app/dns_cache.py /opt/bindguard/app/webapp.py`: passed.
- `git diff --check`: passed.
- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
- `/opt/bindguard/tests/test_acceptance.sh`: passed. Expected invalid-RPZ and
  forced-rollback tracebacks appeared, as did pre-existing backup ResourceWarnings;
  final result was `BindGuard acceptance suite passed`.

Live service state after acceptance:

- `bindguard`, `named`, `dnsdist`, and `bindguard-analytics` remained active.

## Package 6 - External Beta and v1.0 Hardening

Implemented:

- Added beta and release documentation:
  - `docs/beta-readiness.md`
  - `docs/versioning.md`
  - `docs/release-notes.md`
  - `docs/supported-systems.md`
  - `docs/hardware-requirements.md`
- Added operator guides:
  - `docs/backup-recovery.md`
  - `docs/migration.md`
  - `docs/troubleshooting.md`
- Added tester and issue templates:
  - `docs/beta-feedback-template.md`
  - `docs/bug-report-template.md`
  - `docs/feature-request-template.md`
- Added `docs/hardening-review.md` covering authentication/authorization,
  CSRF, session cookies, input validation, upload handling, command execution,
  permissions/ownership, secret storage, logging/redaction, DNS recursion ACLs,
  public exposure, backup encryption, and replication auth/revocation.
- Added `BINDGUARD_COOKIE_SECURE=1` support in `app/webapp.py` so HTTPS admin
  deployments can mark session cookies Secure while current HTTP lab mode
  remains usable.
- Updated `docs/security.md`, `docs/issues.md`, `CHANGELOG.md`, and
  `docs/progress.md`.
- Added `tests/test_beta_hardening_docs.sh` and included it in acceptance.

Tests:

- `python3 -m py_compile /opt/bindguard/app/webapp.py`: passed.
- `git diff --check`: passed.
- `/opt/bindguard/tests/test_beta_hardening_docs.sh`: passed.
- `/opt/bindguard/tests/test_web_smoke.sh`: passed.
- `/opt/bindguard/tests/test_acceptance.sh`: passed. Expected invalid-RPZ and
  forced-rollback tracebacks appeared, as did pre-existing backup ResourceWarnings;
  final result was `BindGuard acceptance suite passed`.

Known limitations before external beta:

- A controlled full reboot still needs to be performed after the final beta
  commit, then post-reboot DNS/listener/service verification repeated.
- Admin UI HTTPS remains a beta risk; use private access or a trusted reverse
  proxy and set `BINDGUARD_COOKIE_SECURE=1`.
- Signed apt repository publishing is not implemented; only local test `.deb`
  creation is currently validated.

## Post-Reboot Verification (after Package 6 checkpoint `da0ab25`)

The controlled full reboot referenced above was performed. This section
records the post-reboot verification pass.

Services:

- `bindguard`, `named`, `dnsdist`, and `bindguard-analytics` all came back
  `enabled` and `active` on boot with no restarts or manual intervention.
- `journalctl -b` for all four units showed no errors, crash loops, migration
  failures, permission problems, or certificate/listener failures at any
  priority.

Listeners (matched the intended topology, no unintended exposure):

- dnsdist frontend: plain DNS `0.0.0.0:53`/`[::]:53`, DoH `443/tcp`, DoH3
  `443/udp`, DoT `853/tcp`, DoQ `853/udp` (all enabled via the
  `dnsdist.service.d/bindguard.conf` drop-in); DNSCrypt correctly absent
  (disabled). Console (`127.0.0.1:5199`) and webserver (`127.0.0.1:8083`)
  stayed loopback-only.
- BIND backend: `127.0.0.1:5353` (plain) and `127.0.0.1:5354` (proxy-protocol
  from dnsdist), rndc on `127.0.0.1:953`, stats on `127.0.0.1:8053` — all
  loopback-only.
- BindGuard web: `0.0.0.0:3000` (HTTP) and `0.0.0.0:8843` (replication
  listener/HTTPS admin), `bindguard-analytics` remote-logger receiver on
  `127.0.0.1:5301`.
- `dnsdist.conf`'s `setACL` confirmed restricted to RFC1918 + loopback +
  ULA ranges (`BINDGUARD_DNS_ALLOW_ALL` unset) — no open-resolver exposure.

DNS functionality (all verified live against the running stack):

- Recursive resolution through dnsdist `:53` and BIND backend `:5353` both
  returned correct answers.
- Local A record (`adguard.mylan.network`) and PTR record
  (`9.43.16.172.in-addr.arpa` -> `adguard.mylan.network.`) resolved correctly
  from the persisted local zone files.
- RPZ filtering confirmed live: a known blocklist entry
  (`0.avmarket.rs`) returned `NXDOMAIN` with the `bindguard.rpz` SOA in the
  additional section.
- Upstream forwarder pool (`bindguard_upstreams`, `firstAvailable` policy)
  showed all 4 configured upstreams `up` via dnsdist's `showServers()`,
  confirming persisted upstream configuration and health checking survived
  reboot.
- DoT (`kdig +tls` on `853/tcp`) and DoH (raw wire-format query over
  `https://127.0.0.1/dns-query`) both resolved correctly against the
  self-signed lab certificate (valid until 2028-10-31, as expected for the
  documented lab TLS mode).
- Unauthenticated requests to `/`, `/dashboard`, and `/status/summary` all
  redirected to `/login` (auth enforcement intact).

Feature persistence (verified directly in `bindguard.db` and on disk):

- `upstream_resolvers` (4 rows, `last_status=healthy`), `replication_settings`
  (role `primary`, node id, listen port 8843), `encryption_settings` (DoH/
  DoH3/DoT/DoQ enabled, DNSCrypt off, cert/key paths), `dns_cache_settings`
  (including the `recursive_clients=1000` value added in Package 5),
  `local_dns_settings`, `analytics_settings`, `admins` (argon2 hash intact)
  all matched their expected values and matched the actually-deployed
  dnsdist/BIND config on disk.
- Analytics data persisted (17k+ `query_events`, populated aggregate
  buckets); replication enrollments/replicas rows persisted; certificates
  present with correct ownership/permissions.

Tests:

- `tests/test_web_smoke.sh`: passed.
- `tests/test_acceptance.sh`: passed (run twice after fixes below, both
  clean). Expected invalid-RPZ and forced-rollback tracebacks appeared as
  documented; final line `BindGuard acceptance suite passed`.
- `tests/test_beta_hardening_docs.sh`: passed standalone.
- All package-specific suites bundled in `test_acceptance.sh`
  (`test_bind_backend.sh`, `test_dnsdist_frontend.sh`,
  `test_blocklist_deploy.sh`, `test_blocklist_failure_paths.sh`,
  `test_analytics.py`, `test_local_dns.py`, `test_dns_cache.py`,
  `test_upstream_dns.py`, `test_dns_cache_benchmark.sh`, `test_encryption.py`,
  `test_importer.py`, `test_backup.py`, `test_replication.py`,
  `test_install_upgrade_diagnostics.sh`, `test_service_restart_analytics.sh`,
  `test_backup_restore.sh`) all passed.

Two real defects were found and fixed during this verification pass (each
committed separately, with a regression test, before this closeout commit):

1. **Unclosed SQLite connections in `tests/test_backup.py`**
   (`06cab14`). `sqlite3.Connection.__exit__` only commits/rolls back a
   transaction — it does not close the connection. `BackupTestBase.setUp()`
   and several test methods used `with backup.connect() as conn:` directly,
   leaking one connection per test and producing the pre-existing
   `ResourceWarning: unclosed database` noise seen during backup test runs
   (already known/accepted per the pre-reboot checkpoint). Fixed by wrapping
   with `contextlib.closing()` — the same effect `local_dns.py` and
   `bindguard_compiler.py` already get from their `BindGuardConnection`
   factory (`__exit__` override that also calls `close()`). Full acceptance
   suite now runs with zero `ResourceWarning`s. **Tech debt** (not fixed, out
   of scope for this pass): `app/dns_cache.py`, `app/importer.py`,
   `app/upstream_dns.py`, `app/encryption.py`, and `app/backup.py` still
   define a plain `connect()` (no `BindGuardConnection` factory) and use the
   same `with connect() as conn:` pattern internally. In practice CPython's
   refcounting closes these promptly when `conn` goes out of scope, so no
   FD/lock exhaustion has been observed in production, but adopting the
   `BindGuardConnection` factory there too would be a low-risk future
   cleanup for consistency and defense against reference-cycle edge cases.
2. **RNDC/TSIG secret leak in the diagnostics bundle** (`3892dc2`) — a real,
   production-impacting finding, not just documented. `bind_validation.txt`
   in every `bindguard-diagnostics` bundle is generated from
   `named-checkconf -p`, which echoes the live BIND control-channel key
   verbatim (`key "rndc-key" { secret "<real key>"; };`). None of the
   existing `REDACTION_PATTERNS` matched BIND's `secret "value";` config
   syntax (they covered `key=value`/`key: value` forms, private-key PEM
   blocks, and HTTP auth headers, but not this one), so every diagnostics
   bundle generated before this fix leaked the live RNDC/TSIG shared secret
   in plaintext by default. Fixed by adding a `secret "..."` redaction
   pattern, extending `bindguard-diagnostics --self-test-redaction` to cover
   an rndc-key sample, and adding a bundle-level regression check in
   `tests/test_install_upgrade_diagnostics.sh` that fails if any unredacted
   `secret "..."` value survives in a real generated bundle. Verified with a
   fresh diagnostics run post-fix: no known secret values (session secret,
   dnsdist console/webserver key, RNDC key) appear anywhere in the bundle.

Backup/restore final check (production flow, not just unit tests):

- Created a real backup via the same `backup_requests` intent-row +
  `bindguard_compiler.py backup-create` path the web UI uses, with default
  components (`private_keys`/`user_auth_data`/`analytics_history` all off).
- Validated the resulting archive: all 25 manifest SHA-256 checksums matched
  the extracted files exactly; no `.key` files or `secrets.env` present;
  the bundled `bindguard.db` had `admins`, `login_attempts`, `query_events`,
  and `analytics_aggregate_buckets` correctly stripped (0 rows) while
  `upstream_resolvers`/`custom_rules` were retained — matching the documented
  secret/private-data policy exactly.
- Reversible restore test: inserted a temporary `custom_rules` row, then
  requested a `custom_rules`-only scoped restore from the fresh backup (same
  intent-row + `backup-restore` production path). The restore automatically
  took its own pre-restore safety backup, reverted the temporary row, left
  every other table (`upstream_resolvers`, `admins`, `query_events`, etc.)
  untouched, and passed its own post-restore validation
  (`named-checkconf`/`visudo` OK).
- Confirmed `bindguard`/`named`/`dnsdist`/`bindguard-analytics` stayed active
  and DNS (`example.com`, `adguard.mylan.network`) resolved correctly
  throughout and after.
- Cleaned up the temporary extraction directories used for checksum
  verification; the two backup archives created during this test (the
  manual verification backup and its auto-generated pre-restore safety
  backup) were left in `/var/lib/bindguard/backups/` as legitimate recovery
  points, tracked in `backup_history` like any other backup.

Installer/packaging/diagnostics consistency:

- `VERSION` (`0.4.0-beta.1`) is consistent with `docs/release-notes.md`,
  `docs/versioning.md`, and `packaging/debian/changelog`
  (`0.4.0~beta1-1`, correct Debian tilde-versioning for a pre-release).
- All required docs present: install, upgrade, backup-recovery, migration,
  security, troubleshooting, supported-systems, hardware-requirements,
  beta-readiness, beta-feedback/bug-report/feature-request templates.
- Ran `bindguard-diagnostics` (no arguments beyond `--output-dir`) once
  end-to-end and manually inspected every extracted file; after the RNDC
  fix above, no secrets, credentials, private keys, resolver secrets,
  Authorization headers, or private DNS/query data were present.

Remaining known issues / external-beta blockers: none found that block a
first external tester, beyond the pre-existing documented ones (self-signed
lab TLS cert, admin UI HTTP-by-default requiring `BINDGUARD_COOKIE_SECURE=1`
behind a reverse proxy for real HTTPS, signed apt repo not yet implemented,
per-network policy runtime enforcement not yet wired up). BindGuard is ready
to hand to a first external tester on this checkpoint.

## Rename: BindGuard -> Alderpoint DNS (after checkpoint `0cf8045`)

Deliberate pre-public-beta product rename, executed as source rename +
compatibility tooling first (commits `83deadf`..`18a7143`), then a real,
live cutover of this VM's own running installation.

### Naming map

Public name `Alderpoint DNS`; machine identifier `alderpointdns`; env var
prefix `ALDERPOINTDNS_`; paths `/opt/alderpointdns`, `/etc/alderpointdns`,
`/var/lib/alderpointdns`, `/var/log/alderpointdns`; services
`alderpointdns.service`, `alderpointdns-analytics.service`,
`alderpointdns-backup.service`/`.timer`; command `alderpointdns-diagnostics`;
Debian package `alderpointdns`. Full table in `docs/compatibility.md`.

**Intentionally not renamed:** the `bindguard` Linux system user/group
(ownership-migration risk with no correctness benefit -- documented in
`docs/compatibility.md`); HTTP routes, DB columns/table names, migration IDs,
replication protocol field names (none of these referenced the product name
in the first place); historical docs (`docs/progress.md` above this section,
`CHANGELOG.md`'s pre-rename entries, `bindguard-handoff.md`) and the
`audit/pre-proxyv2-20260728T233402/` snapshot, left untouched as frozen
historical record; real user data (a local DNS host record literally named
`bindguard.home.arpa` -> `172.16.43.101`, and an RPZ custom-rule test domain
`bindguard-block-test.invalid`) -- confirmed intact and unmodified after
migration by direct `dig` lookup.

### Source rename (commits `83deadf`, `110201a`, `ccc6192`, `eff8704`)

Ordered token substitution (`BindGuardConnection`/`AsyncForm`/`AutoRefresh`/
`Status`/`Replication` -> `AlderpointDNS...`, then `BindGuard` -> `Alderpoint
DNS`, `BINDGUARD_`/`BINDGUARD` -> `ALDERPOINTDNS_`/`ALDERPOINTDNS`, then
`bindguard` -> `alderpointdns`) across ~105 files, with the Linux-account
lines manually reverted afterward (`chown`/`useradd`/`groupadd`/sudoers
leading field/systemd `User=`/`Group=`). File renames via `git mv`:
`app/bindguard_compiler.py` -> `alderpointdns_compiler.py`,
`scripts/bindguard-diagnostics` -> `alderpointdns-diagnostics`, all
`packaging/bindguard*` -> `alderpointdns*`. Added deprecated exec-wrapper
compatibility shims at both old filenames. `app/backup.py` gained
`LEGACY_*` constants and an `_extracted_path()` resolver so
BindGuard-branded backup archives remain restorable (verified against a
real pre-rename archive during live-system checks, see below). New
docs: `docs/compatibility.md`, `docs/migrating-from-bindguard.md`.

### Live migration of this VM (commits `c1ba4a9`..`18a7143`)

Ran the real `scripts/upgrade.sh` legacy-migration path against this VM's
own installation (native backup, live BIND/dnsdist/AppArmor config
token-rewrite, directory moves, new units/sudoers, compatibility symlinks,
service restarts). This surfaced and fixed several real bugs the sandboxed
tests hadn't caught, all now covered by `tests/test_rename_migration.sh`:

1. `SOURCE_DIR` resolving inside the legacy directory being moved (this
   VM's actual situation: the git checkout is both the running legacy
   install and the new release) silently broke every step after the `mv`.
   Fixed by staging `SOURCE_DIR` to a temp copy first, in both
   `migrate_legacy_layout()` and `replace_application()` (the latter is a
   separate, more general instance of the same bug: any `--source` pointing
   at the install target itself, including this script's own default,
   triggers it).
2. `pre_upgrade_backup()` hard-failed on the very first post-migration
   upgrade run, before `install_units()` had created the new unit/sudoers
   files `scripts/backup.sh` looks for. Now warns and continues (the
   rollback `snapshot()` right after is still a safety net).
3. A stray empty database had been created at the new DB path earlier in
   this session (an artifact of testing the compat wrapper against live
   code before the physical migration), which made `mv
   var/lib/bindguard -> var/lib/alderpointdns` nest instead of rename since
   the destination already existed. Fixed by hand for this run and added a
   loud pre-flight check in `migrate_legacy_layout()` so a pre-existing
   destination now aborts the migration instead of silently corrupting the
   layout.
4. Generated BIND/dnsdist config under `compiled/` (ACL name, `/var/lib/
   bindguard/` path prefixes, dnsdist pool name/enable flag, comment
   headers) was never rewritten, so `named` failed to start (undefined ACL)
   and dnsdist's upstream pool silently stopped matching. Fixed with a
   targeted sed pass over exactly four generated files, deliberately never
   touching the `.zone` record files themselves (which hold the real
   `bindguard.home.arpa` user record above).
5. `secrets.env` kept its old `BINDGUARD_SESSION_SECRET=` key after the
   `/etc` move; the renamed `webapp.py` only recognizes
   `ALDERPOINTDNS_SESSION_SECRET=`, doesn't find it, and crashes trying to
   append a new one as an unprivileged user with only group-read on the
   file. Fixed by rewriting just the key name in place, preserving the
   secret value (existing sessions/cookies kept validating).
5b. TLS cert/key/CA filenames (`bindguard-lab.*`, `bindguard-ca.*`) were
   never renamed, so dnsdist failed to start (missing certificate file now
   that `dnsdist.conf`'s already-rewritten paths expect `alderpointdns-*`).
   Fixed by renaming the five files. Separately, the lab cert's own
   CN/SAN literally encoded `bindguard.local`; regenerated it via the
   (already-renamed) `ensure_tls_cert.sh` since it is a self-signed,
   internally-trusted-only artifact, not a real credential -- old cert/key
   backed up to `/root/pre-rename-cert-backup/` first.
6. `/var/lib/alderpointdns` ended up `755` instead of the original `775`
   as a side effect of fix #3's manual cleanup, so the analytics collector
   (running as `bindguard:bindguard`) couldn't create WAL/journal files:
   `sqlite3.OperationalError: attempt to write a readonly database`. Fixed
   by restoring the directory mode.
7. `install_units()` never called `systemctl enable`, so a freshly migrated
   install would not have survived a reboot. Fixed.
8. `migrate_legacy_layout()` deleted
   `/etc/systemd/system/dnsdist.service.d/bindguard.conf` outright instead
   of migrating it. That file is **operator-editable state**
   (`app/encryption.py`'s `DNSDIST_ENV_OVERRIDE`, rewritten whenever DoH/
   DoT/DoQ/DoH3/DNSCrypt toggles or ports are changed on the Encryption
   Settings page) -- this VM's actual drop-in had DoQ/DoH3 enabled with
   explicit ports and a DNSCrypt provider hostname, none of which would
   have survived the delete. Fixed by rename+token-patch in place instead,
   recovered from a pre-migration raw safety tar for this run since the
   live file had already been deleted before the bug was caught.

A pre-migration raw safety tar (`/root/alderpointdns-pre-rename-safety-
20260730T004042Z.tar.gz`, taken after checkpointing the SQLite WAL) and a
native BindGuard-branded backup (via the legacy `scripts/backup.sh`,
`bindguard-backup-20260730T004700Z.tar.gz`) were both taken before any
files moved.

### Post-migration verification

- All four services (`named`, `dnsdist`, `alderpointdns`,
  `alderpointdns-analytics`) active and enabled; survived a full manual
  stop/start cycle in dependency order (a literal OS reboot was not
  performed -- it would terminate this session's shell -- this is the
  documented substitute, matching the depth of the prior post-reboot
  verification pass).
- Full `tests/test_acceptance.sh` (19 suites including the new
  `test_rename_migration.sh`) passed clean on the migrated system.
- DNS verified end-to-end: `dnsdist:53` and BIND backend `:5353` both
  resolve; RPZ blocks `bindguard-block-test.invalid` (NXDOMAIN); the real
  local user record `bindguard.home.arpa` -> `172.16.43.101` resolves
  correctly with a matching PTR, confirming user data was never touched.
  `showACL()` on the live dnsdist console still shows only RFC1918/
  loopback/ULA ranges -- no open-resolver exposure introduced.
- DoH/DoT/DoQ/DoH3-capability config all verified via
  `tests/test_dnsdist_frontend.sh` against the regenerated lab cert.
- `alderpointdns-diagnostics --output-dir ... --no-journal` bundle
  inspected: correctly branded, RNDC/TSIG secret still redacted, no
  session secret/API key/private key leakage.
- Native backup/restore verified on the live system three ways: (a) a
  freshly created backup uses `alderpointdns-backup-` naming and a
  `alderpointdns_app_version` manifest key; (b) `preview_restore()` against
  a real pre-rename BindGuard-branded archive
  (`bindguard-backup-20260729T231743Z.tar.gz`, found via `backup_history`)
  correctly reports `compatible: True` with an app-version-mismatch warning
  and real table/file diffs; (c) the unit-test suite's two new
  legacy-archive regression tests pass.
- Sudo-privileged path (`alderpointdns_compiler.py` via the new sudoers
  rule, `bindguard` OS user unchanged) verified working end-to-end.
- Cleaned up stray artifacts created while diagnosing the above: orphaned
  `.tmp` backup files, and a scratch backup made purely to inspect manifest
  content.

No production-impacting failure was concealed or merely documented --
every defect found above was fixed and is now covered by
`tests/test_rename_migration.sh` or `tests/test_backup.py`'s new legacy-
archive tests. Alderpoint DNS is ready to hand to a first external tester
on this checkpoint.

## Post-reboot acceptance: live-database backup race (after rename checkpoint `0e689a0`)

A post-reboot run of `tests/test_acceptance.sh` stopped with `tar:
var/lib/alderpointdns/alderpointdns.db: file changed as we read it` (no
saved run log existed to inspect after the fact, so this was reproduced
live on this box instead).

Root cause: `scripts/backup.sh` (the "native" backup used by
`scripts/upgrade.sh`'s `pre_upgrade_backup()`, `app/importer.py`'s
`create_pre_import_backup()`, and directly by
`tests/test_backup_restore.sh`) tarred
`var/lib/alderpointdns/alderpointdns.db` straight off disk while it was
live -- the `alderpointdns`/`alderpointdns-analytics` services keep the DB
in WAL mode and commit/checkpoint continuously, so a checkpoint landing
mid-tar changes the file's size/mtime out from under `tar`, which reports
the warning and exits 1. Under `set -eu` that aborts `backup.sh` before its
final `mv`, which aborts `tests/test_backup_restore.sh` (a plain command
substitution assignment), which aborts the whole `set -eu` acceptance
suite -- so the run never reached "Alderpoint DNS acceptance suite passed"
and returned a nonzero exit code. Reproduced directly: running the old
`tar -C / -czf ... var/lib/alderpointdns/alderpointdns.db` against the live
DB under a concurrent write+checkpoint loop reliably printed the same
warning with tar exit 1; the app's own `app/backup.py` `create_backup()`
path (used for scheduled timer backups and manual/web backups) was never
affected, since it already builds the archive from a completed
`sqlite3.Connection.backup()` snapshot rather than the live file.

Fix, confined to `scripts/backup.sh`: before tarring, take an online
backup-API snapshot of the live DB (`python3` + `sqlite3.Connection.backup()`,
since this system has no `sqlite3` CLI binary installed) into a fresh
`mktemp -d` under `/var/lib/alderpointdns/staging`, `chown
--reference`/`chmod --reference` the snapshot against the live DB so
ownership/mode survive into the archive, tar the snapshot instead of the
live path (`-C snapshot_root var/lib/alderpointdns/alderpointdns.db`
alongside the existing `-C /` entries), and `trap ... EXIT` the snapshot
dir so it's removed whether the script succeeds or fails. The backup API
handles WAL correctly on its own (folds in committed WAL frames), so no
checkpoint/lock-out of writers was needed. `scripts/restore.sh` needed no
changes -- it only ever extracts whatever `var/lib/alderpointdns/
alderpointdns.db` path is inside the archive, which is now always the
consistent snapshot.

Verified this fixes every caller of the unsafe path: scheduled backups
(timer -> `alderpointdns_compiler.py backup-create` -> `app/backup.py`)
and manual/web backups were already safe; upgrade backups
(`pre_upgrade_backup()`) and import safety backups
(`create_pre_import_backup()`) both shell out to the now-fixed
`scripts/backup.sh`; `alderpointdns-diagnostics` only ever opens the DB
read-only for a schema summary (no tar involved, never affected).

Regression coverage added:

- `tests/test_backup.py::ConcurrentWriteBackupTest` -- runs a background
  writer thread committing+checkpointing against the (redirected, sandboxed)
  test DB while `create_backup()` runs concurrently, then asserts: no "file
  changed as we read it" in the captured `tar` output, a `deployed` history
  row, valid manifest sha256 checksums against the extracted archive,
  `PRAGMA integrity_check` = `ok` on the archived snapshot, a committed-not-
  torn row count, and a successful isolated `restore_backup()` (confined to
  the test's temp sandbox, no real systemctl calls).
- `tests/test_backup_restore.sh` -- extended with a live-system concurrency
  check: creates a throwaway `backup_race_test` table (dropped in a trap
  regardless of outcome), hammers it with committed writes + periodic
  `wal_checkpoint(TRUNCATE)` from a background `python3` process for the
  duration of a real `scripts/backup.sh` run, and asserts exit 0, no tar
  warning in captured stderr, and (via an isolated `tar -x` into a scratch
  dir, never touching live paths) `PRAGMA integrity_check` = `ok` plus a
  row count that never exceeds what the writer had actually committed.

Tests run: `python3 -m unittest tests.test_backup` (36 tests, all pass,
including the new concurrency test); `sh tests/test_backup_restore.sh`
(passed, including the new live race check, with the old raw-tar
reproduction separately confirmed to fail the same way pre-fix);
`sh tests/test_web_smoke.sh` (passed); full `sh tests/test_acceptance.sh`
(exit code 0, ends with "Alderpoint DNS acceptance suite passed" -- the
earlier BIND `allow-proxy` experimental-option notices and the invalid-
RPZ/forced-post-deploy tracebacks are the suite's own expected negative-
path tests, not failures). Services (`named`, `dnsdist`, `alderpointdns`,
`alderpointdns-analytics`) confirmed active after the run. Scratch backup
archives and the throwaway race table created while testing were cleaned
up; pre-existing backup history/files were left untouched.

The post-reboot acceptance check is now complete: the backup race is
fixed at its source (not masked), covered by regression tests at both the
Python and shell layers, and the full acceptance suite passes cleanly
end-to-end.

## v0.4.0-beta.2 usability/interface-polish milestone

Checkpoint commit: `129cb97`. Version bumped `0.4.0-beta.1` ->
`0.4.0-beta.2` (Debian package version `0.4.0~beta2-1`). Scope was
explicitly limited to the 7 named UI/UX items below plus versioning
closeout -- no unrelated major features, no reboot performed (that is
reserved for the human operator per the request).

### 1. Collapsible desktop sidebar (`web/templates/base.html`, `app.css`, `app.js`)

Icon-only rail toggled by a button in the sidebar header; `aria-label`/
`title` on every nav link/section button so meaning survives when the
text label is visually hidden; grouped sections keep their existing
click-to-open behavior but render as a flyout next to the icon instead of
pushing content down while collapsed; state persisted to
`localStorage('alderpointdnsSidebarCollapsed')` and applied via a tiny
blocking inline `<script>` in `<head>` before first paint (no expand-
then-collapse flash). Scoped to `@media (min-width: 841px)` so the
existing separate mobile drawer is untouched.

### 2. Compact Local DNS page (`web/templates/local_dns.html`)

The record table previously rendered a full edit form as a second,
always-visible `<tr>` under every row (that, not the text wrapping, was
the main source of the reported bloat) plus `wrap-anywhere` on hostname/
comment cells, which is what produced the `reverse for adguard.mylan.netwo` /
`rk` mid-word split in the bug report. Fixed: the edit row now starts
`hidden` and opens via a delegated `data-row-edit-toggle` click handler
(so it survives `data-async-form`'s `<main>` innerHTML swaps); hostname/
value cells use `.truncate` (single line, ellipsis, full value in
`title=`) instead of forced character wrapping; the auto-generated
`reverse for <fqdn>` PTR comment renders as a compact "&#8617; reverse of
<target>" badge instead of the raw sentence (the underlying stored
`comment` text is unchanged -- this is a display-only transform, so
export/import/compat behavior is untouched). Actions column uses Edit +
the new overflow menu (see below) instead of three stacked buttons, which
turned out to be the second, larger source of excess row height (button
wrap forced ~150px rows before that fix).

### 3. DNS Settings action cleanup (`web/templates/dns_settings.html`)

Upstream resolver rows: Save (primary) and Enable/Disable (secondary)
stay inline; Move up/Move down/Delete move into a compact overflow menu
with a divider separating the destructive Delete from the routine
reorder actions.

### 4. Blocklists + managed categories (`app/blocklist_categories.py`, `web/templates/blocklists.html`, `app/webapp.py`)

Discovered the database already has a `categories` table (key/name/
description) seeded with sensible defaults -- built for a not-yet-exposed
per-network policy-profile feature (`policy_profiles`/`network_policies`/
`profile_categories`, confirmed still unused by the actual `deploy()` RPZ
compilation path; this remains accurately described by the existing
"modeled but not fully enforced" line in `docs/known-limitations.md`, now
also linked from a new bullet about Recent Logs' scope). Reused that same
table as the managed-category taxonomy for Blocklists instead of adding a
parallel schema: `sources.category` already stored the category *key*
(not display name) in the common case, so **renaming** a category is a
pure metadata update (no source rows touched); **merge** and **delete-
with-reassignment** repoint `sources.category` to the target/fallback
key; a **migration** function normalizes/deduplicates whatever free-text
values existing rows had (matches by normalized display name first, so
e.g. "Ads and Trackers" typed with different casing merges into the
existing `ads_trackers` category instead of creating a near-duplicate)
and is idempotent. `Uncategorized` is a protected built-in that can't be
renamed/merged/deleted. The source table itself is compact with category/
status/health badges, an Edit-row + overflow-menu actions column, and
server-side search/category/status filters plus sorting.

### 5. System Status Recent Logs (`app/service_logs.py`, `app/alderpointdns_compiler.py`, `packaging/sudoers-alderpointdns`)

Root cause: `system_page()` ran `journalctl -u alderpointdns` directly as
the unprivileged `bindguard` web user, which has no journal group
membership on a fresh install, so the page rendered journald's own
"insufficient permissions" hint text. Fixed with the same pattern every
other privileged web action in this app already uses -- a fixed,
sudoers-enumerated subcommand (`alderpointdns_compiler.py logs <unit>`),
one literal sudoers line per allowed unit (`alderpointdns`,
`alderpointdns-analytics`, `named`, `dnsdist`; verified a 5th, disallowed
unit is rejected by sudo itself, not just by application-layer
validation). The helper always fetches a fixed-size window via
`journalctl -o json --output-fields=...` (line count/severity are never
threaded through to the privileged call -- they're applied web-side to
the already-fetched, already-sanitized buffer) and redacts common secret
shapes (passwords, API keys, tokens, Basic/Bearer auth headers, PEM
private keys) before the JSON ever leaves the root process. Discovered
and fixed a real robustness bug while wiring this up: `sudo` on this VM
prints `sudo: unable to resolve host bindguard-1: ...` to stderr on every
invocation (a pre-existing `/etc/hosts` mismatch left over from the
BindGuard->Alderpoint rename, unrelated to this milestone and out of
scope to fix here) -- the shared `run()` helper merges stderr into
stdout, which would have corrupted the strict-JSON parse, so the new
`fetch_service_log_entries()` calls `subprocess.run()` directly with
stdout/stderr kept separate instead of reusing `run()`. System Status now
has service/severity/line-count selects, Refresh, and auto-refresh
(reusing the existing generic `#autoRefresh`/`data-refresh-url`
mechanism), and a friendly empty state (no raw journalctl text) when logs
are unavailable. Fresh installs and upgrades both pick up the new
sudoers entries automatically since both already deploy
`packaging/sudoers-alderpointdns` verbatim -- verified via the dry-run
installer/upgrade tests plus a real `install -D` + `visudo -cf` onto this
VM's actual `/etc/sudoers.d/alderpointdns` and an end-to-end
`runuser -u bindguard -- sudo -n ... logs <unit>` call.

### 6. Dashboard/System Status health card word-splitting (`web/static/app.css`)

Root cause: a blanket `.card *, .panel *` selector forced
`overflow-wrap: anywhere; word-break: break-word` onto every descendant
of a card/panel, including status badges and headings, so short single-
word labels split mid-character whenever a card got tight ("Healthy" ->
"Heal"/"thy", "DNSSEC" -> "DNSSE"/"C", "Alderpoint DNS"/"Backend health"
wrapping was actually fine -- only the *badge* text below them was
splitting). Removed `.card`/`.card *`/`.panel`/`.panel *` from that rule,
added a targeted rule forcing normal word wrapping on card/panel
headings and `.status-badge`, and let the card head row itself
`flex-wrap` so a badge that doesn't fit drops to its own line instead of
being crushed into a mid-word split. Table headers (`th`) had the same
generic rule and produced the same bug on narrow columns (confirmed live:
"HEALTH" -> "HEA"/"LTH" in the Blocklists table header) -- given their
own `white-space: nowrap; text-overflow: ellipsis` treatment instead.
Also widened the Dashboard System Health grid's minimum card width
(190px -> 210px via a new `.grid.health` class).

### 7. Shared compact visual standards

Added reusable primitives in `app.css`/`components.html`/`app.js`:
`.table-compact` (reduced padding/row height, including a rule that keeps
Edit+overflow-menu-trigger on one line instead of wrapping to two, which
was the single largest remaining source of excess row height after the
Local DNS edit-row fix), `.category-badge`, `.overflow-menu` (event-
delegated open/close/outside-click/Escape, `role="menu"`/`menuitem`), and
the `data-row-edit-toggle` pattern -- all reused across Local DNS, DNS
Settings, and Blocklists rather than three separate implementations.

### Verification

- `python3 -m unittest discover -s tests -p "test_*.py"`: 190 tests, all
  pass (includes two new modules: `tests/test_service_logs.py`,
  `tests/test_blocklist_categories.py`).
- `sh tests/test_web_smoke.sh`: passed, including new assertions for the
  sidebar-collapse/table-compact/overflow-menu CSS+JS hooks, a regression
  guard against the `.card */.panel *` selector reappearing, rendered-
  content checks for the category dropdown/management panel, the reverse-
  record badge, the DNS Settings overflow menu, and Recent Logs' friendly
  empty state (plus an assertion `webapp.py` never calls `journalctl`
  directly).
- `sh tests/test_install_upgrade_diagnostics.sh`: passed, including new
  assertions that both the fresh-install and upgrade dry-run plans
  install `packaging/sudoers-alderpointdns`, that the file's log-access
  entries are the exact 4 allowlisted units (no wildcards), and that
  `visudo -cf` accepts it.
- `sh tests/test_beta_hardening_docs.sh`: passed.
- Full `sh tests/test_acceptance.sh`: exit code 0, ends with "Alderpoint
  DNS acceptance suite passed" (the BIND `allow-proxy` experimental-
  option notices and the invalid-RPZ/forced-post-deploy tracebacks are
  the suite's own expected negative-path tests).
- Service restart cycle: `systemctl restart named dnsdist alderpointdns
  alderpointdns-analytics` -- all four `active` afterward.
- DNS checks after restart: plain query resolves (`example.com` via
  `127.0.0.1:5353`), local DNS resolves (`adguard.mylan.network` ->
  `172.16.43.9`), reverse DNS resolves (`172.16.43.9` -> PTR), filtering
  confirmed (`doubleclick.net` -> `NXDOMAIN` through the real client
  frontend on port 53), encrypted listeners confirmed bound on `:443`/
  `:853` (both IPv4 and IPv6).
- Fresh backup: `scripts/backup.sh` run manually post-restart, exit 0, no
  tar warning; extracted snapshot's `PRAGMA integrity_check` = `ok`. This
  file was left in place (a real, valid backup, not test scratch).
- Visual verification: logged in as a temporary admin account (created
  for this purpose, deleted afterward -- only the original `admin`
  account remains), fetched each changed page's authenticated HTML,
  screenshotted with headless `chromium --screenshot` at 1440x900
  (desktop), 834x1112 (tablet), and 390x844 (mobile) for Dashboard, Local
  DNS, DNS Settings, Blocklists, and System Status, plus an isolated
  System-Health-fragment screenshot confirming no word ever splits mid-
  character at any width. Screenshots are in the session scratchpad
  (`/tmp/.../scratchpad/shots/`), not committed to the repo. This process
  caught two real layout bugs neither the CSS-substring test nor a code
  read would have surfaced (both fixed and reverified before committing):
  the Actions-column button-wrap row-height regression in Local DNS/
  Blocklists, and the `th` mid-word split / header-overlap on Blocklists'
  "Health" column.
- Commit self-containment: each of the first 5 commits was checked out
  into an isolated `git worktree` and `import app.webapp` (plus, for the
  Recent Logs commit, the new unit test module) verified to succeed
  standalone -- catching and fixing (via a targeted `git update-index` +
  `commit --amend`, safe here since none of this was pushed anywhere) one
  real mistake where the Blocklists commit's import-line hunk had pulled
  in an unrelated `service_logs` import that didn't exist as a file until
  the next commit.

### Side notes (not milestone bugs, disclosed for transparency)

- While cleaning up the temporary screenshot-verification admin account,
  a stray SQL statement (`DELETE FROM login_attempts WHERE ip NOT IN
  (... LIMIT 0)`) unintentionally cleared the `login_attempts` table
  (used only for the 15-minute failed-login rate-limit window). No
  functional impact -- no real admin data, DNS records, config,
  certificates, or backups were affected -- but noted here rather than
  silently left out.
- The `sudo: unable to resolve host bindguard-1: ...` stderr warning seen
  on every sudo call on this VM is a pre-existing `/etc/hosts` leftover
  from the BindGuard->Alderpoint rename (the hostname is still literally
  `bindguard-1`, but `/etc/hosts` only maps `alderpointdns-1...`). Out of
  scope for this milestone; worked around (not fixed) in the new Recent
  Logs code by not relying on merged stdout/stderr.
- `packaging/sudoers-alderpointdns` was installed onto this VM's real
  `/etc/sudoers.d/alderpointdns` (via the same `install -D -m 0440` +
  `visudo -cf` the installer/upgrade scripts already run) to verify the
  Recent Logs feature end-to-end as the real `bindguard` user. This is
  the expected steady-state file content going forward, not a one-off.

Remaining for the human operator: reboot the VM and follow
`POST_REBOOT_HANDOFF.md`.

## v0.4.0-beta.2 post-reboot backup interruption fix

Started from Claude Code's unfinished post-reboot state after the VM had
already rebooted. Initial audit showed exactly two modified files:
`scripts/backup.sh` and `tests/test_backup_restore.sh`; no staged changes and
no untracked files. Services (`named`, `dnsdist`, `alderpointdns`,
`alderpointdns-analytics`) were enabled/active. Recent journals showed normal
startup/restart activity, expected BIND `allow-proxy` warnings, and the
pre-existing `sudo: unable to resolve host bindguard-1` warning, but no crash
loops or migration failures.

Defect: an interrupted `scripts/backup.sh` run could leave project-owned
temporary artifacts behind, especially a partially-created
`alderpointdns-backup-*.tar.gz.tmp` in the real backup directory. A failed
regression attempt also reproduced a stale `backup-snapshot.*` directory when
the test sent `INT` in a way `/bin/sh` could not trap.

Root cause: the previous script only removed the SQLite snapshot directory via
an `EXIT` trap. `/bin/sh` needs explicit `INT`/`TERM`/`HUP` traps to exit after
cleanup, and cleanup must include the in-progress archive. The regression test
also needed to reset inherited ignored `SIGINT` handling before launching the
background backup process; otherwise dash cannot install an `INT` trap.

Fix:

- `scripts/backup.sh` now sets `umask 077` before creating temporary archive
  files.
- Cleanup is idempotent and pattern-constrained to
  `/var/lib/alderpointdns/staging/backup-snapshot.*` and
  `/var/lib/alderpointdns/backups/alderpointdns-backup-*.tar.gz.tmp`, so empty
  or malformed variables cannot remove unrelated paths.
- `INT`, `TERM`, and `HUP` run cleanup and exit `143`.
- Normal success still atomically moves `$tmp` to the final archive path, then
  chmods the completed archive to `0640`; the cleanup trap only targets the
  `.tmp` path and cannot remove a completed final archive.
- Added a narrow test-only pause hook
  (`ALDERPOINTDNS_BACKUP_TEST_PAUSE_AFTER_TMP_CREATE`) so the live regression
  can deterministically interrupt after the `.tmp` archive exists.
- `tests/test_backup_restore.sh` now verifies successful backup creation,
  archive mode `0640`, no live-database tar race warning, SQLite integrity,
  restore health, and interrupted `INT`/`TERM`/`HUP` runs with no orphaned
  `.tmp` archives or `backup-snapshot.*` directories.

Validation:

- `/opt/alderpointdns/tests/test_backup_restore.sh`: passed. It still prints
  the known unrelated `sudo: unable to resolve host bindguard-1` warning.
- `python3 -B tests/test_backup.py`: 36 tests passed, covering manifest
  checksums, SQLite integrity, secret stripping, encrypted backup
  round-trips, isolated restore, rollback behavior, and legacy archive
  compatibility.
- A direct rerun of `/opt/alderpointdns/tests/test_dnsdist_frontend.sh` passed
  after one transient immediate-after-restore DoQ query failure during an
  earlier backup/restore run; dnsdist listeners and logs showed the DoQ
  listener active.

## v0.4.0-beta.2 post-reboot unit-test isolation fix

Full `python3 -m unittest discover -s tests -p "test_*.py"` initially failed
in `tests/test_analytics.py::AnalyticsTests.test_query_log_filtering` with
`sqlite3.OperationalError: attempt to write a readonly database`.

Root cause: analytics tests redirected `analytics.DB_PATH` and
`alderpointdns_compiler.DB_PATH` to a temporary database, but
`analytics.query_log()` decorates query rows through
`local_dns.alias_for_client()`. `local_dns.DB_PATH` was not redirected in the
analytics test fixture, so full-suite order could leave it pointing at another
test's cleaned-up database.

Fix: `tests/test_analytics.py` now redirects `local_dns.DB_PATH` to the same
temporary database during setup and restores the original path during teardown.

Validation:

- `python3 -B tests/test_analytics.py`: 24 tests passed.
- `python3 -m unittest discover -s tests -p "test_*.py"`: 190 tests passed.
  The known pre-existing backup-test SQLite `ResourceWarning` messages still
  print, but the final exit status was zero.

## v0.4.0-beta.2 post-reboot verification closeout

Completed the post-reboot handoff on the already-rebooted VM. No second reboot
was performed.

Commits created after checkpoint `6fe3788` during this continuation:

- `462e90f` Clean interrupted backup artifacts.
- `0c32547` Fix analytics test database isolation.

Service verification:

- `systemctl is-active named dnsdist alderpointdns alderpointdns-analytics`:
  all four `active`.
- `systemctl is-enabled named dnsdist alderpointdns alderpointdns-analytics`:
  all four `enabled`.
- Recent warning-level journals for the four services showed only the expected
  BIND `allow-proxy` / `allow-proxy-on` experimental warnings. No startup
  failures, crash loops, permission errors, migrations failures, TLS/listener
  failures, or backup errors were found.

Listener and DNS verification:

- `ss -ltnup` confirmed dnsdist on UDP/TCP `0.0.0.0:53` and `[::]:53`, DoH/
  DoH3 on `:443`, DoT/DoQ on `:853`, BIND backend on `127.0.0.1:5353`/
  `127.0.0.1:5354` and `::1:5353`, web on `0.0.0.0:3000` and `0.0.0.0:8843`,
  analytics on `127.0.0.1:5301`, and dnsdist management on loopback only
  (`127.0.0.1:8083`, `127.0.0.1:5199`).
- dnsdist frontend resolution: `dig @127.0.0.1 example.com A +short` returned
  A records.
- BIND backend resolution: `dig @127.0.0.1 -p 5353 example.com A +short`
  returned A records.
- Local A: `dig @127.0.0.1 -p 5353 adguard.mylan.network A +short` returned
  `172.16.43.9`.
- Local AAAA: no AAAA record is configured for `adguard.mylan.network`; the
  query returned no answer with exit status 0.
- PTR: `dig @127.0.0.1 -p 5353 -x 172.16.43.9 +short` returned
  `adguard.mylan.network.`.
- RPZ filtering: `dig @127.0.0.1 doubleclick.net A` returned `NXDOMAIN` with
  the `alderpointdns.rpz` SOA.
- DNSSEC path: `dig @127.0.0.1 . DNSKEY +dnssec +short` returned DNSKEY/RRSIG
  data.
- `/opt/alderpointdns/tests/test_dnsdist_frontend.sh`: passed, covering UDP,
  TCP, DoH, DoT, DoQ, DoH3 capability config, dnsdist stats authentication,
  loopback-only management listeners, ACL config, restart/recovery, and PROXYv2
  client-address preservation.
- Upstream resolver health: four imported plain upstreams (`1.1.1.2`,
  `1.0.0.2`, `4.2.2.1`, `4.2.2.2`) are enabled and `healthy`.
- Per-upstream analytics: live
  `upstream_resolver_aggregate_buckets` rows exist with `health_state='up'`;
  recent resolver 1 buckets showed successful query counts with zero failures.
- Recursion ACLs: dnsdist runtime environment does not set
  `ALDERPOINTDNS_DNS_ALLOW_ALL`; config uses the intended RFC1918, loopback,
  and `fc00::/7` ACL set. No accidental open-resolver exposure was found.

Recent Logs verification:

- `runuser -u bindguard -- sudo -n /opt/alderpointdns/app/alderpointdns_compiler.py logs alderpointdns`
  returned valid JSON log entries. The known unrelated `sudo: unable to
  resolve host bindguard-1` warning still prints to stderr, but does not
  corrupt stdout JSON.
- `runuser -u bindguard -- sudo -n /opt/alderpointdns/app/alderpointdns_compiler.py logs sshd`
  was denied by sudo itself (`sudo: a password is required`).
- Rendered System Status did not show raw `journalctl` or insufficient-
  permissions notices.

Rendered UI verification:

- Created temporary admin `codex_post_reboot` only for Chromium inspection;
  removed it afterward and confirmed zero remaining rows for that username.
- `python3 /tmp/alderpointdns_ui_inspect.py` drove headless Chromium through
  DevTools Protocol and passed all rendered checks:
  login, desktop expanded sidebar, desktop collapsed sidebar, collapsed
  persistence across reload, expansion restore, mobile drawer open, compact
  Local DNS rows/edit controls, PTR relationship display, DNS Settings overflow
  actions, Blocklist category controls/compact table, Recent Logs content with
  no permission notice, and Dashboard health labels/status text.
- Screenshots were captured under `/tmp/alderpointdns-ui/` for Dashboard,
  Local DNS, DNS Settings, Blocklists, and System at desktop (`1440x900`),
  tablet (`900x900`), and mobile (`390x844`) widths. Sampled desktop Dashboard
  and mobile Local DNS screenshots showed intact layout with no incoherent
  overlap or normal-word mid-word splitting.

Backup and restore verification:

- `/opt/alderpointdns/tests/test_backup_restore.sh`: passed, covering live
  successful backup, restore health, concurrent-write backup race regression,
  archive mode `0640`, interrupted `INT`/`TERM`/`HUP` cleanup, no orphaned
  `.tmp` archives, and no orphaned snapshot directories.
- Fresh live low-level backup:
  `/var/lib/alderpointdns/backups/alderpointdns-backup-20260730T035950Z.tar.gz`
  exited 0, mode `0640`, included the SQLite snapshot, and the extracted
  database returned `PRAGMA integrity_check = ok`.
- App-managed default backup:
  `/var/lib/alderpointdns/backups/alderpointdns-backup-20260730T040030Z.tar.gz`
  included `manifest.json`, had zero checksum mismatches, excluded private
  keys and `etc/alderpointdns/secrets.env`, and the extracted database returned
  `PRAGMA integrity_check = ok`.
- Final cleanup checks found no `*.tar.gz.tmp` files in
  `/var/lib/alderpointdns/backups` and no `backup-snapshot.*` directories in
  `/var/lib/alderpointdns/staging`.
- Live services remained active after backup checks.

Test verification:

- `python3 -B tests/test_backup.py`: 36 tests passed.
- `/opt/alderpointdns/tests/test_backup_restore.sh`: passed.
- `python3 -B tests/test_analytics.py`: 24 tests passed.
- `python3 -m unittest discover -s tests -p "test_*.py"`: 190 tests passed
  (known pre-existing SQLite `ResourceWarning` messages still print).
- `./tests/test_web_smoke.sh`: passed.
- `./tests/test_acceptance.sh`: passed with final line
  `Alderpoint DNS acceptance suite passed`. Expected invalid-RPZ and forced
  rollback tracebacks appeared during negative-path tests.
- `./tests/test_beta_hardening_docs.sh`: passed.
- `./tests/test_install_upgrade_diagnostics.sh`: passed.
- `python3 -B tests/test_local_dns.py`: 17 tests passed.
- `python3 -B tests/test_blocklist_categories.py`: 12 tests passed.
- `python3 -B tests/test_service_logs.py`: 9 tests passed.
- `python3 -B tests/test_upstream_dns.py`: 7 tests passed.
- `/opt/alderpointdns/tests/test_dnsdist_frontend.sh`: passed.

Known limitations / notes:

- The VM still has the pre-existing hostname-resolution warning
  `sudo: unable to resolve host bindguard-1`; it is unrelated to beta.2
  correctness and does not break Recent Logs because stdout/stderr are kept
  separate.
- The documented BIND `allow-proxy` and `allow-proxy-on` experimental warnings
  remain expected.
- Default app-managed backups strip secrets/private keys; the low-level
  `scripts/backup.sh` full system archive intentionally includes
  `/etc/alderpointdns` as part of disaster-recovery coverage.

Result: Alderpoint DNS v0.4.0-beta.2 post-reboot verification is complete and
ready for external testing.

## Final pre-public-release milestone (in progress, checkpoint `9082d98`)

Started from clean `main` at `c4221c8` (Dex's Import/Migration route-conflict
fix, already committed and verified: 8/8 tests in `tests/test_import_routes.py`
pass; preserved as-is, not reimplemented). Mission: three remaining product
requirements before the first public GitHub upload -- (1) first-class custom
filtering rules + correct AdGuard Home/Pi-hole migration, (2) configurable
automatic filter update interval, (3) certificate settings panel layout fix.
Former-name cleanup is a separate, already-completed milestone; this pass
preserves the zero-trace requirement throughout (verified: no new `bindguard`-
product-name references introduced; the `bindguard` OS user is intentionally
unchanged).

Ran as four parallel subagents in isolated git worktrees (A/C/D built on `main`
directly; B built on the post-A/C merged `main` since it depends on A's model),
with this session doing central coordination, conflict resolution, live
integration, and verification. Progress logged here mid-run per an explicit
stop-and-log request; **Workstream B (migration) is still running in the
background at this checkpoint** -- everything below it is what has actually
landed and been live-verified so far, not a final closeout.

### Workstream D -- Certificate settings panel layout (complete, merged `ac0c5ae`)

Root cause: `web/templates/encryption.html`'s Protocols/Certificate `<section
class="grid">` inherited CSS grid's default `align-items: stretch`, so
expanding any Certificate `<details>` (self-signed, local CA, upload, existing
paths) stretched the unrelated Protocols panel and left artificial empty space
inside it (because `.stack` is itself a grid with `align-content: stretch`,
redistributing the borrowed height across every Protocols control).

Fix: added a scoped `.grid.align-start` utility (`align-items: start`) in
`web/static/app.css` and applied it to that one section only -- the global
`.grid` rule (used for card grids elsewhere) is untouched. Added
`tests/test_encryption_layout.sh`, a headless-Chromium regression harness
(renders the real template into a temp dir with file://-friendly static
assets, measures real layout at 1680x1000/1366x900/900x900/390x844) wired into
`tests/test_acceptance.sh`. Demonstrated the defect pre-fix (Protocols grew up
to +172px at wide desktop) and a clean pass post-fix (Protocols delta 0px at
every width across all four Certificate sections, Certificate panel grows
normally, no horizontal overflow, mobile stacks correctly). Subagent D also
found and reported (without touching, to stay scoped) the identical defect on
two more pages; this session applied the same one-line `.grid.align-start` fix
to both in a fast follow-up commit (`1799977`):
`web/templates/dns_cache.html` (Cache Tuning / Flush Cache) and
`web/templates/backup.html` (Create Backup / Import Backup).

Verified live: re-ran `tests/test_encryption_layout.sh` from `/opt/alderpointdns`
post-merge -- passes at all four widths with the exact figures above.

### Workstream C -- Configurable filter update scheduling (complete, merged `6989ccb`, follow-up fix `9082d98`)

New `app/filter_schedule.py` mirrors the existing `app/backup.py` scheduled-
timer architecture exactly: a `filter_update_settings` key/value table
(`interval_hours`, `last_attempt`, `last_success`, `last_result`), a fixed
server-side allowlist (`disabled`, `1`, `12`, `24`, `72`, `168` hours mapped to
the exact required labels `Disabled — No Updates`/`1 Hour`/`12 Hours`/
`1 Day`/`3 Days`/`1 Week`, default `1 Day` on fresh init, never overwritten
once set), and a `filter-schedule-deploy` compiler subcommand that renders the
`OnBootSec=`/`OnUnitActiveSec=` drop-in from the allowlist mapping only (never
from user text) at `/etc/systemd/system/alderpointdns-filter-update.timer.d/
alderpointdns.conf`, enabling/disabling the new
`alderpointdns-filter-update.{service,timer}` units. A `filter-update-run`
subcommand (timer-invoked, root) records `last_attempt`, delegates to the
existing `deploy(download=True, trigger="scheduled")` (unchanged flock/
enabled-lists-only/rollback guarantees), and records `last_success` +a
sanitized `last_result` only on success. Added a nullable `deployments.trigger`
column via the existing idempotent `_ensure_column` migration pattern.
Blocklists page gained a compact "Automatic Updates" panel (interval select,
enabled/disabled badge, last attempt/success, next scheduled update, Save
schedule, Update All Now) that shows "Automatic updates disabled" with no
next-run time when disabled. Both new sudoers lines added as single literal
command strings (no wildcards); `visudo -cf` clean. Installer/upgrade/Debian
packaging updated to install and enable the new units per the backup-timer
pattern.

Live verification performed by this session after merging:
- Installed the two new unit files + updated sudoers to the real system,
  `visudo -cf` clean, `daemon-reload`.
- `alderpointdns_compiler.py deploy --no-download` (creates the new schema),
  then `filter-schedule-deploy` -- confirmed `alderpointdns-filter-update.timer`
  enabled with the `1 Day` drop-in and a real scheduled next run.
- Triggered a real scheduled run (`systemctl start
  alderpointdns-filter-update.service`): produced `deployments` row (id 322,
  `status=deployed`, `trigger=scheduled`, 481,823 active domains) and correct
  `last_attempt`/`last_success`/`last_result` rows in the new settings table.
- Full disable -> manual-update-still-works -> re-enable cycle tested live:
  disabling stopped the timer cleanly (`systemctl is-active` -> inactive, no
  drop-in confusion) while `runuser -u bindguard -- sudo -n ... update-sources`
  still worked; re-enabling restored the exact prior cadence.
- Restarted `alderpointdns`; all four services stayed active; web smoke suite
  passed.
- **Real defect found and fixed live** (`9082d98`, not just documented):
  `next_run_at()` originally read only `systemctl show ... 
  NextElapseUSecRealtime`, which is empty for monotonic
  (`OnBootSec`/`OnUnitActiveSec`) timers -- exactly what this feature uses --
  so the Blocklists panel showed "Unknown until timer deploys" even with the
  timer correctly armed. Confirmed by direct Chromium screenshot inspection of
  the live authenticated page. Fixed by preferring `systemctl list-timers
  --all -o json`'s projected `next` field (converted from the epoch-microsecond
  value to an ISO timestamp) with the original property parse kept as a
  fallback for systemd versions without JSON list-timers support. Added 2 new
  regression tests (`tests/test_filter_schedule.py`, now 51 tests, all
  passing); reran live and confirmed the panel now shows a real timestamp
  (`2026-07-31T03:20:06+00:00`) matching `systemctl list-timers` directly.

### Workstream A -- First-class custom filtering rules (complete, merged `93c594e` + fixture fix `bbc1bd3`)

New `app/custom_rules.py` (~1450 lines) and `custom_filter_rules` table --
full typed model (`rule_text`, `normalized`, `rule_type`, `action`, `domain`,
`match_subdomains`, `pattern`, `rewrite_address`, `address_family`,
`qtype_restriction`, `priority`, `enabled`, `validation_state`,
`unsupported_reason`, `source_system`, `import_job_id`, `comment`,
timestamps). Parser (`parse_rule`) classifies `||domain^` (subdomain block),
`@@||domain^` (subdomain allow/exception), hosts-style lines (`0.0.0.0`/
`127.0.0.1`/`::`/`::1` sentinels -> exact block; any other address -> exact
rewrite preserving IPv4/AAAA family; multiple aliases -> one rule per
hostname; inline comments preserved), `!`/`#` comments (no DNS effect, never
"failed"), `/REGEX/` (validated against a conservative POSIX-ERE-compatible
subset since dnsdist's `RegexRule` uses `regcomp`; incompatible/invalid
patterns stored inactive with an exact reason, never silently dropped or
treated as a literal domain), plain domains (subdomain-inclusive by default
per AdGuard semantics, with a `plain_domain_subdomains=False` parameter for
exact-only callers like the coming Pi-hole importer), and AdGuard `$`
modifiers (`$important` honored as a priority boost; `$dnsrewrite` with a
plain address translated; everything else -- `$client`, `$dnstype`,
`$ctag`, `$badfilter`, unsupported `$dnsrewrite` forms -- stored inactive with
an exact reason, and the underlying base rule is never silently broadened and
activated).

Documented, deterministic compile-time precedence (`docs/filtering.md`): local
DNS zones > exact rewrites > explicit allow rules (subdomain-aware
compile-time subtraction from external blocklists + emitted `rpz-passthru.`
records so allows survive blocklist refreshes without ever mutating stored
blocklist data) > explicit block rules (exact rules emit no wildcard, so no
accidental parent-zone takeover) > regex allow > regex block (dnsdist layer,
ordered so it can never override local/rewrite/allow precedence) > external
blocklists. Same-owner-name conflicts: rewrite > allow > block, with
`$important` (priority 100) able to let a block beat a normal allow. RPZ
rendering and a new guarded `dofile()` include in `packaging/dnsdist.conf`
(`compiled/dnsdist/custom-rules.conf`, static Lua only -- rule text/patterns
live in plain data files read with `io.lines`, never interpolated into Lua
code) both extended; `deploy()` now stages, validates, atomically activates,
health-checks (including a rewrite-resolves check), and rolls back the new
layers under the existing `DEPLOY_LOCK`. Legacy `custom_rules` rows migrated
once, idempotently, into the new table (`source_system='legacy'`,
subdomain-inclusive, enabled/comment/created_at preserved) via the existing
`_ensure_column`-style pattern; the legacy table is left intact but frozen
(marked `migrated_to_v2`) and no longer read by the compile path. New compact
Filters UI (`/custom-rules`): counts strip, single-line add form + collapsible
bulk editor (per-line validation results), search/type/status filters,
bulk-selectable compact table with type/action/state/source badges and hidden
per-row editors, and a "Test a Domain" panel backed by a new
`evaluate_domain()` API. `custom_filter_rules` wired into `app/backup.py`
(existing `custom_rules` component now covers both tables) and
`app/replication.py` (`REPLICABLE_TABLES`, excluding the node-local
`import_job_id`).

Merge required resolving 4 conflicts against the already-merged Workstream C
(`app/alderpointdns_compiler.py` import list + `init_db` wiring, `app/webapp.py`
import list, `docs/web.md`, `tests/test_analytics.py`) -- all simple unions,
no logic lost on either side; verified with `py_compile` and a full test run
immediately after. One test fixture broke on merge
(`tests/test_web_smoke.sh`'s `custom_rules.html` mock context still used the
old flat `rules=[{domain, action, enabled, comment}]` shape and was missing
`counts`/filter/test-panel context the new template requires) -- fixed in
`bbc1bd3` with a fixture matching the real row shape; smoke suite now passes.

Live verification performed by this session after merging:
- `alderpointdns_compiler.py deploy --no-download`: all 7 pre-existing legacy
  custom rules (including the real `bindguard-block-test.invalid` deployment-
  test record) migrated correctly with identical live DNS behavior to the
  pre-migration baseline (apex and subdomain both NXDOMAIN, matching the
  recorded baseline dig output).
- Added 5 live test rules through the new `add_rule()` API covering every
  required form -- a regex block, an anchored+case-varied regex block, a
  non-sentinel IPv4 rewrite, a `0.0.0.0` exact block, and an allow overriding
  an external blocklist entry (`doubleclick.net`) -- redeployed, and confirmed
  every one live via `dig` through the real dnsdist frontend: regex blocks
  return NXDOMAIN case-insensitively including with a trailing-`$` anchor,
  the rewrite returns exactly `192.168.77.7` (not a generic block), the exact
  `0.0.0.0` block carries the RPZ SOA on the apex but leaves an unrelated
  subdomain fully unaffected (no parent-zone takeover), and the allow rule
  made `doubleclick.net` resolve normally despite being on an active
  subscription blocklist. Removed all 5 test rules, redeployed, and confirmed
  `doubleclick.net` returned to NXDOMAIN (no residual state).
  services stayed active throughout; the dnsdist restart path (only
  restarted when the custom-rule dnsdist layer content hash actually changes)
  worked correctly.
- Ran the targeted shell suites this workstream's sandboxed tests could not
  exercise: `tests/test_blocklist_deploy.sh`, `tests/test_blocklist_failure_paths.sh`
  (rollback-on-failure still correct with the new layers present),
  `tests/test_dnsdist_frontend.sh`, `tests/test_install_upgrade_diagnostics.sh`,
  `tests/test_beta_hardening_docs.sh` -- all passed.
- Chromium screenshots of the live authenticated Filters and Blocklists pages
  at 1440x900/900x900/390x844 -- compact, correctly badged, correctly stacked
  on mobile. Used a temporary throwaway admin account for the authenticated
  fetch, confirmed deleted afterward (0 residual rows, 1 real admin remains).

### Workstream B -- AdGuard Home / Pi-hole migration (in progress, not yet merged)

Launched in its own worktree on top of the merged A+C `main`, with a detailed
brief covering: routing every AdGuard `user_rules` line and Pi-hole export
line through Workstream A's typed `parse_rule`/`add_rule` API (replacing the
current lossy classification in `app/importer.py`) instead of the legacy
`custom_rules` table; correct AdGuard-vs-Pi-hole plain-domain semantics
(subdomain-inclusive vs exact-only); full per-item categorized preview with
per-item/per-category deselection; transactional apply with a real
mid-apply-failure test proving no partial state in any destination table;
rollback extended to remove `custom_filter_rules` by `import_job_id`;
sanitized downloadable migration reports (no credentials/tokens/URLs with
embedded auth); SSRF/size/line-count limits on the AdGuard API fetch and file
uploads; and explicit preservation of Dex's `/import/jobs/{job_id}` route
fix. **Still running at this checkpoint -- not reviewed, not merged, no live
verification performed yet.**

### Overall test status at this checkpoint

- `python3 -m unittest discover -s tests -p "test_*.py"`: **296 tests, all
  passing** (198 baseline + 49 Workstream A + 48 Workstream C + 1 net from the
  Workstream C next-run regression fix).
- `tests/test_web_smoke.sh`: passing.
- `tests/test_encryption_layout.sh`, `tests/test_blocklist_deploy.sh`,
  `tests/test_blocklist_failure_paths.sh`, `tests/test_dnsdist_frontend.sh`,
  `tests/test_install_upgrade_diagnostics.sh`,
  `tests/test_beta_hardening_docs.sh`: all passing.
- Not yet run at this checkpoint: the full `tests/test_acceptance.sh`,
  `tests/test_replication.py`(spot-checked: 5 tests pass, `custom_filter_rules`
  correctly present in `REPLICABLE_TABLES`), a full backup/restore round-trip
  covering the two new tables/settings, and anything specific to Workstream B
  once it lands.

### Explicitly not done yet

- Workstream B implementation, review, and merge.
- Final full integration pass across all four workstreams together
  (interactions like "custom allow rules survive a scheduler-triggered
  automatic blocklist refresh with imported rules present" need an end-to-end
  check once B is in).
- Full `tests/test_acceptance.sh` run.
- Independent final-review subagent.
- Version/changelog/CHANGELOG.md closeout, final commit, and completion
  report.
- No reboot has been performed or requested at this checkpoint; not blocked
  on one so far.

Stopping here per an explicit stop-and-log-progress request. Subagent B
continues running in the background and will be integrated (reviewed, merged,
conflict-resolved, live-verified) when it completes, followed by the full
verification battery, independent review, and closeout described in the
mission brief.

### Update: Workstream B interrupted (not a normal completion)

Immediately after the log entry above was written, Subagent B's task
notification arrived with `status: failed` -- terminated by the coordinating
account hitting its monthly API spend limit, not a bug in B's own work. Its
last progress line was `Full suite green (328 tests). Now the documentation.`,
i.e. it had finished implementation and testing and was interrupted only
during the documentation step, before making any of its three planned logical
commits.

Confirmed by inspecting its worktree directly (read-only `git status`/`log`,
no further agent spend): `/opt/alderpointdns/.claude/worktrees/
agent-ae3d7e95f4817a7d9` still exists, branch `worktree-agent-ae3d7e95f4817a7d9`,
HEAD still at the pre-B checkpoint `bbc1bd3` (no commits made), with 10 files
of real uncommitted work sitting in the worktree: modified
`app/custom_rules.py`, `app/importer.py`, `app/webapp.py`,
`docs/adguard-parity.md`, `docs/known-limitations.md`, `docs/migration.md`,
`tests/test_import_routes.py`, `tests/test_importer.py`,
`web/templates/import_migration.html`, plus a new untracked
`tests/fixtures/` directory. **This work is not lost** -- it is intact on
disk in the worktree, uncommitted, pending review and a resumed session.

Per the explicit stop instruction, no further agent work was launched to
avoid immediately re-hitting the same spend limit. Next session should:
1. Resume/inspect the `agent-ae3d7e95f4817a7d9` worktree's uncommitted diff.
2. Verify the claimed "328 tests, all green" independently
   (`python3 -m unittest discover -s tests -p "test_*.py"` inside that
   worktree) before trusting it.
3. Have it (or a fresh reviewer) finish the documentation step and make the
   three planned commits ("Import AdGuard custom filtering rules", "Import
   Pi-hole filtering data correctly", "Add migration preview, apply,
   rollback, and reports").
4. Then proceed with merge, conflict resolution, live verification,
   independent review, full acceptance run, and closeout as originally
   planned.

## Workstream B completed, integrated, and live-verified (checkpoint after `531ea25`/`dd4caa8`)

Resumed from the interrupted worktree above. Independently verified the
claimed test count first, per the note-to-self above: `python3 -m unittest
discover -s tests -p "test_*.py"` in the worktree really did pass 328 tests
before any further work.

Reviewed the actual diff (not just the agent's report) before committing:
`app/importer.py`'s AdGuard/Pi-hole translation now defers all rule
classification to Workstream A's `custom_rules.parse_rule`/`add_rule`
(replacing the old `||^`/`@@||^`/plain-only classification that dumped
everything else into `unsupported_rules`), `build_migration_plan()` gives
every preview item a stable `category:index` key derived only from the
frozen job translation, `apply_migration_job()` wraps every destination
write in one transaction with a traced exception path that records the
exact failing stage, SSRF protections on the AdGuard API fetch
(`_HttpOnlyRedirectHandler`, response size cap, credentials never stored --
only the sanitized base URL lands in the job row), and `redact_sensitive()`
applied at every `report_json` persistence and download point. The checked-in
`tests/fixtures/adguard_home.yaml` deliberately includes adversarial cases
(a lookahead regex that must be rejected, a wildcard CNAME-style rewrite, a
malformed rewrite target, a subscription URL with an embedded token) --
confirmed each is handled correctly, not just present.

Committed as one commit (`7752930`, later folded into the merge at `6c8b0c0`):
AdGuard mapping, Pi-hole mapping, and the preview/apply/rollback/report
machinery share the same core functions (`build_migration_plan`,
`apply_migration_job`) tightly enough that splitting into three separate
commits after the fact would have produced individually non-functional
intermediate states, so this was committed as a single cohesive change
instead of forcing an artificial split.

Merge into `main` was clean (no conflicts) since Workstream A had already
landed. `python3 -m unittest discover` after merge: 330 tests, all passing.

### Two real production defects found and fixed only by live testing (unit tests never caught either)

The full 330-test suite passed throughout both of the following -- neither
was a sandboxed-test gap that "should have" caught something obscure; both
were basic, common-path defects that simply never got exercised because no
test actually rendered the real Jinja template or ran the real privileged
code path end-to-end.

1. **`GET /import/jobs/{id}/preview` 500 on any real content** (`531ea25`).
   `web/templates/import_migration.html`'s category loop uses
   `section.items` where `section` is a plain dict with an `items` key.
   Jinja's default `getattr()` tries attribute access before subscript, and
   `dict.items` resolves to the dict's own bound method -- so this always
   returned `<built-in method items of dict>`, and `|length` on that raised
   `TypeError`. Caught by rendering the page with a real, non-empty
   `migration_summary` (first through an updated `tests/test_web_smoke.sh`
   fixture, matching the earlier `custom_rules.html` fixture fix pattern;
   then reproduced against the live running app by actually uploading
   `tests/fixtures/adguard_home.yaml` through the real `/import/migration/
   adguard/yaml` route). Every existing test either checked `importer.py`'s
   return values directly or grepped the template source text
   (`test_preview_template_renders_itemized_selection` explicitly only does
   `assertIn` on the raw template string) -- none rendered the template
   through the real Jinja engine with populated categories. Fixed with
   bracket subscript (`section['items']`) at all six call sites; scanned
   every touched template for the same dict-method-name collision pattern
   (`items`/`keys`/`values` via dot notation) and found no other instance
   (existing `.get(...)` calls elsewhere are legitimate dict method calls,
   not field-name collisions).

2. **Every migration ever applied through the web UI silently proceeded
   without a real backup** (`dd4caa8`) -- a latent defect predating this
   milestone, exposed (not introduced) by Workstream B's mission-correct
   strict backup check. `create_pre_import_backup()` shelled out directly to
   `scripts/backup.sh` as whatever user calls it. Reproduced directly:
   `runuser -u bindguard -- /opt/alderpointdns/scripts/backup.sh` fails with
   `chown: changing ownership of '.../var/lib/alderpointdns.db': Operation
   not permitted`, because the unprivileged web user cannot `chown` the
   SQLite snapshot to match the live DB's ownership. The *old* migration
   apply code called this with `strict=False` (silently swallowing the
   failure and proceeding anyway) -- so on this VM, every AdGuard/Pi-hole
   migration ever applied through the web UI before this milestone
   proceeded with **no working pre-import safety backup**, undetected until
   now. Workstream B's `apply_migration_job()` correctly uses
   `strict=True` per the mission ("create a verified backup" before apply),
   which turned the previously-silent failure into a hard, correct refusal
   -- surfacing the defect instead of masking it further. Fixed by having
   `create_pre_import_backup()` invoke the same privileged, already-tested
   path scheduled/manual backups already use: `sudo alderpointdns_compiler.py
   backup-create` (already in the sudoers allowlist, already runs as root).
   Verified live end-to-end afterward: `runuser -u bindguard -- sudo -n
   .../alderpointdns_compiler.py backup-create` now succeeds
   (`backup_path=...`, `pruned=2`) as the real unprivileged web user.
   Updated `tests/test_importer.py`/`tests/test_import_routes.py` to stub
   the single `subprocess.run` call site instead of writing a fake
   `backup.sh`; removed the now-dead `BACKUP_SCRIPT` constant.

### Full live end-to-end migration verification (real upload, real apply, real rollback)

Created a throwaway admin (`migration_inspect_tmp`, confirmed deleted
afterward, 1 real admin remains), then drove the actual production HTTP
routes with `curl` against the running `alderpointdns` service --
deliberately not just calling `importer.py` functions directly, since that's
exactly the gap that hid both defects above.

- Uploaded `tests/fixtures/adguard_home.yaml` via `POST
  /import/migration/adguard/yaml`; the first attempt (before restarting the
  service to pick up the merged code) went through the *old* pre-merge
  `importer.py` still loaded in the running uvicorn worker's memory --
  caught this by comparing category counts against a standalone
  reproduction and re-did the upload after `systemctl restart alderpointdns`
  (worth noting for future sessions: a `git merge` alone does not make a
  running service pick up new code).
- `GET /import/jobs/2/preview`: 200 OK (previously 500, see defect #1
  above), rendered all 11 populated categories with correct counts (34
  active, matching `summarize_migration()`'s own count computation exactly)
  and correct metric cards (`Will import` 27, `Kept inactive` 6, etc.).
- `POST /import/jobs/2/apply` with the default itemized selection (33 of 34
  selectable items, matching `counts['selected_default']`): 303, job status
  `applied`, `34 object(s)` applied, 0 failed.
- Live `dig` verification against the real dnsdist/BIND stack for every
  required rule form from the fixture, using the RPZ SOA marker in the
  additional section to distinguish "our rule actually fired" from "`.example`
  doesn't exist upstream anyway" (the latter is a trap: NXDOMAIN alone proves
  nothing for reserved TLDs):
  - `ads.example`/`sub.ads.example` (`||...^` block): both NXDOMAIN with the
    RPZ marker -- subdomain block correctly inherited.
  - `exact.example` (`|...^` exact block): NXDOMAIN with RPZ marker;
    `sub.exact.example`: NXDOMAIN **without** the RPZ marker -- proves the
    exact-host-only distinction is real, not just a stored flag with no
    effect.
  - `safe.example`/`exactallow.example` (allow rules): NXDOMAIN without the
    RPZ marker in both cases -- correct (an allow with nothing else trying
    to block it is a no-op; this is not a false negative, it's the expected
    outcome for a domain that plain doesn't exist upstream).
  - `plainblock.example`/`sub.plainblock.example` (plain domain, AdGuard
    subdomain-inclusive semantics): both blocked with the RPZ marker.
  - `hosts-blocked.example` (`0.0.0.0` sentinel) and
    `hosts-blocked-v6.example` (`::` sentinel, queried as AAAA): both exact
    blocks with the RPZ marker.
  - `loopback.example` (`127.0.0.1`, a non-sentinel literal-address
    rewrite per this milestone's design decision): `NOERROR`, answer
    `127.0.0.1`, RPZ marker present (local-data rewrite, not a passthru) --
    confirms 127.0.0.1/::1 are treated as literal rewrite targets, not
    block sentinels, matching the mission's "return the exact specified
    address" requirement for that example line.
  - `hosts-v6.example` and `nas-alias.example` (both aliases on one
    `fd00::9 ... # media box` line, queried as AAAA): both `NOERROR`,
    answer `fd00::9` -- multiple aliases per line and IPv6 family
    preservation both confirmed; the DB row for both carries the inline
    comment `media box`.
  - `important.example` (`$important`): blocked with RPZ marker; DB row
    confirms `priority=100` (`custom_rules.IMPORTANT_PRIORITY`).
  - Regex rules: confirmed via the compiled dnsdist data files rather than
    `.example` domain resolution (which can't prove a regex actually fired,
    only that the domain doesn't exist upstream either way) --
    `^ads[0-9]+\.` and `^goodcdn[0-9]+\.` both landed verbatim in
    `/var/lib/alderpointdns/compiled/dnsdist/custom-regex-{block,allow}.txt`.
    The underlying dnsdist regex enforcement mechanism itself (not specific
    to these two patterns) was already proven live during the Workstream A
    verification pass above.
  - Direct DB inspection of every `custom_filter_rules` row for
    `import_job_id=2` confirmed exact classification and reasons for every
    remaining fixture line: `$client`/`$dnstype`/`$ctag` each stored
    `enabled=0`, `validation_state='unsupported'`, with the precise reason
    text (e.g. `"modifier $client cannot be preserved: Alderpoint DNS has
    no per-client rule enforcement"`) and the underlying base rule (e.g.
    `clientscoped.example`) never activated; the malformed domain and the
    lookahead regex both stored `validation_state='invalid'`/`'unsupported'`
    with exact reasons; all three comment lines (including one that reads
    like a disabled rule, `! ||disabled-rule.example^` -- correct per
    AdGuard's own convention that a `!`-prefixed line is always a comment,
    including the common case of using it to comment out a rule) stored as
    `rule_type='comment'`, no DNS effect.
  - Local DNS vs. custom-rewrite routing verified against the live system's
    actual configured internal domain (`mylan.network`, not the fixture's
    `home.arpa`): `alias.home.arpa -> target.home.arpa` (CNAME-style answer)
    correctly landed in `local_dns_records` regardless of domain match;
    `nas.home.arpa`/`printer.home.arpa`/`external.example.com`/
    `wildcard.example` (IP answers, none under the real internal domain)
    correctly became exact/subdomain rewrite custom rules instead.
  - Blocklist sources (3, including one with a `?auth=` token in its URL --
    confirmed present verbatim in the live preview shown only to the
    uploading admin, but absent from the persisted/downloadable report per
    `redact_sensitive()`), upstream resolvers (2 new: a DoH and a plain
    resolver, correctly distinct from 4 unrelated pre-existing "Imported
    upstream" rows from an earlier, unrelated migration -- cosmetic
    display-name collision only, no functional conflict since dedup keys on
    protocol/address/port/path not name), and client aliases (Phone,
    Laptop) all confirmed via direct DB query.
- `POST /import/jobs/2/rollback`: 303, job status `rolled_back`, message
  `removed 34 imported object(s)`. Verified precisely: `custom_filter_rules`
  with `import_job_id=2` back to 0 rows; the 3 imported sources gone; the
  pre-existing, unrelated `importtest-nas.mylan.network` Local DNS record
  (predating this session) untouched; the 7 pre-existing legacy
  `custom_rules` rows untouched; the 2 imported upstream resolvers and 2
  imported client aliases gone. Re-ran the `loopback.example` dig check
  after rollback: back to plain NXDOMAIN (the rewrite is actually gone from
  the deployed config, not just the database).
- Cleaned up after testing: removed the throwaway admin, the two staged
  upload copies this session created, and canceled the superseded job 1
  (created against the pre-restart old code before the fix). Also found and
  removed one unrelated stray artifact predating this entire session -- an
  unreferenced (`backup_history` has no matching row) extracted-backup
  scratch directory `/var/lib/alderpointdns/staging/verify2-n0PFMK`, dated
  well before this milestone started, evidently left over from an earlier
  session's backup/restore inspection work.

### Full verification battery (after all four workstreams merged)

- `python3 -m unittest discover -s tests -p "test_*.py"`: 330 tests, all
  passing.
- `./tests/test_web_smoke.sh`: passing.
- `./tests/test_acceptance.sh`: exit 0, final line "Alderpoint DNS
  acceptance suite passed" -- includes `test_encryption_layout.sh` (all four
  widths), install/upgrade/diagnostics, the stale-BindGuard-reference scan
  (clean), rename-migration regression, beta-hardening docs,
  `test_service_restart_analytics.sh`, and `test_backup_restore.sh`.
- `python3 -B tests/test_replication.py`: 5 tests passing;
  `custom_filter_rules` confirmed present in `REPLICABLE_TABLES` (excluding
  the node-local `import_job_id`); confirmed `filter_update_settings` is
  deliberately absent from replication, consistent with how every other
  per-node operational-settings table (`dns_cache_settings`,
  `encryption_settings`, `upstream_resolvers`) is handled -- only filtering
  *policy* data replicates, not per-node scheduling preferences.
- `python3 -B tests/test_backup.py`: 36 tests passing. Confirmed
  `custom_filter_rules` has an explicit `TABLE_COMPONENT_MAP` entry
  (reusing the existing `custom_rules` component); confirmed
  `filter_update_settings`'s absence from the same map is consistent with
  every other settings-style table that isn't explicitly listed (it falls
  under the default `sqlite_data` bucket, not excluded from backup).
- `scripts/alderpointdns-diagnostics` re-confirmed to select only `type,
  name` from `sqlite_master` -- the new tables get the same schema-name-only
  treatment as every existing table, no row contents ever exposed.
- Installer/packaging cross-checked directly (not just trusting Workstream
  C's report): `alderpointdns-filter-update.{service,timer}` are installed
  by both `scripts/install.sh` and `scripts/upgrade.sh`, enabled in
  `packaging/debian/postinst`, stopped/disabled in `prerm`, and the runtime
  drop-in directory is purged in `postrm` alongside the existing backup
  timer's.
- Live service/DNS re-verification after all merges and fixes: all four
  services (`named`, `dnsdist`, `alderpointdns`, `alderpointdns-analytics`)
  active; plain recursive resolution and RPZ blocking both still correct;
  DNSSEC (`. DNSKEY +dnssec`) returns DNSKEY/RRSIG data; PTR
  (`172.16.43.9` -> `chat.mylan.network.`) resolves; encrypted listeners
  bound on `:443` (DoH/DoH3) and `:853` (DoT/DoQ) on both IPv4 and IPv6; no
  orphaned staging files, no abandoned import jobs (both test jobs ended in
  a clean terminal state, `rolled_back`/`canceled`); the filter-update timer
  correctly scheduled at `1 Day`.
- Chromium-rendered the Blocklists page in the disabled-scheduler state
  (`interval_hours='disabled'`, redeployed live): confirmed the "Disabled"
  badge, "Automatic updates disabled" text, and **no** next-run time shown,
  exactly per the mission requirement; confirmed manual "Update All Now"
  (`update-sources` via the real sudo helper) still works while disabled;
  restored the schedule to `1 Day` afterward.

## Independent review and final security hardening (checkpoint `0304922`)

An independent review subagent (fresh, no context from this session, given
an adversarial brief covering rule-parser safety, SQL/shell injection,
CSRF/authz, SSRF, transactional-apply correctness, rollback precision,
scheduler input validation, and public-release hygiene, explicitly told
about the two live-only bugs above and instructed not to trust "tests
pass" as proof of correctness) ran in a separate isolated worktree and
reported back with one `should-fix` finding, two `minor` findings, and an
extensive list of things it specifically tried to break and could not
(SQL injection, XSS, credential leakage, path traversal, allowlist
bypass, partial-apply state, and rollback damaging pre-existing objects).

### Fixed: ReDoS via nested-quantifier regex patterns (`373fca0`)

**Finding:** regex validation (`posix_ere_incompatibility`) correctly
rejected PCRE-only syntax but had no defense against catastrophic-
backtracking shapes that are perfectly valid POSIX ERE, e.g. `/^(a+)+$/`.
dnsdist's own `RegexRule` compiles patterns with POSIX `regcomp`, a
non-backtracking automaton immune to this, but the same stored pattern is
also matched with Python's backtracking `re.search()` in
`evaluate_domain()` for the admin-facing "Test a domain" panel
(`/custom-rules/test`). The reviewer confirmed directly: `/^(a+)+$/`
classified `valid`, then hung well past 120 seconds against an adversarial
input. Independently reproduced: a 30-character input still had not
returned after a 5-second `timeout`.

**Fix:** added `nested_quantifier_risk()`, a single-pass scanner mirroring
the existing `posix_ere_incompatibility()` structure -- it tracks a
per-group-nesting flag for "a quantified atom occurred directly inside
this group" and rejects when a group carrying that flag is itself
quantified (`(a+)+`, `(a*)*`, `(ab+)*`, `(.*)*`, ...). Wired into
`_validate_regex()` alongside the POSIX check. Verified against the
reviewer's exact exploit shapes (all now rejected with a clear reason,
kept inactive per the existing unsupported-rule policy) and against every
regex pattern already relied upon across the fixtures and this session's
prior live testing (`^ads[0-9]+\.`, alternation, bounded `{n,m}`
repetition, character classes) -- all remain valid, zero false positives.
No live regex rules existed on this system at fix time, so there was
nothing to retroactively re-validate. 2 new tests added
(`tests/test_custom_rules.py`, now 51 tests); full suite and acceptance
run clean afterward.

### Fixed: exact-match-only secret-key redaction (`0304922`)

**Finding:** `redact_sensitive()` matched credential-bearing dict keys by
exact string only (`"password"`, `"auth"`, ...), so a compound field name
like `"admin_password"` or `"AuthToken"` would bypass redaction entirely.
The reviewer confirmed no current report/summary payload actually
contains such a compound key, and the accompanying URL-scrubbing regex
independently strips embedded credentials from any string regardless of
key name -- so this was not exploitable today, but a real gap for any
field added later, explicitly called out given the mission's strong
"never expose secrets" requirement for downloadable migration reports.

**Fix:** replaced exact-match key checking with word-boundary/camelCase-
aware token matching in `app/importer.py`. Deliberately does **not**
treat bare `"key"` as sensitive, since this codebase has real, non-secret
fields named `key`/`deselected_keys`/`_dupkeys`/`_upstream_key` (the
migration preview's stable per-item selection keys, rendered as checkbox
values in the itemized apply form) -- confirmed those must survive
redaction for the preview/apply UI to keep working, both in a sandboxed
test and by re-verifying live: restarted the service, re-uploaded the
AdGuard fixture, fetched `/import/jobs/{id}/report`, and confirmed
`item.key == "blocklists:0"` was still present in the downloaded,
redacted report. 3 new tests added (`tests/test_importer.py`, now 52
tests).

### Accepted without a code change (documented, not exploitable today)

- **AdGuard API fetch has no total-elapsed-time budget**, only a
  per-socket-operation timeout (`timeout=8`); a slow-drip response could
  keep a fetch thread alive longer than the stated timeout while still
  respecting the response size cap. Low severity: the target is always an
  admin-supplied AdGuard instance the operator already trusts by choosing
  to connect to it, not attacker-controlled input from an untrusted party.
  Not fixed in this pass; noted for a future hardening pass if this
  becomes a real operational issue.
- The reviewer flagged (as an observation, not a new defect) that
  `create_pre_import_backup()`'s privileged `subprocess.run` call is
  mocked in unit tests because it's inherently untestable unprivileged in
  a sandboxed test run -- the same class of gap that produced both
  previously-found live-only bugs. Recorded here as a standing caution for
  future sessions: any privileged-helper call site in this codebase needs
  a live smoke check in addition to its sandboxed unit test, not instead
  of it.

### Final verification after all hardening fixes

- `python3 -m unittest discover -s tests -p "test_*.py"`: 334 tests, all
  passing.
- `./tests/test_web_smoke.sh`: passing.
- `./tests/test_acceptance.sh`: exit 0, final line "Alderpoint DNS
  acceptance suite passed" (includes the encryption layout check at all
  four widths, install/upgrade/diagnostics, stale-reference scan,
  rename-migration regression, backup/restore, service-restart-analytics).
- Live re-verification after restarting `alderpointdns` with the security
  fixes in place: re-uploaded `tests/fixtures/adguard_home.yaml` through
  the real `/import/migration/adguard/yaml` route, confirmed
  `GET /import/jobs/{id}/preview` still renders 200 OK with all categories
  intact, confirmed `GET /import/jobs/{id}/report` still downloads with
  the preview item `key` fields present and correct, canceled the test
  job, and confirmed no admin/job/staging artifacts were left behind (1
  real admin remains; the job ended in `canceled`, a clean terminal
  state).
- All four services (`named`, `dnsdist`, `alderpointdns`,
  `alderpointdns-analytics`) active; `example.com` resolves;
  `doubleclick.net` NXDOMAIN (RPZ still correctly enforced).

## Milestone closeout

This is the final pre-public-release feature and polish milestone.
Checkpoint commit `0304922` on `main`. All three mission requirements
(first-class custom filtering rules with correct AdGuard Home/Pi-hole
migration, configurable automatic filter update interval, certificate
settings panel layout correction) are implemented, integrated, live-
verified end-to-end against the real running stack (not just sandboxed
unit tests), and independently reviewed with all real findings fixed and
re-verified. No reboot was required or performed. The project is ready
for the final clean public export and GitHub upload, subject to whatever
separate export/sanitization step that upload process itself requires
(this session did not touch anything outside the `/opt/alderpointdns` git
history).
