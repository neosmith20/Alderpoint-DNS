# Changelog

All notable changes to Alderpoint DNS are documented in this file. Alderpoint
DNS is currently in **beta**; interfaces, on-disk formats, and configuration
may still change between releases before a stable 1.0.

## v0.4.0-beta.4 (unreleased)

`v0.4.0-beta.3` was version-bumped, tag-created, and immediately withdrawn
before any GitHub Release was published (a first prerelease publish had to
be deleted and its tag name became permanently unusable due to GitHub's
immutable-releases policy); no `beta.3` artifact was ever distributed. All
of its changes are carried forward unchanged under `beta.4` below.

- Fixed filtering deployments incorrectly failing when a downloaded allow
  rule returned a valid DNS response without an IPv4 A record. Cache-only
  changes now report and roll back component state accurately.
- Fixed a production incident in which the analytics writer thread could
  die silently while its parent process kept reporting healthy: closed a
  SQLite connection-descriptor leak present across most of the web app's
  database call sites, added retry-with-backoff and an independent
  heartbeat to the analytics writer, and corrected System Status severity
  reporting (Warning/Error/Info) for these conditions.
- Fixed a blocklist zero-rule ambiguity: a source that legitimately
  compiles to zero rules is now distinguished from a fetch/parse failure,
  IPv6-only hosts-format sinkhole entries now compile correctly, AdGuard
  `$dnsrewrite` handling was corrected, and System Status now reports
  real, distinct blocklist health states instead of collapsing them
  together.
- Fixed the local test-deb builder silently omitting the new admin CLI
  entry point and the `alderpointdns-notify.timer` unit from built
  packages.
- Scrubbed a real home-LAN domain and IP addresses that had been
  reintroduced into test fixtures.
- Documented the recent Administration, Notifications, migration, and
  reliability work.

## v0.4.0-beta.2 (unreleased)

- Configured the BIND recursive backend on loopback with DNSSEC validation,
  RPZ-based filtering, RNDC control, statistics, and AppArmor confinement.
- Configured the dnsdist client-facing frontend with plain DNS, DoH, DoT,
  DoQ, access control lists, rate limits, a packet cache, and statistics.
- Added a blocklist downloader/parser/compiler with safe RPZ deployment and
  automatic rollback on failure.
- Added an authenticated FastAPI web interface with Argon2 password hashing,
  signed session cookies, CSRF protection, and rate-limited login.
- Added a native Backup and Restore page with preview-first restore,
  checksummed archives, scheduled backups, and rollback on failure.
- Added one-way primary-to-replica replication with token enrollment, mTLS,
  generation hashes, drift checks, failed-sync rollback, and revoked-peer
  enforcement.
- Added DNS Settings upstream resolver management for plain DNS, DoT, and
  DoH, backed by BIND plus a managed dnsdist loopback upstream pool with
  validation, health checks, latency tracking, and rollback.
- Added per-upstream resolver analytics from dnsdist's managed-backend
  counters, including dashboard ranking, success/failure/timeout counts,
  latency, and historical resolver snapshots.
- Added configurable client DNS listener IPv4/IPv6 addresses for Encryption
  Settings, with deployment validation and wildcard-listener warnings.
- Added Import and Migration with CSV/XLSX/hosts/zone-file parsing, Pi-hole
  text/list import, AdGuard Home YAML and live-API import (blocklists,
  custom rules, DNS rewrites, upstream resolvers), a native JSON export/
  import format, staged upload retention, and migration summaries covering
  adds, updates, conflicts, skipped items, and unsupported source features.
- Added reviewed install and safe-upgrade scripts with dry-run/test-root
  support, a sanitized diagnostics bundle command, version and dependency
  manifests, and Debian package scaffolding plus a local test `.deb`
  builder.
- Added BIND cache management: cache size, TTL, prefetch, and serve-stale
  tuning; a recursive client limit control; cache flush (all/name/subtree);
  and cache hit/miss statistics sourced from BIND's own statistics channel.
- Added a first-class custom filtering rule subsystem supporting exact and
  subdomain block/allow rules, hosts-style exact rewrites, POSIX-ERE regex
  rules (validated against catastrophic-backtracking patterns and compiled
  into dnsdist without ever interpolating rule text into generated Lua),
  and AdGuard `$` modifiers, with deterministic precedence and a compact
  Filters page supporting search/filter, bulk edit, and a "Test a Domain"
  panel.
- Added a configurable global Filter Update Interval on the Blocklists page,
  backed by a systemd timer and a fixed, server-validated allowlist of
  intervals.
- Added beta-readiness, versioning, release-note, supported-system,
  hardware, migration, recovery, troubleshooting, and feedback/bug-report/
  feature-request documentation, plus a hardening-review document and a
  corresponding automated test.
- Grouped primary navigation into Dashboard, DNS, Security, Operations, and
  System sections with active parent/page state and mobile/keyboard
  support, plus a collapsible desktop sidebar with persisted collapsed
  state.
- Made the top-right service status badge a global authenticated-shell
  component backed by a lightweight status-summary refresh endpoint.
- Redesigned Local DNS's record table to be compact and scannable, with a
  collapsed-by-default row editor and relationship badges in place of
  repetitive comment text.
- Reworked DNS Settings' upstream resolver actions into a clear hierarchy of
  primary inline actions and a compact overflow menu for less common or
  destructive actions.
- Replaced Blocklists' free-text category field with a managed category
  system: create/rename/merge/delete-with-reassignment, plus a compact
  source list with category/status/health badges, sorting, and filtering.
- Verified full reboot survival: services, listeners, DNS functionality,
  feature persistence, and the acceptance/smoke/hardening-doc test suites
  all pass after a full reboot, including a production-flow backup/restore
  round trip.
- Fixed a diagnostics bundle defect that leaked the live BIND RNDC/TSIG
  control-channel secret in plaintext; added a redaction pattern and a
  bundle-level regression test.
- Fixed a live-database backup race where `scripts/backup.sh` tarred the
  live WAL-mode SQLite database file directly, which could race a
  checkpoint and abort the backup. It now takes a transactionally
  consistent snapshot via SQLite's own online backup API first and archives
  that instead.
- Fixed unclosed SQLite connections in the backup test suite that produced
  `ResourceWarning` noise during test runs.
- Fixed System Status's Recent Logs, which previously ran `journalctl`
  directly as the unprivileged web user and could render raw
  permission-denied text into the page. It now goes through a narrowly
  scoped, sudoers-allowlisted helper that returns sanitized, structured log
  entries, with service/severity/line-count filters and a friendly empty
  state.
- Fixed Dashboard/System Status health cards splitting whole words
  mid-character on narrow layouts.
- Fixed the Encryption page's Certificate panel stretching to match an
  adjacent panel's height; the same fix was applied to the equivalent Cache
  Tuning and Backup/Restore panel pairs.
- Hardened custom regex rule validation to reject catastrophic-backtracking
  patterns that are valid POSIX ERE but could otherwise hang the
  admin-facing "Test a domain" evaluation panel indefinitely.
- Hardened migration report redaction to match credential-bearing field
  names by word-boundary/camelCase token instead of exact string, so
  compound field names are caught too.
- Fixed a first-clean-install failure where all four core services
  (`alderpointdns`, `alderpointdns-analytics`, `named`, `dnsdist`) crash-
  looped after a "successful" package install: `secrets.env`/dnsdist API
  and web credentials are now group-readable (0640) instead of 0600; the
  database is chowned to `alderpointdns` after generation; named's
  AppArmor local override is installed and reloaded; `packaging/dnsdist.conf`
  is fixed and made capability-aware for Debian 13's own (non-PowerDNS-repo)
  dnsdist build, and the package now requires `dnsdist (>= 2.0.0)` so
  installing without the documented PowerDNS repository fails cleanly at
  dependency resolution instead of silently pulling an incompatible
  version. dnsdist's web password and API key are now hashed with
  `hashPassword()` before being written into `dnsdist.conf`, eliminating
  the plaintext-credential warning without weakening authentication.
  `postinst` now validates configuration and verifies all four services
  actually reach the active state before reporting success, and
  `StartLimitBurst`/`StartLimitIntervalSec` caps prevent runaway restart
  loops if that ever fails again. Added a container-based clean-install
  regression test and a static built-package inspection test.
- Finalized Alderpoint DNS's license: source-available under the PolyForm
  Noncommercial License 1.0.0 (`LICENSE`), not open source; commercial use
  requires a separate license (`COMMERCIAL_LICENSING.md`). Added
  `COPYRIGHT`, `CONTRIBUTOR_LICENSE_AGREEMENT.md` (structured on the Apache
  Individual CLA, de-branded, contributors retain ownership and grant
  Alderpoint DNS broad reuse/relicensing rights), `TRADEMARKS.md`, and
  `THIRD_PARTY_NOTICES.md` (audit of BIND/dnsdist/Python/OS dependencies
  and their licenses; nothing third-party is vendored into the repo).
  Updated `README.md`/`CONTRIBUTING.md` accordingly and clarified that
  opening a pull request is not, by itself, CLA acceptance. The `.deb` now
  installs `LICENSE`/`copyright`/`COMMERCIAL_LICENSING.md`/
  `THIRD_PARTY_NOTICES.md` under `/usr/share/doc/alderpointdns/`. Added a
  permanent licensing-hygiene test.
- Fixed a second clean-install failure: requiring `dnsdist (>= 2.0.0)` made
  the package impossible to install on a genuinely fresh Debian 13 system
  at all, since a `.deb` cannot configure a third-party repository to
  satisfy its own dependency before apt resolves it, and that version is
  only available from the PowerDNS project's own repository. `Depends` now
  reads `dnsdist (>= 1.9.0)`, the lowest bound Debian 13's own archive
  `dnsdist` (1.9.x) satisfies, so `apt-get install -y ./alderpointdns_*.deb`
  resolves and installs cleanly from stock repositories alone. Debian's own
  `dnsdist` build supports plain DNS, DoH, DoT, DNSCrypt, and everything
  the BIND backend integration needs (packet cache, ACLs, analytics
  logging, authenticated web/API access), but not DNS-over-QUIC or
  DNS-over-HTTP/3; those two now ship disabled by default and
  `app/encryption.py` detects the installed `dnsdist`'s actual capabilities
  (from `dnsdist --version`'s feature list) to keep unsupported protocols
  out of a deployment -- degrading just that protocol with a clear message
  instead of failing or rolling back the whole deployment -- and to show
  them as unsupported, not enabled or broken, on the Encryption Settings
  page. The PowerDNS repository remains available as an optional upgrade
  path for DoQ/DoH3, detected automatically with no reinstall required.
  Rewrote the clean-install container regression test to install strictly
  from stock Debian 13 repositories, with no `repo.powerdns.com` reference
  permitted anywhere in the run.
- Fixed the Encryption Settings page (and the dashboard's System Health
  cert card) throwing a 500 on a genuinely fresh install: the TLS
  certificate directory (`/etc/alderpointdns/certs`) was created
  `root:_dnsdist` mode `0750`, so the unprivileged `alderpointdns` web
  process -- in neither group -- got `PermissionError` on a bare `stat()`
  of its own certificate, even though the certificate file itself is
  world-readable (`0644`). Changed the directory to mode `0751`: still no
  read/write for "other" (can't list the directory or open the `0640`
  private key), but traversable, which is all `os.stat()`/`Path.exists()`
  on the certificate needs. `scripts/ensure_tls_cert.sh` now applies this
  unconditionally, including when certificate material already exists, so
  upgrading an install that predates this fix also picks up the corrected
  mode. Also made the DoQ/DoH3 disabled-checkbox enforcement symmetric:
  `encryption.enforce_capabilities()` (factored out of
  `deploy_encryption()`) is now also applied when saving Encryption
  Settings, so a forged POST setting `doq_enabled=1`/`doh3_enabled=1`
  cannot persist an unsupported protocol as enabled, not just fail to
  render it checked.
- Web interface usability pass from beta feedback:
  - Added a reusable pending-action button state (`app.js`): the submitted
    button disables immediately, its label swaps to an in-progress gerund
    with a spinner, `aria-busy` is set, and it's restored automatically if
    an async action fails without navigating away -- applied globally to
    every form submit (DNS settings, Local DNS, blocklists, imports,
    custom rules, cache, backups, encryption) instead of one-off handlers.
  - Restructured status-tile cards (`.card`/`.card__head`): component name
    centered on top, status badge centered directly below it instead of
    beside the name at an arbitrary offset, applied consistently across
    System Health, System Status, Encryption, Replication, Backup, and DNS
    Settings summary cards; list-content cards (e.g. Allowed Clients) are
    explicitly excluded, not blindly centered.
  - Added a shared `.actions-col` table utility (centered header, buttons,
    status labels, and overflow menus) applied to Local DNS, Blocklists
    (both tables), Custom Rules, DNS Settings upstreams, Backup, and
    Replication, replacing inconsistent per-page alignment.
  - Gave the collapsed-sidebar Logout control a recognizable icon, an
    accessible name and tooltip ("Log out"), and a hover/focus state
    matching other collapsed nav buttons -- it no longer collapses down to
    an unlabeled, easy-to-misclick box.
  - Made sidebar nav sections (DNS/Security/Operations/System) collapsible
    again after opening, including a section containing the active page
    (which stays visually identifiable via its own styling regardless of
    expanded state); expand/collapse state now persists across ordinary
    navigation via `localStorage`.
- Added a first-class Pi-hole Migration panel to Import and Migration,
  alongside AdGuard Home's, explaining the supported Pi-hole text-export
  format (adlists.list, whitelist/blacklist, regex.list including the
  wildcard-block idiom, custom.list, dnsmasq `cname=` lines) and warning
  that group assignments have no Alderpoint DNS equivalent. The Pi-hole
  importer backend and preview/apply/rollback pipeline already existed and
  needed no changes; only the dedicated UI panel (previously just a
  dropdown option with no format explanation) and end-to-end route tests
  against the synthetic Pi-hole fixture were added.
- Closed import-idempotency gaps found by re-importing the same AdGuard/
  Pi-hole data against an install that already has it: blocklist sources
  are now also matched by URL (not just name), so the same feed re-added
  under a different name is recognized and skipped instead of creating a
  second subscription; comment and invalid/unsupported custom-rule entries
  (previously exempt from duplicate detection) are now deduplicated the
  same way active rules already were. Local DNS records, client aliases,
  and upstream resolvers were already correctly deduplicated. Added tests
  proving that applying the same AdGuard or Pi-hole import twice, as two
  separate jobs, does not increase any destination table's row count.
- Added password confirmation to first-run setup: a typo is now caught
  before the administrator account is created instead of only being
  discoverable at the next login. Validated both client-side (native form
  validation) and server-side; the entered username is preserved and
  neither password value is echoed back on a failed submission; added a
  CSRF token to `/setup` (previously unenforced, since no session existed
  yet to bind one to -- `render()` now mints and persists an anonymous
  pre-login session on first visit specifically so this token is real);
  added an accessible show/hide toggle for password fields.
- Added System > Administration: change the administrator password
  (requires the current password, revokes every other active session
  automatically), an explicit "revoke all other sessions" action that
  doesn't touch the password, and a session list (start time, last seen,
  IP, client) and recent audit log, without ever exposing a raw session
  token. Sessions are now server-side rows (`sessions` table) referenced by
  an opaque id in the signed cookie, not cookie-embedded state, so they can
  actually be revoked individually. Added a root-only local recovery
  command, `alderpointdns admin reset-password` (`scripts/alderpointdns-
  admin`, installed to `/usr/sbin/alderpointdns`), for a forgotten
  password with no web-reachable route and no email dependency; it shares
  the exact same Argon2 implementation (`app/auth.py`) as the web app and
  revokes the account's existing sessions. `admins`/`login_attempts`/
  `sessions`/`admin_audit_log` remain excluded from backup archives by
  default, gated behind the existing `user_auth_data` component.
- Added System > Notifications: a provider-neutral framework (SMTP email
  and generic HTTP webhook, with Discord/Slack/Microsoft Teams/ntfy/
  Gotify/Pushover as webhook presets sharing the same delivery path) with
  per-event-category subscriptions and severity thresholds, cooldown and
  duplicate suppression, recovery notices, a local delivery history, and a
  test-send action. Provider secrets (SMTP passwords, webhook URLs -- most
  of these presets embed a bearer-equivalent token directly in the URL)
  are masked, write-only, and never rendered back, and are excluded from
  backup archives by default like other credential material. A new
  `alderpointdns-notify.timer` polls every 5 minutes and fires real,
  edge-detected notifications for service up/down/recovered, repeated
  restarts, blocklist/deploy failure, backup failure, upstream resolver
  degraded/all-unavailable, and replication delayed/failed; TLS
  expiry/low disk space/abnormal SERVFAIL rate are defined as subscribable
  categories but not yet evaluated (see `docs/known-limitations.md`).
- Fixed the AdGuard/Pi-hole importer reporting intentional public-IP Local
  DNS records (e.g. a VPN/WireGuard host record) under `Conflicts`, with
  the misleading final result `Applied with conflicts`, even though the
  record imported successfully and nothing actually conflicted. Local DNS
  data-quality findings are now severity-tagged (`local_dns.
  record_findings()`): genuine incompatibilities (duplicate hostname,
  CNAME clash, conflicting PTR, missing PTR target) remain conflicts and
  still require an explicit override; a public IP outside common private
  ranges is now a warning, shown separately, imported as requested, and
  never blocks creation -- including through the plain manual Local DNS
  "add record" form, which previously also wrongly required overriding a
  public IP. Import previews and job results now distinguish Conflicts,
  Warnings, and Unsupported as separate counts/sections instead of folding
  warnings into conflicts.
- Fixed a blocklist-source ambiguity where a subscription that legitimately
  compiles to zero active rules (e.g. an AdGuard-style source consisting
  entirely of `$dnsrewrite` rules Alderpoint DNS cannot express as RPZ
  block rules, or an IPv6-only hosts-format source) was indistinguishable
  from a fetch/parse failure. Health/status reporting for each source now
  reflects its actual state (real zero-rule vs. failed) instead of always
  reading as a generic failure, and IPv6 sinkhole-style hosts entries are
  recognized and compiled correctly rather than silently skipped.
- Fixed a production incident where the analytics writer thread could
  silently die (e.g. after a transient SQLite `database is locked` error)
  while the parent `alderpointdns-analytics` process kept running, so
  systemd and System Status both reported "active" with no query events
  actually being recorded. Root cause was a database-connection-handling
  defect shared across most of the web app's SQLite call sites: Python's
  `sqlite3.Connection` context manager only commits or rolls back on exit,
  it never closes the connection, so long-lived request handlers were
  quietly accumulating open file descriptors against the same database
  file. Every affected `connect()`/`db()` helper (web app, notifications,
  encryption, DNS cache, importer, upstream resolvers, blocklist
  categories, local DNS) now closes deterministically on exit, with an
  explicit `busy_timeout` and short-lived transactions. The analytics
  writer now retries transient lock errors with backoff, isolates
  retention-cleanup failures to a single cycle instead of ever giving up
  entirely, publishes an independent file-based heartbeat so its health can
  be read even when the database itself is unavailable, terminates and
  lets systemd restart it only after sustained, unrecoverable failure, and
  fires a notification and a correctly severity-tagged System Status entry
  (Warning for a recovered transient lock, Error for a terminated writer,
  Info for recovery) instead of misreporting a real failure as routine
  informational logging. Added deterministic connection-lifecycle tests,
  an end-to-end web-traffic file-descriptor regression test, and a
  concurrency test exercising real web requests against the live database
  while the analytics writer is simultaneously writing events and running
  retention cleanup under lock contention.
