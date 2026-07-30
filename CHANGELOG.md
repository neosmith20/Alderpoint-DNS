# Changelog

## Unreleased

- Captured VM baseline and architecture.
- Configured BIND backend on loopback with DNSSEC, RPZ, RNDC, stats, and
  AppArmor confinement.
- Configured dnsdist loopback frontend with DNS, DoH, DoT, ACLs, rate limits,
  packet cache, and stats.
- Added blocklist downloader/parser/compiler with safe RPZ deployment and
  rollback.
- Added authenticated FastAPI web interface.
- Added aggregate dnsdist dashboard statistics.
- Added local backup and restore workflow.
- Added native Backup and Restore page with preview-first restore,
  checksummed archives, scheduled backups, and rollback.
- Added one-way primary-to-replica replication with token enrollment, mTLS,
  generation hashes, drift checks, failed-sync rollback, and revoked-peer
  enforcement.
- Grouped primary navigation into Dashboard, DNS, Security, Operations, and
  System sections with active parent/page state and mobile/keyboard support.
- Added DNS Settings upstream resolver management for plain DNS, DoT, and DoH,
  using BIND plus a managed dnsdist loopback upstream pool with validation,
  health, latency, and rollback.
- Added per-upstream resolver analytics from dnsdist managed-backend counters,
  including dashboard ranking, success/failure/timeout counts, latency, and
  historical resolver snapshots.
- Added configurable client DNS listener IPv4/IPv6 addresses for Encryption
  Settings, with deployment validation and wildcard-listener warnings.
- Expanded Import and Migration with Pi-hole text/list parsing, AdGuard
  upstream resolver translation, BindGuard-native JSON export/import, staged
  upload retention metadata, and migration summaries that surface adds,
  updates, conflicts, skipped items, and unsupported source features.
- Added reviewed-install and safe-upgrade scripts with dry-run/test-root
  support, a sanitized `bindguard-diagnostics` bundle command, version and
  dependency manifests, and Debian package scaffolding plus a local test
  `.deb` builder.
- Expanded BIND cache management with a recursive client limit control, an
  explicit statistics refresh action, and stricter web-route error handling
  for cache deploy and flush helper failures.
- Added beta-readiness, versioning, release-note, supported-system, hardware,
  migration, recovery, troubleshooting, feedback, bug-report, feature-request,
  and hardening-review documentation, plus a hardening test for docs,
  resolver ACL defaults, diagnostics redaction, and secure-cookie deployment
  configuration.
- Made the top-right service status badge a global authenticated-shell
  component with a lightweight `/status/summary` refresh endpoint.
- Verified full reboot survival: services, listeners, DNS functionality,
  feature persistence, and the acceptance/smoke/hardening-doc suites all
  passed post-reboot; validated a production-flow backup/restore round trip.
- Fixed a diagnostics bundle defect where `bindguard-diagnostics` leaked the
  live BIND RNDC/TSIG control-channel secret in plaintext; added a redaction
  pattern and a bundle-level regression test.
- Fixed unclosed SQLite connections in `tests/test_backup.py` that caused
  the pre-existing `ResourceWarning` noise during backup test runs.
- Renamed the project from BindGuard to Alderpoint DNS: new public branding,
  `alderpointdns`/`ALDERPOINTDNS_` machine identifiers, renamed paths/
  services/package, deprecated compatibility wrappers and legacy-install
  migration tooling in `scripts/upgrade.sh`, and backup/restore support for
  reading pre-rename BindGuard-branded archives. Migrated this VM's live
  installation via the real upgrade tooling; see `docs/compatibility.md`
  and `docs/migrating-from-bindguard.md`.
- Fixed a live-database backup race: `scripts/backup.sh` previously tarred
  the live WAL-mode SQLite database file directly, which could race a
  checkpoint and trip tar's "file changed as we read it" (aborting the
  acceptance suite under `set -eu`). It now takes a transactionally
  consistent snapshot via SQLite's own online backup API first and archives
  that instead, with ownership/permissions preserved and the temporary
  snapshot always cleaned up.
- Added a collapsible desktop sidebar: an icon-only rail with tooltip/
  `aria-label`led icons, flyout submenus for grouped sections, visible
  active-page state in both modes, and a `localStorage`-persisted collapsed
  state applied before first paint (no layout jump). The mobile drawer is
  a separate, unaffected code path.
- Redesigned Local DNS's record table to be compact and scannable: single-
  line truncated hostnames/values with full text on hover, a compact
  relationship badge replacing the repetitive "reverse for <fqdn>" comment
  text, and a collapsed-by-default row editor (toggled via an Edit button)
  instead of a permanently expanded edit form under every row.
- Reworked DNS Settings' upstream resolver actions into a clear hierarchy:
  Save and Enable/Disable stay inline as primary/common actions; Move up,
  Move down, and the destructive Delete move into a compact overflow menu
  with a visual divider before Delete.
- Replaced Blocklists' free-text category field with a managed category
  system backed by the existing `categories` table: a dropdown populated
  from real categories (including a built-in Uncategorized), plus
  create/rename/merge/delete-with-reassignment category management and a
  one-time migration that normalizes and deduplicates any legacy free-text
  category values already stored on sources. The source list itself is now
  compact, with category/status/health badges, sorting, and filtering.
- Fixed System Status's Recent Logs, which previously ran `journalctl -u
  alderpointdns` directly as the unprivileged web user and rendered
  journald's raw permission-denied hint text into the page. It now goes
  through a narrowly scoped, sudoers-allowlisted helper (a fixed `logs
  <unit>` subcommand covering only `alderpointdns`, `alderpointdns-
  analytics`, `named`, and `dnsdist`) that returns sanitized, structured
  log entries, with web-side service/severity/line-count filters and a
  friendly empty state when logs are unavailable.
- Fixed Dashboard/System Status health cards splitting whole words mid-
  character on narrow layouts (e.g. "Healthy" -> "Heal"/"thy", "DNSSEC" ->
  "DNSSE"/"C"): a blanket `.card *`/`.panel *` word-break override was
  scoped away from headings and status badges, and table headers no longer
  inherit the same aggressive wrapping arbitrary long data values use.
- Added a shared compact-UI component set (compact table rows, category
  badges, overflow action menus, row-level expandable editors) reused
  across Local DNS, DNS Settings, and Blocklists.
- Added a first-class custom filtering rule subsystem (a new `custom_filter_
  rules` table, replacing the old flat allow/block-only list) that classifies
  `||domain^` and `@@||domain^` (domain-and-subdomain block/allow), hosts-
  style lines (exact-host blocks for `0.0.0.0`/`::` sentinels, exact address
  rewrites preserving IPv4/IPv6 for any other address, multiple aliases per
  line, inline comments), `!`/`#` comments, `/REGEX/` rules (validated
  against a POSIX-ERE-compatible subset and safely compiled into a dnsdist
  layer with no rule text ever interpolated into generated Lua), plain
  domains, and AdGuard `$` modifiers (`$important` honored as priority;
  unsupported modifiers such as `$client`/`$dnstype`/`$ctag` are kept
  visible and inactive with an exact reason instead of silently activating a
  broadened base rule). Deterministic, documented compile-time precedence:
  local DNS, exact rewrites, explicit allow, explicit block, regex allow,
  regex block, external blocklists -- allow rules survive blocklist
  refreshes without ever modifying stored blocklist data. Existing custom
  rules migrate automatically and idempotently. Adds a compact Filters page
  (`/custom-rules`) with search/filter, bulk enable/disable/delete, a
  multiline bulk editor with per-line validation, and a "Test a Domain"
  panel.
- Corrected AdGuard Home and Pi-hole migration to route every custom rule
  through the new filtering subsystem instead of a lossy allow/block-only
  classifier, with AdGuard's subdomain-inclusive and Pi-hole's exact-only
  plain-domain semantics both preserved. AdGuard DNS rewrites now split
  correctly between Local DNS (names under the operator's internal domain)
  and exact rewrite rules (everything else); Pi-hole exports now separate
  adlists, exact allow/block lists, regex allow/block lists, local DNS hosts
  records, and `cname=` records into their own destinations instead of one
  generic import type. Migration preview is now fully itemized and
  categorized with per-item and per-category deselection, and never applies
  anything on its own. Apply is transactional (a verified pre-import backup,
  then every destination write in one transaction; any failure rolls back
  completely and reports the exact failing stage) and reversible (rollback
  removes exactly the imported objects). Migration reports strip credential-
  named fields and URL userinfo/query strings before they are ever stored or
  downloaded.
- Added a configurable global Filter Update Interval on the Blocklists page
  (`Disabled — No Updates`, `1 Hour`, `12 Hours`, `1 Day`, `3 Days`, `1
  Week`; default `1 Day` on fresh installs), backed by a new systemd
  service/timer pair and a fixed, server-side validated allowlist -- no
  arbitrary intervals, cron syntax, or shell input ever reaches the
  scheduler. The panel shows current status, last automatic attempt/
  success, and next scheduled update, and clearly reads "Automatic updates
  disabled" with no misleading next-run time when turned off; manual
  per-source updates and "Update All Now" keep working regardless of the
  automatic schedule.
- Fixed the Encryption page's Certificate panel stretching to match the
  Protocols panel's height whenever a Certificate section (self-signed,
  local CA, upload, existing paths) was expanded, leaving artificial empty
  space in Protocols. Both panels now size independently from their own
  content, verified with a headless-Chromium regression check across four
  viewport widths; the same fix was applied to the equivalent Cache Tuning/
  Flush Cache and Create Backup/Import Backup panel pairs.
- Hardened custom regex rule validation to reject catastrophic-backtracking
  patterns (e.g. `(a+)+`) that are valid POSIX ERE but can hang the
  admin-facing "Test a domain" evaluation panel indefinitely; hardened
  migration report redaction to match credential-bearing field names by
  word-boundary/camelCase token instead of exact string, so compound names
  are caught too.
