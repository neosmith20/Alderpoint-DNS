# Changelog

All notable changes to Alderpoint DNS are documented in this file. Alderpoint
DNS is currently in **beta**; interfaces, on-disk formats, and configuration
may still change between releases before a stable 1.0.

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
