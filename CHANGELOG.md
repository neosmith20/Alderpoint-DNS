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
