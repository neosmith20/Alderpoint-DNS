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
- Made the top-right service status badge a global authenticated-shell
  component with a lightweight `/status/summary` refresh endpoint.
