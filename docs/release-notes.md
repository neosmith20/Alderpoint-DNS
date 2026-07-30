# Release Notes

Alderpoint DNS is pre-release beta software. These notes describe what
changed in each beta build; they are not a claim of production readiness or
long-term stability. See `docs/known-limitations.md` and
`docs/beta-readiness.md` for the current honest state of the project.

## 0.4.0-beta.2

Usability and interface-polish beta build. No DNS, filtering, backup, or
replication behavior changed; this release focuses on the admin UI.

Highlights:

- Collapsible desktop sidebar (icon rail, flyout submenus, persisted state).
- Compact, scannable Local DNS record table with a collapsed-by-default
  row editor and a relationship badge instead of a repeated "reverse for"
  comment sentence.
- Clearer DNS Settings upstream resolver action hierarchy (primary Save/
  Enable actions, overflow menu for reorder/delete).
- Managed Blocklists categories (create/rename/merge/delete-with-
  reassignment) replacing a free-text field, plus a compact, filterable
  source table.
- System Status Recent Logs now shows real, sanitized service logs through
  a narrowly scoped privileged helper instead of a raw permission-denied
  journalctl error.
- Fixed Dashboard/System Status health cards splitting words like
  "Healthy" and "DNSSEC" mid-character on narrow layouts.
- Fixed a live-database backup race in `scripts/backup.sh` (SQLite online-
  backup-API snapshot instead of tarring the live WAL-mode file).

Known release caveats: same as 0.4.0-beta.1 below.

## 0.4.0-beta.1

This is a beta-preparation build, not a v1.0 release.

Highlights:

- Responsive administration sidebar and mobile drawer.
- Managed upstream resolvers for plain DNS, DoT, and DoH.
- Per-upstream resolver analytics from dnsdist backend counters.
- Client-facing encrypted DNS listener controls.
- Expanded import and migration for AdGuard Home, Pi-hole text/list exports,
  BIND zones, hosts files, CSV/XLSX, and Alderpoint DNS-native JSON.
- Fresh-install, upgrade, diagnostics, and local test `.deb` tooling.
- BIND cache management with TTL, size, recursive-client, prefetch,
  serve-stale, and flush controls.

Known release caveats:

- Admin UI HTTPS is not implemented yet; use private networks or a trusted
  reverse proxy and enable `ALDERPOINTDNS_COOKIE_SECURE=1` when served over HTTPS.
- Pi-hole import targets practical text/list data, not Pi-hole's live gravity
  database internals.
- AdGuard domain-specific upstream routing is reported as unsupported.
- `dpkg-deb` test packages are supported for validation; a signed apt
  repository is not published yet.
