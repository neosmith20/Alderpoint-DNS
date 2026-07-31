# Release Notes

Alderpoint DNS is pre-release beta software. These notes describe what
changed in each beta build; they are not a claim of production readiness or
long-term stability. See `docs/known-limitations.md` and
`docs/beta-readiness.md` for the current honest state of the project.

## 0.4.0-beta.3 (unreleased beta update)

Not a final release. This build carries forward the administration and
observability work previously tracked under the `0.4.0~beta2` version
string, now version-bumped to `0.4.0~beta3`. Since the interface-polish
build described below, this line has added a full administration and
observability layer and closed several reliability gaps found during beta
feedback and internal testing:

- **System > Administration**: password change with automatic revocation
  of other sessions, per-session visibility (start time, last seen, IP,
  client) and revocation, a recent audit log, and a root-only local
  `alderpointdns admin reset-password` recovery command with no
  web-reachable route.
- **System > Notifications**: a provider-neutral SMTP/webhook notification
  framework (Discord/Slack/Microsoft Teams/ntfy/Gotify/Pushover presets)
  with per-category subscriptions, severity thresholds, cooldown/dedup,
  recovery notices, and a delivery history, driven by a new
  `alderpointdns-notify.timer`.
- Expanded AdGuard Home and Pi-hole migration: AdGuard DNS Rewrites now
  always map to Local DNS (previously some rewrites could be misclassified
  as Custom Filtering Rules); import idempotency gaps closed (URL-based
  blocklist-source matching, comment/invalid custom-rule dedup); a
  dedicated Pi-hole import panel; setup and import severity/reporting
  fixes so intentional public-IP Local DNS records (e.g. a VPN host) are
  reported as warnings, not conflicts.
- Fixed filtering deployments incorrectly failing when a downloaded allow
  rule returned a valid DNS response without an IPv4 A record. Cache-only
  changes now report and roll back component state accurately.
- Fixed a blocklist zero-rule ambiguity (a source that legitimately
  compiles to zero rules is now distinguished from a fetch/parse failure)
  and IPv6-only hosts-format sinkhole entries are now compiled correctly.
- Fixed a production incident in which the analytics writer thread could
  die silently while its parent process kept reporting healthy: closed a
  SQLite connection-descriptor leak present across most of the web app's
  database call sites, added retry-with-backoff and an independent
  heartbeat to the analytics writer, and corrected System Status severity
  reporting (Warning/Error/Info) for these conditions. See `CHANGELOG.md`
  for the full technical account.
- Added the accompanying automated test coverage: deterministic connection-
  lifecycle tests, a web-traffic file-descriptor regression test, and a
  concurrency test exercising live web requests against the database
  alongside the analytics writer under lock contention, plus deterministic
  regression coverage for the allow-domain/cache-rollback fix above
  (structured DNS-result classification, downloaded-allowlist NODATA/AAAA-
  only/CNAME-only/NXDOMAIN/SERVFAIL/timeout handling, and cache-options
  rollback on a later postcheck failure). As of this update the project's
  test suite (`pytest tests/`) totals 493 automated tests, passing locally
  alongside the shell-based acceptance, package-content,
  licensing-hygiene, and clean Debian 13 install suites; this reflects the
  tests that exist today, not a guarantee of production readiness beyond
  what `docs/known-limitations.md` already states.

## 0.4.0-beta.2 (interface-polish build)

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
