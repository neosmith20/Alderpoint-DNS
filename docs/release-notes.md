# Release Notes

These notes describe what changed in each release. See
`docs/known-limitations.md` for the current honest state of the project.
Everything below `v1.0.0` was a beta-cycle build.

## v1.0.1 (2026-08-11)

Alderpoint DNS v1.0.1 is a bugfix release focused on upstream DNS
reliability, deployment behavior, and backup/restore consistency.

- Managed upstream resolver changes now deploy through the scoped upstream
  path instead of the full blocklist/RPZ pipeline, reducing unnecessary
  work and avoiding unrelated deployment stages for simple upstream edits.
- Overlapping DNS Settings changes are serialized and coalesced so a burst
  of upstream add/edit/toggle/move/delete actions does not queue multiple
  redundant deployments or surface raw database-lock errors.
- Upstream resolver deployment now applies ordinary backend changes to the
  running dnsdist process through its console where possible, avoiding
  unnecessary dnsdist restarts while still keeping the generated startup
  configuration in sync.
- Post-deploy upstream checks now force fresh DNS resolution rather than
  accepting stale cached answers, and per-upstream status is recorded from
  each backend's actual state instead of assuming every enabled resolver is
  healthy when the overall pool can answer.
- DNS Settings now shows direct per-provider health telemetry and refreshes
  it locally while the page is open, without causing extra external DNS or
  DoH probes.
- Direct DoH health probes now resolve the configured DoH hostname through
  bootstrap DNS and send the correct TLS SNI, HTTP Host/authority,
  configured DoH path, and `application/dns-message` request headers.
- Disabling, deleting, or editing the last enabled upstream resolver is
  rejected before the invalid all-disabled state can be committed.
- Backup restore now reconciles managed upstream resolver state with the
  generated runtime configuration when a restore can affect either side,
  and replicated configuration explicitly leaves upstream resolvers
  appliance-local.
- The packaged sudoers policy now includes the required scoped
  `upstream-deploy` grant used by DNS Settings upstream actions.

## v1.0.0 (2026-08-09)

Alderpoint DNS's first stable release. Highlights since the beta.4/beta.5
line, by area (see `CHANGELOG.md` for the full detailed log):

- **DNS/filtering**: fast paths for the overwhelmingly common blocklist
  rule shapes, cheap IP-literal prechecks, an ASCII-normalization
  shortcut, and a source-parse cache keyed by content hash and parser
  version make blocklist updates and deploys substantially faster on
  large lists. Turning **Protection** back on can now reuse a previously
  compiled policy (validated against a canonical hash of everything that
  could have changed it) instead of always rebuilding from scratch.
- **Fresh-install behavior**: a new install now seeds a curated,
  recommended set of default blocklists automatically instead of
  starting with an empty policy.
- **Backup & Restore**: native database restore is now staged and
  atomically promoted -- the expensive merge work happens against a
  private working copy, never directly against the live database, and is
  only swapped in via a brief, validated atomic operation. A restore
  interrupted before that point leaves the live database completely
  untouched. Abandoned restores (a worker that died mid-run) are now
  reliably detected and reported instead of appearing stuck forever.
- **Network Configuration**: change this server's own network interface
  (DHCP/static IPv4/IPv6, gateway) with an explicit confirm-within-timeout
  safety window and automatic rollback if a change leaves the server
  unreachable.
- **Replication and Import**: one-way primary-to-replica sync with hashed,
  one-time, revocable enrollment tokens and mTLS; preview-first import
  from AdGuard Home, Pi-hole, BIND zones, hosts files, and CSV/XLSX.
- **Software Updates**: check for and install newer Alderpoint DNS
  releases from GitHub, or upload a `.deb` manually, with SHA-256 +
  package-metadata validation, an `apt` install simulation, and a
  mandatory pre-upgrade backup before every install. Automatic checking
  is on by default and its interval is configurable; automatic
  installation is intentionally not implemented -- every install is an
  explicit administrator action.
- **Security/hardening**: every privileged operation (deployment, Backup &
  Restore, Network Configuration, Software Updates, Replication) runs
  through fixed, argument-free sudoers entries; see `docs/security.md` and
  `docs/hardening-review.md` for the full reviewed control list.
- **UI/QoL/navigation**: Backup & Restore moved to a reorganized
  **Operations** menu (Import, Backup & Restore, Replication);
  Administration was decluttered of launcher cards that only pointed at
  neighboring System menu items; Dashboard's Top Clients now opens a
  proper client-focused view instead of the unfiltered Query Log.
- **Upgrade/persistence**: upgrading an existing installation (via
  `scripts/upgrade.sh` or in-app Software Updates) preserves all
  configuration and data; schema migrations are idempotent and
  interprocess-lock-protected.

## 0.4.0-beta.4 (unreleased beta update)

Not a final release. This build carries forward the administration and
observability work previously tracked under the `0.4.0~beta2` version
string, now version-bumped to `0.4.0~beta4`. (`0.4.0~beta3` was built and
tag-created but withdrawn before any GitHub Release was published -- a
first prerelease publish had to be deleted and its tag name became
permanently unusable under GitHub's immutable-releases policy; no `beta3`
package was ever distributed. All of its changes are carried forward
unchanged here.) Since the interface-polish build described below, this
line has added a full administration and observability layer and closed
several reliability gaps found during beta feedback and internal testing:

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
