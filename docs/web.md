# Web application

Alderpoint DNS's web interface is a FastAPI/Jinja application served by
`alderpointdns.service`.

Current lab mode:

- URL: `http://<vm-lan-ip>:3000`
- Service user: `alderpointdns`
- Listener: `0.0.0.0:3000`
- Initial admin: none. The first administrator must be created through
  `/setup`.
- Password hashing: Argon2
- Session cookie: signed, `HttpOnly`, `SameSite=Strict`
- CSRF: required for mutating forms
- Login rate limiting: per source IP

The web process does not run as root. It can call only these exact privileged
commands through sudo:

```sh
/opt/alderpointdns/app/alderpointdns_compiler.py deploy
/opt/alderpointdns/app/alderpointdns_compiler.py deploy --no-download
/opt/alderpointdns/app/alderpointdns_compiler.py update-sources
```

The interface uses a shared dark-theme application shell across all admin
pages. The shell is defined in `web/templates/base.html`, reusable components
live in `web/templates/components.html`, and the visual system is maintained in
`web/static/app.css` with CSS custom properties for page background, panels,
borders, text, accent, success, warning, danger, blocked, malware, adult
category, spacing, radius, and shadows. Runtime JavaScript is local-only in
`web/static/app.js`; public CDNs are not used.

The "Clients & Access" nav item (under DNS, alongside Query Log/Clients/
Local DNS) is its own dedicated admin area -- not folded into Local DNS
despite historically-related client-alias plumbing living there -- for
persistent clients, ClientID generation, and DNS allow/deny policy. See
`docs/clients-and-access.md`.

The dashboard is organized around DNS-appliance information hierarchy:

- Protection state and protection enable/disable action with confirmation.
- Manual refresh, auto-refresh control, last refresh timestamp, and a
  session-persisted time-range selector for last hour, last 24 hours, last
  seven days, and last 30 days.
- Primary metric cards for DNS queries, blocked queries, percentage blocked,
  active clients, average response time, and active filtering rules.
- Real sparklines and a responsive local canvas time-series chart using stored
  Alderpoint DNS analytics buckets only.
- Query outcome bars for allowed, blocked, and recorded policy categories.
- Ranked panels for clients, queried domains, blocked domains, query types,
  response codes, protocol usage, and clear unavailable states for upstream
  resolver data that is not yet stored.
- Recent activity and compact system-health chips with low-level details moved
  to `/system`.

The Query Log, Blocklists, Filters, Local DNS, DNS Settings, Cache,
Encryption, Import, Backup, Replication, Statistics, System, login, and setup
pages all use the same card, table, badge, form, button, empty-state, and
confirmation styles. Authenticated pages share a grouped primary navigation:
Dashboard remains a direct link, while DNS, Security, Operations, and System
sections contain the rest of the primary pages. Active pages and parent
sections are marked with `aria-current`, and native disclosure controls keep
the navigation usable by keyboard, touch, and mobile layouts. Long domains,
IPv6 addresses, paths, command names, version strings, and URLs use wrapping
or deliberate local table scrolling so they do not create page-level
horizontal overflow.

The upper-right service-status badge is a global shell component. It uses the
same service-state logic on every authenticated page, exposes accessible text
(`Active`, `Degraded`, `Inactive`, or `Unknown`) in addition to color, and
refreshes through `/status/summary` without a page reload.

The Query Log page supports search, pagination, client/domain filters, query
type, protocol, allowed/blocked status, response code, and direct creation of
allow/block rules with confirmation and normal staged deployment. Auto-refresh
persists for the browser session and refreshes only the query-log result
container through `/query-log/partial`; it does not reload the full page.

Blocklist management supports add, inline edit, enable/disable, delete,
single-source update, update-all, and compile/deploy. Single-source updates are
unprivileged because they only write Alderpoint DNS's database and download cache;
deployment remains privileged and enumerated.

The Blocklists page also has a compact Automatic Updates panel holding the
global Filter Update Interval (`Disabled — No Updates`, `1 Hour`, `12 Hours`,
`1 Day`, `3 Days`, `1 Week`), an enabled/disabled badge, the last automatic
attempt, the last successful automatic update, the next scheduled update, and
the `Update All Now` action. Saving posts to `/blocklists/schedule`, which
validates the value against the fixed allowlist, stores it, and immediately
redeploys the `alderpointdns-filter-update.timer` schedule through the
allowlisted `filter-schedule-deploy` command; a helper failure is shown as a
page error. When updates are disabled the panel shows
`Automatic updates disabled` and no next-run time, while manual per-source
updates and `Update All Now` keep working. See docs/configuration.md for the
stored values, defaults, and systemd units.

The Filters page (`/custom-rules`) manages first-class custom filtering
rules (see `docs/filtering.md` for semantics and precedence): a summary
counts strip; a single-line add form and a collapsible bulk editor with
per-line server-side validation results (valid lines activate; invalid and
unsupported lines are stored inactive with exact reasons); server-side
search/type/status filters; a compact bulk-selectable table with type,
action, state, and source badges, hidden per-row editors, and overflow-menu
enable/disable/delete; and a "Test a domain" panel backed by
`custom_rules.evaluate_domain` showing the final action, the matching rule,
and whether the compiled blocklist RPZ would block the name. Routes:
`/custom-rules`, `/custom-rules/add`, `/custom-rules/bulk`,
`/custom-rules/test`, `/custom-rules/selected` (bulk enable/disable/delete
of selected ids), `/custom-rules/{id}/edit`, `/custom-rules/{id}/toggle`,
`/custom-rules/{id}/delete`, and the query-log quick-add
`/custom-rules/add-from-query`. All are session- and CSRF-protected and run
the normal staged no-download deployment, surfacing deploy errors as page
errors.

The Local DNS page supports:

- Internal domain settings, defaulting to `home.arpa`.
- Setup and page actions to create Alderpoint DNS's own forward and reverse records.
- Simple host entries that create A/AAAA records and optional automatic PTR
  records together.
- Advanced A, AAAA, PTR, and CNAME records with TTL, comments, and enabled
  state.
- Client aliases for dashboard/query-log display without changing DNS behavior.
- CSV preview/import/export and hosts-style preview.
- Last Local DNS deployment status, serial, validation output, and rollback
  result.

Every Local DNS mutation runs the normal no-download deployment path, which
stages generated zones, validates them, installs atomically, reloads BIND, and
records the result. Routine add/edit/toggle forms use targeted async page
updates with toast feedback instead of browser confirmation prompts or full
page reloads. Destructive record deletion still requires confirmation.

Advanced Local DNS records can use fully qualified names outside the default
internal domain. Alderpoint DNS generates an additional managed authoritative
forward zone for the parent domain and clears dnsdist packet-cache entries for
managed local zones after activation, so stale frontend NODATA responses do not
hide newly added records.

The DNS Settings page includes an Upstream Resolvers section. It displays the
current managed resolver set and supports add, edit, enable/disable, reorder,
and delete operations for UDP/TCP DNS, DNS-over-TLS, and DNS-over-HTTPS
upstreams. Changes save through targeted async forms and a scoped upstream-only
deployment path (not the full blocklist/RPZ deploy pipeline -- upstream
resolver state has no effect on it). BIND remains the recursive resolver; for
managed upstreams it forwards to a loopback dnsdist upstream pool that can
speak plain DNS, DoT, or DoH to the selected resolvers. Each upstream
deployment validates dnsdist and BIND config, restarts/reloads services, runs
a functional DNS query, records resolver health and latency, and rolls back
generated files if activation fails -- serialized, appliance-wide, against
every other runtime deployment (full or scoped) by the same deploy lock, so
two can never race the same live config files.

The Cache page (`/dns-cache`) exposes BIND's existing recursive-cache tuning
(max size, positive/negative min/max TTL, recursive clients, prefetch,
serve-stale), flush controls (entire cache, one name, or one subtree), an
explicit statistics refresh action, cache hit/miss/memory stats from BIND's
own statistics API, and recent flush/deployment history. Settings save
through the same staged/validated/atomic/rollback deployment path as Local
DNS. The dashboard shows a cache-effectiveness panel (hit rate, hits/misses,
memory) backed by the same live stats.

The Encryption page (`/encryption`) manages DoH/DoH3/DoT/DoQ (and
best-effort DNSCrypt) listeners: per-protocol enable/port, hostname and
bootstrap IP, self-signed/local-CA/uploaded/existing-path certificate modes
with match/SAN/expiry validation, a downloadable public certificate, real
per-protocol connectivity tests on every deploy, ready-to-copy client
connection info, and Apple `.mobileconfig` downloads for DoH/DoT. Plain
UDP/TCP 53 has no control on this page and cannot be disabled from the UI.

The Encryption page's Protocols and Certificate panels sit in a grid section
marked `grid align-start`, so each panel is sized only by its own content.
Expanding a Certificate disclosure section (self-signed, local CA, upload,
existing paths) grows the Certificate panel alone and leaves the Protocols
panel at its natural height instead of stretching it and opening artificial
empty space. The section still collapses to a single stacked column at narrow
widths. `tests/test_encryption_layout.sh` measures this in headless Chromium
at wide desktop, standard desktop, tablet, and mobile widths.

The Import page (`/import`) and Migration entry point (`/import/migration`)
migrate from AdGuard Home (uploaded `AdGuardHome.yaml` or a direct read-only API
connection), Pi-hole text/list exports, and Alderpoint DNS-native JSON exports.
They also import Local DNS records from CSV/XLSX/hosts/BIND-zone/Alderpoint
DNS-CSV sources, with column mapping, a normalized preview
(valid/invalid/duplicate/conflict), per-conflict skip/merge/replace resolution,
an automatic pre-apply backup, and rollback of exactly the rows a Local DNS
import added. Migration previews show items to add, items to update, conflicts,
skipped source entries, and unsupported source features before anything is
applied.

Import jobs use non-overlapping routes: `/import/upload`,
`/import/jobs/{job_id}`, `/import/jobs/{job_id}/status`,
`/import/jobs/{job_id}/preview`, `/import/jobs/{job_id}/apply`,
`/import/jobs/{job_id}/cancel`, and `/import/jobs/{job_id}/report`. Literal
migration route components such as `/import/migration` are never parsed as job
IDs.

The Backup page (`/backup`) creates versioned, checksummed, optionally
password-encrypted archives with selectable components (private keys and
credentials require an explicit confirmation), imports archives from
elsewhere, and restores through a mandatory preview-first dry-run diff, an
automatic pre-restore safety backup, and automatic rollback on any
post-restore health-check failure. Scheduled backups run via a systemd
timer with configurable interval and retention.

The Replication page (`/replication`) configures a node as standalone,
primary, or replica. A primary issues short-lived, single-use enrollment
tokens, runs an in-process HTTPS listener on the configured replication port,
and serves numbered, content-hashed generations over mutual TLS. A replica
enrolls with the primary, stores the returned CA/client certificate material,
polls for the latest generation, verifies its hash, applies only the
replication allowlist into local tables, and then reuses the normal
`alderpointdns_compiler.py deploy --no-download` pipeline. Failed replica deploys
roll back the replica SQLite changes as well as relying on the compiler's
configuration rollback; revoked replicas are denied by certificate
fingerprint before generation fetch or ACK.

Useful commands:

```sh
systemctl status alderpointdns --no-pager
systemctl status alderpointdns-analytics --no-pager
systemctl restart alderpointdns
systemctl restart alderpointdns-analytics
/opt/alderpointdns/tests/test_web_smoke.sh
```

Responsive review targets are 1920, 1440, 1024, 768, 430, and 360 pixels wide.
The smoke test renders long domains, IPv6 clients, and long upstream URLs and
checks the shared no-overflow CSS contract, mobile navigation hooks, chart data
endpoint, local-only static assets, and dashboard/query-log/settings page
rendering.

The admin listener binds to `0.0.0.0:3000` and requires a Alderpoint DNS admin
session. Your network firewall (VLAN/segmentation rules) is responsible for
restricting network reachability to the management UI.
