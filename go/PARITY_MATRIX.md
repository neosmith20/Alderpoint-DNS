# Alderpoint DNS V2 — Go/Svelte Route-by-Route Parity Matrix

**Status:** authoritative tracking document for the complete Go/Svelte management-application
rewrite. Supersedes `MILESTONE_1_REPORT.md`'s framing of the existing Blocklists/Local DNS work as
a completed frontend milestone — that work is a **foundation slice** (proves the architecture:
Go control-plane API shape, Svelte 5 + strict TS toolchain, auth/session/CSRF, staged-deploy
pattern, isolated preview pipeline). It is not frontend parity. No route below may be marked
`done` until it is real, tested, and owner-accepted end to end — see `docs/v2/v2-roadmap.md`'s
"Definition Of Workflow Parity": a model, a route, or a page with the same title is not parity.

**Source of truth for the Python surface:** `app/v2/webapp.py` (single FastAPI module, 116 routes,
no HTML templates — it serves one SPA shell, `app/v2/ui/index.html`, plus `app/v2/ui/app.js`
(3701 lines, all 20 page renderers + router), `app/v2/ui/data-grid.js` (shared table behavior),
`app/v2/ui/app.css`). V1's `web/templates/*.html` (25 templates, `app/webapp.py`, 141 routes) is a
separate legacy app and is **not** part of this rewrite's target surface — V2 already superseded it
as the functional reference, per the roadmap.

**Testing infrastructure:** `go/tests/acceptance.py` (black-box API, language-neutral) and
`go/tests/browser/chromium_smoke.mjs` (real headless Chromium via `puppeteer-core` against
`/usr/bin/chromium` -- no bundled download, no mocking) are both run against every coherent slice
before it's deployed to `:10443`, not deferred to the end. Run the Chromium harness with
`cd go/tests/browser && npm install && node chromium_smoke.mjs <https-base-url> <username> <password>`
against a **fresh** (`setup_required: true`) instance -- it drives real setup/login and must not be
pointed at the live owner preview, whose credentials are Alex's. `go/tests/browser/perf_measure.mjs`
(same invocation shape) measures real client-side navigation latency.

**Performance (measured 2026-08-26, this build server, real Chromium + curl, not estimated):**

| Metric | Target | Measured |
|---|--:|--:|
| Cold load to first usable screen | < 2000 ms | 1038 ms |
| Route click -> new heading visible (p50, 4 routes) | < 50 ms | 17-29 ms |
| Route click -> new heading visible (max observed) | -- | 38 ms |
| Idle RSS after setup+login | < 25 MB (known-missed, see `MILESTONE_1_REPORT.md`) | 33.5 MB |
| `GET /api/health` (p95 / p99, n=150) | < 25 ms / < 50 ms | 6.95 / 9.33 ms |
| `GET /api/dashboard/summary` (p95 / p99) | < 25 ms / < 50 ms | 7.13 / 8.07 ms |
| `GET /api/analytics/timeseries` (p95 / p99) | < 25 ms / < 50 ms | 8.18 / 8.87 ms |
| `GET /api/analytics/top-domains` (p95 / p99) | < 25 ms / < 50 ms | 17.15 / 18.40 ms |
| `GET /api/blocklists` (p95 / p99) | < 25 ms / < 50 ms | 7.00 / 7.29 ms |
| `GET /api/local-dns` (p95 / p99) | < 25 ms / < 50 ms | 6.91 / 7.20 ms |

All gates met except idle RSS, which was already a known, root-caused, disclosed miss from
Milestone 1 (146 MB -> 36.4 MB fix landed then; 33.5 MB here is consistent, not a new regression --
no auth/session code changed this slice). `top-domains` is the slowest endpoint (a `GROUP BY`
across 24 hours of hour-granularity `dimension_counts` rows) but is still ~3x under its p99 budget.

**Authoritative target surface** (per the governing task): the union of (a) what Python V2 actually
does today, (b) required V1.1.1 workflow semantics per `docs/v2/v1-workflow-parity-contract.md`,
(c) accepted owner corrections already recorded in that contract and in `docs/v2/v2-roadmap.md`'s
"Locked Owner Decisions", and (d) newly approved V2-only functionality. Where Python V2 itself has a
known, documented defect (e.g. a11y/nav bugs already fixed post-audit, raw-ID leaks), the fix is the
target, not the defect — literal bug-for-bug parity is not the goal.

**Status columns legend:** `not started` / `in progress` / `api done` / `ui done` / `done (browser-tested)` / `done (owner-accepted)`.

## Legend for shared mechanics (referenced per-row instead of repeated)

- **Shared data grid**: client-side sort (numeric-aware), drag-resize (persisted per grid id),
  capped row count with overflow notice, no server pagination in Python V2 today, auto-wrap in
  scrollable container. One Svelte component to build once, used by every table row below.
- **Timestamp modes**: Browser Local / Appliance Time / UTC, instant reformat, no refetch. One
  shared mechanism (Administration page owns the preference; every other page consumes it).
- **CSRF/session**: already implemented in the Go foundation slice (`internal/auth`) — reused by
  every route below, not re-derived per page.
- **Stale-response/mutation-race protection**: already implemented for Blocklists
  (`staleGuard.ts`) — the pattern generalizes to every other page's mutations, not rebuilt per page.

---

## Pre-auth

| Page | Route | Python API | Controls | Go API | Svelte | Browser test | Owner accepted |
|---|---|---|---|---|---|---|---|
| Setup / Login | (no nav; gated by `/api/setup/status`) | `GET /api/setup/status`, `POST /api/setup`, `POST /api/login`, `POST /api/logout`, `GET /api/session` | Shared auth form, password show/hide, live mismatch validation | done | done | in progress (acceptance.py covers it; no Chromium yet) | not started |

## Dashboard (top-level, no group)

| Page | Route | Python API | Controls | Tables | Charts/live | Polling | States | Go API | Svelte | Browser test | Owner accepted |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Dashboard | `dashboard` | `GET /api/health`, `/api/system/status`, `/api/replication/health`, `/api/discovery/status`, `/api/analytics/recent`, `/api/clients`, `/api/discovery/observed-clients`, `/api/upstreams`, `/api/analytics/timeseries`, `/api/analytics/live-activity`, `/api/analytics/{top-domains,top-blocked-domains}` | Refresh; range select (Live/1h/24h/7d); top-domains mode select; live pause/resume; **card add/remove/reorder + persistence (not yet in Python V2 either — new V2 requirement)** | Upstreams mini-table, Top-domains table, client mini-list | DNS Activity SVG time-series (queries + blocked), live 1s mode | `setInterval` 1000ms in live mode only, cleared on route leave | degraded banner, live status states (Connecting/Connected/Paused/Reconnecting/Degraded), empty states | **in progress** -- `GET /api/dashboard/summary` (Go-native: blocklists + local-dns + `analytics_available`) plus `GET /api/analytics/{timeseries,live-activity,top-domains,top-blocked-domains}` now real, backed by `internal/pyanalytics` (the compatibility boundary -- read-only SQLite read of Python's own `analytics/aggregates.db`, mounted read-only into the Go container; proven against the actually-live preview's actively-written data, not just a copy; see that package's doc comment). `top-blocked-domains` is honestly, permanently degraded through this boundary (needs Python's raw Parquet/DuckDB path, incompatible with this project's `CGO_ENABLED=0` build). Still missing: Upstreams mini-table, client mini-list -- those need the *policy* boundary (a separate, not-yet-built piece; see the Sequencing note) | **in progress** -- `DashboardView.svelte`: real cards (Blocklists, Local DNS, DNS Activity chart, Top Domains, Top Blocked Domains-with-honest-unavailable), full range selector including live 1s polling (cleared on mode change/route-away), card add/remove/reorder with persistence. Upstreams/clients cards not built (blocked on the policy boundary) | done for everything built (66 Chromium checks: range switching, live polling doesn't error, chart renders both series, DataGrid sort-changes-order + drag-resize-changes-width + width-persists-across-reload, customize hide/reorder/persist across reload, honest degraded text for Top Blocked Domains, full 4-route x 3-viewport x 2-theme sweep with zero horizontal overflow) | not started |

## DNS group

| Page | Route | Python API | Controls | Tables | Charts/live | Polling | States | Go API | Svelte | Browser test | Owner accepted |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Query Log | `analytics` | `GET /api/analytics/query-log`, `/api/analytics/top-domains` | Filter form (window/search/domain/client/qtype/protocol/rcode/upstream/cache-status/limit/blocked-only); Refresh; **Query Log → rule creation (roadmap-required, not yet in Python V2)** | Recent Queries grid, Top Domains grid | — | none | degraded banner, active-filter badge, empty | not started | not started | not started | not started |
| Clients | `clients` | `GET /api/clients`, `/api/discovery/observed-clients`, `/api/discovery/status`, `/api/groups`; `POST /api/clients`, `/clients/{id}/identifiers`, `/clients/{id}/groups`, `/discovery/observed-clients/{ip}/promote`; `DELETE /discovery/observed-clients/{ip}` | Metric strip; "Manage Client" (not "Promote" — locked owner decision) + Forget; Create Managed Client form; Explain link → Policies | Observed Clients grid, Managed Clients grid | — | none | unmanaged/client-N badges, empty | not started | not started | not started | not started |
| Clients & Access (Policies) | `policies` | `GET /api/policy/global`, `/api/networks`, `/api/groups`, `/api/clients`; `PUT /policy/{global,network/{id},group/{id},client/{id}}`; `POST /networks`, `/groups`; `GET /policy/explain` | Global/Network/Group/Client policy editors (shared field set: filtering profile, safesearch, parental/security policy, blocking response mode+custom IP, upstream, fallback strategy, ECS mode, domain routing, query-log/statistics tri-state); Create Network/Group forms; Explain panel | expandable per-object editors | — | none | inherit badges | not started | not started | not started | not started |
| Local DNS | `localdns` | `GET /api/local-dns`, `POST /api/local-dns` | Add Record form (name/type/value/TTL); **edit + delete are a Milestone-1 addition already, ahead of Python V2** | Records grid | — | none | — | **done** (Milestone 1) | **done** (Milestone 1) | not started | not started |
| DNS Settings (Upstreams & Routing) | `upstreams` | `GET /api/upstreams`, `/api/domain-routing`; `POST /upstreams`, `PUT /upstreams/{id}`, `POST /upstreams/{id}/{enable,disable}`, `DELETE /upstreams/{id}`, `POST /upstreams/reorder`; `POST /domain-routing` | Create/Edit Upstream form; per-row Edit/Enable-Disable/Delete + up/down reorder; last-enabled confirm guard (locked owner decision: zero managed upstreams allowed with warning); Domain Route form | Upstream Profiles grid (ordered), Domain Routes grid | — | none | native-recursion info banner when zero enabled | not started | not started | not started | not started |
| Cache | `cache` | `GET /api/cache/status`, `POST /api/cache/flush` | Per-BIND-context flush form (scope/target); dnsdist packet-cache flush; Refresh | plain status table | — | none | unavailable badge, empty | not started | not started | not started | not started |

## Security group

| Page | Route | Python API | Controls | Tables | Go API | Svelte | Browser test | Owner accepted |
|---|---|---|---|---|---|---|---|---|
| Filters (Custom Rules) | `filtering` | `GET /api/services`, `/api/service-rulesets`, `/api/schedules`, `/api/policy/global`; `PUT /policy/global`; `POST /services`, `/service-rulesets`, `/schedules`; `PUT /policy/schedule/{id}` | Global Answer Policy editor; Create Service/Ruleset/Schedule forms; **V1/AdGuard-style allow/block/regex/rewrite/precedence + Query Log→rule (locked owner decision, not yet in Python V2 — required for both)** | Service Catalog, Rulesets, Schedules grids | not started | not started | not started | not started |
| Blocklists | `blocklists` | `GET /api/blocklists`; `POST /blocklists/settings`, `POST /blocklists`, `POST /blocklists/{id}/interval`, `PATCH /blocklists/{id}`, `POST /blocklists/{id}/toggle`, `DELETE /blocklists/{id}`, `POST /blocklists/{id}/refresh`, `POST /blocklists/refresh-all`, `GET /blocklists/jobs/{id}` | Update All; global interval + Save; Add Subscription; per-row Edit (dialog)/Update Now/Enable-Disable/Delete; attention card (≥3 consecutive failures) | Subscriptions grid, Recent Updates | **done** (Milestone 1, incl. immediate pull, attention threshold, previous-good retention, per-row pending feedback, stale-delete guard) | **done** (Milestone 1) | not started | not started |
| Encryption | `encryption` | `GET /api/tls/status`, `/api/dns-transports`; `PUT /dns-transports`; `POST /tls/replace`; `GET /dns-transports/mobileconfig/{protocol}`, `POST /dns-transports/dnscrypt/rotate` | Cert status + replace form; DoT/DoH/DoQ/DoH3/**DNSCrypt** (locked owner decision: first-class, discoverable, not hidden) enable+port form; Apple `.mobileconfig` download links | TLS status table | not started | not started | not started | not started |

## Operations group

| Page | Route | Python API | Controls | Tables | Go API | Svelte | Browser test | Owner accepted |
|---|---|---|---|---|---|---|---|---|
| Import | `importexport` | `GET /api/import/jobs`; `POST /import/jobs`, `/import/jobs/{id}/apply`; `GET /api/migration/detect` | Source-type select (AdGuard YAML/live API, Pi-hole paste, hosts, BIND zone, Alderpoint CSV/XLSX/JSON); preview with per-item selection + status badges; Apply | Recent Import Jobs grid | not started | not started | not started | not started |
| Backup & Restore | `backup` | `GET /api/backup/appliance`, `/api/backup/secrets`; `POST /backup/appliance{,/upload,/upload-settings}`, `DELETE /backup/appliance/uploads/{id}`, `POST /backup/appliance/{name}/{validate,restore}`, `POST /backup/secrets{,/…/validate,/…/restore}` | Create local/portable backup; upload+preview dropzone (`.apdnsbak`/`.tar.gz` — **V1.1.1 `.tar.gz` compatibility is a hard requirement**); retention settings; restore preview (recommended/all/none selection, conflict policy, sensitive-category ack, typed-filename confirm — **mandatory pre-restore safety backup is a locked requirement**) | Appliance backups, Uploaded archives, Safety backups, Restore jobs, Secret backups grids | not started | not started | not started | not started |
| Replication | `replication` | `GET /api/node-identity`, `/api/replication/{health,peers}`; `PUT /replication/peers/{id}`; `DELETE /replication/peers/{id}`; `POST /replication/peers/{id}/sync`, `/replication/issue-peer-cert` | Metric strip; Add/Update Peer form (identity, URL, cert SHA-256, CA/client cert/key PEM, direction); per-peer Sync | Peers grid | not started | not started | not started | not started |

## System group

| Page | Route | Python API | Controls | Tables/panels | Go API | Svelte | Browser test | Owner accepted |
|---|---|---|---|---|---|---|---|---|
| Statistics | `statistics` | `GET /api/statistics/export`; `POST /statistics/clear` | Export link; Clear form (typed "CLEAR" confirm + raw-history option) | — | not started | not started | not started | not started |
| System Status | `health` | `GET /api/health`, `/api/system/status`, `/api/node-identity`, `/api/discovery/status`, `/api/dns/performance`; `POST /dns/performance/benchmark`; `DELETE /dns/performance` | Copy UI Perf Report / Clear Measurements / Refresh; Run Safe DNS Benchmark / Copy DNS Perf Report / Clear | Metric strip, UI Performance table (session-only), DNS Performance panel, BIND Cache Counters, Components, Node Identity | not started | not started | not started | not started |
| Administration | `administration` | `GET /api/system/status`; `POST /session/password`, `/session/revoke-others` | Change Password; Revoke Other Sessions; multi-open nav pref; **Timestamp Display selector (Browser Local / Appliance Time / UTC)** | — | done | done | done (Chromium, see below) | not started |
| Network Configuration | `network` | `GET /api/network/status`; `POST /network/apply`, `/network/confirm` | Change config form (IPv4/IPv6 mode+address+gateway); pending-config confirm with ~120s auto-revert | Current Settings table | not started | not started | not started | not started |
| Notifications | `notifications` | `GET /api/notifications`; `POST /notifications` | Create Provider (webhook/email_smtp/pushover/slack), write-only secret field | Providers grid | not started | not started | not started | not started |
| Software Updates | `updates` | `GET /api/updates/{status,jobs}`; `PUT /updates/settings`; `POST /updates/upload`, `/updates/jobs/{id}/apply` | Metric strip; Private Feed form; Manual `.deb` upload+stage; per-job Apply (with reconnect-poll after restart) | Update Jobs grid | not started | not started | not started | not started |
| Logs (System Logs) | `logs` | `GET /api/logs/units`, `/api/logs/{unit}` | Unit + severity + line-count filter form; **"All" option required** (governing-task requirement; confirm Python has it — see open question below) | Log entries table | not started | not started | not started | not started |

## Cross-cutting / shell-level (Phase 2, not a single page)

| Item | Source | Go API | Svelte | Browser test | Owner accepted |
|---|---|---|---|---|---|
| Nav shell: 4 groups (DNS/Security/Operations/System) + Dashboard, accordion multi-open pref, collapsed flyout, keyboard/pointer/touch | `app.js` GROUP_ORDER + accordion fix history in `v1-workflow-parity-contract.md` | n/a | in progress (`Nav.svelte`, `nav.ts`: full IA, accordion+persist (Administration's "keep multiple open" toggle wired in `navPrefs.ts`), collapsed flyout, off-canvas drawer <760px; Escape handled; arrow-key roving focus not yet added) | in progress -- Chromium now sweeps all 4 implemented routes x 3 viewports (1440/1024/390) x 2 themes (24 checks, all pass: real content renders, zero horizontal overflow) plus 390px drawer open/Escape-close; the collapsed-rail (1120px) flyout and keyboard roving focus specifically are still not individually Chromium-asserted | not started |
| Shared data grid (sort/resize/persist/overflow) | `data-grid.js` | n/a | done (`DataGrid.svelte`; used by every existing page's tables, replacing ad hoc `<table>` markup) | done -- Chromium proves each mechanic actually works, not just renders: clicking a sortable header changes row order (asc then desc), dragging the resize handle changes the column's real pixel width, and that width survives a full page reload (localStorage per gridId) | not started |
| Theme (light/dark), design tokens, local SVG icons | roadmap "Final Product Experience" | n/a | in progress (light/dark CSS-var tokens carried over from Milestone 1; icon set added this slice; no dedicated design-system pass yet) | done (Chromium: theme toggle flips `data-theme`) | not started |
| Timestamp engine (3 modes, instant reformat) | `app.js` timestamp display | n/a | done (`timestamp.svelte.ts`: reactive singleton, Administration owns the picker; not yet consumed by any *other* page's table, since neither existing page has a timestamp column yet) | done (Chromium: mode change updates the on-screen preview instantly) | not started |
| Toasts, dialogs, confirmation flows, action menus (kebab/overflow) | `app.js` shared UI | n/a | not started | not started | not started |
| Route-level code splitting, cancellation, stale-response protection generalized from `staleGuard.ts` | governing task Phase 2 | n/a | done — build-verified (`RouteLoader.svelte` dynamic `import()`; `dist/assets` shows per-page JS/CSS chunks split from the main bundle). `router.svelte.ts`'s per-navigation `AbortSignal` is wired into both existing pages' list fetches (`api.listBlocklists`/`listLocalDNS` now take a signal) -- routing away actually aborts the in-flight request, not just discards its result. Not yet threaded through every mutation call on those pages, and not yet a pattern documented for future pages beyond this example. | not started | not started |

---

## Open questions to resolve against the code (not guessed here)

1. **Logs "All" option**: the inventory found a fixed `LOG_UNITS` select with 8 named units; confirm
   whether an "All" aggregate option exists in Python today or is a new V2 requirement — check
   `app.js` `logs()` and `GET /api/logs/units` response before building the Go equivalent.
2. **Dashboard card customization** (add/remove/reorder/persist): not present in Python V2 per the
   inventory — this is new V2-only scope per the governing task, needs its own small design pass
   before implementation, not an inference from Python behavior.
3. **Query Log → rule creation** and **V1-style custom-rule semantics** (Filters page): locked owner
   decisions in the roadmap, not yet built in Python V2 either. Build against the roadmap's stated
   semantic classes (allow/block/regex/rewrite/precedence/bulk/validate/import), not against a
   Python implementation that doesn't exist yet.

## Sequencing note: the Python compatibility-boundary design gate

Two real technical facts constrain how any Go<->Python compatibility boundary can work safely:

1. **The two backends' sessions are not interchangeable**, despite sharing a cookie name
   (`alderpointdns_v2_session`, deliberately matched for parity) -- each has its own independent
   session table. A naive "forward the incoming cookie to Python" proxy will not authenticate.
2. **"Do not duplicate authoritative state"** (governing task, Phase 4) rules out silently copying
   Python's policy/analytics data into Go's own SQLite -- the boundary has to be a read path
   (direct read-only access to Python's existing stores, or a proxy with its own auth), not a
   second copy.

**Analytics boundary: designed and built** (`internal/pyanalytics`, 2026-08-26). Shape: a direct
read-only SQLite connection to Python's own `analytics/aggregates.db`, mounted read-only into the
Go container (only the `analytics/` subdirectory -- never `control.db`, admins, or secrets). No new
auth surface needed at all, because it never goes through Python's HTTP API or session system in
the first place -- fact 1 above is sidestepped entirely rather than solved. Verified safe (WAL mode
means concurrent readers never block Python's writer) and verified working against the actually-
live, actively-written preview database, not just a static copy. This unblocks Dashboard's
DNS-Activity/Top-Domains data (done, see the Dashboard row) and, going forward, Query Log's
underlying data (still needs its own page built) and any other page that only needs
*read-only analytics*.

**Policy boundary: still not built.** DNS Settings/Upstreams, Clients & Access, Filters, and every
page whose data lives in Python's `control.db` policy tables (not analytics) needs either (a) a
native Go schema + CRUD for that domain (the Blocklists/Local DNS/Dashboard pattern -- Go owns it
outright, no boundary at all, the actual end-state per the Definition of Done's "no permanent
dependency on the Python web application") or (b) a *write-capable* boundary, which is a much bigger
trust/consistency problem than the read-only analytics case above (a write needs to go through
Python's own validation/staging/promotion, or Go needs to reimplement that safely itself) and is
not something to design in passing. Given the Definition of Done explicitly rules out a permanent
proxy, **native Go schema + CRUD is the intended target, not a boundary** -- DNS Settings/Upstreams
is next, built the same way Blocklists/Local DNS/Local DNS already are: real Go tables, real Go
service logic, informed by reading Python's `policy_store.py`/`policy_model.py` for the exact
semantics to preserve, not proxied.

## Non-goals carried over from Milestone 1 (still correct, restated here)

Per `docs/v2/v2-roadmap.md`'s Locked Architecture: DNS hot path (dnsdist → BIND → upstream) never
synchronously depends on the control plane, in Go or Python. Runtime workers not yet in Go
(analytics, discovery, replication, schedule, tier-B, protobuf-receiver) are reached through the
existing authoritative SQLite/YAML/compiled-runtime mechanisms per the governing task's Phase 4
compatibility-boundary rule — tracked per-endpoint in this matrix as each page's Go API work lands,
not proxied wholesale through the Python web app.
