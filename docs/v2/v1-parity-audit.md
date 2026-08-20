# V1.1.1 -> V2 product/UI parity audit (beta-rescue priority 5)

Route-by-route/feature-by-feature disposition, V1.1.1 (`app/webapp.py`)
against V2 as of this pass (`app/v2/webapp.py`, `app/v2/ui/app.js`).

| Area | Disposition | Notes |
|---|---|---|
| Dashboard | preserved | V1 `/` + `/status/summary` + `/analytics/chart-data` -> V2 `dashboard` renderer using `/api/analytics/recent`, `/api/analytics/top-domains`, `/api/health`, `/api/system/status`. |
| Query Log | preserved | V1 `/query-log(/partial)` -> V2 `analytics` page, `/api/analytics/query-log`. |
| Clients | redesigned | V1's simple client list is now a managed/observed split with explicit promotion (`/api/discovery/*`), a real product improvement over V1's model, not a regression. |
| Clients & Access / groups | redesigned | V1's flat access-rule CRUD (`/clients-access/rules`) is replaced by V2's layered global/network/group/client policy model. Intentionally superseded: V2's model expresses everything V1's access rules did, plus inheritance V1 didn't have. |
| Local DNS | preserved | V1 `/local-dns` -> V2 `localdns` page, `/api/local-dns`. |
| DNS Settings | redesigned | V1's single upstream-resolver list -> V2 upstream profiles + explicit domain-routing rules (`upstreams` page). Intentionally superseded: strictly more expressive. |
| Cache | **still missing** | V1 `/dns-cache` (view stats, flush all/by-name/by-tree, cache settings) has no V2 counterpart at all. Not fixed this pass -- real work (a live dnsdist console connection from the web process, or a narrow privileged helper following the Software Updates pattern) that did not fit remaining session capacity. Tracked as a genuine remaining gap, not silently dropped. |
| Filters / custom rules | redesigned | V1's ad-hoc block/allow rule CRUD -> V2's service catalog + service rulesets + schedules (`filtering` page). The import feature (priority 2) also now writes into this exact mechanism. |
| Blocklists (subscribed adlist feeds) | **still missing** | V1 `/blocklists` (add/update/schedule a fetched adlist URL) has no V2 equivalent -- `app/v2/import_migration.py` explicitly documents this: no subscribed/refreshable blocklist feature exists, and deliberately does not add live URL-fetching to an authenticated import endpoint as a workaround. A real subscription+scheduled-refresh feature is future scope, not attempted this pass. |
| Encryption | redesigned | V1's single `/encryption` page -> V2 splits admin-HTTPS (`/api/tls/*`) from DNS transport encryption (`/api/dns-transports*`, DoT/DoH/DoQ/DoH3/DNSCrypt) -- these are different certificates/concerns and the split is intentional, not accidental fragmentation. Apple `.mobileconfig` profile generation (a V1 convenience for enrolling iOS/macOS devices in DoH/DoT) has no V2 equivalent; not restored this pass. |
| Import | restored | Priority 2 of this beta-rescue pass; see `docs/v2/import-migration-adguard-pihole-generic.md`. |
| Backup & Restore | restored | Priority 3 of this beta-rescue pass; see `docs/v2/appliance-backup-restore.md`. |
| Replication | preserved | V1 role/token/enrollment model -> V2's peer-authorization model (`replication` page); V2's is the more explicit/secure design already established before this pass. |
| Statistics | redesigned | V1's dedicated enable/clear/export page -> per-scope `query_log_enabled`/`statistics_enabled` fields on the policy layer. Export/clear actions are not restored this pass -- a real, if minor, capability gap. |
| System Status | preserved | V1 `/system`, `/system/logs` -> V2 `health` page. Raw log viewing (`/system/logs`) has no V2 equivalent; V2 relies on `journalctl`/systemd for logs rather than an in-app viewer -- an intentional platform difference, not tracked as a gap. |
| Administration | **fixed this pass** | Password change and "revoke other sessions" existed in V1.1.1 and had no V2 equivalent at all (a real security-relevant gap: an operator could not change their own password or invalidate a compromised session from the UI). Added `POST /api/session/password` and `POST /api/session/revoke-others`, audit-logged, surfaced on the System Status page. See `tests/v2/test_administration.py`. |
| Network Configuration | not applicable to V2 | V1's `/system/network/apply|confirm` manages the appliance's own physical network interface/IP configuration. V2's `/api/networks` is an unrelated concept (CIDR-based policy-targeting subnets). Whether V2 should also manage host networking is a product-scope decision for the owner, not something to silently invent. |
| Notifications | preserved | V1 `/system/notifications/*` -> V2 `settings` page, `/api/notifications`. |
| Software Updates | restored | Priority 4 of this beta-rescue pass; see `docs/v2/software-updates.md`. |

## Fixed this pass

- Administration password change / session revocation (real security-relevant gap, not cosmetic).

## Genuinely still missing (not fixed this pass, capacity-limited)

- DNS Cache page (view/flush).
- Subscribed/refreshable Blocklists (as opposed to the one-time import-derived block domains already restored in priority 2).
- Statistics export/clear actions.
- Apple `.mobileconfig` DoH/DoT enrollment profile generation.
- Raw in-app log viewer (may be an intentional platform difference -- V2 relies on journalctl).

None of these were silently dropped: each is called out explicitly here and in the relevant module's own docstring/comments where applicable, so a future pass has an exact, honest starting point rather than having to rediscover them.
