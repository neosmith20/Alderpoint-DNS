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
| Cache | **restored** | Priority 3A of this beta-rescue pass. `app/v2/cache_control.py` + `cache` page: real BIND recursive-cache hit/miss/ratio via `rndc`/statistics-channel per context, real dnsdist packet-cache flush. Each layer flushed explicitly, never conflated into one "clear everything" action. See below for the real privilege-model defect found and fixed in the dnsdist flush path. |
| Filters / custom rules | redesigned | V1's ad-hoc block/allow rule CRUD -> V2's service catalog + service rulesets + schedules (`filtering` page). The import feature (priority 2) also now writes into this exact mechanism. |
| Blocklists (subscribed adlist feeds) | **restored** | Priority 3B of this beta-rescue pass. `app/v2/blocklist_subscriptions.py` + `blocklists` page: add/remove/enable/disable/refresh, last-status/last-error/rule-count, a failed refresh keeps the prior valid compiled filtering, and a daily `alderpointdns-v2-blocklist-refresh.timer` runs it in the background. Accumulates into the same shared `imported-blocklist` service ruleset the Import feature (priority 2) already writes into, so both mechanisms are actually enforced together rather than racing for the one enforced ruleset slot. |
| Encryption | redesigned | V1's single `/encryption` page -> V2 splits admin-HTTPS (`/api/tls/*`) from DNS transport encryption (`/api/dns-transports*`, DoT/DoH/DoQ/DoH3/DNSCrypt) -- these are different certificates/concerns and the split is intentional, not accidental fragmentation. Apple `.mobileconfig` profile generation **restored** this pass (priority 3D): `app/v2/mobileconfig.py`, `GET /api/dns-transports/mobileconfig/{protocol}`, only ever advertises a profile for a transport V2 actually has provisioned, using the live cert/identity state, no private key ever included. The `/api/dns-transports` management surface itself also had no UI at all before this pass -- a full DoT/DoH/DoQ/DoH3 toggle panel was added to `settings` alongside the mobileconfig work. |
| Import | restored | Priority 2 of this beta-rescue pass; see `docs/v2/import-migration-adguard-pihole-generic.md`. |
| Backup & Restore | restored | Priority 3 of this beta-rescue pass; see `docs/v2/appliance-backup-restore.md`. |
| Replication | preserved | V1 role/token/enrollment model -> V2's peer-authorization model (`replication` page); V2's is the more explicit/secure design already established before this pass. |
| Statistics | **restored** | Priority 3C of this beta-rescue pass. `app/v2/statistics_control.py`, `GET /api/statistics/export`, `POST /api/statistics/clear`, surfaced on `analytics`. Respects V2's split analytics architecture (aggregate SQLite vs raw Parquet history): clear reports exactly which of the two it affected, export uses a stable named-field schema. |
| System Status | **fixed this pass (log viewer restored)** | V1 `/system`, `/system/logs` -> V2 `health` page. Raw log viewing **restored** (priority 3E): `app/v2/log_viewer.py`, `GET /api/logs/units`, `GET /api/logs/{unit}` -- a narrowly allowlisted set of V2's own units only (never arbitrary journal/file access), real `journalctl` via the standard `systemd-journal` group (not root/sudo), severity filtering. |
| Administration | **fixed this pass** | Password change and "revoke other sessions" existed in V1.1.1 and had no V2 equivalent at all (a real security-relevant gap: an operator could not change their own password or invalidate a compromised session from the UI). Added `POST /api/session/password` and `POST /api/session/revoke-others`, audit-logged, surfaced on the System Status page. See `tests/v2/test_administration.py`. |
| Network Configuration | **restored** | Priority 4 of this beta-rescue pass. Earlier disposition ("not applicable to V2") was wrong per explicit owner rule: V2's `/api/networks` is a genuinely unrelated concept (CIDR-based policy-targeting subnets), so it was never an equivalent -- V1's appliance-own interface/address/gateway configuration had no V2 counterpart at all and needed restoring, not reclassifying away. `app/v2/network_config.py` wraps V1's already-tested `app/network_config.py` wholesale (backend detection/staging/validation/apply/auto-rollback-unless-confirmed for networkd, netplan, NetworkManager, ifupdown), redirected to V2's own state namespace. `GET/POST /api/network/status|apply|confirm`, `network` page. Still DNS-only: no DHCP server, NAT, firewall, or router functionality added. See `docs/v2/network-configuration.md`. |
| Notifications | preserved | V1 `/system/notifications/*` -> V2 `settings` page, `/api/notifications`. |
| Software Updates | restored | Priority 4 of this beta-rescue pass; see `docs/v2/software-updates.md`. |

## Fixed this pass (current beta-rescue continuation)

- DNS Cache (3A), subscribed Blocklists (3B), Statistics export/clear (3C), Apple `.mobileconfig` enrollment (3D), in-app log viewer (3E) -- all five items previously listed below as "genuinely still missing" are now implemented, wired end-to-end (backend module + API routes + UI + systemd packaging where applicable), and tested.
- Network Configuration (priority 4) -- previously misclassified "not applicable to V2"; restored as a real, tested feature per the explicit owner rule that a V1 feature is not out of scope merely because V2 was architected differently.
- Real privilege-model defect found and fixed while restoring Network Configuration: the unprivileged V2 web process (`NoNewPrivileges=true`, no root capability, no sudoers grant) can never itself call `systemctl restart` on a system unit or reconfigure a host interface. This was already latently broken in the just-committed DNS Cache flush (3A), which called `systemctl restart` directly -- fixed to ride the existing root-owned `alderpointdns-v2-dnsdist-reload.path` watcher instead. Network Configuration's apply/confirm use the same root-owned-`.path`-unit convention already established for Software Updates apply, rather than inventing sudo escalation.
- Administration password change / session revocation (real security-relevant gap, not cosmetic; carried over from a prior pass).

## Fixed in an earlier pass

(see git history for the pass that added Import, Backup & Restore, Software Updates, and Administration password/session controls)

No remaining item from the original "genuinely still missing" list is outstanding as of this pass.
