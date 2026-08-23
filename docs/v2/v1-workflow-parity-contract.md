# Alderpoint DNS V1.1.1 -> V2 Workflow Parity Contract

**Canonical status:** this is the authoritative private V2 workflow-parity contract.

**Roadmap:** `docs/v2/v2-roadmap.md`.

**V1 baseline:** the exact accepted V1.1.1 release is the minimum operator-workflow baseline unless
the owner explicitly approves replacing or removing a workflow.

## Definition Of Workflow Parity

A V1 feature is not preserved merely because V2 has a model, table, database row, route, one GET
endpoint, one POST endpoint, page with the same title, or similarly named object.

For applicable product workflows, preserved means:

`operator UI -> authenticated API -> validation -> transactional desired state -> compile/promote -> runtime state -> client-visible DNS/result where applicable -> restart persistence -> full object lifecycle where applicable`

Lifecycle includes as appropriate:

- Create.
- Inspect.
- Edit.
- Enable.
- Disable.
- Delete.
- Order/priority.
- Bulk actions.
- Update/refresh.
- Import/export.
- Validation/test.
- Status/telemetry.

If V1 had that lifecycle and V2 has only Add/List, parity has not been achieved.

## Current Status Summary

RC51 is not V1.1.1 workflow-parity complete. The statuses below are intentionally conservative:
partial UI, database, route, or model presence does not count as parity unless the complete operator
workflow is proven end to end.

Severity definitions:

- P0: runtime/security/data-truth blocker.
- P1: mature product workflow missing or broken.
- P2: significant UX/management regression.
- P3: polish/improvement.

## Workflow Matrix

| Area | Required V1.1.1 Workflow Semantics | Current V2 Contract Status | Severity |
|---|---|---|---|
| Dashboard | Real activity, query volume, query outcomes, cache effectiveness, upstream information, recent activity, system health, Top Domains, Clients, explicit degraded-data status. | Incomplete. Dashboard must distinguish no data from degraded analytics and must show exact-client and Top Domains data only when the ingestion path is healthy. | P0 |
| Query Log | Filtering/search, bounded history, refresh, inspect request/result, Query Log -> custom allow/block rule. | Incomplete. Query Log must become a rule-creation source and must not present empty results as truth when analytics ingestion is degraded. | P1 |
| Clients | Observed exact clients, managed clients, Manage Client flow, edit, enable/disable where applicable, delete, identifier lifecycle, friendly names, group/policy assignments. | Incomplete. Observed identities must be exact; ambiguous "Promote" wording is replaced by Manage Client. Prefix/loopback observations cannot be persisted as clients. | P0 |
| Clients & Access | Default allow/deny behavior, explicit access rules, persistent client lifecycle, strong ClientID lifecycle, runtime enforcement. | Incomplete. V2 policy objects must prove equivalent runtime access enforcement, not merely row presence. | P0 |
| Strong ClientID | Cryptographically strong generated identifiers; V1-equivalent 192/256-bit capability; multiple identifiers per client; encrypted-DNS identity matching; DoT/DoQ SNI behavior where applicable; DoH path identity behavior where applicable; access/policy enforcement; create/revoke lifecycle. | Incomplete. A `clientid` database row is not parity unless dnsdist/runtime can enforce the identity semantics. | P0 |
| Local DNS | Settings, server/appliance records where applicable, hosts, A, AAAA, CNAME, PTR, aliases, edit, enable/disable, delete, import preview, import/apply, export, runtime DNS proof. | Incomplete. Visual hostname/IP fields must not be treated as appliance network configuration unless they actually configure OS hostname/interface state. Runtime DNS proof is required. | P1 |
| DNS Settings / Upstreams | Create, inspect, edit, enable, disable, delete, ordering/priority, status/telemetry, validation, runtime truth, zero-forwarder/native-recursion mode, domain routing, fallback behavior. | Incomplete. Operators may disable all forwarders with confirmation; zero forwarders means BIND native recursion. No hidden fallback is allowed. | P0 |
| Cache | Size controls, TTL controls, negative TTL controls, prefetch, serve stale, recursive-client/cache behavior where applicable, flush all, flush name, flush subtree, telemetry. | Incomplete. Controls must map explicitly to dnsdist and BIND layers rather than copying V1 internals blindly. | P1 |
| Filters / Custom Rules | Allow, block, regex, rewrites, precedence, edit, enable/disable, delete, bulk add, bulk enable/disable/delete, validation, rule test/evaluate, Query Log -> rule, migration/import compatibility. | Incomplete. Modern builder is allowed only as an addition; V1/AdGuard-style semantics and migration compatibility remain required. | P1 |
| Blocklists | Add, edit, enable, disable, delete, update individual, Update All, categories, category lifecycle, update schedule, counts/status, last update, failure state, bounded retries, last-known-good behavior, runtime enforcement truth. | Incomplete. Toggle/edit/update status must prove compiled runtime effect; Update All is required. | P1 |
| Encryption | Certificate generation, self-signed/local CA workflow, upload, safe existing-certificate path workflow, validation/status, DoT, DoH, DNSCrypt, enhanced DoQ/DoH3 where supported, mobile/Apple profile generation, transport status. | Incomplete. DNSCrypt is first-class and discoverable from Encryption, not hidden. Certificate and transport status must reflect runtime truth. | P1 |
| Import / Migration | Detect, preview, findings, inactive unsupported findings rather than silent loss, apply, V1 native, AdGuard, Pi-hole, hosts, BIND, CSV/XLSX/other supported formats, semantic preservation of custom rules/clients where possible. | Incomplete. Unsupported semantics must be explicit findings, not silently dropped. | P1 |
| Backup / Restore | Create, list, download, upload/import, preview, restore, delete, scheduled backup, retention, size limits/controls, secrets handling, transactional restore. | Incomplete. Backup claims must cover the full lifecycle and protected-secret recovery semantics. | P1 |
| Replication | Peer lifecycle, authorization, enable/disable, delete, sync/status, conflict/failure handling, mTLS. | Open for full workflow proof. V2 architecture may be stronger, but lifecycle and failure handling must be verified end to end. | P1 |
| Statistics / Analytics | Enablement, detailed logging, privacy mode, anonymization, retention, bounded storage, intervals, clear, export, Top Domains, Clients, query outcomes, upstreams, cache, explicit degraded state. | Incomplete. Analytics failure must be visible while DNS remains independent. Empty charts are not acceptable degraded-state reporting. | P0 |
| System Status / Logs | Service health, worker progress, analytics health, discovery health, dnsdist/BIND health, allowlisted logs, degraded state versus no data. | Incomplete until health covers analytics/discovery ingestion and differentiates degraded state from empty state. | P1 |
| Administration | Password/session behavior, supported account lifecycle, security controls. | Open for workflow proof. Existing security surfaces must be verified by browser acceptance, restart persistence, and error handling. | P2 |
| Network Configuration | Actual appliance/network configuration, transactional apply/confirm/rollback, clear distinction from Local DNS records. | Incomplete/open for proof. Hostname/IP fields must either configure OS/appliance state or be clearly scoped to Local DNS records. | P1 |
| Notifications | SMTP/webhook, create, edit, enable, disable, delete, test, clear failure, event subscriptions, severity, cooldown, provider status. | Incomplete. Provider rows/endpoints are not parity without lifecycle, status, delivery test, subscription, cooldown, and failure recovery. | P1 |
| Software Updates | Check, stage, validate, apply, status, rollback/failure behavior where designed, privilege separation, private/public feed behavior appropriate to development stage. | Open for workflow proof. Web UI must not gain apt/sudo capability. Private feed behavior must match the private development stage. | P1 |
| Setup / First Run | Initial setup, admin credential creation, network assumptions, DNS service readiness, appliance identity where applicable. | Incomplete/open. Setup must not imply OS/network configuration when only Local DNS records are being created. | P1 |
| UI Foundation | Usable hierarchical navigation, collapsed state, shared sortable/resizable data grids, friendly object selectors, consistent actions and confirmations, accessible status/error states. | Partial. Hierarchical nav (parent toggle/flyout/collapsed rail/keyboard escape/persisted open-state) was already implemented pre-reset and re-verified against this contract, unchanged. `app/v2/ui/data-grid.js` now provides one shared sortable/resizable table implementation (click-to-sort with visual indicator, drag column resize, persisted per-table sort/width, horizontal overflow, `[object Object]`-safe) wired via a `document`-level delegated listener + MutationObserver so it survives every `innerHTML` re-render without per-page glue code; applied to the major tables (Dashboard Top Domains/Upstreams/Clients, Query Log results/Top Domains, Filters rulesets/schedules/services, Upstream Profiles/Domain Routes, Local DNS records, Notification providers, Observed/Managed Clients, Blocklist subscriptions). Friendly-object-selector and internal-ID audit is still open (see below). Interactive proof (real click/drag/persistence in a browser) still requires the workstream 14 Chromium pass -- not yet run for this change, so this row stays open rather than "complete". | P2 |
| Runtime / Control / UI Truth | UI, control state, compiled state, runtime, and client-visible DNS result agree after successful mutation. Pending/degraded/failed states are explicit. | Incomplete. This is a hard acceptance rule across all runtime-affecting features. | P0 |

## Owner-Beta Findings With Contract Homes

| Owner Finding | Contract Home | Required Target Behavior |
|---|---|---|
| Main menu/sidebar cannot properly minimize/use groups; some sections land on unrelated Query Log. | UI Foundation. | Parent items consistently toggle submenu or open useful landing pages; collapsed sidebar remains usable and accessible. |
| Data tables lack sort/reverse sort, resizable columns, usable overflow, and shared behavior. | UI Foundation. | Shared data-grid component used across major tables. Addressed: `app/v2/ui/data-grid.js`; Chromium interaction acceptance still pending (workstream 14). |
| Default and added upstream providers cannot be disabled/removed properly; final provider cannot be disabled. | DNS Settings / Upstreams. | Full lifecycle, ordering, runtime truth, and allowed zero-forwarder native recursion with confirmation. |
| Blocklists lack Update All and may only flip a database boolean. | Blocklists. | Individual and bulk update, lifecycle, status, retries, last-known-good, and compiled runtime enforcement proof. |
| Client attribution shows `192.168.32.0`, `127.0.0.1`, missing activity, empty Top Domains, ambiguous Promote. | Clients; Statistics / Analytics; Exact Client Attribution. | Exact originating client identity preserved asynchronously; unknown/degraded status when unavailable; Manage Client wording and lifecycle. |
| dnsdist reports remote logger `127.0.0.1:5391` connection refused and security-status errors. | Statistics / Analytics; System Status / Logs; Package And Security Contract. | DNS independent; analytics degraded state explicit; receiver ownership/startup/recovery accepted; package security baseline verified without stale version pins. |
| Local DNS appears shallow versus V1 workflow. | Local DNS. | Complete record/settings/import/export lifecycle with runtime DNS proof. |
| Custom rules roadmap says behavior must survive, but V2 risks replacing it with a different model. | Filters / Custom Rules. | V1/AdGuard-style allow/block/regex/rewrite/precedence compatibility and Query Log -> rule workflow. |
| Strong ClientID may exist as a column without runtime enforcement. | Strong ClientID; Clients & Access. | Generated strong identifiers, multiple IDs/client, encrypted-DNS identity matching, create/revoke lifecycle, and policy enforcement. |
| Cache, encryption, notifications, statistics, backup/restore have partial or unproven workflows. | Corresponding matrix rows. | Full lifecycle parity and browser/runtime acceptance before completion claims. |
| Internal IDs appear in operator-facing editors/selectors. | UI Foundation; Object Identity. | Friendly names in normal workflows; immutable IDs only in advanced/details contexts when useful. |

## Acceptance Evidence Required

Each completed matrix row must cite evidence for:

- UI/browser flow.
- Authenticated API behavior.
- Validation and error handling.
- Transactional control-state mutation.
- Compile/promote result.
- Runtime state inspection.
- Client-visible DNS result where applicable.
- Restart persistence.
- Lifecycle completion.
- Degraded/failure behavior.

Headless authenticated Chromium evidence is required for owner-facing actions. Pytest/source
inspection alone is insufficient for private-beta parity.
