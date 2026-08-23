# Alderpoint DNS V2 Roadmap

**Canonical status:** this is the current private V2 roadmap and implementation contract.

**Companion contract:** `docs/v2/v1-workflow-parity-contract.md` is the canonical V1.1.1 -> V2
workflow-parity matrix. No other document may claim V1 parity unless that contract says the
workflow has passed.

**Historical inputs:** `docs/v2/roadmap-reference/*`, `docs/v2/architecture-map.md`,
`docs/v2/rc-ready-gate3.md`, `docs/v2/v1-parity-audit.md`, and `docs/progress.md` are retained as
evidence and project history. Where they conflict with this roadmap or the workflow-parity
contract, this roadmap and the workflow-parity contract win.

## Fundamental Product Rule

Alderpoint DNS V2 is not a greenfield product.

The exact accepted V1.1.1 release is the minimum operator-workflow baseline unless the owner
explicitly approves replacing or removing a workflow. V2 preserves V1 workflow semantics while
replacing the internals with the stronger V2 architecture.

A V1 feature is not preserved merely because V2 has a model, table, database row, route, one GET
endpoint, one POST endpoint, page with the same title, or similarly named object. Parity is measured
end to end by the workflow-parity contract.

## Locked Architecture

The DNS hot path remains:

`client -> dnsdist RAM packet cache -> compiled policy/routing -> BIND recursive cache -> upstream/native recursion`

DNS must never synchronously depend per query on FastAPI/UI, `control.db`, SQLite, DuckDB, Parquet,
analytics, discovery, replication, or persistent Tier B cache state.

The durable architecture remains:

- Desired configuration: validated YAML.
- Transactional bounded state: `control.db` / SQLite.
- Raw history: Parquet + Zstandard + DuckDB.
- Aggregate analytics: separate bounded SQLite WAL database.
- Secrets: protected store, with references only in control state.

The implementation must preserve V1 workflow semantics. It must not restore obsolete V1 internals
when the V2 architecture has a safer boundary.

## Current Private Status

RC51 remains failed owner-beta history for product-parity purposes. Earlier KVM closure and gate
evidence do not mean V1.1.1 workflow parity was accepted.

Current V2 is not V1.1.1 workflow-parity complete. Material open work remains in:

- Navigation and shared data-grid behavior.
- Upstream lifecycle and runtime truth.
- Blocklist lifecycle.
- Exact client attribution.
- Analytics degraded-state handling.
- Clients & Access.
- Strong ClientID.
- Local DNS.
- Custom filtering rules.
- Cache management.
- Encryption.
- Notifications.
- Statistics and analytics administration.
- Backup and restore.
- Setup and network semantic clarity.
- Internal-ID UX.
- Full lifecycle parity for related workflows.

No document may state "all roadmap items complete", "parity complete", "Local DNS preserved",
"Blocklists restored", "Notifications complete", or equivalent completion language until the
workflow-parity contract has passed for the relevant area.

## Locked Owner Decisions

### Zero Managed Upstreams

The operator may disable every managed upstream or forwarder profile.

When disabling the final enabled managed upstream, V2 must show a clear warning/confirmation and
then allow the operation. Zero configured forwarders means BIND operates as a normal recursive
resolver using the DNS root and authoritative hierarchy.

There must be no hidden Cloudflare fallback, hidden Google fallback, silently substituted resolver,
or UI/runtime disagreement. The UI must clearly indicate native recursive/root mode when no
forwarders are enabled.

### Custom Rules

V2 may provide a modern rule builder. That builder is an addition, not permission to discard V1
custom-filter compatibility.

V2 must preserve V1 custom-filter semantics and import/migration behavior, including the relevant
V1/AdGuard-style syntax. Required semantic classes include allow, block, regex, rewrite,
precedence, bulk lifecycle, validation/testing, and Query Log -> rule creation.

### Observed Client Action

The ambiguous operator word "Promote" must be replaced with "Manage Client" or equivalent wording
centered on the operator's intent.

The workflow is: observed exact client -> create/persist managed client -> assign friendly
identity, policy, and settings.

### DNSCrypt

DNSCrypt remains a first-class supported V2 encrypted-DNS capability. It must be discoverable from
Encryption. It may live under an advanced encrypted-DNS section where appropriate, but it must not
be silently hidden from normal administration.

## Product-Wide UI Contract

V2 should not visually clone V1. The target is a modern, serious DNS/network-appliance interface
with a distinct Alderpoint identity.

Navigation requirements:

- Hierarchical sections are consistent and predictable.
- A parent item either toggles its submenu or intentionally opens a useful parent landing page.
- Navigation never accidentally routes to an unrelated Query Log page.
- Collapsed/minimized navigation remains fully usable.
- Keyboard and accessibility semantics are supported.
- Open/collapse state persists where useful.

Data-grid requirements:

- Major tables use a shared grid/table foundation.
- Click header sorts ascending; click again sorts descending.
- Sort state has a clear visual indication.
- Columns are draggable/resizable with sensible minimum widths.
- Horizontal overflow remains usable.
- Column widths and sort state persist where useful.
- Keyboard accessibility is supported.

Object identity requirements:

- Operators work with friendly names.
- Internal IDs remain internal.
- Selectors show friendly objects.
- Advanced/details views may expose immutable IDs when genuinely useful.
- Normal forms must not require the owner to memorize database IDs.

Status requirements:

- UI status reflects actual runtime truth.
- Enabled in DB but not enforced at runtime is a P0 defect.
- Failed analytics show degraded/unavailable status rather than silently empty data.
- A "saved" toast is not success if runtime promotion failed.

Avoid generic AI/Tailwind SaaS appearance, rounded-card soup, excessive pills, glassmorphism,
gratuitous gradients, and huge empty whitespace.

## Exact Client Attribution

Observed client identity must represent the exact originating client.

Never treat an ECS-truncated prefix such as `192.168.32.0/24`, dnsdist tee sender `127.0.0.1`, or
proxy/intermediate transport address as the originating client unless it actually is the client.

Discovery and analytics transport must preserve exact origin identity asynchronously. If exact
identity is unavailable, mark it unknown/degraded. Do not invent or promote a prefix/loopback
identity. Manage Client must not allow invalid observed identities to become persistent managed
clients.

## Analytics Independence And Degraded State

DNS works if analytics is dead. Management must still explicitly surface analytics failure.

If the protobuf receiver or ingestion path is unavailable:

- DNS continues.
- Health shows analytics degraded.
- Dashboard explains data unavailable/degraded.
- Top Domains must not misleadingly appear as "there simply were no domains".
- Worker progress and heartbeat are observable.
- Receiver startup/order/recovery are covered by acceptance.

## Runtime / Control / UI Truth

The following must agree after a successful operation:

`UI -> control state -> compiled state -> runtime -> client-visible DNS result`

Examples:

- A blocklist disabled in UI must actually stop enforcing after successful promotion.
- An upstream disabled in UI must disappear from runtime.
- No enabled forwarders must result in documented native-recursion mode.
- Pending, degraded, or failed state must be explicit.

## Package And Security Contract

Do not freeze a transient dnsdist/BIND package number in the roadmap unless it is a deliberate
minimum floor. V2 must instead require:

- A supported Debian release.
- Security-supported dnsdist and BIND package versions.
- A package gate that verifies installed versions against the currently supported Debian security
  baseline.
- A minimum package floor that does not knowingly allow a superseded vulnerable build.
- Enhanced PowerDNS repository usage only as explicit root-only opt-in.
- No apt or sudo capability in the web UI.

Current package observations belong in package-baseline evidence docs, not as permanent roadmap
version pins unless promoted to a security floor.

## Hardware Reality

Current private V2 evidence:

- 2 GB: minimum proven boot/functional tier; not performance-certified.
- 3 GB: proven comfortable intermediate tier.
- 4 GB: recommended owner/normal deployment target.

Do not claim independent 4 GB stress certification where none exists. Obsolete 512 MB V2
expectations are not meaningful acceptance targets.

## Development And Release Stages

Obsolete calendar-based planning such as "10 working days", "14 calendar days", and old
V1.2.1-before-V2 assumptions is historical only.

Canonical current stages:

1. Private Beta: Alex owner-testing on a real appliance/VM. Bugs and missing workflows are fixed
   until none/minimal.
2. Production Pilot: install on a live network under real household/network workload. Fix remaining
   minor operational issues.
3. Public Ready: live-tested with no meaningful unresolved product defect.
4. Public Release.

V2 remains private until explicitly authorized. RC numbers do not imply progress by themselves.

## Owner-Browser Acceptance Gate

"If Alex can click it, Alderpoint needs to survive Alex clicking it."

For every owner-facing action, acceptance must cover:

- Happy path.
- Invalid input -> correction.
- Repeated clicks.
- Double submit.
- Refresh after mutation.
- Route change during async work.
- Persistence after restart.
- Browser back/forward.
- Dark/light.
- Errors/degraded state.
- Real runtime effect.

Source inspection and pytest alone cannot certify owner-facing parity. Headless authenticated
Chromium is required for private-beta acceptance. Actual owner beta remains the final private-beta
truth.

## Current Workstreams

1. UI Foundation: navigation, shared data grid, friendly selectors, status truth.
2. Clients / Discovery / Analytics Identity: exact attribution, observed clients, Manage Client,
   analytics degradation.
3. Upstream Lifecycle / Runtime Truth: CRUD, enable/disable/order, zero-forwarder native recursion.
4. Blocklist Lifecycle: edit/toggle/runtime, Update All, categories, schedules, status.
5. Clients & Access / Strong ClientID: V1 semantic/runtime parity.
6. Local DNS: complete V1 lifecycle wired to V2 runtime.
7. Filtering / Custom Rules: V1 semantic compatibility, modern builder, Query Log integration.
8. Cache Management: safe V1-equivalent controls mapped to dnsdist/BIND layers.
9. Encryption: certificate and transport workflow parity, including DNSCrypt.
10. Notifications: provider and subscription lifecycle.
11. Statistics / Analytics Administration: privacy, retention, settings, degraded states.
12. Backup / Restore: complete operator lifecycle.
13. Setup / Network Semantic Clarity: actual appliance/network configuration versus Local DNS
    records.
14. Full Workflow Acceptance: Chromium automation and owner-beta regression coverage.

## Canonical Document Map

- Current roadmap: `docs/v2/v2-roadmap.md`.
- Current workflow parity contract: `docs/v2/v1-workflow-parity-contract.md`.
- Historical V1 parity audit: `docs/v2/v1-parity-audit.md`.
- Historical RC/Gate #3 readiness evidence: `docs/v2/rc-ready-gate3.md`.
- Historical/public project progress: `docs/progress.md`.
- Historical/public V2 reference inputs: `docs/v2/roadmap-reference/*`.
- Supporting architecture evidence: `docs/v2/architecture-map.md`.
