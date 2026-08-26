# Alderpoint DNS V2 — Mandatory Feature / Parity Matrix

**Status as of 2026-08-26:** active private engineering. No V2 RC or public V2 package exists.

**Rule:** Every row marked **MANDATORY V2** must have working Go API/control behavior, complete Svelte UI where applicable, automated tests, real Chromium/runtime proof, migration/restart coverage, and owner acceptance before V2 may be published. “Foundation,” “in progress,” “coming soon,” placeholder, or compatibility-design-only work is not complete.

The current-status column describes private engineering evidence. Private checkpoints are not yet public source releases.

| Capability | V1 status | V2 requirement | Current private status | Gate |
|---|---|---|---|---|
| Go control plane | N/A | Native static management/control binary; no Python web runtime in final V2 | Selected; foundation and several product areas deployed privately | MANDATORY V2 |
| Svelte management UI | N/A | Complete polished parity for every management route; no placeholders/dead controls | Shell plus several areas implemented; full route parity incomplete | MANDATORY V2 |
| DNS filtering / blocklists / custom rules | Present | Preserve, harden, editable lifecycle, automatic pull, intervals, failure isolation | Python reference proven; Go Blocklists foundation present; custom-rule/edit parity remains | MANDATORY V2 |
| Local DNS / rewrites | Present | Full validated CRUD and runtime promotion | Go Local DNS CRUD implemented/deployed; complete rewrite/import parity still gated | MANDATORY V2 |
| DoH / DoT / DoQ / DoH3 | Present where dnsdist supports | Preserve, configure, certificate-manage, and prove with real clients | Python preview DoH/DoT currently disabled in latest proof; Go migration open | MANDATORY V2 |
| DNSCrypt | Best-effort/current plumbing | Audit and preserve supported behavior | Not migrated/proven in Go | MANDATORY V2 |
| Native HTTPS administration | Missing in original V1 plan; Python V2 preview implemented | Native secure HTTPS, recovery-safe certificates, secure cookies | Python and isolated Go previews use HTTPS; production certificate lifecycle incomplete | MANDATORY V2 |
| Clients & Access | Present | Unified client/group/network policy with full lifecycle | Go managed Clients/Groups deployed; observed clients, policy assignment, and full lifecycle incomplete | MANDATORY V2 |
| Strong ClientIDs | Present | Preserve without truncated/container identities | Python V2 exact-client identity proven; Go parity open | MANDATORY V2 |
| Client groups/tags | Missing | Add deterministic inheritance and bulk policy | Basic Go Groups implemented; policy inheritance incomplete | MANDATORY V2 |
| Runtime client discovery | Partial | DNS-only discovery, no DHCP, exact plausible identities | Python reference proven; Go observed-client/discovery boundary open | MANDATORY V2 |
| Detailed per-client settings | Partial | Filtering, privacy, schedules, resolver, logging/statistics, tags/groups | Incomplete | MANDATORY V2 |
| Per-client upstreams | Missing | Client/group/network resolver override | Incomplete | MANDATORY V2 |
| Per-client query-log exclusion | Missing | Exclude before retention | Incomplete | MANDATORY V2 |
| Per-client statistics exclusion | Missing | Exclude before aggregate retention | Incomplete | MANDATORY V2 |
| SafeSearch | Partial/modeled | Global/network/group/client enforcement | Incomplete | MANDATORY V2 |
| Parental controls | Not first-class | Full inherited policy capability | Incomplete | MANDATORY V2 |
| Safe-browsing/malware protection | Lists exist; not first-class policy | First-class inherited policy | Incomplete | MANDATORY V2 |
| Service blocking | Missing | Service/category blocking | Incomplete | MANDATORY V2 |
| Service-block schedules / bedtimes | Missing | Timezone/DST-safe schedules | Python schedule infrastructure exists; complete policy/UI parity open | MANDATORY V2 |
| Upstream profile lifecycle | Partial | Add/edit/enable/disable/delete, visible order, all endpoints visible | Python reference proven; Go Upstreams deployed; complete resolver-policy parity still gated | MANDATORY V2 |
| Domain-specific upstream routing | Missing | Validated routes, precedence, fallback | Python reference implemented; Go parity incomplete | MANDATORY V2 |
| Fallback DNS | No first-class model | Explicit groups and triggers; no silent insecure downgrade | Hidden Python fallback removed; explicit V2 model incomplete | MANDATORY V2 |
| Upstream strategies | Partial/internal | Ordered/failover/load-balance/parallel/fastest as validated | Profile/order work exists; full strategy proof incomplete | MANDATORY V2 |
| Blocking response modes | Primarily RPZ/NXDOMAIN | NXDOMAIN/REFUSED/null/custom where safe | Incomplete | MANDATORY V2 |
| ECS controls | Missing/not exposed | Privacy-aware global/per-upstream controls; no leakage | Client-discovery ECS misuse corrected in Python reference; product controls incomplete | MANDATORY V2 |
| Cache tuning/flush/stats | Present | Preserve plus policy-aware RAM-first recovery model | Python runtime foundation exists; Go UI/control parity open | MANDATORY V2 |
| Query Log | Present | Raw history outside control DB; fast viewer and filters | Python Parquet viewer path exists; Go page/API incomplete | MANDATORY V2 |
| Analytics dashboard | Present | Failure-isolated storage, historical and one-second live views | Python proven; Go Dashboard/analytics boundary deployed; full parity and owner acceptance open | MANDATORY V2 |
| Product-wide timestamps | Inconsistent historically | Browser Local / Appliance Time / UTC; correct sorting; no hardcoding | Python reference proven; Go timestamp engine/Admin mode implemented | MANDATORY V2 |
| Customizable Dashboard | Missing/partial | Add/remove/reorder/persist cards and response-time visibility | Incomplete | MANDATORY V2 |
| Backup/restore | Present | V2 format, V1.1.1 `.tar.gz`, upload inventory, selective restore, safety backup, rollback | Python reference proven and owner-tested; Go migration open | MANDATORY V2 |
| V1/Python-V2 migration | V1 migration present | Fresh install, V1.1.1 backup, and Python-V2 state compatibility | Python V1 selective migration proven; Go compatibility not yet proven | MANDATORY V2 |
| Replication | Present | Update for V2 policy/config/storage | Python reference present; Go migration open | MANDATORY V2 |
| Notifications | Present | Preserve and extend where required | Python reference present; Go migration open | MANDATORY V2 |
| Audit logging | Present | Preserve, redact secrets, expose truthful history | Go migration incomplete | MANDATORY V2 |
| Network Configuration | Present | Report/manage host network, never container bridge state | Python host-metadata correction proven; Go page/API incomplete | MANDATORY V2 |
| System Status / services | Present | Truthful health, worker recovery, diagnostics | Python detailed health proven; Go full scope incomplete | MANDATORY V2 |
| Logs | Present | Real combined viewer with All option, filtering, bounded reads | Incomplete | MANDATORY V2 |
| DNS/UI performance diagnostics | Missing/partial | Repeatable p50/p95/p99 reports and UI timing export | Python diagnostics proven; Go complete diagnostics parity open | MANDATORY V2 |
| Software updates | Present | Preserve hardened lifecycle, progress, rollback, truthful history | Python reference present; Go migration open | MANDATORY V2 |
| AdGuard migration | Present | Extend for V2 policy | Go migration open | MANDATORY V2 |
| Pi-hole migration | Present | Preserve | Go migration open | MANDATORY V2 |
| Native export/import | Present | Update for V2 model | Go migration open | MANDATORY V2 |
| Host DNS independence | Present | Must remain under every failure/recovery path | Proven in Python reference; final Go package proof required | MANDATORY V2 |
| amd64 + arm64 packaging | Partial/history varies | Static Go builds, install/upgrade/rollback proof | Static CGO-free builds proven in foundation; full appliance packaging open | MANDATORY V2 |
| Complete owner UI acceptance | N/A | Every route and workflow tested on live preview | In progress; incomplete application cannot pass | MANDATORY V2 |
| DHCP server | Intentionally absent | **DO NOT IMPLEMENT** | Out of scope | OUT OF SCOPE |
| Firewall/NAT/general gateway functions | Absent | **DO NOT IMPLEMENT** | Out of scope | OUT OF SCOPE |

## Current private checkpoint

Private Go/Svelte checkpoint `334af27` includes setup/auth/sessions, shell/navigation infrastructure, themes/timestamps, Administration, Dashboard with an analytics boundary, Blocklists, Local DNS, Upstreams, and managed Clients/Groups.

This checkpoint does **not** satisfy full frontend or product parity. Observed clients, complete per-client policies, Query Log, cache, filtering/custom-rule parity, encrypted transports, import, backup/restore, replication, statistics, full system/network/notifications/update/logging surfaces, remaining workers, packaging, migration, rollback, and owner acceptance remain open.

The Python V2 preview remains the behavioral reference and cannot be retired until all rows are complete.

## Alderpoint beyond parity

- **RAM-first DNS cache with policy-aware sharing and crash-resilient warm-start recovery.** dnsdist and BIND answer from RAM on the hot path, sharing a cached answer only when effective filtering/routing policy is equivalent. Disk persistence is a recovery optimization, never authoritative. DNS availability never waits on recovery.
- **Live owner-preview development.** Coherent private builds remain continuously deployable so owner feedback catches real workflow, layout, identity, performance, and lifecycle defects before packaging/release.
- **Performance contract.** Ordinary warm management interactions target under 50 ms p99; hot DNS responses target under 10 ms p99. Server-local Python-preview benchmarks are substantially below the DNS target, but physical-LAN and final Go-appliance proof remain release gates.
- **Complete product experience.** A polished, responsive, customizable Svelte interface is a release requirement, not optional post-backend decoration.

## Mandatory architectural gates

- Go is the selected final management/control-plane implementation; Svelte 5/strict TypeScript is the selected frontend.
- Raw query history must not share the control database.
- Analytics, web UI, update, backup, and discovery failures must not affect DNS answering.
- Web UI failure must not affect DNS.
- Host DNS must not point at Alderpoint itself by default.
- Passwords must use Argon2id with unique salts and no plaintext/reversible storage; the accepted floor must not be weakened for cosmetic RSS targets.
- Desired configuration must be schema-validated, atomically written, and recoverable.
- Runtime DNS policy must be compiled into native dnsdist/BIND structures, not looked up from a management database per query.
- Network UI must describe the appliance host, not its container bridge.
- Long-running/destructive operations must show immediate progress, validate before promotion, and roll back safely.
- V1.1.1 migration, Python-V2 state migration, fresh install, upgrade, restart persistence, backup/restore, and rollback must pass.
- Full Svelte route/workflow parity and explicit owner acceptance are mandatory.
- Final independent security/architecture review is mandatory.
