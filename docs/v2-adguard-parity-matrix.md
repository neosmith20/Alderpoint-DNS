# Alderpoint DNS V2 — Mandatory Feature / Parity Matrix

**Rule:** Every row marked **MANDATORY V2** must be complete before Alderpoint DNS V2 may be published.

| Capability | V1 Status | V2 Requirement | Release Gate |
|---|---|---|---|
| DNS filtering / blocklists / custom rules | Present | Preserve and harden | MANDATORY V2 |
| Local DNS / rewrites | Present | Preserve | MANDATORY V2 |
| DoH / DoT / DoQ / DoH3 | Present where dnsdist supports | Preserve | MANDATORY V2 |
| DNSCrypt | Best-effort/current plumbing | Audit, preserve supported behavior | MANDATORY V2 |
| Clients & Access | Present | Integrate into unified policy model | MANDATORY V2 |
| Strong ClientIDs | Present | Preserve | MANDATORY V2 |
| SafeSearch | Partial/modeled | Full global/network/group/client enforcement | MANDATORY V2 |
| Parental controls | Not first-class | Full policy capability | MANDATORY V2 |
| Safe-browsing/malware protection | Lists exist; not first-class policy | First-class policy capability | MANDATORY V2 |
| Service blocking | Missing | Service/category blocking | MANDATORY V2 |
| Service-block schedules / bedtimes | Missing | Timezone/DST-safe schedules | MANDATORY V2 |
| Detailed per-client settings | Partial | Full filtering/privacy/resolver policy | MANDATORY V2 |
| Per-client upstreams | Missing | Client/group/network resolver override | MANDATORY V2 |
| Per-client query-log exclusion | Missing | Add | MANDATORY V2 |
| Per-client statistics exclusion | Missing | Add | MANDATORY V2 |
| Client groups/tags | Missing | Add with deterministic inheritance | MANDATORY V2 |
| Runtime client discovery | Partial | Add DNS-only discovery, no DHCP | MANDATORY V2 |
| Domain-specific upstream routing | Missing | Add | MANDATORY V2 |
| Fallback DNS | No equivalent first-class model | Add explicit fallback groups/policy | MANDATORY V2 |
| Upstream strategy selection | Partial/internal behavior | Ordered/failover/load-balance/parallel/fastest as validated | MANDATORY V2 |
| Blocking response modes | Primarily RPZ/NXDOMAIN semantics | NXDOMAIN/REFUSED/null/custom where safe | MANDATORY V2 |
| ECS controls | Missing/not exposed | Add privacy-aware ECS policy | MANDATORY V2 |
| Native HTTPS admin | Missing | Add native HTTPS | MANDATORY V2 |
| Cache tuning/flush/stats | Present | Preserve | MANDATORY V2 |
| Query log | Present | Move history off control DB; preserve UI/features | MANDATORY V2 |
| Analytics dashboard | Present | Redesign storage/failure isolation | MANDATORY V2 |
| Backup/restore | Present | Update for V2 storage/config layout | MANDATORY V2 |
| Replication | Present | Update for V2 policy/config/storage model | MANDATORY V2 |
| Notifications | Present | Preserve and extend as needed | MANDATORY V2 |
| AdGuard migration | Present | Extend for V2 policies | MANDATORY V2 |
| Pi-hole migration | Present | Preserve | MANDATORY V2 |
| Native export/import | Present | Update for V2 model | MANDATORY V2 |
| Software updates | Present | Preserve hardened UX/reliability | MANDATORY V2 |
| Host DNS independence | Present | Must remain | MANDATORY V2 |
| DHCP server | Intentionally absent | **DO NOT IMPLEMENT** | OUT OF SCOPE |
| Router/firewall/NAT | Absent | **DO NOT IMPLEMENT** | OUT OF SCOPE |

## Alderpoint beyond parity

- **RAM-first DNS cache with policy-aware sharing and crash-resilient warm-start recovery.** dnsdist
  and BIND answer from RAM on the hot path, sharing a cached answer between clients only when their
  filtering/routing outcome is equivalent ("effective cache profile"). Disk persistence is a
  recovery optimization only (never the authoritative cache): a validated direct-restore tier for
  entries provably still valid, plus a background popularity-based prewarm tier that always
  re-resolves through the normal policy/DNSSEC path. DNS availability never waits on cache recovery.
  This is not an AdGuard-parity requirement — it is an Alderpoint-specific performance/resilience
  architecture decision. See `docs/v2-architecture-plan.md` §3.6.

## Mandatory architectural gates

- Raw query history must not share the control database.
- Analytics failure must not affect DNS.
- Web UI failure must not affect DNS.
- Host DNS must not point at Alderpoint itself by default.
- Passwords must use Argon2id with unique salts; no plaintext/reversible storage.
- V2 desired configuration must be schema-validated and recoverable.
- Runtime DNS policy must be compiled into native dnsdist/BIND structures, not looked up from the management DB per query.
- V1 -> V2 migration and fresh install must both pass before publication.
- Dex final security/architecture review required.
