# Alderpoint DNS V2 Roadmap

**Status as of 2026-08-26:** active private engineering; not release-ready. The original 10-working-day / 14-calendar-day private-RC target was missed and is now historical, not a current forecast. No RC, tag, public V2 package, or V2 release exists.

Alderpoint DNS V2 is a DNS-only appliance built to be faster, safer, more failure-isolated, easier to operate, and easier to recover than the v1.x line while preserving the useful DNS-appliance capabilities operators expect.

## Selected implementation

- **Management/control plane:** Go, selected after a real Go/Rust/Python vertical-slice bake-off.
- **Frontend:** Svelte 5 with strict TypeScript, compiled to static assets; no Node.js runtime on the appliance.
- **DNS data plane:** dnsdist + BIND remain independent of the management UI.
- **State:** schema-validated YAML for stable desired configuration, bounded SQLite for transactional control state, and generated runtime artifacts promoted atomically.
- **Analytics:** Parquet + Zstandard raw history, DuckDB query access, and bounded SQLite WAL aggregates.
- **API interchange:** JSON only; JSON is not authoritative configuration storage.
- **Password storage:** Argon2id with unique salts and no reversible/plaintext storage. Parameters must not be weakened below the accepted security floor merely to improve an RSS benchmark.
- **Caching:** RAM-first dnsdist/BIND caches with policy-aware sharing; disk warm-state is optional recovery assistance, never authoritative and never a DNS startup gate.
- **Host safety:** the appliance host keeps independent maintenance DNS.

Go was chosen because it delivered near-Rust appliance performance with materially simpler cross-compilation, dependency management, and long-term maintenance. Rust remains a valid specialized option, but is not the selected V2 control-plane language.

## Current private-development state

### Python V2 reference preview

A substantial Python V2 preview was built and owner-tested before the Go decision. It remains the protected behavioral reference while Go/Svelte parity is completed. Proven work includes:

- dnsdist/BIND runtime generation and staged promotion
- exact client discovery and managed-client workflows
- upstream lifecycle and removal of hidden fallback behavior
- minute/hour/day and one-second live analytics
- product-wide local/appliance/UTC timestamp handling
- truthful host-network reporting
- V1.1.1 `.tar.gz` and V2 backup upload, structured preview, selective restore, safety backup, rollback, retention, and archive deletion
- blocklist edit/update/interval/failure-isolation/attention workflows
- UI and DNS performance diagnostics
- hot DNS latency comfortably below the owner’s 10 ms p99 target in server-local and host-to-published-address tests

The Python preview is not an RC and will not be retired until the Go/Svelte application passes complete parity, migration, packaging, rollback, performance, security, browser, and owner-acceptance gates.

### Go/Svelte migration

The first bake-off/foundation slice has been reclassified honestly: it proved the architecture but did **not** constitute frontend parity.

At private engineering checkpoint `334af27`, the isolated Go/Svelte preview includes:

- first-run setup, login, sessions, CSRF protection, and rate limiting
- the complete application shell/navigation foundation, themes, responsive behavior, timestamp engine, and shared UI infrastructure
- Administration workflows
- Dashboard with a real analytics compatibility boundary
- Blocklists and Local DNS
- Upstream profiles
- managed clients and groups

Still incomplete includes observed-client discovery, complete per-client policy/lifecycle behavior, Query Log, cache controls, filters/custom rules parity, encryption/transports, import/migration, backup/restore, replication, statistics, full System Status, Network Configuration, notifications, updates, logs, remaining runtime workers, packaging, upgrades, rollback, and complete frontend/browser parity.

The Go preview remains isolated from the Python reference preview during development. The final product will return to the normal management endpoint only after complete verification and explicit owner approval.

## Mandatory V2 feature and experience gate

V2 will not be published until all agreed capabilities and workflows are complete, including:

- SafeSearch, parental/safe-browsing, malware/phishing, and scheduled service-blocking policies
- detailed per-client settings, groups/tags, strong identities, discovery, privacy exclusions, and upstream overrides
- domain routing, fallback groups, upstream strategies, blocking modes, and ECS controls
- filtering, custom rules, Local DNS, rewrites, cache controls, Query Log, and analytics
- native HTTPS administration and proven DoH/DoT plus every supported encrypted-DNS transport
- complete backup/restore, V1.1.1 migration compatibility, replication, notifications, audit, updates, diagnostics, and rollback
- the complete polished Svelte management interface with no placeholder pages or dead controls
- sub-50 ms ordinary warm management interactions/API targets and preserved sub-10 ms hot DNS p99 target
- fresh installation, upgrade, recovery, amd64/arm64 packaging, security review, and owner acceptance

DHCP, firewall, NAT, and general network-gateway functionality remain intentionally out of scope.

## Delivery governance

The original two-week estimate was not achieved. The project will not substitute another unsupported calendar promise for it.

Progress is measured by complete, working, tested parity rows—not files, commits, scaffolding, or disabled “coming soon” navigation entries. Architecture and scope are now frozen around Go/Svelte and the committed parity contract.

To control engineering cost and avoid repeated work:

- one engineering agent works on Alderpoint at a time
- prompts contain only the current delta, exact objective, constraints, proof, and stop condition
- canonical requirements stay in repository documents rather than being repasted
- focused tests run during implementation; full suites run at meaningful integration/release gates
- Dex is reserved for high-value independent review gates, not repeated review of unchanged code
- no agent may stop at a “natural checkpoint” when no genuine owner blocker exists

## Full planning documents

- [V2 Master Architecture and Delivery Plan](docs/v2-architecture-plan.md)
- [V2 Mandatory Feature / Parity Matrix](docs/v2-feature-parity-matrix.md)

These documents remain the public architecture, implementation-status, and release-governance record for V2.
