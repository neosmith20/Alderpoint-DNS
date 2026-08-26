# Alderpoint DNS V2 — Master Architecture and Delivery Plan

**Status:** Active private engineering and Go/Svelte migration; not release-ready  
**Architecture decision:** Go control plane + Svelte 5/strict TypeScript frontend; dnsdist + BIND data plane  
**Original delivery target:** 10 focused working days / 14 calendar days for a private RC — missed and retained only as historical planning context  
**Current delivery rule:** No replacement date will be asserted until the complete parity matrix has measured implementation burn-down  
**Publication rule:** V2 MUST NOT be published until every mandatory capability, full-UI parity row, migration path, performance/security gate, and owner-acceptance requirement in this document is satisfied.

---

## 0. Current Engineering Status — 2026-08-26

V2 is in active private development. No V2 RC, tag, public package, or release exists.

The first substantial implementation used Python/FastAPI as the management plane and produced a live owner-preview reference with the selected storage/failure-domain design, staged runtime promotion, analytics, discovery, upstreams, blocklists, backup/restore, diagnostics, and extensive browser/runtime proof. Owner testing exposed and corrected important concurrency, lifecycle, identity, timezone, network-reporting, restore, analytics, and performance defects.

A real vertical-slice bake-off then compared Python/FastAPI, Go, and Rust using the same SQLite schema, JSON API, Svelte frontend, fixtures, concurrency, CRUD, migration/rollback, and 250,000-line blocklist pipeline. Representative median results were:

| Measurement | Python | Go | Rust |
|---|---:|---:|---:|
| Cold start | 381 ms | 14.1 ms | 14.2 ms |
| Idle RSS | 55.7 MiB | 11.4 MiB | 8.0 MiB |
| Health p50 at concurrency 50 | 26.6 ms | 2.2 ms | 1.9 ms |
| Local-DNS list p50 at concurrency 50 | 75.8 ms | 21.1 ms | 13.3 ms |
| 250k blocklist pipeline | 0.84 s | 0.57 s | 0.30 s |

These are vertical-slice results, not full-appliance guarantees. Go was selected because it stays in the same appliance-performance class as Rust while providing substantially simpler dependencies, static amd64/arm64 builds, and long-term maintenance for this project.

The Python V2 owner preview remains the protected behavioral reference. The Go/Svelte preview is isolated until complete parity and explicit owner approval.

At private Go checkpoint `334af27`, implemented/deployed areas include setup/auth/session security, the application-shell foundation, Administration, Dashboard with an analytics compatibility boundary, Blocklists, Local DNS, Upstreams, and managed Clients/Groups. Major remaining areas include observed clients and full per-client policy/lifecycle, Query Log, cache, filters/custom rules parity, encryption/transports, import and backup/restore, replication, statistics, full System Status, Network Configuration, notifications, updates, logs, remaining workers, packaging, migration, rollback, and complete browser/owner acceptance.

The existing two-page Go foundation is explicitly **not** frontend parity. Disabled or placeholder navigation does not satisfy a release row.

---

## 1. Product Charter

Alderpoint DNS V2 is a **DNS-only appliance**.

It exists to provide a faster, more secure, easier-to-use DNS filtering and management platform with strong architecture, failure isolation, deployment safety, analytics storage, performance, and administration.

### Explicitly out of scope

- **DHCP server functionality** — intentionally excluded.
- Firewall/NAT functions.
- General network gateway functionality.

DHCP is outside this DNS appliance's product boundary and must not be added merely for checkbox parity.

---

## 2. Non-Negotiable Design Goals

1. **DNS data plane must remain independent of the management plane.**
   - dnsdist remains the client-facing DNS frontend.
   - BIND remains the validating/cache/authoritative backend unless a benchmarked redesign proves a materially better DNS-only architecture.
   - DNS queries must never require the Go management plane, Svelte UI, SQLite, DuckDB, Parquet, analytics, or any compatibility service to answer.

2. **The Alderpoint host must not depend on Alderpoint for its own DNS.**
   - Host maintenance resolution stays separate from the appliance DNS listeners.
   - Failure of Alderpoint DNS must not break apt, package recovery, GitHub access, certificate maintenance, or system recovery.

3. **Failure domains must be separated.**
   - Analytics failure must not affect DNS.
   - Query-history failure must not affect configuration.
   - Session/audit failure must not affect DNS.
   - Update-history failure must not affect DNS.

4. **Security by default.**
   - Least privilege.
   - Narrow root helpers.
   - Strong systemd sandboxing.
   - No secrets in logs/diagnostics.
   - Native HTTPS administration.
   - Strong authentication and password hashing.

5. **Fast by architecture, not by wishful thinking.**
   - No per-query database lookups in the DNS data path.
   - Compile policy into native dnsdist/BIND structures.
   - Benchmark storage and query approaches before committing.

6. **Easy UI without hiding truth.**
   - Clear current vs historical state.
   - Real progress for long-running actions.
   - Preview before destructive/import/migration operations.
   - Honest degraded/unsupported states.

7. **Every runtime change is staged and validated.**
   - Desired state -> generated config -> syntax validation -> atomic activation -> health checks -> rollback on failure.

---

## 3. V2 Storage Architecture

### 3.1 Human-readable declarative configuration

Preferred target:

`/etc/alderpointdns/alderpointdns.yaml`

Use YAML for stable operator-facing desired configuration such as:

- listeners and ports
- global DNS behavior
- upstream strategy
- fallback resolver settings
- domain-specific upstream-routing rules
- global filtering controls
- SafeSearch / parental / service-blocking defaults
- cache settings
- analytics retention and privacy policy
- ECS behavior
- HTTPS management configuration references
- feature toggles

The file must be schema-validated and written atomically.

### 3.2 Small transactional control database

Preferred target:

`/var/lib/alderpointdns/control.db`

Use the control database only where relational/transactional semantics are genuinely useful:

- administrator accounts
- password hashes
- sessions
- authentication/rate-limit state where persistence is required
- audit history
- persistent clients
- client identifiers
- client tags/groups
- client/group policy assignments
- update jobs/history
- backup/restore jobs/history
- replication state
- migration/import bookkeeping
- other bounded control-plane records

**Do not place raw DNS query history in control.db.**

### 3.3 Password security contract

V2 password handling must explicitly require:

- Argon2id
- unique random salt per password
- parameters pinned/configured based on a benchmarked security target rather than silently relying forever on library defaults; the current accepted Argon2id floor is m=19 MiB, t=2, p=1 and must not be weakened merely to improve an RSS measurement
- automatic rehash when parameters are upgraded
- no reversible password storage
- no plaintext passwords in backups/logs/diagnostics

Evaluate a root-only application pepper stored outside control.db, for example under `/etc/alderpointdns/`, so theft of only the database/backup is insufficient for offline verification without also compromising the separate secret.

### 3.4 Raw query history

Raw query events must be removed from the shared control database.

Selected design, proven in the Python V2 reference preview and retained for the Go migration:

`/var/lib/alderpointdns/analytics/queries/YYYY/MM/DD/*.parquet`

Properties:

- batched ingestion from the existing bounded analytics queue
- time and/or size-based rotation
- Parquet columnar format
- Zstandard compression inside Parquet
- immutable closed segments
- atomic temporary-file -> final-file promotion
- retention by deleting complete expired segments
- no million-row DELETE operations
- no VACUUM required to reclaim query-history storage
- corrupted analytics segment must never affect DNS/configuration

Selected query layer:

- DuckDB scanning partitioned Parquet files

The original alternatives remain part of the retained benchmark record and must be rechecked on supported low-end hardware before publication:

- dedicated SQLite WAL analytics database
- compressed JSONL rotation

Decision criteria:

- ingest CPU
- ingest throughput
- disk consumption
- RAM
- 1h/24h/7d/30d query latency
- top-domain/client calculations
- filtered query-log latency
- retention deletion cost
- startup/recovery behavior
- low-end appliance performance

### 3.5 Aggregate analytics

Minute/hour/day aggregate counters must be separate from control.db.

Candidate implementations:

- small dedicated `analytics.db` using SQLite WAL
- small analytics DuckDB database
- aggregate Parquet partitions

Choose by benchmark.

The aggregate store must remain bounded and cheap to rebuild where practical.

### 3.6 DNS cache architecture (RAM-first)

The primary DNS cache is a RAM-first hot path: client -> dnsdist packet cache -> compiled policy ->
BIND recursive cache -> upstream only on miss. The cache hot path must never synchronously depend
on disk, SQLite, control.db, the aggregate store, DuckDB, Parquet, the Go management plane, the Svelte UI, or the
analytics/audit subsystems.

Cached answers may only be shared between clients when the policy properties that can affect the
returned answer are compatible ("effective cache profile") — filtering policy, SafeSearch,
parental/service-blocking state, blocking response mode, upstream/routing profile, ECS state, and
similar answer-producing policy. Do not cache per individual client, and do not use one
unrestricted global cache when policy differences could change the answer.

Disk persistence of cache/warm-state is a recovery optimization only, never the authoritative
cache:

- **Tier A (optional) — direct restore**, only for entries provably still valid (remaining TTL,
  not the original TTL; DNSSEC state; cache-profile generation; routing/upstream context). If
  validity can't be proven, don't restore it.
- **Tier B — popularity-based prewarm**, replaying recently/frequently used names through the
  normal resolution path after startup to obtain fresh TTLs and current policy, populating RAM
  naturally. Asynchronous, background, rate-limited, bounded, safe after unclean power loss.

DNS availability comes first at boot: dnsdist/BIND become operational and clients can resolve
immediately; any cache recovery/prewarm work happens in the background afterward, never as a
startup gate. Failure of persistent cache/warm-state storage must degrade only to a cold cache —
never to a DNS outage, startup failure, or failure propagating into control.db/analytics. See `docs/v2-feature-parity-matrix.md` for the associated Alderpoint-specific resilience gate.

---

## 4. Unified V2 Policy Engine

V2 should replace scattered special-case policy logic with one hierarchical policy model.

Suggested precedence:

1. global defaults
2. network policy
3. group/tag policy
4. individual client policy
5. explicit emergency access deny/allow where deliberately defined

The exact precedence must be documented, deterministic, testable, and visible in the UI.

Policy must be compiled into native dnsdist/BIND runtime structures rather than evaluated from a database on every DNS request.

---

## 5. Mandatory V2 Feature Gate

**V2 MUST NOT be published unless every item below is implemented, tested, documented, migratable, and reviewed.**

### 5.1 SafeSearch

- first-class SafeSearch controls
- global policy
- network/group/client overrides
- supported providers documented
- deterministic enforcement

### 5.2 Parental / safe-browsing controls

- first-class adult/parental filtering policy
- malware/phishing/safe-browsing protection controls
- policy inheritance
- client/group/network overrides

### 5.3 Service blocking with schedules

- named services/app categories
- block/unblock policy
- schedules/bedtimes
- timezone-aware behavior
- DST-safe schedule handling
- per-network/group/client overrides

### 5.4 Detailed per-client settings

Each persistent client must support policy configuration beyond simple access allow/deny, including applicable:

- filtering enable/disable
- SafeSearch
- parental/safe-browsing
- service blocking
- schedule
- upstream selection
- query-log inclusion/exclusion
- statistics inclusion/exclusion
- tags/groups
- privacy/logging policy

### 5.5 Per-client upstreams

- client/group/network-specific upstream resolver policy
- inherits from global resolver policy unless overridden
- must compile efficiently into dnsdist routing policy

### 5.6 Query-log/statistics exclusions

- per-client log exclusion
- per-client statistics exclusion
- group/network equivalents where sensible
- privacy-aware UI
- exclusion must occur early enough that disabled logging is not secretly retained elsewhere

### 5.7 Client tags / groups

- named groups/tags
- bulk policy assignment
- deterministic inheritance
- clear conflict resolution

### 5.8 Runtime client discovery

DNS-only discovery sources may include:

- observed source addresses from dnsdist
- reverse DNS/PTR
- configured Local DNS
- system neighbor/ARP/NDP information where safely available as supplemental metadata
- optional hostname information imported/provided externally

No DHCP server is to be added.

Discovery must never silently grant trust or bypass access policy.

### 5.9 Domain-specific upstream routing

Examples:

- `corp.example` -> internal resolver
- selected domains -> privacy resolver
- default -> global resolver group

Must support validation, fallback behavior, and clear precedence.

### 5.10 Fallback DNS

- explicit fallback resolver groups
- clear trigger semantics
- health-aware behavior
- no silent downgrade from encrypted to plaintext unless the configured policy permits it

### 5.11 Configurable upstream strategies

At minimum evaluate/provide:

- ordered/failover
- load-balanced
- parallel/first-success
- fastest/latency-aware where safe and meaningful

Strategy behavior must be visible and deterministic enough to troubleshoot.

### 5.12 Blocking response modes

Provide appropriate global/policy-selectable modes such as:

- NXDOMAIN
- REFUSED
- null IPv4/IPv6 response
- custom blocking IP where configured

Define TTL behavior.

Do not implement modes that undermine DNS correctness/security without an explicit operator choice.

### 5.13 ECS controls

- global ECS policy
- enable/disable
- prefix controls where supported
- privacy warning in UI
- per-upstream behavior if necessary
- no ECS leakage when disabled

### 5.14 Native HTTPS administration

The V2 admin UI must support HTTPS natively.

Requirements:

- TLS certificate management/reuse where appropriate
- secure cookies
- HSTS where appropriate
- modern TLS defaults
- HTTP-to-HTTPS behavior documented
- no requirement for a reverse proxy simply to secure administration
- recovery path preserved if certificate configuration fails

---

## 6. Existing V1 Capabilities That Must Survive V2

V2 is not allowed to regress working V1 features, including:

- BIND + dnsdist architecture
- RPZ filtering
- external blocklists
- custom rules
- allow/block precedence
- Local DNS
- A/AAAA/PTR/CNAME records
- DNS rewrites
- encrypted client DNS: DoH, DoT, DoQ, DoH3 where supported
- DNSCrypt support where currently supportable/audited
- managed upstream plain DNS/DoT/DoH
- Clients & Access
- strong ClientIDs
- cache controls
- query log
- analytics dashboard
- backup/restore
- encrypted backups
- replication
- migration from AdGuard Home and Pi-hole
- native import/export
- notifications
- audit logging
- software updates
- safe staged deployment/rollback
- host DNS independence

---

## 7. Migration Requirements

V1 -> V2 migration must be boring and recoverable.

Required sequence:

1. detect V1 installation/version
2. mandatory pre-migration backup
3. preview migration
4. migrate configuration/control records
5. migrate clients/access rules
6. migrate policies
7. migrate credentials/secrets safely
8. optionally migrate retained analytics/history or explicitly archive old analytics
9. generate V2 runtime configuration
10. validate all configs
11. health-test DNS and management plane
12. atomically finalize
13. rollback automatically on failure before final commit point
14. retain recovery documentation and backup

Fresh install and upgrade must both be first-class supported paths.

---

## 8. Performance Gates

Define reproducible benchmarks before implementation completes.

Minimum test profiles:

- low-end: 1 vCPU / 512 MiB
- normal: 2 vCPU / 2 GiB
- high-query synthetic load

The 512 MiB low-end profile above is V1's historical figure and is retained here unchanged; it is
not yet re-confirmed as the V2 minimum. V2's actual supported minimum (candidates: 1 GiB or 2 GiB)
will be set from full-appliance benchmarks — all components resident together, not any one
component measured alone — before publication, not assumed from the V1 number.

Measure:

- DNS latency with analytics enabled/disabled
- sustained QPS
- dnsdist queue/drop behavior
- policy compile time
- startup time
- UI dashboard/query-log response time
- analytics ingest throughput
- analytics disk growth
- retention cleanup cost
- CPU/RAM during blocklist compile
- migration duration on large V1 dataset
- cache recovery after simulated abrupt power loss: time until DNS is available, cache-hit latency
  p50/p95/p99, upstream query volume, and time to reach ~50%/90%/99% of prior working-set
  effectiveness, comparing cold-cache, Tier B prewarm, and (if implemented) Tier A+B — using
  realistic repeated-client/domain traffic, not random synthetic names

Performance target principle:

**Analytics and UI must not measurably destabilize DNS answering under normal appliance loads.**

---

## 9. Security Gates

Before V2 publication:

- Argon2id password storage reviewed
- optional pepper decision completed
- secrets separated from public/config data
- TLS/admin HTTPS reviewed
- CSRF/session/cookie controls reviewed
- auth rate limiting reviewed
- file permissions reviewed
- sudoers reviewed
- systemd sandbox reviewed
- upload handling reviewed
- archive extraction reviewed
- command/path injection reviewed
- XSS/template escaping reviewed
- SSRF protections on upstreams/webhooks/import reviewed
- ClientID policy reviewed
- backup encryption reviewed
- replication mTLS reviewed
- dependency/package collision tests retained
- no host-DNS dependency on Alderpoint

Dex must independently attack these areas before release.

---

## 10. Delivery History and Remaining Execution Plan

### Historical result

The original 10-working-day / 14-calendar-day private-RC target was missed. It was based on reuse and focused scope before the true UI/API/parity inventory, owner-preview defect discovery, and Go/Svelte migration were fully known. It must not be presented as a current forecast.

The Python reference implementation proved much of the architecture and behavior but is not release-complete. The Go/Svelte migration is active and incomplete.

### Frozen implementation direction

- Go management/control plane
- Svelte 5 + strict TypeScript frontend
- dnsdist + BIND independent DNS data plane
- Parquet + Zstandard raw analytics, DuckDB reads, bounded SQLite WAL aggregates
- schema-validated YAML plus bounded transactional SQLite
- complete V1.1.1/Python-V2 state compatibility
- no placeholder pages or permanently disabled controls
- no public V2 until complete owner acceptance

### Remaining dependency order

1. Complete shared Svelte infrastructure and every partially implemented product area.
2. Finish Dashboard/analytics, Clients/discovery/policy, Query Log, cache, filtering/custom rules, Local DNS, upstreams, routing, and resolver policy.
3. Complete backup/restore/import/migration, including V1.1.1 `.tar.gz`, V2 backups, selective restore, safety backup, and rollback.
4. Complete Network Configuration, System Status, logs, notifications, schedules, replication, updates, audit, and diagnostics.
5. Complete native HTTPS certificate workflows and prove DoH/DoT plus every supported encrypted-DNS transport without insecure fallback.
6. Migrate/remove temporary compatibility boundaries and remaining worker roles.
7. Complete amd64/arm64 packaging, fresh install, Python-V2 upgrade, V1 migration, restart persistence, rollback, performance, security, browser, and owner-acceptance gates.

Progress is counted only when a real end-to-end workflow has its Go API, Svelte UI, automated tests, Chromium proof, deployed-preview proof, and owner acceptance.

---

## 11. Engineering-Agent Budget and Handoff Rules

The original agent-usage plan did not hold: repeated broad prompts, duplicated context, concurrent implementation/review sessions, repeated full-suite runs, and premature checkpointing consumed the available engineering budget without completing the planned scope.

The replacement rules are mandatory:

- one Alderpoint engineering agent at a time
- no simultaneous CC and Dex implementation sessions
- prompts contain only current delta, exact objective, essential constraints, required proof, and stop condition
- reference canonical repo documents instead of repasting history or architecture
- one coherent end-to-end product slice per assignment
- focused tests during implementation; full suites at meaningful integration/release gates
- concise reports: SHA, deployed version, completed parity rows, failures, and exact next row
- no “natural stopping point” when no genuine owner decision or safety blocker exists
- Dex reserved for high-value independent security/architecture/release gates

The repository parity matrix is the backlog. Agent prose is not a substitute for completed product behavior.

---

## 12. V2 Release Gates

V2 publication is forbidden until all are green:

- every mandatory feature in Section 5 complete
- no DHCP implementation
- V1 feature-regression matrix green
- V1 -> V2 upgrade tested
- fresh install tested
- rollback/recovery tested
- analytics storage bounded and retention proven
- DNS remains operational when analytics is stopped/broken
- DNS remains operational when web UI is stopped/broken
- host resolution remains independent
- performance targets pass
- security review passes
- CC full regression passes
- Dex final review passes
- owner acceptance passes

---

## 13. Version and Migration Strategy

- v1.1.1 remains the current public stable release while V2 is private.
- The Python V2 preview remains a protected engineering/behavioral reference, not a public release line.
- The Go/Svelte implementation is the selected V2 destination.
- V1 receives only critical/security maintenance while V2 is completed.
- Python V2 state and released V1.1.1 `.tar.gz` backups must migrate into Go/Svelte safely.
- The Python management application cannot be retired until full parity, migration, rollback, packaging, performance, security, and owner acceptance pass.
- Promotion to the normal management endpoint is a controlled final step, not an excuse to expose an incomplete preview.

---

## 14. Definition of Success

Alderpoint DNS V2 succeeds when it is:

- DNS-only
- stupid fast
- overly secure by default
- easy to administer
- resilient when analytics/UI/update components fail
- complete coverage of the agreed mandatory DNS-appliance capability set
- architecturally cleaner than V1
- straightforward to upgrade from V1
- easy to recover
- understandable by an operator without knowing internal database schemas
- delivered through a polished, fast, complete Svelte interface with no placeholder routes, dead controls, timestamp ambiguity, container-network leakage, or unexplained waiting

The product is designed to deliver the mandatory DNS-appliance capability set with strong failure isolation, safe deployment, bounded storage, high performance, and an Alderpoint-native UI and architecture.
