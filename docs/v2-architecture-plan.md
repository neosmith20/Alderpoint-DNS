# Alderpoint DNS V2 — Master Architecture and Delivery Plan

**Status:** Mandatory planning document for Alderpoint DNS V2  
**Target start:** After the v1.2.1 release line is completed and stabilized  
**Target delivery:** 10 focused working days / no more than 14 calendar days for a private release candidate, assuming no major external dependency blocker  
**Publication rule:** V2 MUST NOT be published until every mandatory V2 capability and release gate in this document is satisfied.

---

## 1. Product Charter

Alderpoint DNS V2 is a **DNS-only appliance**.

It exists to provide a faster, more secure, easier-to-use DNS filtering and management platform that offers the useful DNS capabilities expected from AdGuard Home while improving architecture, failure isolation, deployment safety, analytics storage, performance, and administration.

### Explicitly out of scope

- **DHCP server functionality** — intentionally excluded.
- Router functions.
- Firewall/NAT functions.
- General network gateway functionality.

DHCP belongs on a router/router OS and must not be added to Alderpoint DNS simply for checkbox parity with AdGuard Home.

---

## 2. Non-Negotiable Design Goals

1. **DNS data plane must remain independent of the management plane.**
   - dnsdist remains the client-facing DNS frontend.
   - BIND remains the validating/cache/authoritative backend unless a benchmarked redesign proves a materially better DNS-only architecture.
   - DNS queries must never require Python, FastAPI, SQLite, DuckDB, Parquet, or the web UI to answer.

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
- parameters pinned/configured based on a benchmarked security target rather than silently relying forever on library defaults
- automatic rehash when parameters are upgraded
- no reversible password storage
- no plaintext passwords in backups/logs/diagnostics

Evaluate a root-only application pepper stored outside control.db, for example under `/etc/alderpointdns/`, so theft of only the database/backup is insufficient for offline verification without also compromising the separate secret.

### 3.4 Raw query history

Raw query events must be removed from the shared control database.

Preferred design to benchmark first:

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

Preferred query layer to benchmark:

- DuckDB scanning partitioned Parquet files

Benchmark against at least:

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
on disk, SQLite, control.db, the aggregate store, DuckDB, Parquet, FastAPI, the web UI, or the
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
never to a DNS outage, startup failure, or failure propagating into control.db/analytics. See
`docs/v2-adguard-parity-matrix.md` for why this is an Alderpoint-specific enhancement, not an
AdGuard-parity requirement.

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
- AdGuard/Pi-hole migration
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

## 10. Delivery Plan — 10 Working Days / 14 Calendar Days Target

This target assumes focused scope, reuse of the existing proven DNS data plane, no DHCP, and no unrelated feature creep.

### Day 1 — Architecture freeze + branch/scaffolding

- finalize this document
- finalize parity matrix
- create V2 development branch
- freeze schemas/interfaces
- define migration boundaries
- benchmark harness skeleton

### Days 2–3 — Storage/failure-domain redesign

- YAML configuration layer
- control.db split/migration
- analytics ingestion abstraction
- Parquet/Zstd/DuckDB vs alternatives benchmark
- implement winning analytics storage approach
- retention/rotation

### Days 4–6 — Unified policy engine + client capabilities

- hierarchy/inheritance
- groups/tags
- per-client settings
- SafeSearch
- parental/safe-browsing
- service blocking
- schedules
- query-log/stat exclusions
- client discovery

### Days 7–8 — Resolver/routing/security features

- per-client upstreams
- domain-specific routing
- fallback DNS
- upstream strategies
- blocking response modes
- ECS controls
- native admin HTTPS

### Day 9 — Migration, package, backup/restore, compatibility

- V1 -> V2 migration
- backup/restore updates
- replication compatibility/design
- import/export updates
- packaging/install/upgrade

### Day 10 — CC integration hardening

- complete regression suite
- performance checks
- security self-review
- docs
- exact package/fresh-install/upgrade validation

### Days 11–12 calendar reserve — Dex architecture/security assault

- independent review
- adversarial migration tests
- auth/TLS/storage/policy review
- performance/failure testing

### Days 13–14 calendar reserve — final fixes + second Dex verification

- CC addresses only proven findings
- targeted rerun
- final full suite
- Dex confirms blockers closed
- owner acceptance

**One week is an aggressive best case. Two weeks is the realistic target.**

Do not publish a broken V2 simply to satisfy the calendar target.

---

## 11. CC / Dex Usage Budget Strategy

Exact agent token consumption cannot be guaranteed because tool/runtime behavior varies. The goal is to minimize repeated context and expensive broad reviews.

### CC allocation

Use CC for implementation and integration.

Target interaction pattern:

1. V2 scaffolding/storage prompt
2. policy-engine/client-features prompt
3. resolver/HTTPS prompt
4. migration/package prompt
5. final integration/hardening prompt
6. one remediation prompt per Dex review only if needed

Avoid one prompt per tiny bug.

Recommended planning allocation:

- approximately 70–80% of Alderpoint's agent-usage budget
- roughly 5–6 major implementation conversations/prompts
- keep each prompt self-contained but reference canonical repo docs rather than repasting the entire architecture every time

### Dex allocation

Use Dex only at high-value review gates, not after every CC commit.

Three review gates maximum unless a blocker justifies another:

1. architecture/storage/policy review after core V2 foundations
2. security/migration/runtime review after feature complete
3. final release-candidate verification

Recommended planning allocation:

- approximately 20–30% of Alderpoint's agent-usage budget
- 2–3 major review conversations/prompts

### Token-saving rules

- Canonical requirements live in repo docs.
- CC and Dex are instructed to read those docs first.
- Reports are committed/saved as files rather than repeatedly pasted.
- Use one consolidated prompt per workstream.
- Do not make Dex re-review unchanged code.
- Give Dex exact starting/final SHAs and changed-file scope.
- CC fixes only proven findings.
- Avoid broad "review the whole project again" prompts unless the release candidate truly requires it.

This preserves agent availability for the router-OS project.

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

## 13. Version Strategy

- Finish/stabilize v1.1.1.
- Complete the intended v1.x line through v1.2.1.
- Freeze major V1 feature development.
- Start V2 only after v1.2.1 is complete.
- V1 receives only critical/security fixes while V2 is developed.

---

## 14. Definition of Success

Alderpoint DNS V2 succeeds when it is:

- DNS-only
- stupid fast
- overly secure by default
- easy to administer
- resilient when analytics/UI/update components fail
- at least feature-parity with the agreed useful AdGuard DNS feature set
- architecturally cleaner than V1
- straightforward to upgrade from V1
- easy to recover
- understandable by an operator without knowing internal database schemas

The product is not trying to clone AdGuard's implementation. It is trying to deliver the useful DNS-appliance capability set with stronger failure isolation, safer deployment, better storage behavior, and an Alderpoint-native UI/architecture.
