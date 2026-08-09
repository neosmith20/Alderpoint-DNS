# Alderpoint DNS Performance Baseline

Source commit: `47cd9b6884651ebca1369bb4dae6c86af24accd7`

This branch is for reproducible baseline/profiling work only. It does not
change production filtering behavior.

## Benchmark Harness

Run:

```bash
python3 scripts/benchmark_filtering.py --datasets small,medium,large --output benchmarks/results/filtering-baseline
```

The harness generates deterministic local synthetic sources at runtime and
does not commit generated blocklist fixtures. It redirects compiler DB,
download, staging, backup, and compiled-output paths to a temporary directory
inside the benchmark process, then imports and calls the current compiler
functions directly.

Dataset targets:

- `small`: about 100k source domains
- `medium`: about 500k source domains
- `large`: about 1M source domains
- `very-large`: about 3M source domains

Each dataset uses three synthetic sources with hosts-format records,
AdGuard-style block rules, plain-domain rules, allow exceptions, duplicates,
and cross-source overlap.

## Measured Phases

- fixture generation
- SQLite schema/source/custom-rule seed
- source read
- parse
- `normalize_domain` sub-time and call count
- deduplication and per-source unique contribution
- database stats writes
- custom rule collection and precedence subtraction
- RPZ render
- RPZ write
- `named-checkzone` validation when available
- cProfile hottest functions by cumulative time and call count
- peak Python allocation from `tracemalloc`
- process peak RSS from `resource.getrusage`

The default harness does not run live `rndc reload`, restart dnsdist, or touch
system BIND/dnsdist configuration. Those service-level timings need a
disposable appliance VM using the production deploy path.

## Environment

- Worktree: `/root/alderpointdns-dex-performance-baseline`
- Branch: `dex/performance-baseline`
- Python: `3.13.5`
- Platform: `Linux-6.12.96+deb13-amd64-x86_64-with-glibc2.41`
- CPU count visible to Python: `4`
- Benchmark command:
  - `python3 scripts/benchmark_filtering.py --datasets small --output benchmarks/results/filtering-baseline-small`
  - `python3 scripts/benchmark_filtering.py --datasets medium,large --output benchmarks/results/filtering-baseline-medium-large`
- Very-large attempt:
  - `python3 scripts/benchmark_filtering.py --datasets very-large --no-validate --output benchmarks/results/filtering-baseline-very-large-no-validate`
  - Stopped after exceeding practical runtime under `cProfile`; no result file was written.

## Filtering Pipeline Map

Manual update/deploy entrypoints:

- Web `POST /blocklists/update`: `app.webapp.blocklist_update()` -> `sudo /opt/alderpointdns/app/alderpointdns_compiler.py update-sources`
- Web `POST /deploy`: `app.webapp.deploy()` -> `sudo ... deploy`
- Scheduled update: `app.filter_schedule.run_scheduled_update()` -> `app.alderpointdns_compiler.run_scheduled_deploy()` -> `deploy(download=True, trigger="scheduled")`
- Fresh install: `app.alderpointdns_compiler.fresh_install_init()` -> `init_db(seed_defaults=True)` -> `deploy(download=True, trigger="fresh-install", fail_on_source_errors=True)`

Core compiler path:

1. `deploy(download=True|False)` opens the deploy flock and records a `deployments` row.
2. `collect_rules(conn, download)` reads enabled sources from `enabled_sources()`.
3. If `download=True`, each source is downloaded serially by `download_source()`.
4. `download_source()` uses `urllib.request.urlopen()` with one request per source, no session reuse.
5. Source bytes are written to a staging file and atomically replaced into `DOWNLOAD_DIR/current`.
6. Each cached/current source file is read by `Path.read_text(errors="replace")`.
7. `parse_rules()` loops over `content.splitlines()`.
8. `parse_source_line()` handles hosts lines directly or delegates AdGuard-style rules to `custom_rules.parse_rule()`.
9. `normalize_domain()` lowercases, IDNA-encodes, regex-validates, and runs `ipaddress.ip_address()` to reject IP literals.
10. Per-source `blocks` and `allows` sets are merged into `all_blocks` and `all_allows`.
11. Cross-source unique contribution is calculated with `seen_domains` and set subtraction.
12. Effective external blocks are `all_blocks - all_allows`.
13. Download and parse stats are written by `record_download_result()` and `record_parse_stats()` in one short transaction.
14. `custom_rules.collect_active()` reads enabled valid custom rules and resolves rewrite/allow/block conflicts in `_resolve_conflicts()`.
15. `custom_rules.subtract_allowed()` removes custom allows from external blocklist domains.
16. `render_rpz()` calls `custom_rules.rpz_records()`, sorts external domains, emits exact and wildcard RPZ records, and returns one large string.
17. `staged_rpz.write_text()` writes the full RPZ text.
18. `validate_rpz()` runs `named-checkzone alderpointdns.rpz <staged_rpz>`.
19. `validate_bind()` runs `named-checkconf -p /etc/bind/named.conf`.
20. Previous compiled RPZ is backed up if present.
21. `os.replace()` atomically installs the staged RPZ.
22. `reload_bind()` runs `rndc reload alderpointdns.rpz`.
23. Sources get `last_compile_success`.
24. `local_dns.deploy_zones(conn)` renders/validates/deploys Local DNS zones, runs `named-checkconf`, `rndc reconfig`, zone reloads, dnsdist packet-cache flush, and live DNS checks.
25. `dns_cache.deploy_cache_options(conn)` deploys BIND cache options.
26. `upstream_dns.deploy_upstreams(conn)` renders dnsdist/BIND upstream config, validates both, restarts dnsdist, runs `rndc reconfig`, and tests resolution.
27. `custom_rules.deploy_dnsdist_layer(conn, custom_active)` renders regex/allow/rewrite dnsdist data files, validates dnsdist config when changed, atomically installs, and restarts dnsdist only if content changed.
28. Post-deploy checks run `dig` for ordinary resolution, blocked-domain behavior, allow-domain structure/live candidates, and rewrites.
29. Deployment row is finalized as `deployed`, `rolled_back`, or `rollback_failed`.

## Protection Toggle Behavior

Current web path:

- `app.webapp.protection_toggle()` determines enable/disable from the latest deployment's `active_domains`.
- Enable path sets all `sources.enabled=1`, all legacy `custom_rules.enabled=1`, and all valid `custom_filter_rules.enabled=1`.
- Disable path sets those rows disabled.
- Both paths call `deploy_no_download()`, which runs `sudo ... deploy --no-download`.

Important finding: Protection OFF -> ON does not download sources, but it still runs the full cache-only compile/deploy pipeline:

- reads all cached source files
- reparses all source content
- renormalizes all domains
- deduplicates/merges all source sets
- recollects custom rules
- re-renders the full RPZ
- writes staged RPZ
- runs `named-checkzone`
- runs `named-checkconf`
- replaces compiled RPZ
- reloads BIND
- redeploys Local DNS, DNS cache, upstream DNS, and dnsdist custom-rule layer as applicable
- runs live post-deploy DNS checks

Repeated enable when a valid compiled policy is already current is therefore not a cheap state flip. It is a full no-download rebuild/deploy.

## Download Architecture Findings

- Serial downloads: `collect_rules()` loops enabled sources one at a time.
- HTTP client: `urllib.request.urlopen()` per source.
- Timeout behavior: connect timeout `10s`; manual total timeout `60s` checked while reading chunks.
- Per-source byte cap: `25 MiB`.
- Connection reuse: none explicit.
- ETag support: none.
- Last-Modified support: none.
- Content hash storage: none.
- Cache behavior: failed download can fall back to existing current file, but that file is still reparsed.
- Unchanged content: still reparsed and recompiled.
- Retry behavior: no bounded retry loop; one attempt per source per deploy.

Safe optimization opportunities: bounded concurrent downloads, connection/session reuse, ETag/If-None-Match, Last-Modified/If-Modified-Since, stored content hash, unchanged-source skip, and unchanged-effective-policy skip.

## SQLite Findings

Filtering pipeline DB work is not the dominant measured cost in synthetic runs.

- Enabled source query: `SELECT * FROM sources WHERE enabled=1 ORDER BY id`.
- Stats writes are batched after parse/download rather than interleaved with network I/O.
- Custom rules collection fetches all enabled valid custom rules in one query: `SELECT * FROM custom_filter_rules WHERE enabled=1 AND validation_state='valid' ORDER BY priority DESC, id`.
- Existing indexes include `idx_custom_filter_rules_enabled` and `idx_custom_filter_rules_domain`.
- `collect_rules()` materializes per-source block sets and all global sets in memory. This is more important than query count for large blocklist scale.
- No per-domain SQLite inserts occur for external blocklist domains; domains are not stored individually.

Potential future DB work: verify query plans around custom-rule collection on large custom-rule tables, but external blocklist performance is currently CPU/memory/string-set dominated, not SQLite dominated.

## Benchmark Results

The measured benchmark is a cache-local compile-like path plus `named-checkzone`.
It does not include live `rndc reload`, dnsdist restart, or post-deploy `dig`
checks.

| Dataset | Target domains | Input rules | Unique domains | Parse s | Normalize subtime s | Dedupe s | Custom/precedence s | RPZ render s | RPZ write s | named-checkzone s | Peak RSS MB | RPZ size MB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Small | 100,000 | 104,349 | 77,101 | 26.664 | 9.157 | 0.016 | 0.623 | 0.743 | 0.004 | 0.596 | 104.45 | 4.85 |
| Medium | 500,000 | 521,739 | 385,507 | 136.291 | 46.736 | 0.087 | 3.240 | 3.926 | 0.021 | 2.754 | 390.70 | 24.26 |
| Large | 1,000,000 | 1,043,478 | 771,013 | 271.191 | 93.688 | 0.178 | 6.502 | 7.900 | 0.042 | 5.541 | 755.36 | 48.53 |

Peak Python allocation from `tracemalloc`:

| Dataset | Peak tracemalloc MB | Peak RSS MB |
| --- | ---: | ---: |
| Small | 49.62 | 104.45 |
| Medium | 220.95 | 390.70 |
| Large | 442.73 | 755.36 |

Protection OFF -> ON with already-current cached policy uses the same no-download rebuild path as the measured cache-local benchmark, plus DB flag updates and live deployment/reload/postcheck. Expected lower bound from the large benchmark is therefore about 291 seconds before live service reload and post-deploy DNS checks:

| Dataset | Cache-local rebuild lower bound s | Notes |
| --- | ---: | --- |
| Small | 27.43 | Excludes live reload/postcheck |
| Medium | 146.36 | Excludes live reload/postcheck |
| Large | 291.44 | Excludes live reload/postcheck |

## Profiler Hotspots

Large dataset, top cumulative functions:

| Function | Calls | Cumulative s |
| --- | ---: | ---: |
| `alderpointdns_compiler.parse_rules` | 3 | 271.127 |
| `alderpointdns_compiler.parse_source_line` | 1,043,478 | 247.682 |
| `custom_rules.parse_rule` | 599,994 | 142.232 |
| `ipaddress.ip_address` | 2,686,950 | 111.077 |
| `benchmark timed normalize wrapper` | 1,043,478 | 95.140 |
| `alderpointdns_compiler.normalize_domain` | 1,043,478 | 92.714 |
| `custom_rules._normalize_domain` | 599,994 | 55.941 |
| `ipaddress.IPv6Address.__init__` | 2,243,466 | 50.663 |
| `alderpointdns_compiler._is_hosts_line` | 1,043,478 | 42.116 |
| `ipaddress.IPv4Address.__init__` | 2,686,950 | 41.216 |

High call-count evidence from the large run:

- `ord`: 32,199,678 calls
- `custom_rules.py:508` control-character generator: 16,699,833 calls
- `str.split`: 8,060,856 calls
- `str.startswith`: 7,873,899 calls
- `str.strip`: 5,373,909 calls
- `str.partition`: 3,886,938 calls

Interpretation: the dominant cost is per-line parsing and validation, especially repeated IP-address parsing and general AdGuard parser delegation for source lines. RPZ render, write, and BIND zone validation are much smaller at these sizes.

## RPZ / BIND Findings

- RPZ render sorts all effective external domains and emits two records per domain.
- RPZ render scales linearly after the sort; for 771k unique domains it took 7.9s.
- RPZ write is not currently a bottleneck on this host: 48.5 MB in 0.042s.
- `named-checkzone` scales reasonably here: 48.5 MB zone in 5.54s.
- Live `rndc reload` was not measured in this safe local harness and must be measured in a disposable appliance VM.
- The current production deploy always validates and reloads after a no-download protection enable.

## Repeat/Warm-Cache Cases

Current behavior by inspection:

- First processing of sources: downloads enabled sources, parses all content, writes stats, compiles, validates, deploys.
- Identical sources processed again with `download=True`: downloads again, overwrites current files, reparses everything, recompiles everything.
- One source changed: all enabled sources are still reparsed from full cached/current files; no incremental parse/compile.
- Protection OFF -> ON when policy already current: no download, but full cached-source reparse/recompile/redeploy.
- Remote content unchanged: there is no ETag/Last-Modified/hash check, so unchanged content still reparses/recompiles.

## Optimization Candidates

### P0

1. Reuse already-valid compiled policy on Protection enable.
   - Evidence: enable calls `deploy --no-download`; large cache-local rebuild lower bound is about 291s before live service checks.
   - Proposed change: introduce durable compiled-policy metadata/hash and allow Protection enable to activate an already-current deployed policy without reparsing/recompiling.
   - Estimated impact: largest user-visible win for OFF -> ON.
   - Correctness risk: high unless policy freshness includes sources, enabled flags, custom rules, Local DNS precedence, dnsdist layer, and deployed artifact hashes.
   - Tests: equivalence hash tests, stale-policy rejection, changed custom rules, changed source files, missing compiled RPZ, failed previous deployment.

2. Avoid unchanged-source reparse and unchanged-effective-policy recompile.
   - Evidence: identical or unchanged content still goes through full parse/render/validate.
   - Proposed change: store source content SHA-256 plus parser version; skip parse for unchanged sources and reuse per-source normalized block/allow artifacts.
   - Estimated impact: large for scheduled/manual updates where upstream content is unchanged.
   - Correctness risk: moderate; parser version and source metadata must invalidate cache.
   - Tests: parser version bump invalidation, corrupted cache, changed allow rules, overlap/dedup ordering.

3. Reduce per-line IP-address parsing.
   - Evidence: `ipaddress.ip_address` consumed 111s cumulative on the large run and is called 2.69M times.
   - Proposed change: cheap lexical prechecks before `ipaddress.ip_address`; avoid IPv6 parsing for ordinary domain labels; avoid duplicate `_is_hosts_line`/`normalize_domain` IP parsing where possible.
   - Estimated impact: large parser CPU reduction.
   - Correctness risk: moderate; IP literal rejection and hosts-line detection must remain exact.
   - Tests: IPv4/IPv6 literals, hosts sentinels, invalid IP-like domains, localhost aliases.

### P1

4. Bounded concurrent blocklist downloads.
   - Evidence: downloads are serial and independent.
   - Proposed change: small concurrency limit with per-source timeout and aggregate deploy lock unchanged.
   - Estimated impact: high when many remote sources are configured.
   - Correctness risk: low to moderate; source ordering for precedence stats must remain source-id order.
   - Tests: timeout, partial failure/cache fallback, deterministic per-source unique contribution.

5. HTTP ETag and Last-Modified support.
   - Evidence: no conditional requests; unchanged remote content is downloaded and reparsed.
   - Proposed change: store ETag/Last-Modified per source and send conditional headers.
   - Estimated impact: high for scheduled updates.
   - Correctness risk: low if 304 handling preserves current file and stats correctly.
   - Tests: 304, changed 200, weak ETag, missing headers, bad server behavior.

6. More direct fast path for common blocklist line formats.
   - Evidence: 600k large-run lines delegate into general custom rule parser.
   - Proposed change: recognize common `||domain^`, `|domain^`, plain-domain, and hosts records without full custom parser when no modifiers/path are present.
   - Estimated impact: high parser CPU reduction.
   - Correctness risk: moderate; unsupported AdGuard syntax must remain unsupported rather than broadened.
   - Tests: all parser fixtures, EasyList/AdGuard variants, modifiers, paths, comments, exceptions.

7. Stream parsing instead of `read_text().splitlines()`.
   - Evidence: full source content, per-source sets, all global sets, and full RPZ text are held in memory.
   - Proposed change: stream file lines into parser and sets.
   - Estimated impact: medium memory reduction.
   - Correctness risk: low if line numbering/rejected samples preserved.
   - Tests: invalid line samples, encodings/errors, multi-host lines.

### P2

8. Avoid repeated sorting where deterministic ordering can be preserved once.
   - Evidence: RPZ render sorts all domains; custom rules also sort categories.
   - Proposed change: cache sorted effective domain list for unchanged policy.
   - Estimated impact: moderate only after caching exists.
   - Correctness risk: low to moderate.

9. Incremental compilation.
   - Evidence: one changed source still rebuilds all sources.
   - Proposed change: per-source normalized artifacts plus deterministic source-order merge.
   - Estimated impact: high for single-source changes.
   - Correctness risk: high because allows, overlap, and custom precedence affect global effective policy.

10. Avoid unnecessary downstream deploy work when generated files are unchanged.
   - Evidence: full deploy calls Local DNS, DNS cache, upstream DNS, and dnsdist layer even for blocklist-only no-download rebuilds.
   - Proposed change: content-hash checks per artifact/layer and skip unchanged reload/restart where safe.
   - Estimated impact: useful, especially on enable/redeploy.
   - Correctness risk: moderate; post-deploy health semantics must remain honest.

## Equivalence Strategy for Future Optimization

The optimization pass should prove semantic equivalence before performance wins are accepted.

Recommended checks:

- Generate canonical effective-policy manifests containing:
  - sorted external block domains after downloaded/list allows
  - sorted custom exact/wildcard allow/block/rewrite records
  - sorted regex allow/block deployed patterns
  - Local DNS authoritative zones
  - final RPZ owner/rdata pairs
  - dnsdist custom data files
- Hash canonical manifests with SHA-256.
- Compare old and optimized pipeline outputs on fixture suites covering:
  - explicit allow
  - explicit block
  - important block vs allow
  - regex allow and regex block
  - rewrites
  - Local DNS precedence
  - external blocklists
  - duplicates and cross-source overlap
  - subdomain vs exact semantics
  - downloaded exceptions
  - unsupported modifiers
- Include live integration tests in a disposable VM for:
  - ordinary resolution
  - blocked external domain
  - custom allow passthrough
  - custom rewrite
  - regex block
  - Local DNS override

## 1.0 Performance Work Blockers

- Protection enable currently performs a full no-download rebuild even when compiled policy is already current.
- Parser CPU dominates large-list deployments; `ipaddress` validation and general parser delegation are the clearest measured hotspots.
- No HTTP freshness model exists, so scheduled/manual updates cannot skip unchanged sources.
- No durable compiled-policy/source-artifact metadata exists to safely skip work.
- Multi-million source scale was not practical to complete under full cProfile on this host; future VM benchmarking should include unprofiled wall-clock runs and live BIND reload timings.

## v1 Feature-Freeze Optimization Pass

Authoritative starting point: `15c9fa92f8cfa3eb45cf5c38feb53aaeff74cf06`

Fresh worktree: `/root/alderpointdns-dex-v1-performance`

Branch: `dex/v1-performance`

### Fresh Before Baseline

Command:

```bash
python3 scripts/benchmark_filtering.py --datasets small,medium,large --output benchmarks/results/v1-before-filtering-baseline
```

| Dataset | Input rules | Unique domains | Parse s | Normalize subtime s | RPZ render s | named-checkzone s | Peak RSS MB | RPZ size MB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Small | 104,349 | 77,101 | 27.115 | 9.316 | 0.761 | 0.655 | 104.80 | 4.85 |
| Medium | 521,739 | 385,507 | 136.289 | 46.988 | 3.906 | 2.824 | 392.38 | 24.26 |
| Large | 1,043,478 | 771,013 | 266.071 | 91.703 | 7.553 | 5.621 | 756.93 | 48.53 |

### Implemented Optimizations

- Added a conservative fast path for common source-list records:
  - `domain.example`
  - `||domain.example^`
  - `|domain.example^`
  - `@@||domain.example^`
  - `@@domain.example`
- Kept complex AdGuard/Pi-hole rules on the existing parser path.
- Added cheap IP-literal prechecks before `ipaddress.ip_address()`.
- Skipped IDNA encode/decode for already-ASCII domains.
- Added streaming source-file parsing for production cache misses.
- Added source parse artifacts keyed by source id, SHA-256 content hash, and parser-cache version.
- Added compiled protection-policy artifact reuse keyed by a canonical manifest of current source rows, source content hashes, custom rules, Local DNS records/settings, DNS cache settings, upstream resolver settings, parser version, and policy-cache version.
- Wired Protection enable to try the fixed privileged `protection-enable-reuse` command first, falling back to `deploy --no-download` whenever reuse cannot be proven safe.

The reuse design fails closed: missing artifacts, unreadable manifests, missing source files, source content changes, source enable/disable changes, custom-rule changes, Local DNS changes, DNS cache setting changes, upstream resolver changes, parser-cache version changes, or policy-cache version changes all force the existing rebuild path.

### Final After Baseline

Command:

```bash
python3 scripts/benchmark_filtering.py --datasets small,medium,large --output benchmarks/results/v1-after-filtering-baseline
```

| Dataset | Input rules | Unique domains | Parse s | Normalize subtime s | RPZ render s | named-checkzone s | Peak RSS MB | RPZ size MB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Small | 104,349 | 77,101 | 9.001 | 2.520 | 0.768 | 0.626 | 103.72 | 4.85 |
| Medium | 521,739 | 385,507 | 45.042 | 12.689 | 3.978 | 3.102 | 391.22 | 24.26 |
| Large | 1,043,478 | 771,013 | 90.827 | 25.651 | 8.104 | 5.949 | 756.27 | 48.53 |

Parser speedup:

| Dataset | Before parse s | After parse s | Speedup |
| --- | ---: | ---: | ---: |
| Small | 27.115 | 9.001 | 3.01x |
| Medium | 136.289 | 45.042 | 3.03x |
| Large | 266.071 | 90.827 | 2.93x |

Normalization speedup:

| Dataset | Before normalize s | After normalize s | Speedup |
| --- | ---: | ---: | ---: |
| Small | 9.316 | 2.520 | 3.70x |
| Medium | 46.988 | 12.689 | 3.70x |
| Large | 91.703 | 25.651 | 3.57x |

Peak RSS was essentially unchanged in the direct parser benchmark because the
harness intentionally still materializes the full generated source text and
full block/allow/domain sets while running cProfile. Production cache misses
now parse source files as streams, and unchanged source runs avoid parsing
entirely through artifacts.

### Source Cache Reuse Benchmark

Command used a local harness snippet over the same generated datasets and
called `collect_rules(download=False)` twice: first cache miss, then unchanged
cache hit.

Result file: `benchmarks/results/v1-source-cache-reuse.json`

| Dataset | Input rules | Unique domains | First collect s | Second unchanged collect s | Speedup | Equivalent |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Small | 104,349 | 77,101 | 0.741 | 0.060 | 12.38x | yes |
| Medium | 521,739 | 385,507 | 3.742 | 0.295 | 12.69x | yes |
| Large | 1,043,478 | 771,013 | 8.077 | 0.639 | 12.64x | yes |

These figures are unprofiled wall-clock timings, so they are much lower than
the cProfile direct-parser benchmark. The important comparison is first
cache-miss collect versus second unchanged collect in the same process.

### Final Hotspots

After optimization, large-dataset cumulative profile:

- `parse_rule_lines`: 90.328s
- `parse_source_line`: 70.069s
- `_fast_common_source_rule`: 28.244s
- `normalize_domain`: 24.860s
- `_is_hosts_line`: 17.401s
- `ipaddress.ip_address`: 15.389s

The original `custom_rules.parse_rule` hotspot is no longer on the common-path
top list for the synthetic blocklist mix because common source lines no longer
delegate to the full custom-rule parser.

### Remaining Bottlenecks

- First-time parsing of very large ASCII source lists still spends significant
  time in per-line Python string processing and set insertion.
- Memory is still dominated by the complete effective domain sets and generated
  RPZ text. Reducing that further would require deeper streaming/partitioning
  design and more semantic proof.
- Live `rndc reload`, dnsdist restart, and full appliance DNS behavior were not
  measured in this local worktree benchmark because this branch was not
  installed over the running appliance.
