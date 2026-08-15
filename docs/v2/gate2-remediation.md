# Gate #2 Blocker Remediation (this pass)

**Status:** All 3 blockers, both HIGH findings, and both MEDIUM findings fixed and proven with
real runtime/adversarial tests. Regressions re-verified.

## Blockers

1. **DoH silent downgrade** — real dnsdist 2.1.1 DoH backend support implemented and verified
   end-to-end (live isolated instance, `backend.protocol="DoH"`, real HTTPS/443 resolution to
   Cloudflare). `policy_store.create_upstream_profile()` now rejects a DoH profile with no TLS
   hostname at creation time; the generator refuses to synthesize one even if bypassed. See
   `app/v2/policy_store.py`, `app/v2/dnsdist_gen.py`, `tests/v2/test_doh_no_downgrade.py`.
2. **Effective policy not enforced at runtime** — `app/v2/dnsdist_policy_runtime.py` (new) compiles
   real per-client-network dnsdist rules (SafeSearch/parental/malware/service blocking/response
   modes/domain routing/ECS), all enforced before BIND is contacted, per-effective-cache-profile
   packet-cache partitioning. Proven with a real cross-policy DNS test matrix using distinct real
   loopback source IPs in both query orders with cache warming. See
   `docs/v2/policy-runtime-architecture.md`, `tests/v2/test_policy_runtime_matrix.py`.
3. **pyarrow/duckdb missing from production packaging** — real vendored-wheel provisioning
   mechanism (mirrors the project's existing python-multipart precedent), proven against the real
   system `python3` (not `dev/.venv-v2-bench`): 683 tests passing, 0 skipped, 0 failed. Degraded
   state is now observable (`WriterStats.dependency_unavailable`, `QueryResult.degraded`,
   `AnalyticsService.health()`). See `docs/v2/analytics-dependency-packaging.md`,
   `app/v2/analytics_deps.py`.

## HIGH findings

- **Secret restore not atomic** — real stage→backup→promote→rollback implementation in
  `SecretStore.import_all()`; a write failure at any point leaves the store in its exact pre-call
  state. See `tests/v2/test_secret_restore_atomicity.py`.
- **Migration source detection too lax** — real exhaustive schema contract
  (`REQUIRED_TABLES_AND_COLUMNS`/`OPTIONAL_TABLES_AND_COLUMNS` in `app/v2/migration_convert.py`),
  rejecting an incomplete source at detection time with every missing table/column named. See
  `tests/v2/test_migration_source_detection.py`.

## MEDIUM findings

- **Raw SQL fragment API** — `analytics_query.py`'s `query_time_window()` hardened to an
  allowlisted column projection + sort-column/sort-direction enum. See
  `tests/v2/test_analytics_query_sql_hardening.py`.
- **Pre-render DNS name validation** — `app/v2/dns_name_validate.py` (new), wired into every real
  generation call site. See `tests/v2/test_dns_name_validate.py`,
  `tests/v2/test_dns_name_validation_at_generation.py`.

## Regression verification (this pass, after all fixes)

- `tests/v2/`: **683 passed, 0 skipped, 0 failed** under both the real system `python3` and
  `dev/.venv-v2-bench` (previously Dex reproduced 521 passed/5 skipped/5 failed under the real
  runtime due to Blocker 3).
- V1 regression surface (27 files): **966 passed, 0 failed** under the real system `python3`.
- Control.db forbidden-schema invariant: re-verified, `tests/v2/test_control_db.py` (16 tests)
  green.
- Domain-routing shuffled-order precedence: re-verified, `tests/v2/test_p0_review_fixes.py` green.
- Real REFUSED RCODE 5: re-verified multiple times across this pass's own new tests
  (`test_doh_no_downgrade.py`, `test_policy_runtime_matrix.py`, `test_dnsdist_cache_policy.py`).

## Safety

V1 services (`alderpointdns`, `alderpointdns-analytics`, `dnsdist`, `named`, `bind9`) remained
active throughout every checkpoint; memory/disk usage unaffected; no orphaned test processes; no
public push/tag/release.
