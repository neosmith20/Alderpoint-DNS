# Workstream 4A — Clean-Install Evidence

## Artifact identity

- Filename: `alderpointdns-v2_2.0.0~private1-1_all.deb`
- Built by: `scripts/build-v2-deb.sh` from commit (see `git log` at the top of this pass)
- Size: 69,679,692 bytes
- SHA-256: `ca030d507ee9fe673ff3fa821532f79eeb09c04ee0009917511eb2b5621d71d9`
- Retained at (this session's scratchpad, not committed to git — reproducible byte-for-byte from
  `scripts/build-v2-deb.sh` against this commit; the 69MB binary itself does not belong in git
  history): `/tmp/claude-0/-root/e06833ae-afeb-4ece-bf06-24584462b1d4/scratchpad/alderpointdns-v2_2.0.0~private1-1_all.deb`

## Environment

- Base image: `docker.io/library/debian:trixie` (pulled fresh this session), then `systemd
  systemd-sysv dbus apparmor apparmor-utils sudo procps iproute2` installed (the same minimal
  systemd-bootstrap set `tests/test_clean_install_container.sh` already uses for V1) — no
  Alderpoint-anything present before the package under test was installed.
- Container engine: `podman`, `--systemd=always`, `/sbin/init` as PID 1, confirmed
  `systemctl is-system-running` → `running` before any install step.
- Install command: `apt-get install -y -qq /tmp/alderpointdns-v2.deb` — dependency resolution
  against Debian 13's own stock repositories only, no third-party repo configured at any point.

## Proof transcript (summarized; full session output available in conversation history)

1. **`apt-get install`**: succeeded, exit 0. `Depends:` resolved entirely from stock Debian 13
   (`dnsdist`, `bind9-utils`, `python3-argon2`, `python3-cryptography`, `python3-pip`, `sqlite3`).
2. **postinst ran to completion**: vendor runtime provisioned, `init-state` wrote a valid default
   config + initialized `control.db` (schema version 2) + initialized the secret store,
   `generate-runtime` produced a real dnsdist config validated by real `dnsdist --check-config`
   and a real RPZ zone validated by real `named-checkzone`.
3. **`dpkg -s alderpointdns-v2`** → `Status: install ok installed`.
4. **Three systemd services active**: `alderpointdns-v2-analytics`, `alderpointdns-v2-tierb`,
   `alderpointdns-v2-schedule`, all `active (running)`, confirmed via `systemctl status` showing
   the real `MemoryMax=512M` cgroup limit applied and the process running as `alderpointdns-v2`.
5. **Filesystem ownership/modes**: matches `docs/v2/packaging.md`'s table exactly (verified via
   `ls -ld` on every path — `/var/lib/alderpointdns-v2/secrets` is `0700`, config is `0640
   root:alderpointdns-v2`, `compiled/` is `0755`).
6. **Python imports from installed paths, system `python3`, no dev paths**:
   `PYTHONPATH=/opt/alderpointdns-v2:/opt/alderpointdns-v2/vendor-runtime-v2-analytics python3 -c
   "import app.v2.policy_store, app.v2.dnsdist_gen; import pyarrow, duckdb"` → `pyarrow 25.0.1`,
   `duckdb 1.5.5`.
7. **Secret store**: wrote+read+deleted a real secret through the installed `SecretStore` class.
8. **Policy compile**: `compile_effective_policy(PolicyLayer(safesearch_mode="strict"))` →
   `strict`, from the installed package.
9. **Analytics real round-trip**: `alderpointdns-v2-ctl analytics-worker --once
   --inject-test-event` → real Parquet segment written
   (`analytics/queries/2026/08/15/08-000000.parquet`), queried by real DuckDB
   (`duckdb.connect().execute("select domain, qtype, client from read_parquet(...)")` →
   `[('clean-install-proof.example', 'A', '127.0.0.1')]`), real aggregate row present in
   `aggregates.db`'s `time_buckets` table.
10. **Real isolated DNS test (mandatory Gate #2 cross-policy matrix, re-run from the installed
    package)**: built two `ClientPolicyBinding`s (strict client `127.0.0.2` with a REFUSED-mode
    blocked domain, lenient client `127.0.0.100` with no blocks) via
    `app.v2.dnsdist_policy_runtime.compile_multi_policy_dnsdist_config`, validated with real
    `dnsdist --check-config`, started a real isolated `dnsdist` process, queried with real `dig -b
    <source-ip>`:
    - strict client → blocked domain: **RCODE REFUSED** (`status: REFUSED`)
    - lenient client → same domain: **not** refused (`status: NXDOMAIN` — real upstream response
      for a nonexistent domain, correctly distinguishable from a forced REFUSED)
    - both clients → `iana.org`: **NOERROR**, real resolution
    - lenient client → blocked domain again (warm cache, second query order): still **not**
      refused — no cross-policy leakage under warm cache
11. **Failure isolation**: with `alderpointdns-v2-analytics` stopped, `alderpointdns-v2-tierb`
    `SIGKILL`ed with its state file corrupted to invalid JSON, and the DuckDB/pyarrow vendor
    runtime directory renamed away entirely — step 10's full DNS test re-run and **passed
    identically**. All three broken services also self-recovered via `Restart=on-failure` without
    manual intervention once their inputs were restored.
12. **Reinstall idempotency**: `apt-get install --reinstall` over the running install preserved a
    hand-edited config value, a manually-created secret, directory ownership, and left all three
    services active.
13. **Remove vs purge**: `apt-get remove` preserved `/etc/alderpointdns-v2`,
    `/var/lib/alderpointdns-v2` (including the secret created in step 12), and
    `/var/log/alderpointdns-v2` — package reported `deinstall ok config-files`. `apt-get purge`
    fully removed all three trees and the `alderpointdns-v2` user/group.
14. **Failure-injection install tests** (fresh reinstall, then targeted breakage):
    - vendor wheels directory missing → `provision-v2-analytics-vendor-runtime.sh` exits 1 with
      `AnalyticsDependencyError: vendor directory not found`, no partial runtime installed.
    - `dnsdist` binary missing → `generate-runtime` exits 1 with `ValidationFailedError`, nothing
      promoted to `compiled/` (directory left empty, not a broken config).
    - `control.db` corrupted to a non-SQLite file → `init-state` exits 1 with
      `sqlite3.DatabaseError: file is not a database`, does not silently proceed.
    - a syntactically-valid-YAML-but-schema-invalid existing config (an unknown top-level key) →
      `init-state` correctly refuses with `ConfigValidationError` rather than silently accepting
      or discarding it (this was found via an unintentional test-harness mistake during the
      reinstall-persistence check, and is the *correct* documented behavior, not a defect).

## Real defect found and fixed during this pass

`__pycache__` directories generated by the Python interpreter at runtime under
`/opt/alderpointdns-v2/app/` and `/opt/alderpointdns-v2/vendor-runtime-v2-analytics/` are not
tracked by dpkg, so `apt-get purge` left `dpkg: warning: ... directory '.../app/v2' not empty so
not removed` and an orphaned `/opt/alderpointdns-v2` directory behind. **Fixed** in
`packaging/v2/postrm` (explicit `find ... -name __pycache__ -exec rm -rf {} +` on both `remove`
and `purge`) and by adding `-B` (no bytecode cache) to every `python3` invocation in `postinst`
and all three systemd units. **Rebuilt the .deb, torn down the container, built a genuinely new
one, reinstalled the exact new artifact, and re-ran the full proof matrix above** — purge now
removes `/opt/alderpointdns-v2` completely with no warning.
