# Alderpoint DNS V2 — Private Candidate Packaging (Workstream 4A)

Real, built, clean-installed .deb. Fully separate namespace from the live V1 `alderpointdns`
package — different package name, paths, user/group, and systemd unit names — so it can never
interact with the V1 appliance even if a mistake put both on the same host (belt-and-suspenders:
the package also declares `Conflicts: alderpointdns`).

## Filesystem layout

| Path | Owner:Group | Mode | Contents |
|---|---|---|---|
| `/opt/alderpointdns-v2/` | root:root | 0755 | `app/` (only `app/__init__.py` + `app/v2/` — no V1 code, confirmed no cross-imports), `vendor/v2-analytics/*.whl`, `scripts/v2/alderpointdns_v2_ctl.py`, `scripts/provision-v2-analytics-vendor-runtime.sh` |
| `/opt/alderpointdns-v2/vendor-runtime-v2-analytics/` | root:root | 0755 | Provisioned pyarrow/duckdb, generated at install time, reproducible from the bundled wheels — never user state, deleted on remove/purge |
| `/etc/alderpointdns-v2/` | root:alderpointdns-v2 | 0750 | `alderpointdns.yaml` (0640, root:alderpointdns-v2) |
| `/var/lib/alderpointdns-v2/` | alderpointdns-v2:alderpointdns-v2 | 0750 | state root |
| `/var/lib/alderpointdns-v2/control.db` | alderpointdns-v2:alderpointdns-v2 | — | control/policy/migration-state SQLite |
| `/var/lib/alderpointdns-v2/secrets/` | alderpointdns-v2:alderpointdns-v2 | **0700** | one-file-per-secret store, owner-only |
| `/var/lib/alderpointdns-v2/analytics/queries/` | alderpointdns-v2:alderpointdns-v2 | 0750 | raw Parquet history |
| `/var/lib/alderpointdns-v2/analytics/aggregates.db` | alderpointdns-v2:alderpointdns-v2 | 0750 | bounded aggregate SQLite |
| `/var/lib/alderpointdns-v2/analytics/inbox/` | alderpointdns-v2:alderpointdns-v2 | 0750 | real event-file drop point for analytics-worker (nothing writes into it yet — no DNS-side event logger exists; see "Known limitations") |
| `/var/lib/alderpointdns-v2/tierb/working-set.json` | alderpointdns-v2:alderpointdns-v2 | 0750 | Tier B popularity snapshot |
| `/var/lib/alderpointdns-v2/schedule/` | alderpointdns-v2:alderpointdns-v2 | 0750 | schedule-transition state |
| `/var/lib/alderpointdns-v2/migration/` | alderpointdns-v2:alderpointdns-v2 | 0750 | migration working state |
| `/var/lib/alderpointdns-v2/backups/` | alderpointdns-v2:alderpointdns-v2 | 0750 | backup archives |
| `/var/lib/alderpointdns-v2/staging/` | alderpointdns-v2:alderpointdns-v2 | 0750 | stage-before-promote scratch for generated runtime |
| `/var/lib/alderpointdns-v2/compiled/` | alderpointdns-v2:alderpointdns-v2 | **0755** | generated+validated dnsdist.conf / bind/*.rpz — world-readable-by-group like the V1 precedent, since a future dnsdist/named integration needs to read it |
| `/var/lib/alderpointdns-v2/certs/` | alderpointdns-v2:alderpointdns-v2 | 0750 | reserved for HTTPS material (Priority 4, not yet implemented) |
| `/var/log/alderpointdns-v2/` | alderpointdns-v2:alderpointdns-v2 | 0750 | reserved for structured logging (workers currently log to journald via systemd) |

## Ownership model

One dedicated system user/group, `alderpointdns-v2:alderpointdns-v2`, created by `postinst`. No
component of this package runs as root after install — the three worker systemd units run
`User=alderpointdns-v2 Group=alderpointdns-v2`. `/etc/alderpointdns-v2` itself stays root-owned
(group-readable) matching the V1 `/etc/alderpointdns` convention: config is root-controlled,
readable by the service group, not writable by unprivileged code.

## Package identity

- Package: `alderpointdns-v2`
- Private candidate version: `2.0.0~private1-1` (the `~` sorts before the eventual `2.0.0-1` final
  release this is a pre-release of, same convention V1's own beta/dev/rc tags use)
- `Depends: dnsdist (>= 1.9.0), bind9-utils, python3 (>= 3.11), python3-argon2, python3-cryptography, python3-yaml, python3-pip, sqlite3`
  — every one of these resolves from Debian 13's own stock repositories (verified: the clean-install
  container never configured a third-party repo). `python3-pip` is required at install time only
  (provisioning step), matching V1's own documented lesson about this exact dependency.
- `Conflicts: alderpointdns` — cannot be co-installed with the live V1 package.

## Package lifecycle

- **preinst**: no-op today (first private candidate — nothing to be compatible with yet); real hook
  point reserved for a future upgrade's layout-version check.
- **postinst** (`configure`): create user/group → provision analytics vendor runtime (fails the
  install non-zero on failure) → `alderpointdns-v2-ctl init-state` (idempotent: writes default
  config only if absent, initializes control.db/secret store, validates an existing config loudly)
  → `alderpointdns-v2-ctl generate-runtime` (real `dnsdist --check-config` / `named-checkzone`
  validation of the default-install runtime artifacts) → ownership reassertion → enable+restart the
  three worker services → wait for each to reach `active`, fail the install if any doesn't.
- **prerm**: stops the three worker services on remove/upgrade/deconfigure.
- **postrm**:
  - `remove` — deletes only package-owned, 100%-reproducible-from-the-package content
    (`vendor-runtime-v2-analytics/`, runtime `__pycache__`); **config, control.db, secrets,
    analytics history, backups all survive.**
  - `purge` — deletes everything under `/etc/alderpointdns-v2`, `/var/lib/alderpointdns-v2`,
    `/var/log/alderpointdns-v2`, and removes the system user/group. This is the one path where
    destroying secrets/control state is correct and expected.

## Why no dnsdist/BIND/management-API/HTTPS systemd unit

Two independent, real reasons, not scope-avoidance:

1. **No API/UI exists.** `app/v2/` has zero `FastAPI(` occurrences and zero `if __name__` entry
   points anywhere (verified by inspection before writing any packaging code) — Priority 6/7 of the
   Workstream 4 roadmap. There is nothing to package as a service.
2. **V2 must not become authoritative yet** (explicit safety constraint carried across every
   workstream). Shipping a systemd unit that binds a real dnsdist/BIND listener on port 53 would
   risk exactly that the moment this package is ever installed anywhere real. `generate-runtime`
   proves the generation+validation pipeline against the real installed binaries; nothing in this
   package starts a live listener on its own.

The three units this package *does* ship (`alderpointdns-v2-analytics`, `-tierb`, `-schedule`) are
real: each is a thin `alderpointdns_v2_ctl.py` subcommand wrapper around already-tested library
code (`app/v2/analytics_pipeline.py`, `app/v2/tier_b_prewarm.py`, `app/v2/schedule_runtime.py`),
proven running under systemd hardening (`ProtectSystem=strict`, `NoNewPrivileges=true`, scoped
`ReadWritePaths=`, `MemoryMax=`) inside the clean-install container.

## DNS-first startup order

None of the three worker units are `Before=`/`After=`/`Requires=`-related to any DNS-serving
process, in either direction — proven, not just asserted: with all three workers stopped/killed/
corrupted simultaneously (analytics service stopped, Tier B process `SIGKILL`ed with a corrupted
JSON state file, and the DuckDB/pyarrow vendor runtime directory renamed away), a freshly started
isolated dnsdist instance using the installed package's own
`dnsdist_policy_runtime.compile_multi_policy_dnsdist_config` still answered every query in the
mandatory Gate #2 cross-policy matrix correctly (REFUSED for the blocked client, NXDOMAIN/NOERROR
for the other, no leakage in either query order, warm-cache no-leakage). See
`docs/v2/clean-install-evidence.md`.

## Known limitations (real, not placeholders)

- `alderpointdns-v2-analytics.service`'s inbox directory (`analytics/inbox/`) has no real producer
  yet — nothing on the DNS side emits query events into it. The worker, pipeline, Parquet writer,
  and DuckDB query path are all real and proven (clean-install evidence has a real injected test
  event producing a real Parquet segment queried by real DuckDB), but wiring an actual DNS
  event source is Priority 6+ (management/observability) work.
- `generate-runtime` compiles the fresh-install *default* profile only (a fixed private-network ACL
  + two public fallback resolvers) — it does not yet compile a real multi-network/multi-client
  effective-policy runtime from arbitrary `control.db` content, because nothing populates
  networks/clients/policies without a management API, which does not exist yet.
- No HTTPS/TLS listener, no client discovery, no mTLS secret replication transport — all
  out of scope for this packaging pass (Priorities 3–8 of the Workstream 4 spec).
