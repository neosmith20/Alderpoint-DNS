# Filtering and RPZ deployment

BindGuard v1 filtering is implemented by `app/bindguard_compiler.py`.

Current capabilities:

- SQLite state at `/var/lib/bindguard/bindguard.db`
- Public source tracking with per-source parse statistics and last errors
- A curated 19-source public blocklist catalog seeded with `seed-public`,
  spanning AdGuard-hosted assets and GitHub raw URLs
- Bulk source updates with `update-sources` and single-source refreshes with
  `update-source <id>`
- Downloads through the host resolver with connection and total timeouts
- Maximum source size limit of 25 MiB per list
- Preservation of the last successful downloaded copy when an update fails
- Plain domain, hosts-file, basic `||domain^`, and basic `@@||domain^`
  parsing
- IDN normalization, invalid rule counts, unsupported rule counts, duplicate
  counts
- Custom allow and block rules
- Custom allow precedence over all block rules
- Generated RPZ at `/var/lib/bindguard/compiled/bind/bindguard.rpz`
- `named-checkzone` and `named-checkconf` validation before deploy
- Atomic RPZ replacement, `rndc reload bindguard.rpz`, post-deploy DNS tests,
  and rollback to the previous RPZ on failure
- Download-only updates with `update-sources`, used for maintenance-resolution
  testing while DNS services are stopped

Seed the lab source and deploy:

```sh
/opt/bindguard/app/bindguard_compiler.py init-db
/opt/bindguard/app/bindguard_compiler.py seed-lab
/opt/bindguard/app/bindguard_compiler.py deploy
/opt/bindguard/app/bindguard_compiler.py update-sources
```

Refresh one source without touching the other configured sources:

```sh
/opt/bindguard/app/bindguard_compiler.py update-source 1
```

Seed the larger public catalog when operationally ready:

```sh
/opt/bindguard/app/bindguard_compiler.py seed-public
/opt/bindguard/app/bindguard_compiler.py update-sources
/opt/bindguard/app/bindguard_compiler.py deploy
```

Use `seed-public --disabled` to load the catalog metadata without enabling the
sources immediately.

Run tests:

```sh
/opt/bindguard/tests/test_blocklist_deploy.sh
/opt/bindguard/tests/test_blocklist_failure_paths.sh
```

Unsupported AdGuard syntax such as regex rules, modifiers, cosmetic rules, and
browser-only rules is counted and reported, not interpreted as DNS policy.
