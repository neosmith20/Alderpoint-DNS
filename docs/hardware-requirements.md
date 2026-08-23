# Hardware Requirements

**Public/stable notice:** this page is not the private V2 hardware acceptance contract. Private V2
hardware requirements are governed by `docs/v2/v2-roadmap.md`.

Current private V2 evidence treats 2 GB as the minimum proven boot/functional tier, 3 GB as a
comfortable intermediate tier, and 4 GB as the recommended owner/normal deployment target. Obsolete
512 MiB V2 expectations are not meaningful V2 acceptance targets.

Minimum system:

- 1 vCPU
- 512 MiB RAM
- 1 GiB free disk after OS installation
- One private network interface

Recommended system:

- 2 vCPU
- 2 GiB RAM
- 8 GiB free disk
- Reliable local storage for SQLite and backups

Sizing notes:

- Analytics, backups, and imported source retention drive disk usage.
- BIND cache size defaults to a conservative fraction of RAM and is tunable
  under `/dns-cache`.
- Large blocklists increase generated RPZ size and BIND memory use.
