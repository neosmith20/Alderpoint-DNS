# Hardware Requirements

Minimum beta test system:

- 1 vCPU
- 512 MiB RAM
- 1 GiB free disk after OS installation
- One private network interface

Recommended beta test system:

- 2 vCPU
- 2 GiB RAM
- 8 GiB free disk
- Reliable local storage for SQLite and backups

Sizing notes:

- Analytics, backups, and imported source retention drive disk usage.
- BIND cache size defaults to a conservative fraction of RAM and is tunable
  under `/dns-cache`.
- Large blocklists increase generated RPZ size and BIND memory use.
