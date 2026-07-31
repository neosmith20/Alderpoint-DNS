# Supported Systems

Supported for beta testing:

- Debian 12
- Debian 13
- Ubuntu 24.04 LTS
- Ubuntu 26.04 LTS, once its package set matches the documented dependencies

Supported architectures:

- x86_64/amd64
- arm64/aarch64

Required services:

- BIND 9
- dnsdist (>= 1.9.0); Debian 13's own archive package satisfies this with no
  third-party repository, and supports plain DNS, DoH, DoT, and DNSCrypt.
  DoQ/DoH3 additionally require a dnsdist build with QUIC support (for
  example, the official PowerDNS repository build) — Alderpoint DNS detects
  this automatically and reports DoQ/DoH3 as unsupported rather than
  enabling them when it is missing; see `docs/dnsdist.md`.
- systemd
- SQLite

Unsupported:

- Public recursive-resolver exposure without firewall controls
- Non-systemd Linux distributions
- Containers that cannot run BIND/dnsdist with required listeners and
  capabilities
