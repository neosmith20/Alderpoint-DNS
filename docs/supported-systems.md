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
- PowerDNS dnsdist with DoH/DoT support; DoQ/DoH3 require a dnsdist build with
  QUIC support
- systemd
- SQLite

Unsupported:

- Public recursive-resolver exposure without firewall controls
- Non-systemd Linux distributions
- Containers that cannot run BIND/dnsdist with required listeners and
  capabilities
