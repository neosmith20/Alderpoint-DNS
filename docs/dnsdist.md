# dnsdist frontend

Alderpoint DNS uses dnsdist as the only client-facing DNS frontend.

Current lab configuration:

- Plain UDP/TCP DNS: `0.0.0.0:53`, `[::]:53`
- DoH: `https://<vm-lan-ip>/dns-query`
- DoH3: UDP `0.0.0.0:443`, `[::]:443` (only if the installed dnsdist build supports it)
- DoT: `0.0.0.0:853`, `[::]:853`
- DoQ: UDP `0.0.0.0:853`, `[::]:853` (only if the installed dnsdist build supports it)
- BIND backend: `127.0.0.1:5354` with PROXYv2 client address forwarding
- BIND recovery/health listener: `127.0.0.1:5353`
- ACL: RFC1918 private networks, loopback, and `fc00::/7` by default
- dnsdist web/API: `127.0.0.1:8083`, random local credentials
- dnsdist console: `127.0.0.1:5199`, random local key

Set `ALDERPOINTDNS_DNS_ALLOW_ALL=1` in the dnsdist service environment to allow
queries from all IPv4 and IPv6 clients. Alderpoint DNS expects your network firewall (VLAN/segmentation rules) to
be the network exposure boundary.

Encryption Settings writes `ALDERPOINTDNS_DNS_LISTEN_IPV4` and
`ALDERPOINTDNS_DNS_LISTEN_IPV6` into the dnsdist systemd override. The defaults
are `0.0.0.0` and `::`; blanking either family disables listeners for that
family, and at least one family must remain configured.

### dnsdist build and capability detection

Alderpoint DNS depends on `dnsdist (>= 1.9.0)` and installs cleanly from
Debian 13's own archive (`dnsdist 1.9.x`) with no third-party repository —
this is the default, tested install path. That build supports plain DNS,
DoH, DoT, DNSCrypt, and everything the BIND backend integration needs
(packet cache, ACLs, remote-logging analytics, authenticated local
web/API access), but does not include DNS-over-QUIC or DNS-over-HTTP/3
(`dnsdist --version` will not list `dns-over-quic` or `dns-over-http3`
among its "Enabled features").

`app/encryption.py`'s `dnsdist_capabilities()` detects this directly by
parsing `dnsdist --version`'s feature list at deploy time (and again live
in the web UI, via `/encryption`). DoQ and DoH3 are:

- **off by default** (`packaging/dnsdist.service.d/alderpointdns.conf`
  ships `ALDERPOINTDNS_DNS_DOQ=0`/`ALDERPOINTDNS_DNS_DOH3=0`), so a fresh
  install never attempts to start a listener the installed build can't
  provide;
- **shown as unsupported, not enabled or broken**, in Encryption
  Settings — their checkboxes render disabled with an explanatory badge
  when the installed dnsdist lacks the capability;
- **defensively re-checked at deploy time** in `deploy_encryption()`: even
  if a saved configuration requests DoQ/DoH3 (for example, restored from a
  backup taken on a QUIC-capable install), the deploy step disables just
  that protocol and reports why in the deployment message, rather than
  restarting dnsdist into a failed protocol test that would roll back
  every other protocol along with it.

`packaging/dnsdist.conf` itself also wraps every DoQ/DoH3/DNSCrypt
`add*Local`/`add*Bind` call in `alderpointdnsSafeCapabilityCall()`, which
checks the Lua function exists and `pcall`s it, so even a hand-edited or
manually deployed configuration degrades safely instead of crash-looping
dnsdist.

DoQ/DoH3 are optional. To use them, install dnsdist from the official
PowerDNS `trixie-dnsdist-21` repository (see `docs/install.md`) *before*
installing/upgrading Alderpoint DNS, and verify `dnsdist --version` reports
`dns-over-quic`; Alderpoint DNS then detects and exposes the extra
capability automatically, with no reinstall required.

Validation commands:

```sh
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf
systemctl status dnsdist --no-pager
/opt/alderpointdns/tests/test_dnsdist_frontend.sh
```
