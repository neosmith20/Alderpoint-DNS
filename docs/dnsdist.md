# dnsdist frontend

Alderpoint DNS uses dnsdist as the only client-facing DNS frontend.

Current lab configuration:

- Plain UDP/TCP DNS: `0.0.0.0:53`, `[::]:53`
- DoH: `https://<vm-lan-ip>/dns-query`
- DoH3: UDP `0.0.0.0:443`, `[::]:443`
- DoT: `0.0.0.0:853`, `[::]:853`
- DoQ: UDP `0.0.0.0:853`, `[::]:853`
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

The Debian dnsdist package is not sufficient because it lacks DNS-over-QUIC.
Install dnsdist from the official PowerDNS `trixie-dnsdist-21` repository and
verify `dnsdist --version` reports `dns-over-quic`.

Validation commands:

```sh
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf
systemctl status dnsdist --no-pager
/opt/alderpointdns/tests/test_dnsdist_frontend.sh
```
