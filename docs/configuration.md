# Configuration

Current configuration:

- Admin UI: `0.0.0.0:3000`, authenticated by BindGuard
- dnsdist DNS: `0.0.0.0:53`, `[::]:53`
- dnsdist DoH/DoH3: `0.0.0.0:443`, `[::]:443`, path `/dns-query`
- dnsdist DoT/DoQ: `0.0.0.0:853`, `[::]:853`
- BIND dnsdist backend: `127.0.0.1:5354` with PROXYv2
- BIND recovery/health listener: `127.0.0.1:5353`
- BIND RPZ: `/var/lib/bindguard/compiled/bind/bindguard.rpz`
- Maintenance DNS: `1.1.1.2`, `1.0.0.2`, `4.2.2.1`, `4.2.2.2`

dnsdist accepts RFC1918 private clients by default. Set
`BINDGUARD_DNS_ALLOW_ALL=1` only when pfSense rules are ready to enforce the
intended boundary. The generated self-signed certificate lives at
`/etc/bindguard/certs/bindguard-lab.crt`; replace both cert and key together to
install production TLS material.
